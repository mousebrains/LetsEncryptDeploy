#! /usr/bin/python3
#
# This script is designed to install a renewed certificate on
# an HP Color LaserJet M452dn printer via its Embedded Web Server (EWS).
#
# The certificate must use an RSA key. ECC keys are not supported
# by HP LaserJet printers.
#
# Authentication uses HTTP Basic Auth. The upload flow:
#   POST /hp/device/set_config_networkCerts.html/config      -> navigate to print certs
#   POST /hp/device/set_config_networkPrintCerts.html/config -> navigate to import page
#   POST /hp/device/Certificate.pfx                          -> upload PKCS12 file
#
# On your letsencrypt host:
#  1) Create the certificate with an RSA key:
#     sudo certbot certonly --key-type rsa --dns-cloudflare \
#         --dns-cloudflare-credentials /home/pat/.config/cloudflare.token \
#         -d laserjet.mousebrains.com
#  2) Create a JSON config file with the printer's EWS admin credentials:
#     tee ~pat/.config/laserjet.json <<< '{"admin_user":"admin","admin_password":"YOUR_PASSWORD"}'
#     chmod 600 ~pat/.config/laserjet.json
#  3) Install this script:
#     sudo cp laserjet.mousebrains.com.py /etc/letsencrypt/renewal-hooks/deploy/
#
# The name of the script should be the FQDN of the printer (with .py extension)
#
# Jan-2026 Pat Welch pat@mousebrains.com

from argparse import ArgumentParser
import json
import logging
import os
import secrets
import subprocess
import sys
import tempfile

logDir = "/var/log"


def curlPOST(curl: str, url: str, data: str | None = None,
             netrc_file: str | None = None,
             verbose: bool = False) -> subprocess.CompletedProcess:
    """POST data with curl using a netrc file for authentication."""
    cmd = [curl, "-sk", "-X", "POST", url, "-L"]
    if verbose:
        cmd.append("-v")
    if netrc_file:
        cmd += ["--netrc-file", netrc_file]
    if data:
        cmd += ["-H", "Content-Type: application/x-www-form-urlencoded", "-d", data]
    sp = subprocess.run(cmd, capture_output=True, timeout=180)
    logging.info("POST %s returncode=%s stdout=%s stderr=%s",
                 url, sp.returncode,
                 sp.stdout.decode(errors="replace")[:500],
                 sp.stderr.decode(errors="replace")[:500])
    if sp.returncode != 0:
        raise RuntimeError(f"curl POST {url} failed with return code {sp.returncode}: {sp.stderr.decode(errors='replace')}")
    return sp


def upload_certificate(curl: str, hostname: str, pfx_path: str, pfx_password: str,
                       netrc_file: str, verbose: bool = False) -> None:
    """Upload certificate through the EWS form-based flow."""

    base_url = f"https://{hostname}"

    # Step 1: Navigate to certificate configuration
    logging.info("Step 1: Navigating to certificate configuration page")
    curlPOST(curl, f"{base_url}/hp/device/set_config_networkCerts.html/config",
             data="ConfigurePrintCert=Configure",
             netrc_file=netrc_file, verbose=verbose)

    # Step 2: Select import certificate option
    logging.info("Step 2: Selecting import certificate option")
    curlPOST(curl, f"{base_url}/hp/device/set_config_networkPrintCerts.html/config",
             data="ConfigOpt=ImptCert&Next=Next",
             netrc_file=netrc_file, verbose=verbose)

    # Step 3: Upload the PKCS12 file via multipart form
    # The form has fields: CertFile (the file), CertPwd (password), ImportCert (submit button)
    logging.info("Step 3: Uploading PKCS12 certificate")
    cmd = [curl, "-sk", "-X", "POST", "-L",
           f"{base_url}/hp/device/Certificate.pfx",
           "--netrc-file", netrc_file,
           "-F", f"CertFile=@{pfx_path};filename=Certificate.pfx",
           "-F", f"CertPwd={pfx_password}",
           "-F", "ImportCert=Import"]
    if verbose:
        cmd.insert(1, "-v")
    sp = subprocess.run(cmd, capture_output=True, timeout=180)
    logging.info("Upload returncode=%s stdout=%s stderr=%s",
                 sp.returncode,
                 sp.stdout.decode(errors="replace")[:1000],
                 sp.stderr.decode(errors="replace")[:500])
    if sp.returncode != 0:
        raise RuntimeError(f"Certificate upload failed with return code {sp.returncode}: {sp.stderr.decode(errors='replace')}")

    logging.info("Certificate upload completed")


def main():
    scriptName = os.path.basename(sys.argv[0])
    hostname = scriptName.removesuffix(".py")

    parser = ArgumentParser(f"{scriptName} deployment script")
    parser.add_argument("--logfile", type=str,
                        default=os.path.join(logDir, f"{hostname}.log"),
                        help="Where to log to, empty for stderr")
    parser.add_argument("--verbose", action="store_true", help="Enable logging.debug messages")
    parser.add_argument("--certName", type=str, default="fullchain.pem",
                        help="Which certificate file to use")
    parser.add_argument("--keyName", type=str, default="privkey.pem",
                        help="Which key file to use")
    parser.add_argument("--configFile", type=str,
                        default="~pat/.config/laserjet.json",
                        help="JSON config file with admin_user and admin_password")
    parser.add_argument("--openssl", type=str, default="/usr/bin/openssl",
                        help="OpenSSL command to use")
    parser.add_argument("--curl", type=str, default="/usr/bin/curl",
                        help="curl command to use")
    args = parser.parse_args()

    logfilename = None
    if args.logfile:
        logfilename = os.path.abspath(os.path.expanduser(args.logfile))
        logdirname = os.path.dirname(logfilename)
        if not os.path.isdir(logdirname):
            os.makedirs(logdirname, exist_ok=True)

    logging.basicConfig(filename=logfilename,
                        level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s: %(message)s",
                        )

    pfxPath = None
    netrcPath = None
    try:
        for key in ["DOMAINS", "LINEAGE"]:
            name = "RENEWED_" + key
            if name not in os.environ:
                raise KeyError(f"{name} not in environment")

        domains = os.environ["RENEWED_DOMAINS"].split()
        lineage = os.environ["RENEWED_LINEAGE"]

        if hostname not in domains:
            logging.info("Mismatch: %s not in %s", hostname, domains)
            sys.exit(0)

        crtname = os.path.abspath(os.path.expanduser(os.path.join(lineage, args.certName)))
        keyname = os.path.abspath(os.path.expanduser(os.path.join(lineage, args.keyName)))

        configFile = os.path.abspath(os.path.expanduser(args.configFile))

        if not os.path.isfile(crtname):
            raise FileNotFoundError(f"Certificate file not found: {crtname}")
        if not os.path.isfile(keyname):
            raise FileNotFoundError(f"Key file not found: {keyname}")
        if not os.path.isfile(configFile):
            raise FileNotFoundError(f"Config file not found: {configFile}")

        with open(configFile) as fp:
            config = json.load(fp)

        adminUser = config.get("admin_user", "admin")
        adminPassword = config.get("admin_password")
        if not adminPassword:
            raise RuntimeError(f"admin_password not set in {configFile}")

        # Create a temporary netrc file for curl authentication
        fd, netrcPath = tempfile.mkstemp(prefix="netrc-", mode=0o600)
        with os.fdopen(fd, "w") as fp:
            fp.write(f"machine {hostname} login {adminUser} password {adminPassword}\n")

        pfxPassword = secrets.token_hex(6)  # 12-char alphanumeric, printer limit

        # Create a temp file for the PKCS12 bundle
        fd, pfxPath = tempfile.mkstemp(suffix=".pfx")
        os.close(fd)

        # Convert PEM cert+key to PKCS12 using env var for password
        env = os.environ.copy()
        env["PFX_PASSOUT"] = pfxPassword
        cmd = (
                args.openssl, "pkcs12", "-export",
                "-out", pfxPath,
                "-inkey", keyname,
                "-in", crtname,
                "-passout", "env:PFX_PASSOUT",
                )
        sp = subprocess.run(cmd, shell=False, capture_output=True, timeout=180, env=env)
        logging.info("openssl returncode=%s stdout=%s stderr=%s",
                     sp.returncode,
                     sp.stdout.decode(errors="replace"),
                     sp.stderr.decode(errors="replace"))
        if sp.returncode != 0:
            raise RuntimeError(f"openssl pkcs12 failed with return code {sp.returncode}: {sp.stderr.decode(errors='replace')}")

        # Upload the certificate
        upload_certificate(args.curl, hostname, pfxPath, pfxPassword,
                           netrcPath, verbose=args.verbose)

        logging.info("Deployment to %s completed successfully", hostname)
    except (FileNotFoundError, KeyError, RuntimeError) as e:
        logging.error("%s", e)
        sys.exit(1)
    except Exception:
        logging.exception("GotMe")
        sys.exit(1)
    finally:
        if pfxPath and os.path.isfile(pfxPath):
            os.unlink(pfxPath)
        if netrcPath and os.path.isfile(netrcPath):
            os.unlink(netrcPath)

if __name__ == "__main__":
    main()
