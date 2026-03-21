#! /usr/bin/python3
#
# Certbot deploy hook for HP Color LaserJet M452dn printer.
#
# Converts PEM cert+key to PKCS12 and uploads it through the printer's
# EWS form-based flow using HTTP Basic Auth via a temporary netrc file.
#
# See README.laserjet.md for setup instructions.
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


def curlPOST(curl, url, netrc_file=None, data=None, extra_args=None,
             verbose=False):
    """POST with curl using a netrc file for authentication."""
    cmd = [curl, "-sk", "-X", "POST", url, "-L"]
    if verbose:
        cmd.append("-v")
    if netrc_file:
        cmd += ["--netrc-file", netrc_file]
    if data:
        cmd += ["-H", "Content-Type: application/x-www-form-urlencoded", "-d", data]
    if extra_args:
        cmd += extra_args
    sp = subprocess.run(cmd, capture_output=True, timeout=180)
    logging.info("POST %s returncode=%s stdout=%s stderr=%s",
                 url, sp.returncode,
                 sp.stdout.decode(errors="replace")[:500],
                 sp.stderr.decode(errors="replace")[:500])
    if sp.returncode != 0:
        raise RuntimeError(
            f"curl POST {url} failed with return code {sp.returncode}: "
            f"{sp.stderr.decode(errors='replace')}")
    return sp


def upload_certificate(curl, hostname, pfx_path, pfx_password,
                       netrc_file, verbose=False):
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
    logging.info("Step 3: Uploading PKCS12 certificate")
    curlPOST(curl, f"{base_url}/hp/device/Certificate.pfx",
             netrc_file=netrc_file, verbose=verbose,
             extra_args=[
                 "-F", f"CertFile=@{pfx_path};filename=Certificate.pfx",
                 "-F", f"CertPwd={pfx_password}",
                 "-F", "ImportCert=Import",
             ])

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
                        format="%(asctime)s %(levelname)s: %(message)s")

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

        crtname = os.path.join(lineage, args.certName)
        keyname = os.path.join(lineage, args.keyName)
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

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create netrc file for curl authentication
            netrcPath = os.path.join(tmpdir, "netrc")
            with open(netrcPath, "w") as fp:
                fp.write(f"machine {hostname} login {adminUser} password {adminPassword}\n")

            pfxPassword = secrets.token_hex(6)  # 12-char alphanumeric, printer limit
            pfxPath = os.path.join(tmpdir, "cert.pfx")

            # Convert PEM cert+key to PKCS12 using env var for password
            env = os.environ.copy()
            env["PFX_PASSOUT"] = pfxPassword
            cmd = (args.openssl, "pkcs12", "-export",
                   "-out", pfxPath,
                   "-inkey", keyname,
                   "-in", crtname,
                   "-passout", "env:PFX_PASSOUT")
            sp = subprocess.run(cmd, capture_output=True, timeout=180, env=env)
            logging.info("openssl returncode=%s stdout=%s stderr=%s",
                         sp.returncode,
                         sp.stdout.decode(errors="replace")[:500],
                         sp.stderr.decode(errors="replace")[:500])
            if sp.returncode != 0:
                raise RuntimeError(
                    f"openssl pkcs12 failed with return code {sp.returncode}: "
                    f"{sp.stderr.decode(errors='replace')}")

            # Upload the certificate
            upload_certificate(args.curl, hostname, pfxPath, pfxPassword,
                               netrcPath, verbose=args.verbose)

        logging.info("Deployment to %s completed successfully", hostname)
    except subprocess.TimeoutExpired as e:
        logging.error("Timed out: %s", e)
        sys.exit(1)
    except (FileNotFoundError, KeyError, RuntimeError) as e:
        logging.error("%s", e)
        sys.exit(1)
    except Exception:
        logging.exception("GotMe")
        sys.exit(1)

if __name__ == "__main__":
    main()
