#! /usr/bin/python3
#
# This script is designed to install a renewed certificate on
# an HP LaserJet MFP printer via its Embedded Web Server (EWS).
#
# The certificate must use an RSA key. ECC keys are not supported
# by HP LaserJet printers.
#
# Authentication uses the printer's CDM OAuth2 password grant:
#   POST /cdm/oauth2/v1/token           -> get access token
#   POST /cdm/certificate/v1/certificates -> upload PKCS12
#
# On your letsencrypt host:
#  1) Create the certificate with an RSA key:
#     sudo certbot certonly --key-type rsa --dns-cloudflare \
#         --dns-cloudflare-credentials /home/pat/.config/cloudflare.token \
#         -d ljscan.mousebrains.com
#  2) Create a JSON config file with the printer's EWS admin credentials:
#     tee ~pat/.config/ljscan.json <<< '{"admin_user":"admin","admin_password":"YOUR_PASSWORD"}'
#     chmod 600 ~pat/.config/ljscan.json
#  3) Install this script:
#     sudo cp ljscan.mousebrains.com.py /etc/letsencrypt/renewal-hooks/deploy/
#
# The name of the script should be the FQDN of the printer (with .py extension)
#
# Jan-2026 Pat Welch pat@mousebrains.com

from argparse import ArgumentParser
import base64
import json
import logging
import os
import secrets
import subprocess
import sys
import tempfile
import urllib.parse

logDir = "/var/log"


def curlPOST(curl, url, dataFile=None, contentType="application/json",
             headerFile=None, verbose=False):
    """POST data with curl, reading POST body and extra headers from temp files.

    The User-Agent is set to AppleWebKit because HP's printer firmware
    rejects requests with certain other User-Agent strings.
    """
    cmd = [
        curl, "-sk", "-X", "POST", url,
        "-H", f"Content-Type: {contentType}",
        "-H", "User-Agent: AppleWebKit",
    ]
    if dataFile:
        cmd += ["-d", f"@{dataFile}"]
    if headerFile:
        cmd += ["-H", f"@{headerFile}"]
    if verbose:
        cmd.append("-v")
    sp = subprocess.run(cmd, capture_output=True, timeout=180)
    logging.info("POST %s returncode=%s stdout=%s stderr=%s",
                 url, sp.returncode,
                 sp.stdout.decode(errors="replace"),
                 sp.stderr.decode(errors="replace"))
    if sp.returncode != 0:
        raise RuntimeError(
            f"curl POST {url} failed with return code {sp.returncode}: "
            f"{sp.stderr.decode(errors='replace')}")
    return sp


def authenticate(curl, hostname, username, password, verbose=False):
    """Authenticate to the printer's CDM OAuth2 API using the password
    grant flow and return a bearer token.

    POST /cdm/oauth2/v1/token with grant_type=password
    """
    client_id = "com.hp.cdm.client.hpEws"
    scope = "deviceAdmin"

    token_data = urllib.parse.urlencode({
        "grant_type": "password",
        "username": username,
        "password": password,
        "client_id": client_id,
        "scope": scope,
    })

    # Write POST body to temp file to avoid credentials on command line
    fd, dataPath = tempfile.mkstemp(prefix="auth-")
    try:
        with os.fdopen(fd, "w") as fp:
            fp.write(token_data)

        logging.info("AUTH: requesting token via password grant")
        sp = curlPOST(curl, f"https://{hostname}/cdm/oauth2/v1/token",
                       dataFile=dataPath,
                       contentType="application/x-www-form-urlencoded",
                       verbose=verbose)
    finally:
        if os.path.isfile(dataPath):
            os.unlink(dataPath)

    try:
        result = json.loads(sp.stdout)
    except json.JSONDecodeError:
        raise RuntimeError(
            f"Authentication response is not valid JSON: "
            f"{sp.stdout.decode(errors='replace')[:500]}")

    logging.info("AUTH: token_type=%s scope=%s",
                 result.get("token_type"), result.get("scope"))

    token = result.get("access_token")
    if not token:
        error = result.get("error", "unknown error")
        error_desc = result.get("error_description", "")
        raise RuntimeError(
            f"Authentication failed: {error}\n  {error_desc}\n  response={result}")
    return token


def main():
    scriptName = os.path.basename(sys.argv[0])
    hostname = scriptName.removesuffix(".py")

    parser = ArgumentParser(f"{scriptName} deployment script")
    parser.add_argument("--logfile", type=str,
                        default=os.path.join(logDir, f"{hostname}.log"),
                        help="Where to log to, empty for stderr")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable logging.debug messages")
    parser.add_argument("--certName", type=str, default="fullchain.pem",
                        help="Which certificate file to use")
    parser.add_argument("--keyName", type=str, default="privkey.pem",
                        help="Which key file to use")
    parser.add_argument("--configFile", type=str,
                        default="~pat/.config/ljscan.json",
                        help="JSON config file with admin_user and admin_password")
    parser.add_argument("--uploadPath", type=str,
                        default="/cdm/certificate/v1/certificates",
                        help="EWS certificate API path")
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

    pfxPath = None
    headerPath = None
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

        pfxPassword = secrets.token_hex(6)  # 12-char alphanumeric, printer limit

        # Create a temp file for the PKCS12 bundle
        fd, pfxPath = tempfile.mkstemp(suffix=".pfx")
        os.close(fd)

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
                     sp.stdout.decode(errors="replace"),
                     sp.stderr.decode(errors="replace"))
        if sp.returncode != 0:
            raise RuntimeError(
                f"openssl pkcs12 failed with return code {sp.returncode}: "
                f"{sp.stderr.decode(errors='replace')}")

        # Read and base64-encode the PKCS12 file
        with open(pfxPath, "rb") as fp:
            pfxData = base64.b64encode(fp.read()).decode("ascii")

        # Authenticate to get a bearer token
        token = authenticate(args.curl, hostname, adminUser, adminPassword,
                             verbose=args.verbose)

        # Write bearer token to a temp header file to avoid it on command line
        fd, headerPath = tempfile.mkstemp(prefix="header-")
        with os.fdopen(fd, "w") as fp:
            fp.write(f"Authorization: Bearer {token}")

        # Upload the certificate payload via temp file
        uploadPayload = json.dumps({
            "certificateData": pfxData,
            "certificateFormat": "pkcs12",
            "password": pfxPassword,
            "privateKeyExportable": False,
            "requestType": "importId",
            "version": "1.1.0",
        })
        fd, uploadPath = tempfile.mkstemp(prefix="upload-")
        try:
            with os.fdopen(fd, "w") as fp:
                fp.write(uploadPayload)
            curlPOST(args.curl,
                      f"https://{hostname}{args.uploadPath}",
                      dataFile=uploadPath,
                      headerFile=headerPath)
        finally:
            if os.path.isfile(uploadPath):
                os.unlink(uploadPath)

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
        if headerPath and os.path.isfile(headerPath):
            os.unlink(headerPath)


if __name__ == "__main__":
    main()
