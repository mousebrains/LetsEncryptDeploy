#! /usr/bin/python3
#
# This script is designed to install a renewed certificate on
# an HP LaserJet MFP printer via its Embedded Web Server (EWS).
#
# The certificate must use an RSA key. ECC keys are not supported
# by HP LaserJet printers.
#
# On your letsencrypt host:
#  1) Create the certificate with an RSA key:
#     sudo certbot certonly --key-type rsa -d ljscan.mousebrains.com
#  2) Store the printer's EWS admin password in a file:
#     echo 'YOUR_ADMIN_PASSWORD' | sudo tee /etc/letsencrypt/ljscan.admin.password
#     sudo chmod 600 /etc/letsencrypt/ljscan.admin.password
#  3) Install this script:
#     sudo cp ljscan.mousebrains.com.py /etc/letsencrypt/renewal-hooks/deploy/
#     sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/ljscan.mousebrains.com.py
#
# The script converts the PEM cert+key to PKCS12 format, base64-encodes it,
# and POSTs it as JSON to the printer's CDM certificate API.
#
# The name of the script should be the FQDN of the printer (with .py extension)
#
# Jan-2026 Pat Welch pat@mousebrains.com

logDir = "/var/log"

from argparse import ArgumentParser
import base64
import json
import logging
import os
import secrets
import ssl
import sys
import subprocess
import tempfile
import urllib.request
import urllib.error

def main():
    scriptName = os.path.basename(sys.argv[0]) # This script's name
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
    parser.add_argument("--adminPasswordFile", type=str,
                        default="/etc/letsencrypt/ljscan.admin.password",
                        help="File containing the printer's EWS admin password")
    parser.add_argument("--uploadPath", type=str,
                        default="/cdm/certificate/v1/certificates",
                        help="EWS certificate API path")
    parser.add_argument("--openssl", type=str, default="/usr/bin/openssl",
                        help="OpenSSL command to use")
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

        if not os.path.isfile(crtname):
            raise FileNotFoundError(f"Certificate file not found: {crtname}")
        if not os.path.isfile(keyname):
            raise FileNotFoundError(f"Key file not found: {keyname}")
        if not os.path.isfile(args.adminPasswordFile):
            raise FileNotFoundError(f"Admin password file not found: {args.adminPasswordFile}")

        with open(args.adminPasswordFile) as fp:
            adminPassword = fp.read().strip()
        if not adminPassword:
            raise RuntimeError(f"Admin password file is empty: {args.adminPasswordFile}")

        pfxPassword = secrets.token_urlsafe(32)

        # Create a temp file for the PKCS12 bundle
        fd, pfxPath = tempfile.mkstemp(suffix=".pfx")
        os.close(fd)

        # Convert PEM cert+key to PKCS12
        cmd = (
                args.openssl, "pkcs12", "-export",
                "-out", pfxPath,
                "-inkey", keyname,
                "-in", crtname,
                "-password", f"pass:{pfxPassword}",
                )
        sp = subprocess.run(cmd, shell=False, capture_output=True, timeout=180)
        logging.info("openssl returncode=%s stdout=%s stderr=%s",
                     sp.returncode,
                     sp.stdout.decode(errors="replace"),
                     sp.stderr.decode(errors="replace"))
        if sp.returncode != 0:
            raise RuntimeError(f"openssl pkcs12 failed with return code {sp.returncode}: {sp.stderr.decode(errors='replace')}")

        # Read and base64-encode the PKCS12 file
        with open(pfxPath, "rb") as fp:
            pfxData = base64.b64encode(fp.read()).decode("ascii")

        # Build the JSON payload for the CDM certificate API
        payload = json.dumps({
            "certificateData": pfxData,
            "certificateFormat": "pkcs12",
            "password": pfxPassword,
            "privateKeyExportable": False,
            "requestType": "importId",
            "version": "1.1.0",
        }).encode("utf-8")

        # POST to the printer's certificate API
        url = f"https://{hostname}{args.uploadPath}"
        req = urllib.request.Request(url, data=payload, method="POST")
        req.add_header("Content-Type", "application/json")

        # HTTP Basic Auth
        credentials = base64.b64encode(
                f"admin:{adminPassword}".encode()
                ).decode("ascii")
        req.add_header("Authorization", f"Basic {credentials}")

        # Skip TLS verification (printer may have expired/self-signed cert)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        response = urllib.request.urlopen(req, context=ctx, timeout=180)
        status = response.status
        body = response.read().decode(errors="replace")
        logging.info("POST %s status=%s body=%s", url, status, body)

        logging.info("Deployment to %s completed successfully", hostname)
    except (FileNotFoundError, RuntimeError) as e:
        logging.error("%s", e)
        sys.exit(1)
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace") if e.fp else ""
        logging.error("HTTP %s %s: %s", e.code, e.reason, body)
        sys.exit(1)
    except Exception:
        logging.exception("GotMe")
        sys.exit(1)
    finally:
        if pfxPath and os.path.isfile(pfxPath):
            os.unlink(pfxPath)

if __name__ == "__main__":
    main()
