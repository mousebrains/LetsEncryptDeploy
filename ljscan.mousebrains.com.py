#! /usr/bin/python3
#
# This script is designed to install a renewed certificate on
# an HP LaserJet MFP printer via its Embedded Web Server (EWS).
#
# The certificate must use an RSA key. ECC keys are not supported
# by HP LaserJet printers.
#
# Authentication uses the printer's CDM OAuth2 API:
#   POST /cdm/security/v1/authenticate  -> bearer token
#   POST /cdm/certificate/v1/certificates -> upload PKCS12
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
# The name of the script should be the FQDN of the printer (with .py extension)
#
# Jan-2026 Pat Welch pat@mousebrains.com

logDir = "/var/log"

from argparse import ArgumentParser
import base64
import http.cookiejar
import json
import logging
import os
import secrets
import ssl
import sys
import subprocess
import tempfile
import urllib.parse
import urllib.request
import urllib.error
import uuid

def mkSSLContext() -> ssl.SSLContext:
    """Create an SSL context that skips verification (printer may have
    an expired or self-signed certificate)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def mkOpener(ctx:ssl.SSLContext) -> urllib.request.OpenerDirector:
    """Create a URL opener with a cookie jar and SSL context."""
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=ctx),
    )

def postJSON(opener:urllib.request.OpenerDirector, url:str,
             payload:dict, bearer:str=None) -> dict:
    """POST a JSON payload and return the parsed JSON response."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if bearer:
        req.add_header("Authorization", f"Bearer {bearer}")

    response = opener.open(req, timeout=180)
    body = response.read().decode(errors="replace")
    logging.info("POST %s status=%s body=%s", url, response.status, body)
    return json.loads(body) if body.strip() else {}

def authenticate(opener:urllib.request.OpenerDirector,
                 hostname:str, username:str, password:str) -> str:
    """Authenticate to the printer's CDM OAuth2 API and return the
    bearer token.  Uses a two-step flow: first GET the authorize
    endpoint to establish a session, then POST credentials to the
    authenticate endpoint."""
    state = secrets.token_urlsafe(48)
    client_id = "com.hp.cdm.client.hpEws"
    scope = "com.hp.cdm.auth.alias.deviceRole.deviceAdmin"

    # Step 1: GET the authorize endpoint to establish session cookies
    params = urllib.parse.urlencode({
        "response_type": "code",
        "client_id": client_id,
        "state": state,
        "redirect_uri": f"https://{hostname}/",
        "scope": scope,
    })
    auth_url = f"https://{hostname}/cdm/oauth2/v1/authorize?{params}"
    logging.info("AUTH step 1: GET %s", auth_url)
    resp1 = opener.open(auth_url, timeout=180)
    body1 = resp1.read().decode(errors="replace")
    logging.info("AUTH step 1: status=%s url=%s headers=%s body=%s",
                 resp1.status, resp1.url, dict(resp1.getheaders()), body1)

    # Step 2: POST credentials to the authenticate endpoint
    url = f"https://{hostname}/cdm/security/v1/authenticate"
    payload = {
        "agentId": str(uuid.uuid4()),
        "client_id": client_id,
        "client_secret": "98429f9c-f357-4746-ab0f-eeef094430ce",
        "grant_type": "authorization_code",
        "password": password,
        "scope": scope,
        "state": state,
        "username": username,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")

    resp2 = opener.open(req, timeout=180)
    headers = dict(resp2.getheaders())
    body = resp2.read().decode(errors="replace")
    logging.info("AUTH step 2: status=%s headers=%s body=%s",
                 resp2.status, headers, body)

    # Try JSON body first
    if body.strip():
        result = json.loads(body)
        token = result.get("access_token")
        if token:
            return token

    # Check response headers for the token
    for hdr in ("X-Auth-Token", "Authorization"):
        value = resp2.getheader(hdr, "")
        if value:
            # Strip "Bearer " prefix if present
            if value.lower().startswith("bearer "):
                return value[7:]
            return value

    raise RuntimeError(
        f"Authentication failed, no bearer token found in body or headers.\n"
        f"  step 1 status={resp1.status}\n"
        f"  step 2 status={resp2.status}\n"
        f"  step 2 headers={headers}\n"
        f"  step 2 body={body!r}"
    )

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
    parser.add_argument("--adminUser", type=str, default="admin",
                        help="EWS admin username")
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

        ctx = mkSSLContext()
        opener = mkOpener(ctx)

        # Authenticate to get a bearer token
        token = authenticate(opener, hostname, args.adminUser, adminPassword)

        # Upload the certificate
        url = f"https://{hostname}{args.uploadPath}"
        payload = {
            "certificateData": pfxData,
            "certificateFormat": "pkcs12",
            "password": pfxPassword,
            "privateKeyExportable": False,
            "requestType": "importId",
            "version": "1.1.0",
        }
        postJSON(opener, url, payload, bearer=token)

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
