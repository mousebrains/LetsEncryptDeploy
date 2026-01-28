#! /usr/bin/python3
#
# This script is designed to install a renewed certificate on
# an HP LaserJet MFP printer via its Embedded Web Server (EWS).
#
# The certificate must use an RSA key. ECC keys are not supported
# by HP LaserJet printers.
#
# Authentication uses the printer's CDM OAuth2 API:
#   GET  /cdm/oauth2/v1/authorize      -> create OAuth2 session
#   POST /cdm/security/v1/authenticate  -> get authorization code
#   POST /cdm/oauth2/v1/token           -> exchange code for token
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
import json
import logging
import os
import secrets
import sys
import subprocess
import tempfile
import urllib.parse
import uuid

def curlGET(curl:str, url:str, cookieJar:str=None,
            verbose:bool=False, follow:bool=False) -> subprocess.CompletedProcess:
    """GET a URL with curl, optionally saving cookies."""
    cmd = [curl, "-sk", url]
    if follow:
        cmd.append("-L")
    if verbose:
        cmd.append("-v")
    if cookieJar:
        cmd += ["-c", cookieJar, "-b", cookieJar]
    sp = subprocess.run(cmd, capture_output=True, timeout=180)
    logging.info("GET %s returncode=%s stdout=%s stderr=%s",
                 url, sp.returncode,
                 sp.stdout.decode(errors="replace"),
                 sp.stderr.decode(errors="replace"))
    return sp

def curlPOST(curl:str, url:str, data:str, contentType:str="application/json",
             cookieJar:str=None, bearer:str=None,
             verbose:bool=False) -> subprocess.CompletedProcess:
    """POST data with curl, optionally sending cookies or bearer token."""
    cmd = [curl, "-sk", "-X", "POST", url,
           "-H", f"Content-Type: {contentType}",
           "-H", "X-Client-Info: HP-Web-Client",
           "-H", f"Origin: https://{urllib.parse.urlparse(url).hostname}",
           "-d", data]
    if verbose:
        cmd.append("-v")
    if cookieJar:
        cmd += ["-c", cookieJar, "-b", cookieJar]
    if bearer:
        cmd += ["-H", f"Authorization: Bearer {bearer}"]
    sp = subprocess.run(cmd, capture_output=True, timeout=180)
    logging.info("POST %s returncode=%s stdout=%s stderr=%s",
                 url, sp.returncode,
                 sp.stdout.decode(errors="replace"),
                 sp.stderr.decode(errors="replace"))
    if sp.returncode != 0:
        raise RuntimeError(f"curl POST {url} failed with return code {sp.returncode}: {sp.stderr.decode(errors='replace')}")
    return sp

def authenticate(curl:str, hostname:str, username:str, password:str,
                 verbose:bool=False) -> str:
    """Authenticate to the printer's CDM OAuth2 API and return a
    bearer token.  Three-step flow using curl:
      1) GET  /cdm/oauth2/v1/authorize      -> create OAuth2 session
         + intermediate GETs that the login-page Angular app makes
      2) POST /cdm/security/v1/authenticate  -> get authorization code
      3) POST /cdm/oauth2/v1/token           -> exchange code for token

    All requests in steps 1-2 use a single curl invocation (--next) so
    the HTTP keep-alive connection is reused and the server can track
    the session across requests.
    """
    state = secrets.token_urlsafe(48)
    client_id = "com.hp.cdm.client.hpEws"
    client_secret = "98429f9c-f357-4746-ab0f-eeef094430ce"
    scope = "com.hp.cdm.auth.alias.deviceRole.deviceAdmin"
    app_data = base64.b64encode(
        json.dumps({"lang": "en", "theme": "theme-light"},
                   separators=(",", ":")).encode()
    ).decode()
    redirect_uri = f"https://{hostname}/index.html"

    # API calls the login-page Angular app makes before authenticating.
    # The printer may require these to arm the OAuth2 session.
    pre_auth_paths = [
        "/cdm/system/v1/configuration",
        "/cdm/security/v1/deviceAdminConfig",
        "/cdm/ews/v1/configuration",
        "/cdm/security/v1/deviceAdminConfig/constraints",
        "/cdm/ews/v1/configuration/constraints",
        "/cdm/remoteAuthentication/v1/capabilities",
    ]

    fd, cookieJar = tempfile.mkstemp(suffix=".cookies")
    os.close(fd)
    try:
        # Build authorize URL
        auth_params = urllib.parse.urlencode({
            "response_type": "code",
            "client_id": client_id,
            "state": state,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "appData": app_data,
        })
        auth_url = f"https://{hostname}/cdm/oauth2/v1/authorize?{auth_params}"

        # Build authenticate payload using compact JSON (no spaces)
        # to match the browser's Angular app format.
        payload = json.dumps({
            "agentId": str(uuid.uuid4()),
            "username": username,
            "password": password,
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": scope,
            "state": state,
            "grant_type": "authorization_code",
        }, separators=(",", ":"))

        # The Angular login app rewrites the URL to the root path
        # via history.replaceState, so the browser's Referer uses "/"
        # rather than "/device/security/login/".
        referer_params = urllib.parse.urlencode({
            "client_id": client_id,
            "state": state,
            "appData": app_data,
        })
        referer = f"https://{hostname}/?{referer_params}"

        # Build a single curl command with --next sections:
        #   1. GET authorize (follow redirect to login page)
        #   2. GET each pre-auth API endpoint (with Referer)
        #   3. POST authenticate (with Referer + Origin)
        # All share the same TCP/TLS connection via HTTP keep-alive.
        cmd = [curl, "-sk", "-L",
               "-c", cookieJar, "-b", cookieJar,
               "-o", "/dev/null",
               auth_url]
        if verbose:
            cmd.insert(1, "-v")

        for path in pre_auth_paths:
            cmd += ["--next", "-sk",
                    "-c", cookieJar, "-b", cookieJar,
                    "-H", f"Referer: {referer}",
                    "-o", "/dev/null",
                    f"https://{hostname}{path}"]

        cmd += ["--next", "-sk",
                "-X", "POST",
                "-c", cookieJar, "-b", cookieJar,
                "-H", "Content-Type: application/json",
                "-H", "X-Client-Info: HP-Web-Client",
                "-H", f"Origin: https://{hostname}",
                "-H", f"Referer: {referer}",
                "-H", "Accept: application/json, text/plain, */*",
                "-H", "Accept-Language: en",
                "-H", "Cache-Control: no-cache",
                "-H", "Sec-Fetch-Dest: empty",
                "-H", "Sec-Fetch-Mode: cors",
                "-H", "Sec-Fetch-Site: same-origin",
                "-d", payload,
                f"https://{hostname}/cdm/security/v1/authenticate"]
        if verbose:
            # Add -v to the POST section (last --next)
            last_next = len(cmd) - 1
            while cmd[last_next] != "--next":
                last_next -= 1
            cmd.insert(last_next + 2, "-v")

        logging.info("AUTH steps 1+2: running combined curl "
                     "(%d pre-auth GETs)", len(pre_auth_paths))
        sp2 = subprocess.run(cmd, capture_output=True, timeout=180)
        logging.info("AUTH steps 1+2: returncode=%s stdout=%s stderr=%s",
                     sp2.returncode,
                     sp2.stdout.decode(errors="replace"),
                     sp2.stderr.decode(errors="replace"))
        if sp2.returncode != 0:
            raise RuntimeError(
                f"curl authenticate failed rc={sp2.returncode}: "
                f"{sp2.stderr.decode(errors='replace')}")

        result2 = json.loads(sp2.stdout)
        logging.info("AUTH step 2: %s", result2)

        if result2.get("error"):
            raise RuntimeError(
                f"Authentication failed: {result2.get('error')}\n"
                f"  response={result2}"
            )

        code = result2.get("code")
        if not code:
            redir = result2.get("redirect_uri", "")
            parsed = urllib.parse.urlparse(redir)
            code = urllib.parse.parse_qs(parsed.query).get("code", [None])[0]
        if not code:
            raise RuntimeError(
                f"No authorization code in authenticate response.\n"
                f"  response={result2}"
            )

        # Step 3: Exchange the authorization code for an access token
        token_data = urllib.parse.urlencode({
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": f"https://{hostname}/",
            "client_id": client_id,
        })
        sp3 = curlPOST(curl,
                        f"https://{hostname}/cdm/oauth2/v1/token",
                        token_data,
                        contentType="application/x-www-form-urlencoded",
                        verbose=verbose)
        result3 = json.loads(sp3.stdout)
        logging.info("AUTH step 3: token_type=%s expires_in=%s",
                     result3.get("token_type"), result3.get("expires_in"))

        token = result3.get("access_token")
        if not token:
            raise RuntimeError(
                f"No access_token in token response.\n"
                f"  response={result3}"
            )
        return token
    finally:
        if os.path.isfile(cookieJar):
            os.unlink(cookieJar)

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

        # Authenticate to get a bearer token
        token = authenticate(args.curl, hostname, args.adminUser, adminPassword,
                             verbose=args.verbose)

        # Upload the certificate
        uploadPayload = json.dumps({
            "certificateData": pfxData,
            "certificateFormat": "pkcs12",
            "password": pfxPassword,
            "privateKeyExportable": False,
            "requestType": "importId",
            "version": "1.1.0",
        })
        curlPOST(args.curl,
                  f"https://{hostname}{args.uploadPath}",
                  uploadPayload, bearer=token)

        logging.info("Deployment to %s completed successfully", hostname)
    except (FileNotFoundError, RuntimeError) as e:
        logging.error("%s", e)
        sys.exit(1)
    except Exception:
        logging.exception("GotMe")
        sys.exit(1)
    finally:
        if pfxPath and os.path.isfile(pfxPath):
            os.unlink(pfxPath)

if __name__ == "__main__":
    main()
