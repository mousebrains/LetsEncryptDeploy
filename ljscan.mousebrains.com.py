#! /usr/bin/python3
#
# Certbot deploy hook for HP LaserJet MFP printer.
#
# Converts PEM cert+key to PKCS12, authenticates via CDM OAuth2
# password grant, and uploads the certificate via the CDM API.
#
# The User-Agent is set to AppleWebKit because HP's printer firmware
# rejects requests with certain other User-Agent strings.
#
# See README.ljscan.md for setup instructions.
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
                 sp.stdout.decode(errors="replace")[:500],
                 sp.stderr.decode(errors="replace")[:500])
    if sp.returncode != 0:
        raise RuntimeError(
            f"curl POST {url} failed with return code {sp.returncode}: "
            f"{sp.stderr.decode(errors='replace')}")
    return sp


def authenticate(curl, hostname, username, password, tmpdir, verbose=False):
    """Authenticate to the printer's CDM OAuth2 API using the password
    grant flow and return a bearer token.

    POST /cdm/oauth2/v1/token with grant_type=password
    """
    token_data = urllib.parse.urlencode({
        "grant_type": "password",
        "username": username,
        "password": password,
        "client_id": "com.hp.cdm.client.hpEws",
        "scope": "deviceAdmin",
    })

    # Write POST body to temp file to avoid credentials on command line
    dataPath = os.path.join(tmpdir, "auth-data")
    with open(dataPath, "w") as fp:
        fp.write(token_data)

    logging.info("AUTH: requesting token via password grant")
    sp = curlPOST(curl, f"https://{hostname}/cdm/oauth2/v1/token",
                   dataFile=dataPath,
                   contentType="application/x-www-form-urlencoded",
                   verbose=verbose)

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

            # Read and base64-encode the PKCS12 file
            with open(pfxPath, "rb") as fp:
                pfxData = base64.b64encode(fp.read()).decode("ascii")

            # Authenticate to get a bearer token
            token = authenticate(args.curl, hostname, adminUser, adminPassword,
                                 tmpdir, verbose=args.verbose)

            # Write bearer token to a temp header file
            headerPath = os.path.join(tmpdir, "auth-header")
            with open(headerPath, "w") as fp:
                fp.write(f"Authorization: Bearer {token}")

            # Write upload payload to a temp file
            uploadPath = os.path.join(tmpdir, "upload-data")
            with open(uploadPath, "w") as fp:
                json.dump({
                    "certificateData": pfxData,
                    "certificateFormat": "pkcs12",
                    "password": pfxPassword,
                    "privateKeyExportable": False,
                    "requestType": "importId",
                    "version": "1.1.0",
                }, fp)

            curlPOST(args.curl,
                      f"https://{hostname}{args.uploadPath}",
                      dataFile=uploadPath,
                      headerFile=headerPath)

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
