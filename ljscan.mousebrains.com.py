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

import base64
import hashlib
import json
import logging
import os
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
from argparse import ArgumentParser

LOG_DIR = "/var/log"

# Post-deploy verification: how long to wait for the printer to serve the new
# certificate (the web server restarts briefly after an import).
VERIFY_ATTEMPTS = 6
VERIFY_DELAY = 10.0
VERIFY_DEADLINE = 120.0


def leaf_cert_der(pem_path: str) -> bytes:
    """Return the DER bytes of the first certificate in a PEM file."""
    begin = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"
    with open(pem_path) as fp:
        text = fp.read()
    start = text.find(begin)
    stop = text.find(end)
    if start == -1 or stop == -1:
        msg = f"No PEM certificate found in {pem_path}"
        raise RuntimeError(msg)
    return base64.b64decode("".join(text[start + len(begin):stop].split()))


def served_cert_der(hostname: str, port: int = 443, timeout: float = 15.0) -> bytes:
    """Return the DER bytes of the leaf certificate served on host:port.

    Uses an unverified context so an expired or mismatched cert can still be
    fetched for comparison.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((hostname, port), timeout=timeout) as sock, \
            ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
        der = ssock.getpeercert(binary_form=True)
    if not der:
        msg = f"No certificate returned by {hostname}:{port}"
        raise RuntimeError(msg)
    return der


def verify_served_certificate(
    hostname: str,
    crtname: str,
    attempts: int = VERIFY_ATTEMPTS,
    delay: float = VERIFY_DELAY,
    deadline: float = VERIFY_DEADLINE,
    port: int = 443,
) -> None:
    """Confirm the printer is actually serving the just-deployed certificate.

    Compares the SHA-256 of the served leaf cert to the deployed one, retrying
    to allow the web server to restart. Raises on mismatch so a deploy that
    does not take effect becomes a hard failure.
    """
    expected = hashlib.sha256(leaf_cert_der(crtname)).hexdigest()
    start = time.monotonic()
    last = "no attempt made"
    for attempt in range(1, attempts + 1):
        try:
            served = hashlib.sha256(served_cert_der(hostname, port)).hexdigest()
            if served == expected:
                logging.info("Verified: %s is serving the deployed certificate",
                             hostname)
                return
            last = f"served {served[:16]}... != deployed {expected[:16]}..."
        except (OSError, ssl.SSLError) as exc:
            last = f"connect/TLS error: {exc}"
        elapsed = time.monotonic() - start
        logging.info("Verify attempt %d/%d for %s (%.0fs elapsed): %s",
                     attempt, attempts, hostname, elapsed, last)
        if attempt >= attempts:
            break
        if elapsed + delay >= deadline:
            last = f"{last}; stopped at {deadline:.0f}s deadline"
            break
        time.sleep(delay)
    msg = f"Verification failed: {hostname} not serving new certificate ({last})"
    raise RuntimeError(msg)


def curl_post(
    curl: str,
    url: str,
    data_file: str | None = None,
    content_type: str = "application/json",
    header_file: str | None = None,
    verbose: bool = False,
) -> subprocess.CompletedProcess[bytes]:
    """POST data with curl, reading POST body and extra headers from temp files.

    The User-Agent is set to AppleWebKit because HP's printer firmware
    rejects requests with certain other User-Agent strings.
    """
    cmd = [
        curl, "-sk", "-X", "POST", url,
        "-H", f"Content-Type: {content_type}",
        "-H", "User-Agent: AppleWebKit",
    ]
    if data_file:
        cmd += ["-d", f"@{data_file}"]
    if header_file:
        cmd += ["-H", f"@{header_file}"]
    if verbose:
        cmd.append("-v")
    sp = subprocess.run(cmd, capture_output=True, timeout=180)
    logging.info("POST %s returncode=%s stdout=%s stderr=%s",
                 url, sp.returncode,
                 sp.stdout.decode(errors="replace")[:500],
                 sp.stderr.decode(errors="replace")[:500])
    if sp.returncode != 0:
        msg = f"curl POST {url} failed with return code {sp.returncode}"
        raise RuntimeError(msg)
    return sp


def authenticate(
    curl: str,
    hostname: str,
    username: str,
    password: str,
    tmpdir: str,
    verbose: bool = False,
) -> str:
    """Authenticate to the printer's CDM OAuth2 API.

    Uses the password grant flow and returns a bearer token.
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
    data_path = os.path.join(tmpdir, "auth-data")
    with open(data_path, "w") as fp:
        fp.write(token_data)

    logging.info("AUTH: requesting token via password grant")
    sp = curl_post(curl, f"https://{hostname}/cdm/oauth2/v1/token",
                   data_file=data_path,
                   content_type="application/x-www-form-urlencoded",
                   verbose=verbose)

    try:
        result = json.loads(sp.stdout)
    except json.JSONDecodeError as exc:
        raw = sp.stdout.decode(errors="replace")[:500]
        msg = f"Authentication response is not valid JSON: {raw}"
        raise RuntimeError(msg) from exc

    logging.info("AUTH: token_type=%s scope=%s",
                 result.get("token_type"), result.get("scope"))

    token: str | None = result.get("access_token")
    if not token:
        error = result.get("error", "unknown error")
        error_desc = result.get("error_description", "")
        msg = f"Authentication failed: {error}\n  {error_desc}\n  response={result}"
        raise RuntimeError(msg)
    return token


def main() -> None:
    script_name = os.path.basename(sys.argv[0])
    hostname = script_name.removesuffix(".py")

    parser = ArgumentParser(f"{script_name} deployment script")
    parser.add_argument("--logfile", type=str,
                        default=os.path.join(LOG_DIR, f"{hostname}.log"),
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
    parser.add_argument("--no-verify", action="store_true",
                        help="Skip verifying the printer serves the new certificate")
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
                raise KeyError(name + " not in environment")

        domains = os.environ["RENEWED_DOMAINS"].split()
        lineage = os.environ["RENEWED_LINEAGE"]

        if hostname not in domains:
            logging.info("Mismatch: %s not in %s", hostname, domains)
            sys.exit(0)

        crtname = os.path.join(lineage, args.certName)
        keyname = os.path.join(lineage, args.keyName)
        config_file = os.path.abspath(os.path.expanduser(args.configFile))

        if not os.path.isfile(crtname):
            raise FileNotFoundError(crtname)
        if not os.path.isfile(keyname):
            raise FileNotFoundError(keyname)
        if not os.path.isfile(config_file):
            raise FileNotFoundError(config_file)

        with open(config_file) as fp:
            config = json.load(fp)

        admin_user: str = config.get("admin_user", "admin")
        admin_password: str | None = config.get("admin_password")
        if not admin_password:
            msg = f"admin_password not set in {config_file}"
            raise RuntimeError(msg)

        with tempfile.TemporaryDirectory() as tmpdir:
            pfx_password = secrets.token_hex(6)  # 12-char alphanumeric, printer limit
            pfx_path = os.path.join(tmpdir, "cert.pfx")

            # Convert PEM cert+key to PKCS12 using env var for password
            env = os.environ.copy()
            env["PFX_PASSOUT"] = pfx_password
            cmd = (args.openssl, "pkcs12", "-export",
                   "-out", pfx_path,
                   "-inkey", keyname,
                   "-in", crtname,
                   "-passout", "env:PFX_PASSOUT")
            sp = subprocess.run(cmd, capture_output=True, timeout=180, env=env)
            logging.info("openssl returncode=%s stdout=%s stderr=%s",
                         sp.returncode,
                         sp.stdout.decode(errors="replace")[:500],
                         sp.stderr.decode(errors="replace")[:500])
            if sp.returncode != 0:
                msg = f"openssl pkcs12 failed with return code {sp.returncode}"
                raise RuntimeError(msg)

            # Read and base64-encode the PKCS12 file
            with open(pfx_path, "rb") as fp_bin:
                pfx_data = base64.b64encode(fp_bin.read()).decode("ascii")

            # Authenticate to get a bearer token
            token = authenticate(args.curl, hostname, admin_user, admin_password,
                                 tmpdir, verbose=args.verbose)

            # Write bearer token to a temp header file
            header_path = os.path.join(tmpdir, "auth-header")
            with open(header_path, "w") as fp:
                fp.write(f"Authorization: Bearer {token}")

            # Write upload payload to a temp file
            upload_path = os.path.join(tmpdir, "upload-data")
            with open(upload_path, "w") as fp:
                json.dump({
                    "certificateData": pfx_data,
                    "certificateFormat": "pkcs12",
                    "password": pfx_password,
                    "privateKeyExportable": False,
                    "requestType": "importId",
                    "version": "1.1.0",
                }, fp)

            curl_post(args.curl,
                      f"https://{hostname}{args.uploadPath}",
                      data_file=upload_path,
                      header_file=header_path)

        if not args.no_verify:
            verify_served_certificate(hostname, crtname)

        logging.info("Deployment to %s completed successfully", hostname)
    except subprocess.TimeoutExpired as e:
        logging.error("Timed out: %s", e)
        sys.exit(1)
    except (FileNotFoundError, KeyError, RuntimeError) as e:
        logging.error("%s", e)
        sys.exit(1)
    except Exception:
        logging.exception("Unexpected error deploying to %s", hostname)
        sys.exit(1)


if __name__ == "__main__":
    main()
