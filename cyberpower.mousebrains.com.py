#! /usr/bin/python3
#
# Certbot deploy hook for CyberPower UPS with RMCARD205.
#
# Authenticates via the RMCARD205 REST API, uploads a combined
# PEM file (fullchain + privkey), and logs out to apply the change.
#
# See README.cyberpower.md for setup instructions.
#
# Mar-2026 Pat Welch pat@mousebrains.com

import json
import logging
import os
import subprocess
import sys
import tempfile
from argparse import ArgumentParser

LOG_DIR = "/var/log"


def curl_request(
    curl: str,
    method: str,
    url: str,
    data_file: str | None = None,
    form_file: str | None = None,
    token: str | None = None,
    verbose: bool = False,
) -> subprocess.CompletedProcess[bytes]:
    """Make an HTTP request with curl, reading POST body from a temp file."""
    cmd = [curl, "-sk", "-X", method, url]
    if data_file:
        cmd += ["-d", f"@{data_file}"]
    if form_file:
        cmd += ["-F", f"upfile=@{form_file}"]
    if token:
        cmd += ["-H", f"Authorization: Bearer {token}"]
    if verbose:
        cmd.append("-v")
    sp = subprocess.run(cmd, capture_output=True, timeout=180)
    logging.info("%s %s returncode=%s stdout=%s stderr=%s",
                 method, url, sp.returncode,
                 sp.stdout.decode(errors="replace")[:500],
                 sp.stderr.decode(errors="replace")[:500])
    if sp.returncode != 0:
        msg = f"curl {method} {url} failed with return code {sp.returncode}"
        raise RuntimeError(msg)
    return sp


def parse_response(sp: subprocess.CompletedProcess[bytes], context: str) -> dict[str, object]:
    """Parse a JSON response from the RMCARD205 API."""
    try:
        result: dict[str, object] = json.loads(sp.stdout)
        return result
    except json.JSONDecodeError as exc:
        raw = sp.stdout.decode(errors="replace")[:500]
        msg = f"{context}: response is not valid JSON: {raw}"
        raise RuntimeError(msg) from exc


def login(
    curl: str,
    hostname: str,
    username: str,
    password: str,
    tmpdir: str,
    verbose: bool = False,
) -> str:
    """Two-step login to get a session token.

    Step 1: POST /api/login/ with credentials to get a temp_token.
    Step 2: GET /api/login/status/ with the temp_token to get the session token.
    """
    # Write credentials to temp file to avoid exposure on command line
    creds_path = os.path.join(tmpdir, "creds")
    with open(creds_path, "w") as fp:
        json.dump({"username": username, "passwd": password}, fp)

    logging.info("LOGIN: requesting temp token")
    sp = curl_request(curl, "POST", f"https://{hostname}/api/login/",
                      data_file=creds_path, verbose=verbose)
    result = parse_response(sp, "Login")

    temp_token = str(result["temp_token"]) if "temp_token" in result else None
    if not temp_token:
        msg = f"Login failed: no temp_token in response: {result}"
        raise RuntimeError(msg)

    logging.info("LOGIN: verifying temp token")
    sp = curl_request(curl, "GET", f"https://{hostname}/api/login/status/",
                      token=temp_token, verbose=verbose)
    result = parse_response(sp, "Login verify")

    if result.get("result") != "success":
        msg = f"Login verification failed: {result}"
        raise RuntimeError(msg)

    token = str(result["token"])
    logging.info("LOGIN: authenticated, expires_in=%s", result.get("expires_in"))
    return token


def upload_certificate(
    curl: str,
    hostname: str,
    combined_path: str,
    token: str,
    verbose: bool = False,
) -> None:
    """Upload combined PEM (fullchain + privkey) to the RMCARD205."""
    logging.info("UPLOAD: sending certificate to %s", hostname)
    sp = curl_request(curl, "POST",
                      f"https://{hostname}/api/network/web/https/upload/cert/",
                      form_file=combined_path, token=token, verbose=verbose)
    result = parse_response(sp, "Certificate upload")

    if result.get("result") != "success":
        msg = f"Certificate upload failed: {result}"
        raise RuntimeError(msg)
    logging.info("UPLOAD: %s", result.get("msg", "success"))


def logout(
    curl: str,
    hostname: str,
    token: str,
    tmpdir: str,
    verbose: bool = False,
) -> None:
    """Logout to apply the certificate change."""
    data_path = os.path.join(tmpdir, "logout")
    with open(data_path, "w") as fp:
        json.dump({"logout": "true"}, fp)

    logging.info("LOGOUT: logging out to apply changes")
    curl_request(curl, "PUT", f"https://{hostname}/api/logout/",
                 data_file=data_path, token=token, verbose=verbose)


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
                        default="~pat/.config/cyberpower.json",
                        help="JSON config file with admin_user and admin_password")
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
            # Concatenate fullchain + privkey into a single PEM file
            combined_path = os.path.join(tmpdir, "combined.pem")
            with open(combined_path, "wb") as out:
                for src in (crtname, keyname):
                    with open(src, "rb") as inp:
                        out.write(inp.read())

            token = login(args.curl, hostname, admin_user, admin_password,
                          tmpdir, verbose=args.verbose)
            upload_certificate(args.curl, hostname, combined_path, token,
                               verbose=args.verbose)
            logout(args.curl, hostname, token, tmpdir, verbose=args.verbose)

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
