#! /usr/bin/python3
#
# Certbot deploy hook for Supermicro BMC (IPMI) via the web interface.
#
# Authenticates via the BMC's CGI login, uploads cert and key through
# the SSL upload endpoint, validates the certificate, triggers a BMC
# reset to apply the change, and logs out.
#
# Requires RSA certificates; ECDSA keys are not supported by the BMC.
#
# See README.nas0ipmi.md for setup instructions.
#
# Mar-2026 Pat Welch pat@mousebrains.com

import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import urllib.parse
from argparse import ArgumentParser

LOG_DIR = "/var/log"


def curl_request(
    curl: str,
    url: str,
    cookies_file: str,
    method: str = "GET",
    form_fields: list[tuple[str, str]] | None = None,
    post_data: str | None = None,
    headers: dict[str, str] | None = None,
    verbose: bool = False,
) -> subprocess.CompletedProcess[bytes]:
    """Make an HTTP request with curl using cookie-based session auth."""
    cmd = [curl, "-sk", "-b", cookies_file]
    if method == "POST" and not form_fields:
        cmd += ["-X", "POST"]
    if form_fields:
        for name, value in form_fields:
            cmd += ["-F", f"{name}={value}"]
    if post_data:
        cmd += ["-d", post_data]
    if headers:
        for key, value in headers.items():
            cmd += ["-H", f"{key}: {value}"]
    if verbose:
        cmd.append("-v")
    cmd.append(url)
    sp = subprocess.run(cmd, capture_output=True, timeout=180)
    logging.info("%s %s returncode=%s stdout=%s stderr=%s",
                 method, url, sp.returncode,
                 sp.stdout.decode(errors="replace")[:500],
                 sp.stderr.decode(errors="replace")[:500])
    if sp.returncode != 0:
        msg = f"curl {method} {url} failed with return code {sp.returncode}"
        raise RuntimeError(msg)
    return sp


def bmc_login(
    curl: str,
    hostname: str,
    username: str,
    password: str,
    cookies_file: str,
    verbose: bool = False,
) -> None:
    """Login to BMC web interface and store session cookie."""
    encoded_password = urllib.parse.quote(password, safe="")
    cmd = [curl, "-sk", "-c", cookies_file, "-X", "POST",
           f"https://{hostname}/cgi/login.cgi",
           "-d", f"name={username}&pwd={encoded_password}"]
    if verbose:
        cmd.append("-v")
    sp = subprocess.run(cmd, capture_output=True, timeout=180)
    logging.info("LOGIN returncode=%s stdout=%s stderr=%s",
                 sp.returncode,
                 sp.stdout.decode(errors="replace")[:500],
                 sp.stderr.decode(errors="replace")[:500])
    if sp.returncode != 0:
        msg = f"BMC login failed with return code {sp.returncode}"
        raise RuntimeError(msg)


def get_csrf_token(
    curl: str,
    hostname: str,
    cookies_file: str,
    verbose: bool = False,
) -> str:
    """Fetch the SSL configuration page and extract the CSRF token."""
    sp = curl_request(curl,
                      f"https://{hostname}/cgi/url_redirect.cgi?url_name=config_ssl",
                      cookies_file, verbose=verbose)
    html = sp.stdout.decode(errors="replace")
    match = re.search(r'CSRF-TOKEN",\s*"([^"]+)"', html)
    if not match:
        msg = "Could not extract CSRF token from SSL config page"
        raise RuntimeError(msg)
    token = match.group(1)
    logging.info("CSRF token obtained")
    return token


def upload_certificate(
    curl: str,
    hostname: str,
    cert_path: str,
    key_path: str,
    cookies_file: str,
    csrf_token: str,
    verbose: bool = False,
) -> None:
    """Upload certificate and key via the BMC's SSL upload CGI."""
    logging.info("UPLOAD: sending certificate to %s", hostname)
    cert_field = f"@{cert_path};type=application/x-x509-ca-cert"
    key_field = f"@{key_path};type=application/x-x509-ca-cert"
    curl_request(curl, f"https://{hostname}/cgi/upload_ssl.cgi",
                 cookies_file, method="POST",
                 form_fields=[
                     ("cert_file", cert_field),
                     ("key_file", key_field),
                     ("CSRF-TOKEN", csrf_token),
                 ], verbose=verbose)


def validate_certificate(
    curl: str,
    hostname: str,
    cookies_file: str,
    csrf_token: str,
    verbose: bool = False,
) -> None:
    """Check that the BMC accepted the uploaded certificate."""
    sp = curl_request(curl, f"https://{hostname}/cgi/ipmi.cgi",
                      cookies_file, post_data="op=SSL_VALIDATE.XML&r=(0,0)",
                      headers={"CSRF-TOKEN": csrf_token}, verbose=verbose)
    response = sp.stdout.decode(errors="replace")
    match = re.search(r'VALIDATE="(\d+)"', response)
    if not match or match.group(1) != "1":
        msg = f"Certificate validation failed: {response[:500]}"
        raise RuntimeError(msg)
    logging.info("VALIDATE: certificate accepted by BMC")


def bmc_reset(
    curl: str,
    hostname: str,
    cookies_file: str,
    csrf_token: str,
    verbose: bool = False,
) -> None:
    """Trigger a BMC reset to apply the new certificate."""
    logging.info("RESET: triggering BMC reset")
    curl_request(curl, f"https://{hostname}/cgi/ipmi.cgi",
                 cookies_file, post_data="op=main_bmcreset",
                 headers={"CSRF-TOKEN": csrf_token}, verbose=verbose)


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
                        default="~pat/.config/nas0ipmi.json",
                        help="JSON config file with admin_user and admin_password")
    parser.add_argument("--curl", type=str, default="/usr/bin/curl",
                        help="curl command to use")
    parser.add_argument("--no-reset", action="store_true",
                        help="Skip BMC reset after upload (cert won't take effect)")
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
            cookies_file = os.path.join(tmpdir, "cookies")

            bmc_login(args.curl, hostname, admin_user, admin_password,
                      cookies_file, verbose=args.verbose)
            csrf_token = get_csrf_token(args.curl, hostname, cookies_file,
                                        verbose=args.verbose)
            upload_certificate(args.curl, hostname, crtname, keyname,
                               cookies_file, csrf_token, verbose=args.verbose)
            validate_certificate(args.curl, hostname, cookies_file,
                                 csrf_token, verbose=args.verbose)

            if not args.no_reset:
                bmc_reset(args.curl, hostname, cookies_file, csrf_token,
                          verbose=args.verbose)
                logging.info("BMC reset triggered; certificate will be active "
                             "after reboot (~90 seconds)")

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
