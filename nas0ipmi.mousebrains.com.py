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

import base64
import hashlib
import json
import logging
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
from argparse import ArgumentParser

LOG_DIR = "/var/log"

# Post-deploy verification: the BMC reboots (~90 s) before the new certificate
# is served, so wait before the first check and then retry.
VERIFY_INITIAL_DELAY = 90.0
VERIFY_ATTEMPTS = 10
VERIFY_DELAY = 15.0
VERIFY_DEADLINE = 300.0


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
    initial_delay: float = VERIFY_INITIAL_DELAY,
    deadline: float = VERIFY_DEADLINE,
    port: int = 443,
) -> None:
    """Confirm the BMC is actually serving the just-deployed certificate.

    Compares the SHA-256 of the served leaf cert to the deployed one, retrying
    to allow the BMC reboot to finish. Raises on mismatch so a certificate
    that uploads and validates but does not survive the reset (as happened on
    2026-05-31) becomes a hard failure instead of a silent one.
    """
    expected = hashlib.sha256(leaf_cert_der(crtname)).hexdigest()
    start = time.monotonic()
    if initial_delay:
        time.sleep(initial_delay)
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
    cmd = [curl, "-sk", "--fail-with-body", "-b", cookies_file]
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
    tmpdir: str,
    verbose: bool = False,
) -> None:
    """Login to BMC web interface and store session cookie.

    The POST body is read from a temp file so credentials never appear
    on the curl command line (visible in `ps` while curl runs).
    """
    encoded_user = urllib.parse.quote(username, safe="")
    encoded_password = urllib.parse.quote(password, safe="")
    login_data_path = os.path.join(tmpdir, "login-data")
    with open(login_data_path, "w") as fp:
        fp.write(f"name={encoded_user}&pwd={encoded_password}")

    cmd = [curl, "-sk", "--fail-with-body", "-c", cookies_file, "-X", "POST",
           f"https://{hostname}/cgi/login.cgi",
           "-d", f"@{login_data_path}"]
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


def convert_key_to_pkcs1(openssl: str, key_path: str, out_path: str) -> None:
    """Rewrite a PKCS#8 RSA key as traditional PKCS#1.

    certbot writes PKCS#8 (``-----BEGIN PRIVATE KEY-----``). This BMC firmware
    validates such a key in-session but silently fails to persist it, leaving
    the stored cert paired with the old key (``SSL_VALIDATE`` = 0 in any later
    session). The traditional PKCS#1 form (``-----BEGIN RSA PRIVATE KEY-----``)
    is stored correctly.
    """
    cmd = (openssl, "rsa", "-in", key_path, "-out", out_path)
    sp = subprocess.run(cmd, capture_output=True, timeout=180)
    logging.info("openssl rsa (PKCS#1) returncode=%s stderr=%s",
                 sp.returncode, sp.stderr.decode(errors="replace")[:500])
    if sp.returncode != 0:
        msg = f"openssl rsa PKCS#1 conversion failed with return code {sp.returncode}"
        raise RuntimeError(msg)


def upload_certificate(
    curl: str,
    hostname: str,
    cert_path: str,
    key_path: str,
    cookies_file: str,
    csrf_token: str,
    verbose: bool = False,
) -> None:
    """Upload certificate and key via the BMC's SSL upload CGI.

    The files are uploaded without a forced MIME type, matching the browser
    and known-working community scripts. Tagging the private key as
    ``application/x-x509-ca-cert`` (as this hook originally did) makes the BMC
    store the certificate but silently drop the key, leaving a mismatched pair
    that fails ``SSL_VALIDATE`` in any later session.
    """
    logging.info("UPLOAD: sending certificate to %s", hostname)
    cert_field = f"@{cert_path}"
    key_field = f"@{key_path}"
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
    ipmitool: str,
    hostname: str,
    username: str,
    password: str,
    verbose: bool = False,
) -> None:
    """Cold-reset the BMC over IPMI-over-LAN to activate the new certificate.

    The web UI's warm reset (``op=main_bmcreset``) uploads and stores the new
    certificate but does not re-load it, so the BMC keeps serving the previous
    cert. A cold reset (``mc reset cold``) makes it pick up the stored cert.
    The password is passed via the ``IPMI_PASSWORD`` environment variable so it
    never appears on the command line (visible in ``ps``).
    """
    logging.info("RESET: cold-resetting BMC via IPMI to activate certificate")
    env = os.environ.copy()
    env["IPMI_PASSWORD"] = password
    cmd = [ipmitool, "-I", "lanplus", "-H", hostname, "-U", username, "-E",
           "mc", "reset", "cold"]
    sp = subprocess.run(cmd, capture_output=True, timeout=180, env=env)
    logging.info("IPMI cold reset returncode=%s stdout=%s stderr=%s",
                 sp.returncode,
                 sp.stdout.decode(errors="replace")[:500],
                 sp.stderr.decode(errors="replace")[:500])
    if sp.returncode != 0:
        msg = f"IPMI cold reset failed with return code {sp.returncode}"
        raise RuntimeError(msg)


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
    parser.add_argument("--openssl", type=str, default="/usr/bin/openssl",
                        help="OpenSSL command to use")
    parser.add_argument("--ipmitool", type=str, default="/usr/bin/ipmitool",
                        help="ipmitool command (used for the cold reset)")
    parser.add_argument("--no-reset", action="store_true",
                        help="Skip BMC reset after upload (cert won't take effect)")
    parser.add_argument("--no-verify", action="store_true",
                        help="Skip verifying the BMC serves the new certificate")
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

            # The BMC persists only a traditional PKCS#1 RSA key, so convert
            # certbot's PKCS#8 key before uploading it.
            pkcs1_key = os.path.join(tmpdir, "privkey_pkcs1.pem")
            convert_key_to_pkcs1(args.openssl, keyname, pkcs1_key)

            bmc_login(args.curl, hostname, admin_user, admin_password,
                      cookies_file, tmpdir, verbose=args.verbose)
            csrf_token = get_csrf_token(args.curl, hostname, cookies_file,
                                        verbose=args.verbose)
            upload_certificate(args.curl, hostname, crtname, pkcs1_key,
                               cookies_file, csrf_token, verbose=args.verbose)
            validate_certificate(args.curl, hostname, cookies_file,
                                 csrf_token, verbose=args.verbose)

            if not args.no_reset:
                bmc_reset(args.ipmitool, hostname, admin_user, admin_password,
                          verbose=args.verbose)
                logging.info("BMC cold reset triggered; certificate will be "
                             "active after reboot (~90 seconds)")

        # The upload can validate yet fail to persist across the reset, so
        # confirm the BMC actually serves the new cert once it is back up.
        if not args.no_reset and not args.no_verify:
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
