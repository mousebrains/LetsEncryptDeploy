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
from argparse import ArgumentParser

LOG_DIR = "/var/log"

# Post-deploy verification: how long to wait for the printer to start serving
# the new certificate (the EWS briefly restarts HTTPS after an import).
VERIFY_ATTEMPTS = 6
VERIFY_DELAY = 10.0
VERIFY_DEADLINE = 120.0


def curl_post(
    curl: str,
    url: str,
    netrc_file: str | None = None,
    cookies_file: str | None = None,
    data: str | None = None,
    extra_args: list[str] | None = None,
    verbose: bool = False,
) -> subprocess.CompletedProcess[bytes]:
    """POST with curl using a netrc file for authentication.

    ``--fail-with-body`` makes curl exit non-zero on an HTTP >= 400 response
    (e.g. the 405 the printer used to return) while still capturing the body
    for the log, so a rejected upload is no longer reported as success.

    ``-X POST`` is deliberately NOT used: steps 1 and 2 answer with ``303 See
    Other`` and forcing POST would make curl re-POST the redirect target and
    get a 405. Letting curl follow the 303 as a GET (the RFC behaviour) keeps
    the wizard's session cookie flowing through the ``cookies_file`` jar.
    """
    cmd = [curl, "-sk", "--fail-with-body", "-L", url]
    if cookies_file:
        cmd += ["-c", cookies_file, "-b", cookies_file]
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
        msg = f"curl POST {url} failed with return code {sp.returncode}"
        raise RuntimeError(msg)
    return sp


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
    initial_delay: float = 0.0,
    deadline: float = VERIFY_DEADLINE,
    port: int = 443,
) -> None:
    """Confirm the device is actually serving the just-deployed certificate.

    Compares the SHA-256 of the served leaf cert to the deployed one, retrying
    to allow the device to restart its web server. Raises on mismatch so a
    silently-ignored upload becomes a hard failure.
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


def upload_certificate(
    curl: str,
    hostname: str,
    pfx_path: str,
    pfx_password_file: str,
    netrc_file: str,
    cookies_file: str,
    verbose: bool = False,
) -> None:
    """Upload certificate through the EWS form-based flow.

    The three steps navigate the printer's certificate wizard; the session is
    carried across them via *cookies_file*. The PKCS12 password is read from
    *pfx_password_file* via curl's ``-F name=<file`` form so it never appears
    on the command line.

    Field names come from the live EWS import form served by the M452dn's
    Virata-EmWeb firmware: the file field is ``FileName``, the password field
    is ``Password``, and ``Finish`` is the submit button.
    """
    base_url = f"https://{hostname}"

    # Step 1: Navigate to certificate configuration (303 -> Configure page)
    logging.info("Step 1: Navigating to certificate configuration page")
    curl_post(curl, f"{base_url}/hp/device/set_config_networkCerts.html/config",
              data="ConfigurePrintCert=Configure",
              netrc_file=netrc_file, cookies_file=cookies_file, verbose=verbose)

    # Step 2: Select import certificate option (303 -> import form)
    logging.info("Step 2: Selecting import certificate option")
    curl_post(curl, f"{base_url}/hp/device/set_config_networkPrintCerts.html/config",
              data="ConfigOpt=ImptCert&Next=Next",
              netrc_file=netrc_file, cookies_file=cookies_file, verbose=verbose)

    # Step 3: Upload the PKCS12 file via multipart form
    logging.info("Step 3: Uploading PKCS12 certificate")
    curl_post(curl, f"{base_url}/hp/device/Certificate.pfx",
              netrc_file=netrc_file, cookies_file=cookies_file, verbose=verbose,
              extra_args=[
                  "-F", f"FileName=@{pfx_path};filename=Certificate.pfx",
                  "-F", f"Password=<{pfx_password_file}",
                  "-F", "Finish=",
              ])

    logging.info("Certificate upload completed")


def main() -> None:
    script_name = os.path.basename(sys.argv[0])
    hostname = script_name.removesuffix(".py")

    parser = ArgumentParser(f"{script_name} deployment script")
    parser.add_argument("--logfile", type=str,
                        default=os.path.join(LOG_DIR, f"{hostname}.log"),
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
            # Create netrc file for curl authentication
            netrc_path = os.path.join(tmpdir, "netrc")
            with open(netrc_path, "w") as fp:
                fp.write(f"machine {hostname} login {admin_user} password {admin_password}\n")

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

            # Write the PFX password to a temp file so it doesn't appear
            # on the curl command line
            pfx_pw_path = os.path.join(tmpdir, "pfx-password")
            with open(pfx_pw_path, "w") as fp:
                fp.write(pfx_password)

            # Upload the certificate
            cookies_path = os.path.join(tmpdir, "cookies")
            upload_certificate(args.curl, hostname, pfx_path, pfx_pw_path,
                               netrc_path, cookies_path, verbose=args.verbose)

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
