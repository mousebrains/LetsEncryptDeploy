#! /usr/bin/python3
#
# Certbot deploy hook for UISP.
#
# SCPs fullchain.pem and privkey.pem to the UISP host's certificate directory,
# then SSHes in to restart the UISP service so it picks up the new cert.
#
# See README.uisp.md for setup instructions.
#
# Sep-2025 Pat Welch pat@mousebrains.com

import base64
import hashlib
import logging
import os
import socket
import ssl
import subprocess
import sys
import time
from argparse import ArgumentParser

LOG_DIR = "/var/log"

# Post-deploy verification: UISP restarts its stack, so allow a wide window for
# the web frontend to come back up serving the new certificate.
VERIFY_ATTEMPTS = 12
VERIFY_DELAY = 10.0
VERIFY_DEADLINE = 180.0


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
    """Confirm the host is actually serving the just-deployed certificate.

    Compares the SHA-256 of the served leaf cert to the deployed one, retrying
    to allow the service to restart. Raises on mismatch so a deploy that does
    not take effect becomes a hard failure.
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
    parser.add_argument("--certDir", type=str,
                        default=f"/etc/certificates/{hostname}",
                        help="Remote directory for certificate files on the UISP host")
    parser.add_argument("--reload", type=str,
                        default="app/unms-cli restart",
                        help="Command to restart UISP on the remote host")
    parser.add_argument("--reloadTimeout", type=int, default=600,
                        help="Timeout in seconds for the reload command")
    parser.add_argument("--ssh", type=str, default="/usr/bin/ssh", help="SSH command to use")
    parser.add_argument("--scp", type=str, default="/usr/bin/scp", help="SCP command to use")
    parser.add_argument("--no-verify", action="store_true",
                        help="Skip verifying the host serves the new certificate")
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

        if not os.path.isfile(crtname):
            raise FileNotFoundError(crtname)
        if not os.path.isfile(keyname):
            raise FileNotFoundError(keyname)

        # SCP cert and key to the UISP host's certificate directory
        scp_cmd = (args.scp, crtname, keyname, hostname + ":" + args.certDir + "/")
        sp = subprocess.run(scp_cmd, capture_output=True, timeout=180)
        logging.info("SCP returncode=%s stdout=%s stderr=%s",
                     sp.returncode,
                     sp.stdout.decode(errors="replace")[:500],
                     sp.stderr.decode(errors="replace")[:500])
        if sp.returncode != 0:
            msg = f"SCP failed with return code {sp.returncode}"
            raise RuntimeError(msg)

        # Restart UISP to pick up the new certificate
        ssh_cmd = (args.ssh, hostname, args.reload)
        sp = subprocess.run(ssh_cmd, capture_output=True, timeout=args.reloadTimeout)
        logging.info("SSH returncode=%s stdout=%s stderr=%s",
                     sp.returncode,
                     sp.stdout.decode(errors="replace")[:500],
                     sp.stderr.decode(errors="replace")[:500])
        if sp.returncode != 0:
            msg = f"SSH reload failed with return code {sp.returncode}"
            raise RuntimeError(msg)

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
