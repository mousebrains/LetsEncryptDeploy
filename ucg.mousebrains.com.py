#! /usr/bin/python3
#
# Certbot deploy hook for UniFi Cloud Gateway.
#
# SCPs fullchain.pem and privkey.pem to the gateway, then reloads nginx
# via SSH to pick up the new certificate.
#
# See README.ucg.md for setup instructions.
#
# Jan-2026 Pat Welch pat@mousebrains.com

from argparse import ArgumentParser
import logging
import os
import subprocess
import sys

logDir = "/var/log"

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
    parser.add_argument("--reload", type=str,
                        default="/usr/sbin/nginx -s reload",
                        help="How to force reloading the new certificate on the UniFi system.")
    parser.add_argument("--ssh", type=str, default="/usr/bin/ssh", help="SSH command to use")
    parser.add_argument("--scp", type=str, default="/usr/bin/scp", help="SCP command to use")
    args = parser.parse_args()

    logfilename = None
    if args.logfile:
        logfilename = os.path.abspath(os.path.expanduser(args.logfile))
        logdirname = os.path.dirname(logfilename)
        if not os.path.isdir(logdirname):
            os.makedirs(logdirname, exist_ok=True) # For race issues

    logging.basicConfig(filename=logfilename,
                        level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s: %(message)s",
                        )
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

        if not os.path.isfile(crtname):
            raise FileNotFoundError(f"Certificate file not found: {crtname}")
        if not os.path.isfile(keyname):
            raise FileNotFoundError(f"Key file not found: {keyname}")

        cmd = (
                args.scp,
                crtname,
                keyname,
                hostname + ":",
                )
        sp = subprocess.run(cmd, capture_output=True, timeout=180)
        logging.info("SCP returncode=%s stdout=%s stderr=%s",
                     sp.returncode,
                     sp.stdout.decode(errors="replace"),
                     sp.stderr.decode(errors="replace"))
        if sp.returncode != 0:
            raise RuntimeError(f"SCP failed with return code {sp.returncode}: {sp.stderr.decode(errors='replace')}")

        cmd = (
                args.ssh,
                hostname,
                args.reload,
                )
        sp = subprocess.run(cmd, capture_output=True, timeout=180)
        logging.info("SSH returncode=%s stdout=%s stderr=%s",
                     sp.returncode,
                     sp.stdout.decode(errors="replace"),
                     sp.stderr.decode(errors="replace"))
        if sp.returncode != 0:
            raise RuntimeError(f"SSH reload failed with return code {sp.returncode}: {sp.stderr.decode(errors='replace')}")

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

