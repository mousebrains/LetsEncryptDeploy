#! /usr/bin/python3
#
# Certbot deploy hook for UISP (uisp.mousebrains.com)
#
# Designed to be run by certbot from /etc/letsencrypt/renewal-hooks/deploy
# to deploy a renewed certificate. It will be run as the root user.
#
# SCPs fullchain.pem and privkey.pem to the UISP host's certificate directory,
# then SSHes in to restart the UISP service so it picks up the new cert.
#
# Sep-2025, Pat Welch, pat@mousebrains.com

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

        # SCP cert and key to the UISP host's certificate directory
        cmd = (
                args.scp,
                crtname,
                keyname,
                hostname + ":" + args.certDir + "/",
                )
        sp = subprocess.run(cmd, shell=False, capture_output=True, timeout=180)
        logging.info("SCP returncode=%s stdout=%s stderr=%s",
                     sp.returncode,
                     sp.stdout.decode(errors="replace"),
                     sp.stderr.decode(errors="replace"))
        if sp.returncode != 0:
            raise RuntimeError(f"SCP failed with return code {sp.returncode}: {sp.stderr.decode(errors='replace')}")

        # Restart UISP to pick up the new certificate
        cmd = (
                args.ssh,
                hostname,
                args.reload,
                )
        sp = subprocess.run(cmd, shell=False, capture_output=True, timeout=args.reloadTimeout)
        logging.info("SSH returncode=%s stdout=%s stderr=%s",
                     sp.returncode,
                     sp.stdout.decode(errors="replace"),
                     sp.stderr.decode(errors="replace"))
        if sp.returncode != 0:
            raise RuntimeError(f"SSH reload failed with return code {sp.returncode}: {sp.stderr.decode(errors='replace')}")

        logging.info("Deployment to %s completed successfully", hostname)
    except (FileNotFoundError, KeyError, RuntimeError) as e:
        logging.error("%s", e)
        sys.exit(1)
    except Exception:
        logging.exception("GotMe")
        sys.exit(1)

if __name__ == "__main__":
    main()
