#! /usr/bin/python3
#
# This script is designed to install a renewed certificate and key on
# a UniFi Fiber Gateway.
#
# On your letsencrypt host:
#  1) In your root account create a SSH key pair
#  2) update /root/.ssh/config with the target Unifi Gateway information
#
# On the Unifi Gateway:
#  A) Enable SSH
#  B) Log into the Unifi Gateway and add your public SSH key you'll be using into
#     the authorized_keys file.
#
# On your letsencrypt host, where fqdn is the UniFi gateway fully qualified hostname:
#  3) scp /etc/letsencrypt/live/fqdn/fullchain.pem /etc/letsencrypt/live/fqdn/privkey.pem fqdn:
#
# On the UniFi Gateway:
#  C) cd /data/unifi-core/config
#  D) There will be a certificate file like bf800083-907e-44b4-af66-0a0a92fe9acc.crt
#     and a key file bf800083-907e-44b4-af66-0a0a92fe9acc.key
#     The bf800 portion is the UUID, I think
#     Copy these files for backup,
#        cp bf800083-907e-44b4-af66-0a0a92fe9acc.crt bf800083-907e-44b4-af66-0a0a92fe9acc.crt.bak
#        cp bf800083-907e-44b4-af66-0a0a92fe9acc.key bf800083-907e-44b4-af66-0a0a92fe9acc.key.bak
#     Now make a symbolic link to the new LetsEncrypt certificate and key:
#        ln -sf /root/fullchain.pem bf800083-907e-44b4-af66-0a0a92fe9acc.crt
#        ln -sf /root/privkey.pem bf800083-907e-44b4-af66-0a0a92fe9acc.key
#  E) Now reload the certificate:
#     nginx -s reload
#
# Install this script on your letsencrypt host in /etc/letsencrypt/renewal-hooks/deploy
# The script should run on the next renewal and install the updated certificate and key,
# and force the webserver to reload them.
#
# The name of the script should be the FQDN of the UniFi Gateway (with .py extension)
#  
# Jan-2026 Pat Welch pat@mousebrains.com

logDir = "/var/log"

from argparse import ArgumentParser
import logging
import os
import sys
import subprocess

if __name__ == "__main__":
    scriptName = os.path.basename(sys.argv[0]) # This script's name
    hostname = scriptName.removesuffix(".py")

    parser = ArgumentParser(f"{scriptName} deployment script")
    parser.add_argument("--logfile", type=str,
                        default=os.path.join(logDir, f"{hostname}.log"),
                        help="Where to log to")
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

        crtname = os.path.abspath(os.path.expanduser(os.path.join(lineage, args.certName)))
        keyname = os.path.abspath(os.path.expanduser(os.path.join(lineage, args.keyName)))

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
        sp = subprocess.run(cmd, shell=False, capture_output=True, timeout=180)
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
        sp = subprocess.run(cmd, shell=False, capture_output=True, timeout=180)
        logging.info("SSH returncode=%s stdout=%s stderr=%s",
                     sp.returncode,
                     sp.stdout.decode(errors="replace"),
                     sp.stderr.decode(errors="replace"))
        if sp.returncode != 0:
            raise RuntimeError(f"SSH reload failed with return code {sp.returncode}: {sp.stderr.decode(errors='replace')}")

        logging.info("Deployment to %s completed successfully", hostname)
    except Exception:
        logging.exception("GotMe")
        sys.exit(1)

