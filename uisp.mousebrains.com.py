#! /usr/bin/env python3
#
# UISP.mousebrains.com
#
# Designed to be run by certbot from /etc/letsencrypt/renwal-hooks/deploy and deploy
# a newly renewe certificate. It will be run as the root user.
#
# Sep-2025, Pat Welch, pat@mousebrains.com

hostname = "uisp.mousebrains.com" # Target certificate/hostname
logDir = "~pat/logs" # Where to put log files

crtName = "fullchain.pem" # Which cert file should we use
keyName = "privkey.pem" # Which key file should we use, None indicates not to copy


from argparse import ArgumentParser
import os
import logging
import sys
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
from cryptography.hazmat.primitives.serialization import pkcs12
import paramiko # For SSH

def mkPkcs12(fnCrt:str, fnKey:str, name:str, password=str) -> bytes:
    with open(fnCrt, "rb") as fp:
        cert = load_pem_x509_certificate(fp.read())
    with open(fnKey, "rb") as fp:
        key = load_pem_private_key(
                fp.read(),
                password=None, # No password needed for unencrypted keys
                )

    p12 = pkcs12.serialize_key_and_certificates(
            name=name.encode("utf-8"),
            key=key,
            cert=cert,
            cas=None,
            encryption_algorithm=BestAvailableEncryption(password.encode("utf-8")),
            )
    return p12

def deployIt(fnCrt:str, fnKey:str, hostname:str, args:ArgumentParser) -> None:
    p12 = mkPkcs12(fnCrt, fnKey, hostname)

    logging.info("Deploy %s %s", fnCrt, fnKey)
    logging.info("P12 %s %s", len(p12), type(p12))

    with paramiko.SSHClient() as client:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=hostname)


parser = ArgumentParser(f"{hostname} deployment script")
parser.add_argument("--logfile", type=str, default=f"{logDir}/{hostname}.log",
                    help="Where to log to, empty goes to stdout")
parser.add_argument("--verbose", action="store_true", help="Enable logging.debug messages")
parser.add_argument("--fqdn", type=str, help="Fully qualified domain name")
parser.add_argument("--liveDir", type=str, default="/etc/letsencrypt/live", 
                    help="Where live certificates are stored.")
parser.add_argument("--certName", type=str, help="Which certificate file to use")
parser.add_argument("--keyName", type=str, help="Which key file to use")
parser.add_argument("--ssh", type=str, default="/usr/bin/ssh", help="Which ssh binary to use")
parser.add_argument("--scp", type=str, default="/usr/bin/scp", help="Which ssh binary to use")
args = parser.parse_args()

if args.fqdn: hostname = args.fqdn

if args.certName: crtName = args.certName
if args.keyName: keyName = args.keyName

logfilename = None
if args.logfile and len(args.logfile):
    logfilename = os.path.abspath(os.path.expanduser(args.logfile))
    dirname = os.path.dirname(logfilename)
    if not os.path.isdir(dirname):
        os.makedirs(dirname, exist_ok=True)

logging.basicConfig(filename=logfilename, 
                    level=logging.DEBUG if args.verbose else logging.INFO,
                    format="%(asctime)s %(levelname)s: %(message)s",
                    )

try:
    logging.debug("Args: %s", args)

    if "RENEWED_DOMAINS" in os.environ:
        domains = os.environ["RENEWED_DOMAINS"].split()
        if hostname not in domains:
            logging.info("%s is not in RENEWED_DOMAINS, %s", hostname, domains)
            sys.exit(0)

    if "RENEWED_LINEAGE" in os.environ:
        liveDir = os.environ["RENEWED_LINEAGE"]
    else:
        liveDir = os.path.join(args.liveDir, hostname)

    if not os.path.isdir(liveDir): 
        raise FileNotFoundError(f"Live directory '{liveDir}' does not exist")

    crtFilename = os.path.join(liveDir, crtName)
    keyFilename = os.path.join(liveDir, keyName)

    if not os.path.isfile(crtFilename): 
        raise FileNotFound(f"Certificate '{crtFilename}' does not exist")

    if keyFilename and not os.path.isfile(keyFilename): 
        raise FileNotFound(f"Key '{keyFilename}' does not exist")

    deployIt(crtFilename, keyFilename, hostname, args)
except SystemExit as e:
    pass
except:
    logging.exception("Args:%s\nEnviron: %s", args, os.environ)
