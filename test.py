#! /usr/bin/python3
#
# Test a deploy hook script locally without renewing the certificate.
#
# Usage: sudo python3 test.py <hostname> [deploy-hook-args...]
#   e.g. sudo python3 test.py ljscan.mousebrains.com
#        sudo python3 test.py ljscan.mousebrains.com --logfile ""
#
# Mar-2026 Pat Welch pat@mousebrains.com

import os
import subprocess
import sys


def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <hostname> [deploy-hook-args...]", file=sys.stderr)
        sys.exit(1)

    hostname = sys.argv[1].removesuffix(".py")
    extra_args = sys.argv[2:]

    if os.geteuid() != 0:
        print(f"This script must be run as root. Try:\n"
              f"  sudo python3 {' '.join(sys.argv)}", file=sys.stderr)
        sys.exit(1)

    script_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    script = os.path.join(script_dir, f"{hostname}.py")
    if not os.path.isfile(script):
        print(f"Deploy script not found: {script}", file=sys.stderr)
        sys.exit(1)

    lineage = f"/etc/letsencrypt/live/{hostname}"
    if not os.path.isdir(lineage):
        print(f"Certificate directory not found: {lineage}", file=sys.stderr)
        sys.exit(1)

    env = os.environ.copy()
    env["RENEWED_DOMAINS"] = hostname
    env["RENEWED_LINEAGE"] = lineage

    cmd = [sys.executable, script, "--verbose", *extra_args]
    print(f"Running {' '.join(cmd)}")
    print(f"  RENEWED_DOMAINS={hostname}")
    print(f"  RENEWED_LINEAGE={lineage}")
    print()

    try:
        sp = subprocess.run(cmd, env=env, timeout=900)
        returncode = sp.returncode
    except subprocess.TimeoutExpired:
        print(f"ERROR: {script} timed out after 900 seconds", file=sys.stderr)
        returncode = 1

    print()
    logfile = f"/var/log/{hostname}.log"
    if os.path.isfile(logfile):
        print(f"--- Last 20 lines of {logfile} ---")
        with open(logfile) as fp:
            lines = fp.readlines()
            for line in lines[-20:]:
                print(line, end="")
    else:
        print(f"Log file not found: {logfile}")

    sys.exit(returncode)


if __name__ == "__main__":
    main()
