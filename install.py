#! /usr/bin/python3
#
# Install deploy hook scripts into certbot's renewal-hooks/deploy directory.
#
# Usage: sudo python3 install.py [hostname[.py] ...]
#   e.g. sudo python3 install.py ljscan.mousebrains.com
#        sudo python3 install.py                          # installs all hooks
#
# Mar-2026 Pat Welch pat@mousebrains.com

import glob
import os
import shutil
import sys

deployDir = "/etc/letsencrypt/renewal-hooks/deploy"

def main():
    if os.geteuid() != 0:
        print(f"This script must be run as root. Try:\n"
              f"  sudo python3 {' '.join(sys.argv)}", file=sys.stderr)
        sys.exit(1)

    if not os.path.isdir(deployDir):
        print(f"Deploy directory not found: {deployDir}", file=sys.stderr)
        sys.exit(1)

    scriptDir = os.path.dirname(os.path.abspath(sys.argv[0]))

    if len(sys.argv) > 1:
        # Install specific scripts
        scripts = [f"{arg.removesuffix('.py')}.py" for arg in sys.argv[1:]]
    else:
        # Install all deploy hook scripts (*.mousebrains.com.py)
        scripts = [os.path.basename(f)
                   for f in sorted(glob.glob(os.path.join(scriptDir, "*.mousebrains.com.py")))]
        if not scripts:
            print("No deploy hook scripts found", file=sys.stderr)
            sys.exit(1)

    errors = 0
    for scriptName in scripts:
        src = os.path.join(scriptDir, scriptName)
        dst = os.path.join(deployDir, scriptName)

        if not os.path.isfile(src):
            print(f"Deploy script not found: {src}", file=sys.stderr)
            errors += 1
            continue

        shutil.copy2(src, dst)
        print(f"Installed {src} -> {dst}")

    sys.exit(1 if errors else 0)

if __name__ == "__main__":
    main()
