#! /usr/bin/python3
#
# Install deploy hook scripts into certbot's renewal-hooks/deploy directory.
#
# Usage: sudo python3 install.py [hostname[.py] ...]
#   e.g. sudo python3 install.py ljscan.mousebrains.com
#        sudo python3 install.py                          # installs all hooks
#
# Mar-2026 Pat Welch pat@mousebrains.com

import os
import shutil
import sys
from pathlib import Path

DEPLOY_DIR = "/etc/letsencrypt/renewal-hooks/deploy"


def main() -> None:
    if os.geteuid() != 0:
        print(f"This script must be run as root. Try:\n"
              f"  sudo python3 {' '.join(sys.argv)}", file=sys.stderr)
        sys.exit(1)

    if not Path(DEPLOY_DIR).is_dir():
        print(f"Deploy directory not found: {DEPLOY_DIR}", file=sys.stderr)
        sys.exit(1)

    script_dir = Path(sys.argv[0]).resolve().parent

    if len(sys.argv) > 1:
        # Install specific scripts
        scripts = [f"{arg.removesuffix('.py')}.py" for arg in sys.argv[1:]]
    else:
        # Install all deploy hook scripts (*.mousebrains.com.py)
        scripts = sorted(p.name for p in script_dir.glob("*.mousebrains.com.py"))
        if not scripts:
            print("No deploy hook scripts found", file=sys.stderr)
            sys.exit(1)

    errors = 0
    for script_name in scripts:
        src = script_dir / script_name
        dst = Path(DEPLOY_DIR) / script_name

        if not src.is_file():
            print(f"Deploy script not found: {src}", file=sys.stderr)
            errors += 1
            continue

        shutil.copy2(src, dst)
        print(f"Installed {src} -> {dst}")

    if errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
