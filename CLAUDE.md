# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Project Overview

Let's Encrypt certificate deployment scripts for Ubiquiti network devices. The Python scripts are certbot renewal hooks that automatically deploy renewed certificates via SSH/SCP. The bash scripts provide a more general deployment framework for Ubiquiti Cloud Gateway devices.

## Repository Structure

- `ucg.mousebrains.com.py` - Certbot deploy hook for UniFi Cloud Gateway (Python)
- `uisp.mousebrains.com.py` - Certbot deploy hook for UISP (Python, uses paramiko + cryptography)
- `deploy-ubiquiti-ssl.sh` - General-purpose Ubiquiti SSL deployment script (bash)
- `certbot-hook-ubiquiti.sh` - Example certbot renewal hook wrapper (bash)
- `test-ubiquiti-deploy.sh` - Test suite for deploy-ubiquiti-ssl.sh
- `ubiquiti-ssl.conf` - Configuration template for bash deployment script
- `ubiquiti-ssl-example.conf` - Example configuration
- `README.uisp` - UISP-specific setup notes

## Languages and Tools

- **Python 3.10+** for certbot deploy hooks (`*.py`)
- **Bash** for general deployment scripts (`*.sh`)
- **certbot** for Let's Encrypt certificate management
- **SSH/SCP** for remote certificate deployment
- No package manager or build system; scripts are standalone

## Common Commands

```bash
# Syntax check a Python deploy hook
python3 -m py_compile ucg.mousebrains.com.py

# Test certbot renewal (dry run with deploy hooks)
sudo certbot renew --dry-run --run-deploy-hooks

# Test a specific certificate renewal
sudo certbot renew --cert-name ucg.mousebrains.com --dry-run --run-deploy-hooks

# Run the bash deployment test suite
./test-ubiquiti-deploy.sh

# Test bash deployment in dry-run mode
./deploy-ubiquiti-ssl.sh --dry-run
```

## Code Conventions

- Python deploy hooks are named `<fqdn>.py` (e.g., `ucg.mousebrains.com.py`). The hostname is derived from the script filename by stripping the `.py` suffix.
- Deploy hooks are installed to `/etc/letsencrypt/renewal-hooks/deploy/` and run as root by certbot.
- Certbot sets `RENEWED_DOMAINS` (space-separated) and `RENEWED_LINEAGE` environment variables when invoking deploy hooks.
- Python scripts use `if __name__ == "__main__":` guards.
- Python scripts log to `/var/log/<fqdn>.log` by default.
- Subprocess calls should include `timeout=180` and use `.decode(errors="replace")` on output.
- Check subprocess return codes and raise on failure so the except block can log and `sys.exit(1)`.
- Bash scripts use `set -e` and colored output for logging.

## Security Notes

- Never commit certificate files (`.pem`, `.key`) or SSH keys (`id_rsa*`); these are in `.gitignore`.
- Scripts run as root. SSH key paths default to `/root/.ssh/`.
- Deploy hooks use SSH key authentication configured in `/root/.ssh/config`.

## License

GPLv3
