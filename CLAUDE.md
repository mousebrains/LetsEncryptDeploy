# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Project Overview

Let's Encrypt certificate deployment scripts for network devices. The Python scripts are certbot renewal hooks that automatically deploy renewed certificates via SSH/SCP or HTTPS upload.

## Repository Structure

- `ucg.mousebrains.com.py` - Certbot deploy hook for UniFi Cloud Gateway (Python)
- `uisp.mousebrains.com.py` - Certbot deploy hook for UISP (Python, uses paramiko + cryptography)
- `ljscan.mousebrains.com.py` - Certbot deploy hook for HP LaserJet MFP (Python, uses openssl + urllib)
- `README.uisp` - UISP-specific setup notes

## Languages and Tools

- **Python 3.10+** for certbot deploy hooks (`*.py`)
- **certbot** for Let's Encrypt certificate management
- **SSH/SCP** for remote certificate deployment
- **openssl** for PKCS12 conversion (HP printer); HTTPS upload uses Python stdlib (`urllib`)
- No package manager or build system; scripts are standalone

## Common Commands

```bash
# Syntax check a Python deploy hook
python3 -m py_compile ucg.mousebrains.com.py

# Test certbot renewal (dry run with deploy hooks)
sudo certbot renew --dry-run --run-deploy-hooks

# Test a specific certificate renewal
sudo certbot renew --cert-name ucg.mousebrains.com --dry-run --run-deploy-hooks
```

## Code Conventions

- Python deploy hooks are named `<fqdn>.py` (e.g., `ucg.mousebrains.com.py`). The hostname is derived from the script filename by stripping the `.py` suffix.
- Deploy hooks are installed to `/etc/letsencrypt/renewal-hooks/deploy/` and run as root by certbot.
- Certbot sets `RENEWED_DOMAINS` (space-separated) and `RENEWED_LINEAGE` environment variables when invoking deploy hooks.
- Python scripts use `if __name__ == "__main__":` guards.
- Python scripts log to `/var/log/<fqdn>.log` by default.
- Subprocess calls should include `timeout=180` and use `.decode(errors="replace")` on output.
- Check subprocess return codes and raise on failure so the except block can log and `sys.exit(1)`.

## Security Notes

- Never commit certificate files (`.pem`, `.key`) or SSH keys (`id_rsa*`); these are in `.gitignore`.
- Scripts run as root. SSH key paths default to `/root/.ssh/`.
- Deploy hooks use SSH key authentication configured in `/root/.ssh/config`.
- HP printer admin password is stored in `/etc/letsencrypt/hp-admin-password` (mode 600).
- HP LaserJet printers require RSA keys; ECC keys are not supported.

## License

GPLv3
