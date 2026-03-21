# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Project Overview

Let's Encrypt certificate deployment scripts for network devices. The Python scripts are certbot renewal hooks that automatically deploy renewed certificates via SSH/SCP or HTTPS upload.

## Repository Structure

- `ucg.mousebrains.com.py` - Certbot deploy hook for UniFi Cloud Gateway (Python, uses SSH/SCP)
- `uisp.mousebrains.com.py` - Certbot deploy hook for UISP (Python, uses SSH/SCP)
- `ljscan.mousebrains.com.py` - Certbot deploy hook for HP LaserJet MFP (Python, uses openssl + curl)
- `laserjet.mousebrains.com.py` - Certbot deploy hook for HP Color LaserJet M452dn (Python, uses openssl + curl)
- `README.ucg.md` - UniFi Cloud Gateway setup notes
- `README.uisp.md` - UISP setup notes
- `README.ljscan.md` - HP LaserJet MFP setup notes
- `README.laserjet.md` - HP Color LaserJet M452dn setup notes
- `test.py` - Manual testing helper (sets env vars and runs a deploy hook)
- `install.py` - Installs deploy hooks to certbot's renewal-hooks/deploy directory

## Languages and Tools

- **Python 3.13+** for certbot deploy hooks (`*.py`)
- **certbot** for Let's Encrypt certificate management
- **SSH/SCP** for remote certificate deployment (UCG, UISP)
- **openssl** for PKCS12 conversion (HP printers)
- **curl** for HTTPS certificate upload (HP printers)
- No package manager or build system; scripts are standalone

## Common Commands

```bash
# Syntax check a Python deploy hook
python3 -m py_compile ucg.mousebrains.com.py

# Test a deploy hook (without renewing the certificate)
sudo python3 test.py ucg.mousebrains.com

# Install a deploy hook to certbot's directory
sudo python3 install.py ucg.mousebrains.com

# Verify the deployed certificate
echo | openssl s_client -connect ucg.mousebrains.com:443 2>/dev/null | openssl x509 -noout -issuer -dates
```

## Code Conventions

- Python deploy hooks are named `<fqdn>.py` (e.g., `ucg.mousebrains.com.py`). The hostname is derived from the script filename by stripping the `.py` suffix.
- Deploy hooks are installed to `/etc/letsencrypt/renewal-hooks/deploy/` and run as root by certbot.
- Certbot sets `RENEWED_DOMAINS` (space-separated) and `RENEWED_LINEAGE` environment variables when invoking deploy hooks.
- Python scripts use `if __name__ == "__main__":` guards.
- Python scripts log to `/var/log/<fqdn>.log` by default.
- Subprocess calls should include an appropriate `timeout` (180s default, 600s for slow operations like UISP restart) and use `.decode(errors="replace")[:500]` on output.
- Check subprocess return codes and raise on failure so the except block can log and `sys.exit(1)`.
- Catch `subprocess.TimeoutExpired`, `KeyError` (missing env vars), `FileNotFoundError`, and `RuntimeError` explicitly; use generic `except Exception` as a fallback.
- Avoid exposing secrets on the command line; use environment variables (`-passout env:VAR`) for openssl and netrc files (`--netrc-file`) for curl.

## Security Notes

- Never commit certificate files (`.pem`, `.key`, `.pfx`, `.p12`) or SSH keys (`id_rsa*`); these are in `.gitignore`.
- Scripts run as root. SSH key paths default to `/root/.ssh/`.
- Deploy hooks use SSH key authentication configured in `/root/.ssh/config`.
- HP LaserJet M452dn admin credentials are stored in `~pat/.config/laserjet.json` (mode 600).
- HP LaserJet MFP admin credentials are stored in `~pat/.config/ljscan.json` (mode 600).
- HP LaserJet printers require RSA keys; ECC keys are not supported.

## License

GPLv3
