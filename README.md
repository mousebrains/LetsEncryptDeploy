# LetsEncryptDeploy

![CI](https://github.com/mousebrains/LetsEncryptDeploy/actions/workflows/ci.yml/badge.svg)
![Python 3.13+](https://img.shields.io/badge/python-3.13%2B-blue)
![License: GPLv3](https://img.shields.io/badge/license-GPLv3-green)
![Linting: ruff](https://img.shields.io/badge/linting-ruff-orange)
![Type checking: mypy](https://img.shields.io/badge/types-mypy--strict-blue)

Certbot deploy hooks for automatically deploying renewed Let's Encrypt certificates to network devices.

## Scripts

- `ucg.mousebrains.com.py` -- UniFi Cloud Gateway (copies cert/key via SCP, reloads nginx)
- `uisp.mousebrains.com.py` -- UISP (copies cert/key via SCP, restarts UISP)
- `ljscan.mousebrains.com.py` -- HP LaserJet MFP (converts to PKCS12, uploads via CDM OAuth2 API)
- `laserjet.mousebrains.com.py` -- HP Color LaserJet M452dn (converts to PKCS12, uploads via HTTP Basic Auth)

Each script is named after the FQDN it handles. Certbot sets `RENEWED_DOMAINS` when invoking deploy hooks; the script compares the domain list against its own filename and exits silently if there is no match.

## Device-specific setup

- [UniFi Cloud Gateway](README.ucg.md)
- [UISP](README.uisp.md)
- [HP LaserJet MFP](README.ljscan.md)
- [HP Color LaserJet M452dn](README.laserjet.md)

## Installation

Use `install.py` to copy deploy hooks into certbot's directory:

```bash
sudo python3 install.py ucg.mousebrains.com
```

Install all hooks at once (no arguments installs every `*.mousebrains.com.py` script):

```bash
sudo python3 install.py
```

## Testing

### Using test.py

The `test.py` script sets the certbot environment variables and runs a deploy hook locally:

```bash
sudo python3 test.py ljscan.mousebrains.com
```

Verify the certificate was deployed:

```bash
echo | openssl s_client -connect ljscan.mousebrains.com:443 2>/dev/null | openssl x509 -noout -issuer -dates
```

### Full renewal dry-run

Note: `--dry-run` simulates renewal but does **not** run deploy hooks.

```bash
sudo certbot renew --dry-run
```

To actually run deploy hooks, use `--force-renewal` instead (this issues a real renewal):

```bash
sudo certbot renew --cert-name ucg.mousebrains.com --force-renewal
```

Run any deploy hook with `--help` to see all available options:

```bash
python3 ljscan.mousebrains.com.py --help
```

## Logging

By default, scripts log to `/var/log/<fqdn>.log`. Pass `--logfile ""` to log to stderr instead. Use `--verbose` for debug-level output.

## Troubleshooting

### Hook runs but certificate doesn't change on the device

Check the log file for errors:

```bash
sudo cat /var/log/ucg.mousebrains.com.log
```

Run the hook manually for debug output (`test.py` always enables `--verbose`):

```bash
sudo python3 test.py ucg.mousebrains.com
```

### "Permission denied" or SSH connection failures

Ensure the SSH key is installed for root and the target host is in `/root/.ssh/config`:

```bash
sudo ssh device hostname
```

If this fails, verify the key exists and re-copy it:

```bash
sudo ssh-copy-id device
```

### "RENEWED_DOMAINS" or "RENEWED_LINEAGE" KeyError

The hook is being run outside of certbot. Use `test.py` to set the required environment variables automatically, or run via certbot with `--force-renewal`.

### HP printer rejects the certificate

- HP printers require RSA keys. If your certificate uses ECC, re-create it with `--key-type rsa`.
- Verify the credentials file exists and has correct permissions (`chmod 600`).
- Some HP firmware versions are picky about User-Agent strings; the ljscan hook handles this automatically.

### Timeout errors

The default subprocess timeout is 180 seconds (600 seconds for UISP restarts). If your device or network is slow, you may see `TimeoutExpired` errors in the log. When testing manually, you can pass extra arguments:

```bash
sudo python3 test.py uisp.mousebrains.com --reloadTimeout 900
```

For certbot-invoked hooks, edit the `default=` value in the script's argparse definition.

### Verifying the deployed certificate

After deployment, confirm the device is serving the new certificate:

```bash
echo | openssl s_client -connect <fqdn>:443 2>/dev/null | openssl x509 -noout -issuer -dates
```

The `notAfter` date should reflect the renewed certificate.

## Creating a new deploy hook

1. Copy an existing script that's closest to your target device and rename it to `<your-fqdn>.py`.
2. The hostname is derived from the filename automatically.
3. Modify the deployment logic for your device (SCP + SSH reload, curl upload, etc.).
4. Add a setup document as `README.<short-name>.md` and list the new hook in this file.
5. Add tests in `tests/test_<short-name>.py`.
6. Install with `sudo python3 install.py <your-fqdn>`.

See [CONTRIBUTING.md](CONTRIBUTING.md) for full conventions.

## License

GNU General Public License v3.0. See [LICENSE](LICENSE).
