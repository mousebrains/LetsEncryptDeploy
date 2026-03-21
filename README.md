# LetsEncryptDeploy

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

## Testing

Dry-run all deploy hooks:
```bash
sudo certbot renew --dry-run --run-deploy-hooks
```

Test a specific certificate:
```bash
sudo certbot renew --cert-name ucg.mousebrains.com --dry-run --run-deploy-hooks
```

## Logging

By default, scripts log to `/var/log/<fqdn>.log`. Pass `--logfile ""` to log to stderr instead. Use `--verbose` for debug-level output.

## Creating a new deploy hook

1. Copy an existing script and rename it to `<your-fqdn>.py`.
2. The hostname is derived from the filename automatically.
3. Adjust the `--reload` command if the target device uses something other than `nginx -s reload`.
4. Install the script to `/etc/letsencrypt/renewal-hooks/deploy/` and make it executable.

## License

GNU General Public License v3.0. See [LICENSE](LICENSE).
