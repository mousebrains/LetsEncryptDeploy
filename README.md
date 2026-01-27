# LetsEncryptDeploy

Certbot deploy hooks for automatically deploying renewed Let's Encrypt certificates to Ubiquiti network devices via SSH.

## Scripts

- `ucg.mousebrains.com.py` -- UniFi Cloud Gateway (copies cert/key via SCP, reloads nginx)
- `uisp.mousebrains.com.py` -- UISP (converts to PKCS12, deploys via paramiko SSH)

Each script is named after the FQDN it handles. Certbot sets `RENEWED_DOMAINS` when invoking deploy hooks; the script compares the domain list against its own filename and exits silently if there is no match.

## Setup

### On the Let's Encrypt host

1. Create an SSH key pair for root:
   ```bash
   sudo ssh-keygen -t ed25519
   ```

2. Configure `/root/.ssh/config` with the target device:
   ```
   Host ucg.mousebrains.com
       HostName ucg.mousebrains.com
       User root
       IdentityFile ~/.ssh/id_ed25519
   ```

3. Copy the deploy hook into certbot's renewal hooks directory:
   ```bash
   sudo cp ucg.mousebrains.com.py /etc/letsencrypt/renewal-hooks/deploy/
   sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/ucg.mousebrains.com.py
   ```

### On the UniFi Cloud Gateway (for ucg)

1. Enable SSH on the gateway.
2. Add the Let's Encrypt host's public SSH key to the gateway's `authorized_keys`.
3. Set up symbolic links in `/data/unifi-core/config/` pointing the gateway's certificate UUID files to `/root/fullchain.pem` and `/root/privkey.pem` (see comments in `ucg.mousebrains.com.py` for details).

### On the UISP host

See `README.uisp` for UISP-specific setup instructions.

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
