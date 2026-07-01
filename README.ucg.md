# UniFi Cloud Gateway (ucg.mousebrains.com)

Deploys Let's Encrypt certificates to a UniFi Cloud Gateway via SCP and nginx reload.

## On the Let's Encrypt host

### Create the initial certificate

```bash
sudo certbot certonly --dns-cloudflare \
    --dns-cloudflare-credentials /home/pat/.config/cloudflare.token \
    -d ucg.mousebrains.com
```

### Set up SSH config for root

Add to `/root/.ssh/config`:

```text
Host ucg ucg.mousebrains.com
    HostName ucg.mousebrains.com
    User root
    IdentityFile ~/.ssh/id_ed25519
```

### Copy the SSH key to the gateway

```bash
sudo ssh-copy-id ucg
```

### Install the deploy hook

```bash
sudo python3 install.py ucg.mousebrains.com
```

### Test the deploy hook

```bash
sudo python3 test.py ucg.mousebrains.com
```

## On the UniFi Cloud Gateway

### Enable SSH

Enable SSH on the gateway through the UniFi controller UI, and copy the deploy
host's SSH key to the gateway (`sudo ssh-copy-id ucg`).

### How UniFi OS serves the certificate

UniFi OS's "User Certificates" feature tracks the active certificate by UUID
(`activeCertId` in `/data/unifi-core/config/settings.yaml`) and points nginx at
`<uuid>.crt` / `<uuid>.key` via `/data/unifi-core/config/http/local-certs.conf`:

```text
ssl_certificate     /data/unifi-core/config/<uuid>.crt;
ssl_certificate_key /data/unifi-core/config/<uuid>.key;
```

**Firmware updates regenerate this UUID** (and wipe any symlinks you create by
hand), so the hook does not hard-code it — it reads the active paths out of
`local-certs.conf` at deploy time. No manual symlink setup is required.

## How it works

1. SCP `fullchain.pem` and `privkey.pem` to the gateway's home directory (`/root`).
2. SSH a small script that reads the active `ssl_certificate` / `ssl_certificate_key`
   paths from `local-certs.conf`, overwrites those files in place (preserving
   their ownership/mode), and runs `nginx -s reload`.
3. Reconnect to `:443` and verify the served leaf certificate matches the
   deployed one; the deploy fails loudly if it does not.

Use `--no-verify` to skip the wire check, and `--certConf` to override the
`local-certs.conf` path.

## Notes

- If a firmware update repoints `local-certs.conf` to a fresh self-signed cert,
  the gateway serves that until the next renewal; the hook re-installs the
  Let's Encrypt cert (and verification confirms it) on the next deploy. Run
  `sudo python3 test.py ucg.mousebrains.com` to re-install immediately.
