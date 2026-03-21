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

Enable SSH on the gateway through the UniFi controller UI.

### Set up certificate symlinks

In `/data/unifi-core/config/`, find the certificate UUID files (e.g. `bf800083-...-.crt` and `.key`). Back them up, then create symbolic links to the Let's Encrypt files:

```bash
ln -sf /root/fullchain.pem bf800083-907e-44b4-af66-0a0a92fe9acc.crt
```

```bash
ln -sf /root/privkey.pem bf800083-907e-44b4-af66-0a0a92fe9acc.key
```

### Reload nginx

```bash
nginx -s reload
```

## How it works

The deploy hook SCPs `fullchain.pem` and `privkey.pem` to the gateway's home directory, then runs `nginx -s reload` via SSH to pick up the new certificate.
