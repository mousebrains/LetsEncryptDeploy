# UISP (uisp.mousebrains.com)

Deploys Let's Encrypt certificates to a Ubiquiti UISP instance running inside the UNMS Docker container on Debian Bookworm.

## On the Let's Encrypt host

### Create the initial certificate

```bash
sudo certbot certonly --dns-cloudflare \
    --dns-cloudflare-credentials /home/pat/.config/cloudflare.token \
    -d uisp.mousebrains.com
```

### Set up SSH config

Add to both `~/.ssh/config` and `/root/.ssh/config`:

```text
Host uisp uisp.mousebrains.com
    HostName uisp.mousebrains.com
    User unms
    IdentityFile ~/.ssh/id_ed25519
```

### Copy SSH keys to the UISP host

As your user:

```bash
ssh-copy-id uisp
```

As root:

```bash
sudo ssh-copy-id uisp
```

### Copy the initial certificates to the UISP host

```bash
sudo scp -r /etc/letsencrypt/live/uisp.mousebrains.com uisp:/etc/certificates
```

### Install the deploy hook

```bash
sudo python3 install.py uisp.mousebrains.com
```

### Test the deploy hook

```bash
sudo python3 test.py uisp.mousebrains.com
```

## On the UISP host

### Create the certificate directory

```bash
sudo mkdir -p /etc/certificates
```

```bash
sudo chown unms:unms /etc/certificates
```

```bash
sudo chmod 700 /etc/certificates
```

### Install UISP with the SSL certificates

```bash
curl -fsSL https://uisp.ui.com/install > /tmp/uisp_inst.sh && \
    sudo bash /tmp/uisp_inst.sh \
        --ssl-cert-dir /etc/certificates/uisp.mousebrains.com \
        --ssl-cert fullchain.pem \
        --ssl-cert-key privkey.pem
```

## How it works

The deploy hook SCPs `fullchain.pem` and `privkey.pem` to `/etc/certificates/uisp.mousebrains.com/` on the UISP host, then runs `app/unms-cli restart` via SSH (as the `unms` user) to reload the certificates.

To manually restart UISP after a certificate update:

```bash
ssh uisp.mousebrains.com app/unms-cli restart
```
