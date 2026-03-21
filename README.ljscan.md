# HP LaserJet MFP (ljscan.mousebrains.com)

Deploys Let's Encrypt certificates to HP LaserJet printers via their Embedded Web Server (EWS). HP LaserJet printers require RSA keys; ECC keys are not supported.

There are two deploy scripts for different printer models:

- `ljscan.mousebrains.com.py` -- HP LaserJet MFP (uses CDM OAuth2 API)
- `laserjet.mousebrains.com.py` -- HP Color LaserJet M452dn (uses HTTP Basic Auth)

## On the Let's Encrypt host

### Create the initial certificate with an RSA key

```bash
sudo certbot certonly --key-type rsa --dns-cloudflare \
    --dns-cloudflare-credentials /home/pat/.config/cloudflare.token \
    -d ljscan.mousebrains.com
```

### Store the printer's EWS admin password

```bash
echo 'YOUR_ADMIN_PASSWORD' | sudo tee /etc/letsencrypt/ljscan.admin.password
```

```bash
sudo chmod 600 /etc/letsencrypt/ljscan.admin.password
```

### Install the deploy hook

```bash
sudo cp ljscan.mousebrains.com.py /etc/letsencrypt/renewal-hooks/deploy/
```

## How it works

The script converts the PEM certificate and key to PKCS12 format, base64-encodes it, and uploads it to the printer:

- **ljscan** (MFP): Authenticates via CDM OAuth2 password grant (`/cdm/oauth2/v1/token`), then POSTs the PKCS12 to `/cdm/certificate/v1/certificates`. Override the endpoint with `--uploadPath`.
- **laserjet** (M452dn): Authenticates via HTTP Basic Auth and uploads the PKCS12 through the EWS configuration pages.
