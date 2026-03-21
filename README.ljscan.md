# HP LaserJet MFP (ljscan.mousebrains.com)

Deploys Let's Encrypt certificates to an HP LaserJet MFP printer via its CDM OAuth2 API.

HP LaserJet printers require RSA keys; ECC keys are not supported.

## On the Let's Encrypt host

### Create the initial certificate with an RSA key

```bash
sudo certbot certonly --key-type rsa --dns-cloudflare \
    --dns-cloudflare-credentials /home/pat/.config/cloudflare.token \
    -d ljscan.mousebrains.com
```

### Create the JSON config file

Store the printer's EWS admin credentials in a JSON file:

```bash
tee ~pat/.config/ljscan.json > /dev/null <<'EOF'
{
    "admin_user": "admin",
    "admin_password": "YOUR_PASSWORD"
}
EOF
```

```bash
chmod 600 ~pat/.config/ljscan.json
```

### Install the deploy hook

```bash
sudo python3 install.py ljscan.mousebrains.com
```

### Test the deploy hook

```bash
sudo python3 test.py ljscan.mousebrains.com
```

## How it works

The script converts the PEM certificate and key to PKCS12 format, base64-encodes it, and uploads it to the printer. Authentication uses the CDM OAuth2 password grant (`/cdm/oauth2/v1/token`) to obtain a bearer token, then POSTs the PKCS12 to `/cdm/certificate/v1/certificates`.

The PKCS12 password is passed to openssl via an environment variable (not on the command line). Override the upload endpoint with `--uploadPath`.
