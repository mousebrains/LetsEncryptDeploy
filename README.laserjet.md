# HP Color LaserJet M452dn (laserjet.mousebrains.com)

Deploys Let's Encrypt certificates to an HP Color LaserJet M452dn printer via its Embedded Web Server (EWS) using HTTP Basic Auth.

HP LaserJet printers require RSA keys; ECC keys are not supported.

## On the Let's Encrypt host

### Create the initial certificate with an RSA key

```bash
sudo certbot certonly --key-type rsa --dns-cloudflare \
    --dns-cloudflare-credentials /home/pat/.config/cloudflare.token \
    -d laserjet.mousebrains.com
```

### Create the JSON config file

Store the printer's EWS admin credentials in a JSON file:

```bash
tee ~pat/.config/laserjet.json > /dev/null <<'EOF'
{
    "admin_user": "admin",
    "admin_password": "YOUR_PASSWORD"
}
EOF
```

```bash
chmod 600 ~pat/.config/laserjet.json
```

### Install the deploy hook

```bash
sudo cp laserjet.mousebrains.com.py /etc/letsencrypt/renewal-hooks/deploy/
```

## How it works

The script converts the PEM certificate and key to PKCS12 format, then uploads it through the printer's EWS form-based flow:

1. `POST /hp/device/set_config_networkCerts.html/config` -- navigate to certificate configuration
2. `POST /hp/device/set_config_networkPrintCerts.html/config` -- select import certificate
3. `POST /hp/device/Certificate.pfx` -- upload the PKCS12 file

Authentication credentials are passed to curl via a temporary netrc file (not on the command line). The PKCS12 password is passed to openssl via an environment variable.
