# Supermicro BMC/IPMI (nas0ipmi.mousebrains.com)

Deploys Let's Encrypt certificates to a Supermicro BMC (IPMI) via its web interface CGI endpoints.

Supermicro BMCs require RSA keys; ECDSA keys are not supported.

## On the Let's Encrypt host

### Create the initial certificate with an RSA key

```bash
sudo certbot certonly --key-type rsa --dns-cloudflare \
    --dns-cloudflare-credentials /home/pat/.config/cloudflare.token \
    -d nas0ipmi.mousebrains.com
```

### Create the JSON config file

Store the BMC admin credentials in a JSON file:

```bash
tee ~pat/.config/nas0ipmi.json > /dev/null <<'EOF'
{
    "admin_user": "admin",
    "admin_password": "YOUR_PASSWORD"
}
EOF
```

```bash
chmod 600 ~pat/.config/nas0ipmi.json
```

### Install the deploy hook

```bash
sudo python3 install.py nas0ipmi.mousebrains.com
```

### Test the deploy hook

```bash
sudo python3 test.py nas0ipmi.mousebrains.com
```

### Verify the deployed certificate

```bash
echo | openssl s_client -connect nas0ipmi.mousebrains.com:443 2>/dev/null \
    | openssl x509 -noout -issuer -dates
```

## On the BMC

### Enable HTTPS

HTTPS is enabled by default on the Supermicro BMC web interface (port 443).

### Change the default password

The factory default credentials are `ADMIN` / `ADMIN`. Change the password through the web interface at **Configuration > Users**.

## How it works

The deploy hook authenticates via the BMC's web interface, uploads the certificate and private key through the SSL configuration page, validates the upload, and triggers a BMC reset:

1. `POST /cgi/login.cgi` -- authenticate and get a session cookie (`SID`)
2. `GET /cgi/url_redirect.cgi?url_name=config_ssl` -- fetch the SSL config page and extract the CSRF token
3. `POST /cgi/upload_ssl.cgi` -- upload `fullchain.pem` and `privkey.pem` as multipart form fields (`cert_file` and `key_file`) with content-type `application/x-x509-ca-cert`
4. `POST /cgi/ipmi.cgi` with `op=SSL_VALIDATE.XML` -- verify the BMC accepted the certificate (`VALIDATE="1"`)
5. `POST /cgi/ipmi.cgi` with `op=main_bmcreset` -- trigger a BMC reset to apply the new certificate

The BMC takes approximately 90 seconds to reboot after the reset. During this time the IPMI web interface will be unavailable, but the host system is not affected.

The CSRF token is required as a header (`CSRF-TOKEN`) for `ipmi.cgi` POST requests and as a form field for the upload. Credentials are URL-encoded and passed via `-d` to curl.

Use `--no-reset` to skip the BMC reset (the certificate will not take effect until the BMC is manually rebooted).

## Notes

- The BMC only accepts RSA certificates. ECDSA certificates will upload but fail validation (`VALIDATE="0"`).
- The Redfish `CertificateService.ReplaceCertificate` endpoint requires a DCMS license on this firmware version (01.74.13). The CGI upload approach works without any license.
- The BMC's Redfish `Certificate.Rekey` action only supports `TPM_ALG_RSA`, confirming the RSA-only requirement.
