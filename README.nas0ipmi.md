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

## Prerequisites

- `curl` for the CGI upload.
- `openssl` to convert the key to PKCS#1 before upload.
- `ipmitool` for the cold reset (`sudo apt-get install -y ipmitool`).
- **IPMI-over-LAN must be enabled** on the BMC (623/udp). The same admin
  credentials in `nas0ipmi.json` are used for both the web CGI and IPMI-over-LAN.

## How it works

The deploy hook authenticates via the BMC's web interface, uploads the certificate and private key through the SSL configuration page, validates the upload, then **cold-resets** the BMC over IPMI to activate the new certificate:

1. Convert `privkey.pem` (PKCS#8) to traditional PKCS#1 with `openssl rsa`.
2. `POST /cgi/login.cgi` -- authenticate and get a session cookie (`SID`)
3. `GET /cgi/url_redirect.cgi?url_name=config_ssl` -- fetch the SSL config page and extract the CSRF token
4. `POST /cgi/upload_ssl.cgi` -- upload `fullchain.pem` and the PKCS#1 key as multipart form fields (`cert_file` and `key_file`), with **no forced MIME type**
5. `POST /cgi/ipmi.cgi` with `op=SSL_VALIDATE.XML` -- confirm the upload was accepted in-session (`VALIDATE="1"`)
6. `ipmitool -I lanplus ... mc reset cold` -- **cold**-reset the BMC to activate the stored certificate
7. Reconnect to `:443` and verify the served leaf certificate matches the deployed one (retries while the BMC reboots)

The BMC takes approximately 90 seconds to reboot after the reset. During this time the IPMI web interface will be unavailable, but the host system is not affected.

Use `--no-reset` to skip the cold reset (the certificate is stored but not activated), and `--no-verify` to skip the post-reset wire check.

## Notes

- **A warm reset is not enough.** The web UI's `op=main_bmcreset` (and re-uploading in the UI) stores the new certificate but does not re-load it, so the BMC keeps serving the *previous* cert. Only a **cold** reset (`mc reset cold`) activates a replaced certificate on this firmware. This is why the hook uses `ipmitool` rather than the CGI reset.
- **The key must be uploaded without a certificate MIME type.** Tagging the private key as `application/x-x509-ca-cert` (an earlier version of this hook did) makes the BMC store the cert but drop the key.
- `op=SSL_VALIDATE.XML` is **session-scoped** -- it validates the pair staged in the current login session, not the persisted/active pair. It reads `1` right after an upload but `0` in any fresh session even when the active certificate is correct. Do not use it as a health check; verify on the wire (`:443`) instead.
- The BMC only accepts RSA certificates. ECDSA certificates will upload but fail validation (`VALIDATE="0"`).
- The Redfish `CertificateService.ReplaceCertificate` endpoint requires a DCMS license on this firmware version (01.74.13). The CGI upload approach works without any license.
- The BMC's Redfish `Certificate.Rekey` action only supports `TPM_ALG_RSA`, confirming the RSA-only requirement.
