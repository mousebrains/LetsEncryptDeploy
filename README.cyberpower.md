# CyberPower UPS RMCARD205 (cyberpower.mousebrains.com)

Deploys Let's Encrypt certificates to a CyberPower UPS remote management card (RMCARD205) via its REST API.

The RMCARD205 accepts certificates in standard PEM format. The deploy hook concatenates `fullchain.pem` and `privkey.pem` into a single file and uploads it via the REST API. Both RSA and ECDSA keys are supported.

## On the Let's Encrypt host

### Create the initial certificate

```bash
sudo certbot certonly --dns-cloudflare \
    --dns-cloudflare-credentials /home/pat/.config/cloudflare.token \
    -d cyberpower.mousebrains.com
```

### Create the JSON config file

Store the RMCARD205 admin credentials in a JSON file:

```bash
tee ~pat/.config/cyberpower.json > /dev/null <<'EOF'
{
    "admin_user": "admin",
    "admin_password": "YOUR_PASSWORD"
}
EOF
```

```bash
chmod 600 ~pat/.config/cyberpower.json
```

### Install the deploy hook

```bash
sudo python3 install.py cyberpower.mousebrains.com
```

### Test the deploy hook

```bash
sudo python3 test.py cyberpower.mousebrains.com
```

### Verify the deployed certificate

```bash
echo | openssl s_client -connect cyberpower.mousebrains.com:443 2>/dev/null \
    | openssl x509 -noout -issuer -dates
```

## On the RMCARD205

### Enable HTTPS

In the web interface, go to **System > Network Service > Web Service** and set Access to **HTTPS**. The default HTTPS port is 443.

### Change the default password

The factory default credentials are `cyber` / `cyber`. Change the admin password via the web interface at **System > Security > Local Account** or via the REST API. The maximum username and password length is 63 characters.

## How it works

The deploy hook authenticates via the RMCARD205 REST API using a two-step login flow, uploads the combined PEM, and logs out to apply the change:

1. `POST /api/login/` -- send credentials, receive a temporary token
2. `GET /api/login/status/` -- exchange the temporary token for a session token (expires in 180 seconds)
3. `POST /api/network/web/https/upload/cert/` -- upload the combined PEM (fullchain + privkey) as a multipart form
4. `PUT /api/logout/` -- logout to apply the new certificate

The certificate file must be a concatenation of the full certificate chain and private key in PEM format. Uploading only the certificate (without the key) will break HTTPS access until recovered.

Credentials are written to a temporary file and passed to curl via `-d @file` to avoid exposing them on the command line.

## SSH access

The RMCARD205 has a limited SSH server (`CPS_SSH_ID_0.10`) that requires non-default key exchange settings. Add to `~/.ssh/config`:

```text
Host cyberpower cyberpower.mousebrains.com
    HostName cyberpower.mousebrains.com
    User admin
    KexAlgorithms diffie-hellman-group14-sha256,diffie-hellman-group-exchange-sha256
    HostKeyAlgorithms +ssh-ed25519
    PubkeyAuthentication no
    PreferredAuthentications keyboard-interactive
```

## Recovery

If a certificate is uploaded without its matching private key, HTTPS will break (TLS handshake fails with `bad signature`). To recover:

1. SSH into the card (SSH uses a separate key and is unaffected)
2. Run `web access http` to switch to HTTP-only mode
3. Use the HTTP API to upload a corrected combined PEM file (fullchain + privkey)
4. Switch back to HTTPS: `PUT /api/network/web/access/ -d '{"access":"https"}'`
5. Logout to apply

To factory reset the card, remove the reset jumper from the card's pins, insert the card into the UPS, wait for the Tx/Rx LED to flash (once per second), remove the card, replace the jumper, and re-insert. This resets all settings including credentials.
