# LetsEncryptDeploy

Deployment scripts for Let's Encrypt certificate renewal to various network devices and services.

## Overview

This repository contains scripts to automatically deploy SSL certificates from Let's Encrypt to network devices and services after certificate renewal. Currently supports:

- **Ubiquiti Cloud Gateway devices** (UniFi Security Gateway, EdgeRouter, Cloud Key)

## Ubiquiti Cloud Gateway SSL Deployment

The `deploy-ubiquiti-ssl.sh` script automatically deploys Let's Encrypt SSL certificates to Ubiquiti gateway devices.

### Features

- **Auto-detection** of gateway type (UniFi vs EdgeOS)
- **SSH-based deployment** with key authentication support
- **Backup** of existing certificates before replacement
- **Dry-run mode** for testing configuration
- **Comprehensive logging** with colored output
- **Configuration file** support for easy management
- **Integration** with Let's Encrypt certbot renewal hooks

### Supported Devices

- UniFi Security Gateway (USG)
- UniFi Dream Machine (UDM/UDM Pro)
- UniFi Cloud Key
- EdgeRouter series
- Any Ubiquiti device running UniFi OS or EdgeOS

### Quick Start

1. **Download and configure:**
   ```bash
   wget https://raw.githubusercontent.com/mousebrains/LetsEncryptDeploy/main/deploy-ubiquiti-ssl.sh
   wget https://raw.githubusercontent.com/mousebrains/LetsEncryptDeploy/main/ubiquiti-ssl.conf
   chmod +x deploy-ubiquiti-ssl.sh
   ```

2. **Edit configuration:**
   ```bash
   nano ubiquiti-ssl.conf
   ```
   Update the domain, gateway IP, and SSH credentials.

3. **Test deployment:**
   ```bash
   ./deploy-ubiquiti-ssl.sh --dry-run
   ```

4. **Deploy certificate:**
   ```bash
   ./deploy-ubiquiti-ssl.sh
   ```

### Configuration

Edit `ubiquiti-ssl.conf` with your specific settings:

```bash
# Domain name for the certificate
DOMAIN="gateway.example.com"

# Gateway connection details
GATEWAY_HOST="192.168.1.1"
SSH_USER="ubnt"
SSH_PORT="22"

# SSH key authentication (optional)
SSH_KEY="/home/user/.ssh/id_rsa"

# Gateway type (auto-detect if not specified)
GATEWAY_TYPE="auto"
```

### Command Line Usage

```bash
./deploy-ubiquiti-ssl.sh [OPTIONS]

OPTIONS:
    -c, --config FILE       Configuration file
    -d, --domain DOMAIN     Domain name for the certificate
    -g, --gateway HOST      Gateway hostname or IP address
    -u, --user USER         SSH username for gateway access
    -k, --keyfile FILE      SSH private key file
    -p, --port PORT         SSH port (default: 22)
    --cert-path PATH        Path to certificate file
    --key-path PATH         Path to private key file
    --ca-path PATH          Path to CA certificate file
    --dry-run              Show what would be done without executing
    -v, --verbose          Enable verbose output
    -h, --help             Show help message
```

### Examples

**Basic deployment:**
```bash
./deploy-ubiquiti-ssl.sh -d gateway.example.com -g 192.168.1.1 -u admin
```

**Using configuration file:**
```bash
./deploy-ubiquiti-ssl.sh --config /etc/ubiquiti-ssl.conf
```

**Dry run to test configuration:**
```bash
./deploy-ubiquiti-ssl.sh --dry-run
```

**Custom certificate paths:**
```bash
./deploy-ubiquiti-ssl.sh -d example.com -g 192.168.1.1 -u admin \
  --cert-path /path/to/cert.pem \
  --key-path /path/to/privkey.pem
```

### Integration with Let's Encrypt

#### Certbot Renewal Hook

Add the deployment script as a certbot renewal hook:

1. **Create hook script** `/etc/letsencrypt/renewal-hooks/deploy/ubiquiti-deploy.sh`:
   ```bash
   #!/bin/bash
   /path/to/deploy-ubiquiti-ssl.sh -d $RENEWED_DOMAINS
   ```

2. **Make it executable:**
   ```bash
   chmod +x /etc/letsencrypt/renewal-hooks/deploy/ubiquiti-deploy.sh
   ```

3. **Test renewal:**
   ```bash
   certbot renew --dry-run
   ```

#### Systemd Timer Integration

Create a systemd service for automated deployment:

1. **Create service file** `/etc/systemd/system/ubiquiti-ssl-deploy.service`:
   ```ini
   [Unit]
   Description=Deploy SSL certificates to Ubiquiti gateway
   After=network.target
   
   [Service]
   Type=oneshot
   ExecStart=/path/to/deploy-ubiquiti-ssl.sh
   User=root
   StandardOutput=journal
   StandardError=journal
   ```

2. **Create timer file** `/etc/systemd/system/ubiquiti-ssl-deploy.timer`:
   ```ini
   [Unit]
   Description=Deploy SSL certificates to Ubiquiti gateway
   Requires=ubiquiti-ssl-deploy.service
   
   [Timer]
   OnCalendar=daily
   Persistent=true
   
   [Install]
   WantedBy=timers.target
   ```

3. **Enable and start:**
   ```bash
   systemctl enable ubiquiti-ssl-deploy.timer
   systemctl start ubiquiti-ssl-deploy.timer
   ```

### Prerequisites

- **SSH access** to the Ubiquiti gateway device
- **Root or administrative privileges** on the gateway
- **Certificate files** from Let's Encrypt (or other CA)
- **bash**, **ssh**, and **scp** utilities

### SSH Setup

1. **Generate SSH key pair** (if not already done):
   ```bash
   ssh-keygen -t rsa -b 4096 -f ~/.ssh/ubiquiti_gateway
   ```

2. **Copy public key to gateway:**
   ```bash
   ssh-copy-id -i ~/.ssh/ubiquiti_gateway.pub ubnt@192.168.1.1
   ```

3. **Test SSH connection:**
   ```bash
   ssh -i ~/.ssh/ubiquiti_gateway ubnt@192.168.1.1
   ```

### Troubleshooting

#### Common Issues

**SSH Connection Failed:**
- Verify gateway IP address and SSH port
- Check SSH key permissions (should be 600)
- Ensure SSH is enabled on the gateway
- Try connecting manually first

**Certificate Installation Failed:**
- Verify certificate file paths are correct
- Check file permissions on certificate files
- Ensure SSH user has sufficient privileges
- Review gateway logs for specific errors

**Service Restart Failed:**
- Some gateways may require manual service restart
- Check if certificates are properly installed
- Verify certificate format matches gateway requirements

#### Debugging

**Enable verbose output:**
```bash
./deploy-ubiquiti-ssl.sh --verbose
```

**Use dry-run mode:**
```bash
./deploy-ubiquiti-ssl.sh --dry-run
```

**Check logs:**
```bash
tail -f /var/log/ubiquiti-ssl-deploy.log
```

### Security Considerations

- Store SSH private keys securely with proper permissions (600)
- Use dedicated SSH keys for automation
- Regularly rotate SSH keys
- Monitor deployment logs for unauthorized access
- Consider using SSH certificate authentication for enhanced security

### Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### License

This project is licensed under the GNU General Public License v3.0. See [LICENSE](LICENSE) for details.

### Support

For issues and questions:
- Create an issue on GitHub
- Check existing issues for solutions
- Provide detailed logs and configuration when reporting issues
