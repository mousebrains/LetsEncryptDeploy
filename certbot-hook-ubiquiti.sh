#!/bin/bash

#
# Example certbot renewal hook script for Ubiquiti gateway SSL deployment
#
# Place this script in /etc/letsencrypt/renewal-hooks/deploy/
# and make it executable (chmod +x)
#

# Path to the deployment script
DEPLOY_SCRIPT="/usr/local/bin/deploy-ubiquiti-ssl.sh"

# Configuration file path
CONFIG_FILE="/etc/ubiquiti-ssl.conf"

# Log file for hook execution
HOOK_LOG="/var/log/certbot-ubiquiti-hook.log"

# Function to log messages
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$HOOK_LOG"
}

# Check if the deployment script exists
if [[ ! -f "$DEPLOY_SCRIPT" ]]; then
    log_message "ERROR: Deployment script not found at $DEPLOY_SCRIPT"
    exit 1
fi

# Check if configuration file exists
if [[ ! -f "$CONFIG_FILE" ]]; then
    log_message "ERROR: Configuration file not found at $CONFIG_FILE"
    exit 1
fi

log_message "INFO: Starting Ubiquiti SSL certificate deployment"
log_message "INFO: Renewed domains: $RENEWED_DOMAINS"

# Deploy certificate for each renewed domain
for domain in $RENEWED_DOMAINS; do
    log_message "INFO: Deploying certificate for domain: $domain"
    
    if "$DEPLOY_SCRIPT" -c "$CONFIG_FILE" -d "$domain"; then
        log_message "INFO: Successfully deployed certificate for $domain"
    else
        log_message "ERROR: Failed to deploy certificate for $domain"
        exit 1
    fi
done

log_message "INFO: Ubiquiti SSL certificate deployment completed successfully"