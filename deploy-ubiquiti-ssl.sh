#!/bin/bash

#
# Ubiquiti Cloud Gateway SSL Certificate Deployment Script
# For use with Let's Encrypt certificates
#
# Copyright (C) 2024
# Licensed under GNU General Public License v3.0
#

set -e  # Exit on any error

# Default configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/ubiquiti-ssl.conf"
LOG_FILE="/var/log/ubiquiti-ssl-deploy.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        "ERROR")
            echo -e "${RED}[$timestamp] ERROR: $message${NC}" >&2
            ;;
        "WARN")
            echo -e "${YELLOW}[$timestamp] WARN: $message${NC}" >&2
            ;;
        "INFO")
            echo -e "${GREEN}[$timestamp] INFO: $message${NC}"
            ;;
        *)
            echo "[$timestamp] $level: $message"
            ;;
    esac
    
    # Also log to file if possible
    if [[ -w "$(dirname "$LOG_FILE")" ]] || [[ -w "$LOG_FILE" ]]; then
        echo "[$timestamp] $level: $message" >> "$LOG_FILE"
    fi
}

# Display usage information
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Deploy SSL certificates to Ubiquiti Cloud Gateway devices.

OPTIONS:
    -c, --config FILE       Configuration file (default: $CONFIG_FILE)
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
    -h, --help             Show this help message

EXAMPLES:
    $0 -d example.com -g 192.168.1.1 -u admin
    $0 --config /etc/ubiquiti-ssl.conf --dry-run
    $0 -d mysite.com -g gateway.local -u root -k ~/.ssh/id_rsa

EOF
}

# Load configuration from file
load_config() {
    local config_file="$1"
    
    if [[ -f "$config_file" ]]; then
        log "INFO" "Loading configuration from $config_file"
        
        # Store command line values before sourcing config
        local cmd_domain="$DOMAIN"
        local cmd_gateway="$GATEWAY_HOST"
        local cmd_user="$SSH_USER"
        local cmd_key="$SSH_KEY"
        local cmd_port="$SSH_PORT"
        local cmd_cert="$CERT_PATH"
        local cmd_keypath="$KEY_PATH"
        local cmd_ca="$CA_PATH"
        local cmd_dryrun="$DRY_RUN"
        local cmd_verbose="$VERBOSE"
        
        source "$config_file"
        
        # Restore command line values if they were set (command line takes precedence)
        [[ -n "$cmd_domain" ]] && DOMAIN="$cmd_domain"
        [[ -n "$cmd_gateway" ]] && GATEWAY_HOST="$cmd_gateway"
        [[ -n "$cmd_user" ]] && SSH_USER="$cmd_user"
        [[ -n "$cmd_key" ]] && SSH_KEY="$cmd_key"
        [[ -n "$cmd_port" ]] && SSH_PORT="$cmd_port"
        [[ -n "$cmd_cert" ]] && CERT_PATH="$cmd_cert"
        [[ -n "$cmd_keypath" ]] && KEY_PATH="$cmd_keypath"
        [[ -n "$cmd_ca" ]] && CA_PATH="$cmd_ca"
        [[ -n "$cmd_dryrun" ]] && DRY_RUN="$cmd_dryrun"
        [[ -n "$cmd_verbose" ]] && VERBOSE="$cmd_verbose"
    else
        log "WARN" "Configuration file $config_file not found, using defaults"
    fi
}

# Validate required parameters
validate_config() {
    local errors=0
    
    if [[ -z "$DOMAIN" ]]; then
        log "ERROR" "Domain name is required (-d/--domain or DOMAIN in config)"
        ((errors++))
    fi
    
    if [[ -z "$GATEWAY_HOST" ]]; then
        log "ERROR" "Gateway host is required (-g/--gateway or GATEWAY_HOST in config)"
        ((errors++))
    fi
    
    if [[ -z "$SSH_USER" ]]; then
        log "ERROR" "SSH user is required (-u/--user or SSH_USER in config)"
        ((errors++))
    fi
    
    # Set default certificate paths if not specified
    if [[ -z "$CERT_PATH" ]]; then
        CERT_PATH="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
    fi
    
    if [[ -z "$KEY_PATH" ]]; then
        KEY_PATH="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
    fi
    
    if [[ -z "$CA_PATH" ]]; then
        CA_PATH="/etc/letsencrypt/live/$DOMAIN/chain.pem"
    fi
    
    # Validate certificate files exist
    if [[ ! -f "$CERT_PATH" ]]; then
        log "ERROR" "Certificate file not found: $CERT_PATH"
        ((errors++))
    fi
    
    if [[ ! -f "$KEY_PATH" ]]; then
        log "ERROR" "Private key file not found: $KEY_PATH"
        ((errors++))
    fi
    
    if [[ ! -f "$CA_PATH" ]]; then
        log "WARN" "CA certificate file not found: $CA_PATH (will skip)"
    fi
    
    if [[ $errors -gt 0 ]]; then
        log "ERROR" "Configuration validation failed with $errors error(s)"
        exit 1
    fi
}

# Test SSH connectivity to gateway
test_ssh_connection() {
    local ssh_opts=()
    
    [[ -n "$SSH_KEY" ]] && ssh_opts+=("-i" "$SSH_KEY")
    [[ -n "$SSH_PORT" ]] && ssh_opts+=("-p" "$SSH_PORT")
    ssh_opts+=("-o" "ConnectTimeout=10")
    ssh_opts+=("-o" "BatchMode=yes")
    ssh_opts+=("-o" "StrictHostKeyChecking=no")
    
    log "INFO" "Testing SSH connection to $SSH_USER@$GATEWAY_HOST"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "[DRY RUN] Would test SSH connection to $SSH_USER@$GATEWAY_HOST"
        return 0
    fi
    
    if ssh "${ssh_opts[@]}" "$SSH_USER@$GATEWAY_HOST" "echo 'SSH connection successful'" >/dev/null 2>&1; then
        log "INFO" "SSH connection test successful"
        return 0
    else
        log "ERROR" "SSH connection test failed"
        return 1
    fi
}

# Upload certificate files to gateway
upload_certificates() {
    local ssh_opts=()
    local scp_opts=()
    
    [[ -n "$SSH_KEY" ]] && ssh_opts+=("-i" "$SSH_KEY") && scp_opts+=("-i" "$SSH_KEY")
    [[ -n "$SSH_PORT" ]] && ssh_opts+=("-p" "$SSH_PORT") && scp_opts+=("-P" "$SSH_PORT")
    ssh_opts+=("-o" "StrictHostKeyChecking=no")
    scp_opts+=("-o" "StrictHostKeyChecking=no")
    
    local remote_dir="/tmp/ssl-deploy-$$"
    
    log "INFO" "Creating temporary directory on gateway"
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "[DRY RUN] Would create directory: $remote_dir"
    else
        ssh "${ssh_opts[@]}" "$SSH_USER@$GATEWAY_HOST" "mkdir -p $remote_dir"
    fi
    
    log "INFO" "Uploading certificate files"
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "[DRY RUN] Would upload: $CERT_PATH -> $remote_dir/server.crt"
        log "INFO" "[DRY RUN] Would upload: $KEY_PATH -> $remote_dir/server.key"
        [[ -f "$CA_PATH" ]] && log "INFO" "[DRY RUN] Would upload: $CA_PATH -> $remote_dir/ca.crt"
    else
        scp "${scp_opts[@]}" "$CERT_PATH" "$SSH_USER@$GATEWAY_HOST:$remote_dir/server.crt" >/dev/null
        scp "${scp_opts[@]}" "$KEY_PATH" "$SSH_USER@$GATEWAY_HOST:$remote_dir/server.key" >/dev/null
        [[ -f "$CA_PATH" ]] && scp "${scp_opts[@]}" "$CA_PATH" "$SSH_USER@$GATEWAY_HOST:$remote_dir/ca.crt" >/dev/null
    fi
    
    echo "$remote_dir"
}

# Install certificates on UniFi gateway
install_certificates_unifi() {
    local remote_dir="$1"
    local ssh_opts=()
    
    [[ -n "$SSH_KEY" ]] && ssh_opts+=("-i" "$SSH_KEY")
    [[ -n "$SSH_PORT" ]] && ssh_opts+=("-p" "$SSH_PORT")
    ssh_opts+=("-o" "StrictHostKeyChecking=no")
    
    log "INFO" "Installing certificates on UniFi gateway"
    
    local install_script="
        set -e
        
        # Backup existing certificates
        cp /etc/ssl/private/cloudkey.crt /etc/ssl/private/cloudkey.crt.backup.\$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
        cp /etc/ssl/private/cloudkey.key /etc/ssl/private/cloudkey.key.backup.\$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
        
        # Install new certificates
        cp $remote_dir/server.crt /etc/ssl/private/cloudkey.crt
        cp $remote_dir/server.key /etc/ssl/private/cloudkey.key
        
        # Set proper permissions
        chmod 644 /etc/ssl/private/cloudkey.crt
        chmod 600 /etc/ssl/private/cloudkey.key
        chown root:ssl-cert /etc/ssl/private/cloudkey.crt
        chown root:ssl-cert /etc/ssl/private/cloudkey.key
        
        # Clean up temporary files
        rm -rf $remote_dir
        
        # Restart services
        systemctl restart nginx
        systemctl restart unifi 2>/dev/null || true
        
        echo 'Certificate installation completed successfully'
    "
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "[DRY RUN] Would execute certificate installation script"
        log "INFO" "[DRY RUN] Script content:"
        echo "$install_script" | sed 's/^/[DRY RUN]   /'
    else
        ssh "${ssh_opts[@]}" "$SSH_USER@$GATEWAY_HOST" "$install_script"
    fi
}

# Install certificates on EdgeOS gateway
install_certificates_edgeos() {
    local remote_dir="$1"
    local ssh_opts=()
    
    [[ -n "$SSH_KEY" ]] && ssh_opts+=("-i" "$SSH_KEY")
    [[ -n "$SSH_PORT" ]] && ssh_opts+=("-p" "$SSH_PORT")
    ssh_opts+=("-o" "StrictHostKeyChecking=no")
    
    log "INFO" "Installing certificates on EdgeOS gateway"
    
    local install_script="
        set -e
        
        # Enter configuration mode
        configure
        
        # Backup existing certificates
        cp /config/ssl/server.pem /config/ssl/server.pem.backup.\$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
        
        # Combine certificate and key for EdgeOS
        cat $remote_dir/server.crt $remote_dir/server.key > /config/ssl/server.pem
        
        # Set proper permissions
        chmod 600 /config/ssl/server.pem
        chown root:vyattacfg /config/ssl/server.pem
        
        # Configure SSL certificate
        set service gui cert-file /config/ssl/server.pem
        
        # Commit and save configuration
        commit
        save
        exit
        
        # Clean up temporary files
        rm -rf $remote_dir
        
        # Restart web server
        sudo /etc/init.d/lighttpd restart
        
        echo 'Certificate installation completed successfully'
    "
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "[DRY RUN] Would execute EdgeOS certificate installation script"
        log "INFO" "[DRY RUN] Script content:"
        echo "$install_script" | sed 's/^/[DRY RUN]   /'
    else
        ssh "${ssh_opts[@]}" "$SSH_USER@$GATEWAY_HOST" "$install_script"
    fi
}

# Detect gateway type and install certificates accordingly
install_certificates() {
    local remote_dir="$1"
    local ssh_opts=()
    
    [[ -n "$SSH_KEY" ]] && ssh_opts+=("-i" "$SSH_KEY")
    [[ -n "$SSH_PORT" ]] && ssh_opts+=("-p" "$SSH_PORT")
    ssh_opts+=("-o" "StrictHostKeyChecking=no")
    
    log "INFO" "Detecting gateway type"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "[DRY RUN] Would detect gateway type and install certificates"
        log "INFO" "[DRY RUN] Using configured gateway type: ${GATEWAY_TYPE:-auto}"
        
        case "${GATEWAY_TYPE:-auto}" in
            "unifi"|"cloudkey")
                install_certificates_unifi "$remote_dir"
                ;;
            "edgeos"|"edge")
                install_certificates_edgeos "$remote_dir"
                ;;
            "auto"|*)
                log "INFO" "[DRY RUN] Would auto-detect gateway type"
                install_certificates_unifi "$remote_dir"
                ;;
        esac
        return
    fi
    
    # Auto-detect gateway type based on filesystem
    local gateway_type=""
    
    if ssh "${ssh_opts[@]}" "$SSH_USER@$GATEWAY_HOST" "test -d /usr/lib/unifi" >/dev/null 2>&1; then
        gateway_type="unifi"
    elif ssh "${ssh_opts[@]}" "$SSH_USER@$GATEWAY_HOST" "test -f /opt/vyatta/sbin/vyatta-cfg-cmd-wrapper" >/dev/null 2>&1; then
        gateway_type="edgeos"
    else
        log "WARN" "Could not auto-detect gateway type, assuming UniFi"
        gateway_type="unifi"
    fi
    
    log "INFO" "Detected gateway type: $gateway_type"
    
    case "$gateway_type" in
        "unifi")
            install_certificates_unifi "$remote_dir"
            ;;
        "edgeos")
            install_certificates_edgeos "$remote_dir"
            ;;
        *)
            log "ERROR" "Unsupported gateway type: $gateway_type"
            exit 1
            ;;
    esac
}

# Main deployment function
deploy_certificate() {
    log "INFO" "Starting SSL certificate deployment for $DOMAIN"
    
    # Test SSH connection
    if ! test_ssh_connection; then
        log "ERROR" "Cannot connect to gateway, aborting deployment"
        exit 1
    fi
    
    # Upload certificates
    local remote_dir
    remote_dir=$(upload_certificates)
    
    # Install certificates
    install_certificates "$remote_dir"
    
    log "INFO" "SSL certificate deployment completed successfully"
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -d|--domain)
                DOMAIN="$2"
                shift 2
                ;;
            -g|--gateway)
                GATEWAY_HOST="$2"
                shift 2
                ;;
            -u|--user)
                SSH_USER="$2"
                shift 2
                ;;
            -k|--keyfile)
                SSH_KEY="$2"
                shift 2
                ;;
            -p|--port)
                SSH_PORT="$2"
                shift 2
                ;;
            --cert-path)
                CERT_PATH="$2"
                shift 2
                ;;
            --key-path)
                KEY_PATH="$2"
                shift 2
                ;;
            --ca-path)
                CA_PATH="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN="true"
                shift
                ;;
            -v|--verbose)
                VERBOSE="true"
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

# Main script execution
main() {
    # Set defaults
    SSH_PORT="${SSH_PORT:-22}"
    DRY_RUN="${DRY_RUN:-false}"
    VERBOSE="${VERBOSE:-false}"
    
    # Parse command line arguments first
    parse_args "$@"
    
    # Load configuration file (command line args take precedence)
    load_config "$CONFIG_FILE"
    
    # Validate configuration
    validate_config
    
    # Deploy certificate
    deploy_certificate
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi