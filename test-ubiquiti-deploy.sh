#!/bin/bash

#
# Test script for Ubiquiti SSL deployment
#
# This script validates the deployment script functionality
# without requiring an actual Ubiquiti gateway device
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_SCRIPT="$SCRIPT_DIR/deploy-ubiquiti-ssl.sh"
CONFIG_FILE="$SCRIPT_DIR/ubiquiti-ssl.conf"
TEST_CONFIG="/tmp/test-ubiquiti-ssl.conf"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Test result tracking
TESTS_PASSED=0
TESTS_FAILED=0

# Test logging function
test_log() {
    local level="$1"
    shift
    local message="$*"
    
    case "$level" in
        "PASS")
            echo -e "${GREEN}[PASS]${NC} $message"
            ((TESTS_PASSED++))
            ;;
        "FAIL")
            echo -e "${RED}[FAIL]${NC} $message"
            ((TESTS_FAILED++))
            ;;
        "INFO")
            echo -e "${YELLOW}[INFO]${NC} $message"
            ;;
    esac
}

# Create test configuration
create_test_config() {
    cat > "$TEST_CONFIG" << EOF
DOMAIN="test.example.com"
GATEWAY_HOST="192.168.1.99"
SSH_USER="testuser"
SSH_PORT="22"
GATEWAY_TYPE="unifi"
DRY_RUN="true"
EOF
}

# Create test certificate files
create_test_certificates() {
    local test_dir="/tmp/letsencrypt-test"
    mkdir -p "$test_dir/live/test.example.com"
    
    # Create dummy certificate files
    echo "-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKEz8mY8+TestCertificate
-----END CERTIFICATE-----" > "$test_dir/live/test.example.com/fullchain.pem"
    
    echo "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQTestPrivateKey
-----END PRIVATE KEY-----" > "$test_dir/live/test.example.com/privkey.pem"
    
    echo "-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKEz8mY8+TestChainCertificate
-----END CERTIFICATE-----" > "$test_dir/live/test.example.com/chain.pem"
    
    # Update test config with certificate paths
    cat >> "$TEST_CONFIG" << EOF
CERT_PATH="$test_dir/live/test.example.com/fullchain.pem"
KEY_PATH="$test_dir/live/test.example.com/privkey.pem"
CA_PATH="$test_dir/live/test.example.com/chain.pem"
EOF
}

# Test script existence and permissions
test_script_basic() {
    test_log "INFO" "Testing script basic properties"
    
    if [[ -f "$DEPLOY_SCRIPT" ]]; then
        test_log "PASS" "Deployment script exists"
    else
        test_log "FAIL" "Deployment script not found: $DEPLOY_SCRIPT"
        return 1
    fi
    
    if [[ -x "$DEPLOY_SCRIPT" ]]; then
        test_log "PASS" "Deployment script is executable"
    else
        test_log "FAIL" "Deployment script is not executable"
        return 1
    fi
}

# Test help output
test_help_output() {
    test_log "INFO" "Testing help output"
    
    if "$DEPLOY_SCRIPT" --help >/dev/null 2>&1; then
        test_log "PASS" "Help option works"
    else
        test_log "FAIL" "Help option failed"
    fi
}

# Test configuration validation
test_config_validation() {
    test_log "INFO" "Testing configuration validation"
    
    # Test missing domain
    local temp_config="/tmp/test-config-missing-domain.conf"
    cat > "$temp_config" << EOF
GATEWAY_HOST="192.168.1.1"
SSH_USER="testuser"
DRY_RUN="true"
EOF
    
    if ! "$DEPLOY_SCRIPT" -c "$temp_config" >/dev/null 2>&1; then
        test_log "PASS" "Correctly rejects missing domain configuration"
    else
        test_log "FAIL" "Should reject missing domain configuration"
    fi
    
    rm -f "$temp_config"
}

# Test dry run functionality
test_dry_run() {
    test_log "INFO" "Testing dry run functionality"
    
    if "$DEPLOY_SCRIPT" -c "$TEST_CONFIG" --dry-run >/dev/null 2>&1; then
        test_log "PASS" "Dry run mode executes successfully"
    else
        test_log "FAIL" "Dry run mode failed"
    fi
}

# Test command line argument parsing
test_argument_parsing() {
    test_log "INFO" "Testing command line argument parsing"
    
    # Test various argument combinations with test certificate files
    if "$DEPLOY_SCRIPT" -d "test.com" -g "1.1.1.1" -u "user" \
        --cert-path "/tmp/letsencrypt-test/live/test.example.com/fullchain.pem" \
        --key-path "/tmp/letsencrypt-test/live/test.example.com/privkey.pem" \
        --ca-path "/tmp/letsencrypt-test/live/test.example.com/chain.pem" \
        --dry-run >/dev/null 2>&1; then
        test_log "PASS" "Command line arguments parsed correctly"
    else
        test_log "FAIL" "Command line argument parsing failed"
    fi
}

# Test configuration file loading
test_config_loading() {
    test_log "INFO" "Testing configuration file loading"
    
    if "$DEPLOY_SCRIPT" -c "$TEST_CONFIG" --dry-run >/dev/null 2>&1; then
        test_log "PASS" "Configuration file loads successfully"
    else
        test_log "FAIL" "Configuration file loading failed"
    fi
}

# Clean up test files
cleanup() {
    rm -f "$TEST_CONFIG"
    rm -rf "/tmp/letsencrypt-test"
    rm -f "/tmp/test-config-"*.conf
}

# Main test execution
main() {
    test_log "INFO" "Starting Ubiquiti SSL deployment script tests"
    test_log "INFO" "Script location: $DEPLOY_SCRIPT"
    
    # Setup test environment
    create_test_config
    create_test_certificates
    
    # Run tests
    test_script_basic
    test_help_output
    test_config_validation
    test_dry_run
    test_argument_parsing
    test_config_loading
    
    # Cleanup
    cleanup
    
    # Report results
    echo
    test_log "INFO" "Test Summary:"
    test_log "INFO" "Tests Passed: $TESTS_PASSED"
    test_log "INFO" "Tests Failed: $TESTS_FAILED"
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        test_log "INFO" "All tests passed!"
        exit 0
    else
        test_log "INFO" "Some tests failed!"
        exit 1
    fi
}

# Run tests if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi