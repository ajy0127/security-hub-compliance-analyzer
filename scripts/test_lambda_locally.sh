#!/bin/bash
# =========================================================================
# Local Lambda Testing Script for SecurityHub SOC2 Compliance Analyzer
# =========================================================================
# This script allows you to test the Lambda function locally before deployment.
# It simulates the Lambda environment and invokes the handler function with
# various test events to verify functionality.
#
# Usage: 
#   ./test_lambda_locally.sh [aws-profile-name]
# =========================================================================

set -e  # Exit immediately if a command exits with a non-zero status

# Terminal colors for better user experience
GREEN='\033[0;32m'   # Success messages
YELLOW='\033[1;33m'  # Warning/information messages
RED='\033[0;31m'     # Error messages
NC='\033[0m'         # Reset color (No Color)

echo -e "${GREEN}Testing AWS Lambda Function Locally${NC}"
echo "========================================================"

# Get script and project directories for file references
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"
SRC_DIR="$PROJECT_ROOT/src"
EXAMPLES_DIR="$PROJECT_ROOT/examples"

# === AWS Profile Setup ===
# Check if an AWS profile name was provided as an argument
if [ $# -eq 0 ]; then
    echo -e "${YELLOW}No profile specified, using default AWS profile${NC}"
    PROFILE_ARG=""
else
    PROFILE="$1"
    echo -e "${YELLOW}Using AWS profile: $PROFILE${NC}"
    PROFILE_ARG="--profile $PROFILE"
    export AWS_PROFILE="$PROFILE"
fi

# === Prerequisites Check ===
# Check if AWS CLI is installed - required for accessing AWS services
if ! command -v aws &> /dev/null; then
    echo -e "${RED}Error: AWS CLI is not installed. Please install it first.${NC}"
    echo "Visit https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html for installation instructions."
    exit 1
fi

# Check if the source files exist - verify project structure
if [ ! -f "$SRC_DIR/app.py" ]; then
    echo -e "${RED}Error: app.py not found in $SRC_DIR. Please check the project structure.${NC}"
    exit 1
fi

# === Python Environment Setup ===
# Setup virtual environment if it doesn't exist or activate existing one
if [ ! -d "$PROJECT_ROOT/venv" ]; then
    echo -e "${YELLOW}Creating Python virtual environment...${NC}"
    python3 -m venv "$PROJECT_ROOT/venv"
    source "$PROJECT_ROOT/venv/bin/activate"
    echo -e "${YELLOW}Installing dependencies...${NC}"
    pip install -r "$SRC_DIR/requirements.txt"
else
    echo -e "${YELLOW}Activating existing virtual environment...${NC}"
    source "$PROJECT_ROOT/venv/bin/activate"
fi

# === Test Configuration ===
# Display test options and get user selection
echo -e "${YELLOW}Select test option:${NC}"
echo "1. Send test email"
echo "2. Generate report with findings from the last 24 hours"
echo "3. Generate report with findings from the last 7 days"
echo "4. Custom event"
read -p "Enter option (1-4): " option

# Configure test event based on selection
case $option in
    1)
        echo -e "${YELLOW}Invoking Lambda function to send test email...${NC}"
        EVENT='{"test_email": true}'
        ;;
    2)
        echo -e "${YELLOW}Invoking Lambda function to generate report (24 hours)...${NC}"
        EVENT='{}'
        ;;
    3)
        echo -e "${YELLOW}Invoking Lambda function to generate report (7 days)...${NC}"
        EVENT='{"hours": 168}'
        ;;
    4)
        echo -e "${YELLOW}Enter custom event JSON:${NC}"
        read -p "Event JSON: " custom_event
        EVENT="$custom_event"
        ;;
    *)
        echo -e "${RED}Invalid option. Exiting.${NC}"
        exit 1
        ;;
esac

# === Environment Variables Setup ===
# Set default environment variables
export SENDER_EMAIL="your-verified-email@example.com"
export RECIPIENT_EMAIL="your-email@example.com"
export BEDROCK_MODEL_ID="anthropic.claude-3-sonnet"
export FINDINGS_HOURS="24"

# Prompt to update email environment variables with user values
echo -e "${YELLOW}Would you like to set the email environment variables? (y/n)${NC}"
read -p "Update environment variables? " update_env

if [[ "$update_env" = "y" || "$update_env" = "Y" ]]; then
    read -p "Enter sender email (must be verified in SES): " sender_email
    read -p "Enter recipient email (must be verified in SES): " recipient_email
    
    export SENDER_EMAIL="$sender_email"
    export RECIPIENT_EMAIL="$recipient_email"
    
    echo -e "${YELLOW}Environment variables updated.${NC}"
fi

# === Lambda Invocation ===
# Save event to a temporary file
TEMP_EVENT_FILE=$(mktemp)
echo "$EVENT" > "$TEMP_EVENT_FILE"

# Run the Lambda function with the Python script
echo -e "${YELLOW}Running Lambda function with event: $EVENT${NC}"
cd "$PROJECT_ROOT"

# Use Python to invoke the Lambda handler directly
PYTHONPATH="$SRC_DIR" python3 -c "
import json
import os
import sys
sys.path.append('$SRC_DIR')
from app import lambda_handler

# Load the event from the temporary file
with open('$TEMP_EVENT_FILE', 'r') as f:
    event = json.load(f)

# Display configuration information
print('Running lambda_handler with the following configuration:')
print('Event:', event)
print('Environment variables:')
print('  SENDER_EMAIL:', os.environ.get('SENDER_EMAIL'))
print('  RECIPIENT_EMAIL:', os.environ.get('RECIPIENT_EMAIL'))
print('  BEDROCK_MODEL_ID:', os.environ.get('BEDROCK_MODEL_ID'))
print('  FINDINGS_HOURS:', os.environ.get('FINDINGS_HOURS'))

# Invoke the Lambda handler
try:
    print('\\nInvoking Lambda handler...')
    result = lambda_handler(event, {})
    print('\\nResult:', json.dumps(result, indent=2))
    print('\\nLambda function completed successfully!')
except Exception as e:
    import traceback
    print('\\nError:', str(e))
    traceback.print_exc()
    print('\\nLambda function failed!')
    sys.exit(1)
"

# Check if the Lambda invocation was successful
if [ $? -ne 0 ]; then
    echo -e "${RED}Lambda invocation failed. Please check the errors above.${NC}"
    rm -f "$TEMP_EVENT_FILE"
    exit 1
fi

# === Cleanup ===
# Remove temporary file
rm -f "$TEMP_EVENT_FILE"

# === Success Message ===
echo -e "${GREEN}Lambda function invoked successfully!${NC}"
echo "=========================================================" 