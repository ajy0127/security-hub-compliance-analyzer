#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}Testing AWS Lambda Function Locally${NC}"
echo "========================================================"

# Get the script directory and project root
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"
SRC_DIR="$PROJECT_ROOT/src"
EXAMPLES_DIR="$PROJECT_ROOT/examples"

# Check if profile name is provided
if [ $# -eq 0 ]; then
    echo -e "${YELLOW}No profile specified, using default AWS profile${NC}"
    PROFILE_ARG=""
else
    PROFILE="$1"
    echo -e "${YELLOW}Using profile: $PROFILE${NC}"
    PROFILE_ARG="--profile $PROFILE"
    export AWS_PROFILE="$PROFILE"
fi

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo -e "${RED}Error: AWS CLI is not installed. Please install it first.${NC}"
    exit 1
fi

# Check if the source files exist
if [ ! -f "$SRC_DIR/app.py" ]; then
    echo -e "${RED}Error: app.py not found in $SRC_DIR. Please check the project structure.${NC}"
    exit 1
fi

# Setup virtual environment if it doesn't exist
if [ ! -d "$PROJECT_ROOT/venv" ]; then
    echo -e "${YELLOW}Creating virtual environment...${NC}"
    python3 -m venv "$PROJECT_ROOT/venv"
    source "$PROJECT_ROOT/venv/bin/activate"
    pip install -r "$SRC_DIR/requirements.txt"
else
    source "$PROJECT_ROOT/venv/bin/activate"
fi

# Test options
echo -e "${YELLOW}Select test option:${NC}"
echo "1. Send test email"
echo "2. Generate report with findings from the last 24 hours"
echo "3. Generate report with findings from the last 7 days"
echo "4. Custom event"
read -p "Enter option (1-4): " option

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
        EVENT='{"findings_hours": 168}'
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

# Set environment variables for testing
export SENDER_EMAIL="your-verified-email@example.com"
export RECIPIENT_EMAIL="your-email@example.com"
export BEDROCK_MODEL_ID="anthropic.claude-3-sonnet"
export FINDINGS_HOURS="24"

echo -e "${YELLOW}Would you like to set the email environment variables? (y/n)${NC}"
read -p "Update environment variables? " update_env

if [[ "$update_env" = "y" || "$update_env" = "Y" ]]; then
    read -p "Enter sender email (must be verified in SES): " sender_email
    read -p "Enter recipient email (must be verified in SES): " recipient_email
    
    export SENDER_EMAIL="$sender_email"
    export RECIPIENT_EMAIL="$recipient_email"
fi

# Save event to a temporary file
TEMP_EVENT_FILE=$(mktemp)
echo "$EVENT" > "$TEMP_EVENT_FILE"

# Run the Lambda function with the Python script
echo -e "${YELLOW}Running Lambda function with event: $EVENT${NC}"
cd "$PROJECT_ROOT"
PYTHONPATH="$SRC_DIR" python3 -c "
import json
import os
import sys
sys.path.append('$SRC_DIR')
from app import lambda_handler

with open('$TEMP_EVENT_FILE', 'r') as f:
    event = json.load(f)

print('Running lambda_handler with event:', event)
print('Environment variables:')
print('  SENDER_EMAIL:', os.environ.get('SENDER_EMAIL'))
print('  RECIPIENT_EMAIL:', os.environ.get('RECIPIENT_EMAIL'))
print('  BEDROCK_MODEL_ID:', os.environ.get('BEDROCK_MODEL_ID'))
print('  FINDINGS_HOURS:', os.environ.get('FINDINGS_HOURS'))

try:
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

if [ $? -ne 0 ]; then
    echo -e "${RED}Lambda invocation failed. Please check the errors above.${NC}"
    rm -f "$TEMP_EVENT_FILE"
    exit 1
fi

# Clean up temporary file
rm -f "$TEMP_EVENT_FILE"

echo -e "${GREEN}Lambda function invoked successfully!${NC}"
echo "=========================================================" 