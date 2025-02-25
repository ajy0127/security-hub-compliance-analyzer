#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}Testing AWS Lambda Function Locally${NC}"
echo "========================================================"

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

# Check if SAM CLI is installed
if ! command -v sam &> /dev/null; then
    echo -e "${RED}Error: AWS SAM CLI is not installed. Please install it first.${NC}"
    exit 1
fi

# Build the application if it hasn't been built yet
if [ ! -d ".aws-sam" ]; then
    echo -e "${YELLOW}Building the application...${NC}"
    sam build $PROFILE_ARG
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}Build failed. Please check the errors above.${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}Build successful!${NC}"
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

# Invoke the Lambda function locally
echo -e "${YELLOW}Invoking Lambda function with event: $EVENT${NC}"
sam local invoke $PROFILE_ARG --event <(echo "$EVENT") SecurityHubAnalyzerFunctionZip

if [ $? -ne 0 ]; then
    echo -e "${RED}Lambda invocation failed. Please check the errors above.${NC}"
    exit 1
fi

echo -e "${GREEN}Lambda function invoked successfully!${NC}"
echo "========================================================" 