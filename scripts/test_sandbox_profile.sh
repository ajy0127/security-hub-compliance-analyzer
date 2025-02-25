#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}Testing AWS Sandbox Profile${NC}"
echo "========================================================"

# Check if profile name is provided
if [ $# -eq 0 ]; then
    echo -e "${YELLOW}No profile specified, using 'sandbox' as default${NC}"
    PROFILE="sandbox"
else
    PROFILE="$1"
    echo -e "${YELLOW}Using profile: $PROFILE${NC}"
fi

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo -e "${RED}Error: AWS CLI is not installed. Please install it first.${NC}"
    exit 1
fi

# Check if the profile exists
if ! aws configure list-profiles | grep -q "^$PROFILE$"; then
    echo -e "${RED}Error: AWS profile '$PROFILE' does not exist.${NC}"
    echo "Please create it first with: aws configure --profile $PROFILE"
    exit 1
fi

echo -e "${YELLOW}Testing AWS credentials with profile: $PROFILE${NC}"

# Test AWS credentials using the Python script
echo -e "${YELLOW}Running test_credentials.py with profile: $PROFILE${NC}"
python3 test_credentials.py --profile "$PROFILE"

if [ $? -ne 0 ]; then
    echo -e "${RED}AWS credential test failed. Please check the errors above.${NC}"
    exit 1
fi

# Test SAM CLI with the profile
echo -e "${YELLOW}Testing SAM CLI with profile: $PROFILE${NC}"
export AWS_PROFILE="$PROFILE"

# Validate the template
echo -e "${YELLOW}Validating CloudFormation template...${NC}"
sam validate --template template.yaml

if [ $? -ne 0 ]; then
    echo -e "${RED}Template validation failed. Please check the errors above.${NC}"
    exit 1
fi

echo -e "${GREEN}Template validation successful!${NC}"

# Test SAM build
echo -e "${YELLOW}Testing SAM build...${NC}"
sam build --use-container

if [ $? -ne 0 ]; then
    echo -e "${RED}SAM build failed. Please check the errors above.${NC}"
    exit 1
fi

echo -e "${GREEN}SAM build successful!${NC}"

echo -e "${GREEN}All tests passed successfully!${NC}"
echo "========================================================"
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Run the deployment script with: ./deploy.sh --profile $PROFILE"
echo "2. For container deployment, add --docker flag: ./deploy.sh --profile $PROFILE --docker"
echo "========================================================" 