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

# Get the script directory and project root
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"
SRC_DIR="$PROJECT_ROOT/src"

# Test AWS credentials using the Python script
echo -e "${YELLOW}Running test_credentials.py with profile: $PROFILE${NC}"
python3 "$SRC_DIR/test_credentials.py" --profile "$PROFILE"

if [ $? -ne 0 ]; then
    echo -e "${RED}AWS credential test failed. Please check the errors above.${NC}"
    exit 1
fi

# Test CloudFormation with the profile
echo -e "${YELLOW}Testing CloudFormation with profile: $PROFILE${NC}"
export AWS_PROFILE="$PROFILE"

# Validate the template
echo -e "${YELLOW}Validating CloudFormation template...${NC}"
aws cloudformation validate-template --template-body file://"$PROJECT_ROOT/deployment/cloudformation.yaml"

if [ $? -ne 0 ]; then
    echo -e "${RED}Template validation failed. Please check the errors above.${NC}"
    exit 1
fi

echo -e "${GREEN}Template validation successful!${NC}"

# Check if cfn-lint is installed
if command -v cfn-lint &> /dev/null; then
    echo -e "${YELLOW}Running CloudFormation linting...${NC}"
    cfn-lint "$PROJECT_ROOT/deployment/cloudformation.yaml"
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}CloudFormation linting failed. Please check the errors above.${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}CloudFormation linting successful!${NC}"
else
    echo -e "${YELLOW}cfn-lint not installed, skipping linting.${NC}"
fi

# Test Lambda code packaging
echo -e "${YELLOW}Testing Lambda code packaging...${NC}"
cd "$PROJECT_ROOT"
source "$PROJECT_ROOT/venv/bin/activate" 2>/dev/null || python3 -m venv "$PROJECT_ROOT/venv" && source "$PROJECT_ROOT/venv/bin/activate"
pip install -r "$SRC_DIR/requirements.txt"

if [ $? -ne 0 ]; then
    echo -e "${RED}Dependency installation failed. Please check the errors above.${NC}"
    exit 1
fi

echo -e "${GREEN}Lambda code dependencies installed successfully!${NC}"

echo -e "${GREEN}All tests passed successfully!${NC}"
echo "========================================================"
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Run the deployment script with: ./scripts/deploy.sh --profile $PROFILE --sender-email your-email@example.com --recipient-email your-email@example.com"
echo "2. After deployment, you can test the Lambda function by running: ./scripts/test_lambda_locally.sh $PROFILE"
echo "========================================================" 