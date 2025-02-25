#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}SecurityHub SOC 2 Email Reporter - CloudFormation Packaging Script${NC}"
echo "========================================================"

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo -e "${RED}Error: AWS CLI is not installed. Please install it first.${NC}"
    exit 1
fi

# Parse command line arguments
S3_BUCKET=""
REGION=""
AWS_PROFILE=""

while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --bucket)
            S3_BUCKET="$2"
            shift 2
            ;;
        --bucket=*)
            S3_BUCKET="${1#*=}"
            shift
            ;;
        --region)
            REGION="$2"
            shift 2
            ;;
        --region=*)
            REGION="${1#*=}"
            shift
            ;;
        --profile)
            AWS_PROFILE="$2"
            shift 2
            ;;
        --profile=*)
            AWS_PROFILE="${1#*=}"
            shift
            ;;
        *)
            echo -e "${RED}Unknown option: $key${NC}"
            echo "Usage: ./package_for_cloudformation.sh --bucket <s3-bucket-name> [--region <aws-region>] [--profile <aws-profile>]"
            exit 1
            ;;
    esac
done

# Check for required parameters
if [ -z "$S3_BUCKET" ]; then
    echo -e "${RED}Error: S3 bucket name is required. Use --bucket parameter.${NC}"
    echo "Usage: ./package_for_cloudformation.sh --bucket <s3-bucket-name> [--region <aws-region>] [--profile <aws-profile>]"
    exit 1
fi

# Set AWS profile if provided
if [ -n "$AWS_PROFILE" ]; then
    echo -e "${YELLOW}Using AWS profile: $AWS_PROFILE${NC}"
    export AWS_PROFILE="$AWS_PROFILE"
fi

# Set AWS region
if [ -z "$REGION" ]; then
    REGION=$(aws configure get region)
    if [ -z "$REGION" ]; then
        echo -e "${YELLOW}AWS region not found in config. Using us-east-1 as default.${NC}"
        REGION="us-east-1"
    fi
    echo -e "${YELLOW}Using AWS region: $REGION${NC}"
fi

# Check if the S3 bucket exists
echo -e "${YELLOW}Checking if S3 bucket exists...${NC}"
if ! aws s3 ls "s3://$S3_BUCKET" &>/dev/null; then
    echo -e "${YELLOW}S3 bucket does not exist. Creating it...${NC}"
    aws s3 mb "s3://$S3_BUCKET" --region "$REGION"
fi

# Create a zip file of all code
echo -e "${YELLOW}Creating Lambda code package...${NC}"
zip -r lambda-code.zip . -x "*.git*" -x "*.zip" -x "venv/*"

# Upload the zip file to S3
echo -e "${YELLOW}Uploading Lambda code package to S3...${NC}"
aws s3 cp lambda-code.zip "s3://$S3_BUCKET/lambda-code.zip"

echo -e "${GREEN}Package uploaded successfully!${NC}"
echo "========================================================"
echo -e "${GREEN}Now you can deploy using CloudFormation with these parameters:${NC}"
echo ""
echo -e "S3BucketName: ${YELLOW}$S3_BUCKET${NC}"
echo ""
echo "Upload the template.yaml file to CloudFormation and provide the parameters."
echo ""
echo "Remember to verify your SES email addresses before deployment!"