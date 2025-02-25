#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}SecurityHub SOC 2 Email Reporter - Deployment Script${NC}"
echo "========================================================"

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo -e "${RED}Error: AWS CLI is not installed. Please install it first.${NC}"
    exit 1
fi

# Parse command line arguments
AWS_PROFILE=""
SENDER_EMAIL=""
RECIPIENT_EMAIL=""

while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --profile)
            AWS_PROFILE="$2"
            shift 2
            ;;
        --profile=*)
            AWS_PROFILE="${1#*=}"
            shift
            ;;
        --sender-email)
            SENDER_EMAIL="$2"
            shift 2
            ;;
        --recipient-email)
            RECIPIENT_EMAIL="$2"
            shift 2
            ;;
        *)
            echo -e "${RED}Unknown option: $key${NC}"
            echo "Usage: ./deploy.sh [--profile <aws-profile>] [--sender-email <email>] [--recipient-email <email>]"
            exit 1
            ;;
    esac
done

# Set AWS profile if provided
if [ -n "$AWS_PROFILE" ]; then
    echo -e "${YELLOW}Using AWS profile: $AWS_PROFILE${NC}"
    export AWS_PROFILE="$AWS_PROFILE"
fi

# Get AWS account ID and region
AWS_CMD="aws"
AWS_ACCOUNT_ID=$($AWS_CMD sts get-caller-identity --query Account --output text)
AWS_REGION=$($AWS_CMD configure get region)

if [ -z "$AWS_REGION" ]; then
    echo -e "${YELLOW}AWS region not found in config. Using us-east-1 as default.${NC}"
    AWS_REGION="us-east-1"
fi

# Prompt for email addresses if not provided
if [ -z "$SENDER_EMAIL" ]; then
    read -p "Enter sender email address (must be verified in SES): " SENDER_EMAIL
fi

if [ -z "$RECIPIENT_EMAIL" ]; then
    read -p "Enter recipient email address (must be verified in SES): " RECIPIENT_EMAIL
fi

echo -e "${YELLOW}Verifying email addresses in SES...${NC}"
echo "Checking if sender email $SENDER_EMAIL is verified in SES..."
SENDER_VERIFIED=$(aws ses get-identity-verification-attributes --identities "$SENDER_EMAIL" --query "VerificationAttributes.$SENDER_EMAIL.VerificationStatus" --output text)

if [ "$SENDER_VERIFIED" != "Success" ]; then
    echo -e "${YELLOW}Sending verification email to $SENDER_EMAIL...${NC}"
    aws ses verify-email-identity --email-address "$SENDER_EMAIL"
    echo -e "${RED}Please check your email and verify the sender address before continuing.${NC}"
    echo "Press Enter to continue once you've verified the email, or Ctrl+C to cancel."
    read
fi

echo "Checking if recipient email $RECIPIENT_EMAIL is verified in SES..."
RECIPIENT_VERIFIED=$(aws ses get-identity-verification-attributes --identities "$RECIPIENT_EMAIL" --query "VerificationAttributes.$RECIPIENT_EMAIL.VerificationStatus" --output text)

if [ "$RECIPIENT_VERIFIED" != "Success" ]; then
    echo -e "${YELLOW}Sending verification email to $RECIPIENT_EMAIL...${NC}"
    aws ses verify-email-identity --email-address "$RECIPIENT_EMAIL"
    echo -e "${RED}Please check your email and verify the recipient address before continuing.${NC}"
    echo "Press Enter to continue once you've verified the email, or Ctrl+C to cancel."
    read
fi

# Package Lambda code
echo -e "${YELLOW}Packaging Lambda code...${NC}"
S3_BUCKET_NAME="securityhub-soc2-analyzer-$(date +%s)-deployment"
echo -e "${YELLOW}Creating S3 bucket for deployment: $S3_BUCKET_NAME${NC}"
aws s3 mb s3://$S3_BUCKET_NAME --region $AWS_REGION

# Run the package_for_cloudformation.sh script
echo -e "${YELLOW}Running packaging script...${NC}"
cd ..
./scripts/package_for_cloudformation.sh --bucket $S3_BUCKET_NAME --region $AWS_REGION
cd scripts

# Deploy the application
echo -e "${YELLOW}Deploying the application...${NC}"

# Build CloudFormation deployment command
CF_DEPLOY_CMD="aws cloudformation create-stack \
  --stack-name securityhub-soc2-analyzer \
  --template-body file://../deployment/cloudformation.yaml \
  --capabilities CAPABILITY_IAM \
  --parameters \
    ParameterKey=SenderEmail,ParameterValue=$SENDER_EMAIL \
    ParameterKey=RecipientEmail,ParameterValue=$RECIPIENT_EMAIL \
    ParameterKey=S3BucketName,ParameterValue=$S3_BUCKET_NAME \
    ParameterKey=S3KeyName,ParameterValue=lambda-code.zip"

# Execute the deployment
echo "Running: $CF_DEPLOY_CMD"
eval $CF_DEPLOY_CMD

if [ $? -ne 0 ]; then
    echo -e "${RED}Deployment failed. Please check the errors above.${NC}"
    exit 1
fi

echo -e "${GREEN}Deployment successful!${NC}"
echo "========================================================"
echo -e "${GREEN}SecurityHub SOC 2 Email Reporter has been deployed successfully!${NC}"
echo ""
echo "To test the solution, run:"
echo -e "${YELLOW}aws lambda invoke --function-name securityhub-soc2-analyzer-EmailFunction --payload '{\"test_email\":true}' response.json${NC}"
echo ""
echo "You should receive a test email shortly if everything is configured correctly."
echo ""
echo "Next steps:"
echo "1. Ensure AWS SecurityHub is enabled in your account"
echo "2. Wait for findings to be generated or create test findings"
echo "3. The Lambda function will run on a schedule to analyze findings"
echo ""
echo "For more information, refer to the docs/DEPLOYMENT_GUIDE.md file."