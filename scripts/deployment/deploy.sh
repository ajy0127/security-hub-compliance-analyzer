#!/bin/bash
# =========================================================================
# Deploy Script for AWS SecurityHub SOC2 Compliance Analyzer
# =========================================================================
# This script automates the deployment of the SecurityHub SOC2 Compliance
# Analyzer to AWS. It handles:
#   1. Email verification in SES
#   2. Lambda code packaging and upload to S3
#   3. CloudFormation stack deployment
#
# Usage:
#   ./deploy.sh [--profile <aws-profile>] [--sender-email <email>] [--recipient-email <email>]
# =========================================================================

set -e  # Exit immediately if a command exits with a non-zero status

# Terminal colors for better user experience
GREEN='\033[0;32m'   # Success messages
YELLOW='\033[1;33m'  # Warning/information messages
RED='\033[0;31m'     # Error messages
NC='\033[0m'         # Reset color

echo -e "${GREEN}SecurityHub SOC2 Compliance Analyzer - Deployment Script${NC}"
echo "========================================================"

# Verify AWS CLI is installed - required for deployment
if ! command -v aws &> /dev/null; then
    echo -e "${RED}Error: AWS CLI is not installed. Please install it first.${NC}"
    echo "Visit https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html for installation instructions."
    exit 1
fi

# Parse command line arguments for configuration options
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

# Get AWS account ID and region for deployment
AWS_CMD="aws"
AWS_ACCOUNT_ID=$($AWS_CMD sts get-caller-identity --query Account --output text)
AWS_REGION=$($AWS_CMD configure get region)

# Default to us-east-1 if region not found in AWS config
if [ -z "$AWS_REGION" ]; then
    echo -e "${YELLOW}AWS region not found in config. Using us-east-1 as default.${NC}"
    AWS_REGION="us-east-1"
fi

# Prompt for email addresses if not provided via command-line arguments
if [ -z "$SENDER_EMAIL" ]; then
    read -p "Enter sender email address (must be verified in SES): " SENDER_EMAIL
fi

if [ -z "$RECIPIENT_EMAIL" ]; then
    read -p "Enter recipient email address (must be verified in SES): " RECIPIENT_EMAIL
fi

# ===== Email Verification in Amazon SES =====
echo -e "${YELLOW}Verifying email addresses in Amazon SES...${NC}"
echo "Checking if sender email $SENDER_EMAIL is verified in SES..."

# Check if sender email is already verified
SENDER_VERIFIED=$(aws ses get-identity-verification-attributes --identities "$SENDER_EMAIL" --query "VerificationAttributes.$SENDER_EMAIL.VerificationStatus" --output text)

# If not verified, send verification email and wait for user confirmation
if [ "$SENDER_VERIFIED" != "Success" ]; then
    echo -e "${YELLOW}Sending verification email to $SENDER_EMAIL...${NC}"
    aws ses verify-email-identity --email-address "$SENDER_EMAIL"
    echo -e "${RED}Please check your email and verify the sender address before continuing.${NC}"
    echo "Press Enter to continue once you've verified the email, or Ctrl+C to cancel."
    read
fi

# Check if recipient email is already verified
echo "Checking if recipient email $RECIPIENT_EMAIL is verified in SES..."
RECIPIENT_VERIFIED=$(aws ses get-identity-verification-attributes --identities "$RECIPIENT_EMAIL" --query "VerificationAttributes.$RECIPIENT_EMAIL.VerificationStatus" --output text)

# If not verified, send verification email and wait for user confirmation
if [ "$RECIPIENT_VERIFIED" != "Success" ]; then
    echo -e "${YELLOW}Sending verification email to $RECIPIENT_EMAIL...${NC}"
    aws ses verify-email-identity --email-address "$RECIPIENT_EMAIL"
    echo -e "${RED}Please check your email and verify the recipient address before continuing.${NC}"
    echo "Press Enter to continue once you've verified the email, or Ctrl+C to cancel."
    read
fi

# ===== Lambda Code Packaging =====
echo -e "${YELLOW}Packaging Lambda code...${NC}"

# Create a unique S3 bucket for deployment artifacts
S3_BUCKET_NAME="security-hub-compliance-analyzer-$(date +%s)-deployment"
echo -e "${YELLOW}Creating S3 bucket for deployment: $S3_BUCKET_NAME${NC}"
aws s3 mb s3://$S3_BUCKET_NAME --region $AWS_REGION

# Run the package_for_cloudformation.sh script to package and upload the Lambda code
echo -e "${YELLOW}Running packaging script to prepare Lambda code...${NC}"
cd ..
./scripts/package_for_cloudformation.sh --bucket $S3_BUCKET_NAME --region $AWS_REGION
cd scripts

# ===== CloudFormation Deployment =====
echo -e "${YELLOW}Deploying the application via CloudFormation...${NC}"

# Build CloudFormation deployment command with parameters
CF_DEPLOY_CMD="aws cloudformation create-stack \
  --stack-name security-hub-compliance-analyzer \
  --template-body file://../deployment/cloudformation.yaml \
  --capabilities CAPABILITY_IAM \
  --parameters \
    ParameterKey=SenderEmail,ParameterValue=$SENDER_EMAIL \
    ParameterKey=RecipientEmail,ParameterValue=$RECIPIENT_EMAIL \
    ParameterKey=S3BucketName,ParameterValue=$S3_BUCKET_NAME \
    ParameterKey=S3KeyName,ParameterValue=lambda-code.zip"

# Execute CloudFormation deployment
echo "Running: $CF_DEPLOY_CMD"
eval $CF_DEPLOY_CMD

# Check if deployment succeeded
if [ $? -ne 0 ]; then
    echo -e "${RED}Deployment failed. Please check the errors above.${NC}"
    exit 1
fi

# ===== Success Message and Next Steps =====
echo -e "${GREEN}Deployment successful!${NC}"
echo "========================================================"
echo -e "${GREEN}SecurityHub SOC2 Compliance Analyzer has been deployed successfully!${NC}"
echo ""
echo "To test the solution, run:"
echo -e "${YELLOW}aws lambda invoke --function-name security-hub-compliance-analyzer-EmailFunction --payload '{\"test_email\":true}' response.json${NC}"
echo ""
echo "You should receive a test email shortly if everything is configured correctly."
echo ""
echo "Next steps:"
echo "1. Ensure AWS SecurityHub is enabled in your account"
echo "2. Wait for findings to be generated or create test findings"
echo "3. The Lambda function will run on a schedule to analyze findings"
echo ""
echo "For more information, refer to the docs/DEPLOYMENT_GUIDE.md file."