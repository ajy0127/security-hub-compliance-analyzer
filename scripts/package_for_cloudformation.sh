#!/bin/bash
# =========================================================================
# Lambda Packaging Script for AWS SecurityHub SOC2 Compliance Analyzer
# =========================================================================
# This script packages the Lambda function code for CloudFormation deployment.
# It creates a ZIP file with all necessary source files and dependencies,
# then uploads it to an S3 bucket for CloudFormation to access.
#
# Usage: 
#   ./package_for_cloudformation.sh --bucket your-bucket-name [--region your-region]
# =========================================================================

set -e  # Exit immediately if a command exits with a non-zero status

# Default configuration values
S3_BUCKET=""
REGION="us-east-1"
ZIP_FILE="lambda-code.zip"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    --bucket)
      S3_BUCKET="$2"
      shift
      shift
      ;;
    --region)
      REGION="$2"
      shift
      shift
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Validate required parameters
if [ -z "$S3_BUCKET" ]; then
  echo "Error: S3 bucket name is required"
  echo "Usage: ./package_for_cloudformation.sh --bucket your-bucket-name [--region your-region]"
  exit 1
fi

echo "Packaging Lambda code for CloudFormation deployment..."
echo "S3 Bucket: $S3_BUCKET"
echo "Region: $REGION"

# === S3 Bucket Management ===
# Check if the bucket exists, create it if it doesn't
if ! aws s3 ls "s3://$S3_BUCKET" 2>&1 > /dev/null; then
  echo "Bucket does not exist. Creating bucket $S3_BUCKET..."
  aws s3 mb "s3://$S3_BUCKET" --region "$REGION"
else
  echo "Bucket $S3_BUCKET already exists."
fi

# === Temporary Build Directory Setup ===
# Create a temporary directory for packaging the Lambda function
TEMP_DIR=$(mktemp -d)
echo "Created temporary directory: $TEMP_DIR"

# === Source File Preparation ===
# Copy all required source files to the temporary directory
echo "Copying source files to temporary directory..."
cp ../src/app.py ../src/utils.py ../src/soc2_mapper.py ../src/requirements.txt "$TEMP_DIR/"

# Create a directory for the SOC2 control mappings configuration
echo "Setting up configuration directory structure..."
mkdir -p "$TEMP_DIR/config"
cp ../deployment/config/mappings.json "$TEMP_DIR/config/"

# === Lambda Package Preparation ===
# Change to the temporary directory to install dependencies and create zip
cd "$TEMP_DIR"

# Install dependencies directly into the package directory
echo "Installing Python dependencies..."
pip install -r requirements.txt -t .

# Create the ZIP file containing all code and dependencies
echo "Creating Lambda deployment package (ZIP file)..."
zip -r "$ZIP_FILE" .

# === Upload to S3 ===
# Upload the ZIP file to S3 for CloudFormation to access
echo "Uploading Lambda package to S3 bucket..."
aws s3 cp "$ZIP_FILE" "s3://$S3_BUCKET/$ZIP_FILE"

# === Cleanup ===
# Return to the original directory and clean up temporary files
cd -
rm -rf "$TEMP_DIR"
echo "Cleaned up temporary build directory"

# === Success Message ===
echo "============================================================"
echo "Package successfully uploaded to s3://$S3_BUCKET/$ZIP_FILE"
echo ""
echo "To deploy with CloudFormation, use the following parameters:"
echo "  S3BucketName: $S3_BUCKET"
echo "  S3KeyName: $ZIP_FILE"
echo ""
echo "Example CloudFormation deployment command:"
echo "aws cloudformation create-stack \\"
echo "  --stack-name security-hub-compliance-analyzer \\"
echo "  --template-body file://deployment/cloudformation.yaml \\"
echo "  --capabilities CAPABILITY_IAM \\"
echo "  --parameters \\"
echo "    ParameterKey=SenderEmail,ParameterValue=your-verified@email.com \\"
echo "    ParameterKey=RecipientEmail,ParameterValue=your-verified@email.com \\"
echo "    ParameterKey=S3BucketName,ParameterValue=$S3_BUCKET \\"
echo "    ParameterKey=S3KeyName,ParameterValue=$ZIP_FILE"