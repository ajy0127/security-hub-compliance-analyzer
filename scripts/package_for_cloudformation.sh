#!/bin/bash

# Script to package Lambda code for CloudFormation deployment
# Usage: ./package_for_cloudformation.sh --bucket your-bucket-name

set -e

# Default values
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

# Check if bucket name is provided
if [ -z "$S3_BUCKET" ]; then
  echo "Error: S3 bucket name is required"
  echo "Usage: ./package_for_cloudformation.sh --bucket your-bucket-name [--region your-region]"
  exit 1
fi

echo "Packaging Lambda code for CloudFormation deployment..."
echo "S3 Bucket: $S3_BUCKET"
echo "Region: $REGION"

# Check if the bucket exists, create it if it doesn't
if ! aws s3 ls "s3://$S3_BUCKET" 2>&1 > /dev/null; then
  echo "Bucket does not exist. Creating bucket $S3_BUCKET..."
  aws s3 mb "s3://$S3_BUCKET" --region "$REGION"
else
  echo "Bucket $S3_BUCKET already exists."
fi

# Create a temporary directory for packaging
TEMP_DIR=$(mktemp -d)
echo "Created temporary directory: $TEMP_DIR"

# Copy required files to the temporary directory
echo "Copying files to temporary directory..."
cp ../src/app.py ../src/utils.py ../src/soc2_mapper.py ../src/requirements.txt "$TEMP_DIR/"

# Create a directory for mappings
mkdir -p "$TEMP_DIR/config"
cp ../deployment/config/mappings.json "$TEMP_DIR/config/"

# Make sure we're using the correct directory structure for Lambda
echo "Ensuring proper directory structure for Lambda..."

# Change to the temporary directory
cd "$TEMP_DIR"

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt -t .

# Create the ZIP file
echo "Creating ZIP file..."
zip -r "$ZIP_FILE" .

# Upload the ZIP file to S3
echo "Uploading ZIP file to S3..."
aws s3 cp "$ZIP_FILE" "s3://$S3_BUCKET/$ZIP_FILE"

# Clean up
cd -
rm -rf "$TEMP_DIR"

echo "Package uploaded to s3://$S3_BUCKET/$ZIP_FILE"
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