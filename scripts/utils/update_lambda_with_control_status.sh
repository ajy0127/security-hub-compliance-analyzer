#!/bin/bash
# Script to update Lambda function with the new NIST control status code

# Function name
FUNCTION_NAME="security-hub-compliance-analyzer-SecurityHubAnalyzer"

# Set AWS profile
if [ -z "$AWS_PROFILE" ]; then
  echo "AWS_PROFILE environment variable not set, using sandbox"
  AWS_PROFILE="sandbox"
fi

echo "Updating Lambda function with NIST 800-53 control status code..."
echo "Using AWS profile: $AWS_PROFILE"

# Create a deployment package
echo "Creating deployment package..."
# First copy files to a temporary directory
rm -rf lambda_package
mkdir -p lambda_package

# Copy files correctly
cp src/app.py lambda_package/
cp src/utils.py lambda_package/
cp src/soc2_mapper.py lambda_package/
cp src/requirements.txt lambda_package/
cp src/framework_mapper.py lambda_package/
cp src/mapper_factory.py lambda_package/
mkdir -p lambda_package/mappers
cp src/mappers/*.py lambda_package/mappers/

# Create zip from the temporary directory
cd lambda_package
zip -r ../lambda-code-control-status.zip * 
cd ..

# Update the Lambda function code
echo "Updating Lambda function code..."
aws lambda update-function-code \
  --profile $AWS_PROFILE \
  --function-name $FUNCTION_NAME \
  --zip-file fileb://lambda-code-control-status.zip \
  --publish

echo "Lambda function updated. Wait a few seconds for the update to complete."
echo "Then run the test_direct_email.py script to test the new functionality."