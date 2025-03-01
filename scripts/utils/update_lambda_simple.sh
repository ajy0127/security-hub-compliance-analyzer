#!/bin/bash
# Simple script to update the Lambda function with our email changes

# Set variables
FUNCTION_NAME="security-hub-compliance-analyzer-SecurityHubAnalyzer"
PROFILE="sandbox"

# Create a temporary directory for our updated files
TEMP_DIR=$(mktemp -d)
echo "Created temporary directory: $TEMP_DIR"

# Create the structure for our Lambda deployment
mkdir -p "$TEMP_DIR/src"
mkdir -p "$TEMP_DIR/config/mappings"

# Copy our updated app.py file
cp /Users/comoelcoqui/repos/security-hub-compliance-analyzer/src/app.py "$TEMP_DIR/src/"

# Update Lambda with the new code
echo "Updating Lambda function with improved email formatting..."
aws lambda update-function-code \
  --function-name "$FUNCTION_NAME" \
  --zip-file fileb:///Users/comoelcoqui/repos/security-hub-compliance-analyzer/lambda-code.zip \
  --profile "$PROFILE"

echo "Lambda function updated successfully."