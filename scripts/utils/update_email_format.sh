#!/bin/bash
# Script to update only the app.py file in the Lambda function

# Set variables
FUNCTION_NAME="security-hub-compliance-analyzer-SecurityHubAnalyzer"
PROFILE="sandbox"

# Create a temporary directory
TEMP_DIR=$(mktemp -d)
echo "Created temporary directory: $TEMP_DIR"

# Copy the file we want to update
echo "Copying app.py to temporary directory..."
cp /Users/comoelcoqui/repos/security-hub-compliance-analyzer/src/app.py "$TEMP_DIR/"

# Change to temp directory
cd "$TEMP_DIR"

# Create ZIP file with just the app.py file
echo "Creating ZIP file..."
zip -r lambda-update.zip app.py

# Update Lambda function
echo "Updating Lambda function's app.py file..."
aws lambda update-function-code \
  --function-name "$FUNCTION_NAME" \
  --zip-file fileb://lambda-update.zip \
  --profile "$PROFILE"

# Clean up
cd -
rm -rf "$TEMP_DIR"
echo "Temporary directory removed."

echo "Lambda function update completed."