#!/bin/bash
# Script to invoke the SecurityHub Compliance Analyzer Lambda with a new email address

# Function name
FUNCTION_NAME="security-hub-compliance-analyzer-SecurityHubAnalyzer"

# Get recipient email from environment variable or prompt user
if [ -z "$RECIPIENT_EMAIL" ]; then
  echo "RECIPIENT_EMAIL environment variable not set"
  echo -n "Enter recipient email address: "
  read RECIPIENT_EMAIL
fi

# Create payload with new email address
PAYLOAD="{\"email\":\"$RECIPIENT_EMAIL\",\"framework\":\"NIST800-53\",\"hours\":24,\"generate_csv\":true,\"combined_analysis\":false}"

echo "Invoking Lambda function '$FUNCTION_NAME' with the sandbox profile"
echo "Sending NIST 800-53 report to: $RECIPIENT_EMAIL"

# Invoke the Lambda function using AWS CLI with the sandbox profile
aws lambda invoke \
  --profile sandbox \
  --function-name "$FUNCTION_NAME" \
  --payload "$PAYLOAD" \
  --cli-binary-format raw-in-base64-out \
  new_email_response.json

echo "Response saved to new_email_response.json"

# Print the response
echo "Response:"
cat new_email_response.json