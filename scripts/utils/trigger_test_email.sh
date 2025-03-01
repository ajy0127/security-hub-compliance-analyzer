#!/bin/bash
# Script to invoke the SecurityHub Compliance Analyzer Lambda for a test email

# Function name
FUNCTION_NAME="security-hub-compliance-analyzer-SecurityHubAnalyzer"

# Get recipient email from environment variable or prompt user
if [ -z "$RECIPIENT_EMAIL" ]; then
  echo "RECIPIENT_EMAIL environment variable not set"
  echo -n "Enter recipient email address: "
  read RECIPIENT_EMAIL
fi

# Create payload for test email
PAYLOAD="{\"test_email\":true,\"recipient_email\":\"$RECIPIENT_EMAIL\"}"

echo "Invoking Lambda function '$FUNCTION_NAME' with the sandbox profile"
echo "Sending test email to: $RECIPIENT_EMAIL"

# Invoke the Lambda function using AWS CLI with the sandbox profile
aws lambda invoke \
  --profile sandbox \
  --function-name "$FUNCTION_NAME" \
  --payload "$PAYLOAD" \
  --cli-binary-format raw-in-base64-out \
  test_email_response.json

echo "Response saved to test_email_response.json"

# Print the response
echo "Response:"
cat test_email_response.json