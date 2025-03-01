#!/bin/bash
# Script to invoke the Lambda with a specific environment override

# Function name
FUNCTION_NAME="security-hub-compliance-analyzer-SecurityHubAnalyzer"

# Get recipient email from environment variable or prompt user
if [ -z "$RECIPIENT_EMAIL" ]; then
  echo "RECIPIENT_EMAIL environment variable not set"
  echo -n "Enter recipient email address: "
  read RECIPIENT_EMAIL
fi

# Create payload with environment variables
PAYLOAD="{
  \"email\": \"$RECIPIENT_EMAIL\", 
  \"framework\": \"NIST800-53\",
  \"hours\": 24,
  \"generate_csv\": true,
  \"combined_analysis\": false
}"

echo "Invoking Lambda function with custom payload"
echo "Sending report to: $RECIPIENT_EMAIL"

# Invoke the Lambda function
aws lambda invoke \
  --profile sandbox \
  --function-name "$FUNCTION_NAME" \
  --payload "$PAYLOAD" \
  --cli-binary-format raw-in-base64-out \
  final_response.json

echo "Response saved to final_response.json"

# Print the response
echo "Response:"
cat final_response.json