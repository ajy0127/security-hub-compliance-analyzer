#!/bin/bash
# ============================================================================
# Script to test the NIST 800-53 direct control status reporting functionality
# 
# This script invokes the Lambda function to generate a cATO-focused report
# using direct control status data from Security Hub, rather than just findings.
# ============================================================================

# Get recipient email from environment variable or prompt user
if [ -z "$RECIPIENT_EMAIL" ]; then
  echo "RECIPIENT_EMAIL environment variable not set"
  echo -n "Enter recipient email address: "
  read RECIPIENT_EMAIL
fi

# Get AWS profile to use
if [ -z "$AWS_PROFILE" ]; then
  echo "AWS_PROFILE environment variable not set, using sandbox"
  AWS_PROFILE="sandbox"
fi

echo "Testing NIST 800-53 direct control status reporting"
echo "=================================================="
echo "Using AWS profile: $AWS_PROFILE"
echo "Sending email to: $RECIPIENT_EMAIL"
echo

# Create payload for the Lambda function
PAYLOAD="{
  \"email\": \"$RECIPIENT_EMAIL\",
  \"framework\": \"NIST800-53\",
  \"hours\": 24
}"

echo "Invoking Lambda function with NIST 800-53 direct control reporting..."
aws lambda invoke \
  --profile $AWS_PROFILE \
  --function-name "security-hub-compliance-analyzer-SecurityHubAnalyzer" \
  --payload "$PAYLOAD" \
  --cli-binary-format raw-in-base64-out \
  nist_direct_control_response.json

echo "Response saved to nist_direct_control_response.json"
echo "Response:"
cat nist_direct_control_response.json

echo 
echo "If the Lambda function was successful, check your email for the enhanced NIST 800-53 report"
echo "The report should contain control family breakdowns and compliance status percentages"