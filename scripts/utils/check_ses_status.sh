#!/bin/bash
# Script to check SES verification status and limits

echo "Checking SES account status and verified identities..."

# Check if SES is in sandbox mode
aws ses get-account-sending-enabled --profile sandbox || echo "Error checking sending status"

# Check daily quota
aws ses get-send-quota --profile sandbox || echo "Error checking send quota"

# List verified email identities
echo "Listing verified email identities:"
aws ses list-identities --profile sandbox --identity-type EmailAddress || echo "Error listing identities"

# Get email to check from environment variable or prompt user
if [ -z "$CHECK_EMAIL" ]; then
  echo "CHECK_EMAIL environment variable not set"
  echo -n "Enter email address to check verification status: "
  read CHECK_EMAIL
fi

# Check verification status for the specific email
echo "Checking verification status for $CHECK_EMAIL:"
aws ses get-identity-verification-attributes --profile sandbox --identities "$CHECK_EMAIL" || echo "Error checking verification attributes"