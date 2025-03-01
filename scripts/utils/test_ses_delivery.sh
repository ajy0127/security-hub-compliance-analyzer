#!/bin/bash
# Script to test SES email delivery with different methods

# Set default profile
AWS_PROFILE=${AWS_PROFILE:-"sandbox"}

# Get sender and recipient emails
if [ -z "$SENDER_EMAIL" ]; then
  echo "SENDER_EMAIL environment variable not set"
  echo -n "Enter verified sender email address: "
  read SENDER_EMAIL
fi

if [ -z "$RECIPIENT_EMAIL" ]; then
  echo "RECIPIENT_EMAIL environment variable not set"
  echo -n "Enter recipient email address: "
  read RECIPIENT_EMAIL
fi

echo "============================================"
echo "AWS SES Email Delivery Test"
echo "============================================"
echo "Testing email delivery with these parameters:"
echo "AWS Profile: $AWS_PROFILE"
echo "Sender: $SENDER_EMAIL"
echo "Recipient: $RECIPIENT_EMAIL"
echo "============================================"

# Step 1: Check SES verification status
echo "STEP 1: Checking SES verification status"
echo "----------------------------------------"
CHECK_EMAIL=$SENDER_EMAIL ./check_ses_status.sh
echo "----------------------------------------"

# Step 2: Test basic SES email delivery
echo "STEP 2: Testing basic SES email delivery"
echo "----------------------------------------"
echo "Sending basic SES email..."
aws ses send-email \
  --profile $AWS_PROFILE \
  --from $SENDER_EMAIL \
  --destination "ToAddresses=$RECIPIENT_EMAIL" \
  --message "Subject={Data=SES Basic Test Email,Charset=UTF-8},Body={Text={Data=This is a basic test email from AWS SES.,Charset=UTF-8}}" \
  || echo "Error sending basic email"
echo "----------------------------------------"

# Step 3: Run the direct email Python script
echo "STEP 3: Testing email delivery with direct Python script"
echo "----------------------------------------"
python3 send_direct_email.py --profile $AWS_PROFILE --sender $SENDER_EMAIL --recipient $RECIPIENT_EMAIL
echo "----------------------------------------"

# Step 4: Run the specialized NIST email Python script
echo "STEP 4: Testing NIST report email delivery with Python script"
echo "----------------------------------------"
python3 send_direct_nist_email.py --profile $AWS_PROFILE --sender $SENDER_EMAIL --recipient $RECIPIENT_EMAIL
echo "----------------------------------------"

# Step 5: Test Lambda email delivery
echo "STEP 5: Testing Lambda email delivery"
echo "----------------------------------------"
echo "Testing Lambda test email function..."
RECIPIENT_EMAIL=$RECIPIENT_EMAIL ./trigger_test_email.sh
echo "----------------------------------------"

echo "All tests complete. Please check your inbox (and spam folder) for test emails."
echo "If you received some emails but not all, this can help identify where the issue is occurring."