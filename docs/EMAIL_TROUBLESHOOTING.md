# Email Delivery Troubleshooting Guide

This guide provides detailed troubleshooting steps for resolving email delivery issues with the Security Hub Compliance Analyzer.

## Prerequisites

Before troubleshooting, ensure you have:

1. AWS CLI configured with appropriate credentials
2. Verified sender email address in Amazon SES
3. Appropriate SES permissions configured
4. Lambda function deployed with proper IAM permissions

## Common Issues and Solutions

### Email Not Sending

1. **SES Verification Issues**
   - Ensure sender email is verified in SES
   - In AWS SES sandbox mode, recipient emails must also be verified
   - Run `./check_ses_status.sh` to verify email status

2. **IAM Permission Issues**
   - Lambda function must have `ses:SendEmail` and `ses:SendRawEmail` permissions
   - Check Lambda execution role in the AWS Console
   - Add missing permissions if needed:
   ```json
   {
       "Version": "2012-10-17",
       "Statement": [
           {
               "Effect": "Allow",
               "Action": [
                   "ses:SendEmail",
                   "ses:SendRawEmail"
               ],
               "Resource": "*"
           }
       ]
   }
   ```

3. **Environment Variables**
   - `SENDER_EMAIL` must be set in Lambda environment
   - Ensure it matches a verified email address in SES

### Emails Going to Spam

1. **SPF/DKIM Setup**
   - Configure SPF and DKIM for your domain if using a custom domain
   - DKIM signing is available in the SES console

2. **Email Content**
   - Avoid spam trigger words in subject and content
   - Ensure proper HTML formatting

3. **Reputation**
   - SES account might have reputation issues
   - Check SES dashboard for reputation metrics

## Testing Email Delivery

### Basic Email Delivery Testing

Use the provided testing script to isolate where the issue is occurring:

```bash
# Set the sender and recipient emails
export SENDER_EMAIL="your-verified-sender@example.com"
export RECIPIENT_EMAIL="recipient@example.com"

# Run the test script
./test_ses_delivery.sh
```

This script tests email delivery through:
1. Basic SES API
2. Direct Python scripts
3. Lambda function

If some tests succeed while others fail, this helps pinpoint the issue.

### Testing NIST 800-53 Control Status Emails

For testing the more complex NIST 800-53 control status emails:

```bash
# Option 1: Generate HTML locally and view in browser
./debug_email_output.py
# Open debug_email.html in your browser to verify formatting

# Option 2: Send debug email directly
./send_debug_email.py --sender your-verified@email.com --recipient your-verified@email.com

# Option 3: Test through Lambda
./test_nist_direct_controls.sh
```

These specialized debug scripts help isolate whether the issue is with:
- Email delivery in general
- Complex HTML rendering
- Lambda configuration
- Control status data retrieval

## Step-by-Step Diagnosis

1. **Check SES Configuration**
   ```bash
   CHECK_EMAIL=your-verified-email@example.com ./check_ses_status.sh
   ```

2. **Test Direct SES Delivery**
   ```bash
   aws ses send-email \
     --profile sandbox \
     --from your-verified-email@example.com \
     --destination "ToAddresses=recipient@example.com" \
     --message "Subject={Data=Test Email,Charset=UTF-8},Body={Text={Data=Test content,Charset=UTF-8}}"
   ```

3. **Check Lambda Configuration**
   - Verify `SENDER_EMAIL` environment variable
   - Check Lambda execution role permissions
   - Review CloudWatch logs for errors

4. **Test Lambda Email Function**
   ```bash
   RECIPIENT_EMAIL=recipient@example.com ./trigger_test_email.sh
   ```

## Lambda CloudWatch Logs

Look for these specific error patterns in Lambda logs:

1. **SES Verification Errors**
   ```
   Email address is not verified. The following identities failed the check...
   ```

2. **Permission Denied**
   ```
   User: arn:aws:sts::... is not authorized to perform: ses:SendRawEmail
   ```

3. **Rate Limiting**
   ```
   Throttling Exception: Rate exceeded
   ```

## Moving Out of SES Sandbox

If you're in the SES sandbox, you're limited to sending to verified email addresses only. To move out of the sandbox:

1. Request production access through the SES console
2. Provide business case and sending patterns
3. Once approved, you can send to any recipient

## Need More Help?

If you're still experiencing issues after following this guide, check the AWS SES documentation or contact AWS Support for further assistance.