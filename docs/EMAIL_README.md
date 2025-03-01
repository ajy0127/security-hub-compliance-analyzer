# Email Functionality Guide

This guide explains how to use the email functionality in the Security Hub Compliance Analyzer, including the cATO-focused NIST 800-53 email reports.

## Setup

### Prerequisites

1. **AWS SES Configuration**
   - Sender email must be verified in SES
   - If your account is in the SES sandbox, recipient emails must also be verified
   - Lambda function must have appropriate SES permissions

2. **Lambda Environment Variables**
   - `SENDER_EMAIL`: The verified email address to send from
   - `RECIPIENT_EMAIL`: Default recipient email (can be overridden in event payload)

### Email Types

The analyzer supports several types of email reports:

1. **Test Email**: Simple verification that email delivery works
2. **Framework-Specific Reports**: Detailed compliance reports for specific frameworks
3. **NIST 800-53 cATO Reports**: Specialized reports for cATO compliance  
4. **Multi-Framework Reports**: Combined analysis across multiple frameworks

## Using Email Functionality

### Test Email

Send a test email to verify configuration:

```bash
# Set recipient email
export RECIPIENT_EMAIL="recipient@example.com"

# Trigger test email
./trigger_test_email.sh
```

### NIST 800-53 cATO Reports

Send a specialized NIST 800-53 report with cATO-focused content:

```bash
# Set recipient email
export RECIPIENT_EMAIL="recipient@example.com"

# Trigger NIST 800-53 report
./trigger_nist_lambda.sh
```

### Direct Testing

Test email delivery directly without invoking Lambda:

```bash
# Using SES CLI
export SENDER_EMAIL="your-verified-email@example.com" 
export RECIPIENT_EMAIL="recipient@example.com"

# Run the direct email test script
python3 send_direct_email.py --profile sandbox --sender $SENDER_EMAIL --recipient $RECIPIENT_EMAIL
```

### Comprehensive Testing

Use the comprehensive test script to try all methods:

```bash
export SENDER_EMAIL="your-verified-email@example.com"
export RECIPIENT_EMAIL="recipient@example.com"

./test_ses_delivery.sh
```

## Email Content

### NIST 800-53 cATO Emails

The specialized NIST 800-53 cATO emails include:

1. **Executive Summary**: Overview of compliance status
2. **cATO Implementation Status**: Visual progress meter and status
3. **Control Family Analysis**: Breakdown of findings by control family
4. **Critical Actions**: Prioritized list of required remediations
5. **Expert Analysis**: AI-generated compliance assessment
6. **CSV Attachment**: Detailed findings with ASCII visualizations

### Email Customization

The email templates use responsive HTML with professional styling:

- Color-coded severity indicators
- Progress bars for cATO readiness
- Control family distribution visualizations
- Formatted analysis sections

## Troubleshooting

If you encounter email delivery issues:

1. Check SES verification status with `./check_ses_status.sh`
2. Verify Lambda environment variables are correctly set
3. Look for errors in CloudWatch logs
4. See the [Email Troubleshooting Guide](EMAIL_TROUBLESHOOTING.md) for detailed help

## Security Considerations

- Never hardcode email addresses in scripts for public repositories
- Use environment variables or command-line parameters for email addresses
- Ensure sensitive compliance data is only sent to authorized recipients
- Consider encrypting email attachments for sensitive compliance data