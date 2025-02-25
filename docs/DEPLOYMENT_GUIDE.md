# Deployment Guide for GRC Professionals

This guide will walk you through setting up the AWS SecurityHub SOC 2 Compliance Lab step-by-step, with minimal technical knowledge required. By the end, you'll have a working compliance reporting system that you can showcase in your professional portfolio.

## Before You Begin

### What You'll Need

- An AWS account (free tier is sufficient)
- A verified email address in Amazon SES (for sending reports) - **CRITICAL REQUIREMENT**
- Approximately 1-2 hours to complete the setup
- No coding experience required!

### AWS Free Tier Information

AWS offers a free tier that includes most services we'll use. To avoid unexpected charges:
1. Create a new AWS account specifically for this lab
2. Set up billing alerts (we'll show you how)
3. Remember to shut down resources when you're done experimenting

## Step 1: Set Up Your AWS Account

If you already have an AWS account, you can skip to Step 2.

1. Go to [aws.amazon.com](https://aws.amazon.com) and click "Create an AWS Account"
2. Follow the registration process
3. You'll need to provide a credit card, but we'll stay within free tier limits

> 💡 **GRC Insight**: Document this process as part of your portfolio to demonstrate your understanding of cloud account governance.

## Step 2: Set Up Billing Alerts

Before deploying any resources, let's set up billing alerts to avoid surprises:

1. Log in to your AWS account
2. In the search bar at the top, type "Billing" and select "Billing Dashboard"
3. In the left navigation, click "Budgets"
4. Click "Create budget"
5. Select "Simplified" and "Monthly cost budget"
6. Set a budget amount (e.g., $10)
7. Enter your email address for notifications
8. Click "Create budget"

> 💡 **GRC Insight**: This demonstrates cost governance and risk management - important GRC skills!

## Step 3: Enable AWS SecurityHub

SecurityHub is AWS's security findings service that we'll use as our data source:

1. In the AWS search bar, type "SecurityHub" and select it
2. Click "Go to Security Hub"
3. On the welcome page, keep the default settings and click "Enable SecurityHub"
4. Wait a few minutes for SecurityHub to initialize

> 💡 **GRC Insight**: In your portfolio, explain how centralized security findings repositories support continuous compliance monitoring.

## Step 4: Verify Your Email in Amazon SES

⚠️ **CRITICAL STEP**: This solution sends email reports, which requires verified email addresses in Amazon SES.

1. In the AWS search bar, type "SES" and select "Amazon Simple Email Service"
2. In the left navigation, click "Verified identities"
3. Click "Create identity"
4. Select "Email address" and enter your email address
5. Click "Create identity"
6. Check your email for a verification message from AWS
7. Click the verification link in the email

> ⚠️ **Important**: Both the sender and recipient email addresses must be verified in SES. If you plan to send reports to a different email than your own, repeat this process for that email address as well.

> 💡 **GRC Insight**: Document this email verification process as part of your compliance controls implementation.

## Step 5: Deploy the Solution Using CloudFormation

Now we'll deploy the solution using AWS CloudFormation:

1. Download the CloudFormation template:
   - Go to the [GitHub repository](https://github.com/ajy0127/securityhub_soc2analysis)
   - Download the `cloudformation.yaml` file
   - Download the `lambda-code.zip` file (or create it by zipping the Python files as described in the README)

2. Create an S3 bucket to store the Lambda code:
   - In the AWS search bar, type "S3" and select it
   - Click "Create bucket"
   - Enter a unique bucket name (e.g., "securityhub-soc2-analyzer-[your-initials]")
   - Keep all default settings and click "Create bucket"
   - Upload the `lambda-code.zip` file to this bucket

3. Deploy the CloudFormation stack:
   - In the AWS search bar, type "CloudFormation" and select it
   - Click "Create stack" > "With new resources"
   - Select "Upload a template file"
   - Click "Choose file" and select the `cloudformation.yaml` file you downloaded
   - Click "Next"
   - Enter a stack name (e.g., "securityhub-soc2-analyzer")
   - Fill in the parameters:
     - SenderEmail: Your verified email address
     - RecipientEmail: Your verified email address (or another verified email)
     - S3BucketName: The name of the bucket you created
     - S3KeyName: "lambda-code.zip"
   - Click "Next" twice
   - Check the box acknowledging that CloudFormation might create IAM resources
   - Click "Create stack"
   - Wait for the stack creation to complete (this may take 5-10 minutes)

> 💡 **GRC Insight**: This demonstrates infrastructure-as-code, a key concept in modern compliance automation.

## Step 6: Test the Deployment

Let's make sure everything is working:

1. In the AWS search bar, type "Lambda" and select it
2. Find the function named `securityhub-soc2-analyzer-SecurityHubAnalyzer` (or with your stack name)
3. Click on the function name
4. Click the "Test" tab
5. In the Event JSON box, paste:
   ```json
   {
     "test_email": "your-verified-email@example.com"
   }
   ```
6. Replace with your actual verified email address
7. Click "Test"
8. Check your email for a test message

> ⚠️ **IMPORTANT**: If you receive an error, check the CloudWatch logs for the Lambda function. The most common issue is using an email address that hasn't been verified in SES.

> 💡 **GRC Insight**: Testing is a critical part of any compliance implementation - document your test approach!

## Step 7: Generate Your First Compliance Report

Now let's generate a real compliance report:

1. Return to the Lambda function from Step 6
2. Create a new test event with:
   ```json
   {
     "email": "your-verified-email@example.com",
     "hours": 24
   }
   ```
3. Click "Test"
4. Check your email for the compliance report

> 💡 **GRC Insight**: The report maps technical findings to SOC 2 controls - a perfect example of translating technical details into compliance language.

## Step 8: Customize the SOC 2 Control Mappings

Let's customize the mappings to demonstrate your SOC 2 knowledge:

1. In the AWS search bar, type "S3" and select it
2. Find the bucket named `securityhub-soc2-analyzer-configbucket-XXXX`
3. Click on the bucket name
4. Find and click on the file `mappings.json`
5. Click "Download"
6. Open the file in a text editor (even Notepad works)
7. Modify the mappings based on your SOC 2 knowledge
8. Save the file
9. Return to the S3 bucket and click "Upload"
10. Upload your modified file, overwriting the existing one

> 💡 **GRC Insight**: This customization demonstrates your understanding of how technical controls map to SOC 2 requirements.

## Step 9: Schedule Regular Reports

Let's set up a schedule for weekly reports:

1. In the AWS search bar, type "EventBridge" and select it
2. In the left navigation, click "Rules"
3. Find the rule named `securityhub-soc2-analyzer-WeeklyAnalysisSchedule-XXXX`
4. Click on the rule name
5. Click "Edit"
6. Under "Schedule pattern", you can modify the schedule
7. The default is Monday at 9 AM UTC - you can keep this or change it
8. Click "Next" twice, then "Update rule"

> 💡 **GRC Insight**: Regular reporting schedules are a key part of continuous compliance monitoring programs.

## Step 10: Document Your Work for Your Portfolio

Now that you have a working solution, document it for your portfolio:

1. Take screenshots of:
   - Your SecurityHub dashboard
   - The compliance report email
   - The CloudFormation stack showing successful deployment
   - The Lambda function configuration

2. Write a brief case study including:
   - The compliance challenge (monitoring AWS against SOC 2)
   - Your solution approach (automated mapping and reporting)
   - The implementation process (this deployment)
   - The outcomes (automated compliance reporting)
   - Next steps or improvements

> 💡 **GRC Insight**: Documentation is a critical GRC skill - this demonstrates your ability to communicate complex compliance concepts.

## Understanding What You've Built

Let's break down what you've deployed in non-technical terms:

1. **The Collector** (Lambda Function): A scheduled task that gathers security findings
2. **The Mapper** (SOC2Mapper): A translator that converts technical findings into SOC 2 language
3. **The Analyzer** (AI Component): An assistant that reviews findings and generates insights
4. **The Reporter** (Email Component): A communication tool that creates and delivers reports

This entire system runs automatically on your schedule, providing regular compliance insights without manual effort.

## Troubleshooting Common Issues

### No Email Received

1. Check your spam folder
2. **Verify both sender and recipient emails are correctly verified in SES**
3. Check if your AWS account is still in the SES sandbox (it most likely is)
   - In the SES console, look for "Account dashboard" in the left navigation
   - Under "Sending statistics", it will indicate if you're in the sandbox
   - While in the sandbox, you can only send to verified email addresses
4. Check the CloudWatch logs for the Lambda function for specific error messages

### No Findings in Report

1. SecurityHub may need more time to generate findings
2. Try increasing the "hours" parameter to look back further
3. Ensure SecurityHub is enabled and configured correctly

### Error in Lambda Function

1. In the Lambda console, check the "Monitor" tab
2. Click "View logs in CloudWatch"
3. Look for error messages that might explain the issue
4. Common errors include:
   - Email verification issues
   - Missing permissions
   - Configuration errors

## Next Steps for Your GRC Portfolio

After completing this lab, consider these portfolio-enhancing activities:

1. **Map to Additional Frameworks**: Modify the solution to include NIST CSF or ISO 27001
2. **Create an Executive Dashboard**: Design a visual summary of compliance status
3. **Document Remediation Procedures**: Create playbooks for addressing common findings
4. **Perform a Gap Analysis**: Compare SecurityHub coverage to complete SOC 2 requirements

## Getting Help

If you encounter issues with this lab:

1. Check the [FAQ section](https://example.com/faq)
2. Join our [LinkedIn Group](https://linkedin.com/groups/grc-cloud-portfolio) for peer support
3. Attend our monthly webinars for live assistance

Remember, the journey of building your technical GRC skills is as valuable as the destination. Document your challenges and how you overcame them as part of your portfolio! 