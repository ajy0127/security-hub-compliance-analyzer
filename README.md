# AWS SecurityHub Multi-Framework Compliance Analyzer
## Supporting SOC 2 and NIST 800-53 Frameworks

[![CI/CD Pipeline](https://github.com/ajy0127/security-hub-compliance-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/ajy0127/security-hub-compliance-analyzer/actions/workflows/ci.yml)

## A Portfolio-Building Project for GRC Professionals

This lab project is designed specifically for Governance, Risk, and Compliance (GRC) professionals who want to enhance their technical skills and build a practical portfolio demonstrating cloud security compliance expertise.

## Why This Project Matters for Your GRC Portfolio

As a GRC professional, demonstrating practical experience with cloud compliance tools is increasingly valuable. This project allows you to:

- **Showcase Compliance Framework Knowledge**: Demonstrate your understanding of SOC 2 and NIST 800-53 controls in a practical context
- **Bridge the Technical Gap**: Build confidence working with cloud security tools without needing deep technical expertise
- **Create Tangible Deliverables**: Generate professional compliance reports you can showcase to potential employers
- **Learn AWS Security Basics**: Gain hands-on experience with AWS SecurityHub in a guided environment

## What You'll Learn

This lab will help you understand:

1. **How AWS SecurityHub Works**: Learn how cloud security findings are generated and managed
2. **Compliance Control Mapping**: See how technical findings map to SOC 2 and NIST 800-53 compliance requirements
3. **Multi-Framework Analysis**: Understand how security findings impact different compliance frameworks
3. **Compliance Reporting**: Create professional reports suitable for auditors and executives
4. **Basic Cloud Automation**: Experience how compliance monitoring can be automated

## Project Overview (Non-Technical)

This solution automatically:
1. Collects security findings from AWS SecurityHub
2. Maps those findings to relevant SOC 2 and NIST 800-53 controls
3. Uses AI to analyze the compliance impact for each framework
4. Provides cross-framework analysis to identify common issues
5. Generates and emails professional reports for single or multiple frameworks

Think of it as an automated compliance assistant that helps you monitor security compliance across multiple frameworks in AWS.

### Framework Selection

**Important**: When using the tool, you must specify which compliance framework to analyze:

- **SOC 2**: For analyzing against SOC 2 controls only
- **NIST 800-53**: For analyzing against NIST 800-53 controls only
- **All Frameworks**: To analyze against all configured frameworks

If no framework is specified, the system defaults to SOC 2.

## ⚠️ Important Requirements

### Email Verification Requirement

Before deploying this solution, you **must verify email addresses in Amazon SES**:

* This solution sends compliance reports via email, requiring verified sender and recipient addresses
* AWS requires email verification to prevent unauthorized use of email sending capabilities
* New AWS accounts are in "SES sandbox" mode, which only allows sending to verified email addresses

See the [Deployment Guide](docs/DEPLOYMENT_GUIDE.md) for detailed instructions on email verification.

### Framework Selection

When triggering the compliance analyzer manually, specify the framework using the event payload:

* Use `"framework": "SOC2"` for SOC 2 compliance analysis
* Use `"framework": "NIST800-53"` for NIST 800-53 compliance analysis
* Use `"framework": "all"` for analysis of all configured frameworks

Example events for triggering the Lambda function can be found in the `examples/` directory:
- `test-soc2-event.json` - Analyze using SOC 2 framework
- `test-nist-event.json` - Analyze using NIST 800-53 framework
- `test-all-frameworks-event.json` - Analyze using all frameworks with combined analysis
- `default-nist-event.json` - Default template for NIST 800-53 analysis

## Getting Started

### For Non-Technical Users
1. Follow the step-by-step [Deployment Guide](docs/DEPLOYMENT_GUIDE.md) which includes:
   - Setting up your AWS account
   - **Verifying your email addresses in Amazon SES** (critical step)
   - Deploying the solution using CloudFormation
   - Configuring and testing the solution

### For Technical Users (Advanced Deployment)
1. Clone this repository
2. **Verify your email addresses in Amazon SES** (required)
3. Package the Lambda code:
   ```
   zip -r lambda-code.zip src/app.py src/utils.py src/soc2_mapper.py src/requirements.txt
   ```
4. Upload the `lambda-code.zip` file to an S3 bucket
5. Deploy the CloudFormation stack:
   ```
   aws cloudformation create-stack \
     --stack-name security-hub-compliance-analyzer \
     --template-body file://deployment/cloudformation.yaml \
     --capabilities CAPABILITY_IAM \
     --parameters \
       ParameterKey=SenderEmail,ParameterValue=your-verified@email.com \
       ParameterKey=RecipientEmail,ParameterValue=your-verified@email.com \
       ParameterKey=S3BucketName,ParameterValue=your-bucket-name \
       ParameterKey=S3KeyName,ParameterValue=lambda-code.zip
   ```
6. Configure SecurityHub in your AWS account

**Note:** The CI/CD pipeline only validates code quality and tests.

## Sample Deliverables for Your Portfolio

After completing this lab, you'll have several artifacts to add to your professional portfolio:

1. **SOC 2 Compliance Reports**: Professional-looking reports mapping AWS findings to SOC 2 controls
2. **Compliance Dashboard**: Screenshots of your compliance monitoring setup
3. **Project Implementation**: Documentation of your deployment process
4. **Risk Analysis**: Sample analysis of security findings and their compliance impact

## Understanding the Components (Simplified)

This solution consists of several parts, explained in non-technical terms:

1. **The Collector** (Lambda Function): Automatically gathers security findings on a schedule
2. **The Framework Mappers**: Translate technical security findings into compliance control language for different frameworks
   - SOC2Mapper: Maps findings to SOC 2 controls
   - NIST800-53Mapper: Maps findings to NIST 800-53 controls
3. **The Analyzer** (AI Component): Reviews findings and generates compliance insights for each framework
4. **The Cross-Framework Analyzer**: Identifies common issues and priorities across multiple frameworks
5. **The Reporter** (Email Component): Creates and delivers professional reports with framework-specific sections

## Repository Structure

This repository is organized into the following directories:

- **docs/**: Documentation files including deployment guides, interview guides, and SOC 2 mapping references
- **src/**: Source code for the application, including Lambda function code and utility modules
  - **src/tests/**: Test files to verify the functionality of the code
- **deployment/**: Files related to deployment, including CloudFormation templates and configuration
  - **deployment/config/**: Configuration files like the SOC 2 control mappings 
- **scripts/**: Utility scripts for package creation, deployment, and local testing
- **examples/**: Example files including sample reports and test data

## Customizing for Your Portfolio

You can customize this project to demonstrate your unique GRC expertise:

1. **Modify Control Mappings**: Edit the mapping files in the config/mappings/ directory to show your understanding of different compliance frameworks
2. **Customize Report Format**: Adjust the email template to showcase your reporting style
3. **Add Additional Controls**: Extend the project to include other compliance frameworks you're familiar with

## FAQ for GRC Professionals

**Q: Do I need coding experience to use this?**  
A: No! The step-by-step guide allows you to deploy and use the solution without writing code.

**Q: Will this cost money to run?**  
A: AWS offers a free tier that should cover most of your usage. We recommend setting up billing alerts.

**Q: Can I use this for actual compliance monitoring?**  
A: This is designed as a learning tool. For production environments, additional security and reliability considerations would be needed.

**Q: How do I explain this project in interviews?**  
A: We've included talking points in the [Interview Guide](docs/INTERVIEW_GUIDE.md) to help you articulate what you've learned.

**Q: Why do I need to verify my email address?**  
A: AWS requires email verification to prevent spam and unauthorized use. This is a security control that protects both AWS and email recipients.

**Q: What if I get an error about email sending?**  
A: The most common issue is not properly verifying both sender and recipient email addresses in Amazon SES. See the troubleshooting section in the [Deployment Guide](docs/DEPLOYMENT_GUIDE.md).

## Next Steps After Completing This Lab

After you've completed this lab, consider these next steps for your GRC portfolio:

1. **Add More Frameworks**: Extend the project to map findings to additional frameworks like ISO 27001, CIS Controls, or HIPAA
2. **Create Executive Dashboards**: Design visual summaries of compliance status
3. **Develop Remediation Workflows**: Outline processes for addressing compliance gaps
4. **Document Your Journey**: Write a blog post or LinkedIn article about what you learned

## Resources for GRC Professionals

- [SOC 2 Control Mapping Guide](docs/SOC2_MAPPING_GUIDE.md)
- [Sample Portfolio Write-up Template](docs/PORTFOLIO_TEMPLATE.md)
- [Example SOC 2 Compliance Report](examples/example-report-email.md)

## Community Support

Join our community of GRC professionals building their technical portfolios:

- [Connect on LinkedIn](https://www.linkedin.com/in/ajyawn/)

## Acknowledgments

This project was designed to bridge the gap between technical security implementations and GRC requirements, making cloud compliance more accessible to non-technical professionals.

This project was inspired by [AWS Security Hub Findings Summarizer with AI-Powered Analysis](https://github.com/aws-samples/analyze-securityhub-findings-with-bedrock), an AWS sample that demonstrates how to use Amazon Bedrock to analyze SecurityHub findings. While our project focuses specifically on SOC 2 compliance for GRC professionals, we appreciate the architectural patterns and concepts demonstrated in the original AWS sample.
