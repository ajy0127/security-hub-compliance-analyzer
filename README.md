# AWS SecurityHub Multi-Framework Compliance Analyzer
## A GRC Portfolio Playground for Cloud Compliance

[![CI/CD Pipeline](https://github.com/ajy0127/security-hub-compliance-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/ajy0127/security-hub-compliance-analyzer/actions/workflows/ci.yml)

**⚠️ Verify Emails First!**  
This tool requires sender and recipient emails verified in Amazon SES. See [Deployment Guide](docs/DEPLOYMENT_GUIDE.md) before starting—skipping this breaks email reporting!

## Welcome to Your Compliance Sandbox!

Hey GRC folks! This is your sandbox to experiment with AWS SecurityHub compliance—think of it as a portfolio-building side quest. It's a work in progress, so dive in, play with it, and make it yours. You'll end up with professional compliance reports and legit cloud skills to showcase. No pressure, just adventure!

## Why Tinker With This?

- **Boost Your AWS Game**: Poke around with compliance frameworks without stress
- **Score Easy Wins**: Snag some real compliance reports to show off in interviews
- **Flex Your GRC Muscles**: Spot control gaps and map findings like a pro
- **Have Fun with Cloud Tools**: Mess with Lambda and Bedrock—see what sticks!
- **Build While You Learn**: Add this project to your portfolio while picking up practical skills

## Skills You'll Pick Up

Play with this sandbox and you'll get to:

1. **Decode AWS SecurityHub**: See how cloud security findings are captured in the real world 
2. **Map Techie Stuff to GRC-Speak**: Connect security findings to SOC 2 and NIST controls
3. **Juggle Multiple Frameworks**: See how one security issue impacts different compliance frameworks
4. **Craft Pro-Level Reports**: Make compliance reports that would impress auditors
5. **Track cATO Status**: Monitor NIST 800-53 control status like the FedRAMP pros do
6. **Automate Boring Stuff**: Let Lambda do the compliance work while you focus on the fun parts

## Project Overview (Non-Technical)

This solution automatically:
1. Collects security findings from AWS SecurityHub
2. Maps those findings to relevant SOC 2 and NIST 800-53 controls
3. Uses AI to analyze the compliance impact for each framework
4. Provides cross-framework analysis to identify common issues
5. Generates and emails professional reports for single or multiple frameworks

Think of it as an automated compliance assistant that helps you monitor security compliance across multiple frameworks in AWS.

### Your First Adventure
1. **Email Warm-Up**: Verify an email in SES (5 mins, see [this guide](docs/DEPLOYMENT_GUIDE.md#email-verification)).
2. **Launch It**: Fire off the CloudFormation template [like this](docs/DEPLOYMENT_GUIDE.md)—boom, it's live!
3. **Grab a Prize**: Run your first report with `test-soc2-event.json` and snag a shiny compliance report.

### Framework Selection

**Important**: When using the tool, you must specify which compliance framework to analyze:

- **SOC 2**: For analyzing against SOC 2 controls only
- **NIST 800-53**: For analyzing against NIST 800-53 controls only (includes enhanced cATO status reporting)
- **All Frameworks**: To analyze against all configured frameworks

If no framework is specified, the system defaults to SOC 2.

### NIST 800-53 cATO Monitoring

The system now provides enhanced continuous Authorization to Operate (cATO) monitoring for NIST 800-53:

- **Direct Control Status**: Retrieves actual control status from Security Hub instead of just findings
- **Control Family Breakdown**: Organizes compliance by control family (AC, CM, IA, etc.)
- **Compliance Percentages**: Calculates actual compliance percentages by family and overall
- **cATO Readiness**: Provides visual indicators of cATO implementation progress
- **Tailored Recommendations**: Suggests actions based on control status

**Sample NIST cATO Report:**
```
## Control Family Status

### AC: Access Control
Total Controls: 25
Passing: 20 (80%)
Failing: 3 (12%)
Not Applicable: 2 (8%)

### CM: Configuration Management
Total Controls: 22
Passing: 18 (82%)
Failing: 2 (9%)
Not Applicable: 2 (9%)
```

#### Running NIST 800-53 cATO Reports

To generate a cATO-focused NIST 800-53 report:

```bash
# Set your email address
export RECIPIENT_EMAIL="your-verified-email@example.com"

# Option 1: Use the Lambda function (deployed version)
./test_nist_direct_controls.sh

# Option 2: Test locally
source nist_venv/bin/activate  # Activate the Python virtual environment
./debug_email_output.py        # Generate HTML report
./send_debug_email.py --sender your-verified@email.com --recipient your-verified@email.com
```

For more details, see the [NIST Control Status Guide](docs/NIST_CONTROL_STATUS.md).

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
2. **Project Implementation**: Documentation of your deployment process
3. **Risk Analysis**: Sample analysis of security findings and their compliance impact

## Cool Features (So Far!)

This solution packs a bunch of fun tools to play with:

1. **Compliance Matchmaker** (Lambda): Automatically hunts for security findings and matches them to compliance controls
2. **Framework Translators**: Turns techie security speak into GRC language for different frameworks
   - SOC2Mapper: Connects findings to SOC 2 controls (perfect for audits!)
   - NIST800-53Mapper: Maps to NIST 800-53 controls (great for FedRAMP fans!)
3. **Control Status Tracker**: Grabs NIST 800-53 control statuses directly for cATO reporting
4. **AI Analysis Helper**: Uses Bedrock to review findings and generate insights (still tweaking this!)
5. **Email Reporter**: Delivers shiny reports right to your inbox—fancy, right?

*Note*: This is a growing toolkit—expect quirks and cool updates!

## Repository Structure

This repository is organized into the following directories:

- **docs/**: Documentation files including deployment guides, interview guides, and SOC 2 mapping references
- **src/**: Source code for the application, including Lambda function code and utility modules
  - **src/tests/**: Test files to verify the functionality of the code
- **deployment/**: Files related to deployment, including CloudFormation templates and configuration
  - **deployment/config/**: Configuration files like the SOC 2 control mappings 
- **scripts/**: Utility scripts for package creation, deployment, and local testing
- **examples/**: Example files including sample reports and test data

## Make It Your Own

This is your playground—hack away!

1. **Tweak the Mappings**: Dive into `config/mappings/` and add your expertise to the compliance mappings
2. **Fancy Up the Reports**: Play with email templates in `deployment/config/` to showcase your style
3. **Add Your Frameworks**: Extend with ISO 27001, HIPAA, or whatever frameworks you love
4. **Share Your Story**: Blog your customizations—level up your portfolio!

## FAQ for GRC Professionals

**Q: Do I need coding experience to use this?**  
A: No! The step-by-step guide allows you to deploy and use the solution without writing code.

**Q: Will this cost money to run?**  
A: Free in AWS Free Tier for light use (e.g., 100 Lambda runs/month). Bedrock/SES may add ~$1-2/month—set billing alerts!

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
2. **Develop Remediation Workflows**: Outline processes for addressing compliance gaps
3. **Set Up Executive Reporting**: Configure scheduled email reports for executive stakeholders
4. **Document Your Journey**: Write a blog post or LinkedIn article about what you learned

## Resources for GRC Professionals

- [SOC 2 Control Mapping Guide](docs/SOC2_MAPPING_GUIDE.md)
- [NIST 800-53 Control Status Guide](docs/NIST_CONTROL_STATUS.md)
- [NIST 800-53 cATO Control Mapping](docs/CATO_CONTROL_MAPPING.md)
- [Sample Portfolio Write-up Template](docs/PORTFOLIO_TEMPLATE.md)
- [Example SOC 2 Compliance Report](examples/example-report-email.md)
- [Email Setup and Delivery Guide](docs/EMAIL_README.md)
- [Email Troubleshooting Guide](docs/EMAIL_TROUBLESHOOTING.md)

## Community Support

Join our community of GRC professionals building their technical portfolios:

- [Connect on LinkedIn](https://www.linkedin.com/in/ajyawn/)

## Acknowledgments

This project was designed to bridge the gap between technical security implementations and GRC requirements, making cloud compliance more accessible to non-technical professionals.

This project was inspired by [AWS Security Hub Findings Summarizer with AI-Powered Analysis](https://github.com/aws-samples/analyze-securityhub-findings-with-bedrock), an AWS sample that demonstrates how to use Amazon Bedrock to analyze SecurityHub findings. While our project focuses specifically on SOC 2 compliance for GRC professionals, we appreciate the architectural patterns and concepts demonstrated in the original AWS sample.

## Join the Journey

Got ideas? Found a bug? Just wanna chat GRC adventures? Hit me up on [LinkedIn](https://www.linkedin.com/in/ajyawn/) or toss thoughts in GitHub Issues. This is a WIP—let's build it together!

## Related Projects
Check out my other GRC playground: [aws_automated_access_review](https://github.com/ajy0127/aws_automated_access_review) for IAM-focused security audits and access reviews!
