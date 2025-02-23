# SecurityHub SOC 2 Analyzer User Guide

This guide provides detailed instructions for setting up, configuring, and using the SecurityHub SOC 2 Analyzer.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Usage](#usage)
5. [Reports](#reports)
6. [Troubleshooting](#troubleshooting)

## Prerequisites

### AWS Services

1. **AWS SecurityHub**
   - Enable SecurityHub in all monitored regions
   - Configure security standards:
     - AWS Foundational Security Best Practices
     - CIS AWS Foundations Benchmark
     - PCI DSS

2. **Amazon SES**
   - Move out of sandbox mode
   - Verify sender and recipient email addresses
   - Configure appropriate sending limits

3. **Amazon Bedrock**
   - Enable Claude 3 Sonnet model access
   - Configure appropriate invocation limits
   - Set up IAM permissions

4. **IAM Permissions**
   Required permissions for:
   - SecurityHub read access
   - SES send email
   - Bedrock model invocation
   - CloudWatch logging
   - Lambda execution

### Development Environment

1. **Python Environment**
   - Python 3.9 or later
   - Virtual environment tool
   - pip package manager

2. **AWS CLI**
   - Configured with appropriate credentials
   - Default region set

3. **AWS SAM CLI**
   - Latest version installed
   - Basic SAM knowledge

## Installation

1. **Clone Repository**
   ```bash
   git clone https://github.com/ajy0127/analyze-securityhub-findings-with-bedrock-soc2.git
   cd analyze-securityhub-findings-with-bedrock-soc2
   ```

2. **Create Virtual Environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Deploy with SAM**
   ```bash
   sam build
   sam deploy --guided
   ```

## Configuration

### Environment Variables

1. **Required Variables**
   - `SENDER_EMAIL`: SES verified sender email
   - `RECIPIENT_EMAIL`: Report recipient email
   - `BEDROCK_MODEL_ID`: Claude 3 Sonnet model ID
   - `FINDINGS_HOURS`: Time window for analysis

2. **Optional Variables**
   - `LOG_LEVEL`: Logging verbosity
   - `AWS_REGION`: Deployment region
   - `TIMEZONE`: Report timezone

### SOC 2 Control Mappings

1. **Mapping Configuration**
   - Located in `config/soc2_control_mappings.json`
   - Customize finding type mappings
   - Adjust control assignments
   - Update risk levels

2. **Control Descriptions**
   - Edit control descriptions
   - Add new controls
   - Modify existing mappings

### Schedule Configuration

1. **Default Schedule**
   - Runs Monday-Friday at 11 AM IST (5:30 AM UTC)
   - Configured in CloudFormation template

2. **Custom Schedule**
   - Modify EventBridge rule
   - Update cron expression
   - Adjust timezone

## Usage

### Manual Execution

1. **AWS Console**
   - Navigate to Lambda function
   - Click "Test" button
   - Review execution results

2. **AWS CLI**
   ```bash
   aws lambda invoke --function-name SecurityHubAnalyzer output.json
   ```

### Automated Reports

1. **Daily Reports**
   - Automated execution via EventBridge
   - Email delivery through SES
   - CSV attachment for detailed findings

2. **Report Contents**
   - AI-generated analysis
   - SOC 2 control mappings
   - Risk assessments
   - Remediation guidance

### Compliance Monitoring

1. **Control Status**
   - Track failing controls
   - Monitor risk levels
   - Review remediation progress

2. **Evidence Collection**
   - Automated evidence gathering
   - Audit trail maintenance
   - Compliance documentation

## Reports

### Email Reports

1. **HTML Format**
   - Executive summary
   - Critical findings
   - Risk analysis
   - Control status

2. **CSV Attachment**
   - Detailed findings
   - Control mappings
   - Evidence references
   - Remediation steps

### Report Analysis

1. **AI Analysis**
   - Finding categorization
   - Impact assessment
   - Pattern recognition
   - Remediation priorities

2. **SOC 2 Context**
   - Control mapping
   - Compliance impact
   - Risk evaluation
   - Evidence collection

## Troubleshooting

### Common Issues

1. **Lambda Execution**
   - Check IAM permissions
   - Review CloudWatch logs
   - Verify timeout settings
   - Monitor memory usage

2. **Email Delivery**
   - Verify SES configuration
   - Check email limits
   - Validate addresses
   - Review bounce notifications

3. **Finding Analysis**
   - Check SecurityHub access
   - Verify finding filters
   - Review Bedrock quotas
   - Validate control mappings

### Error Resolution

1. **Lambda Errors**
   - Check error messages in CloudWatch
   - Verify environment variables
   - Review IAM roles
   - Test locally with SAM

2. **Integration Issues**
   - Validate service connections
   - Check API quotas
   - Review network access
   - Test service permissions

### Support

1. **Documentation**
   - Review guides directory
   - Check AWS documentation
   - Consult SOC 2 resources
   - Read control mappings

2. **Getting Help**
   - Open GitHub issues
   - Review existing issues
   - Check AWS forums
   - Contact maintainers

## Best Practices

1. **Regular Maintenance**
   - Update dependencies
   - Review configurations
   - Monitor performance
   - Backup reports

2. **Compliance Management**
   - Regular control reviews
   - Update mappings
   - Document changes
   - Maintain evidence

3. **Security Considerations**
   - Follow AWS best practices
   - Enable encryption
   - Use least privilege
   - Monitor access

## Additional Resources

- [AWS SecurityHub Documentation](https://docs.aws.amazon.com/securityhub/)
- [SOC 2 Compliance Guide](https://www.aicpa.org/soc2)
- [AWS Security Best Practices](https://aws.amazon.com/architecture/security-identity-compliance/)
- [Claude Documentation](https://docs.anthropic.com/claude/) 