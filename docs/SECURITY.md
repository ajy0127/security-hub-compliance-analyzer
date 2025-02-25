# Security Policy

## Supported Versions

This project follows semantic versioning. Currently supported versions:

| Version | Supported          | Notes |
| ------- | ------------------ | ----- |
| 1.0.x   | :white_check_mark: | Current stable release |
| < 1.0   | :x:               | Development versions |

## SOC 2 Security Considerations

As this tool is designed for SOC 2 compliance analysis, we maintain strict security standards:

1. **Access Control**: All AWS credentials and sensitive configurations must be properly secured
2. **Encryption**: All data in transit and at rest must be encrypted
3. **Logging**: Comprehensive logging must be enabled for audit trails
4. **Authentication**: MFA should be enabled for all AWS accounts
5. **Monitoring**: CloudWatch alerts should be configured for security events

## Reporting a Vulnerability

We take the security of SecurityHub SOC 2 Analyzer seriously. If you believe you have found a security vulnerability, please report it to us as described below.

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via:
1. AWS Security: If the vulnerability relates to AWS services, report through [AWS Security](https://aws.amazon.com/security/vulnerability-reporting/)
2. GitHub Security: Use the [Security tab](https://github.com/ajy0127/analyze-securityhub-findings-with-bedrock-soc2/security) to report repository-specific issues
3. Email: For other security concerns, contact the repository Owner: Through GitHub


You should receive a response within 48 hours. If for some reason you do not, please follow up to ensure we received your original message.

### Required Information

Please include the following information to help us better understand and address the issue:

* Type of issue (e.g., access control, encryption, credential exposure)
* Full paths of source file(s) related to the issue
* The location of the affected source code (tag/branch/commit or direct URL)
* AWS service(s) affected (if applicable)
* SOC 2 controls impacted (if known)
* Any special configuration required to reproduce the issue
* Step-by-step instructions to reproduce the issue
* Proof-of-concept or exploit code (if possible)
* Impact assessment, including:
  - Potential data exposure
  - Compliance implications
  - Service disruption risks

### Security Best Practices

When working with this tool:

1. **AWS Configuration**:
   - Use IAM roles with least privilege
   - Enable CloudTrail logging
   - Configure SecurityHub standards
   - Enable GuardDuty

2. **Code Security**:
   - Keep dependencies updated
   - Review CloudFormation templates
   - Validate Lambda permissions
   - Monitor CloudWatch logs

3. **SOC 2 Compliance**:
   - Maintain evidence of security controls
   - Document configuration changes
   - Regular security assessments
   - Monitor compliance status

## Preferred Languages

We prefer all communications to be in English.

## Disclosure Policy

We follow the principle of [Responsible Disclosure](https://en.wikipedia.org/wiki/Responsible_disclosure):

1. Report the vulnerability to us privately
2. Allow up to 90 days for vulnerability assessment and patch
3. Coordinate the public release of information after the patch

## Security Update Process

1. Security patches are released as soon as possible
2. Updates are documented in release notes
3. Users are notified through GitHub releases
4. Critical updates are highlighted in the repository

## Compliance Impact

Security issues may affect SOC 2 compliance. We assess each vulnerability for:

1. Trust Services Criteria impact
2. Control effectiveness
3. Audit implications
4. Required compensating controls

## Contact

For any security-related questions, contact:
- Security Team: [security@yourdomain.com](mailto:security@yourdomain.com)
- AWS Security: [AWS Security Contact](https://aws.amazon.com/security/vulnerability-reporting/)
- Repository Owner: Through GitHub 