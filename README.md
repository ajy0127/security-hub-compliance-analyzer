[![CI/CD Pipeline](https://github.com/ajy0127/securityhub_soc2analysis/actions/workflows/ci.yml/badge.svg)](https://github.com/ajy0127/securityhub_soc2analysis/actions/workflows/ci.yml)

# SecurityHub SOC 2 Compliance Analyzer

> This project is a SOC 2-focused fork of [AWS's Security Hub Findings Analyzer](https://github.com/aws-samples/analyze-securityhub-findings-with-bedrock), enhanced with automated SOC 2 control mapping and compliance reporting capabilities.

## Overview

The **SecurityHub SOC 2 Compliance Analyzer** is a specialized tool that automates the collection and analysis of AWS SecurityHub findings with a focus on SOC 2 compliance. Using Amazon Bedrock's Claude 3 Sonnet model, it provides AI-powered insights through daily email reports, helping security and compliance teams understand their security posture and SOC 2 compliance status across AWS accounts.

### Key Features

- **SOC 2 Control Mapping**: Automatic mapping of SecurityHub findings to SOC 2 Trust Service Criteria
- **AI-Powered Analysis**: Utilizes Claude 3 Sonnet for intelligent finding summarization and compliance impact analysis
- **Automated Daily Reports**: Runs Monday-Friday at 11 AM IST (5:30 AM UTC)
- **Multi-Account Support**: Aggregates findings across multiple AWS accounts
- **Severity-Based Classification**: Categorizes findings by CRITICAL, HIGH, and MEDIUM severity levels
- **Audit-Ready Reports**: Generates SOC 2-formatted workpapers in CSV format
- **HTML/Text Email Format**: Provides both HTML and plain text email formats

### Architecture Details

![Architecture Diagram](docs/architecture/Architecture.png)

#### Components

1. **AWS Lambda**
   - **Runtime**: Python 3.12
   - **Memory**: 256MB
   - **Timeout**: 300 seconds
   - **Environment Variables**:
     - `SENDER_EMAIL`
     - `RECIPIENT_EMAIL`
     - `BEDROCK_MODEL_ID`
     - `FINDINGS_HOURS`

2. **Amazon EventBridge**
   - **Schedule**: `cron(30 5 ? * MON-FRI *)`
   - Triggers the Lambda function mon-fri.

3. **Amazon Bedrock**
   - **Model**: Claude 3 Sonnet
   - Used for AI analysis of findings.

4. **Amazon SES**
   - Handles email delivery.
   - Supports attachments and HTML formatting.

5. **AWS Security Hub**
   - Source of security findings.
   - Filtered for FAILED compliance status.

### Prerequisites

#### AWS Services

1. **AWS SecurityHub**
   - Must be enabled in all monitored regions.
   - Security standards enabled as needed.

2. **Amazon SES**
   - Production access required.
   - Verified sender and recipient email addresses.
   - Appropriate sending limits.

3. **Amazon Bedrock**
   - Access to the Claude 3 Sonnet model.
   - Appropriate model invocation limits.

4. **IAM Permissions**
   - SecurityHub read access.
   - SES send email permissions.
   - Bedrock model invocation rights.
   - CloudWatch Logs access.

## Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/[your-username]/securityhub-soc2-analyzer.git
   cd securityhub-soc2-analyzer
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Deploy using AWS SAM:
   ```bash
   sam build
   sam deploy --guided
   ```

## Configuration

### SOC 2 Control Mappings

Control mappings are defined in `config/soc2_control_mappings.json`. You can customize:
- Finding type to control mappings
- Severity to risk level mappings
- Control descriptions

### Lambda Configuration

Environment variables in `template.yaml`:
- `FINDINGS_HOURS`: Time window for analysis
- `BEDROCK_MODEL_ID`: AI model selection
- `SENDER_EMAIL`: Email for sending reports
- `RECIPIENT_EMAIL`: Email for receiving reports

## Project Structure

```
.
├── .github/            # GitHub Actions workflows
├── docs/              # Documentation
│   ├── architecture/  # Architecture diagrams
│   └── guides/        # User and developer guides
├── src/               # Source code
│   ├── handlers/      # Lambda handlers
│   └── lib/           # Shared libraries
├── tests/             # Test files
├── config/            # Configuration files
└── template.yaml      # SAM template
```

## Development

1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Install development dependencies:
   ```bash
   pip install -r requirements.txt
   pip install pre-commit
   pre-commit install
   ```

3. Make your changes and run tests:
   ```bash
   pytest tests/
   flake8 src/
   black src/
   cfn-lint template.yaml
   ```

## Documentation

- [User Guide](docs/guides/user-guide.md)
- [Developer Guide](docs/guides/developer-guide.md)
- [SOC 2 Controls](docs/guides/soc2-controls.md)

## Security

See [SECURITY.md](SECURITY.md) for security reporting instructions.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

This project is a SOC 2-focused fork of the AWS Security Hub Findings Analyzer. While we welcome contributions that enhance SOC 2 compliance capabilities, general improvements should be directed to the [original project](https://github.com/aws-samples/analyze-securityhub-findings-with-bedrock).

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## Disclaimer

This solution is provided as-is without any warranties or guarantees of performance or reliability. Users should thoroughly test this solution in their own environments before deploying it in production settings. It is recommended to review AWS best practices regarding security configurations, IAM permissions, and resource management.



