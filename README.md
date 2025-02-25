[![CI/CD Pipeline](https://github.com/ajy0127/securityhub_soc2analysis/actions/workflows/ci.yml/badge.svg)](https://github.com/ajy0127/securityhub_soc2analysis/actions/workflows/ci.yml)

# SecurityHub SOC 2 Email Reporter

A simplified solution for analyzing AWS SecurityHub findings and mapping them to SOC 2 controls.

## Overview

This solution automatically analyzes AWS SecurityHub findings, maps them to SOC 2 controls, and sends email reports with AI-powered analysis. It's designed to be simple, reliable, and easy to deploy.

## Features

- **SecurityHub Integration**: Automatically retrieves findings from AWS SecurityHub
- **SOC 2 Mapping**: Maps findings to relevant SOC 2 controls
- **AI Analysis**: Uses Amazon Bedrock (Claude 3 Sonnet) to generate insights
- **Email Reports**: Sends HTML emails with findings and analysis
- **CSV Export**: Attaches a CSV file with detailed findings
- **Weekly Schedule**: Runs automatically every Monday morning
- **CLI Support**: Run the tool from the command line for local testing
- **CI/CD Pipeline**: Automated testing, linting, and deployment

## Architecture

The solution consists of:

1. **Lambda Function**: Retrieves findings, performs analysis, and sends emails
2. **EventBridge Rule**: Triggers the Lambda function on a schedule
3. **SOC 2 Mapper**: Maps SecurityHub findings to SOC 2 controls
4. **Configuration**: Simple JSON-based mapping configuration

## Prerequisites

- AWS Account with SecurityHub enabled
- Amazon SES with verified sender email
- Amazon Bedrock with access to Claude 3 Sonnet model
- Docker (for building the container image)
- AWS CLI and SAM CLI (for deployment)

## Deployment Options

### Option 1: Deploy with SAM CLI (Local Code)

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/securityhub-soc2-reporter.git
   cd securityhub-soc2-reporter
   ```

2. Deploy with SAM:
   ```bash
   sam build
   sam deploy --guided
   ```

3. During the guided deployment, you'll be prompted to enter:
   - Stack name (e.g., `securityhub-soc2-reporter`)
   - AWS Region
   - Sender email address (must be verified in SES)
   - Recipient email address
   - Findings hours (default: 24)
   - Bedrock model ID (default: anthropic.claude-3-sonnet)

### Option 2: Deploy with Docker Image

1. Build and push the Docker image:
   ```bash
   docker build -t securityhub-soc2-reporter .
   aws ecr create-repository --repository-name securityhub-soc2-reporter
   aws ecr get-login-password | docker login --username AWS --password-stdin $(aws sts get-caller-identity --query Account --output text).dkr.ecr.$(aws configure get region).amazonaws.com
   docker tag securityhub-soc2-reporter:latest $(aws sts get-caller-identity --query Account --output text).dkr.ecr.$(aws configure get region).amazonaws.com/securityhub-soc2-reporter:latest
   docker push $(aws sts get-caller-identity --query Account --output text).dkr.ecr.$(aws configure get region).amazonaws.com/securityhub-soc2-reporter:latest
   ```

2. Deploy with SAM:
   ```bash
   sam deploy --guided \
     --parameter-overrides ImageRepository=$(aws sts get-caller-identity --query Account --output text).dkr.ecr.$(aws configure get region).amazonaws.com/securityhub-soc2-reporter
   ```

### Option 3: Use the Deployment Script

For convenience, a deployment script is provided:

```bash
./deploy.sh
```

This script will:
1. Build the Docker image
2. Create an ECR repository if it doesn't exist
3. Push the image to ECR
4. Deploy the SAM template

## Testing

### Lambda Testing

After deployment, you can test the solution by sending a test email:

```bash
aws lambda invoke \
  --function-name securityhub-soc2-analyzer-SecurityHubAnalyzerFunction-XXXXXXXXXXXX \
  --payload '{"test_email":"your-email@example.com"}' \
  response.json
```

### Local Testing

You can also test the solution locally using the CLI:

```bash
# Install the package
pip install -e .

# Send a test email
securityhub-soc2-analyzer test-email --email your-email@example.com

# Generate a report
securityhub-soc2-analyzer report --email your-email@example.com --hours 24 --csv
```

### Automated Testing

The project includes automated tests that can be run with pytest:

```bash
pytest tests/
```

## CI/CD Pipeline

This project includes a GitHub Actions workflow for CI/CD that:

1. **Tests**: Runs unit tests and generates coverage reports
2. **Lints**: Checks code quality with flake8, black, and isort
3. **Builds**: Builds the Docker image
4. **Deploys**: Deploys the solution to AWS (on push to main branch)

To use the CI/CD pipeline, you need to set up the following GitHub secrets:

- `AWS_ACCESS_KEY_ID`: AWS access key with permissions to deploy
- `AWS_SECRET_ACCESS_KEY`: AWS secret key
- `AWS_REGION`: AWS region to deploy to
- `ECR_REPOSITORY`: Name of the ECR repository

## Customization

### SOC 2 Control Mappings

You can customize the SOC 2 control mappings by editing the `config/mappings.json` file:

- `type_mappings`: Maps SecurityHub finding types to SOC 2 controls
- `title_mappings`: Maps keywords in finding titles to SOC 2 controls
- `control_descriptions`: Descriptions of SOC 2 controls

### Email Schedule

By default, the solution sends reports every Monday at 9 AM UTC. You can change this by modifying the `WeeklyAnalysisSchedule` resource in the `template.yaml` file.

## Project Structure

```
.
├── .github/workflows/  # GitHub Actions workflows
├── config/             # Configuration files
│   └── mappings.json   # SOC 2 control mappings
├── tests/              # Test files
├── app.py              # Main application code
├── soc2_mapper.py      # SOC 2 mapping logic
├── utils.py            # Utility functions
├── Dockerfile          # Docker image definition
├── template.yaml       # SAM template
└── requirements.txt    # Python dependencies
```

## Troubleshooting

- **Email Delivery Issues**: Verify that your sender email is verified in SES and that you're not in the SES sandbox
- **Missing Findings**: Check that SecurityHub is enabled and generating findings
- **Lambda Errors**: Check CloudWatch Logs for error messages
- **Bedrock Access**: Ensure you have access to the Claude 3 Sonnet model in Bedrock

## Security

See [SECURITY.md](SECURITY.md) for security reporting instructions.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## Disclaimer

This solution is provided as-is without any warranties or guarantees of performance or reliability. Users should thoroughly test this solution in their own environments before deploying it in production settings. It is recommended to review AWS best practices regarding security configurations, IAM permissions, and resource management.