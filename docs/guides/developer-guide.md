# SecurityHub SOC 2 Analyzer Developer Guide

This guide provides detailed information for developers who want to contribute to or modify the SecurityHub SOC 2 Analyzer.

## Development Environment Setup

### Prerequisites

1. **Python Environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. **Development Tools**
   ```bash
   pip install -r requirements-dev.txt
   pre-commit install
   ```

3. **AWS Credentials**
   - Configure AWS CLI with appropriate permissions
   - Set up local AWS profiles if needed
   - Configure AWS SAM CLI

### Code Structure

```
.
├── .github/            # GitHub Actions workflows
├── docs/              # Documentation
│   ├── architecture/  # Architecture diagrams
│   └── guides/        # User and developer guides
├── src/               # Source code
│   ├── handlers/      # Lambda handlers
│   ├── lambda/        # Lambda-specific helper functions
│   ├── lib/           # Shared libraries
│   └── utils/         # Utility modules and helpers
├── tests/             # Test files
├── config/            # Configuration files
├── deployment/        # Environment-specific templates
│   └── environments/  # Staging and production templates
└── template.yaml      # Base SAM template
```

## Core Components

### 1. SecurityHub Handler (`src/handlers/securityhub_handler.py`)
- Retrieves SecurityHub findings
- Processes findings for analysis
- Generates email reports
- Handles Lambda events

### 2. SOC 2 Mapper (`src/lib/soc2_mapper.py`)
- Maps findings to SOC 2 controls
- Manages control descriptions
- Handles risk assessment
- Generates compliance reports

### 3. Custom Mapper (`src/lib/custom_mapper.py`)
- Extends base SOC2Mapper functionality
- Adds organization-specific controls
- Implements regex-based mapping
- Provides resource-specific mappings

### 4. Utility Modules
- **Common Utilities** (`src/utils/common.py`): Shared functions
- **Logging Utilities** (`src/utils/logging_utils.py`): Structured logging
- **Deduplication** (`src/utils/deduplication.py`): Finding deduplication
- **Remediation Tracking** (`src/utils/remediation_tracker.py`): Progress tracking

### 5. Lambda Helper Functions
- **Version Handler** (`src/lambda/version_handler.py`): Manages Lambda versions
- **Pre-traffic Hook** (`src/lambda/pretraffic_hook.py`): Deployment validation
- **CloudFormation Response** (`src/lambda/cfnresponse.py`): Custom resources

### 6. Configurations
- **Base Mappings** (`config/soc2_control_mappings.json`): Core control mappings
- **Custom Controls** (`config/custom_controls.json`): Organization-specific definitions
- **Environment Templates** (`deployment/environments/`): Staging and production configs

## Development Workflow

### 1. Feature Development

1. **Create Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Implement Changes**
   - Follow Python style guide (PEP 8)
   - Add appropriate documentation
   - Include type hints
   - Write unit tests

3. **Local Testing**
   ```bash
   pytest tests/
   flake8 src/
   black src/
   ```

4. **Commit Changes**
   ```bash
   git add .
   git commit -m "Description of changes"
   ```

### 2. Testing

1. **Unit Tests**
   - Located in `tests/` directory
   - Use pytest framework
   - Mock AWS services
   - Test edge cases

2. **Integration Tests**
   - Test AWS service integration
   - Verify email delivery
   - Check report generation
   - Validate control mappings

3. **Code Quality**
   ```bash
   # Style checks
   flake8 src/
   black src/
   
   # Type checking
   mypy src/
   
   # Security scanning
   bandit -r src/
   ```

### 3. Documentation

1. **Code Documentation**
   - Add docstrings to functions
   - Update README.md
   - Document configuration changes
   - Add architecture diagrams

2. **User Documentation**
   - Update user guide
   - Add examples
   - Document new features
   - Include troubleshooting

## SOC 2 Development Guidelines

### 1. Control Mapping Development

1. **Adding New Controls**
   ```json
   {
     "finding_type_mappings": {
       "new-finding-type": {
         "primary_controls": ["CC6.1", "CC7.1"],
         "secondary_controls": ["CC8.1"]
       }
     }
   }
   ```

2. **Modifying Existing Controls**
   - Update control descriptions
   - Adjust risk mappings
   - Modify control relationships
   - Document changes

### 2. Report Generation

1. **CSV Report Format**
   - Follow SOC 2 workpaper format
   - Include all required fields
   - Maintain consistency
   - Support filtering

2. **Email Report Format**
   - Clear presentation
   - Include summaries
   - Highlight critical findings
   - Add compliance context

### 3. Compliance Considerations

1. **Evidence Collection**
   - Automated gathering
   - Proper formatting
   - Clear references
   - Audit support

2. **Control Testing**
   - Validate mappings
   - Test effectiveness
   - Document results
   - Track changes

## AWS Integration

### 1. SecurityHub Integration

1. **Finding Retrieval**
   ```python
   def get_findings(self):
       response = self.securityhub.get_findings(
           Filters={
               "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
               "ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}]
           }
       )
   ```

2. **Finding Processing**
   - Filter relevant findings
   - Extract key information
   - Map to controls
   - Generate analysis

### 2. Bedrock Integration

1. **AI Analysis**
   ```python
   def analyze_findings(self, findings):
       response = self.bedrock.invoke_model(
           modelId=BEDROCK_MODEL_ID,
           body=json.dumps({
               "messages": [{"role": "user", "content": prompt}]
           })
       )
   ```

2. **Prompt Engineering**
   - Clear instructions
   - Relevant context
   - Compliance focus
   - Consistent format

### 3. SES Integration

1. **Email Formatting**
   - HTML templates
   - Text alternatives
   - Proper encoding
   - Attachment handling

2. **Delivery Management**
   - Error handling
   - Retry logic
   - Bounce processing
   - Quota management

## Best Practices

### 1. Code Quality

1. **Style Guide**
   - Follow PEP 8
   - Use type hints
   - Add docstrings
   - Maintain consistency

2. **Testing**
   - High coverage
   - Edge cases
   - Mocked services
   - Integration tests

### 2. Security

1. **AWS Security**
   - Least privilege
   - Encryption
   - Secure storage
   - Access logging

2. **Code Security**
   - Input validation
   - Error handling
   - Dependency scanning
   - Regular updates

### 3. Performance

1. **Lambda Optimization**
   - Memory usage
   - Execution time
   - Cold starts
   - Error handling

2. **Resource Management**
   - API quotas
   - Rate limiting
   - Batch processing
   - Caching

## Troubleshooting

### 1. Common Issues

1. **AWS Integration**
   - Check permissions
   - Verify configurations
   - Review quotas
   - Monitor logs

2. **Development Issues**
   - Debug locally
   - Use SAM CLI
   - Check dependencies
   - Review documentation

### 2. Debug Tools

1. **Logging**
   ```python
   import logging
   logger = logging.getLogger()
   logger.setLevel(logging.DEBUG)
   ```

2. **Testing Tools**
   - pytest-cov
   - moto
   - AWS SAM CLI
   - CloudWatch Logs

## Additional Resources

- [AWS Lambda Developer Guide](https://docs.aws.amazon.com/lambda/)
- [SecurityHub API Reference](https://docs.aws.amazon.com/securityhub/latest/APIReference/)
- [SOC 2 Compliance Guide](https://www.aicpa.org/soc2)
- [Python Best Practices](https://docs.python-guide.org/) 