# NIST 800-53 Email Reporting Guide

This guide explains how to use the AWS SecurityHub Compliance Analyzer to generate and send NIST 800-53 compliance reports via email.

## Overview

The NIST 800-53 compliance analyzer retrieves findings from AWS SecurityHub, maps them to NIST 800-53 controls, generates AI-powered analysis, and delivers a comprehensive report via email. This functionality helps security teams and compliance officers monitor their AWS environment's compliance with NIST 800-53 controls.

## Triggering a NIST 800-53 Report

### Using Lambda

To trigger a NIST 800-53 compliance report via AWS Lambda, send an event with the following structure:

```json
{
    "email": "your-verified-email@example.com",
    "framework": "NIST800-53",
    "hours": 24,
    "generate_csv": true,
    "combined_analysis": false
}
```

You can find this template in the `examples/default-nist-event.json` file.

### Using Command Line

To generate a NIST 800-53 report from the command line:

```bash
python src/app.py report --email your-verified-email@example.com --framework NIST800-53 --hours 24 --csv
```

## Email Report Contents

The NIST 800-53 email report includes:

1. **Executive Summary**: A brief overview of the security posture
2. **NIST 800-53 Impact**: How the findings affect NIST 800-53 compliance
3. **Key Recommendations**: Top actions to address critical issues
4. **Auditor's Perspective**: An expert analysis written from a NIST auditor's viewpoint
5. **CSV Attachment**: Detailed findings mapped to NIST 800-53 controls

## Testing Functionality

Two test scripts are provided for testing the NIST 800-53 email functionality:

1. `run_nist_test.py`: Tests with real SecurityHub data (requires AWS credentials)
2. `run_nist_test_with_mocks.py`: Tests with mock data (does not require actual SecurityHub findings)

To test with mock data:

```bash
python run_nist_test_with_mocks.py
```

## NIST 800-53 Control Mapping

Findings are mapped to NIST 800-53 controls based on:

1. Finding types (e.g., "Software and Configuration Checks" maps to AC-3, AC-6, SI-2)
2. Keywords in finding titles (e.g., "encryption" maps to SC-13, SC-28)
3. Control attribute from SecurityHub if available

The mapping configuration is stored in:
- `config/mappings/nist800_53_mappings.json`
- Default mappings in `src/mappers/nist_mapper.py`

## Customizing the Report

To customize the NIST 800-53 report:

1. Modify the prompt in `analyze_findings()` function in `src/app.py`
2. Update the email styling and formatting in `send_email()` function in `src/app.py`
3. Add additional control mappings in `config/mappings/nist800_53_mappings.json`