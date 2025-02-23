# SOC 2 Control Mappings Guide

This guide explains how AWS SecurityHub findings are mapped to SOC 2 Trust Services Criteria (TSC) in the SecurityHub SOC 2 Analyzer.

## Overview

The analyzer automatically maps SecurityHub findings to relevant SOC 2 controls based on:
- Finding type and category
- AWS service affected
- Security impact
- Compliance implications

## Control Mapping Logic

### Primary Controls

Primary controls are directly impacted by the security finding. These typically include:
- Access control violations (CC6.1)
- System operation issues (CC7.1)
- Change management concerns (CC8.1)
- Risk assessment findings (CC9.1)

### Secondary Controls

Secondary controls are indirectly affected or serve as compensating controls:
- Monitoring controls
- Logging requirements
- Backup procedures
- Alternative security measures

## AWS Service to SOC 2 Control Mappings

### Identity and Access Management (IAM)
- **CC6.1.2**: MFA Configuration
- **CC6.1.3**: Password Policies
- **CC6.1.9**: Access Reviews
- **CC6.2.1**: Account Provisioning

### S3 and Data Storage
- **CC6.1.7**: Encryption at Rest
- **CC6.1.8**: Key Management
- **CC6.1.10**: Public Access
- **CC6.1.4**: Network Controls

### Security Services
- **CC6.6.2**: CloudTrail Logging
- **CC6.6.3**: WAF Configuration
- **CC6.6.4**: Security Monitoring
- **CC7.1.2**: Vulnerability Scanning

### Container Services
- **CC7.1.5**: Container Security
- **CC8.1.5**: Deployment Controls
- **CC6.6.1**: Configuration Management

## Risk Level Mapping

SecurityHub severity levels are mapped to SOC 2 risk levels:
- CRITICAL → High Risk
- HIGH → High Risk
- MEDIUM → Medium Risk
- LOW → Low Risk
- INFORMATIONAL → Low Risk

## Control Categories

### CC6.0: Logical and Physical Access Controls
- Access provisioning and review
- Authentication mechanisms
- Network security
- Data encryption

### CC7.0: System Operations
- Vulnerability management
- Malicious software prevention
- Security incident handling
- Resource monitoring

### CC8.0: Change Management
- System development lifecycle
- Infrastructure changes
- Access control changes
- Security testing

### CC9.0: Risk Mitigation
- Risk assessment
- Vendor management
- Business continuity
- Incident response

## Evidence Collection

For each mapped control, the analyzer collects:
1. SecurityHub finding details
2. Affected resources
3. Compliance status
4. Remediation steps
5. Timeline requirements

## Report Generation

The analyzer generates SOC 2-formatted reports including:
1. Control mapping details
2. Risk assessments
3. Evidence references
4. Remediation status
5. Compliance impact

## Using Control Mappings

### For Audits
1. Use generated CSV reports as audit evidence
2. Reference SecurityHub findings for control testing
3. Document remediation efforts
4. Track compliance status

### For Compliance
1. Monitor control effectiveness
2. Identify control gaps
3. Implement remediation
4. Maintain evidence

## Customizing Mappings

Control mappings can be customized in `config/soc2_control_mappings.json`:
1. Add new finding type mappings
2. Modify control assignments
3. Update risk levels
4. Enhance control descriptions

## Best Practices

1. **Regular Reviews**
   - Monitor mapping effectiveness
   - Update for new finding types
   - Adjust risk levels
   - Enhance control descriptions

2. **Evidence Management**
   - Maintain detailed findings
   - Document remediation
   - Track timelines
   - Archive reports

3. **Compliance Monitoring**
   - Review daily reports
   - Track control status
   - Address high-risk findings
   - Update documentation

## Additional Resources

- [SOC 2 Trust Services Criteria](https://us.aicpa.org/interestareas/frc/assuranceadvisoryservices/trustservices)
- [AWS Security Hub Documentation](https://docs.aws.amazon.com/securityhub/)
- [Security Best Practices](https://aws.amazon.com/architecture/security-identity-compliance/)
- [Compliance Resources](https://aws.amazon.com/compliance/resources/) 