# SOC 2 Control Mapping Guide for GRC Professionals

This guide will help you understand how AWS SecurityHub findings map to SOC 2 controls in our lab project, and how you can customize these mappings to demonstrate your SOC 2 expertise.

## Understanding SOC 2 Controls

SOC 2 is organized around five Trust Services Criteria:

1. **Security** - Protection against unauthorized access (both physical and logical)
2. **Availability** - Systems are available for operation and use as committed or agreed
3. **Processing Integrity** - System processing is complete, valid, accurate, timely, and authorized
4. **Confidentiality** - Information designated as confidential is protected as committed or agreed
5. **Privacy** - Personal information is collected, used, retained, disclosed, and disposed of in conformity with commitments

Each criterion contains multiple control objectives that organizations must implement to achieve compliance.

## How AWS SecurityHub Findings Relate to SOC 2

AWS SecurityHub generates findings based on security checks across your AWS environment. These findings often relate directly to SOC 2 control requirements:

| SecurityHub Finding Category | Related SOC 2 Trust Services Criteria |
|------------------------------|---------------------------------------|
| Identity and Access Management | Security (Access Control) |
| Detection Controls | Security (System Monitoring) |
| Network Security | Security (Network Protection) |
| Data Protection | Confidentiality, Privacy |
| Vulnerability Management | Security (Vulnerability Management) |
| Logging | Security (Logging and Monitoring) |
| Resilience | Availability |

## How the Mapping Works in Our Solution

Our solution uses a `mappings.json` file to connect SecurityHub findings to SOC 2 controls in two ways:

1. **Type Mappings**: Maps SecurityHub finding types (e.g., `Software and Configuration Checks/Industry and Regulatory Standards/CIS Host Hardening Benchmarks`) to SOC 2 controls
2. **Title Mappings**: Maps keywords in finding titles (e.g., "encryption", "password") to SOC 2 controls

When a finding is processed, the system:
1. Checks if the finding type matches any type mappings
2. Checks if the finding title contains any keywords from title mappings
3. Associates the finding with the corresponding SOC 2 controls
4. If no matches are found, assigns a default control (usually CC7.1)

## Example Mappings

Here are some example mappings from our solution:

### Type Mappings

```json
"type_mappings": {
  "Software and Configuration Checks/Industry and Regulatory Standards/CIS Host Hardening Benchmarks": ["CC6.1", "CC6.8"],
  "Software and Configuration Checks/Vulnerabilities/CVE": ["CC7.1", "CC7.2"],
  "Effects/Data Exposure": ["CC6.1", "CC6.7", "CC5.1"]
}
```

### Title Mappings

```json
"title_mappings": {
  "password": ["CC6.1", "CC6.3"],
  "encryption": ["CC6.1", "CC6.7"],
  "access": ["CC6.1", "CC6.3"],
  "permission": ["CC6.3"],
  "exposed": ["CC6.1", "CC6.7"],
  "public": ["CC6.1", "CC6.7"]
}
```

## Common SOC 2 Controls in Cloud Environments

Here are key SOC 2 controls that frequently apply to AWS environments:

| Control | Description | Common AWS Findings |
|---------|-------------|---------------------|
| CC6.1 | Logical access security software, infrastructure, and architectures | IAM policies, S3 bucket permissions, Security Groups |
| CC6.3 | Authorization processes to restrict access | IAM roles, resource policies, least privilege violations |
| CC6.7 | Encryption of sensitive data | Unencrypted S3 buckets, EBS volumes, RDS instances |
| CC6.8 | Vulnerability management | Patch management, security updates, CVEs |
| CC7.1 | Security monitoring and analysis | CloudTrail logging, GuardDuty findings |
| CC7.2 | Incident response activities | Security Hub integrations, response plans |
| CC8.1 | Change management | Infrastructure changes, configuration drift |
| A1.2 | Environmental protections | Availability Zone usage, backup configurations |

## Customizing the Mappings

You can customize the `mappings.json` file to demonstrate your understanding of SOC 2 controls. Here's how:

1. **Download** the current mappings.json file from the S3 bucket
2. **Open** it in a text editor
3. **Modify** the mappings based on your knowledge
4. **Upload** the modified file back to the S3 bucket

### Tips for Customization

1. **Add New Keywords**: Think about security terms that might appear in findings and map them to relevant controls
   ```json
   "title_mappings": {
     "root account": ["CC6.1", "CC6.3", "CC6.8"],
     "multi-factor": ["CC6.1", "CC6.3"],
     "least privilege": ["CC6.1", "CC6.3", "CC6.4"]
   }
   ```

2. **Expand Control Coverage**: Add additional controls to existing mappings
   ```json
   "type_mappings": {
     "Software and Configuration Checks/Industry and Regulatory Standards/CIS Host Hardening Benchmarks": ["CC6.1", "CC6.8", "CC7.1", "CC7.2"]
   }
   ```

3. **Add Control Descriptions**: Enhance the control descriptions to show your understanding
   ```json
   "control_descriptions": {
     "CC6.1": "The entity implements logical access security software, infrastructure, and architectures for protection of its assets against external threats and unauthorized internal access. This includes implementing appropriate access controls for cloud resources, enforcing least privilege principles, and regularly reviewing access permissions.",
     ...
   }
   ```

4. **Add New Controls**: Include additional SOC 2 controls that aren't in the default mappings
   ```json
   "control_descriptions": {
     "CC9.1": "The entity identifies, selects, and develops risk mitigation activities for risks arising from potential business disruptions.",
     "CC9.2": "The entity assesses and manages risks associated with vendors and business partners."
   }
   ```

## Example: Enhanced Mapping for a GRC Portfolio

Here's an example of how you might enhance the mappings to demonstrate your expertise:

```json
{
  "type_mappings": {
    "Software and Configuration Checks/Industry and Regulatory Standards/CIS Host Hardening Benchmarks": ["CC6.1", "CC6.8", "CC7.1"],
    "Software and Configuration Checks/Vulnerabilities/CVE": ["CC7.1", "CC7.2", "CC6.8", "CC8.1"],
    "Effects/Data Exposure": ["CC6.1", "CC6.7", "CC5.1", "P4.1"],
    "TTPs/Initial Access/Trusted Relationship": ["CC9.2", "CC6.1"],
    "Effects/Data Exfiltration": ["CC6.1", "CC6.7", "CC5.1", "P4.1", "P4.2"]
  },
  "title_mappings": {
    "password": ["CC6.1", "CC6.3", "CC5.2"],
    "encryption": ["CC6.1", "CC6.7", "P3.1"],
    "access": ["CC6.1", "CC6.3", "CC6.4"],
    "permission": ["CC6.3", "CC6.4", "CC6.5"],
    "exposed": ["CC6.1", "CC6.7", "P4.1"],
    "public": ["CC6.1", "CC6.7", "P4.1"],
    "root account": ["CC6.1", "CC6.3", "CC6.8"],
    "multi-factor": ["CC6.1", "CC6.3"],
    "least privilege": ["CC6.1", "CC6.3", "CC6.4"],
    "backup": ["A1.2", "A1.3"],
    "logging": ["CC7.1", "CC7.2", "CC4.1"],
    "monitoring": ["CC7.1", "CC7.2", "CC7.3"],
    "patch": ["CC6.8", "CC8.1"],
    "update": ["CC6.8", "CC8.1"],
    "configuration": ["CC6.1", "CC6.8", "CC8.1"]
  },
  "control_descriptions": {
    "CC5.1": "The entity selects and develops control activities that contribute to the mitigation of risks to the achievement of objectives to acceptable levels.",
    "CC5.2": "The entity also selects and develops general control activities over technology to support the achievement of objectives.",
    "CC6.1": "The entity implements logical access security software, infrastructure, and architectures for protection against security threats both external and internal to the organization. This includes implementing appropriate access controls for cloud resources, enforcing least privilege principles, and regularly reviewing access permissions.",
    "CC6.3": "The entity authorizes, modifies, or removes access to data, infrastructure, and application software based on user roles and responsibilities, ensuring appropriate segregation of duties.",
    "CC6.4": "The entity restricts physical access to facilities and protected information assets to authorized personnel to meet the entity's objectives.",
    "CC6.5": "The entity discontinues logical and physical protections over physical assets only after the ability to read or recover data and software from those assets has been diminished and is no longer required to meet the entity's objectives.",
    "CC6.7": "The entity restricts the transmission, movement, and removal of information to authorized users and processes, and protects it during transmission, movement, or removal to meet the entity's objectives. This includes implementing encryption for data in transit and at rest.",
    "CC6.8": "The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software to meet the entity's objectives. This includes vulnerability management, patch management, and endpoint protection.",
    "CC7.1": "The entity selects, develops, and performs ongoing and/or separate evaluations to ascertain whether the components of internal control are present and functioning. This includes implementing comprehensive logging and monitoring solutions.",
    "CC7.2": "The entity evaluates and communicates internal control deficiencies in a timely manner to those parties responsible for taking corrective action, including senior management and the board of directors, as appropriate. This includes incident response procedures and security alerting.",
    "CC7.3": "The entity evaluates and communicates internal control deficiencies in a timely manner to those parties responsible for taking corrective action, including senior management and the board of directors, as appropriate.",
    "CC8.1": "The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures to meet its objectives. This includes change management processes for cloud infrastructure.",
    "A1.2": "The entity authorizes, designs, develops or acquires, implements, operates, approves, maintains, and monitors environmental protections, software, data backup processes, and recovery infrastructure to meet its objectives. This includes implementing multi-AZ deployments and backup strategies.",
    "A1.3": "The entity tests recovery plan procedures supporting system recovery to meet its objectives. This includes regular testing of backup and restore procedures.",
    "P3.1": "The entity collects personal information in accordance with the entity's objectives related to privacy.",
    "P4.1": "The entity limits the use of personal information to the purposes identified in the entity's objectives related to privacy.",
    "P4.2": "The entity retains personal information consistent with the entity's objectives related to privacy.",
    "CC9.1": "The entity identifies, selects, and develops risk mitigation activities for risks arising from potential business disruptions.",
    "CC9.2": "The entity assesses and manages risks associated with vendors and business partners."
  }
}
```

## Mapping Best Practices

1. **Be Comprehensive**: Ensure your mappings cover all five Trust Services Criteria where applicable
2. **Be Specific**: Tailor mappings to specific finding types rather than using generic mappings
3. **Be Accurate**: Ensure the controls you map to are actually relevant to the finding
4. **Be Detailed**: Provide thorough descriptions that demonstrate your understanding
5. **Think Like an Auditor**: Consider what an auditor would look for when assessing these controls

## Using Your Customized Mappings in Your Portfolio

After customizing your mappings:

1. **Document Your Approach**: Write a brief explanation of your mapping methodology
2. **Highlight Your Enhancements**: Note specific improvements you made to the default mappings
3. **Create a Sample Report**: Generate a report using your custom mappings
4. **Prepare to Discuss**: Be ready to explain your mapping decisions in interviews

By customizing these mappings, you demonstrate not just theoretical knowledge of SOC 2, but the ability to apply that knowledge in a practical cloud security context—a valuable skill for any GRC professional. 