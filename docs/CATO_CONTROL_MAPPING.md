# NIST 800-53 Control Mapping for cATO

This document explains how NIST 800-53 controls are mapped to continuous Authorization to Operate (cATO) requirements in the Security Hub Compliance Analyzer.

## Control Family Mapping

The analyzer automatically groups NIST 800-53 controls by family to help with cATO implementation:

| Control Family | Examples | Description | cATO Priority |
|----------------|----------|-------------|---------------|
| AC - Access Control | AC-1, AC-2, AC-17 | Defines who can access what resources | Critical - High |
| AU - Audit and Accountability | AU-1, AU-2, AU-6 | Logging, monitoring, and auditing | Critical - High |
| CM - Configuration Management | CM-1, CM-2, CM-6 | System baseline and change control | Critical - High |
| IA - Identification and Authentication | IA-1, IA-2, IA-5 | User identity management | Critical - High |
| RA - Risk Assessment | RA-1, RA-3, RA-5 | Identifying and analyzing risks | Critical - Medium |
| SC - System and Communications Protection | SC-1, SC-7, SC-12 | Data protection and communications | Critical - High |
| SI - System and Information Integrity | SI-1, SI-4, SI-7 | System monitoring and protection | Critical - High |
| CA - Assessment, Authorization, and Monitoring | CA-1, CA-2, CA-6 | System assessment procedures | Critical - Medium |
| CP - Contingency Planning | CP-1, CP-2, CP-9 | Recovery and continuity | Medium |
| IR - Incident Response | IR-1, IR-4, IR-8 | Security incident handling | Medium - High |
| MA - Maintenance | MA-1, MA-2, MA-5 | System maintenance | Medium |
| MP - Media Protection | MP-1, MP-2, MP-6 | Protection of system media | Medium |
| PE - Physical and Environmental Protection | PE-1, PE-2, PE-6 | Facility protection | Medium |
| PL - Planning | PL-1, PL-2, PL-8 | Information system planning | Medium |
| PS - Personnel Security | PS-1, PS-3, PS-7 | Personnel controls | Medium |
| SA - System and Services Acquisition | SA-1, SA-3, SA-10 | System development lifecycle | Medium |
| AT - Awareness and Training | AT-1, AT-2, AT-3 | Security training | Medium - Low |

## cATO Implementation Phases

For cATO implementation, controls are prioritized across three phases:

### Phase 1: Foundation (Critical Controls)

Focus on implementing these control families first:
- Access Control (AC)
- Identification and Authentication (IA)
- System and Communications Protection (SC)
- Audit and Accountability (AU)
- System and Information Integrity (SI)
- Configuration Management (CM)

### Phase 2: Framework (High-Priority Controls)

Add these control families next:
- Risk Assessment (RA)
- Incident Response (IR)
- Assessment, Authorization, and Monitoring (CA)
- Media Protection (MP)
- System and Services Acquisition (SA)

### Phase 3: Maturity (Medium-Priority Controls)

Complete the implementation with:
- Contingency Planning (CP)
- Maintenance (MA)
- Physical and Environmental Protection (PE)
- Planning (PL)
- Personnel Security (PS)
- Awareness and Training (AT)

## Control Status in Security Hub

In AWS Security Hub, NIST 800-53 controls can have the following statuses:

| Security Hub Status | cATO Mapping |
|---------------------|--------------|
| PASSED | Control implemented successfully |
| FAILED | Control not implemented or not working |
| WARNING | Control partially implemented |
| NOT_APPLICABLE | Control not applicable to the system |
| NO_DATA | Control not yet evaluated |

The analyzer calculates compliance percentages based on these statuses to determine your cATO implementation phase.

## Continuous Monitoring Requirements

For true cATO implementation, controls must be continuously monitored:

1. **Automated Assessment**: Controls should be evaluated automatically where possible
2. **Deviation Detection**: Changes that affect control status must be detected quickly
3. **Evidence Collection**: Continuous collection of compliance evidence
4. **Regular Reporting**: Automatic generation of compliance status reports (this tool)

The Security Hub Compliance Analyzer helps with the reporting aspect of cATO, but a complete cATO implementation requires additional components for continuous monitoring and assessment.

## References

- [NIST 800-53 Revision 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [NIST 800-37 - Risk Management Framework](https://csrc.nist.gov/publications/detail/sp/800-37/rev-2/final)
- [AWS Security Hub NIST 800-53 Standard](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-nist.html)