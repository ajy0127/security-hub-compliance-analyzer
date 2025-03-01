# Changelog

## [1.1.0] - 2025-02-28

### Added
- NIST 800-53 direct control status reporting for enhanced cATO monitoring
- Control family breakdown with compliance percentages
- Visual control family compliance indicators in email reports
- cATO readiness assessment and phase detection
- Comprehensive documentation for NIST control status feature
- Test scripts for NIST control status functionality
- Enhanced email templates with control family status tables
- Environment variable support for email addresses in all scripts

### Changed
- Updated README with NIST 800-53 cATO monitoring information
- Improved email styling for better readability
- Enhanced CSV generation with additional control status data
- Modified lambda handler to support direct control status retrieval

### Fixed
- Removed hardcoded email addresses from scripts
- Added proper error handling for control status API calls
- Fixed security issue with email addresses in public repository

## [1.0.0] - 2025-02-15

### Added
- Initial release with SOC 2 and NIST 800-53 findings analysis
- Email reporting with framework-specific formatting
- AWS Bedrock integration for AI-powered analysis
- Control mapping for SOC 2 and NIST 800-53
- CloudFormation deployment template
- Documentation and deployment guides