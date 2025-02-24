# Contributing to SecurityHub SOC 2 Compliance Analyzer

First off, thank you for considering contributing to the SecurityHub SOC 2 Compliance Analyzer! This is a specialized fork focused on SOC 2 compliance capabilities.

## Focus Areas for Contributions

We especially welcome contributions in these areas:
- SOC 2 control mapping improvements
- Additional Trust Service Criteria coverage
- Audit report enhancements
- Compliance documentation improvements
- SOC 2 evidence collection features

For general SecurityHub or non-SOC 2 improvements, please consider contributing to the [original project](https://github.com/aws-samples/analyze-securityhub-findings-with-bedrock).

## Development Process

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-soc2-feature`)
3. Set up development environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   pip install -r requirements.txt
   pip install pre-commit
   pre-commit install
   ```
4. Make your changes
5. Run all tests and checks:
   ```bash
   pytest tests/
   flake8 src/
   black src/
   cfn-lint template.yaml
   ```
6. Update documentation as needed
7. Commit your changes (`git commit -m 'Add amazing SOC 2 feature'`)
8. Push to your fork (`git push origin feature/amazing-soc2-feature`)
9. Create a Pull Request

## Pull Request Guidelines

1. Focus on SOC 2 compliance enhancements
2. Include test coverage for new features
3. Update relevant documentation
4. Ensure CI/CD pipeline passes
5. Add clear description of changes and benefits

## SOC 2 Compliance Considerations

When contributing, please ensure:
1. Control mappings align with SOC 2 Trust Service Criteria
2. Evidence collection meets audit requirements
3. Report formats follow SOC 2 documentation standards
4. Security controls maintain SOC 2 compliance

## Code of Conduct

### Our Pledge

We pledge to make participation in our project a harassment-free experience for everyone, regardless of level of experience, gender, gender identity and expression, sexual orientation, disability, personal appearance, body size, race, ethnicity, age, religion, or nationality.

### Our Standards

Examples of behavior that contributes to creating a positive environment include:
- Using welcoming and inclusive language
- Being respectful of differing viewpoints and experiences
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members

### Our Responsibilities

Project maintainers are responsible for clarifying the standards of acceptable behavior and are expected to take appropriate and fair corrective action in response to any instances of unacceptable behavior.

## Questions or Concerns?

Feel free to open an issue or contact the maintainers directly. 