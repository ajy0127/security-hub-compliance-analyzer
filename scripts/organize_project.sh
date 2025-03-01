#!/bin/bash

# Create necessary directories
mkdir -p deployment/config
mkdir -p examples/payloads
mkdir -p examples/reports
mkdir -p scripts/deployment
scripts/testing
mkdir -p scripts/utils
mkdir -p src/tests/data
mkdir -p config/mappings

# Move deployment files
mv cloudformation.yaml deployment/
mv deployment/config/* config/mappings/
rm -rf deployment/config

# Move example files
mv examples/*.json examples/payloads/
mv nist_report.md examples/reports/
mv debug_email.html examples/reports/

# Organize scripts
mv scripts/deploy.sh scripts/deployment/
mv scripts/package_for_cloudformation.sh scripts/deployment/
mv scripts/test_sandbox_profile.sh scripts/testing/
mv scripts/test_locally.py scripts/testing/
mv scripts/test_lambda_locally.sh scripts/testing/
mv scripts/format_code.py scripts/utils/
mv check_ses_status.sh scripts/utils/
mv test_ses_delivery.sh scripts/utils/
mv fix_imports.sh scripts/utils/

# Clean up temporary and test files
rm -f output*.json
rm -f *_response.json
rm -f direct_*.json
rm -f test_*.json
rm -f nist_*.json
rm -f cato_*.json
rm -f frameworks_*.json
rm -f lambda-code*.zip
rm -rf temp_venv/
rm -rf nist_venv/
rm -rf .pytest_cache/
rm -rf __pycache__/
rm -rf .aws-sam/

# Keep necessary files
touch examples/payloads/.gitkeep
touch examples/reports/.gitkeep
touch config/mappings/.gitkeep

echo "Project structure organized successfully!" 