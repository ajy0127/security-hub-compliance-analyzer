#!/bin/bash

# Create necessary directories if they don't exist
mkdir -p deployment/config
mkdir -p examples/payloads
mkdir -p examples/reports
mkdir -p scripts/{deployment,testing,utils}
mkdir -p src/tests/data
mkdir -p config/mappings

# Move test files to scripts/testing
mv test_*.py scripts/testing/
mv test_*.sh scripts/testing/
mv *test*.py scripts/testing/
mv run_test.py scripts/testing/

# Move utility scripts to scripts/utils
mv trigger_*.sh scripts/utils/
mv update_*.sh scripts/utils/
mv send_*.py scripts/utils/
mv run_*.py scripts/utils/
mv generate_*.py scripts/utils/

# Move example files
mv report_payload.json examples/payloads/
mv debug_email.html examples/reports/
mv nist_report.md examples/reports/

# Move configuration files
mv templates/* deployment/config/
rmdir templates

# Clean up temporary files
rm -f response.json
rm -f *.zip
rm -f output*.json
rm -f direct_*.json
rm -f test_*.json
rm -f nist_*.json
rm -f cato_*.json
rm -f frameworks_*.json

# Clean up Python cache
find . -type d -name "__pycache__" -exec rm -r {} +
find . -type d -name "*.egg-info" -exec rm -r {} +
find . -type f -name "*.pyc" -delete
find . -type f -name "*.pyo" -delete
find . -type f -name "*.pyd" -delete

# Clean up test artifacts
rm -rf .pytest_cache
rm -rf htmlcov
rm -f .coverage
rm -f coverage.xml

# Clean up virtual environments
rm -rf temp_venv
rm -rf nist_venv
rm -rf dist

echo "Project cleanup completed successfully!" 