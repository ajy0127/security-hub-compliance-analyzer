#!/bin/bash
# Script to fix the imports in the Lambda function

# Set variables
FUNCTION_NAME="security-hub-compliance-analyzer-SecurityHubAnalyzer"
PROFILE="sandbox"

# Create a temporary directory
TEMP_DIR=$(mktemp -d)
echo "Created temporary directory: $TEMP_DIR"

# Create directory structure
mkdir -p "$TEMP_DIR/config/mappings"
mkdir -p "$TEMP_DIR/mappers"

# Copy source code files
PROJECT_ROOT="/Users/comoelcoqui/repos/security-hub-compliance-analyzer"
echo "Copying source files..."

# Create a fixed app.py
cat > "$TEMP_DIR/app.py" << 'EOL'
"""AWS SecurityHub Compliance Analyzer with multi-framework support."""

import argparse
import csv
import io
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import boto3

from soc2_mapper import SOC2Mapper
from framework_mapper import FrameworkMapper  
from mapper_factory import MapperFactory, load_frameworks
from utils import format_datetime, get_resource_id

# Configure logging for both Lambda and CLI environments
logger = logging.getLogger()
logger.setLevel(logging.INFO)
EOL

# Copy rest of app.py content (without import statements)
tail -n +27 "$PROJECT_ROOT/src/app.py" >> "$TEMP_DIR/app.py"

# Copy and fix other necessary files
cp "$PROJECT_ROOT/src/utils.py" "$TEMP_DIR/utils.py"
cp "$PROJECT_ROOT/src/soc2_mapper.py" "$TEMP_DIR/soc2_mapper.py"

# Copy the framework_mapper file and fix its imports
cat "$PROJECT_ROOT/src/framework_mapper.py" | sed 's/from src\./from /g' > "$TEMP_DIR/framework_mapper.py"

# Copy the mapper_factory file and fix its imports
cat "$PROJECT_ROOT/src/mapper_factory.py" | sed 's/from src\./from /g' | sed 's/from \.mappers/from mappers/g' > "$TEMP_DIR/mapper_factory.py"

# Copy mappers module files
cp "$PROJECT_ROOT/src/mappers/__init__.py" "$TEMP_DIR/mappers/"
cat "$PROJECT_ROOT/src/mappers/soc2_mapper.py" | sed 's/from \.\./from /g' > "$TEMP_DIR/mappers/soc2_mapper.py"
cat "$PROJECT_ROOT/src/mappers/nist_mapper.py" | sed 's/from \.\./from /g' > "$TEMP_DIR/mappers/nist_mapper.py"

# Copy configuration files
echo "Copying configuration files..."
cp "$PROJECT_ROOT/config/frameworks.json" "$TEMP_DIR/config/"
cp "$PROJECT_ROOT/config/mappings/soc2_mappings.json" "$TEMP_DIR/config/mappings/"
cp "$PROJECT_ROOT/config/mappings/nist800_53_mappings.json" "$TEMP_DIR/config/mappings/"

# Add requirements file
cat > "$TEMP_DIR/requirements.txt" << 'EOL'
boto3>=1.28.0
EOL

# Change to temp directory and create ZIP file
cd "$TEMP_DIR"
echo "Creating ZIP file..."
zip -r lambda-fixed-imports.zip .

# Update Lambda function
echo "Updating Lambda function with fixed imports..."
aws lambda update-function-code \
  --function-name "$FUNCTION_NAME" \
  --zip-file fileb://lambda-fixed-imports.zip \
  --profile "$PROFILE"

# Clean up
cd -
rm -rf "$TEMP_DIR"
echo "Temporary directory removed."

echo "Lambda function updated with fixed imports."