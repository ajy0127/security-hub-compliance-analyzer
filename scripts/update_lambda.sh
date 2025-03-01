#!/bin/bash
# Script to update the Lambda function with the latest code

# Set variables
FUNCTION_NAME="security-hub-compliance-analyzer-SecurityHubAnalyzer"
S3_BUCKET="openauditorcode"
ZIP_FILE="lambda-code.zip"
PROFILE="sandbox"

echo "Creating Lambda deployment package..."

# Create a temporary directory
TEMP_DIR=$(mktemp -d)
echo "Created temporary directory: $TEMP_DIR"

# Get the project root
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"

# Copy source files
echo "Copying source files..."
cp "$PROJECT_ROOT/src/app.py" "$TEMP_DIR/app.py.orig"
cp "$PROJECT_ROOT/src/utils.py" "$TEMP_DIR/"
cp "$PROJECT_ROOT/src/framework_mapper.py" "$TEMP_DIR/"
cp "$PROJECT_ROOT/src/mapper_factory.py" "$TEMP_DIR/"
cp "$PROJECT_ROOT/src/requirements.txt" "$TEMP_DIR/"
cp "$PROJECT_ROOT/src/soc2_mapper.py" "$TEMP_DIR/"  # Include the old mapper for backward compatibility

# Fix import paths in app.py for Lambda
cat "$TEMP_DIR/app.py.orig" | sed 's/from src\./from /g' > "$TEMP_DIR/app.py"
rm "$TEMP_DIR/app.py.orig"

# Create directories for mappers module
echo "Setting up mappers module structure..."
mkdir -p "$TEMP_DIR/mappers"
cp "$PROJECT_ROOT/src/mappers/__init__.py" "$TEMP_DIR/mappers/"
cp "$PROJECT_ROOT/src/mappers/soc2_mapper.py" "$TEMP_DIR/mappers/"
cp "$PROJECT_ROOT/src/mappers/nist_mapper.py" "$TEMP_DIR/mappers/"

# Create directory for config
echo "Setting up config structure..."
mkdir -p "$TEMP_DIR/config/mappings"
cp "$PROJECT_ROOT/config/frameworks.json" "$TEMP_DIR/config/"
cp "$PROJECT_ROOT/config/mappings/soc2_mappings.json" "$TEMP_DIR/config/mappings/"
cp "$PROJECT_ROOT/config/mappings/nist800_53_mappings.json" "$TEMP_DIR/config/mappings/"

# Change to temp directory
cd "$TEMP_DIR"

# Install dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt -t .

# Create ZIP file
echo "Creating ZIP file..."
zip -r "$ZIP_FILE" .

# Upload to S3
echo "Uploading to S3..."
aws s3 cp "$ZIP_FILE" "s3://$S3_BUCKET/$ZIP_FILE" --profile "$PROFILE"

# Update Lambda function
echo "Updating Lambda function..."
aws lambda update-function-code \
  --function-name "$FUNCTION_NAME" \
  --s3-bucket "$S3_BUCKET" \
  --s3-key "$ZIP_FILE" \
  --profile "$PROFILE"

# Update Lambda configuration to ensure the function can handle NIST framework
echo "Updating Lambda configuration..."
aws lambda update-function-configuration \
  --function-name "$FUNCTION_NAME" \
  --handler "app.lambda_handler" \
  --memory-size 512 \
  --timeout 300 \
  --environment "Variables={SENDER_EMAIL=alexanderjyawn@gmail.com,RECIPIENT_EMAIL=alexanderjyawn@gmail.com,DEFAULT_FRAMEWORK=all,BEDROCK_MODEL_ID=anthropic.claude-3-sonnet-20240229-v1:0}" \
  --profile "$PROFILE"

# Clean up
cd "$PROJECT_ROOT"
rm -rf "$TEMP_DIR"
echo "Temporary directory removed."

echo "Lambda function update completed."