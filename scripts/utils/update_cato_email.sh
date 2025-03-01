#!/bin/bash
# Script to update the Lambda function with cATO-focused email changes

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
cp "$PROJECT_ROOT/src/app.py" "$TEMP_DIR/app.py"
cp "$PROJECT_ROOT/src/utils.py" "$TEMP_DIR/utils.py"
cp "$PROJECT_ROOT/src/framework_mapper.py" "$TEMP_DIR/framework_mapper.py"
cp "$PROJECT_ROOT/src/mapper_factory.py" "$TEMP_DIR/mapper_factory.py"
cp "$PROJECT_ROOT/src/soc2_mapper.py" "$TEMP_DIR/soc2_mapper.py"  # For backward compatibility
cp "$PROJECT_ROOT/src/mappers/__init__.py" "$TEMP_DIR/mappers/"
cp "$PROJECT_ROOT/src/mappers/soc2_mapper.py" "$TEMP_DIR/mappers/"
cp "$PROJECT_ROOT/src/mappers/nist_mapper.py" "$TEMP_DIR/mappers/"

# Copy configuration files
echo "Copying configuration files..."
cp "$PROJECT_ROOT/config/frameworks.json" "$TEMP_DIR/config/"
cp "$PROJECT_ROOT/config/mappings/soc2_mappings.json" "$TEMP_DIR/config/mappings/"
cp "$PROJECT_ROOT/config/mappings/nist800_53_mappings.json" "$TEMP_DIR/config/mappings/"

# Fix imports - replace "from src." with "from "
echo "Fixing import paths for Lambda deployment..."
sed -i '' 's/from src\./from /g' "$TEMP_DIR/app.py"
sed -i '' 's/from src\./from /g' "$TEMP_DIR/framework_mapper.py"
sed -i '' 's/from src\./from /g' "$TEMP_DIR/mapper_factory.py"
sed -i '' 's/from \.mappers/from mappers/g' "$TEMP_DIR/mapper_factory.py"

# Change to temp directory and create ZIP file
cd "$TEMP_DIR"
echo "Creating ZIP file..."
zip -r lambda-cato-update.zip .

# Update Lambda function
echo "Updating Lambda function with cATO email improvements..."
aws lambda update-function-code \
  --function-name "$FUNCTION_NAME" \
  --zip-file fileb://lambda-cato-update.zip \
  --profile "$PROFILE"

# Clean up
cd -
rm -rf "$TEMP_DIR"
echo "Temporary directory removed."

echo "Lambda function updated with cATO email improvements."
echo "Send a test email to verify the changes using:"
echo "aws lambda invoke --function-name $FUNCTION_NAME --payload '{\"test_email\": true, \"recipient_email\": \"your-email@example.com\"}' --profile $PROFILE output.json"
echo "To send a NIST 800-53 report with cATO formatting, use:"
echo "aws lambda invoke --function-name $FUNCTION_NAME --payload '{\"framework\": \"NIST800-53\", \"email\": \"your-email@example.com\"}' --profile $PROFILE output.json"