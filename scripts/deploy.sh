#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}SecurityHub SOC 2 Email Reporter - Deployment Script${NC}"
echo "========================================================"

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo -e "${RED}Error: AWS CLI is not installed. Please install it first.${NC}"
    exit 1
fi

# Check if SAM CLI is installed
if ! command -v sam &> /dev/null; then
    echo -e "${RED}Error: AWS SAM CLI is not installed. Please install it first.${NC}"
    exit 1
fi

# Parse command line arguments
USE_DOCKER=false
GUIDED=true
AWS_PROFILE=""
RESOLVE_S3=false

while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --docker)
            USE_DOCKER=true
            shift
            ;;
        --no-guided)
            GUIDED=false
            shift
            ;;
        --resolve-s3)
            RESOLVE_S3=true
            shift
            ;;
        --profile)
            AWS_PROFILE="$2"
            shift 2
            ;;
        --profile=*)
            AWS_PROFILE="${1#*=}"
            shift
            ;;
        *)
            echo -e "${RED}Unknown option: $key${NC}"
            echo "Usage: ./deploy.sh [--docker] [--no-guided] [--resolve-s3] [--profile <aws-profile>]"
            exit 1
            ;;
    esac
done

# Set AWS profile if provided
if [ -n "$AWS_PROFILE" ]; then
    echo -e "${YELLOW}Using AWS profile: $AWS_PROFILE${NC}"
    export AWS_PROFILE="$AWS_PROFILE"
fi

# Build the application
echo -e "${YELLOW}Building the application...${NC}"
sam build --use-container

if [ $? -ne 0 ]; then
    echo -e "${RED}Build failed. Please check the errors above.${NC}"
    exit 1
fi

echo -e "${GREEN}Build successful!${NC}"

# If using Docker, build and push the image
if [ "$USE_DOCKER" = true ]; then
    echo -e "${YELLOW}Building and pushing Docker image...${NC}"
    
    # Build the AWS CLI command prefix with profile if specified
    AWS_CMD="aws"
    if [ -n "$AWS_PROFILE" ]; then
        echo -e "${YELLOW}Using AWS profile for AWS CLI commands: $AWS_PROFILE${NC}"
    fi
    
    # Get AWS account ID and region
    AWS_ACCOUNT_ID=$($AWS_CMD sts get-caller-identity --query Account --output text)
    AWS_REGION=$($AWS_CMD configure get region)
    
    if [ -z "$AWS_REGION" ]; then
        echo -e "${YELLOW}AWS region not found in config. Using us-east-1 as default.${NC}"
        AWS_REGION="us-east-1"
    fi
    
    # Create ECR repository if it doesn't exist
    echo "Creating ECR repository if it doesn't exist..."
    $AWS_CMD ecr describe-repositories --repository-names securityhub-soc2-reporter 2>/dev/null || \
        $AWS_CMD ecr create-repository --repository-name securityhub-soc2-reporter
    
    # Login to ECR
    echo "Logging in to ECR..."
    $AWS_CMD ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com
    
    # Build and tag the Docker image
    echo "Building Docker image..."
    docker build -t securityhub-soc2-reporter .
    
    # Tag and push the image
    echo "Tagging and pushing Docker image..."
    docker tag securityhub-soc2-reporter:latest $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/securityhub-soc2-reporter:latest
    docker push $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/securityhub-soc2-reporter:latest
    
    # Set the image repository parameter
    IMAGE_REPO_PARAM="--parameter-overrides ImageRepository=$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/securityhub-soc2-reporter"
    
    echo -e "${GREEN}Docker image built and pushed successfully!${NC}"
else
    IMAGE_REPO_PARAM=""
fi

# Deploy the application
echo -e "${YELLOW}Deploying the application...${NC}"

# Create a temporary S3 bucket for packaging if it doesn't exist
S3_BUCKET_NAME="securityhub-soc2-analyzer-$(date +%s)-deployment"
echo -e "${YELLOW}Creating temporary S3 bucket for deployment: $S3_BUCKET_NAME${NC}"
aws s3 mb s3://$S3_BUCKET_NAME --region $(aws configure get region) || {
    echo -e "${RED}Failed to create S3 bucket. Using guided deployment instead.${NC}"
    GUIDED=true
}

# Package the application first
if [ "$GUIDED" = false ]; then
    echo -e "${YELLOW}Packaging the application...${NC}"
    sam package --s3-bucket $S3_BUCKET_NAME --output-template-file packaged.yaml || {
        echo -e "${RED}Packaging failed. Falling back to guided deployment.${NC}"
        GUIDED=true
    }
fi

# Build SAM deployment command
if [ "$GUIDED" = true ]; then
    # For guided deployment
    SAM_DEPLOY_CMD="sam deploy --guided"
else
    # For non-guided deployment with packaging
    SAM_DEPLOY_CMD="sam deploy --template-file packaged.yaml --no-fail-on-empty-changeset"
    
    # Add stack name
    SAM_DEPLOY_CMD="$SAM_DEPLOY_CMD --stack-name securityhub-soc2-analyzer"
fi

# Add image repository parameter if Docker is used
if [ -n "$IMAGE_REPO_PARAM" ]; then
    SAM_DEPLOY_CMD="$SAM_DEPLOY_CMD $IMAGE_REPO_PARAM"
fi

# Execute the deployment
echo "Running: $SAM_DEPLOY_CMD"
eval $SAM_DEPLOY_CMD

if [ $? -ne 0 ]; then
    echo -e "${RED}Deployment failed. Please check the errors above.${NC}"
    exit 1
fi

echo -e "${GREEN}Deployment successful!${NC}"
echo "========================================================"
echo -e "${GREEN}SecurityHub SOC 2 Email Reporter has been deployed successfully!${NC}"
echo ""
echo "To test the solution, run:"
echo -e "${YELLOW}aws lambda invoke --function-name <function-name> --payload '{\"test_email\":true}' response.json${NC}"
echo ""
echo "Replace <function-name> with the actual Lambda function name from the output above."
echo "You should receive a test email shortly."
echo ""
echo "For more information, refer to the README.md file." 