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
        *)
            echo -e "${RED}Unknown option: $key${NC}"
            echo "Usage: ./deploy.sh [--docker] [--no-guided]"
            exit 1
            ;;
    esac
done

# Build the application
echo -e "${YELLOW}Building the application...${NC}"
sam build

if [ $? -ne 0 ]; then
    echo -e "${RED}Build failed. Please check the errors above.${NC}"
    exit 1
fi

echo -e "${GREEN}Build successful!${NC}"

# If using Docker, build and push the image
if [ "$USE_DOCKER" = true ]; then
    echo -e "${YELLOW}Building and pushing Docker image...${NC}"
    
    # Get AWS account ID and region
    AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
    AWS_REGION=$(aws configure get region)
    
    if [ -z "$AWS_REGION" ]; then
        echo -e "${YELLOW}AWS region not found in config. Using us-east-1 as default.${NC}"
        AWS_REGION="us-east-1"
    fi
    
    # Create ECR repository if it doesn't exist
    echo "Creating ECR repository if it doesn't exist..."
    aws ecr describe-repositories --repository-names securityhub-soc2-reporter 2>/dev/null || \
        aws ecr create-repository --repository-name securityhub-soc2-reporter
    
    # Login to ECR
    echo "Logging in to ECR..."
    aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com
    
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

if [ "$GUIDED" = true ]; then
    sam deploy --guided $IMAGE_REPO_PARAM
else
    sam deploy $IMAGE_REPO_PARAM
fi

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