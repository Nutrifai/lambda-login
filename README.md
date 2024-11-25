# NutrifAI - User Authentication Lambda
This repository contains the infrastructure for deploying a Lambda function that handles user authentication. The deployment is managed using Terraform and integrates with other AWS services.

## Key Features

- **User Login**: Users can authenticate themselves by providing their credentials (userId and password).
- **User Registration**: New users can create an account by providing basic information and choosing a secure password.
- **User Logout**: Users can end their session, invalidating their authentication token.

## Requirements

To use this project, ensure you have the following installed:
- [Terraform](https://www.terraform.io/downloads)
- [AWS CLI](https://aws.amazon.com/cli/) configured with appropriate permissions

Ensure that your AWS credentials are configured correctly using `aws configure`

## Instructions to Deploy Locally

### 1. Clone the repository
```bash
git clone https://github.com/Nutrifai/lambda-login.git
cd infra
```

### 2. Initialize Terraform
Before running any commands, initialize Terraform in the project directory.
```bash
terraform init
```

### 3. Plan the Deployment
Generate and review an execution plan to understand the resources that will be created or updated.
```bash
terraform plan
```

### 4. Apply the Configuration
To deploy the resources to AWS, run:
```bash
terraform apply -auto-approve
```

### Outputs
After deploying the infrastructure, Terraform will output useful information such as the API Gateway URL and Lambda function ARN. You can customize these outputs in the `outputs.tf` files.
