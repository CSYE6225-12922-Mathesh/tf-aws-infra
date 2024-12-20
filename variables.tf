variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  default     = "10.0.0.0/16"
}

variable "aws_region" {
  default = "us-east-1"
}

variable "environment" {
  description = "Environment name to uniquely identify resources"
  type        = string
  default     = "dev"
}


variable "vpc_name" {
  description = "Name for the VPC"
  type        = string
  default     = "Main vpc"
}

variable "public_subnets" {
  type    = list(string)
  default = ["10.0.1.0/24", "10.0.3.0/24", "10.0.5.0/24"]
}

variable "private_subnets" {
  type    = list(string)
  default = ["10.0.2.0/24", "10.0.4.0/24", "10.0.6.0/24"]
}

variable "availability_zones" {
  description = "Availability zones in the region"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c", "us-east-1d", "us-east-1e", "us-east-1f"]
}

variable "cidr_block" {
  description = "CIDR block for internet gateway"
  default     = "0.0.0.0/0"
}

variable "application_port" {
  description = "Application port"
  default     = 8082
}

variable "ami_id" {
  description = "AMI ID for EC2 instances"
}

variable "instance_type" {
  description = "Instance type for EC2 instances"
  default     = "t2.micro"
}

variable "key_name" {
  description = "Name of the key pair for EC2 instances"
}

variable "cidr_blocks" {
  description = "CIDR blocks for ingress"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}


variable "database_name" {
  description = "Name for the DB"
  type        = string

}

variable "database_username" {
  description = "Username for the DB"
  type        = string
}

# variable "database_password" {
#   description = "Password for the DB"
#   type        = string
# }

variable "SENDGRID_API_KEY" {
  description = "Sendgrid API Key"
  type        = string
}

variable "down_threshold" {
  description = "Down threshold for the load balancer"
  type        = string
  default     = "6"
}

variable "up_threshold" {
  description = "Down threshold for the load balancer"
  type        = string
  default     = "6.5"
}

variable "lambda_code_path" {
  description = "Path to the Lambda code (zip file)"
  type        = string
  default     = "/Users/mathesh/serverless.zip" # Adjust to your local file path
}

variable "webapp_url" {
  description = "URL of the webapp"
  type        = string
  default     = "http://demo.cloudwebapp.me:80"
}

variable "sendgrid_secret_name" {
  description = "Name of the SendGrid API key secret"
  type        = string
  default     = "csye6225-sendgrid-api-key-3" # Default value (optional)
}
variable "db_password_secret_name" {
  description = "Name of the database password secret"
  type        = string
  default     = "csye6225-db-password-3" # Optional: default value
}




