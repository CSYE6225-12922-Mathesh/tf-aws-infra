resource "aws_vpc" "main" {
  cidr_block = var.vpc_cidr
  tags = {
    Name = "${var.environment}-${var.vpc_name}"
  }
}

resource "aws_subnet" "public" {
  count                   = length(var.public_subnets)
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnets[count.index]
  availability_zone       = element(var.availability_zones, count.index)
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.environment}-${var.vpc_name}-public-${count.index + 1}"
  }
}

resource "aws_subnet" "private" {
  count             = length(var.private_subnets)
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnets[count.index]
  availability_zone = element(var.availability_zones, count.index)

  tags = {
    Name = "${var.environment}-${var.vpc_name}-private-${count.index + 1}"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.environment}-${var.vpc_name}-igw"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = var.cidr_block
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "${var.environment}-${var.vpc_name}-public-route"
  }
}
resource "aws_route_table_association" "public" {
  count          = length(var.public_subnets)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}


resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.environment}-${var.vpc_name}-private-route"
  }
}

resource "aws_route_table_association" "private" {
  count          = length(var.private_subnets)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

resource "aws_security_group" "app_sg" {
  name        = "application security group"
  description = "App Security Group"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  # ingress {
  #   from_port   = 80
  #   to_port     = 80
  #   protocol    = "tcp"
  #   cidr_blocks = var.cidr_blocks
  # }
  # ingress {
  #   from_port   = 443
  #   to_port     = 443
  #   protocol    = "tcp"
  #   cidr_blocks = var.cidr_blocks
  # }

  ingress {
    from_port       = var.application_port
    to_port         = var.application_port
    protocol        = "tcp"
    security_groups = [aws_security_group.load_balancer_sg.id] // Only allow from Load Balancer
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }


  tags = {
    Name = "application security group"
  }
}


//a05
resource "aws_security_group" "database_sg" {
  name        = "database security group"
  description = "Database Security Group "
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app_sg.id]

  }
}

resource "aws_security_group_rule" "app_to_db" {
  type                     = "egress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  security_group_id        = aws_security_group.app_sg.id
  source_security_group_id = aws_security_group.database_sg.id
}

resource "aws_db_parameter_group" "postgresql_param_group" {
  name        = "csye6225-postgresql-params"
  family      = "postgres16"
  description = "Custom parameter group for PostgreSQL 12"

}

resource "aws_db_subnet_group" "rds_subnet" {
  name        = "csye6225-rds-subnet-group"
  description = "Subnet group for RDS instances"
  subnet_ids  = aws_subnet.private[*].id

  tags = {
    Name = "csye6225-rds-subnet-group"
  }
}


resource "aws_db_instance" "db_instance" {
  identifier             = "csye6225"
  engine                 = "postgres"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  db_subnet_group_name   = aws_db_subnet_group.rds_subnet.name
  vpc_security_group_ids = [aws_security_group.database_sg.id]
  parameter_group_name   = aws_db_parameter_group.postgresql_param_group.name
  publicly_accessible    = false
  multi_az               = false
  db_name                = var.database_name
  username               = var.database_username
  password               = random_password.db_password.result
  kms_key_id             = aws_kms_key.rds_key.arn
  storage_encrypted      = true
  skip_final_snapshot    = true
}
resource "aws_iam_role" "cloudwatch_agent_role" {
  name = "CloudWatchAgentRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "ec2.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })
}


resource "aws_iam_policy_attachment" "cloudwatch_agent_policy_attachment" {
  name       = "cloudwatch-agent-policy-attachment"
  roles      = [aws_iam_role.cloudwatch_agent_role.name]
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}
resource "aws_iam_policy" "s3_access_policy" {
  name        = "S3AccessPolicy"
  description = "Policy for accessing S3 bucket from EC2 instance"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ],
        Resource = [
          "arn:aws:s3:::${aws_s3_bucket.web-bucket.bucket}",
          "arn:aws:s3:::${aws_s3_bucket.web-bucket.bucket}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_policy_attachment" "s3_policy_attachment" {
  name       = "s3-policy-attachment"
  roles      = [aws_iam_role.cloudwatch_agent_role.name]
  policy_arn = aws_iam_policy.s3_access_policy.arn
}

resource "aws_iam_instance_profile" "cloudwatch_agent_instance_profile" {
  name = "CloudWatchAgentInstanceProfile"
  role = aws_iam_role.cloudwatch_agent_role.name
}


resource "aws_s3_bucket" "web-bucket" {
  bucket = random_uuid.web_bucket.result
  //acl           = "private"
  force_destroy = true
  tags = {
    Name        = "My bucket"
    Environment = var.environment
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bucket_sse" {
  bucket = aws_s3_bucket.web-bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3_key.arn
    }
  }
}

resource "random_uuid" "web_bucket" {}


resource "aws_s3_bucket_lifecycle_configuration" "web_bucket_lifecycle" {
  bucket = aws_s3_bucket.web-bucket.id

  rule {
    id     = "MoveToIA"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    noncurrent_version_transition {
      noncurrent_days = 30
      storage_class   = "STANDARD_IA"
    }
  }
}


data "aws_route53_zone" "cloudwebapp" {
  name         = "demo.cloudwebapp.me"
  private_zone = false
}

resource "aws_security_group" "load_balancer_sg" {
  name        = "Load Balancer sg"
  description = "Security group for Load Balancer"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port        = 80
    to_port          = 80
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  ingress {
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "LoadBalancerSecurityGroup"
  }
}

resource "aws_kms_key" "secrets_key" {
  description             = "Secrets Manager Encryption Key"
  enable_key_rotation     = true
  rotation_period_in_days = 90
  //rotation_frequency      = "Every90Days"
  key_usage               = "ENCRYPT_DECRYPT"
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid : "EnableRootPermissions",
        Effect : "Allow",
        Principal : {
          AWS : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        },
        Action : "kms:*",
        Resource : "*"
      },
      {
        Sid : "AllowIAMRoleToUseKey",
        Effect : "Allow",
        Principal : {
          AWS : aws_iam_role.cloudwatch_agent_role.arn
        },
        Action : [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:DescribeKey"
        ],
        Resource : "*"
      },
      {
        Sid    = "AllowIAMRoleToUseKey"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.lambda_exec_role.arn
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid : "AllowSecretsManagerAccess",
        Effect : "Allow",
        Principal : {
          Service : "secretsmanager.amazonaws.com"
        },
        Action : [
          "kms:GenerateDataKey*",
          "kms:Decrypt"
        ],
        Resource : "*"
      }
    ]
  })


  tags = {
    Name = "Secrets Key"
  }
}

resource "random_password" "db_password" {
  length  = 16 # Adjust the length based on your requirements
  special = true
  upper   = true
  lower   = true
}

resource "aws_secretsmanager_secret" "db_password" {
  name        = var.db_password_secret_name
  description = "Database password for PostgreSQL"
  kms_key_id  = aws_kms_key.secrets_key.arn # Use Secrets Manager KMS Key

  tags = {
    Name = "DatabasePassword"
  }
}

resource "aws_secretsmanager_secret_version" "db_password_version" {
  secret_id     = aws_secretsmanager_secret.db_password.id
  secret_string = random_password.db_password.result
}

resource "aws_iam_policy" "secretsmanager_access_policy" {
  name        = "SecretsManagerAccessPolicy"
  description = "Policy to allow EC2 instance to access the csye6225-db-password secret"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = "secretsmanager:GetSecretValue",
        Resource = "${aws_secretsmanager_secret.db_password.arn}*" # Updated ARN
      },
      {
        Effect = "Allow",
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ],
        Resource = aws_kms_key.secrets_key.arn # KMS Key ARN
      }
    ]
  })
}


resource "aws_iam_role_policy_attachment" "attach_secretsmanager_policy" {
  policy_arn = aws_iam_policy.secretsmanager_access_policy.arn
  role       = aws_iam_role.cloudwatch_agent_role.name # Attach to your EC2 instance's IAM role
}

resource "aws_launch_template" "web_app_template" {
  name_prefix   = "csye6225_asg"
  image_id      = var.ami_id
  instance_type = var.instance_type
  key_name      = var.key_name
  ebs_optimized = true
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 25
      volume_type           = "gp2"
      delete_on_termination = true
      encrypted             = true
      kms_key_id            = aws_kms_key.ec2_key.arn
    }
  }
  iam_instance_profile {
    name = aws_iam_instance_profile.cloudwatch_agent_instance_profile.name
  }

  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.app_sg.id]
  }

  user_data = base64encode(<<-EOF
    #!/bin/bash
    set -e
    # Try retrieving secret with full details
    DB_PASSWORD=$(aws secretsmanager get-secret-value \
      --secret-id ${var.db_password_secret_name} \
      --query SecretString \
      --output text \
      --region us-east-1)
    # Database and S3 configuration
    DB_HOST="${aws_db_instance.db_instance.address}"
    DB_PORT="5432"
    DB_NAME="${var.database_name}"
    DB_USERNAME="${var.database_username}"
  
    S3_BUCKET_NAME="${aws_s3_bucket.web-bucket.bucket}"
    AWS_REGION="${var.aws_region}"
    SENDGRID_API_KEY="${var.SENDGRID_API_KEY}"
    SNS_TOPIC_ARN="${aws_sns_topic.user_verification.arn}"

    # Create .env file for the application
    cat > /home/csye6225/app/.env <<EOL
    PORT=8082
    DB_HOST=$DB_HOST
    DB_PORT=$DB_PORT
    DB_NAME=$DB_NAME
    DB_USERNAME=$DB_USERNAME
    DB_PASSWORD=$DB_PASSWORD
    S3_BUCKET_NAME=$S3_BUCKET_NAME
    AWS_REGION=$AWS_REGION
    SENDGRID_API_KEY=$SENDGRID_API_KEY
    SNS_TOPIC_ARN=$SNS_TOPIC_ARN
    EOL

    chown csye6225:csye6225 /home/csye6225/app/.env
    chmod 600 /home/csye6225/app/.env

    # sudo mkdir -p /home/csye6225/app/logs
    # sudo chown -R csye6225:csye6225 /home/csye6225/app/logs

    
    sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s
   
    sudo systemctl daemon-reload
    sudo systemctl restart webapp.service


    EOF
  )
}

resource "aws_autoscaling_group" "web_app_asg" {
  launch_template {
    id      = aws_launch_template.web_app_template.id
    version = "$Latest"
  }

  min_size            = 1
  max_size            = 1
  desired_capacity    = 1
  vpc_zone_identifier = aws_subnet.public[*].id
  target_group_arns   = [aws_lb_target_group.app_target_group.arn]
  tag {
    key                 = "Name"
    value               = "WebAppInstance"
    propagate_at_launch = true
  }

}


# CloudWatch Alarm for Scale Up
resource "aws_cloudwatch_metric_alarm" "cpu_scale_up" {
  alarm_name          = "cpu-scale-up-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Average"
  threshold           = var.up_threshold
  alarm_description   = "Alarm when CPU exceeds 5%"
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.web_app_asg.name
  }

  alarm_actions = [
    aws_autoscaling_policy.scale_up.arn
  ]
}

# CloudWatch Alarm for Scale Down
resource "aws_cloudwatch_metric_alarm" "cpu_scale_down" {
  alarm_name          = "cpu-scale-down-alarm"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Average"
  threshold           = var.down_threshold
  alarm_description   = "Alarm when CPU drops below 3%"
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.web_app_asg.name
  }

  alarm_actions = [
    aws_autoscaling_policy.scale_down.arn
  ]
}

# Scale Up Policy
resource "aws_autoscaling_policy" "scale_up" {
  name                   = "scale_up"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 60
  autoscaling_group_name = aws_autoscaling_group.web_app_asg.name
}

# Scale Down Policy
resource "aws_autoscaling_policy" "scale_down" {
  name                   = "scale_down"
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 60
  autoscaling_group_name = aws_autoscaling_group.web_app_asg.name
}

resource "aws_lb" "app_lb" {
  name               = "my-app-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.load_balancer_sg.id]
  subnets            = aws_subnet.public[*].id

  enable_deletion_protection = false

  tags = {
    Name = "MyAppLoadBalancer"
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.app_lb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app_target_group.arn
  }
}
data "aws_acm_certificate" "existing_demo_certificate" {
  domain      = "demo.cloudwebapp.me"
  most_recent = true
  statuses    = ["ISSUED"]
}
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.app_lb.arn
  port              = 443
  protocol          = "HTTPS"

  ssl_policy = "ELBSecurityPolicy-2016-08" # Choose the SSL Policy as per your security standards

  certificate_arn = data.aws_acm_certificate.existing_demo_certificate.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app_target_group.arn
  }
}

resource "aws_acm_certificate" "demo_certificate" {
  domain_name       = "demo.cloudwebapp.me"
  validation_method = "DNS"

  # Optional: specify your DNS validation record if needed, or ACM will manage it
  # validation_option {
  #   domain_name = "demo.cloudwebapp.me"
  #   validation_method = "DNS"
  #   resource_record {
  #     name = "_random_string.demo.cloudwebapp.me"
  #     type = "CNAME"
  #     value = "_random_string.acm-validations.aws"
  #   }
  # }

  tags = {
    Name = "DemoSSL"
  }
}

resource "aws_lb_target_group" "app_target_group" {
  name     = "my-app-target-group"
  port     = var.application_port
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check {
    path                = "/healthz"
    interval            = 30
    timeout             = 10
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
}

resource "aws_route53_record" "alias" {
  zone_id = data.aws_route53_zone.cloudwebapp.zone_id
  name    = "demo.cloudwebapp.me"
  type    = "A"
  alias {
    name                   = aws_lb.app_lb.dns_name
    zone_id                = aws_lb.app_lb.zone_id
    evaluate_target_health = true
  }
}

resource "aws_sns_topic" "user_verification" {
  name = "user-verification-topic"
}

resource "aws_iam_policy" "lambda_secrets_manager_policy" {
  name        = "LambdaSecretsManagerAccessPolicy"
  description = "Policy to allow Lambda to access SendGrid API key stored in Secrets Manager and use KMS for decryption"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = "secretsmanager:GetSecretValue",
        Resource = aws_secretsmanager_secret.email_service_credentials.arn
      },
      {
        Effect = "Allow",
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ],
        Resource = aws_kms_key.secrets_key.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_secrets_manager_attachment" {
  policy_arn = aws_iam_policy.lambda_secrets_manager_policy.arn
  role       = aws_iam_role.lambda_exec_role.name # Attach to the Lambda execution role
}

resource "aws_lambda_function" "user_verification_lambda" {
  function_name = "userVerificationFunction"
  runtime       = "nodejs16.x"
  handler       = "serverless/index.handler"
  role          = aws_iam_role.lambda_exec_role.arn
  filename      = var.lambda_code_path

  environment {
    variables = {
      SENDGRID_API_KEY_SECRET_NAME = var.sendgrid_secret_name
      WEB_APP_URL                  = var.webapp_url
    }
  }

  timeout     = 60
  memory_size = 150
}

resource "aws_iam_role" "lambda_exec_role" {
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Effect = "Allow"
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_policy" {
  name = "LambdaSnsPolicy"
  role = aws_iam_role.lambda_exec_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "sns:Publish"
        Resource = aws_sns_topic.user_verification.arn
        Effect   = "Allow"
      },
      {
        Action   = "ses:SendEmail"
        Resource = "*"
        Effect   = "Allow"
      }
    ]
  })
}

# resource "aws_lambda_event_source_mapping" "sns_lambda_trigger" {
#   event_source_arn = aws_sns_topic.user_verification.arn
#   function_name    = aws_lambda_function.user_verification_lambda.arn
#   enabled          = true
# }
resource "aws_sns_topic_subscription" "lambda" {
  topic_arn = aws_sns_topic.user_verification.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.user_verification_lambda.arn
}

resource "aws_lambda_permission" "with_sns" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.user_verification_lambda.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.user_verification.arn
}

resource "aws_iam_role" "sns_publish_role" {
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Effect = "Allow"
      }
    ]
  })
}

resource "aws_iam_policy" "sns_publish_policy" {
  name        = "SNSPublishPolicy"
  description = "Policy to publish messages to SNS topic"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "sns:Publish"
        Resource = aws_sns_topic.user_verification.arn # SNS Topic ARN
        Effect   = "Allow"
      }
    ]
  })
}

resource "aws_iam_policy_attachment" "sns_publish_attachment" {
  name       = "sns-policy-attachment"
  roles      = [aws_iam_role.sns_publish_role.name]
  policy_arn = aws_iam_policy.sns_publish_policy.arn
}

resource "aws_iam_policy_attachment" "sns_publish_attachment_1" {
  name       = "sns-policy-attachment_1"
  roles      = [aws_iam_role.cloudwatch_agent_role.name]
  policy_arn = aws_iam_policy.sns_publish_policy.arn
}
resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}



resource "aws_kms_key" "ec2_key" {
  description             = "EC2 Encryption Key"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  rotation_period_in_days = 90

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable full key management for root account"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow key usage for EC2 service"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        }, {
        Sid    = "Allow Autoscaling Service Access"
        Effect = "Allow"
        Principal = {
          Service = "autoscaling.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        }, {
        Sid    = "Allow key usage for EC2 service"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/CloudWatchAgentRole"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        }, {
        Sid    = "Allow service-linked role use of the customer managed key",
        Effect = "Allow",
        Principal = {
          AWS = [
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
          ]
        },
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        Resource = "*"
      },
      {
        Sid    = "Allow attachment of persistent resources",
        Effect = "Allow",
        Principal = {
          AWS = [
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
          ]
        },
        Action = [
          "kms:CreateGrant"
        ],
        Resource = "*",
        Condition = {
          Bool = {
            "kms:GrantIsForAWSResource" : true
          }
        }
      }
    ]
  })

  tags = {
    Name = "EC2 Volume Encryption Key"
  }
}

# Add this to get current account ID
data "aws_caller_identity" "current" {}

resource "aws_iam_policy" "kms_access_policy" {
  name        = "KMSAccessPolicy"
  description = "Policy for accessing KMS key for EBS decryption"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        Resource = aws_kms_key.ec2_key.arn # Replace with your actual KMS key ARN
      }
    ]
  })
}

resource "aws_iam_policy_attachment" "kms_policy_attachment" {
  name       = "kms-policy-attachment"
  roles      = [aws_iam_role.cloudwatch_agent_role.name]
  policy_arn = aws_iam_policy.kms_access_policy.arn
}


resource "aws_kms_key" "rds_key" {
  description             = "RDS Encryption Key"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  rotation_period_in_days = 90

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow RDS to use the key"
        Effect = "Allow"
        Principal = {
          Service = "rds.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow CloudWatch Agent Role to use the key"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.cloudwatch_agent_role.arn
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "RDS Key"
  }
}

resource "aws_kms_key" "s3_key" {
  description             = "S3 Encryption Key"
  enable_key_rotation     = true
  rotation_period_in_days = 90
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow S3 to use the key"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow CloudWatch Agent Role to use the key"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.cloudwatch_agent_role.arn
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "S3 Key"
  }
}




resource "aws_secretsmanager_secret" "email_service_credentials" {
  name        = var.sendgrid_secret_name
  description = "SendGrid API key for email service"
  kms_key_id  = aws_kms_key.secrets_key.arn # Use Secrets Manager KMS Key

  tags = {
    Name = "SendGridAPIKey"
  }
}

resource "aws_secretsmanager_secret_version" "email_service_credentials_version" {
  secret_id = aws_secretsmanager_secret.email_service_credentials.id
  secret_string = jsonencode({
    api_key = var.SENDGRID_API_KEY
  })
}
