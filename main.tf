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
  password               = var.database_password
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

resource "random_uuid" "web_bucket" {}

resource "aws_s3_bucket_server_side_encryption_configuration" "web-bucket_sse" {
  bucket = aws_s3_bucket.web-bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

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
    }
  }
  iam_instance_profile {
    name = aws_iam_instance_profile.cloudwatch_agent_instance_profile.name # Removed quotes
  }

  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.app_sg.id]
  }

  user_data = base64encode(<<-EOF
    #!/bin/bash
    set -e

    # Database and S3 configuration
    DB_HOST="${aws_db_instance.db_instance.address}"
    DB_PORT="5432"
    DB_NAME="${var.database_name}"
    DB_USERNAME="${var.database_username}"
    DB_PASSWORD="${var.database_password}"
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

  min_size            = 3
  max_size            = 5
  desired_capacity    = 3
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

resource "aws_lambda_function" "user_verification_lambda" {
  function_name = "userVerificationFunction"
  runtime       = "nodejs16.x"
  handler       = "lamda_workspace/index.handler"
  role          = aws_iam_role.lambda_exec_role.arn
  filename      = var.lambda_code_path

  environment {
    variables = {
      SENDGRID_API_KEY = var.SENDGRID_API_KEY
      WEB_APP_URL      = var.webapp_url
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




















