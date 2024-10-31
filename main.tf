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
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.cidr_blocks
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.cidr_blocks
  }

  ingress {
    from_port   = var.application_port
    to_port     = var.application_port
    protocol    = "tcp"
    cidr_blocks = var.cidr_blocks
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


resource "aws_instance" "Webapp_Instance" {
  ami                     = var.ami_id
  instance_type           = var.instance_type
  key_name                = var.key_name
  vpc_security_group_ids  = [aws_security_group.app_sg.id]
  subnet_id               = aws_subnet.public[0].id
  disable_api_termination = false
  iam_instance_profile    = aws_iam_instance_profile.cloudwatch_agent_instance_profile.name

  root_block_device {
    volume_size           = 25
    volume_type           = "gp2"
    delete_on_termination = true
  }

  ebs_optimized = true
  user_data     = <<-EOF
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
    EOL

    chown csye6225:csye6225 /home/csye6225/app/.env
    chmod 600 /home/csye6225/app/.env

    # sudo mkdir -p /home/csye6225/app/logs
    # sudo chown -R csye6225:csye6225 /home/csye6225/app/logs

    
    sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s
   
    sudo systemctl daemon-reload
    sudo systemctl restart webapp.service


    EOF

  tags = {
    Name = "${var.environment}-webapp-instance"
  }
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

# resource "aws_route53_record" "app_a_record" {
#   zone_id = aws_route53_zone.cloudwebapp.zone_id
#   name    = "cloudwebapp.me" 
#   type    = "A"
#   ttl     = 300
#   records = [aws_instance.Webapp_Instance.public_ip] 

# }

data "aws_route53_zone" "cloudwebapp" {
  name         = "demo.cloudwebapp.me"
  private_zone = false
}


# resource "aws_route53_record" "dev_a_record" {
#   zone_id = data.aws_route53_zone.cloudwebapp.zone_id
#   name    = "dev.cloudwebapp.me"
#   type    = "A"
#   ttl     = 300
#   records = [aws_instance.Webapp_Instance.public_ip]
# }


resource "aws_route53_record" "demo_a_record" {
  zone_id = data.aws_route53_zone.cloudwebapp.zone_id
  name    = "demo.cloudwebapp.me"
  type    = "A"
  ttl     = 300
  records = [aws_instance.Webapp_Instance.public_ip]
}










