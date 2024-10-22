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

  # egress {
  #   from_port   = 5432
  #   to_port     = 5432
  #   protocol    = "tcp"
  #   security_groups = [aws_security_group.database_sg.id]
  # }

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
  db_name                = "csye6225"
  username               = "csye6225"
  password               = "dbpassword1234"
  skip_final_snapshot    = true
}

resource "aws_instance" "Webapp_Instance" {
  ami                     = var.ami_id
  instance_type           = var.instance_type
  key_name                = var.key_name
  vpc_security_group_ids  = [aws_security_group.app_sg.id]
  subnet_id               = aws_subnet.public[0].id
  disable_api_termination = false

  root_block_device {
    volume_size           = 25
    volume_type           = "gp2"
    delete_on_termination = true
  }

  ebs_optimized = true

  user_data = <<-EOF
    #!/bin/bash
    set -e

    # Database configuration passed via Terraform variables
    DB_HOST="${aws_db_instance.db_instance.address}" 
    DB_PORT="5432" 
    DB_NAME="${var.database_name}"
    DB_USERNAME="${var.database_username}"
    DB_PASSWORD="${var.database_password}"


    if [ -f /home/csye6225/app/.env ]; then
      echo ".env file created successfully"
    else
      echo "Error: .env file not created!"
      exit 1
    fi
    
    # Update the .env file for the web application
    cat > /home/csye6225/app/.env <<EOF2
    PORT=8082
    DB_HOST=$DB_HOST
    DB_PORT=$DB_PORT
    DB_NAME=$DB_NAME
    DB_USERNAME=$DB_USERNAME
    DB_PASSWORD=$DB_PASSWORD
    EOF2
    # Set correct permissions for .env file
    chown csye6225:csye6225 /home/csye6225/app/.env
    chmod 600 /home/csye6225/app/.env

    # Reload systemd to pick up changes
    systemctl daemon-reload

    # Restart the web application service to load the updated environment variables
    systemctl restart webapp.service
  EOF

  tags = {
    Name = "${var.environment}-webapp-instance"
  }
}








