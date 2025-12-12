# main.tf
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "eu-north-1"
}

# Get latest Ubuntu 22.04 AMI
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]  # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

# Get availability zone
data "aws_availability_zones" "available" {
  state = "available"
}

# Security group for SSH
resource "aws_security_group" "ssh_access" {
  name        = "allow_ssh"
  description = "Allow SSH inbound traffic"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Change to your IP for better security
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Persistent EBS volume
resource "aws_ebs_volume" "data" {
  availability_zone = data.aws_availability_zones.available.names[0]
  size              = 30  # Size in GB
  type              = "gp3"

  tags = {
    Name = "net-watcher-data-volume"
  }
}

# EC2 instance
resource "aws_instance" "server" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.large"
  key_name      = "net-watcher-access"
  availability_zone = data.aws_availability_zones.available.names[0]

  vpc_security_group_ids = [aws_security_group.ssh_access.id]

  user_data = <<-EOF
              #!/bin/bash
              # Wait for the volume to be attached
              while [ ! -e /dev/nvme1n1 ]; do
                sleep 1
              done
              
              # Check if volume has a filesystem, if not create one
              if ! blkid /dev/nvme1n1; then
                mkfs.ext4 /dev/nvme1n1
              fi
              
              # Create mount point
              mkdir -p /data
              
              # Mount the volume
              mount /dev/nvme1n1 /data
              
              # Add to fstab for automatic mounting on reboot
              UUID=$(blkid -s UUID -o value /dev/nvme1n1)
              echo "UUID=$UUID /data ext4 defaults,nofail 0 2" >> /etc/fstab
              
              # Set permissions and ownership
              chmod 755 /data
              chown ubuntu:ubuntu /data
              EOF

  tags = {
    Name = "net-watcher-testing-instance"
  }
}

# Attach EBS volume to instance
resource "aws_volume_attachment" "data_attachment" {
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.data.id
  instance_id = aws_instance.server.id
}

# -- EC2 instance scheduling (stop/start) --
# Lambda execution role
resource "aws_iam_role" "lambda_role" {
  name = "ec2-scheduler-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy" "lambda_policy" {
  name = "ec2-scheduler-lambda-policy"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:StartInstances",
          "ec2:StopInstances"
        ]
        Resource = aws_instance.server.arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# Lambda function to stop instance
resource "aws_lambda_function" "stop_instance" {
  filename      = "suspend_resume.zip"
  function_name = "stop-ec2-instance"
  role          = aws_iam_role.lambda_role.arn
  handler       = "suspend_resume.handler"
  runtime       = "python3.11"
  source_code_hash = filebase64sha256("suspend_resume.zip")

  environment {
    variables = {
      INSTANCE_ID = aws_instance.server.id
    }
  }
}

# Lambda function to start instance
resource "aws_lambda_function" "start_instance" {
  filename      = "suspend_resume.zip"
  function_name = "start-ec2-instance"
  role          = aws_iam_role.lambda_role.arn
  handler       = "suspend_resume.handler"
  runtime       = "python3.11"
  source_code_hash = filebase64sha256("suspend_resume.zip")

  environment {
    variables = {
      INSTANCE_ID = aws_instance.server.id
      ACTION      = "start"
    }
  }
}

# EventBridge rule to stop instance
resource "aws_cloudwatch_event_rule" "stop_instance" {
  name                = "stop-instance"
  schedule_expression = "cron(0 21 * * ? *)"
}

resource "aws_cloudwatch_event_target" "stop_instance" {
  rule      = aws_cloudwatch_event_rule.stop_instance.name
  target_id = "StopInstance"
  arn       = aws_lambda_function.stop_instance.arn
}

resource "aws_lambda_permission" "allow_eventbridge_stop" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.stop_instance.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.stop_instance.arn
}

# EventBridge rule to start instance
resource "aws_cloudwatch_event_rule" "start_instance" {
  name                = "start-instance"
  schedule_expression = "cron(0 9 * * ? *)"
}

resource "aws_cloudwatch_event_target" "start_instance" {
  rule      = aws_cloudwatch_event_rule.start_instance.name
  target_id = "StartInstance"
  arn       = aws_lambda_function.start_instance.arn
}

resource "aws_lambda_permission" "allow_eventbridge_start" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.start_instance.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.start_instance.arn
}

# -- Elastic IP (static public IP) --
resource "aws_eip" "server_ip" {
  instance = aws_instance.server.id
  domain   = "vpc"

  tags = {
    Name = "net-watcher-access-elastic-ip"
  }
}

# -- Periodic EBS backup (snapshot) --

# Data Lifecycle Manager (DLM) service role
resource "aws_iam_role" "dlm_lifecycle_role" {
  name = "dlm-lifecycle-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "dlm.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy" "dlm_lifecycle_policy" {
  name = "dlm-lifecycle-policy"
  role = aws_iam_role.dlm_lifecycle_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateSnapshot",
          "ec2:CreateSnapshots",
          "ec2:DeleteSnapshot",
          "ec2:DescribeInstances",
          "ec2:DescribeVolumes",
          "ec2:DescribeSnapshots"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateTags"
        ]
        Resource = "arn:aws:ec2:*::snapshot/*"
      }
    ]
  })
}

# DLM Lifecycle Policy for daily backups
resource "aws_dlm_lifecycle_policy" "ebs_backup" {
  description        = "Daily EBS backup policy - keep 5 snapshots"
  execution_role_arn = aws_iam_role.dlm_lifecycle_role.arn
  state              = "ENABLED"

  policy_details {
    resource_types = ["VOLUME"]

    schedule {
      name = "Daily snapshots"

      create_rule {
        interval      = 24
        interval_unit = "HOURS"
        times         = ["03:00"]  # 3 AM UTC - adjust as needed
      }

      retain_rule {
        count = 5  # Keep only 5 most recent snapshots
      }

      tags_to_add = {
        SnapshotType = "DLM-Automated"
      }

      copy_tags = true
    }

    target_tags = {
      Name = "net-watcher-data-volume"  # Must match your EBS volume tag
    }
  }
}

# -- Outputs --
output "instance_ip" {
  value = aws_eip.server_ip.public_ip
  description = "Static Elastic IP address"
}

output "volume_id" {
  value = aws_ebs_volume.data.id
}

output "mount_point" {
  value = "/data"
  description = "Path where the persistent volume is mounted"
}

# ssh -i <path>\net-watcher-access.pem ubuntu@<INSTANCE_IP>