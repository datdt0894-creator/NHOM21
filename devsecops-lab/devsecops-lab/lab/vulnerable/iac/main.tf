# CẢNH BÁO: IaC chứa cấu hình sai CÓ CHỦ ĐÍCH. Không apply lên môi trường thật.
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "ap-southeast-1"
}

# [SEED-08] Security group mở SSH và toàn bộ cổng cho 0.0.0.0/0
resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "web"
  vpc_id      = "vpc-0123456789abcdef0"

  ingress {
    description = "ssh"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "all"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# [SEED-09] S3 public-read, không mã hoá, không block public access
resource "aws_s3_bucket" "data" {
  bucket = "lab-data-bucket-demo"
}

resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"
}

# [SEED-10] IAM quyền quá mức Action:* Resource:*
resource "aws_iam_policy" "admin" {
  name = "app-admin"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# [SEED-11] RDS public, không mã hoá, mật khẩu hard-code
resource "aws_db_instance" "db" {
  identifier           = "lab-db"
  engine               = "postgres"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "admin"
  password             = "admin12345"
  publicly_accessible  = true
  storage_encrypted    = false
  skip_final_snapshot  = true
}
