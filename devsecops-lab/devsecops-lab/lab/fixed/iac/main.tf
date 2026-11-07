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

variable "kms_key_arn" {
  type    = string
  default = "arn:aws:kms:ap-southeast-1:111122223333:key/00000000-0000-0000-0000-000000000000"
}

variable "db_password" {
  type      = string
  sensitive = true
}

resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "HTTPS from internal network only"
  vpc_id      = "vpc-0123456789abcdef0"

  ingress {
    description = "https internal"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
  egress {
    description = "https out to internal"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}

resource "aws_s3_bucket" "data" {
  bucket = "lab-data-bucket-demo"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
  }
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_iam_policy" "app" {
  name = "app-least-privilege"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject"]
      Resource = "${aws_s3_bucket.data.arn}/*"
    }]
  })
}

resource "aws_db_instance" "db" {
  identifier                          = "lab-db"
  engine                              = "postgres"
  instance_class                      = "db.t3.micro"
  allocated_storage                   = 20
  username                            = "app"
  password                            = var.db_password
  publicly_accessible                 = false
  storage_encrypted                   = true
  kms_key_id                          = var.kms_key_arn
  iam_database_authentication_enabled = true
  backup_retention_period             = 7
  auto_minor_version_upgrade          = true
  copy_tags_to_snapshot               = true
  deletion_protection                 = true
  skip_final_snapshot                 = true
}
