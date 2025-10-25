# 1. Public S3 bucket
resource "aws_s3_bucket" "my_bucket" {
  bucket = "my-insecure-project-bucket"
  acl    = "public-read"
}

# 2. Security group open to the world
resource "aws_security_group" "web_sg" {
  name        = "web-server-sg"
  description = "Allow HTTP and SSH traffic"

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
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 3. Weak TLS policy
resource "aws_lb_listener" "http_listener" {
  load_balancer_arn = aws_lb.my_lb.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-0-2015-04"
  certificate_arn   = "arn:aws:acm:region:account:certificate/abc123"
}

# 4. Hardcoded AWS credentials
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAEXAMPLEACCESSKEY"
  secret_key = "secret1234examplekey"
}

# 5. S3 bucket without encryption
resource "aws_s3_bucket" "unencrypted_bucket" {
  bucket = "my-unencrypted-bucket"
  acl    = "private"
  # No server-side encryption configuration
}
