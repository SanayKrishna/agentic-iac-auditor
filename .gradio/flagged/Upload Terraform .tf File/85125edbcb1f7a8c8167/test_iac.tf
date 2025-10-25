resource "aws_s3_bucket" "my_bucket" {
  bucket = "my-insecure-project-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "web_sg" {
  name        = "web-server-sg"
  description = "Allow HTTP and SSH traffic"
  
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}