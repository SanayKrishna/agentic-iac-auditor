resource "aws_db_instance" "public_rds" {
  allocated_storage    = 20
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.micro"
  name                 = "publicdb"
  username             = "admin"
  password             = "password123"  # ❌ Hardcoded password
  publicly_accessible  = true           # ❌ Public access
}