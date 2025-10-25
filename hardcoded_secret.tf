resource "aws_s3_bucket" "secret_bucket" {
  bucket = "my-secret-bucket"
}

resource "aws_iam_access_key" "bad_key" {
  user    = "example-user"
  pgp_key = "keybase:someone"
  # ❌ Hardcoded credentials; should use Secrets Manager or environment variables
}