// iam_and_storage.tf
resource "aws_iam_policy" "wide_open_policy" {
  name        = "wide-open-policy"
  description = "Dangerously permissive policy"

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "*",
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
POLICY
}

resource "aws_s3_bucket" "no_encryption" {
  bucket = "no-encrypt-bucket"
  acl    = "private"
  # No server-side encryption block defined
}

resource "aws_ebs_volume" "unenc_volume" {
  availability_zone = "us-east-1a"
  size              = 20
  # No encrypted = true provided => unencrypted volume
}
