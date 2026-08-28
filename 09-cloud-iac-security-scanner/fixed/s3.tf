resource "aws_s3_bucket" "reports" {
  bucket = "meridian-quarterly-reports"
  acl    = "private"

  versioning {
    enabled = true
  }
}
