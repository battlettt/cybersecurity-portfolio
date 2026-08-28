resource "aws_s3_bucket" "reports" {
  bucket = "meridian-quarterly-reports"
  acl    = "public-read"

  versioning {
    enabled = false
  }
}
