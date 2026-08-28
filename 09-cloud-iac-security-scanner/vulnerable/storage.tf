resource "aws_db_instance" "prod" {
  identifier        = "meridian-prod-db"
  engine            = "postgres"
  instance_class    = "db.t3.medium"
  storage_encrypted = false
}

resource "aws_ebs_volume" "app_data" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false
}
