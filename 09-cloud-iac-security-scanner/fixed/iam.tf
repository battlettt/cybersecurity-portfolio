resource "aws_iam_policy" "deploy_bot" {
  name = "deploy-bot-policy"

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ecs:UpdateService",
        "ecs:DescribeServices"
      ],
      "Resource": "arn:aws:ecs:us-east-1:123456789012:service/meridian-cluster/*"
    }
  ]
}
POLICY
}
