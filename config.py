import boto3

AWS_ACCESS_KEY_ID     = "AKIAV2J4G5C6LF4PCA4P"
AWS_SECRET_ACCESS_KEY = ""
AWS_REGION            = "ap-south-1"

s3 = boto3.client(
    "s3",
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY
)
