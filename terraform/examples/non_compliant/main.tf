terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  description = "Región donde se crean los recursos no conformes para pruebas."
  type        = string
  default     = "us-east-1"
}

data "aws_caller_identity" "current" {}

resource "aws_dynamodb_table" "provisioned_no_pitr" {
  name         = "noncompliant-provisioned"
  billing_mode = "PROVISIONED"

  read_capacity  = 1
  write_capacity = 1

  attribute {
    name = "id"
    type = "S"
  }

  hash_key = "id"

  point_in_time_recovery {
    enabled = false
  }

  deletion_protection_enabled = false

  tags = {
    Purpose = "NonCompliant-DynamoDB"
  }
}

resource "aws_sns_topic" "public" {
  name = "noncompliant-public-topic"
}

resource "aws_sns_topic_policy" "public" {
  arn    = aws_sns_topic.public.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicPublishSubscribe"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["SNS:Subscribe", "SNS:Publish"]
        Resource  = aws_sns_topic.public.arn
      }
    ]
  })
}

resource "aws_sqs_queue" "public" {
  name = "noncompliant-public-queue"
}

resource "aws_sqs_queue_policy" "public" {
  queue_url = aws_sqs_queue.public.id
  policy    = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicSendReceive"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["SQS:SendMessage", "SQS:ReceiveMessage"]
        Resource  = aws_sqs_queue.public.arn
      }
    ]
  })
}

resource "aws_kms_key" "public_policy" {
  description = "Llave KMS con política pública para prueba de remediación"
  policy      = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowRoot"
        Effect   = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid      = "PublicEncrypt"
        Effect   = "Allow"
        Principal = {
          AWS = "*"
        }
        Action   = "kms:Encrypt"
        Resource = "*"
      }
    ]
  })
}

output "dynamodb_table_name" {
  value = aws_dynamodb_table.provisioned_no_pitr.name
}

output "sns_topic_arn" {
  value = aws_sns_topic.public.arn
}

output "sqs_queue_arn" {
  value = aws_sqs_queue.public.arn
}

output "kms_key_id" {
  value = aws_kms_key.public_policy.key_id
}
