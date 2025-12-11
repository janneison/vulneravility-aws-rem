terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  description = "AWS region to deploy the remediation lambda."
  type        = string
  default     = "us-east-1"
}

variable "lambda_name" {
  description = "Name of the remediation lambda function."
  type        = string
  default     = "security-hub-remediator"
}

variable "default_min_capacity" {
  description = "Minimum provisioned capacity for DynamoDB autoscaling targets."
  type        = number
  default     = 1
}

variable "default_max_capacity" {
  description = "Maximum provisioned capacity for DynamoDB autoscaling targets."
  type        = number
  default     = 50
}

variable "dynamodb_scaling_role_arn" {
  description = "(Optional) IAM role ARN for DynamoDB Application Auto Scaling."
  type        = string
  default     = ""
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda"
  output_path = "${path.module}/build/lambda.zip"
}

resource "aws_iam_role" "lambda_exec" {
  name               = "${var.lambda_name}-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy" "lambda_policy" {
  name   = "${var.lambda_name}-policy"
  role   = aws_iam_role.lambda_exec.id
  policy = data.aws_iam_policy_document.lambda_permissions.json
}

resource "aws_lambda_function" "remediator" {
  function_name = var.lambda_name
  filename      = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  role              = aws_iam_role.lambda_exec.arn
  handler           = "lambda_function.lambda_handler"
  runtime           = "python3.12"

  environment {
    variables = {
      DEFAULT_MIN_CAPACITY = tostring(var.default_min_capacity)
      DEFAULT_MAX_CAPACITY = tostring(var.default_max_capacity)
      DYNAMODB_SCALING_ROLE = var.dynamodb_scaling_role_arn
    }
  }

  depends_on = [aws_iam_role_policy.lambda_policy]
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "lambda_permissions" {
  statement {
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["arn:aws:logs:*:*:*"]
  }

  statement {
    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:UpdateTable",
      "dynamodb:UpdateContinuousBackups"
    ]
    resources = ["*"]
  }

  statement {
    actions = [
      "application-autoscaling:RegisterScalableTarget",
      "application-autoscaling:PutScalingPolicy"
    ]
    resources = ["*"]
  }

  statement {
    actions   = ["sns:GetTopicAttributes", "sns:SetTopicAttributes"]
    resources = ["*"]
  }

  statement {
    actions   = ["sqs:GetQueueAttributes", "sqs:SetQueueAttributes"]
    resources = ["*"]
  }

  statement {
    actions   = ["kms:GetKeyPolicy", "kms:PutKeyPolicy"]
    resources = ["*"]
  }

  dynamic "statement" {
    for_each = length(var.dynamodb_scaling_role_arn) > 0 ? [1] : []
    content {
      actions   = ["iam:PassRole"]
      resources = [var.dynamodb_scaling_role_arn]
      conditions {
        test     = "StringEquals"
        variable = "iam:PassedToService"
        values   = ["application-autoscaling.amazonaws.com"]
      }
    }
  }
}

output "lambda_function_name" {
  value = aws_lambda_function.remediator.function_name
}
