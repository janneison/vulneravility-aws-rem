import json
import os
from typing import Any, Dict, List, Optional

import boto3
from botocore.config import Config

CONFIG = Config(retries={"max_attempts": 5, "mode": "standard"})
dynamodb = boto3.client("dynamodb", config=CONFIG)
autoscaling = boto3.client("application-autoscaling", config=CONFIG)
sns = boto3.client("sns", config=CONFIG)
sqs = boto3.client("sqs", config=CONFIG)
sts = boto3.client("sts", config=CONFIG)
kms = boto3.client("kms", config=CONFIG)

DEFAULT_MIN_CAPACITY = int(os.getenv("DEFAULT_MIN_CAPACITY", "1"))
DEFAULT_MAX_CAPACITY = int(os.getenv("DEFAULT_MAX_CAPACITY", "50"))
DYNAMODB_SCALING_ROLE = os.getenv("DYNAMODB_SCALING_ROLE", "")


class RemediationError(Exception):
    pass


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Entry point for Security Hub event remediation.

    The function expects Security Hub findings with control IDs such as
    DynamoDB.1, DynamoDB.2, DynamoDB.6, SNS.4, SQS.3, and KMS.5. For each
    supported finding, it applies a best-effort remediation.
    """

    account_id = sts.get_caller_identity()["Account"]
    results = []

    findings = _extract_findings(event)
    for finding in findings:
        control_id = finding.get("Compliance", {}).get("SecurityControlId")
        resource = _get_primary_resource(finding)
        if not control_id or not resource:
            continue

        try:
            if control_id == "DynamoDB.1" and resource["Type"] == "AwsDynamoDbTable":
                results.append(_remediate_dynamodb_autoscaling(resource))
            elif control_id == "DynamoDB.2" and resource["Type"] == "AwsDynamoDbTable":
                results.append(_enable_pitr(resource))
            elif control_id == "DynamoDB.6" and resource["Type"] == "AwsDynamoDbTable":
                results.append(_enable_deletion_protection(resource))
            elif control_id == "SNS.4" and resource["Type"] == "AwsSnsTopic":
                results.append(_harden_sns_policy(resource, account_id))
            elif control_id == "SQS.3" and resource["Type"] == "AwsSqsQueue":
                results.append(_harden_sqs_policy(resource, account_id))
            elif control_id == "KMS.5" and resource["Type"] == "AwsKmsKey":
                results.append(_harden_kms_policy(resource, account_id))
        except Exception as exc:  # noqa: BLE001
            results.append({"resource": resource.get("Id"), "status": "FAILED", "error": str(exc)})

    return {"remediationResults": results}


def _extract_findings(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Pull the findings list from a Security Hub event."""

    detail = event.get("detail") or {}
    findings = detail.get("findings")
    if isinstance(findings, list):
        return findings
    return []


def _get_primary_resource(finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    resources = finding.get("Resources", [])
    if resources:
        return resources[0]
    return None


def _remediate_dynamodb_autoscaling(resource: Dict[str, Any]) -> Dict[str, Any]:
    table_name = resource.get("Id", "").split("table/")[-1]
    if not table_name:
        raise RemediationError("Missing DynamoDB table name")

    description = dynamodb.describe_table(TableName=table_name)["Table"]
    billing_mode = description.get("BillingModeSummary", {}).get("BillingMode", "PROVISIONED")

    if billing_mode == "PAY_PER_REQUEST":
        return {"resource": table_name, "status": "SKIPPED", "reason": "On-demand billing already enabled"}

    _ensure_provisioned_throughput(description, table_name)
    _configure_autoscaling(table_name)
    return {"resource": table_name, "status": "UPDATED", "action": "Enabled autoscaling"}


def _ensure_provisioned_throughput(description: Dict[str, Any], table_name: str) -> None:
    provisioned = description.get("ProvisionedThroughput", {})
    read = max(DEFAULT_MIN_CAPACITY, int(provisioned.get("ReadCapacityUnits", 5)))
    write = max(DEFAULT_MIN_CAPACITY, int(provisioned.get("WriteCapacityUnits", 5)))

    dynamodb.update_table(
        TableName=table_name,
        ProvisionedThroughput={"ReadCapacityUnits": read, "WriteCapacityUnits": write},
    )


def _configure_autoscaling(table_name: str) -> None:
    resource_id = f"table/{table_name}"
    for dimension in ("ReadCapacityUnits", "WriteCapacityUnits"):
        autoscaling.register_scalable_target(
            ServiceNamespace="dynamodb",
            ResourceId=resource_id,
            ScalableDimension=f"dynamodb:table:{dimension}",
            MinCapacity=DEFAULT_MIN_CAPACITY,
            MaxCapacity=DEFAULT_MAX_CAPACITY,
            RoleARN=DYNAMODB_SCALING_ROLE or None,
        )

        autoscaling.put_scaling_policy(
            ServiceNamespace="dynamodb",
            ResourceId=resource_id,
            ScalableDimension=f"dynamodb:table:{dimension}",
            PolicyName=f"{table_name}-{dimension}-target-tracking",
            PolicyType="TargetTrackingScaling",
            TargetTrackingScalingPolicyConfiguration={
                "TargetValue": 70.0,
                "PredefinedMetricSpecification": {
                    "PredefinedMetricType": "DynamoDBReadCapacityUtilization"
                    if dimension == "ReadCapacityUnits"
                    else "DynamoDBWriteCapacityUtilization"
                },
                "ScaleInCooldown": 60,
                "ScaleOutCooldown": 60,
            },
        )


def _enable_pitr(resource: Dict[str, Any]) -> Dict[str, Any]:
    table_name = resource.get("Id", "").split("table/")[-1]
    if not table_name:
        raise RemediationError("Missing DynamoDB table name")

    dynamodb.update_continuous_backups(TableName=table_name, PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True})
    return {"resource": table_name, "status": "UPDATED", "action": "Enabled PITR"}


def _enable_deletion_protection(resource: Dict[str, Any]) -> Dict[str, Any]:
    table_name = resource.get("Id", "").split("table/")[-1]
    if not table_name:
        raise RemediationError("Missing DynamoDB table name")

    dynamodb.update_table(TableName=table_name, DeletionProtectionEnabled=True)
    return {"resource": table_name, "status": "UPDATED", "action": "Enabled deletion protection"}


def _harden_sns_policy(resource: Dict[str, Any], account_id: str) -> Dict[str, Any]:
    topic_arn = resource.get("Id")
    if not topic_arn:
        raise RemediationError("Missing SNS topic ARN")

    policy = _get_json_attribute(sns.get_topic_attributes(TopicArn=topic_arn), "Attributes", "Policy")
    updated_policy = _remove_public_access(policy, account_id)
    sns.set_topic_attributes(TopicArn=topic_arn, AttributeName="Policy", AttributeValue=json.dumps(updated_policy))
    return {"resource": topic_arn, "status": "UPDATED", "action": "Restricted SNS policy"}


def _harden_sqs_policy(resource: Dict[str, Any], account_id: str) -> Dict[str, Any]:
    queue_url = resource.get("Id")
    if not queue_url:
        raise RemediationError("Missing SQS queue URL")

    attributes = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["Policy"]) or {}
    policy = json.loads(attributes.get("Attributes", {}).get("Policy", "{}"))
    updated_policy = _remove_public_access(policy, account_id)
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(updated_policy)})
    return {"resource": queue_url, "status": "UPDATED", "action": "Restricted SQS policy"}


def _harden_kms_policy(resource: Dict[str, Any], account_id: str) -> Dict[str, Any]:
    key_arn = resource.get("Id")
    if not key_arn:
        raise RemediationError("Missing KMS key ARN")

    policy_response = kms.get_key_policy(KeyId=key_arn, PolicyName="default")
    policy = json.loads(policy_response.get("Policy", "{}"))
    updated_policy = _remove_public_access(policy, account_id)
    kms.put_key_policy(KeyId=key_arn, PolicyName="default", Policy=json.dumps(updated_policy))
    return {"resource": key_arn, "status": "UPDATED", "action": "Restricted KMS key policy"}


def _get_json_attribute(response: Dict[str, Any], outer_key: str, inner_key: str) -> Dict[str, Any]:
    container = response.get(outer_key, {}) if response else {}
    return json.loads(container.get(inner_key, "{}"))


def _remove_public_access(policy: Dict[str, Any], account_id: str) -> Dict[str, Any]:
    if not policy:
        return policy

    statements = policy.get("Statement", [])
    account_arn = f"arn:aws:iam::{account_id}:root"

    for statement in statements:
        principal = statement.get("Principal")
        if principal in ("*", {"AWS": "*"}):
            statement["Principal"] = {"AWS": account_arn}
        elif isinstance(principal, dict):
            aws_principal = principal.get("AWS")
            if aws_principal == "*":
                statement["Principal"]["AWS"] = account_arn

        condition = statement.get("Condition", {})
        if "IpAddress" in condition or "NotIpAddress" in condition:
            # IP-based allow rules are also considered public
            statement["Principal"] = {"AWS": account_arn}
            statement.pop("Condition", None)

    policy["Statement"] = statements
    return policy
