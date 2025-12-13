Feature: Security compliance for Talos Kubernetes Cluster
  As a security engineer
  I want to ensure the cluster follows security best practices
  So that the Kubernetes infrastructure is secure

  Scenario: S3 buckets must have versioning enabled for disaster recovery
    Given I have aws_s3_bucket_versioning defined
    Then it must have versioning_configuration
    And its versioning_configuration must have status
    And its status must be Enabled

  Scenario: S3 buckets must block public access
    Given I have aws_s3_bucket_public_access_block defined
    Then it must have block_public_acls
    And its block_public_acls must be true
    And it must have block_public_policy
    And its block_public_policy must be true
    And it must have ignore_public_acls
    And its ignore_public_acls must be true
    And it must have restrict_public_buckets
    And its restrict_public_buckets must be true

  Scenario: S3 buckets must have encryption enabled
    Given I have aws_s3_bucket_server_side_encryption_configuration defined
    Then it must have rule

  Scenario: Security groups must not allow unrestricted SSH access
    Given I have aws_security_group defined
    When it has ingress
    When its from_port is 22
    Then it must not have cidr_blocks containing ["0.0.0.0/0"]

  Scenario: Security groups must not allow unrestricted access to Kubernetes API
    Given I have aws_security_group defined
    When it has ingress
    When its from_port is 6443
    Then it must not have cidr_blocks containing ["0.0.0.0/0"]

  Scenario: IAM roles must have trust relationships defined
    Given I have aws_iam_role defined
    Then it must have assume_role_policy

  Scenario: IAM policies must be attached to roles
    Given I have aws_iam_role_policy_attachment defined
    Then it must have role
    And it must have policy_arn

  Scenario: OIDC providers must use HTTPS thumbprints
    Given I have aws_iam_openid_connect_provider defined
    Then it must have url
    And it must have thumbprint_list

  Scenario: VPC flow logs must be enabled for network monitoring
    Given I have aws_flow_log defined
    Then it must have traffic_type
    And its traffic_type must be ALL

  Scenario: Flow logs must use S3 for long-term storage
    Given I have aws_flow_log defined
    Then it must have log_destination
    Or it must have log_destination_type
