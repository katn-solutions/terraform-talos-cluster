Feature: Kubernetes cluster compliance
  As a Kubernetes administrator
  I want to ensure proper cluster configuration
  So that the cluster is production-ready

  Scenario: Control plane must have adequate instance sizing
    Given I have aws_instance defined
    When it has tags
    When its tags has Role
    When its Role is control-plane
    Then it must have instance_type

  Scenario: Worker nodes must have adequate instance sizing
    Given I have aws_instance defined
    When it has tags
    When its tags has Role
    When its Role is worker
    Then it must have instance_type

  Scenario: All nodes must be in a VPC
    Given I have aws_instance defined
    Then it must have subnet_id

  Scenario: All nodes must have proper tagging for identification
    Given I have aws_instance defined
    Then it must have tags
    And it must have tags.Cluster
    And it must have tags.Role

  Scenario: Control plane should have at least 3 nodes for HA
    Given I have aws_instance defined
    When it has tags
    When its tags has Role
    When its Role is control-plane
    Then it must have tags.Cluster

  Scenario: OIDC discovery must be configured for IRSA
    Given I have aws_s3_object defined
    When it has key
    When its key is .well-known/openid-configuration
    Then it must have content
    And it must have content_type

  Scenario: Cluster must support IAM Roles for Service Accounts
    Given I have aws_iam_openid_connect_provider defined
    When it has url
    Then it must have client_id_list
    And its client_id_list must contain sts.amazonaws.com

  Scenario: Launch templates should be used for node configuration
    Given I have aws_launch_template defined
    Then it must have image_id
    And it must have instance_type
    And it must have user_data

  Scenario: Nodes must use EBS volumes with proper sizing
    Given I have aws_launch_template defined
    When it has block_device_mappings
    Then it must have ebs

  Scenario: Network interfaces must be configured
    Given I have aws_instance defined
    Then it must have network_interface
    Or it must have subnet_id
