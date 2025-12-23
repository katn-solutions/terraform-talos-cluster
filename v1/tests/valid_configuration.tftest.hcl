# Test valid cluster configuration (v1 without Kafka)
run "valid_cluster_configuration" {
  command = plan

  variables {
    aws_region               = "us-west-2"
    vpc_id                   = "vpc-12345678"
    cluster_name             = "test-cluster"
    organization             = "test-org"
    cluster_lb_subnets       = ["subnet-abc123", "subnet-def456"]
    talos_version            = "v1.7.0"
    talos_arch               = "amd64"
    k8s_version              = "v1.30.0"
    apiserver_internal_lb    = false
    talos_access_cidr        = ["10.0.0.0/8"]
    group_nodes_together     = false
    dns_zone_id              = "test-zone-id"
    dns_provider             = "cloudflare"
    sso_accelerator_dns_name = "sso.example.com"
    node_access_cidrs        = ["10.0.0.0/8"]
  }

  assert {
    condition     = aws_lb.apiserver.load_balancer_type == "network"
    error_message = "API server load balancer must be network type"
  }

  assert {
    condition     = aws_lb.ingress-int.load_balancer_type == "network"
    error_message = "Internal ingress load balancer must be network type"
  }

  assert {
    condition     = aws_lb.ingress-ext.load_balancer_type == "network"
    error_message = "External ingress load balancer must be network type"
  }

  assert {
    condition     = aws_lb.ingress-int.internal == true
    error_message = "Internal ingress load balancer should be internal"
  }

  assert {
    condition     = aws_lb.ingress-ext.internal == false
    error_message = "External ingress load balancer should be internet-facing"
  }
}

# Test OIDC bucket naming with organization
run "oidc_bucket_naming" {
  command = plan

  variables {
    aws_region               = "us-west-2"
    vpc_id                   = "vpc-12345678"
    cluster_name             = "test-cluster"
    organization             = "mycompany"
    cluster_lb_subnets       = ["subnet-abc123"]
    talos_version            = "v1.7.0"
    talos_arch               = "amd64"
    k8s_version              = "v1.30.0"
    apiserver_internal_lb    = false
    talos_access_cidr        = ["10.0.0.0/8"]
    group_nodes_together     = false
    dns_zone_id              = "test-zone-id"
    dns_provider             = "cloudflare"
    sso_accelerator_dns_name = "sso.example.com"
    node_access_cidrs        = ["10.0.0.0/8"]
  }

  assert {
    condition     = aws_s3_bucket.oidc.bucket == "mycompany-oidc-test-cluster"
    error_message = "OIDC bucket should use organization prefix"
  }

  assert {
    condition     = aws_s3_bucket.flow-logs.bucket == "mycompany-test-cluster-flow-logs"
    error_message = "Flow logs bucket should use organization prefix"
  }
}

# Test internal API server load balancer
run "internal_apiserver_lb" {
  command = plan

  variables {
    aws_region               = "us-west-2"
    vpc_id                   = "vpc-12345678"
    cluster_name             = "test-cluster"
    organization             = "test-org"
    cluster_lb_subnets       = ["subnet-abc123"]
    talos_version            = "v1.7.0"
    talos_arch               = "amd64"
    k8s_version              = "v1.30.0"
    apiserver_internal_lb    = true
    talos_access_cidr        = ["10.0.0.0/8"]
    group_nodes_together     = false
    dns_zone_id              = "test-zone-id"
    dns_provider             = "cloudflare"
    sso_accelerator_dns_name = "sso.example.com"
    node_access_cidrs        = ["10.0.0.0/8"]
  }

  assert {
    condition     = aws_lb.apiserver.internal == true
    error_message = "API server load balancer should be internal when specified"
  }
}

# Test placement group creation
run "placement_group_enabled" {
  command = plan

  variables {
    aws_region               = "us-west-2"
    vpc_id                   = "vpc-12345678"
    cluster_name             = "test-cluster"
    organization             = "test-org"
    cluster_lb_subnets       = ["subnet-abc123"]
    talos_version            = "v1.7.0"
    talos_arch               = "amd64"
    k8s_version              = "v1.30.0"
    apiserver_internal_lb    = false
    talos_access_cidr        = ["10.0.0.0/8"]
    group_nodes_together     = true
    dns_zone_id              = "test-zone-id"
    dns_provider             = "cloudflare"
    sso_accelerator_dns_name = "sso.example.com"
    node_access_cidrs        = ["10.0.0.0/8"]
  }

  assert {
    condition     = length(aws_placement_group.resource_group) == 1
    error_message = "Placement group should be created when enabled"
  }

  assert {
    condition     = aws_placement_group.resource_group[0].strategy == "cluster"
    error_message = "Placement group strategy should be cluster"
  }
}

# Test IAM roles for IRSA
run "irsa_iam_roles" {
  command = plan

  variables {
    aws_region               = "us-west-2"
    vpc_id                   = "vpc-12345678"
    cluster_name             = "test-cluster"
    organization             = "test-org"
    cluster_lb_subnets       = ["subnet-abc123"]
    talos_version            = "v1.7.0"
    talos_arch               = "amd64"
    k8s_version              = "v1.30.0"
    apiserver_internal_lb    = false
    talos_access_cidr        = ["10.0.0.0/8"]
    group_nodes_together     = false
    dns_zone_id              = "test-zone-id"
    dns_provider             = "cloudflare"
    sso_accelerator_dns_name = "sso.example.com"
    node_access_cidrs        = ["10.0.0.0/8"]
  }

  assert {
    condition     = aws_iam_role.image-pull.name == "test-cluster-image-pull"
    error_message = "Image pull IAM role should exist with correct name"
  }

  assert {
    condition     = aws_iam_role.csi.name == "test-cluster-csi"
    error_message = "CSI IAM role should exist with correct name"
  }
}

# Test target group configurations
run "target_group_configurations" {
  command = plan

  variables {
    aws_region               = "us-west-2"
    vpc_id                   = "vpc-12345678"
    cluster_name             = "test-cluster"
    organization             = "test-org"
    cluster_lb_subnets       = ["subnet-abc123"]
    talos_version            = "v1.7.0"
    talos_arch               = "amd64"
    k8s_version              = "v1.30.0"
    apiserver_internal_lb    = false
    talos_access_cidr        = ["10.0.0.0/8"]
    group_nodes_together     = false
    dns_zone_id              = "test-zone-id"
    dns_provider             = "cloudflare"
    sso_accelerator_dns_name = "sso.example.com"
    node_access_cidrs        = ["10.0.0.0/8"]
  }

  assert {
    condition     = aws_lb_target_group.apiserver.port == 6443
    error_message = "API server target group should be on port 6443"
  }

  assert {
    condition     = aws_lb_target_group.cleartext_int.port == 30080
    error_message = "Internal cleartext target group should be on port 30080"
  }

  assert {
    condition     = aws_lb_target_group.tls_int.port == 30443
    error_message = "Internal TLS target group should be on port 30443"
  }

  assert {
    condition     = aws_lb_target_group.cleartext_ext.port == 31080
    error_message = "External cleartext target group should be on port 31080"
  }

  assert {
    condition     = aws_lb_target_group.tls_ext.port == 31443
    error_message = "External TLS target group should be on port 31443"
  }

  assert {
    condition     = aws_lb_target_group.tls_int.proxy_protocol_v2 == true
    error_message = "Internal TLS target group should have proxy protocol v2 enabled"
  }

  assert {
    condition     = aws_lb_target_group.tls_ext.proxy_protocol_v2 == true
    error_message = "External TLS target group should have proxy protocol v2 enabled"
  }
}

# Test Global Accelerator configuration
run "global_accelerator_configuration" {
  command = plan

  variables {
    aws_region               = "us-west-2"
    vpc_id                   = "vpc-12345678"
    cluster_name             = "test-cluster"
    organization             = "test-org"
    cluster_lb_subnets       = ["subnet-abc123"]
    talos_version            = "v1.7.0"
    talos_arch               = "amd64"
    k8s_version              = "v1.30.0"
    apiserver_internal_lb    = false
    talos_access_cidr        = ["10.0.0.0/8"]
    group_nodes_together     = false
    dns_zone_id              = "test-zone-id"
    dns_provider             = "cloudflare"
    sso_accelerator_dns_name = "sso.example.com"
    node_access_cidrs        = ["10.0.0.0/8"]
  }

  assert {
    condition     = aws_globalaccelerator_accelerator.cluster.enabled == true
    error_message = "Global Accelerator should be enabled"
  }

  assert {
    condition     = aws_globalaccelerator_accelerator.cluster.ip_address_type == "IPV4"
    error_message = "Global Accelerator should use IPv4"
  }

  assert {
    condition     = length(aws_globalaccelerator_listener.http) > 0
    error_message = "Global Accelerator should have HTTP listener"
  }

  assert {
    condition     = length(aws_globalaccelerator_listener.https) > 0
    error_message = "Global Accelerator should have HTTPS listener"
  }
}

# Test Talos machine secrets generation
run "machine_secrets_generation" {
  command = plan

  variables {
    aws_region               = "us-west-2"
    vpc_id                   = "vpc-12345678"
    cluster_name             = "test-cluster"
    organization             = "test-org"
    cluster_lb_subnets       = ["subnet-abc123"]
    talos_version            = "v1.7.0"
    talos_arch               = "amd64"
    k8s_version              = "v1.30.0"
    apiserver_internal_lb    = false
    talos_access_cidr        = ["10.0.0.0/8"]
    group_nodes_together     = false
    dns_zone_id              = "test-zone-id"
    dns_provider             = "cloudflare"
    sso_accelerator_dns_name = "sso.example.com"
    node_access_cidrs        = ["10.0.0.0/8"]
  }

  assert {
    condition     = talos_machine_secrets.this != null
    error_message = "Talos machine secrets should be generated"
  }

  assert {
    condition     = output.talos_machine_secrets != null
    error_message = "Talos machine secrets output should be available"
  }
}

# Test talosconfig generation with control plane endpoints
run "talosconfig_generation" {
  command = plan

  variables {
    aws_region                   = "us-west-2"
    vpc_id                       = "vpc-12345678"
    cluster_name                 = "test-cluster"
    organization                 = "test-org"
    cluster_lb_subnets           = ["subnet-abc123"]
    talos_version                = "v1.7.0"
    talos_arch                   = "amd64"
    k8s_version                  = "v1.30.0"
    apiserver_internal_lb        = false
    talos_access_cidr            = ["10.0.0.0/8"]
    group_nodes_together         = false
    dns_zone_id                  = "test-zone-id"
    dns_provider                 = "cloudflare"
    sso_accelerator_dns_name     = "sso.example.com"
    node_access_cidrs            = ["10.0.0.0/8"]
    control_plane_node_endpoints = ["10.0.1.10", "10.0.1.11", "10.0.1.12"]
  }

  assert {
    condition     = data.talos_client_configuration.this[0] != null
    error_message = "Talos client configuration should be generated when endpoints are provided"
  }

  assert {
    condition     = output.talosconfig != null
    error_message = "Talosconfig output should be available when endpoints are provided"
  }
}

# Test talosconfig not generated without endpoints
run "talosconfig_no_endpoints" {
  command = plan

  variables {
    aws_region                   = "us-west-2"
    vpc_id                       = "vpc-12345678"
    cluster_name                 = "test-cluster"
    organization                 = "test-org"
    cluster_lb_subnets           = ["subnet-abc123"]
    talos_version                = "v1.7.0"
    talos_arch                   = "amd64"
    k8s_version                  = "v1.30.0"
    apiserver_internal_lb        = false
    talos_access_cidr            = ["10.0.0.0/8"]
    group_nodes_together         = false
    dns_zone_id                  = "test-zone-id"
    dns_provider                 = "cloudflare"
    sso_accelerator_dns_name     = "sso.example.com"
    node_access_cidrs            = ["10.0.0.0/8"]
    control_plane_node_endpoints = []
  }

  assert {
    condition     = length(data.talos_client_configuration.this) == 0
    error_message = "Talos client configuration should not be generated when no endpoints provided"
  }

  assert {
    condition     = output.talosconfig == null
    error_message = "Talosconfig output should be null when no endpoints provided"
  }
}
