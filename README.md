# terraform-talos-cluster

Terraform module for deploying comprehensive Talos Kubernetes cluster infrastructure on AWS.

## Overview

This module creates the foundational infrastructure for a Talos Kubernetes cluster, including:

- API server Network Load Balancer
- Internal and external ingress load balancers
- Security groups with least-privilege access controls
- OIDC provider setup for IRSA (IAM Roles for Service Accounts)
- IAM roles for ECR image pulling and EBS CSI driver
- AWS Global Accelerator for global traffic distribution
- S3 buckets for OIDC discovery and flow logs

## Versions

### v0
Full-featured cluster infrastructure with Kafka-specific networking support (ports 31999-32002 for load balancer access, configurable port range for VPC access).

### v1
Streamlined cluster infrastructure without Kafka-specific features. Recommended for general-purpose Kubernetes workloads.

## Usage

```hcl
module "talos_cluster" {
  source = "github.com/katn-solutions/terraform-talos-cluster//v1"

  # Basic Configuration
  aws_region          = "us-west-2"
  vpc_id              = "vpc-12345678"
  cluster_name        = "production"
  organization        = "mycompany"
  cluster_lb_subnets  = ["subnet-abc123", "subnet-def456"]

  # Talos/K8s Versions
  talos_version       = "v1.7.0"
  talos_arch          = "amd64"
  k8s_version         = "v1.30.0"

  # Access Controls
  apiserver_internal_lb = false
  talos_access_cidr     = ["10.0.0.0/8"]
  node_access_cidrs     = ["10.0.0.0/8", "172.16.0.0/12"]

  # Placement
  group_nodes_together  = false

  # DNS
  cloudflare_zone_id           = "cloudflare-zone-id"
  sso_accelerator_dns_name     = "sso.example.com"
}
```

### v0 Additional Variables (Kafka Support)

```hcl
module "talos_cluster" {
  source = "github.com/katn-solutions/terraform-talos-cluster//v0"

  # ... same as v1 plus:

  kafka_vpc_access_cidr = ["10.0.0.0/8"]
  kafka_port_start      = 32000
  kafka_port_end        = 32010
}
```

## Testing

This module includes comprehensive testing for both v0 and v1 versions using Terratest (Go-based unit tests) and Terraform Compliance (BDD-style policy tests).

### Running Tests Locally

```bash
# Install dependencies (one-time setup)
make init

# Run all tests (both versions)
make all                    # Runs lint + validation + unit tests

# Run specific test types
make lint                   # Format check + tflint (both versions)
make test                   # Terraform validation (v0 and v1)
make test-v0                # Validate v0 only
make test-v1                # Validate v1 only
make test-unit              # Terratest unit tests (both versions)
make test-compliance        # BDD compliance tests (both versions)
```

### Test Structure

**Terratest (Unit Tests)** - `test/terraform_test.go`
- Validates module configuration without creating infrastructure
- Tests organization variable, instance configurations, and both versions
- Includes HA configuration tests and version-specific features
- Runs in parallel for fast feedback
- No AWS credentials required

**Terraform Compliance (Policy Tests)** - `compliance/*.feature`
- Security compliance: S3 encryption, IAM roles, security groups, VPC flow logs
- Kubernetes compliance: Node tagging, OIDC setup, IRSA configuration
- Validates both v0 (with Kafka) and v1 (streamlined) configurations

### CI/CD

Tests run automatically in GitHub Actions on every push and pull request:
- Code formatting (terraform fmt)
- Linting (tflint)
- Validation (terraform validate) for both v0 and v1
- Unit tests (Terratest) covering all scenarios

## Requirements

| Name | Version |
|------|---------|
| terraform | >=1.1.7, <2.0.0 |
| aws | >=5.39.0, <6.0.0 |
| cloudflare | 4.8.0 |
| talos | 0.4.0 |

## Inputs

### Common Inputs (v0 and v1)

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| aws_region | AWS region for deployment | `string` | n/a | yes |
| vpc_id | VPC ID where resources will be created | `string` | n/a | yes |
| cluster_name | Name of the Kubernetes cluster | `string` | n/a | yes |
| organization | Organization name for S3 bucket naming | `string` | n/a | yes |
| cluster_lb_subnets | Subnet IDs for load balancer placement | `list(string)` | n/a | yes |
| talos_version | Talos Linux version (e.g., v1.7.0) | `string` | n/a | yes |
| talos_arch | CPU architecture (amd64 or arm64) | `string` | n/a | yes |
| k8s_version | Kubernetes version (e.g., v1.30.0) | `string` | n/a | yes |
| apiserver_internal_lb | Make API server LB internal (true) or external (false) | `bool` | n/a | yes |
| talos_access_cidr | CIDR blocks allowed to access Talos API (port 50000) | `list(string)` | n/a | yes |
| node_access_cidrs | CIDR blocks allowed to access cluster nodes | `list(string)` | n/a | yes |
| group_nodes_together | Create placement group for low-latency node communication | `bool` | n/a | yes |
| cloudflare_zone_id | Cloudflare Zone ID for DNS management | `string` | n/a | yes |
| sso_accelerator_dns_name | DNS name of SSO accelerator for internal services | `string` | n/a | yes |

### v0-Specific Inputs (Kafka Support)

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| kafka_vpc_access_cidr | CIDR blocks for VPC access to Kafka | `list(string)` | n/a | yes |
| kafka_port_start | Beginning port for Kafka traffic range | `number` | n/a | yes |
| kafka_port_end | End port for Kafka traffic range | `number` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| talos_ami_id | AMI ID for Talos Linux nodes |
| apiserver_lb_target_group_arn | Target group ARN for API server (port 6443) |
| apiserver_lb_url | URL for Kubernetes API server |
| cleartext_int_lb_target_group_arn | Internal cleartext ingress target group (port 30080) |
| tls_int_lb_target_group_arn | Internal TLS ingress target group (port 30443) |
| cleartext_ext_lb_target_group_arn | External cleartext ingress target group (port 31080) |
| tls_ext_lb_target_group_arn | External TLS ingress target group (port 31443) |
| node_security_group_id | Security group ID for cluster nodes |
| external_lb_arn | ARN of external ingress load balancer |
| oidc_provider_arn | ARN of OIDC provider for IRSA |
| oidc_provider_url | URL of OIDC provider |
| aga_dns | DNS name of AWS Global Accelerator |
| aga_ips | Static IP addresses of Global Accelerator |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ AWS Global Accelerator (Static IPs, Global Anycast)        │
└────────────────────┬────────────────────────────────────────┘
                     │
                     v
┌─────────────────────────────────────────────────────────────┐
│ External Ingress NLB (Internet-Facing)                      │
│  - HTTP Listener (80 -> NodePort 31080)                    │
│  - HTTPS Listener (443 -> NodePort 31443)                  │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ Internal Ingress NLB (VPC-Internal)                         │
│  - HTTP Listener (80 -> NodePort 30080)                    │
│  - HTTPS Listener (443 -> NodePort 30443)                  │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ API Server NLB (Internal or External)                       │
│  - TCP Listener (6443 -> Node Port 6443)                   │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ OIDC Infrastructure (IRSA)                                  │
│  - S3 Bucket: <organization>-oidc-<cluster>                │
│  - IAM OIDC Provider                                        │
│  - IAM Roles: ECR Image Pull, EBS CSI Driver               │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ Security Groups                                             │
│  - API Server Access (6443, 50000)                         │
│  - Node Communication (All traffic between nodes)          │
│  - Ingress LB Access (80, 443, NodePorts)                  │
│  - Kafka Access (v0 only: 31999-32002, custom range)      │
└─────────────────────────────────────────────────────────────┘
```

## Post-Deployment: OIDC Configuration

After the cluster infrastructure is created, the OIDC S3 bucket must be populated with discovery documents:

```bash
# Extract OIDC configuration from Kubernetes API server
kubectl get --raw /.well-known/openid-configuration > openid-configuration
kubectl get --raw /openid/v1/jwks > jwks.json

# Upload to S3 bucket
aws s3 cp openid-configuration s3://<organization>-oidc-<cluster>/.well-known/openid-configuration
aws s3 cp jwks.json s3://<organization>-oidc-<cluster>/.well-known/jwks.json

# Verify accessibility
curl https://<organization>-oidc-<cluster>.s3.<region>.amazonaws.com/.well-known/openid-configuration
curl https://<organization>-oidc-<cluster>.s3.<region>.amazonaws.com/.well-known/jwks.json
```

## IAM Roles for Service Accounts (IRSA)

The module creates two IAM roles with trust relationships to the cluster's OIDC provider:

### 1. ECR Image Pull Role
- **Purpose**: Pull container images from ECR
- **Policy**: `arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly`
- **Service Account Annotation**: `eks.amazonaws.com/role-arn: <role-arn>`

### 2. EBS CSI Driver Role
- **Purpose**: Manage EBS volumes for persistent storage
- **Permissions**:
  - Create/Delete/Attach/Detach volumes
  - Create/Delete snapshots
  - Tag resources
  - Describe volumes, snapshots, availability zones

## Port Mapping

### API Server
- **6443**: Kubernetes API server
- **50000**: Talos API (machine configuration)

### Internal Ingress (VPC-Internal Services)
- **80** → NodePort **30080** (HTTP)
- **443** → NodePort **30443** (HTTPS)

### External Ingress (Internet-Facing Services)
- **80** → NodePort **31080** (HTTP)
- **443** → NodePort **31443** (HTTPS)

### Kafka (v0 Only)
- **31999-32002**: Load balancer access to Kafka brokers
- **Custom range**: VPC-internal access (configurable via `kafka_port_start`/`kafka_port_end`)

## Features

### Client IP Preservation
All target groups use Proxy Protocol v2 to preserve client IP addresses through the load balancer.

### Placement Groups
When `group_nodes_together = true`, nodes are placed in a cluster placement group for low-latency communication (recommended for latency-sensitive workloads).

### AMI Selection
The module automatically selects the official Talos Linux AMI from Sidero Labs (AWS Account: 540036508848) matching the specified version, region, and architecture.

### Flow Logs
AWS Global Accelerator flow logs are stored in S3 bucket: `<organization>-<cluster>-flow-logs`

## Version Differences

| Feature | v0 | v1 |
|---------|----|----|
| API Server LB | ✓ | ✓ |
| Internal Ingress LB | ✓ | ✓ |
| External Ingress LB | ✓ | ✓ |
| OIDC/IRSA Setup | ✓ | ✓ |
| Global Accelerator | ✓ | ✓ |
| Kafka Networking | ✓ | ✗ |
| Security Group Rules | Kafka-specific | Streamlined |

## Dependencies

This module must be deployed **before** node modules:
- `terraform-talos-cp-node` (control plane nodes)
- `terraform-talos-worker-node` (worker nodes)

Node modules consume outputs from this module (target group ARNs, security group IDs, AMI ID, OIDC configuration).

## Notes

- S3 bucket names must be globally unique (hence the `organization` variable)
- The OIDC bucket is publicly readable (required for AWS OIDC provider integration)
- Security groups enforce least-privilege access - modify `talos_access_cidr` and `node_access_cidrs` to restrict access
- Cloudflare DNS integration is available but not currently used (commented out in main.tf)
- Global Accelerator provides static IPs and DDoS protection via AWS Shield Standard

## License

Proprietary
