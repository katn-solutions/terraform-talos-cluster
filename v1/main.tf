# Vars --------------------------------------------------------------------------------
variable "aws_region" {
  type        = string
  description = "AWS Region"
}

variable "vpc_id" {
  description = "ID of the VPC"
  type        = string
}

variable "cluster_name" {
  description = "Name of the Cluster"
  type        = string
}

variable "cluster_lb_subnets" {
  description = "Subnet ID's for placement of Load Balancers"
  type        = list(string)
}

variable "talos_version" {
  type        = string
  description = "Version of Talos to use"
}

variable "talos_arch" {
  type        = string
  description = "Chip Architecture"
}

# tflint-ignore: terraform_unused_declarations
variable "k8s_version" {
  type        = string
  description = "K8s Version"
}

variable "apiserver_internal_lb" {
  type        = bool
  description = "Flag to make Apiserver Load Balancer Internal"
}

variable "talos_access_cidr" {
  type        = list(string)
  description = "CIDR block for access to Talos API"
}

variable "expose_talos_api_via_lb" {
  type        = bool
  description = "Expose Talos API (port 50000) through the apiserver load balancer"
  default     = false
}

variable "group_nodes_together" {
  type        = bool
  description = "Whether or not to create a placement group and place the nodes together."
}

# tflint-ignore: terraform_unused_declarations
variable "dns_provider" {
  description = "DNS provider to use (cloudflare or route53)"
  type        = string
  default     = "cloudflare"
  validation {
    condition     = contains(["cloudflare", "route53"], var.dns_provider)
    error_message = "dns_provider must be either 'cloudflare' or 'route53'"
  }
}

# tflint-ignore: terraform_unused_declarations
variable "dns_zone_id" {
  type        = string
  description = "DNS Zone ID (Cloudflare Zone ID or Route53 Hosted Zone ID)"
}

variable "enable_global_accelerator" {
  type        = bool
  description = "Enable AWS Global Accelerator for the cluster ingress"
  default     = true
}

# tflint-ignore: terraform_unused_declarations
variable "sso_accelerator_dns_name" {
  type        = string
  description = "DNS name of Internal Accelerator for SSO"
}

variable "node_access_cidrs" {
  type        = list(string)
  description = "list of cidr blocks that can access the nodes"
}

variable "organization" {
  type        = string
  description = "Organization name for S3 bucket naming (ensures global uniqueness)"
}

# -------------------------------------------------------------------------------------

resource "aws_placement_group" "resource_group" {
  count    = var.group_nodes_together ? 1 : 0
  name     = var.cluster_name
  strategy = "cluster"
}

# Talos Machine Secrets
# Generate all cryptographic material needed for the cluster:
# - PKI certificates (etcd, Kubernetes, OS)
# - Cluster ID and secret
# - Bootstrap token
# - Trustd token
# - Client configuration (for talosctl)
resource "talos_machine_secrets" "this" {}

output "talos_machine_secrets" {
  value       = talos_machine_secrets.this
  description = "Talos machine secrets for cluster nodes"
  sensitive   = true
}

# Talos Info
data "aws_ami" "talos-ami" {
  most_recent = true
  filter {
    name   = "name"
    values = ["talos-${var.talos_version}-${var.aws_region}-${var.talos_arch}"]
  }
  owners = ["540036508848"] # Sidero Labs' AWS Account
}

output "talos_ami_id" {
  value       = data.aws_ami.talos-ami.id
  description = "Talos AMI ID"
}


# API Server Load Balancer
resource "aws_lb" "apiserver" {
  name               = "${var.cluster_name}-apiserver"
  load_balancer_type = "network"
  internal           = var.apiserver_internal_lb
  subnets            = var.cluster_lb_subnets

  tags = {
    Cluster = var.cluster_name
  }
  security_groups = [
    aws_security_group.cluster-apiserver-lb.id,
  ]
}

output "apiserver_lb_target_group_arn" {
  value       = aws_lb_target_group.apiserver-6443.arn
  description = "ARN of the aws lb for the apiserver"
}

output "apiserver_lb_url" {
  value = "https://${aws_lb.apiserver.dns_name}:6443"
}

output "talos_api_lb_target_group_arn" {
  value       = var.expose_talos_api_via_lb ? aws_lb_target_group.talos-50000[0].arn : ""
  description = "ARN of the Talos API target group (empty if not exposed via LB)"
}

output "talos_api_lb_url" {
  value       = var.expose_talos_api_via_lb ? "https://${aws_lb.apiserver.dns_name}:50000" : ""
  description = "URL for Talos API via load balancer (empty if not exposed)"
}

output "cleartext_int_lb_target_group_arn" {
  value       = aws_lb_target_group.ingress-int-clear.arn
  description = "ARN of the target group for internal cleartext"
}

output "tls_int_lb_target_group_arn" {
  value       = aws_lb_target_group.ingress-int-tls.arn
  description = "ARN of the target group for internal tls"
}

output "cleartext_ext_lb_target_group_arn" {
  value       = aws_lb_target_group.ingress-clear-ext.arn
  description = "ARN of the target group for external cleartext"
}

output "tls_ext_lb_target_group_arn" {
  value       = aws_lb_target_group.ingress-tls-ext.arn
  description = "ARN of the target group for external tls"
}


# Security Group for the k8s apiserver
resource "aws_security_group" "cluster-apiserver-lb" {
  vpc_id = var.vpc_id

  egress {
    description = "Egress everywhere"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "K8S API"
    from_port   = 6443
    to_port     = 6443
    protocol    = "tcp"
    cidr_blocks = [
      "0.0.0.0/0",
    ]
  }

  tags = {
    Cluster = var.cluster_name
  }
}

# Allow Talos API ingress to apiserver LB (optional)
resource "aws_security_group_rule" "apiserver-lb-talos" {
  count             = var.expose_talos_api_via_lb ? 1 : 0
  type              = "ingress"
  description       = "Talos API"
  from_port         = 50000
  to_port           = 50000
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.cluster-apiserver-lb.id
}

# Listener for the k8s apiserver
resource "aws_lb_listener" "apiserver-6443" {
  load_balancer_arn = aws_lb.apiserver.arn
  port              = "6443"
  protocol          = "TCP"
  tags = {
    Cluster = var.cluster_name
  }

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.apiserver-6443.arn
  }
}

# Target group for the apiserver
resource "aws_lb_target_group" "apiserver-6443" {
  name               = "${var.cluster_name}-apiserver-6443"
  port               = 6443
  protocol           = "TCP"
  vpc_id             = var.vpc_id
  proxy_protocol_v2  = false // not supported by k8s yet
  preserve_client_ip = true
  target_type        = "instance"

  health_check {
    protocol            = "TCP"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 10
    port                = 6443
  }

  tags = {
    Cluster = var.cluster_name
  }
}

# Listener for the Talos API (optional)
resource "aws_lb_listener" "talos-50000" {
  count             = var.expose_talos_api_via_lb ? 1 : 0
  load_balancer_arn = aws_lb.apiserver.arn
  port              = "50000"
  protocol          = "TCP"
  tags = {
    Cluster = var.cluster_name
  }

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.talos-50000[0].arn
  }
}

# Target group for the Talos API (optional)
resource "aws_lb_target_group" "talos-50000" {
  count              = var.expose_talos_api_via_lb ? 1 : 0
  name               = "${var.cluster_name}-talos-50000"
  port               = 50000
  protocol           = "TCP"
  vpc_id             = var.vpc_id
  proxy_protocol_v2  = false
  preserve_client_ip = true
  target_type        = "instance"

  health_check {
    protocol            = "TCP"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 10
    port                = 50000
  }

  tags = {
    Cluster = var.cluster_name
  }
}

# Security Group for K8S Nodes
resource "aws_security_group" "cluster-node" {
  name   = "${var.cluster_name}-nodes"
  vpc_id = var.vpc_id
  tags = {
    Cluster = var.cluster_name
  }
}

output "node_security_group_id" {
  value = aws_security_group.cluster-node.id
}

# Access to the K8S apiserver from the loadbalancer
resource "aws_security_group_rule" "apiserver" {
  type                     = "ingress"
  from_port                = 6443
  to_port                  = 6443
  protocol                 = "TCP"
  security_group_id        = aws_security_group.cluster-node.id
  source_security_group_id = aws_security_group.cluster-apiserver-lb.id
}

# Access to the Talos API from the loadbalancer (optional)
resource "aws_security_group_rule" "talos-lb" {
  count                    = var.expose_talos_api_via_lb ? 1 : 0
  type                     = "ingress"
  from_port                = 50000
  to_port                  = 50000
  protocol                 = "TCP"
  security_group_id        = aws_security_group.cluster-node.id
  source_security_group_id = aws_security_group.cluster-apiserver-lb.id
}

# Allow all ports from the node security group.  This means all nodes can reach each other on any port.
resource "aws_security_group_rule" "ingress" {
  type              = "ingress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  security_group_id = aws_security_group.cluster-node.id
  #source_security_group_id  = aws_security_group.cluster-node.id
  cidr_blocks = var.node_access_cidrs
}

# Allow port 50000 from within the VPC - Needed for Talos admin over VPN
resource "aws_security_group_rule" "talos" {
  type              = "ingress"
  from_port         = 50000
  to_port           = 50000
  protocol          = "TCP"
  security_group_id = aws_security_group.cluster-node.id
  cidr_blocks       = var.talos_access_cidr
}

# Allow cleartext traffic from Ingress Controller Internal Load Balancer
resource "aws_security_group_rule" "ingress-80" {
  type                     = "ingress"
  from_port                = 30080
  to_port                  = 30080
  protocol                 = "TCP"
  security_group_id        = aws_security_group.cluster-node.id
  source_security_group_id = aws_security_group.cluster-ingress-lb-int.id
}

# Allow TLS traffic from Ingress Controller Internal Load Balancer
resource "aws_security_group_rule" "ingress-443" {
  type                     = "ingress"
  from_port                = 30443
  to_port                  = 30443
  protocol                 = "TCP"
  security_group_id        = aws_security_group.cluster-node.id
  source_security_group_id = aws_security_group.cluster-ingress-lb-int.id
}

# Allow cleartext traffic from Ingress Controller External Load Balancer
resource "aws_security_group_rule" "ingress-80-ext" {
  type                     = "ingress"
  from_port                = 31080
  to_port                  = 31080
  protocol                 = "TCP"
  security_group_id        = aws_security_group.cluster-node.id
  source_security_group_id = aws_security_group.cluster-ingress-lb-ext.id
}

# Allow TLS traffic from Ingress Controller External Load Balancer
resource "aws_security_group_rule" "ingress-443-ext" {
  type                     = "ingress"
  from_port                = 31443
  to_port                  = 31443
  protocol                 = "TCP"
  security_group_id        = aws_security_group.cluster-node.id
  source_security_group_id = aws_security_group.cluster-ingress-lb-ext.id
}

# Open Egress from the cluster
resource "aws_security_group_rule" "cluster-egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.cluster-node.id
}

# Internal Load Balancer for Ingress
resource "aws_lb" "ingress-int" {
  name               = "${var.cluster_name}-ingress-int"
  load_balancer_type = "network"
  internal           = true
  subnets            = var.cluster_lb_subnets

  tags = {
    Cluster = var.cluster_name
  }
  security_groups = [
    aws_security_group.cluster-ingress-lb-int.id
  ]
}

# Security group for cluster ingress
resource "aws_security_group" "cluster-ingress-lb-int" {
  vpc_id = var.vpc_id

  ingress {
    description = "Cleartext Traffic"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [
      "0.0.0.0/0",
    ]
  }

  ingress {
    description = "TLS Traffic"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [
      "0.0.0.0/0",
    ]
  }

  egress {
    description = "Egress everywhere"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Cluster = var.cluster_name
  }
}

# Cleartext ingress listener
resource "aws_lb_listener" "ingress-clear" {
  load_balancer_arn = aws_lb.ingress-int.arn
  port              = "80"
  protocol          = "TCP"
  tags = {
    Cluster = var.cluster_name
  }

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ingress-int-clear.arn
  }
}

# TLS ingress listener
resource "aws_lb_listener" "ingress-tls" {
  load_balancer_arn = aws_lb.ingress-int.arn
  port              = "443"
  protocol          = "TCP"
  tags = {
    Cluster = var.cluster_name
  }

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ingress-int-tls.arn
  }
}

# Target group for ingress cleartext
resource "aws_lb_target_group" "ingress-int-clear" {
  name               = "${var.cluster_name}-ingress-int-clear"
  port               = 30080
  protocol           = "TCP"
  vpc_id             = var.vpc_id
  proxy_protocol_v2  = true
  preserve_client_ip = true
  target_type        = "instance"

  health_check {
    protocol            = "TCP"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 10
    port                = 30080
  }

  tags = {
    Cluster = var.cluster_name
  }
}

# Target group for ingress tls
resource "aws_lb_target_group" "ingress-int-tls" {
  name               = "${var.cluster_name}-ingress-int-tls"
  port               = 30443
  protocol           = "TCP"
  vpc_id             = var.vpc_id
  proxy_protocol_v2  = true
  preserve_client_ip = true
  target_type        = "instance"

  health_check {
    protocol            = "TCP"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 10
    port                = 30443
  }

  tags = {
    Cluster = var.cluster_name
  }
}

# External Load Balancer for Ingress
resource "aws_lb" "ingress-ext" {
  name               = "${var.cluster_name}-ingress-ext"
  load_balancer_type = "network"
  internal           = false
  subnets            = var.cluster_lb_subnets

  tags = {
    Cluster = var.cluster_name
  }
  security_groups = [
    aws_security_group.cluster-ingress-lb-ext.id,
  ]
}

output "external_lb_arn" {
  value       = aws_lb.ingress-ext.arn
  description = "ARN of external ingress load balancer"
}

# Security group for external ingress
resource "aws_security_group" "cluster-ingress-lb-ext" {
  vpc_id = var.vpc_id

  ingress {
    description = "Cleartext Traffic"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [
      "0.0.0.0/0",
    ]
  }

  ingress {
    description = "TLS Traffic"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [
      "0.0.0.0/0",
    ]
  }

  egress {
    description = "Egress everywhere"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Cluster = var.cluster_name
  }
}

# Listener for external ingress cleartext
resource "aws_lb_listener" "ingress-clear-ext" {
  load_balancer_arn = aws_lb.ingress-ext.arn
  port              = "80"
  protocol          = "TCP"
  tags = {
    Cluster = var.cluster_name
  }

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ingress-clear-ext.arn
  }
}

# Listener for external ingress tls
resource "aws_lb_listener" "ingress-443-ext" {
  load_balancer_arn = aws_lb.ingress-ext.arn
  port              = "443"
  protocol          = "TCP"
  tags = {
    Cluster = var.vpc_id
  }

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ingress-tls-ext.arn
  }
}

# Target group for external ingress cleartext
resource "aws_lb_target_group" "ingress-clear-ext" {
  name               = "${var.cluster_name}-ingress-clear-ext"
  port               = 31080
  protocol           = "TCP"
  vpc_id             = var.vpc_id
  proxy_protocol_v2  = true
  preserve_client_ip = true
  target_type        = "instance"

  health_check {
    protocol            = "TCP"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 10
    port                = 31080
  }

  tags = {
    Cluster = var.cluster_name
  }
}

# Target group for external ingress tls
resource "aws_lb_target_group" "ingress-tls-ext" {
  name               = "${var.cluster_name}-ingress-tls-ext"
  port               = 31443
  protocol           = "TCP"
  vpc_id             = var.vpc_id
  proxy_protocol_v2  = true
  preserve_client_ip = true
  target_type        = "instance"

  health_check {
    protocol            = "TCP"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 10
    port                = 31443
  }

  tags = {
    Cluster = var.cluster_name
  }
}

# Bucket for hosting the OIDC Configuration for for the cluster.
# This is needed in order to register the cluster as an OIDC Identity Provider with your AWS account, which is necessary for IRSA
# The info is available in the k8s apiserver, but for AWS to use it, it has to be available on the internet without authentication.  This sounds scary, but it's how all OIDC Identity Providers in AWS work.

resource "aws_s3_bucket" "oidc" {
  bucket = "${var.organization}-oidc-${var.cluster_name}"

}

resource "aws_s3_bucket_ownership_controls" "oidc" {
  bucket = aws_s3_bucket.oidc.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_public_access_block" "oidc" {
  bucket                  = aws_s3_bucket.oidc.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}


resource "aws_s3_bucket_policy" "oidc" {
  bucket = aws_s3_bucket.oidc.bucket

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect    = "Allow",
        Principal = "*",
        Action    = "s3:GetObject",
        Resource  = "${aws_s3_bucket.oidc.arn}/*",
      },
    ],
  })

  depends_on = [
    aws_s3_bucket.oidc,
    aws_s3_bucket_ownership_controls.oidc,
    aws_s3_bucket_public_access_block.oidc,
  ]
}

# Once the bucket exists, it needs to be filled with 2 files:

# Source: k get --raw /.well-known/openid-configuration > openid-configuration
# aws s3 cp openid-configuration s3://<organization>-oidc-<cluster>/.well-known/openid-configuration
# Dest: https://<organization>-oidc-<cluster>.s3.<region>.amazonaws.com/.well-known/openid-configuration

# Source: k get --raw /openid/v1/jwks > jwks.json
# aws s3 cp jwks.json s3://<organization>-oidc-<cluster>/.well-known/jwks.json
# Dest: https://<organization>-oidc-<cluster>.s3.<region>.amazonaws.com/.well-known/jwks.json

# Read the cert for the s3 bucket so we can extract the thumbprint, even though AWS doesn't require a thumprint for s3, terraform won't apply it without it.  Thankfully, terraform will look up the cert, and extract the thumbprint.
data "tls_certificate" "oidc-bucket" {
  url = "https://${aws_s3_bucket.oidc.bucket_regional_domain_name}"
}

# Setup the OIDC Identity Provider
resource "aws_iam_openid_connect_provider" "oidc" {
  url             = "https://${aws_s3_bucket.oidc.bucket_regional_domain_name}"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.oidc-bucket.certificates[0].sha1_fingerprint]
}

output "oidc_provider_arn" {
  value = aws_iam_openid_connect_provider.oidc.arn
}

output "oidc_provider_url" {
  value = aws_iam_openid_connect_provider.oidc.url
}

resource "aws_iam_role" "image-pull" {
  name = "image-pull-${var.cluster_name}"

  assume_role_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Federated" : aws_iam_openid_connect_provider.oidc.arn,
        },
        "Action" : "sts:AssumeRoleWithWebIdentity",
        "Condition" : {
          "StringEquals" : {
            "${aws_iam_openid_connect_provider.oidc.url}:sub" : "system:serviceaccount:ecr-image-auth:default",
            "${aws_iam_openid_connect_provider.oidc.url}:aud" : "sts.amazonaws.com",
          }
        }
      },
      {
        "Effect" : "Allow",
        "Principal" : {
          "Federated" : aws_iam_openid_connect_provider.oidc.arn,
        },
        "Action" : "sts:AssumeRoleWithWebIdentity",
        "Condition" : {
          "StringEquals" : {
            "${aws_iam_openid_connect_provider.oidc.url}:sub" : "system:serviceaccount:flux-system:image-reflector-controller",
            "${aws_iam_openid_connect_provider.oidc.url}:aud" : "sts.amazonaws.com",
          }
        }
      }
    ]
  })
  depends_on = [aws_iam_openid_connect_provider.oidc]
}

resource "aws_iam_role_policy_attachment" "image-pull-zulu" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.image-pull.name
}

resource "aws_iam_role" "csi" {
  name = "${var.cluster_name}-csi"

  assume_role_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Federated" : aws_iam_openid_connect_provider.oidc.arn,
        },
        "Action" : "sts:AssumeRoleWithWebIdentity",
        "Condition" : {
          "StringEquals" : {
            "${trimprefix(aws_iam_openid_connect_provider.oidc.url, "https://")}:sub" : "system:serviceaccount:kube-system:ebs-csi-controller-sa",
            "${trimprefix(aws_iam_openid_connect_provider.oidc.url, "https://")}:aud" : "sts.amazonaws.com",
          }
        }
      }
    ]
  })
}

resource "aws_iam_policy" "csi" {
  name = "${var.cluster_name}-csi"

  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Action" : [
          "ec2:CreateSnapshot",
          "ec2:AttachVolume",
          "ec2:DetachVolume",
          "ec2:ModifyVolume",
          "ec2:DescribeAvailabilityZones",
          "ec2:DescribeInstances",
          "ec2:DescribeSnapshots",
          "ec2:DescribeTags",
          "ec2:DescribeVolumes",
          "ec2:DescribeVolumesModifications",
          "kms:Decrypt",
          "kms:GenerateDataKeyWithoutPlaintext",
          "kms:CreateGrant"
        ],
        "Resource" : "*"
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "ec2:CreateTags"
        ],
        "Resource" : [
          "arn:aws:ec2:*:*:volume/*",
          "arn:aws:ec2:*:*:snapshot/*"
        ],
        "Condition" : {
          "StringEquals" : {
            "ec2:CreateAction" : [
              "CreateVolume",
              "CreateSnapshot"
            ]
          }
        }
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "ec2:DeleteTags"
        ],
        "Resource" : [
          "arn:aws:ec2:*:*:volume/*",
          "arn:aws:ec2:*:*:snapshot/*"
        ]
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "ec2:CreateVolume"
        ],
        "Resource" : "*",
        "Condition" : {
          "StringLike" : {
            "aws:RequestTag/ebs.csi.aws.com/cluster" : "true"
          }
        }
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "ec2:CreateVolume"
        ],
        "Resource" : "*",
        "Condition" : {
          "StringLike" : {
            "aws:RequestTag/CSIVolumeName" : "*"
          }
        }
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "ec2:DeleteVolume"
        ],
        "Resource" : "*",
        "Condition" : {
          "StringLike" : {
            "ec2:ResourceTag/ebs.csi.aws.com/cluster" : "true"
          }
        }
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "ec2:DeleteVolume"
        ],
        "Resource" : "*",
        "Condition" : {
          "StringLike" : {
            "ec2:ResourceTag/CSIVolumeName" : "*"
          }
        }
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "ec2:DeleteVolume"
        ],
        "Resource" : "*",
        "Condition" : {
          "StringLike" : {
            "ec2:ResourceTag/kubernetes.io/created-for/pvc/name" : "*"
          }
        }
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "ec2:DeleteSnapshot"
        ],
        "Resource" : "*",
        "Condition" : {
          "StringLike" : {
            "ec2:ResourceTag/CSIVolumeSnapshotName" : "*"
          }
        }
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "ec2:DeleteSnapshot"
        ],
        "Resource" : "*",
        "Condition" : {
          "StringLike" : {
            "ec2:ResourceTag/ebs.csi.aws.com/cluster" : "true"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "csi" {
  policy_arn = aws_iam_policy.csi.arn
  role       = aws_iam_role.csi.name
}

resource "aws_s3_bucket" "flow-logs" {
  count  = var.enable_global_accelerator ? 1 : 0
  bucket = "${var.organization}-${var.cluster_name}-flow-logs"
}

resource "aws_globalaccelerator_accelerator" "cluster" {
  count           = var.enable_global_accelerator ? 1 : 0
  name            = var.cluster_name
  ip_address_type = "IPV4"
  enabled         = true

  attributes {
    flow_logs_enabled   = true
    flow_logs_s3_bucket = aws_s3_bucket.flow-logs[0].bucket
    flow_logs_s3_prefix = "flow-logs/"
  }
}

output "aga_dns" {
  value       = var.enable_global_accelerator ? aws_globalaccelerator_accelerator.cluster[0].dns_name : ""
  description = "Global Accelerator DNS name (empty if Global Accelerator is disabled)"
}

output "aga_ips" {
  value       = var.enable_global_accelerator ? aws_globalaccelerator_accelerator.cluster[0].ip_sets : []
  description = "Global Accelerator IP sets (empty if Global Accelerator is disabled)"
}

resource "aws_globalaccelerator_listener" "http" {
  count           = var.enable_global_accelerator ? 1 : 0
  accelerator_arn = aws_globalaccelerator_accelerator.cluster[0].id
  #client_affinity = "SOURCE_IP"
  protocol = "TCP"
  port_range {
    from_port = 80
    to_port   = 80
  }
}

resource "aws_globalaccelerator_listener" "https" {
  count           = var.enable_global_accelerator ? 1 : 0
  accelerator_arn = aws_globalaccelerator_accelerator.cluster[0].id
  #client_affinity = "SOURCE_IP"
  protocol = "TCP"
  port_range {
    from_port = 443
    to_port   = 443
  }
}

resource "aws_globalaccelerator_endpoint_group" "http" {
  count        = var.enable_global_accelerator ? 1 : 0
  listener_arn = aws_globalaccelerator_listener.http[0].id
  endpoint_configuration {
    endpoint_id                    = aws_lb.ingress-ext.arn
    client_ip_preservation_enabled = true
    weight                         = 128
  }
}

resource "aws_globalaccelerator_endpoint_group" "https" {
  count        = var.enable_global_accelerator ? 1 : 0
  listener_arn = aws_globalaccelerator_listener.https[0].id
  endpoint_configuration {
    endpoint_id                    = aws_lb.ingress-ext.arn
    client_ip_preservation_enabled = true
    weight                         = 128
  }
}

# resource "cloudflare_record" "prometheus-int" {
#   zone_id = var.cloudflare_zone_id
#   type    = "CNAME"
#   name    = "prometheus-${var.cluster_name}.corp"
#   value   = aws_lb.ingress-int.dns_name
#   proxied = false
#   ttl     = 60
# }

# resource "cloudflare_record" "alertmanager-int" {
#   zone_id = var.cloudflare_zone_id
#   type    = "CNAME"
#   name    = "alertmanager-${var.cluster_name}.corp"
#   value   = aws_lb.ingress-int.dns_name
#   proxied = false
#   ttl     = 60
# }

# resource "cloudflare_record" "alertmanager-ext" {
#   zone_id = var.cloudflare_zone_id
#   type    = "CNAME"
#   name    = "alertmanager-${var.cluster_name}.sso.corp"
#   value   = var.sso_accelerator_dns_name
#   proxied = false
#   ttl     = 60
# }
#
# resource "cloudflare_record" "prometheus-ext" {
#   zone_id = var.cloudflare_zone_id
#   type    = "CNAME"
#   name    = "prometheus-${var.cluster_name}.sso.corp"
#   value   = var.sso_accelerator_dns_name
#   proxied = false
#   ttl     = 60
# }
