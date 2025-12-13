

terraform {
  required_version = ">= 1.1.7, < 2.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">=5.39.0, < 6.0.0"
    }

    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "4.8.0"
    }

    talos = {
      source  = "siderolabs/talos"
      version = "0.4.0"
    }

    tls = {
      source  = "hashicorp/tls"
      version = ">=4.0.0, <5.0.0"
    }
  }
}
