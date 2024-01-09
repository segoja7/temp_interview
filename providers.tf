terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.66.1"
    }
  }
}

provider "aws" {
  region  = local.region
  profile = local.profile
}