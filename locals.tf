locals {
  region  = "us-east-1"
  profile = "segoja7"
  name    = "wordpress"
}

locals {
  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}