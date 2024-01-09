module "kms" {
  source      = "terraform-aws-modules/kms/aws"
  version     = "2.1.0"
  description = "kms for encrypt wordpress app"
  key_usage   = "ENCRYPT_DECRYPT"
  # Aliases
  aliases           = ["nequi/wordpress"]
  key_service_users = [module.ecs_service.tasks_iam_role_arn, module.ecs_service.task_exec_iam_role_arn]
  key_statements = [
    {
      sid = "fargate"
      actions = [
        "kms:Encrypt*",
        "kms:Decrypt*",
        "kms:Describe*"
      ]
      resources = ["*"]

      principals = [
        {
          type        = "Service"
          identifiers = ["ecs-tasks.amazonaws.com"]
        }
      ]

    }
  ]


  tags = local.tags
}

module "vpc" {
  source = "terraform-aws-modules/vpc/aws"

  name                                 = "wordpress-vpc"
  cidr                                 = "10.0.0.0/16"
  enable_flow_log                      = true
  create_flow_log_cloudwatch_iam_role  = true
  create_flow_log_cloudwatch_log_group = true
  azs                                  = ["us-east-1a", "us-east-1b"]
  private_subnets                      = ["10.0.1.0/24", "10.0.2.0/24"]
  database_subnets                     = ["10.0.21.0/24", "10.0.22.0/24"]
  public_subnets                       = ["10.0.101.0/24", "10.0.102.0/24"]


  enable_nat_gateway      = true
  single_nat_gateway      = true
  one_nat_gateway_per_az  = false
  map_public_ip_on_launch = true

  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}

#module "endpoints" {
#  source                     = "terraform-aws-modules/vpc/aws//modules/vpc-endpoints"
#  create_security_group      = true
#  security_group_name_prefix = "${local.name}-vpc-endpoints-"
#  security_group_description = "VPC endpoint security group"
#  vpc_id                     = module.vpc.vpc_id
#  security_group_rules = {
#    ingress_https = {
#      description = "HTTPS from VPC"
#      cidr_blocks = [module.vpc.vpc_cidr_block]
#    }
#  }
#
#  endpoints = {
#    #        efs = {
#    #          # interface endpoint
#    #          service             = "elasticfilesystem"
#    #          tags                = { Name = "elasticfilesystem-vpc-endpoint" }
#    #          subnet_ids          = concat(module.vpc.private_subnets, module.vpc.public_subnets)
#    #        },
#    #        rds = {
#    #          service         = "rds"
#    #          tags            = { Name = "rds-vpc-endpoint" }
#    #          subnet_ids          = concat(module.vpc.private_subnets, module.vpc.public_subnets)
#    #        },
#    #        kms = {
#    #          service    = "kms"
#    #          tags       = { Name = "kms-vpc-endpoint" }
#    #          subnet_ids          = concat(module.vpc.private_subnets, module.vpc.public_subnets)
#    #        }
#    secretsmanager = {
#      service    = "secretsmanager"
#      tags       = { Name = "secretsmanager-vpc-endpoint" }
#      subnet_ids = concat(module.vpc.private_subnets)
#    }
#  }
#
#  tags = local.tags
#}

module "efs" {
  source      = "terraform-aws-modules/efs/aws"
  version     = "1.3.1"
  name        = "efs-wordpress"
  encrypted   = true
  kms_key_arn = module.kms.key_arn

  performance_mode                = "generalPurpose"
  throughput_mode                 = "provisioned"
  provisioned_throughput_in_mibps = 5

  lifecycle_policy = {
    transition_to_ia = "AFTER_30_DAYS"
  }

  # File system policy
  attach_policy                      = true
  bypass_policy_lockout_safety_check = false
  policy_statements = [
    {
      sid     = "connect"
      actions = ["elasticfilesystem:ClientMount"]
      principals = [
        {
          type        = "AWS"
          identifiers = ["*"]
        }
      ]
    }
  ]

  # Mount targets / security group
  mount_targets = {
    "us-east-1a" = {
      subnet_id = module.vpc.private_subnets[0]
    }
    "us-east-1b" = {
      subnet_id = module.vpc.private_subnets[1]
    }
  }
  security_group_description = "EFS security group"
  security_group_vpc_id      = module.vpc.vpc_id
  security_group_rules = {
    vpc = {
      # relying on the defaults provdied for EFS/NFS (2049/TCP + ingress)
      description = "NFS ingress from VPC private subnets"
      cidr_blocks = concat(module.vpc.private_subnets_cidr_blocks)
    }
  }

  # Access point(s)
  access_points = {
    posix = {
      name = "posix"
      posix_user = {
        gid = 1001
        uid = 1001
      }
    }
    root_wordpress = {
      root_directory = {
        path = "/bitnami"
        creation_info = {
          owner_gid   = 1001
          owner_uid   = 1001
          permissions = "755"
        }
      }
    }
  }
  # Backup policy
  enable_backup_policy = true

  tags = local.tags
}


module "ecs_cluster" {
  source  = "terraform-aws-modules/ecs/aws//modules/cluster"
  version = "5.7.4"


  cluster_name = "ecs-fargate-${local.name}"

  cluster_settings = {
    "name" : "containerInsights",
    "value" : "enabled"
  }

  fargate_capacity_providers = {
    FARGATE = {
      default_capacity_provider_strategy = {
        weight = 50
      }
    }
    FARGATE_SPOT = {
      default_capacity_provider_strategy = {
        weight = 50
      }
    }
  }


  tags = local.tags
}


module "ecs_service" {
  source  = "terraform-aws-modules/ecs/aws//modules/service"
  version = "5.7.4"

  name        = "ecs-${local.name}"
  cluster_arn = module.ecs_cluster.arn

  cpu                        = 256
  memory                     = 512
  network_mode               = "awsvpc"
  assign_public_ip           = false
  tasks_iam_role_name        = "${local.name}-tasks"
  tasks_iam_role_description = "IAM role for ${local.name} tasks fargate"
  tasks_iam_role_statements = [
    {
      actions   = ["kms:Decrypt"]
      resources = [module.kms.key_arn]
    },
    {
      actions   = ["secretsmanager:GetSecretValue"]
      resources = [data.aws_secretsmanager_secret.by-arn.arn]
    }
  ]

  # Container definition(s)
  container_definitions = {
    (local.name) = {
      cpu       = 256
      memory    = 512
      essential = true
      image     = "public.ecr.aws/bitnami/wordpress:latest"
      namespace = local.name
      port_mappings = [
        {
          containerPort = 8080
          protocol      = "tcp"
        }
      ]
      essential = true
      environment = [
        {
          name  = "WORDPRESS_DATABASE_HOST"
          value = "wordpress-db.c786ycr4mzb8.us-east-1.rds.amazonaws.com"
        },
        {
          name  = "WORDPRESS_DATABASE_PORT_NUMBER"
          value = "3306"
        },
        {
          name  = "WORDPRESS_DATABASE_USER"
          value = "wordpress"
        },
        {
          name  = "WORDPRESS_DATABASE_PASSWORD"
          value = "#F[*y>W00Wbic4+_HfYUAy9tb~[:"
        },
        {
          name  = "WORDPRESS_DATABASE_PASSWORD"
          value = jsondecode(data.aws_secretsmanager_secret_version.db_password.secret_string)["password"]
        },
        {
          name  = "WORDPRESS_DATABASE_NAME"
          value = "wordpressdb"
        }
      ]
#      secrets = [
#        {
#          name      = "WORDPRESS_DATABASE_PASSWORD"
#          valueFrom = jsondecode(data.aws_secretsmanager_secret_version.db_password.secret_string)["password"]
#        }
#      ]
      readonly_root_filesystem = false
      mount_points = [
        {
          sourceVolume  = "wordpress"
          containerPath = "/bitnami/wordpress"
          readOnly      = false
        }
      ]
    }
  }
  volume = {
    wordpress = {
      file_system_id = module.efs.id
      #      root_directory          = "/bitnami/wordpress"
      transit_encryption      = "ENABLED"
      transit_encryption_port = 2999
      authorization_config = {
        access_point_id = module.efs.access_points
        iam             = "ENABLED"
      }
    }
  }

  load_balancer = {
    service = {
      target_group_arn = module.alb.target_groups["ex_ecs"].arn
      container_name   = local.name
      container_port   = 8080
    }
  }

  subnet_ids = module.vpc.private_subnets
  security_group_rules = {
    alb_ingress = {
      type                     = "ingress"
      from_port                = 8080
      to_port                  = 8080
      protocol                 = "tcp"
      description              = "Service port"
      source_security_group_id = module.alb.security_group_id
    }
    egress_all = {
      type        = "egress"
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  tags = local.tags
}

module "alb" {
  source  = "terraform-aws-modules/alb/aws"
  version = "~> 9.0"

  name = local.name

  load_balancer_type = "application"

  vpc_id  = module.vpc.vpc_id
  subnets = module.vpc.public_subnets

  # For example only
  enable_deletion_protection = false

  # Security Group
  security_group_ingress_rules = {
    all_http = {
      from_port   = 80
      to_port     = 80
      ip_protocol = "tcp"
      cidr_ipv4   = "0.0.0.0/0"
    }
  }
  security_group_egress_rules = {
    all = {
      ip_protocol = "-1"
      cidr_ipv4   = module.vpc.vpc_cidr_block
    }
  }

  listeners = {
    ex_http = {
      port     = 80
      protocol = "HTTP"

      forward = {
        target_group_key = "ex_ecs"
      }
    }
  }

  target_groups = {
    ex_ecs = {
      backend_protocol                  = "HTTP"
      backend_port                      = "8080"
      target_type                       = "ip"
      deregistration_delay              = 5
      load_balancing_cross_zone_enabled = true

      health_check = {
        enabled             = true
        healthy_threshold   = 5
        interval            = 30
        matcher             = "200"
        path                = "/"
        port                = "traffic-port"
        protocol            = "HTTP"
        timeout             = 5
        unhealthy_threshold = 2
      }

      # There's nothing to attach here in this definition. Instead,
      # ECS will attach the IPs of the tasks to this target group
      create_attachment = false
    }
  }

  tags = local.tags
}


module "db" {
  source = "terraform-aws-modules/rds/aws"

  identifier = "wordpress-db"

  engine               = "mysql"
  engine_version       = "8.0"
  family               = "mysql8.0" # DB parameter group
  major_engine_version = "8.0"      # DB option group
  allocated_storage    = 5
  instance_class       = "db.t3.small"

  db_name  = "wordpressdb"
  username = "wordpress"
  port     = "3306"

  db_subnet_group_name   = module.vpc.database_subnet_group
  vpc_security_group_ids = [module.security-group.security_group_id]

  skip_final_snapshot = true
  deletion_protection = false

  tags = local.tags

  cloudwatch_log_group_kms_key_id        = module.kms.key_arn
  cloudwatch_log_group_retention_in_days = 7
  copy_tags_to_snapshot                  = true
  create_cloudwatch_log_group            = true
  create_db_instance                     = true
  kms_key_id                             = module.kms.key_arn
  manage_master_user_password            = true
  master_user_secret_kms_key_id          = module.kms.key_arn
  publicly_accessible                    = true


}

module "security-group" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "5.1.0"

  name        = local.name
  description = "MySQL security group"
  vpc_id      = module.vpc.vpc_id

  # ingress
  ingress_with_cidr_blocks = [
    {
      from_port   = 3306
      to_port     = 3306
      protocol    = "tcp"
      description = "MySQL access from within VPC"
      cidr_blocks = module.vpc.vpc_cidr_block
    },
  ]

  tags = local.tags
}

#resource "aws_secretsmanager_secret_version" "example2" {
#  secret_id     = data.aws_secretsmanager_secret.by-arn.id
#  secret_string = jsondecode(data.aws_secretsmanager_secret_version.db_password.secret_string)["password"]
#}



#default user: user
#password: bitnami