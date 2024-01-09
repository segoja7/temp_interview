data "aws_availability_zones" "available" {}

#data "aws_secretsmanager_secrets" "example" {
#  filter {
#    name   = module.db.db_instance_master_user_secret_arn
#    values = ["example"]
#  }
#}

data "aws_secretsmanager_secret" "by-arn" {
  arn = module.db.db_instance_master_user_secret_arn
}

data "aws_secretsmanager_secret_version" "db_password" {
  secret_id = data.aws_secretsmanager_secret.by-arn.id
  #  secret_string = jsonencode({ username : "admin", password : aws_directory_service_directory.test.password })
}



data "aws_region" "current" {}