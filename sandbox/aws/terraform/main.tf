###############################################################################
# PhishGuard isolated detonation sandbox on AWS.
#
# Creates a DEDICATED VPC (not connected to any of your other infrastructure),
# a locked-down EC2 instance that runs the dispatcher, and the networking so it
# can reach the internet (to open links) but has no route to your private
# resources. Because the VPC has no peering, VPN, or transit gateway, there is
# simply nothing internal for a compromised link to reach.
###############################################################################

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

# Latest Amazon Linux 2023 image.
data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

# --- Dedicated, isolated network -------------------------------------------
resource "aws_vpc" "sandbox" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "phishguard-sandbox-vpc" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.sandbox.id
  tags   = { Name = "phishguard-sandbox-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.sandbox.id
  cidr_block              = "10.42.1.0/24"
  map_public_ip_on_launch = true
  tags                    = { Name = "phishguard-sandbox-subnet" }
}

resource "aws_route_table" "rt" {
  vpc_id = aws_vpc.sandbox.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = { Name = "phishguard-sandbox-rt" }
}

resource "aws_route_table_association" "assoc" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.rt.id
}

# A network ACL that explicitly DENIES the EC2 from talking to private IP
# ranges, as defence-in-depth on top of the dedicated VPC.
resource "aws_network_acl" "nacl" {
  vpc_id     = aws_vpc.sandbox.id
  subnet_ids = [aws_subnet.public.id]

  # Inbound: the dispatcher port from the allowed source, plus return traffic.
  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = var.allowed_cidr
    from_port  = 9000
    to_port    = 9000
  }
  ingress {
    protocol   = "tcp"
    rule_no    = 110
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  # Outbound: DENY all private ranges first, then ALLOW the rest (the internet).
  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "deny"
    cidr_block = "10.0.0.0/8"
    from_port  = 0
    to_port    = 0
  }
  egress {
    protocol   = "-1"
    rule_no    = 110
    action     = "deny"
    cidr_block = "172.16.0.0/12"
    from_port  = 0
    to_port    = 0
  }
  egress {
    protocol   = "-1"
    rule_no    = 120
    action     = "deny"
    cidr_block = "192.168.0.0/16"
    from_port  = 0
    to_port    = 0
  }
  egress {
    protocol   = "-1"
    rule_no    = 200
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = { Name = "phishguard-sandbox-nacl" }
}

# --- Security group: only the backend may call the dispatcher --------------
resource "aws_security_group" "sg" {
  name        = "phishguard-sandbox-sg"
  description = "Allow dispatcher port only from the backend; outbound web only."
  vpc_id      = aws_vpc.sandbox.id

  ingress {
    description = "Dispatcher API, restricted to the backend IP or VPN."
    from_port   = 9000
    to_port     = 9000
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
  }

  # Outbound: HTTP/HTTPS (to open links) and DNS only.
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "phishguard-sandbox-sg" }
}

# --- IAM: allow SSM management so we need NO inbound SSH -------------------
resource "aws_iam_role" "role" {
  name = "phishguard-sandbox-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "profile" {
  name = "phishguard-sandbox-profile"
  role = aws_iam_role.role.name
}

# --- The instance ----------------------------------------------------------
resource "aws_instance" "sandbox" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.sg.id]
  iam_instance_profile   = aws_iam_instance_profile.profile.name
  user_data              = file("${path.module}/../user-data.sh")

  metadata_options {
    http_tokens = "required" # enforce IMDSv2
  }

  root_block_device {
    volume_size = 20
    encrypted   = true
  }

  tags = { Name = "phishguard-sandbox" }
}

output "sandbox_public_ip" {
  value = aws_instance.sandbox.public_ip
}

output "sandbox_url" {
  description = "Set SANDBOX_URL on the backend to this value."
  value       = "http://${aws_instance.sandbox.public_ip}:9000"
}
