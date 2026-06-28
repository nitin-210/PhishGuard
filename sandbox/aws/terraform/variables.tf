variable "region" {
  description = "AWS region to deploy the sandbox in."
  type        = string
  default     = "us-east-1"
}

variable "instance_type" {
  description = "EC2 size. t3.small is enough for occasional detonations."
  type        = string
  default     = "t3.small"
}

variable "allowed_cidr" {
  description = "The ONLY source allowed to call the sandbox (your backend's public IP as a /32, or your VPN range). Do NOT use 0.0.0.0/0."
  type        = string
}
