variable "iso_url" {
  type        = string
  description = "Path or URL to the Ubuntu Server installation ISO."
}

variable "iso_checksum" {
  type        = string
  description = "Checksum source for the Ubuntu Server ISO."
  default     = "file:https://releases.ubuntu.com/24.04/SHA256SUMS"
}

variable "ssh_username" {
  type        = string
  description = "SSH user created by the autoinstall configuration."
  default     = "ansible"
}

variable "ssh_private_key_file" {
  type        = string
  description = "Path to the private SSH key corresponding to the public key configured in http/user-data."
}

variable "output_directory" {
  type        = string
  description = "Directory where Packer writes the VMware VM."
  default     = "output"
}

variable "vmnet" {
  type        = string
  description = "VMware virtual network used by the generated VM."
  default     = "VMnet8"
}

variable "vm_name" {
  type        = string
  description = "Name of the base VMware VM."
  default     = "k3s-base-v2"
}

variable "cpus" {
  type    = number
  default = 4
}

variable "memory" {
  type    = number
  default = 8192
}

variable "disk_size" {
  type    = number
  default = 40000
}

variable "headless" {
  type    = bool
  default = false
}
