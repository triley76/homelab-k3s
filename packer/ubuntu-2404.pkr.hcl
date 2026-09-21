packer {
  required_plugins {
    vmware = {
      version = "~> 1"
      source  = "github.com/hashicorp/vmware"
    }
  }
}

source "vmware-iso" "k3s-base" {
  iso_url              = var.iso_url
  iso_checksum         = var.iso_checksum
  vm_name              = var.vm_name
  output_directory     = "${var.output_directory}/${var.vm_name}"
  guest_os_type        = "ubuntu-64"
  cpus                 = var.cpus
  memory               = var.memory
  disk_size            = var.disk_size
  network_adapter_type = "vmxnet3"
  headless             = var.headless

  vmx_data = {
    "serial0.present"        = "TRUE"
    "serial0.fileType"       = "file"
    "serial0.fileName"       = "install-console.log"
    "serial0.startConnected" = "TRUE"
  }

  vmx_data_post = {
    "ethernet0.connectionType" = "custom"
    "ethernet0.displayName"    = var.vmnet
    "ethernet0.vnet"           = var.vmnet
  }

  http_directory = "http"

  boot_wait = "30s"
  boot_command = [
    "c<wait>",
    "linux /casper/vmlinuz --- console=tty0 console=ttyS0,115200n8 autoinstall ds=\"nocloud-net;seedfrom=http://{{ .HTTPIP }}:{{ .HTTPPort }}/\"<enter><wait>",
    "initrd /casper/initrd<enter><wait>",
    "boot<enter>"
  ]

  communicator         = "ssh"
  ssh_username         = var.ssh_username
  ssh_private_key_file = var.ssh_private_key_file
  ssh_timeout          = "30m"

  shutdown_command = "sudo shutdown -P now"
}

build {
  sources = ["source.vmware-iso.k3s-base"]

  provisioner "shell" {
    inline = [
      "sudo apt-get update",
      "sudo apt-get install -y open-vm-tools curl",
      "sudo cloud-init clean --logs",
      "sudo rm -f /etc/machine-id",
      "sudo touch /etc/machine-id",
      "sudo truncate -s 0 /etc/machine-id"
    ]
  }
}
