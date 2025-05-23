provider "libvirt" {
  uri = var.libvirt_uri
}

resource "libvirt_volume" "bootstrap" {
  name           = "${var.cluster_id}-bootstrap"
  base_volume_id = var.base_volume_id
  pool           = var.pool
  # Bump this so it works for OKD too
  size = "34359738368"
}

resource "libvirt_ignition" "bootstrap" {
  name    = "${var.cluster_id}-bootstrap.ign"
  content = var.ignition_bootstrap
  pool    = var.pool
}

resource "libvirt_domain" "bootstrap" {
  name = "${var.cluster_id}-bootstrap"

  memory = var.libvirt_bootstrap_memory

  vcpu = "2"

  coreos_ignition = libvirt_ignition.bootstrap.id

  disk {
    volume_id = libvirt_volume.bootstrap.id
  }

  console {
    type        = "pty"
    target_port = 0
  }

  cpu {
    mode = "host-passthrough"
  }

  network_interface {
    network_id = var.network_id
    hostname   = "${var.cluster_id}-bootstrap.${var.cluster_domain}"
    addresses  = [var.libvirt_bootstrap_ip]
  }

  graphics {
    type        = "vnc"
    listen_type = "address"
  }
}

