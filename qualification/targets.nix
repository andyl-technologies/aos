##! Reference configurations are qualification requirements, not passing claims.
let
  disk = platform: machine: acceleration: {
    id = "disk-${platform}";
    inherit platform;
    kind = "image";
    required = true;
    configuration = {
      inherit machine acceleration;
      firmware = "aos-edk2-uefi";
      firmware_state = "persistent";
      tpm = "2.0-persistent";
      storage = "virtio-single-disk";
      network = "virtio-single-nic";
      vcpus = "2";
      memory_mib = "8192";
      disk_mib = "32768";
      security = "external-secureboot-measuredboot-verity-encrypted-state-recovery";
    };
  };
  container = platform: {
    id = "container-${platform}";
    inherit platform;
    kind = "container";
    required = true;
    configuration = {
      runtime = "aos-containerd-runc";
      workload = "persistent-network-service";
    };
  };
in [
  (disk "x86_64-linux" "q35" "kvm")
  (disk "aarch64-linux" "virt" "tcg-functional-only")
  (container "x86_64-linux")
  (container "aarch64-linux")
]
