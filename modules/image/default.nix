##! modules/image/default.nix — Disk image format module
##!
##! Provides aos.image options and wires system.build.image.{format} to
##! image builder derivations. The raw GPT image is the base format;
##! all others are converted from it via qemu-img.
##!
##! Supported formats:
##!   raw   — raw GPT disk image (base, bootable via dd or losetup)
##!   qcow2 — QEMU copy-on-write (KVM, OpenStack, Proxmox)
##!   vmdk  — VMware/vSphere
##!   vhd   — Azure/Hyper-V
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.aos.image;
  buildImage = import ./_builder.nix;

  rawImage = buildImage {
    inherit pkgs lib;
    system = { inherit config; };
    name = config.aos.system.name;
    inherit (cfg) diskSize bootSize rootSize;
  };

  # Convert a raw image to another format via qemu-img
  convertImage =
    format: formatFlag:
    pkgs.mkDerivation {
      name = "aos-image-${config.aos.system.name}-${format}";
      src = null;
      buildDeps = [ pkgs.qemu ];
      phases = [
        {
          name = "convert";
          script = ''
            mkdir -p $out
            qemu-img convert -f raw -O ${formatFlag} \
              ${rawImage}/aos-${config.aos.system.name}.img \
              $out/aos-${config.aos.system.name}.${format}
          '';
        }
      ];
      meta = {
        description = "AOS ${config.aos.system.name} image (${format})";
      };
    };
in
{
  options.aos.image = {
    ## Whether to build disk images for this system variant.
    enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Whether to build disk images for this system variant.";
    };
    ## Total raw disk image size.
    diskSize = lib.mkOption {
      type = lib.types.str;
      default = "16G";
      description = "Total raw disk image size.";
    };
    ## Boot partition size.
    bootSize = lib.mkOption {
      type = lib.types.str;
      default = "1500M";
      description = ''
        Boot partition size (kernel + initrd). Needs to hold the full
        initramfs — today's tier-ii initrd is ~700 MiB compressed
        because AOS packages carry bootstrap-toolchain references into
        their runtime closures; shrinking the initrd is a follow-up.
      '';
    };
    ## Root filesystem partition size.
    rootSize = lib.mkOption {
      type = lib.types.str;
      default = "8G";
      description = "Root filesystem partition size.";
    };
  };

  options.system.build.image = {
    raw = lib.mkOption {
      type = lib.types.package;
      description = "Raw GPT disk image (bootable via dd).";
    };
    qcow2 = lib.mkOption {
      type = lib.types.package;
      description = "QCOW2 image (QEMU/KVM, OpenStack, Proxmox).";
    };
    vmdk = lib.mkOption {
      type = lib.types.package;
      description = "VMDK image (VMware/vSphere).";
    };
    vhd = lib.mkOption {
      type = lib.types.package;
      description = "VHD image (Azure/Hyper-V).";
    };
  };

  config = lib.mkIf cfg.enable {
    system.build.image = {
      raw = rawImage;
      qcow2 = convertImage "qcow2" "qcow2";
      vmdk = convertImage "vmdk" "vmdk";
      vhd = convertImage "vhd" "vpc";
    };
  };
}
