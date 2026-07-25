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
}: let
  cfg = config.aos.image;
  buildImage = import ./_builder.nix;

  rawImage = buildImage {
    inherit pkgs lib;
    system = {inherit config;};
    name = config.aos.system.name;
  };

  # Convert a raw image to another format via qemu-img
  convertImage = format: formatFlag:
    pkgs.mkDerivation {
      name = "aos-image-${config.aos.system.name}-${format}";
      src = null;
      buildDeps = [pkgs.qemu];
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
in {
  options.aos.image = {
    ## Whether to build disk images for this system variant.
    enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Whether to build disk images for this system variant.";
    };

    erofsCompressionLevel = lib.mkOption {
      type = lib.types.int;
      default = 19;
      description = ''
        Zstandard compression level used for EROFS root images. Production
        keeps level 19 for distribution size; VM-test variants may select a
        faster level without changing the filesystem or boot semantics.
      '';
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

  options.system.build.uki = lib.mkOption {
    type = lib.types.package;
    description = ''
      The assembled Unified Kernel Image (`.efi`) written to the image's
      ESP. Secure Boot signed when `aos.boot.secureBoot.enable` is set.
      Exposed so it can be published (`apr publish --image`) and have its
      Secure Boot facts cataloged (RFC-0006 phase 4).
    '';
  };

  config = lib.mkIf cfg.enable {
    system.build.image = {
      raw = rawImage;
      qcow2 = convertImage "qcow2" "qcow2";
      vmdk = convertImage "vmdk" "vmdk";
      vhd = convertImage "vhd" "vpc";
    };
    system.build.uki = rawImage.uki;
  };
}
