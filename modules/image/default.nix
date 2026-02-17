##! modules/image/default.nix — Disk image builder module
##!
##! Provides aos.image options and wires system.build.image to the
##! builder derivation. System variants set image sizing options;
##! the builder produces a bootable GPT disk image.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.image;
  buildImage = import ./builder.nix;
in {
  options.aos.image = {
    ## Whether to build a disk image for this system variant.
    enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Whether to build a disk image for this system variant.";
    };
    ## Total raw disk image size.
    diskSize = lib.mkOption {
      type = lib.types.str;
      default = "16G";
      description = "Total raw disk image size.";
    };
    ## EFI System Partition size.
    espSize = lib.mkOption {
      type = lib.types.str;
      default = "1G";
      description = "EFI System Partition size.";
    };
    ## Root filesystem partition size.
    rootSize = lib.mkOption {
      type = lib.types.str;
      default = "8G";
      description = "Root filesystem partition size.";
    };
  };

  ## The bootable disk image derivation for this system variant.
  options.system.build.image = lib.mkOption {
    type = lib.types.package;
    description = "The bootable disk image derivation for this system variant.";
  };

  config = lib.mkIf cfg.enable {
    system.build.image = buildImage {
      inherit pkgs lib;
      system = {inherit config;};
      name = config.aos.system.variant;
      inherit (cfg) diskSize espSize rootSize;
    };
  };
}
