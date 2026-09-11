# Evaluates a foreign image without executing target binaries. Image identity
# must describe the guest while assembly and budget checks use native tools.
let
  aos = import ../../. {
    system = "x86_64-linux";
    crossSystem = "aarch64-linux";
  };
  system = aos.mkSystem ../../systems/server.nix;
  images = system.config.system.build.image;
  raw = images.raw;
  budgetCheck = system.config.system.build.checks.image-budget;

  nativeBuilder = image:
    image.system == "x86_64-linux" && builtins.isString image.drvPath;
in
  assert raw.IMAGE_ARCHITECTURE == "aarch64";
  assert raw.IMAGE_PLATFORM == "aarch64-linux";
  assert raw.UEFI_FALLBACK_FILENAME == "BOOTAA64.EFI";
  assert raw.SDBOOT_FILENAME == "systemd-bootaa64.efi";
  assert builtins.all nativeBuilder (builtins.attrValues images);
  assert nativeBuilder budgetCheck; true
