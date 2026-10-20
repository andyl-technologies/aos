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

  carriers = [
    (aos.pkgs.aosMountExecutableCarrierForKernel aos.pkgs.linux)
    (aos.pkgs.aosMountSourceExecutableCarrierForKernel aos.pkgs.linux)
  ];
  carrierHasNativeSealingAndTargetData = carrier: let
    held = carrier.passthru;
  in
    carrier.system == "x86_64-linux"
    && held.targetSystem == "aarch64-linux"
    && held.kernel.drvPath == aos.pkgs.linux.drvPath
    && held.launcher.drvPath == aos.pkgs.systemd.drvPath
    && held.daemon.drvPath == aos.pkgs.aos-sandbox-mountd.drvPath
    && held.sealingKernel.drvPath == aos.pkgs.buildPackages.linux.drvPath
    && held.sealingTool.system == "x86_64-linux"
    && held.sealingRootfs.system == "x86_64-linux";

  nativeBuilder = image:
    image.system == "x86_64-linux" && builtins.isString image.drvPath;
in
  assert raw.IMAGE_ARCHITECTURE == "aarch64";
  assert raw.IMAGE_PLATFORM == "aarch64-linux";
  assert builtins.all nativeBuilder (builtins.attrValues images);
  assert nativeBuilder budgetCheck;
  assert builtins.all carrierHasNativeSealingAndTargetData carriers;
  assert !(builtins.elemAt carriers 0).passthru.sourceProviderCarrier;
  assert (builtins.elemAt carriers 1).passthru.sourceProviderCarrier; true
