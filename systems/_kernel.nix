##! Exact kernel selection shared by current bootable system variants.
{
  config,
  lib,
  pkgs,
  ...
}: let
  kernel = lib.abilities.interfaces.kernelPlatform.interfaces.kernel;
  configured = config.aos.abilities.environment != null;
in {
  aos.kernel.packageRoot = pkgs.linux;

  environment.systemPackages = [config.aos.kernel.packageRoot];
  aos.boot.initrd.packageRoots = [config.aos.kernel.packageRoot];

  aos.abilities.instances = lib.mkMerge [
    {"linux:kernel-provider".implementation = "linux:kernel";}
    (lib.mkIf configured {kernel = {};})
  ];

  aos.abilities.requirementTemplates.kernel = {
    description = "Requires the system's package-owned kernel artifact provider.";
    interface = kernel.identity.name;
    inherit (kernel.identity) abi descriptor;
  };
  aos.abilities.requests = lib.mkIf configured {
    kernel = {
      requirement = "kernel";
      consumer = "kernel";
      parameters = true;
    };
  };

  aos.abilities.bindings."kernel:linux" = {
    request = "aos:kernel";
    implementation = "linux:kernel";
    providerInstance = "linux:kernel-provider";
    slot = "kernel";
  };
}
