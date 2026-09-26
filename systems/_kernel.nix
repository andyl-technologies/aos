##! Exact kernel selection shared by current bootable system variants.
{
  config,
  pkgs,
  ...
}: {
  aos.kernel.packageRoot = pkgs.linux;

  environment.systemPackages = [config.aos.kernel.packageRoot];
  aos.boot.initrd.packageRoots = [config.aos.kernel.packageRoot];

  aos.abilities.instances."linux:kernel-provider".implementation = "linux:kernel";

  aos.abilities.bindings."kernel:linux" = {
    request = "aos:kernel";
    implementation = "linux:kernel";
    providerInstance = "linux:kernel-provider";
    slot = "kernel";
  };
}
