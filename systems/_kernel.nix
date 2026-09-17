##! Exact kernel selection shared by current bootable system variants.
{pkgs, ...}: {
  aos.kernel.packageRoot = pkgs.linux;

  aos.abilities.instances."linux:kernel-provider".implementation = "linux:kernel";

  aos.abilities.bindings."kernel:linux" = {
    request = "aos:kernel";
    implementation = "linux:kernel";
    providerInstance = "linux:kernel-provider";
    slot = "kernel";
  };
}
