##! Selects the package-owned fleet BPF-LSM policy loader.
{
  lib,
  pkgs,
  ...
}: {
  environment.systemPackages = [pkgs.aos];
  aos.security.ebpfLsm.enable = lib.mkDefault true;
}
