##! Selects the package-owned fleet BPF-LSM policy loader.
{
  lib,
  pkgs,
  ...
}: {
  environment.systemPackages = [pkgs.aos-ebpf-lsm-policy];
  aos.security.ebpfLsm.enable = lib.mkDefault true;
}
