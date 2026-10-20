##! Bounded bootable-base image budgets for server and edge variants.
{
  lib,
  pkgs,
  ...
}: let
  isX86 = pkgs.stdenv.hostPlatform.constraints.cpu == "x86_64";
in {
  # OCI images use a separate package slice and closure budget.
  aos.image.budgets.maxRootMiB = lib.mkDefault 640;
  # The checked x86 native closure is 903 MiB, including its compressed initrd.
  # Keep the independently defined target allowance on other architectures.
  aos.image.budgets.maxRuntimeClosureMiB = lib.mkIf isX86 (lib.mkDefault 960);
  aos.image.budgets.maxVerityMiB = lib.mkDefault 16;
  # Both checked x86 variants need 154 MiB. The boot executable additionally
  # embeds the kernel; two executables require bounded firmware headroom.
  aos.image.budgets.maxInitrdMiB = lib.mkIf isX86 (lib.mkDefault 160);
  aos.image.budgets.maxBootExecutableMiB = lib.mkIf isX86 (lib.mkDefault 200);
  aos.image.budgets.maxFirmwarePartitionMiB = lib.mkIf isX86 (lib.mkDefault 448);
  aos.image.budgets.maxDevelopmentPayloadMiB = lib.mkDefault 48;
  aos.image.budgets.maxDownloadMiB = lib.mkDefault 768;
}
