##! Bounded bootable-base image budgets for server and edge variants.
{
  lib,
  pkgs,
  ...
}: {
  # OCI images use a separate package slice and closure budget.
  aos.image.budgets.maxRootMiB = lib.mkDefault 640;
  # The checked x86 native closure is 903 MiB, including its compressed initrd.
  # Keep the independently defined target allowance on other architectures.
  aos.image.budgets.maxRuntimeClosureMiB = lib.mkIf (pkgs.stdenv.hostPlatform.constraints.cpu == "x86_64") (lib.mkDefault 960);
  aos.image.budgets.maxDevelopmentPayloadMiB = lib.mkDefault 48;
  aos.image.budgets.maxDownloadMiB = lib.mkDefault 768;
  # VHD block allocation adds fixed overhead above 800 MiB on AArch64.
  aos.image.budgets.maxConvertedDownloadMiB =
    lib.mkIf (pkgs.stdenv.hostPlatform.constraints.cpu == "aarch64") (lib.mkDefault 801);
}
