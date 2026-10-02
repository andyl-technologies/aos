##! systems/server.nix — Server golden image
##!
##! Builds a server image suitable for cloud/datacenter deployment.
##! The image fixes only boot/storage capabilities. Runtime role, services,
##! security policy, users, and desired packages come from host.nix.
##!
##! Buildable with empty config root — all required options have defaults.
{
  lib,
  pkgs,
  ...
}: {
  # Image capability: immutable root with writable state provisioned on /var.
  aos.filesystems.zfs.enable = lib.mkDefault false;
  aos.filesystems.rootFsType = lib.mkDefault "erofs";
  aos.filesystems.rootReadOnly = lib.mkDefault true;
  # F1 is part of the production image contract: the base library/evaluator
  # root is authenticated by the roothash carried in the signed/measured UKI.
  # Specialized writable-root test variants may override this mkDefault.
  aos.security.verity.enable = lib.mkDefault true;
  aos.image.budgets = {
    # The AArch64 root image measures 647 MiB with the complete runtime; its
    # uncompressed kernel also makes the UKIs, the ESP that retains normal and
    # recovery UKIs, and the compressed raw disk larger than on x86_64.
    maxRootMiB =
      if pkgs.stdenv.hostPlatform.constraints.cpu == "aarch64"
      then 768
      else 640;
    maxUkiMiB = lib.mkIf (pkgs.stdenv.hostPlatform.constraints.cpu == "aarch64") 224;
    # The ESP retains the normal UKI and both recovery UKIs, each embedding
    # the uncompressed AArch64 kernel, plus bootloader and FAT headroom.
    maxEspMiB = lib.mkIf (pkgs.stdenv.hostPlatform.constraints.cpu == "aarch64") 768;
    maxVerityMiB = 16;
    # The recovery-capable runtime initrd measures 140 MiB on x86_64 with the
    # complete aos, apm, and package-runtime CLIs; keep headroom for growth.
    maxInitrdMiB = 160;
    maxDownloadMiB =
      if pkgs.stdenv.hostPlatform.constraints.cpu == "aarch64"
      then 1280
      else 768;
    # Converted formats carry the full ESP and root payload on AArch64.
    maxConvertedDownloadMiB =
      lib.mkIf
      (pkgs.stdenv.hostPlatform.constraints.cpu == "aarch64") (lib.mkDefault 1792);
  };

  # The service modules retain backwards-compatible enabled defaults. Keep
  # the golden image policy-neutral at a weaker priority so authenticated
  # host.nix or aos.roles.server/aos.roles.edge can select runtime services
  # without rebuilding the image.
  aos.services.chrony.enable = lib.mkOverride 1500 false;
  aos.services.ssh.enable = lib.mkOverride 1500 false;
  aos.image.hostConfigClosures = [pkgs.chrony pkgs.openssh];

  # Image capability: support encrypted state/swap selected by host policy.
  aos.kernel.modules = ["dm-crypt" "aes" "xts"];
}
