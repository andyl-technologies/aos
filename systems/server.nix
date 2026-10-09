##! systems/server.nix — Server golden image
##!
##! Builds a server image suitable for cloud/datacenter deployment.
##! The image fixes only boot/storage capabilities. Runtime role, services,
##! security policy, users, and desired packages come from host.nix.
##!
##! Buildable with empty config root — all required options have defaults.
{
  lib,
  packageModulesAvailable ? false,
  pkgs,
  ...
}: {
  imports =
    lib.optionals (!packageModulesAvailable) [../pkgs/system/_aos-host-policy/baseline/boot-policy.nix]
    ++ [
      ./_artifact-backend.nix
      ./_base-packages.nix
      ./_full-host-budgets.nix
      ./_image-builder.nix
      ./_kernel.nix
      ./_system-manager.nix
    ];

  # Image capability: immutable root with writable state provisioned on /var.
  aos.image.enable = true;
  aos.filesystems.zfs.enable = lib.mkDefault false;
  # The signed/measured boot executable authenticates the evaluator's root.
  aos.filesystems.rootFsType = lib.mkDefault "erofs";
  aos.filesystems.rootReadOnly = lib.mkDefault true;

  # Arm's uncompressed kernel and complete runtime need the measured upstream
  # server allowances. Keep edge policy and the native x86 allowances separate.
  aos.image.budgets = lib.mkIf (pkgs.stdenv.hostPlatform.constraints.cpu == "aarch64") {
    maxRootMiB = 768;
    maxBootExecutableMiB = 224;
    maxFirmwarePartitionMiB = 768;
    maxDownloadMiB = 1280;
    maxConvertedDownloadMiB = lib.mkDefault 1792;
  };

  # The service modules retain backwards-compatible enabled defaults. Keep
  # the golden image policy-neutral at a weaker priority so authenticated
  # host.nix or aos.roles.server/aos.roles.edge can select runtime services
  # without rebuilding the image.
  aos.activation.stages.host.configuration = ["${pkgs.aos-host-policy.module}/baseline/server.nix"];

  # Image capability: support encrypted state/swap selected by host policy.
}
