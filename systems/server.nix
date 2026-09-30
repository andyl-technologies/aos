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
  aos.filesystems.rootFsType = lib.mkDefault "erofs";
  aos.filesystems.rootReadOnly = lib.mkDefault true;
  # F1 is part of the production image contract: the base library/evaluator
  # root is authenticated by the roothash carried in the signed/measured UKI.
  # Specialized writable-root test variants may override this mkDefault.
  aos.image.budgets = {
    maxVerityMiB = 16;
    maxInitrdMiB = 132;
    maxBootExecutableMiB = 160;
    maxFirmwarePartitionMiB = 384;
  };

  # The service modules retain backwards-compatible enabled defaults. Keep
  # the golden image policy-neutral at a weaker priority so authenticated
  # host.nix or aos.roles.server/aos.roles.edge can select runtime services
  # without rebuilding the image.
  aos.activation.stages.host.configuration = ["${pkgs.aos-host-policy.module}/baseline/server.nix"];
  aos.image.hostConfigClosures = [pkgs.chrony pkgs.openssh];

  # Image capability: support encrypted state/swap selected by host policy.
}
