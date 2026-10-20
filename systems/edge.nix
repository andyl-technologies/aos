##! systems/edge.nix — Edge/IoT golden image
##!
##! Builds an edge image for IoT and edge deployments (Jetson Nano,
##! Raspberry Pi, small appliances). The image fixes only boot, storage, and
##! evaluator-integrity capabilities. Runtime services, security policy, and
##! resource tuning come from authenticated host.nix (typically by enabling
##! aos.roles.edge).
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

  # Image capability: the evaluator, base module library, and activation
  # machinery live on a read-only EROFS root authenticated by dm-verity.
  aos.image.enable = true;
  aos.filesystems.zfs.enable = lib.mkDefault false;
  aos.filesystems.rootFsType = lib.mkDefault "erofs";
  aos.filesystems.rootReadOnly = lib.mkDefault true;

  # VHD block allocation adds fixed overhead above 800 MiB on AArch64.
  aos.image.budgets.maxConvertedDownloadMiB =
    lib.mkIf (pkgs.stdenv.hostPlatform.constraints.cpu == "aarch64") (lib.mkDefault 801);

  # The service modules predate host-time evaluation and default to enabled.
  # Give this policy-neutral image a lower-priority disabled baseline. A normal
  # host.nix assignment, or aos.roles.edge's mkDefault, overrides it without
  # rebuilding the image.
  aos.activation.stages.host.configuration = ["${pkgs.aos-host-policy.module}/baseline/edge.nix"];
}
