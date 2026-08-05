##! systems/edge.nix — Edge/IoT golden image
##!
##! Builds an edge image for IoT and edge deployments (Jetson Nano,
##! Raspberry Pi, small appliances). The image fixes only boot, storage, and
##! evaluator-integrity capabilities. Runtime services, security policy, and
##! resource tuning come from authenticated host.nix (typically by enabling
##! aos.roles.edge).
##!
##! Buildable with empty config root — all required options have defaults.
{lib, ...}: {
  # Image capability: the evaluator, base module library, and activation
  # machinery live on a read-only EROFS root authenticated by dm-verity.
  aos.filesystems.zfs.enable = lib.mkDefault false;
  aos.filesystems.rootFsType = lib.mkDefault "erofs";
  aos.filesystems.rootReadOnly = lib.mkDefault true;
  aos.security.verity.enable = lib.mkDefault true;

  # The service modules predate host-time evaluation and default to enabled.
  # Give this policy-neutral image a lower-priority disabled baseline. A normal
  # host.nix assignment, or aos.roles.edge's mkDefault, overrides it without
  # rebuilding the image.
  aos.services.chrony.enable = lib.mkOverride 1500 false;
  aos.services.ssh.enable = lib.mkOverride 1500 false;
}
