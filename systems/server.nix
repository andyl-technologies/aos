##! systems/server.nix — Server golden image
##!
##! Builds a server image suitable for cloud/datacenter deployment.
##! The image fixes only boot/storage capabilities. Runtime role, services,
##! security policy, users, and desired packages come from host.nix.
##!
##! Buildable with empty config root — all required options have defaults.
{lib, ...}: {
  # Image capability: immutable root with writable state provisioned on /var.
  aos.filesystems.zfs.enable = lib.mkDefault false;
  aos.filesystems.rootFsType = lib.mkDefault "erofs";
  aos.filesystems.rootReadOnly = lib.mkDefault true;

  # Image capability: support encrypted state/swap selected by host policy.
  aos.kernel.modules = ["dm-crypt" "aes" "xts"];
}
