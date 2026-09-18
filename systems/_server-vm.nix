##! Source-backed server variant for direct-kernel VM checks.
{lib, ...}: {
  imports = [./server.nix];

  aos.filesystems.rootFsType = lib.mkForce "ext4";
  aos.security.verity.enable = lib.mkForce false;
}
