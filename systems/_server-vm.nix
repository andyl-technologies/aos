##! Source-backed server variant for direct-kernel VM checks.
{...}: let
  policy = builtins.path {
    path = ./_server-vm-policy.nix;
    name = "aos-server-vm-policy.nix";
  };
  storageLayout = import ../pkgs/system/_systemd-abilities/testing/storage-layout.nix {};
in {
  imports = [./server.nix policy storageLayout.configurationSource];

  # The image builder and both replayed stages must agree on the test disk's
  # root contract; otherwise initrd services require an absent verity guard.
  aos.activation.stages.initrd.configuration = [policy];
  aos.activation.stages.host.configuration = [policy storageLayout.configurationSource];
}
