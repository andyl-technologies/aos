##! Authored server baseline replayed before host operator configuration.
{lib, ...}: {
  imports = [./common.nix];
  aos.services.chrony.enable = lib.mkOverride 1500 false;
  aos.services.ssh.enable = lib.mkOverride 1500 false;
  aos.kernel.modules = ["dm-crypt" "aes" "xts"];
}
