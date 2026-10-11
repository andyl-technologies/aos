##! Assigns the retained early-boot policy its independent native scope.
{
  imports = [./boot-policy.nix];
  aos.boot.stage = "initrd";
}
