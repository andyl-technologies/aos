# Retained Linux CPL3/no-child/exec-child/refusal probe, separate from the ROM.
{
  pkgs,
  lib,
}:
import ./phase2-qemu-whitebox-out-resume.nix {
  inherit pkgs lib;
  profile = "linux";
}
