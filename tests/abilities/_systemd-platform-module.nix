##! Test adapter for the authenticated systemd package module.
args@{pkgs, ...}:
import ../../pkgs/system/_systemd-abilities/platform/system.nix (
  args
  // {
    packageArtifactFor = selector: let
      packageName =
        if selector.package == "self"
        then "systemd"
        else selector.package;
      package = pkgs.${packageName};
    in
      package.${selector.output} or package;
  }
)
