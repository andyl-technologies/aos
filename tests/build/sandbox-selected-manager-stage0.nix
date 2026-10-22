# The signed guard must pin the same selected manager that the rootfs installs.
{
  lib,
  pkgs,
  systems,
  ...
}: let
  funded = import ../fleet/_sandbox-funded-system.nix {inherit lib pkgs systems;};
  fundedProduction = import ../fleet/_sandbox-funded-system.nix {
    inherit lib pkgs systems;
    releaseAdmission = false;
  };
  production = systems.server-secureboot-lockdown.extendModules {
    modules = [
      {
        aos.security.selinux = {
          enable = true;
          bootMode = "immutable-stage0";
        };
      }
    ];
  };
  matchesSelectedManager = system:
    toString system.config.aos.boot.initrd.stage0.passthru.systemd
    == toString system.config.aos.manager.selected.package;
in
  assert matchesSelectedManager production;
  assert matchesSelectedManager funded;
  assert matchesSelectedManager fundedProduction;
  assert fundedProduction.config.aos.boot.initrd.stage0.passthru.admissionUnit == "aos-selinux-stage0-hold.target";
    pkgs.runCommand "sandbox-selected-manager-stage0-contract" {} ''
      mkdir -p "$out"
      printf '%s\n' 'selected manager stage0 contract passed' > "$out/result"
    ''
