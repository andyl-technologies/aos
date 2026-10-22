# The guard and immutable unit inventory must retain the selected manager.
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
      ${pkgs.python3}/bin/python3 - ${funded.config.system.build.toplevel} <<'PY'
      import os
      import re
      import sys

      toplevel = sys.argv[1]
      units = os.readlink(os.path.join(toplevel, "systemd-units"))
      assert re.fullmatch(r"/nix/store/[0-9a-z]{32}-[^/]+", units), units
      assert os.path.isdir(units), units

      # This mirrors the physical resolver's layout contract without following
      # an extra manager-output hop or accepting a regular inventory leaf.
      for directory, directories, names in os.walk(units):
          if directory == units and "nix-support" in directories:
              directories.remove("nix-support")
          for name in names:
              path = os.path.join(directory, name)
              assert os.path.islink(path), path
              assert os.path.exists(path), path

      for name in ("aos-sandboxd.service", "aoscomponents.slice"):
          target = os.readlink(os.path.join(units, name))
          assert re.fullmatch(r"/nix/store/[0-9a-z]{32}-[^/]+/" + re.escape(name), target), target
      PY

      mkdir -p "$out"
      printf '%s\n' 'selected manager stage0 contract passed' > "$out/result"
    ''
