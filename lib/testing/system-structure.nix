# lib/testing/system-structure.nix — focused system output contract checks.
#
# This check deliberately avoids committed snapshots of rendered systems.
# Nix derivation references carry their output context, so realization resolves
# the exact store paths and retains their closures without copying generated
# units, activation scripts, or package identities into source control.
{
  pkgs,
  lib,
  system,
  variant ? "system",
}: let
  config = system.config;
  manifest = config.system.build.configManifest;
  systemdUnits = config.system.build.systemdSystemUnits;
  contextualOutputs = [
    systemdUnits
    config.system.build.etcDump
    config.system.build.activateScript
    config.environment.etc."os-release".source
    config.aos.config.evalAtBoot.baseLib
  ];
  hasOutputContext = value:
    builtins.attrNames (builtins.getContext (toString value)) != [];
  manifestSystemdPaths =
    builtins.map
    (path: lib.removePrefix "systemd/system/" path)
    (builtins.attrNames (lib.filterAttrs
      (path: _entry: lib.hasPrefix "systemd/system/" path)
      manifest.etc));
  manifestSystemdPathsText = lib.concatStringsSep "\n" manifestSystemdPaths + "\n";
in
  assert builtins.isAttrs manifest;
  assert !(lib.isDerivation manifest);
  assert builtins.all hasOutputContext contextualOutputs;
    pkgs.mkDerivation {
      pname = "aos-system-structure-${variant}";
      version = "0";
      src = null;
      buildDeps = [
        systemdUnits
        pkgs.coreutils
        pkgs.diffutils
        pkgs.findutils
      ];

      expectedSystemdPaths = manifestSystemdPathsText;
      passAsFile = ["expectedSystemdPaths"];

      phases = [
        {
          name = "check";
          script = ''
            set -eu
            ${pkgs.findutils}/bin/find "${systemdUnits}" \
              \( -type f -o -type l \) -printf '%P\n' \
              | ${pkgs.coreutils}/bin/sort > actual-systemd-paths
            ${pkgs.coreutils}/bin/sort "$expectedSystemdPathsPath" \
              > expected-systemd-paths
            ${pkgs.diffutils}/bin/diff -u \
              expected-systemd-paths actual-systemd-paths
            mkdir -p "$out"
            echo PASS > "$out/result"
          '';
        }
      ];

      meta.description = "Focused rendered-system structure check (${variant})";
    }
