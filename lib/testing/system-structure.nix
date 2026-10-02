##! Checks actual image assembly artifacts and retained manager render inputs.
{
  pkgs,
  lib,
  system,
  variant ? "system",
}: let
  config = system.config;
  manager = config.system.build.managerConfiguration;
  units = "${manager}/systemd-units";
  renderedPaths =
    map (path: lib.removePrefix "systemd/system/" path)
    (builtins.attrNames config.system.build.systemdEtcEntries);
  bootstrapServices = import ../../pkgs/system/_systemd-abilities/bootstrap-services.nix {
    inherit config lib pkgs;
  };
  outputs = [manager config.system.build.etcDump config.environment.etc."os-release".source];
  hasContext = value: builtins.attrNames (builtins.getContext (toString value)) != [];
in
  assert builtins.all hasContext outputs;
    pkgs.mkDerivation {
      pname = "aos-system-structure-${variant}";
      version = "0";
      src = null;
      buildDeps = outputs ++ [pkgs.coreutils pkgs.diffutils pkgs.findutils pkgs.grep pkgs.buildPackages.systemd];
      expectedSystemdPaths = lib.concatStringsSep "\n" (renderedPaths ++ ["nix-support/aos-target-platform"]) + "\n";
      bootstrapServicesJSON = builtins.toJSON bootstrapServices;
      passAsFile = ["expectedSystemdPaths" "bootstrapServicesJSON"];
      phases = [
        {
          name = "check";
          script = ''
            set -eu
            [ -d "${units}" ]
            [ -d "${manager}/systemd-presets" ]
            [ -s "${config.system.build.etcDump}" ]
            [ -s "${config.environment.etc."os-release".source}" ]
            # Native bootstrap units supplement the declarative image units.
            # Compare their exact union so undeclared extra files also fail.
            ${pkgs.buildPackages.systemd}/bin/aos-service-handler render \
              --output-dir expected-bootstrap-units < "$bootstrapServicesJSONPath"
            ${pkgs.findutils}/bin/find expected-bootstrap-units \
              \( -type f -o -type l \) -printf '%P\n' > bootstrap-systemd-paths
            cat "$expectedSystemdPathsPath" bootstrap-systemd-paths \
              | ${pkgs.coreutils}/bin/sort -u > expected-systemd-paths
            ${pkgs.findutils}/bin/find "${units}/" \
              \( -type f -o -type l \) -printf '%P\n' \
              | ${pkgs.coreutils}/bin/sort > actual-systemd-paths
            ${pkgs.diffutils}/bin/diff -u expected-systemd-paths actual-systemd-paths
            if ${pkgs.grep}/bin/grep -r '#aos-jobscript:' "${units}"; then
              echo 'unresolved job-script reference in manager output' >&2
              exit 1
            fi
            ${pkgs.grep}/bin/grep -qx 'disable \*' "${manager}/systemd-presets/99-aos-default.preset"
            mkdir -p "$out"
            echo PASS > "$out/result"
          '';
        }
      ];
      meta.description = "Rendered manager and image assembly artifact contract (${variant})";
    }
