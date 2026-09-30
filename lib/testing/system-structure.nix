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
  outputs = [manager config.system.build.etcDump config.environment.etc."os-release".source];
  hasContext = value: builtins.attrNames (builtins.getContext (toString value)) != [];
in
  assert builtins.all hasContext outputs;
    pkgs.mkDerivation {
      pname = "aos-system-structure-${variant}";
      version = "0";
      src = null;
      buildDeps = outputs ++ [pkgs.coreutils pkgs.grep];
      expectedSystemdPaths = lib.concatStringsSep "\n" renderedPaths + "\n";
      passAsFile = ["expectedSystemdPaths"];
      phases = [
        {
          name = "check";
          script = ''
            set -eu
            [ -d "${units}" ]
            [ -d "${manager}/systemd-presets" ]
            [ -s "${config.system.build.etcDump}" ]
            [ -s "${config.environment.etc."os-release".source}" ]
            while IFS= read -r path; do
              [ -z "$path" ] || [ -e "${units}/$path" ] || [ -L "${units}/$path" ]
            done < "$expectedSystemdPathsPath"
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
