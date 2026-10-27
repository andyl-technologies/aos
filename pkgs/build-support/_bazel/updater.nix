##! Source-built resolver tools are confined to the explicit update command.
{
  pkgs,
  lib,
  generator,
}:
pkgs.mkDerivation {
  pname = "aos-bazel-rust-updater";
  version = "1";
  src = null;
  buildDeps = [pkgs.jq];
  runtimeDeps = [pkgs.python3 generator pkgs.rust pkgs.bash pkgs.coreutils pkgs.grep pkgs.sed];
  exportReferencesGraph.updater = [pkgs.python3 generator pkgs.rust pkgs.bash pkgs.coreutils pkgs.grep pkgs.sed];
  outputChecks.out = {};
  dontStrip = true;
  dontPatchELF = true;
  dontNukeRefs = true;
  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out/bin" "$out/libexec"
        cp ${../../../tools/bazel/metadata/update_rust.py} "$out/libexec/update_rust.py"
        cp ${../../../tools/bazel/metadata/optional_dependencies.py} "$out/libexec/optional_dependencies.py"
        jq -cS \
          --arg generator '${generator}/bin/cargo-bazel' \
          --arg cargo '${pkgs.rust}/bin/cargo' \
          --arg rustc '${pkgs.rust}/bin/rustc' \
          --arg path ${lib.escapeShellArg (lib.concatStringsSep ":" (map (tool: "${tool}/bin") [pkgs.rust pkgs.bash pkgs.coreutils pkgs.grep pkgs.sed]))} \
          '{schema_version: 1, generator: $generator, cargo: $cargo, rustc: $rustc, path: $path,
            closure: [.updater[] | {path, narHash}] | sort_by(.path)}' \
          "$NIX_ATTRS_JSON_FILE" > "$out/tool-config.json"
        cat > "$out/bin/aos-bazel-rust-update" <<SCRIPT
        #!${pkgs.bash}/bin/bash
        set -euo pipefail
        exec ${pkgs.python3}/bin/python3 "$out/libexec/update_rust.py" "\$@" --tool-config "$out/tool-config.json"
        SCRIPT
        chmod 0555 "$out/bin/aos-bazel-rust-update"
      '';
    }
  ];
}
