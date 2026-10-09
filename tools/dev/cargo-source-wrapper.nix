# Use the same verified workspace vendor in interactive and direct Cargo calls.
{pkgs}: let
  vendor = pkgs.crucible-controller.passthru.cargoDeps;
  config =
    pkgs.runCommand "aos-dev-cargo-source-config" {
      buildDeps = [pkgs.sed];
    } ''
      # Preserve every generated registry/git mapping from the locked vendor.
      # This generated output leaves both the checkout and user Cargo cache alone.
      ${pkgs.sed}/bin/sed 's|@vendor@|${vendor}|g' \
        ${vendor}/.cargo/config.toml > "$out/config.toml"
    '';
in
  pkgs.writeShellScriptBin "cargo" ''
    arguments=("$@")
    # Cargo's external Clippy delegation omits global --config options.
    # Pass the same source selection in its forwarded subcommand arguments.
    for ((index = 0; index < ''${#arguments[@]}; index++)); do
      case "''${arguments[index]}" in
        --color|--config|-C|-Z|--explain) ((index += 1)) ;;
        -*) ;;
        clippy)
          arguments=(
            "''${arguments[@]:0:index+1}"
            --config ${config}/config.toml
            "''${arguments[@]:index+1}"
          )
          break
          ;;
        *) break ;;
      esac
    done
    exec ${pkgs.rust}/bin/cargo --config ${config}/config.toml "''${arguments[@]}"
  ''
