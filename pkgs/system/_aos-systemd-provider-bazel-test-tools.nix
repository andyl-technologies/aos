##! Supplies only the source-built Nix suite used by the boot-runtime unit tests.
{
  mkDerivation,
  lib,
  bash,
  coreutils,
  nix,
  jq,
}: let
  tools = [bash coreutils nix];
in
  mkDerivation {
    pname = "aos-bazel-systemd-provider-test-tools";
    version = "1";
    src = null;
    sharedBuildCache = false;
    buildDeps = [jq];
    outputChecks.out = {};
    exportReferencesGraph.tools = tools;
    dontStrip = true;
    dontPatchELF = true;
    dontNukeRefs = true;
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          jq -cS '{schema: 1, closure: [.tools[] | {path, narHash}] | sort_by(.path)}' \
            "$NIX_ATTRS_JSON_FILE" > "$out/closure.json"
          cat > "$out/test-setup" <<'SETUP'
          #!${bash}/bin/bash
          set -euo pipefail
          export PATH=${lib.escapeShellArg (lib.makeBinPath tools)}
          export AOS_NIX_STORE=${nix}/bin/nix-store
          export AOS_NIX_INSTANTIATE=${nix}/bin/nix-instantiate
          exec "$@"
          SETUP
          chmod +x "$out/test-setup"
          cat > "$out/BUILD.bazel" <<'BUILD'
          exports_files(["test-setup", "closure.json"], visibility = ["//visibility:public"])
          BUILD
          touch "$out/REPO.bazel"
        '';
      }
    ];
  }
