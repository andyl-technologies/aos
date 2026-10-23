##! Exposes the source-built Worker bundler and every generator's runtime closure.
{pkgs}: let
  bundler = builtins.path {
    path = ../../../tools/bazel/metadata/bundle_worker.py;
    name = "aos-bundle-worker.py";
  };
in
  pkgs.mkDerivation {
    pname = "aos-bazel-worker-tools";
    version = "1";
    src = null;
    sharedBuildCache = false;
    buildDeps = [pkgs.jq];
    outputChecks.out = {};
    exportReferencesGraph.worker = [pkgs.bash pkgs.python3 pkgs.nodejs pkgs.esbuild pkgs.wasm-bindgen-cli bundler];
    dontStrip = true;
    dontPatchELF = true;
    dontNukeRefs = true;
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          cat > "$out/bin/bundle-worker" <<'SCRIPT'
          #!${pkgs.bash}/bin/bash
          set -euo pipefail
          export PYTHONDONTWRITEBYTECODE=1
          exec ${pkgs.python3}/bin/python3 ${bundler} \
            --bindgen ${pkgs.wasm-bindgen-cli}/bin/wasm-bindgen \
            --node ${pkgs.nodejs}/bin/node \
            --esbuild ${pkgs.esbuild}/bin/esbuild "$@"
          SCRIPT
          chmod +x "$out/bin/bundle-worker"
          jq -cS '{schema: 1, closure: [.worker[] | {path, narHash}] | sort_by(.path)}' \
            "$NIX_ATTRS_JSON_FILE" > "$out/closure.json"
          cat > "$out/BUILD.bazel" <<'BUILD'
          exports_files(["bin/bundle-worker", "closure.json"], visibility = ["//visibility:public"])
          BUILD
          touch "$out/REPO.bazel"
        '';
      }
    ];
  }
