##! Declares native registry fixture tools and a private local Nix database.
{
  pkgs,
  lib,
}: let
  tools = [
    pkgs.bash
    pkgs.coreutils
    pkgs.findutils
    pkgs.grep
    pkgs.sed
    pkgs.git-minimal
    pkgs.openssh
    pkgs.zstd
    pkgs.nix
    pkgs.which
  ];
in
  pkgs.mkDerivation {
    pname = "aos-bazel-registry-test-tools";
    version = "1";
    src = null;
    sharedBuildCache = false;
    buildDeps = [pkgs.jq];
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
          cat > "$out/setup" <<'SETUP'
          #!${pkgs.bash}/bin/bash
          set -euo pipefail
          export PATH=${lib.escapeShellArg (lib.concatStringsSep ":" (map (tool: "${tool}/bin") tools))}
          export AOS_NIX_STORE=${pkgs.nix}/bin/nix-store
          export AOS_NIX_INSTANTIATE=${pkgs.nix}/bin/nix-instantiate

          # Each Bazel artifact gets its own database. Tests invoke the local
          # Nix tools as children; no daemon or cache service is started.
          registry_nix_root="''${TEST_TMPDIR:?}/registry-ability-nix"
          mkdir -p "$registry_nix_root/state/db" "$registry_nix_root/state/gcroots" \
            "$registry_nix_root/state/profiles" "$registry_nix_root/log"
          # A rooted local store keeps Nix's .links directory writable inside
          # the test sandbox while preserving logical /nix/store path names.
          registry_nix_remote="local?root=$registry_nix_root"
          NIX_STORE_DIR=/nix/store NIX_STATE_DIR="$registry_nix_root/state" \
            NIX_LOG_DIR="$registry_nix_root/log" NIX_REMOTE="$registry_nix_remote" \
            "$AOS_NIX_STORE" --init
          export AOS_TEST_ABILITY_NIX_STORE_DIR=/nix/store
          export AOS_TEST_ABILITY_NIX_STATE_DIR="$registry_nix_root/state"
          export AOS_TEST_ABILITY_NIX_LOG_DIR="$registry_nix_root/log"
          export AOS_TEST_ABILITY_NIX_REMOTE="$registry_nix_remote"
          exec "$@"
          SETUP
          chmod +x "$out/setup"
          cat > "$out/BUILD.bazel" <<'BUILD'
          exports_files(["setup", "closure.json"], visibility = ["//visibility:public"])
          BUILD
          touch "$out/REPO.bazel"
        '';
      }
    ];
  }
