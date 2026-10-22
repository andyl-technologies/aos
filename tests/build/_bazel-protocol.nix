##! Shared protocol libraries compile and test through the offline Bazel graph.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/protocol-inventory.json,
}: let
  protocol = "//crates/crucible/protocol/crucible-qemu-protocol";
  shmem = "//crates/crucible/protocol/crucible-qemu-shmem";
  integrationTargets = name: let
    entries = builtins.readDir (../../crates/crucible/protocol + "/${name}/tests");
  in
    map (file: "//crates/crucible/protocol/${name}:" + pkgs.lib.removeSuffix ".rs" file)
    (builtins.filter (file: entries.${file} == "regular" && pkgs.lib.hasSuffix ".rs" file) (builtins.attrNames entries));
  workspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory;
    sourceDirectories = pkgs.lib.optionals (sourceInventory == null) [
      "tools/bazel/toolchains"
      "tools/bazel/rules"
      "tools/bazel/metadata"
      "tools/bazel/testing"
      "third_party/rust"
      "crates/crucible/protocol/crucible-qemu-protocol"
      "crates/crucible/protocol/crucible-qemu-shmem"
      "docs/rfcs/0020-crucible-campaigns"
    ];
    repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.core;
    analysisTargets = ["${protocol}:unit" "${shmem}:unit"];
  };
in rec {
  tests = pkgs.mkAosBazelCheck {
    pname = "aos-bazel-protocol-tests";
    inherit workspace;
    targets =
      ["${protocol}:license_closure" "${shmem}:license_closure" "${protocol}:unit" "${protocol}:doc" "${shmem}:unit" "${shmem}:doc" "${shmem}:crucible-shmem-abi-header"]
      ++ integrationTargets "crucible-qemu-protocol"
      ++ integrationTargets "crucible-qemu-shmem";
  };
  cargo = pkgs.mkDerivation {
    pname = "aos-bazel-protocol-cargo-oracle";
    version = "1";
    src = import ../../pkgs/tools/crucible/_cargo-source.nix {inherit (pkgs) lib;};
    buildDeps = [pkgs.rust pkgs.python3 pkgs.sed];
    sharedBuildCache = false;
    dontStrip = true;
    dontPatchELF = true;
    dontNukeRefs = true;
    phases = [
      {
        name = "compare";
        script = ''
          cp -R "$src" source
          chmod -R u+w source
          cd source
          export CARGO_HOME="$TMPDIR/cargo" CARGO_TARGET_DIR="$TMPDIR/target"
          mkdir -p "$CARGO_HOME" .cargo "$out"
          sed 's|@vendor@|${pkgs.aos.passthru.cargoDeps}|g' \
            ${pkgs.aos.passthru.cargoDeps}/.cargo/config.toml > .cargo/config.toml
          cargo test --frozen --offline --manifest-path crates/Cargo.toml \
            -p crucible-qemu-protocol -p crucible-qemu-shmem \
            --jobs "$NIX_BUILD_CORES" --no-run --message-format=json > "$out/cargo-messages.jsonl"
          cargo test --frozen --offline --manifest-path crates/Cargo.toml \
            -p crucible-qemu-protocol -p crucible-qemu-shmem \
            --jobs "$NIX_BUILD_CORES" > "$out/cargo-tests.log" 2>&1 || {
            tail -n 100 "$out/cargo-tests.log"
            exit 1
          }
          # Keep discovered binaries so parity checks can evolve independently
          # of the Cargo compilation oracle during the migration.
          ${pkgs.python3}/bin/python3 - "$out" <<'PY'
          import json
          from pathlib import Path
          import shutil
          import sys

          output = Path(sys.argv[1])
          binaries = output / "test-binaries"
          binaries.mkdir()
          messages = output / "cargo-messages.jsonl"
          events = [json.loads(line) for line in messages.read_text().splitlines()]
          for event in events:
              executable = event.get("executable")
              if event.get("reason") == "compiler-artifact" and executable:
                  target = binaries / Path(executable).name
                  shutil.copy2(executable, target)
                  event["executable"] = str(target)
          messages.write_text("".join(json.dumps(event) + "\n" for event in events))
          PY
        '';
      }
    ];
  };
  oracle = let
    verifier = builtins.path {
      path = ../../tools/bazel/tests;
      name = "aos-protocol-parity-tools";
      filter = path: type: type == "directory" || builtins.elem (baseNameOf path) ["verify_protocol.py" "verify_pilot.py"];
    };
  in
    pkgs.runCommand "aos-bazel-protocol-cargo-parity" {buildDeps = [pkgs.python3];} ''
      mkdir -p "$out"
      ${pkgs.python3}/bin/python3 ${verifier}/verify_protocol.py \
        --tests ${tests}/evidence/tests --inventory ${tests}/inventory.json \
        --messages ${cargo}/cargo-messages.jsonl --output "$out/parity.json"
    '';
  all = pkgs.runCommand "aos-bazel-protocol-checks" {buildDeps = [tests oracle];} ''
    mkdir -p "$out"
    cp -r ${tests}/evidence "$out/evidence"
    cp ${tests}/inventory.json "$out/inventory.json"
    cp ${oracle}/parity.json "$out/parity.json"
  '';
}
