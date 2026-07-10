{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.executionNodeBlobRef",
  taskIds ? ["T-EXEC-10"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  crateRoot = builtins.readFile ../../crates/crucible/src/lib.rs;
  simBackend = builtins.readFile ../../crates/crucible/src/sim_backend.rs;
  replayOracle = builtins.readFile ../../crates/crucible/tests/gate_replay_oracle.rs;
  qemuRealization = builtins.readFile ../../crates/crucible-qemu/src/realization.rs;
  defaultChecks = builtins.readFile ./default.nix;
  rfc = builtins.readFile ../../docs/rfcs/0010-crucible/05-execution-model.md;

  hasInfix = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
  in
    builtins.any (index:
      builtins.substring index needleLen haystack == needle)
    indexes;

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  failures =
    failuresFor "docs/rfcs/0010-crucible/05-execution-model.md" rfc [
      {
        label = "T-EXEC-10 checked off";
        needle = "- [x] **T-EXEC-10**";
      }
      {
        label = "T-EXEC-10 completion note";
        needle = "Completed by `crates/crucible/src/model.rs`: `NodeBlobRef`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "node blob ref enum";
        needle = "pub enum NodeBlobRef";
      }
      {
        label = "baked blob variant";
        needle = "Baked(ContentHash)";
      }
      {
        label = "cow delta blob variant";
        needle = "CowDelta";
      }
      {
        label = "cow delta resolved content hash";
        needle = "resolved: ContentHash";
      }
      {
        label = "blob content hash normalization";
        needle = "pub fn content_hash(&self) -> ContentHash";
      }
      {
        label = "cow delta returns resolved content";
        needle = "Self::CowDelta { resolved, .. } => *resolved";
      }
      {
        label = "checkpoint node blob map";
        needle = "pub node_blobs: BTreeMap<NodeId, NodeBlobRef>";
      }
      {
        label = "checkpoint node blob constructor";
        needle = "pub fn with_node_blobs";
      }
      {
        label = "baked node blob materialization";
        needle = "fn baked_node_blobs(world: &World) -> BTreeMap<NodeId, NodeBlobRef>";
      }
      {
        label = "bake emits baked node refs";
        needle = "NodeBlobRef::baked(blob)";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "baked genesis blob ref test";
        needle = "baked_genesis_records_node_blob_refs_uniformly";
      }
      {
        label = "homogeneous baked and cow delta test";
        needle = "node_blob_refs_are_uniform_for_baked_and_cow_delta_state";
      }
      {
        label = "node blob ref export";
        needle = "NodeBlobRef";
      }
    ]
    ++ failuresFor "crates/crucible/src/sim_backend.rs" simBackend [
      {
        label = "sim snapshots carry node blobs";
        needle = "self.state.node_blobs()";
      }
      {
        label = "sim snapshots use cow delta refs";
        needle = "NodeBlobRef::cow_delta(parent, delta, resolved)";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_replay_oracle.rs" replayOracle [
      {
        label = "replay oracle materialized node blobs";
        needle = "fn materialized_node_blobs";
      }
      {
        label = "replay oracle compares resolved blob hash";
        needle = ".map(NodeBlobRef::content_hash)";
      }
      {
        label = "replay oracle enforces cow delta materialization";
        needle = "Some(NodeBlobRef::CowDelta { resolved, .. }) if *resolved == materialized.state.id";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/realization.rs" qemuRealization [
      {
        label = "QEMU bake node blob regression";
        needle = "qemu_bake_records_baked_node_blob_refs";
      }
      {
        label = "QEMU baked genesis node blob validation";
        needle = "fn validate_baked_genesis_node_blobs";
      }
      {
        label = "QEMU missing baked node blob regression";
        needle = "qemu_instantiate_rejects_baked_genesis_missing_node_blob";
      }
      {
        label = "QEMU fake bake emits node blobs";
        needle = "qemu_baked_node_blobs(world)";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes node blob ref check";
        needle = "executionNodeBlobRef = import ./phase1-execution-node-blob-ref.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 execution node-blob-ref check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-execution-node-blob-ref";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
      ];

      phases = [
        {
          name = "unpack";
          script = ''
            cp -R "$src" source
            chmod -R u+w source
            cd source
          '';
        }
        {
          name = "configure";
          script = ''
            export CARGO_HOME="$TMPDIR/cargo"
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            mkdir -p "$CARGO_HOME" .cargo
            if [ -f "${cargoDeps}/.cargo/config.toml" ]; then
              sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
            else
              printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${cargoDeps}"\n\n' \
                > .cargo/config.toml
            fi
          '';
        }
        {
          name = "run-execution-node-blob-ref";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-execution-node-blob-ref-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --lib \
              node_blob \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-execution-node-blob-ref-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --features test-double \
              --test gate_content_address \
              gate_content_address_excludes_materialization_cache_from_identity \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-execution-node-blob-ref-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --features test-double \
              --test gate_replay_oracle \
              gate_replay_oracle_fixed_checkpoint_corpus_matches_thin_reduction \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-execution-node-blob-ref-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --lib \
              node_blob \
              -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            related_gates=gate:content-address,gate:replay-oracle
            node_blob_ref_variants=baked,cow-delta
            checkpoint_node_blobs=homogeneous-map
            blob_identity=resolved-content-hash
            materialized_snapshots=carry-cow-delta-node-blobs
            qemu_bake_node_blobs=present-and-validated-for-world-nodes
            RESULT
          '';
        }
      ];
    }
