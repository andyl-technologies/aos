{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.spatialSerializableForm",
  taskIds ? ["T-SPAT-16"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  crateRoot = builtins.readFile ../../crates/crucible/src/lib.rs;
  cargoManifest = builtins.readFile ../../crates/crucible/Cargo.toml;
  cargoLock = builtins.readFile ../../crates/Cargo.lock;
  defaultChecks = builtins.readFile ./default.nix;
  spatialGraph = builtins.readFile ../../docs/rfcs/0010-crucible/06-spatial-graph.md;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;


  failures =
    failuresFor "docs/rfcs/0010-crucible/06-spatial-graph.md" spatialGraph [
      {
        label = "T-SPAT-16 checked off";
        needle = "- [x] **T-SPAT-16**";
      }
      {
        label = "T-SPAT-16 completion names serializable form";
        needle = "`ScenarioDefForm`";
      }
      {
        label = "T-SPAT-16 completion names gate";
        needle = "`checks.crucible.phase1.spatialSerializableForm`";
      }
    ]
    ++ failuresFor "crates/crucible/Cargo.toml" cargoManifest [
      {
        label = "serde dependency";
        needle = "serde = { workspace = true }";
      }
      {
        label = "toml dependency";
        needle = "toml = { workspace = true }";
      }
    ]
    ++ failuresFor "crates/Cargo.lock" cargoLock [
      {
        label = "crucible lock records serde";
        needle = " \"serde\",";
      }
      {
        label = "crucible lock records toml";
        needle = " \"toml\",";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "content-addressed blob ref type";
        needle = "pub struct ContentAddressedBlobRef";
      }
      {
        label = "scenario serialized form type";
        needle = "pub struct ScenarioDefForm";
      }
      {
        label = "scenario TOML serializer";
        needle = "pub fn to_canonical_toml(&self) -> Result<String, EngineError>";
      }
      {
        label = "scenario TOML parser";
        needle = "pub fn from_canonical_toml(input: &str) -> Result<Self, EngineError>";
      }
      {
        label = "scenario compact binary serializer";
        needle = "pub fn to_compact_binary(&self) -> Vec<u8>";
      }
      {
        label = "scenario compact binary parser";
        needle = "pub fn from_compact_binary(bytes: &[u8]) -> Result<Self, EngineError>";
      }
      {
        label = "canonical hash material bytes";
        needle = "pub fn canonical_bytes(&self) -> Vec<u8>";
      }
      {
        label = "component TOML serializer";
        needle = "impl Plan";
      }
      {
        label = "component binary parser";
        needle = "pub fn from_compact_binary_for_world";
      }
      {
        label = "content-addressed image ref guard";
        needle = "validate_no_host_path_image_refs_in_toml";
      }
      {
        label = "content-addressed blob parser";
        needle = "parse_content_addressed_blob_ref";
      }
      {
        label = "image refs are serialized fields";
        needle = "kernel: Option<ContentAddressedBlobRef>";
      }
      {
        label = "root image refs are serialized fields";
        needle = "root_image: Option<ContentAddressedBlobRef>";
      }
      {
        label = "initrd refs are serialized fields";
        needle = "initrd: Option<ContentAddressedBlobRef>";
      }
      {
        label = "image refs affect canonical material";
        needle = "optional_blob_ref_material";
      }
      {
        label = "empty world identity is recomputed for serialization";
        needle = "serialized_world_identity";
      }
      {
        label = "binary collection bounds";
        needle = "read_collection_count";
      }
      {
        label = "TOML rejects unknown fields";
        needle = "#[serde(deny_unknown_fields)]";
      }
      {
        label = "serialized id mismatch error";
        needle = "ScenarioSerializedIdMismatch";
      }
      {
        label = "host path image reference error";
        needle = "ScenarioImageReferenceNotContentAddressed";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "form re-export";
        needle = "ScenarioDefForm";
      }
      {
        label = "blob ref re-export";
        needle = "ContentAddressedBlobRef";
      }
      {
        label = "focused serialization test";
        needle = "serializable_scenario_form_round_trips_and_rejects_host_paths";
      }
      {
        label = "test checks TOML round trip";
        needle = "ScenarioDefForm::from_canonical_toml";
      }
      {
        label = "test checks binary round trip";
        needle = "ScenarioDefForm::from_compact_binary";
      }
      {
        label = "test rejects host path image refs";
        needle = "ScenarioImageReferenceNotContentAddressed";
      }
      {
        label = "test serializes kernel reference";
        needle = "kernel = \\\"{}\\\"";
      }
      {
        label = "test serializes root image reference";
        needle = "root_image = \\\"{}\\\"";
      }
      {
        label = "test serializes initrd reference";
        needle = "initrd = \\\"{}\\\"";
      }
      {
        label = "test compares canonical hash material bytes";
        needle = "parsed_binary.canonical_bytes()";
      }
      {
        label = "test rejects empty world id drift";
        needle = "wrong_empty_world_toml";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes spatial serializable form check";
        needle = "spatialSerializableForm = import ./phase1-spatial-serializable-form.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 spatial serializable form check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-spatial-serializable-form";
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
          name = "run-spatial-serializable-form";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-spatial-serializable-form-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --lib \
              serializable_scenario_form_round_trips \
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
            component=serializable-scenario-form
            toml_round_trip=true
            compact_binary_round_trip=true
            content_addressed_image_refs_only=true
            RESULT
          '';
        }
      ];
    }
