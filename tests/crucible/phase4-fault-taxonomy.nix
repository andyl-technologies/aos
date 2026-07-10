{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.faultTaxonomy",
  taskIds ? ["T-FAULT-1"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  faultTest = builtins.readFile ../../crates/crucible/tests/fault_taxonomy.rs;
  faultDoc = builtins.readFile ../../docs/rfcs/0010-crucible/17-fault-injection.md;
  defaultChecks = builtins.readFile ./default.nix;

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

  forbiddenFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/17-fault-injection.md" faultDoc [
      {
        label = "T-FAULT-1 checked off";
        needle = "- [x] **T-FAULT-1**";
      }
      {
        label = "T-FAULT-1 completion note";
        needle = "Completed by `checks.crucible.phase4.faultTaxonomy`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "fault taxonomy enum";
        needle = "pub enum Fault";
      }
      {
        label = "network fault taxonomy";
        needle = "pub enum NetworkFault";
      }
      {
        label = "network corruption taxonomy";
        needle = "pub enum NetworkCorruptionFault";
      }
      {
        label = "node fault taxonomy";
        needle = "pub enum NodeFault";
      }
      {
        label = "block fault taxonomy";
        needle = "pub enum BlockFault";
      }
      {
        label = "9p fault taxonomy";
        needle = "pub enum NinePFault";
      }
      {
        label = "basis-point type";
        needle = "pub struct FaultRateBasisPoints";
      }
      {
        label = "basis-point constructor";
        needle = "pub fn from_basis_points";
      }
      {
        label = "basis-point maximum";
        needle = "MAX_FAULT_RATE_BASIS_POINTS";
      }
      {
        label = "integer duration type";
        needle = "pub struct FaultDuration";
      }
      {
        label = "integer bandwidth type";
        needle = "pub struct FaultBandwidthBitsPerSecond";
      }
      {
        label = "slowdown factor type";
        needle = "pub struct FaultSlowdownFactorBasisPoints";
      }
      {
        label = "slowdown factor minimum";
        needle = "MIN_FAULT_SLOWDOWN_FACTOR_BASIS_POINTS";
      }
      {
        label = "block failure mode type";
        needle = "pub enum IoFailureMode";
      }
      {
        label = "9p errno type";
        needle = "pub struct NinePErrno";
      }
      {
        label = "content-addressed fault material";
        needle = "pub fn content_hash(&self) -> ContentHash";
      }
      {
        label = "canonical material uses basis points";
        needle = "rate_basis_points";
      }
      {
        label = "canonical material uses integer nanoseconds";
        needle = "extra_nanos";
      }
      {
        label = "canonical material uses jitter nanoseconds";
        needle = "jitter_nanos";
      }
      {
        label = "canonical material uses integer bandwidth";
        needle = "bits_per_second";
      }
      {
        label = "canonical material uses slowdown factor";
        needle = "factor_basis_points";
      }
      {
        label = "canonical material uses block failure mode";
        needle = "mode=";
      }
      {
        label = "canonical material uses 9p errno";
        needle = "errno=";
      }
      {
        label = "canonical material length-delimits link";
        needle = "link_len";
      }
      {
        label = "canonical material length-delimits node";
        needle = "node_len";
      }
      {
        label = "canonical material length-delimits device";
        needle = "device_len";
      }
      {
        label = "rate range error";
        needle = "FaultRateBasisPointsOutOfRange";
      }
      {
        label = "slowdown validation error";
        needle = "FaultSlowdownFactorBelowOne";
      }
      {
        label = "bandwidth validation error";
        needle = "FaultBandwidthMustBeNonZero";
      }
      {
        label = "errno validation error";
        needle = "NinePErrnoMustBePositive";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "fault export";
        needle = "Fault,";
      }
      {
        label = "network fault export";
        needle = "NetworkFault";
      }
      {
        label = "block fault export";
        needle = "BlockFault";
      }
      {
        label = "9p fault export";
        needle = "NinePFault";
      }
      {
        label = "basis-point export";
        needle = "FaultRateBasisPoints";
      }
      {
        label = "slowdown factor export";
        needle = "FaultSlowdownFactorBasisPoints";
      }
      {
        label = "bandwidth export";
        needle = "FaultBandwidthBitsPerSecond";
      }
      {
        label = "block failure mode export";
        needle = "IoFailureMode";
      }
      {
        label = "9p errno export";
        needle = "NinePErrno";
      }
    ]
    ++ failuresFor "crates/crucible/tests/fault_taxonomy.rs" faultTest [
      {
        label = "full taxonomy coverage test";
        needle = "fault_taxonomy_covers_all_rfc_fault_kinds";
      }
      {
        label = "integer unit test";
        needle = "fault_taxonomy_uses_integer_basis_point_time_and_bandwidth_units";
      }
      {
        label = "content hash drift test";
        needle = "fault_taxonomy_content_hash_changes_with_parameters";
      }
      {
        label = "target length delimiter test";
        needle = "fault_taxonomy_canonical_material_length_delimits_target_ids";
      }
      {
        label = "bidirectional partition";
        needle = "PartitionDirection::Bidirectional";
      }
      {
        label = "directed partition A to B";
        needle = "PartitionDirection::EndpointAToEndpointB";
      }
      {
        label = "directed partition B to A";
        needle = "PartitionDirection::EndpointBToEndpointA";
      }
      {
        label = "bit-flip corruption";
        needle = "NetworkCorruptionFault::BitFlip";
      }
      {
        label = "field-mutation corruption";
        needle = "NetworkCorruptionFault::FieldMutation";
      }
      {
        label = "truncation corruption";
        needle = "NetworkCorruptionFault::Truncation";
      }
      {
        label = "block failure mode";
        needle = "IoFailureMode::ErrorStatus";
      }
      {
        label = "block drop mode";
        needle = "IoFailureMode::Drop";
      }
      {
        label = "drop is most severe block failure mode";
        needle = "IoFailureMode::Drop > IoFailureMode::ErrorStatus";
      }
      {
        label = "9p errno";
        needle = "NinePErrno";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 fault taxonomy import";
        needle = "faultTaxonomy = import ./phase4-fault-taxonomy.nix";
      }
      {
        label = "phase4 fault taxonomy attr path";
        needle = "attrPath = \"checks.crucible.phase4.faultTaxonomy\"";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/fault_taxonomy.rs" faultTest [
      {
        label = "f64 in taxonomy test";
        needle = "f64";
      }
      {
        label = "f32 in taxonomy test";
        needle = "f32";
      }
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "unfinished todo";
        needle = "todo!";
      }
      {
        label = "unfinished unimplemented";
        needle = "unimplemented!";
      }
    ];
in
  if failures != []
  then throw "crucible phase4 fault-taxonomy check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-fault-taxonomy";
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
          name = "run-fault-taxonomy";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-fault-taxonomy-target" \
              -p crucible \
              --test fault_taxonomy \
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
            tasks=${taskList}
            taxonomy=network,node,block,9p
            rate_unit=basis-points
            time_unit=virtual-nanoseconds
            bandwidth_unit=bits-per-virtual-second
            RESULT
          '';
        }
      ];
    }
