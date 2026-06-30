{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.faultDeterminismGate",
  taskIds ? ["T-FAULT-15"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  gateTest = builtins.readFile ../../crates/crucible/tests/fault_determinism_gate.rs;
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
        label = "T-FAULT-15 checked off";
        needle = "- [x] **T-FAULT-15**";
      }
      {
        label = "T-FAULT-15 completion note";
        needle = "Completed by `checks.crucible.phase4.faultDeterminismGate`";
      }
    ]
    ++ failuresFor "crates/crucible/tests/fault_determinism_gate.rs" gateTest [
      {
        label = "run twice fault determinism gate";
        needle = "gate_fault_determinism_run_twice_matches_activation_effects_and_draws";
      }
      {
        label = "fault decision divergence localization";
        needle = "gate_fault_determinism_divergence_localizes_to_first_fault_decision";
      }
      {
        label = "plan-valid fault kind coverage";
        needle = "gate_fault_determinism_plan_covers_every_currently_plan_valid_fault_kind";
      }
      {
        label = "device taxonomy boundary coverage";
        needle = "gate_fault_determinism_documents_device_taxonomy_boundary";
      }
      {
        label = "activation fingerprint";
        needle = "struct FaultActivationRecord";
      }
      {
        label = "effect and draw fingerprint";
        needle = "struct FaultGateFingerprint";
      }
      {
        label = "live link effect probe";
        needle = "struct LinkEffectProbe";
      }
      {
        label = "full emitted delivery capture";
        needle = "deliveries: Vec<Delivery>";
      }
      {
        label = "injected delivery capture";
        needle = "injected_deliveries: Vec<Delivery>";
      }
      {
        label = "rng draw sequence assertion";
        needle = "Decision::RngDraw";
      }
      {
        label = "fault decision assertion";
        needle = "Decision::FaultFires";
      }
      {
        label = "first differing fault decision helper";
        needle = "fn first_differing_fault_decision";
      }
      {
        label = "first differing raw decision helper";
        needle = "fn first_differing_decision";
      }
      {
        label = "network fault plan coverage";
        needle = "NetworkFault::Corruption";
      }
      {
        label = "bit-flip corruption coverage";
        needle = "NetworkCorruptionFault::BitFlip";
      }
      {
        label = "field-mutation corruption coverage";
        needle = "NetworkCorruptionFault::FieldMutation";
      }
      {
        label = "truncation corruption coverage";
        needle = "NetworkCorruptionFault::Truncation";
      }
      {
        label = "split bit-flip probe";
        needle = "\"corruption-bit-flip\"";
      }
      {
        label = "split field-mutation probe";
        needle = "\"corruption-field-mutation\"";
      }
      {
        label = "split truncation probe";
        needle = "\"corruption-truncation\"";
      }
      {
        label = "injected bit-flip effect";
        needle = "vec![0, 0, 3, 4]";
      }
      {
        label = "injected field mutation effect";
        needle = "vec![1, 130, 3, 4]";
      }
      {
        label = "injected truncation effect";
        needle = "vec![1, 2]";
      }
      {
        label = "shifted fault decision localization";
        needle = "inserted decision should localize at the shifted fault decision";
      }
      {
        label = "truncated fault decision localization";
        needle = "truncated stream should localize at the missing fault decision";
      }
      {
        label = "raw draw divergence localization";
        needle = "changed raw draw should localize";
      }
      {
        label = "live link fault application assertion";
        needle = "bandwidth.link_faults.bandwidth_bits_per_sec";
      }
      {
        label = "node crash effect assertion";
        needle = "node_effects.crash_restart";
      }
      {
        label = "node slowdown effect assertion";
        needle = "node_effects.slow_factor";
      }
      {
        label = "node clock skew effect assertion";
        needle = "node_effects.clock_skew";
      }
      {
        label = "node fault plan coverage";
        needle = "NodeFault::ClockSkew";
      }
      {
        label = "block device taxonomy boundary";
        needle = "PlanFaultUnknownDevice";
      }
      {
        label = "all device taxonomy boundary helper";
        needle = "fn device_taxonomy_faults";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 fault determinism gate import";
        needle = "faultDeterminismGate = import ./phase4-fault-determinism-gate.nix";
      }
      {
        label = "phase4 fault determinism gate attr path";
        needle = "attrPath = \"checks.crucible.phase4.faultDeterminismGate\"";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/fault_determinism_gate.rs" gateTest [
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
      {
        label = "count-only link outcome fingerprint";
        needle = "link_outcome_deliveries";
      }
    ];
in
  if failures != []
  then throw "crucible phase4 fault-determinism-gate check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-fault-determinism-gate";
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
          name = "run-fault-determinism-gate";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-fault-determinism-gate-target" \
              -p crucible \
              --test fault_determinism_gate \
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
            gate=fault-determinism
            run_twice=true
            RESULT
          '';
        }
      ];
    }
