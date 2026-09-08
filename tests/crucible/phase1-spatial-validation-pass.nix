{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.spatialValidationPass",
  taskIds ? ["T-SPAT-21"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  model = import ./_crucible-model-source.nix {inherit lib;};
  worldValidationTests = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/src/tests/world_validation.rs;
  };
  qemuLaunch =
    builtins.readFile ../../crates/crucible-qemu/src/launch.rs
    + builtins.readFile ../../crates/crucible-qemu/src/launch/canonical.rs;
  qemuRealization = builtins.readFile ../../crates/crucible-qemu/src/realization.rs;
  qemuLaunchTest =
    builtins.readFile ../../crates/crucible-qemu/tests/deterministic_launch.rs
    + builtins.readFile ../../crates/crucible-qemu/tests/deterministic_launch/launch_artifacts.rs;
  replayOracleTest = builtins.readFile ../../crates/crucible/tests/gate_replay_oracle.rs;
  defaultChecks = builtins.readFile ./default.nix;
  spatialGraph = builtins.readFile ../../docs/rfcs/0010-crucible/06-spatial-graph.md;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/06-spatial-graph.md" spatialGraph [
      {
        label = "T-SPAT-21 completion names matrix test";
        needle = "`scenario_def_form_rejects_well_formedness_matrix_before_hashing`";
      }
      {
        label = "T-SPAT-21 completion names gate";
        needle = "`checks.crucible.phase1.spatialValidationPass`";
      }
      {
        label = "T-SPAT-21 completion names model launch rows";
        needle = "`WorldNode` now carries fixed `smp_vcpus` and `icount_shift`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "scenario form constructor validates world identity";
        needle = "validate_world_serialized_identity(world)?;";
      }
      {
        label = "scenario form constructor validates plan";
        needle = "plan.validate_for_world(world)?;";
      }
      {
        label = "scenario form constructor validates properties";
        needle = "properties.validate_for_world(world)?;";
      }
      {
        label = "TOML parser validates world first";
        needle = "let world = world_from_toml(toml.world)?;";
      }
      {
        label = "TOML parser validates plan against parsed world";
        needle = "let plan = plan_from_toml_with_assertions(\n        &world,";
      }
      {
        label = "TOML parser validates properties against parsed world";
        needle = "let raw_properties = Properties::from_assertions_for_world(&world, assertions)?;";
      }
      {
        label = "TOML parser constructs validated scenario before id check";
        needle = "let form = ScenarioDefForm::from_components_with_app_random_draw_cap(\n        &world,\n        &plan,\n        &properties,\n        seed,";
      }
      {
        label = "TOML scenario id checked after validation";
        needle = "validate_serialized_id(\"scenario\", expected, form.id())?;";
      }
      {
        label = "binary parser validates world before plan";
        needle = "let world = read_world_binary(reader, includes_devices)?;";
      }
      {
        label = "binary parser validates plan against world";
        needle = "let plan = read_plan_binary_for_scenario(&world, reader)?;";
      }
      {
        label = "binary parser validates properties against world";
        needle = "let properties = read_properties_binary(&world, reader)?;";
      }
      {
        label = "world node validation";
        needle = "fn validate_world_nodes(";
      }
      {
        label = "world link validation";
        needle = "fn validate_world_links_for_node_defs(";
      }
      {
        label = "plan validation";
        needle = "fn validate_plan_entries_for_world(";
      }
      {
        label = "serialized plan pre-validation";
        needle = "fn validate_plan_entries_in_toml(";
      }
      {
        label = "properties validation";
        needle = "fn validate_properties_for_world(";
      }
      {
        label = "duplicate node error";
        needle = "DuplicateWorldNodeId";
      }
      {
        label = "unknown link endpoint error";
        needle = "WorldLinkUnknownNode";
      }
      {
        label = "latency floor error";
        needle = "WorldLinkLatencyBelowFloor";
      }
      {
        label = "jitter floor error";
        needle = "WorldLinkJitterBelowLatencyFloor";
      }
      {
        label = "loss range error";
        needle = "LinkLossProbabilityOutOfRange";
      }
      {
        label = "plan reference errors";
        needle = "PlanFaultUnknownLink";
      }
      {
        label = "partition direction errors";
        needle = "PlanFaultUnknownDirection";
      }
      {
        label = "fault param errors";
        needle = "PlanFaultUnsupportedParam";
      }
      {
        label = "heal tag errors";
        needle = "PlanHealUnknownTag";
      }
      {
        label = "plan time errors";
        needle = "PlanNegativeTime";
      }
      {
        label = "property ref errors";
        needle = "PropertyPredicateUnknownNode";
      }
      {
        label = "ready-point opt-in error";
        needle = "WhiteBoxReadyPointWithoutOptIn";
      }
      {
        label = "world node vCPU field";
        needle = "pub smp_vcpus: u16";
      }
      {
        label = "world node icount-shift field";
        needle = "pub icount_shift: u8";
      }
      {
        label = "zero vCPU validation error";
        needle = "WorldNodeSmpVcpuCountZero";
      }
      {
        label = "icount-shift validation error";
        needle = "WorldNodeIcountShiftTooLarge";
      }
      {
        label = "zero vCPU validator";
        needle = "if node.smp_vcpus == 0";
      }
      {
        label = "icount-shift validator";
        needle = "if node.icount_shift > MAX_WORLD_ICOUNT_SHIFT";
      }
      {
        label = "world material hashes vCPU count";
        needle = "smp_vcpus={}";
      }
      {
        label = "world material hashes icount shift";
        needle = "icount_shift={}";
      }
    ]
    ++ failuresFor "crates/crucible/src/tests/world_validation.rs" worldValidationTests [
      {
        label = "focused validation matrix test";
        needle = "fn scenario_def_form_rejects_well_formedness_matrix_before_hashing()";
      }
      {
        label = "matrix covers duplicate node";
        needle = "duplicate_node_ids";
      }
      {
        label = "matrix covers unknown link endpoint";
        needle = "unknown_link_endpoint";
      }
      {
        label = "matrix covers latency floor";
        needle = "latency_below_floor";
      }
      {
        label = "matrix covers jitter floor";
        needle = "jitter_below_floor";
      }
      {
        label = "matrix covers loss range";
        needle = "loss_out_of_range";
      }
      {
        label = "matrix covers plan refs";
        needle = "plan_unknown_link";
      }
      {
        label = "matrix covers fault params";
        needle = "unsupported_fault_param_toml";
      }
      {
        label = "matrix covers unknown partition directions";
        needle = "unknown_direction_toml";
      }
      {
        label = "matrix covers heal tags";
        needle = "unknown_heal_tag";
      }
      {
        label = "matrix covers plan time";
        needle = "negative_plan_time_toml";
      }
      {
        label = "matrix covers property refs";
        needle = "unknown_property_ref";
      }
      {
        label = "matrix covers empty compound properties";
        needle = "empty_property_compound";
      }
      {
        label = "matrix covers ready point opt-in";
        needle = "white_box_ready_point_without_opt_in";
      }
      {
        label = "matrix covers zero vCPU count";
        needle = "zero_vcpu_count";
      }
      {
        label = "matrix covers vCPU identity sensitivity";
        needle = "changed_vcpu_world";
      }
      {
        label = "matrix covers icount-shift range";
        needle = "icount_shift_too_large";
      }
      {
        label = "matrix covers icount-shift identity sensitivity";
        needle = "changed_shift_world";
      }
      {
        label = "matrix covers full scenario parse validation";
        needle = "scenario_negative_plan_time";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/launch.rs" qemuLaunch [
      {
        label = "launch profile rejects zero vCPU count";
        needle = "if self.smp_vcpus == 0";
      }
      {
        label = "launch profile zero vCPU error";
        needle = "LaunchProfileError::SmpVcpuCountZero";
      }
      {
        label = "launch profile rejects auto icount shift";
        needle = "IcountShiftSetting::Auto => return Err(LaunchProfileError::IcountShiftAuto),";
      }
      {
        label = "launch profile validates shift range";
        needle = "fn validate_icount_shift(shift: u8) -> Result<u8, LaunchProfileError>";
      }
      {
        label = "launch profile rejects too-large shift";
        needle = "LaunchProfileError::IcountShiftTooLarge";
      }
      {
        label = "launch profile hashes vCPU count";
        needle = "format!(\"smp_vcpus={}\", self.smp_vcpus),";
      }
      {
        label = "launch profile hashes fixed icount shift";
        needle = "format!(\"icount_shift={}\", self.icount_shift),";
      }
      {
        label = "launch profile pins single-threaded TCG";
        needle = "DEFAULT_ACCEL.to_owned(),";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/tests/deterministic_launch.rs" qemuLaunchTest [
      {
        label = "multi-vCPU launch validation test";
        needle = "fn multi_vcpu_round_robin_launch_is_pinned_validated_and_hashed()";
      }
      {
        label = "zero vCPU rejection test";
        needle = "Err(LaunchProfileError::SmpVcpuCountZero)";
      }
      {
        label = "auto icount rejection test";
        needle = "Err(LaunchProfileError::IcountShiftAuto)";
      }
      {
        label = "too-large icount rejection test";
        needle = "Err(LaunchProfileError::IcountShiftTooLarge { shift: 63 })";
      }
      {
        label = "node icount shift mismatch test";
        needle = "fn launch_profile_rejects_per_node_icount_shift_mismatch()";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/realization.rs" qemuRealization [
      {
        label = "qemu realization lib test target keeps WorldNode vCPU defaults";
        needle = "smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS";
      }
      {
        label = "qemu realization lib test target keeps WorldNode icount-shift defaults";
        needle = "icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT";
      }
      {
        label = "qemu realization baked-node test is compiled by gate";
        needle = "fn qemu_bake_records_baked_node_blob_refs()";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_replay_oracle.rs" replayOracleTest [
      {
        label = "replay oracle feature test target imports NodeTemplate";
        needle = "NodeTemplate";
      }
      {
        label = "replay oracle feature test target keeps WorldNode vCPU defaults";
        needle = "smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS";
      }
      {
        label = "replay oracle feature test target keeps WorldNode icount-shift defaults";
        needle = "icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT";
      }
      {
        label = "replay oracle loadvm branch is compiled by gate";
        needle = "fn gate_replay_oracle_materialized_state_loadvm_branch_captures_resume_components()";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes spatial validation pass check";
        needle = "spatialValidationPass = import ./phase1-spatial-validation-pass.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 spatial validation pass check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-spatial-validation-pass";
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
          name = "run-spatial-validation-pass";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-spatial-validation-pass-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --lib \
              scenario_def_form_rejects_well_formedness_matrix_before_hashing \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-spatial-validation-pass-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --features test-double \
              --test gate_replay_oracle \
              gate_replay_oracle_materialized_state_loadvm_branch_captures_resume_components \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-spatial-validation-pass-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --lib \
              qemu_bake_records_baked_node_blob_refs \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-spatial-validation-pass-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --test deterministic_launch \
              multi_vcpu_round_robin_launch_is_pinned_validated_and_hashed \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-spatial-validation-pass-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --test deterministic_launch \
              launch_profile_rejects_mutating_or_interactive_state \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-spatial-validation-pass-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --test deterministic_launch \
              launch_profile_rejects_per_node_icount_shift_mismatch \
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
            component=parse-build-validation-pass
            spatial_rows=world,links,plan,properties,ready-point,vcpu-count,icount-shift
            launch_rows=mirrored-by-crucible-qemu
            validation_before_hashing=true
            runtime_defense_required=false
            RESULT
          '';
        }
      ];
    }
