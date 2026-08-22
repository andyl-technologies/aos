{
  pkgs,
  lib,
  phase1GuestEntropyLaunch,
  attrPath ? "checks.crucible.phase4.workloadEntropyBoundary",
  taskIds ? ["T-WL-2"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  workloadDoc = builtins.readFile ../../docs/rfcs/0010-crucible/33-examples-and-workloads.md;
  workloadTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu/tests/workload_entropy_boundary.rs;
  };
  launchEntropy = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu/src/launch/entropy.rs;
  };
  launchValidation = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu/src/launch/validation.rs;
  };
  qemuBoundary = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu/src/determinism_boundary.rs;
  };
  qemuLaunch = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu/src/launch.rs;
  };
  phase1GuestEntropyGate = builtins.readFile ./phase1-guest-entropy-launch.nix;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/33-examples-and-workloads.md" workloadDoc [
      {
        label = "T-WL-2 completion note";
        needle = "Completed by `checks.crucible.phase4.workloadEntropyBoundary`";
      }
      {
        label = "workload entropy implementation note";
        needle = "workload entropy-boundary proof";
      }
      {
        label = "guest RNG reproduces";
        needle = "RNG-backed workload bytes reproduce";
      }
      {
        label = "new entropy source fails";
        needle = "host entropy source fails loudly";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/tests/workload_entropy_boundary.rs" workloadTest [
      {
        label = "workload guest RNG transcript test";
        needle = "workload_guest_rng_transcript_is_seeded_by_scenario_entropy_boundary";
      }
      {
        label = "new entropy source fail-loud test";
        needle = "workload_new_entropy_source_fails_loudly";
      }
      {
        label = "workload selector";
        needle = "GuestWorkloadBinary::ClientLoop";
      }
      {
        label = "guest entropy seed equality";
        needle = "first.guest_entropy_seed(), repeated.guest_entropy_seed()";
      }
      {
        label = "changed seed differs";
        needle = "changed_seed.guest_entropy_seed()";
      }
      {
        label = "firmware seed assertion";
        needle = "name=opt/crucible/seed,file=crucible-guest-entropy-seed.bin";
      }
      {
        label = "seeded virtio rng assertion";
        needle = "virtio-rng-pci,rng=crucible-rng0";
      }
      {
        label = "host rng object rejection";
        needle = "rng-random,id=hostrng,filename=/dev/urandom";
      }
      {
        label = "unseeded guest rng rejection";
        needle = "unseeded guest entropy";
      }
      {
        label = "boundary validator";
        needle = "validate_qemu_determinism_boundary";
      }
      {
        label = "guest entropy microtest";
        needle = "QemuEntropyElimination::GuestEntropyFwCfgSeed";
      }
      {
        label = "pre-spawn host entropy validator";
        needle = "validate_pre_spawn_qemu_launch_args";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/launch/entropy.rs" launchEntropy [
      {
        label = "guest entropy derives from scenario seed";
        needle = "pub fn from_scenario_seed(scenario_seed: u64) -> Self";
      }
      {
        label = "32-byte seed";
        needle = "const GUEST_ENTROPY_SEED_BYTES: usize = 32;";
      }
      {
        label = "seed file writer";
        needle = "pub fn write_to_dir(&self, dir: impl AsRef<Path>) -> std::io::Result<PathBuf>";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/launch.rs" qemuLaunch [
      {
        label = "guest entropy seed stored on profile";
        needle = "guest_entropy_seed: GuestEntropySeed,";
      }
      {
        label = "guest entropy computed during validation";
        needle = "GuestEntropySeed::from_scenario_seed(self.scenario_seed)";
      }
      {
        label = "firmware seed in scenario material";
        needle = "guest_entropy_seed_source=scenario-seed";
      }
      {
        label = "seeded rng device in scenario material";
        needle = "guest_entropy_rng_device=virtio-rng-pci";
      }
      {
        label = "host entropy disabled in scenario material";
        needle = "guest_entropy_host_sources=disabled";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/determinism_boundary.rs" qemuBoundary [
      {
        label = "guest entropy required elimination";
        needle = "QemuEntropyElimination::GuestEntropyFwCfgSeed";
      }
      {
        label = "guest entropy negative case";
        needle = "QemuEntropyEliminationNegativeCase::RemoveGuestEntropySeed";
      }
      {
        label = "unseeded rng replacement";
        needle = "virtio-rng-pci,rng=host-rng0";
      }
      {
        label = "missing fw_cfg negative case";
        needle = "remove_option_pair(&mut without_fw_cfg, \"-fw_cfg\")";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/launch/validation.rs" launchValidation [
      {
        label = "host rng object rejected";
        needle = "reason: \"host entropy\"";
      }
      {
        label = "unseeded guest rng rejected";
        needle = "\"unseeded guest entropy\"";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-guest-entropy-launch.nix" phase1GuestEntropyGate [
      {
        label = "actual guest entropy probe";
        needle = "guest-entropy-probe";
      }
      {
        label = "guest reads urandom";
        needle = "URANDOM_HEX";
      }
      {
        label = "workload selection in actual guest";
        needle = "crucible.workload=httpget";
      }
      {
        label = "actual guest workload binary";
        needle = "crucible-httpget-workload";
      }
      {
        label = "actual guest workload RNG transcript";
        needle = "WORKLOAD_RNG_HEX";
      }
      {
        label = "actual guest workload result";
        needle = "WORKLOAD_RESULT:PASS";
      }
      {
        label = "same seed urandom equality";
        needle = "[ \"$urandom_a\" = \"$urandom_b\" ]";
      }
      {
        label = "different seed urandom changes";
        needle = "[ \"$urandom_a\" != \"$urandom_c\" ]";
      }
      {
        label = "same seed workload transcript equality";
        needle = "[ \"$workload_rng_a\" = \"$workload_rng_b\" ]";
      }
      {
        label = "different seed workload transcript changes";
        needle = "[ \"$workload_rng_a\" != \"$workload_rng_c\" ]";
      }
      {
        label = "same seed hwrng equality";
        needle = "[ \"$hwrng_a\" = \"$hwrng_b\" ]";
      }
      {
        label = "workload transcript fail-loud oracle";
        needle = "same seed changed workload RNG transcript";
      }
      {
        label = "workload result key";
        needle = "workload=crucible.workload=httpget";
      }
      {
        label = "workload binary result key";
        needle = "workload_binary=crucible-httpget-workload";
      }
      {
        label = "workload same seed result";
        needle = "workload_rng_same_seed_reproducible=true";
      }
      {
        label = "workload changed seed result";
        needle = "workload_rng_different_seed_changes=true";
      }
      {
        label = "guest csprng result";
        needle = "guest_csprng_same_seed_reproducible=true";
      }
      {
        label = "host entropy disabled result";
        needle = "host_guest_entropy_sources=disabled";
      }
      {
        label = "jitter adversary";
        needle = "host_adversary=bounded-scheduler-preemption-second-run";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 workload entropy import";
        needle = "workloadEntropyBoundary = import ./phase4-workload-entropy-boundary.nix";
      }
      {
        label = "phase4 workload entropy attr path";
        needle = "checks.crucible.phase4.workloadEntropyBoundary";
      }
      {
        label = "phase4 workload entropy task id";
        needle = "taskIds = [\"T-WL-2\"]";
      }
      {
        label = "phase1 guest entropy dependency";
        needle = "phase1GuestEntropyLaunch = phase1.guestEntropyLaunch;";
      }
    ];
in
  if failures != []
  then
    throw ''
      crucible phase4 workload entropy-boundary check failed:
      ${builtins.concatStringsSep "\n" failures}
    ''
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-workload-entropy-boundary";
      version = "0";
      src = crucibleSrc;
      buildDeps = [pkgs.coreutils pkgs.rust pkgs.sed];
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
            set -eu
            export CARGO_HOME="$TMPDIR/cargo-home"
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
          name = "run-workload-entropy-boundary";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            require_listed() {
              listed="$1"
              test_name="$2"
              if [ -z "$(sed -n "/$test_name/p" "$listed")" ]; then
                printf 'missing expected test: %s\n' "$test_name" >&2
                exit 1
              fi
            }
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-workload-entropy-boundary-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --test workload_entropy_boundary \
              -- --list > "$TMPDIR/workload-entropy-boundary-tests"
            require_listed \
              "$TMPDIR/workload-entropy-boundary-tests" \
              "workload_guest_rng_transcript_is_seeded_by_scenario_entropy_boundary"
            require_listed \
              "$TMPDIR/workload-entropy-boundary-tests" \
              "workload_new_entropy_source_fails_loudly"
            require_listed \
              "$TMPDIR/workload-entropy-boundary-tests" \
              "workload_plugin_observation_uses_fixed_setup_fds"
            phase1_result="${phase1GuestEntropyLaunch}/result"
            if [ ! -f "$phase1_result" ]; then
              printf 'missing phase1 guest entropy result: %s\n' "$phase1_result" >&2
              exit 1
            fi
            require_phase1_result_line() {
              expected="$1"
              found=0
              while IFS= read -r actual; do
                if [ "$actual" = "$expected" ]; then
                  found=1
                fi
              done < "$phase1_result"
              if [ "$found" -ne 1 ]; then
                printf 'missing phase1 guest entropy result line: %s\n' "$expected" >&2
                exit 1
              fi
            }
            require_phase1_result_line "workload=crucible.workload=httpget"
            require_phase1_result_line "workload_binary=crucible-httpget-workload"
            require_phase1_result_line "workload_rng_same_seed_reproducible=true"
            require_phase1_result_line "workload_rng_different_seed_changes=true"
            require_phase1_result_line "guest_csprng_same_seed_reproducible=true"
            require_phase1_result_line "host_guest_entropy_sources=disabled"
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-workload-entropy-boundary-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --test workload_entropy_boundary \
              workload_guest_rng_transcript_is_seeded_by_scenario_entropy_boundary \
              -- --exact --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-workload-entropy-boundary-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --test workload_entropy_boundary \
              workload_new_entropy_source_fails_loudly \
              -- --exact --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-workload-entropy-boundary-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --test workload_entropy_boundary \
              workload_plugin_observation_uses_fixed_setup_fds \
              -- --exact --test-threads=1
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
            workload_guest_rng=seeded-firmware-entropy-boundary
            guest_csprng_same_seed=bit-identical
            host_entropy_mutation=fails-loud
            cross_gate=checks.crucible.phase1.guestEntropyLaunch
            RESULT
          '';
        }
      ];
    }
