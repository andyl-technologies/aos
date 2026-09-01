{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.shmemDeliverability",
  taskIds ? ["T-SHM-13"],
}: let
  phase0S4 = import ./phase0-s4.nix {inherit pkgs;};
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  shmemLib = import ./_crucible-shmem-source.nix {inherit lib;};
  icountTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-shmem/tests/icount_stamped_injection.rs;
  };
  lookaheadTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-shmem/tests/lookahead_gate.rs;
  };
  shmemSpec = builtins.readFile ../../docs/rfcs/0010-crucible/13-shmem-abi.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "crates/crucible-shmem/src/lib.rs" shmemLib [
      {
        label = "frame entry ABI";
        needle = "pub struct FrameEntry";
      }
      {
        label = "in-band delivery icount";
        needle = "pub delivery_icount: u64";
      }
      {
        label = "source-node tie-break field";
        needle = "pub src_node: u32";
      }
      {
        label = "sequence tie-break field";
        needle = "pub seq: u32";
      }
      {
        label = "deliverability predicate";
        needle = "pub fn is_deliverable_at";
      }
      {
        label = "icount-not-wallclock comparison";
        needle = "self.delivery_icount <= consumer_current_icount";
      }
      {
        label = "deterministic delivery key";
        needle = "pub struct FrameDeliveryKey";
      }
      {
        label = "delivery key total order";
        needle = "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]";
      }
      {
        label = "consumer-side visible frame merge";
        needle = "pub fn deliverable_frames_at";
      }
      {
        label = "consumer-side ordering by delivery key";
        needle = "deliverable.sort_by_key(|frame| frame.delivery_key());";
      }
      {
        label = "late enqueue validation helper";
        needle = "pub fn validate_frame_delivery_is_future";
      }
      {
        label = "late enqueue fail-loudly error";
        needle = "LookaheadGateError::DeliveryAlreadyPassed";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/tests/icount_stamped_injection.rs" icountTest [
      {
        label = "in-band delivery icount test";
        needle = "frame_entry_carries_delivery_icount_in_band";
      }
      {
        label = "deliverability ignores arrival order test";
        needle = "deliverability_depends_on_consumer_icount_not_arrival_order";
      }
      {
        label = "same-icount source/sequence order test";
        needle = "same_icount_frames_resolve_by_source_node_then_sequence";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/tests/lookahead_gate.rs" lookaheadTest [
      {
        label = "exact-current delivery admission test";
        needle = "lookahead_gate_allows_exact_current_delivery_icount";
      }
      {
        label = "already passed delivery rejection test";
        needle = "lookahead_gate_rejects_already_passed_delivery_icount";
      }
      {
        label = "future frame exact-delivery test";
        needle = "lookahead_gate_allows_future_frame_to_deliver_at_exact_icount";
      }
    ]
    ++ forbiddenFor "crates/crucible-shmem/tests/icount_stamped_injection.rs" icountTest [
      {
        label = "ignored icount-stamped test";
        needle = "#[ignore";
      }
    ]
    ++ forbiddenFor "crates/crucible-shmem/tests/lookahead_gate.rs" lookaheadTest [
      {
        label = "ignored lookahead test";
        needle = "#[ignore";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/13-shmem-abi.md" shmemSpec [
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes shmem deliverability check";
        needle = "shmemDeliverability = import ./phase2-shmem-deliverability.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 shmem deliverability check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-shmem-deliverability";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.grep
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
          name = "run-shmem-deliverability";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            s4_result="${phase0S4}/result"
            grep -q '^PASS$' "$s4_result"
            grep -q '^delivery_rule=delivery_icount_lte_current_icount$' "$s4_result"
            grep -q '^tie_break_key=delivery_icount_src_node_seq$' "$s4_result"
            grep -q '^arrival_order_negative_control_failed=true$' "$s4_result"
            grep -q '^late_enqueue_negative_control_failed=true$' "$s4_result"
            grep -q '^late_delivery_failures=0$' "$s4_result"
            grep -q '^early_delivery_failures=0$' "$s4_result"

            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-shmem-deliverability-target" \
              -p crucible-shmem \
              --test icount_stamped_injection \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-shmem-deliverability-target" \
              -p crucible-shmem \
              --test lookahead_gate \
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
            gate=gate:layer1-injection
            gate=gate:content-address
            gate=gate:divergence-bisect
            rust_tests=crucible-shmem::icount_stamped_injection,crucible-shmem::lookahead_gate
            deliverability=delivery_icount_lte_current_icount
            deterministic_order=delivery_icount,src_node,seq
            late_enqueue_policy=fail_loudly
            phase0_evidence=checks.crucible.phase0.s4ShmemVisibility
            RESULT
          '';
        }
      ];
    }
