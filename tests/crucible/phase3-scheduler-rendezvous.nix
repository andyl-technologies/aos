{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.schedulerRendezvous",
  taskIds ? ["T-SCHED-7"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  rendezvousTest = builtins.readFile ../../crates/crucible/tests/scheduler_rendezvous.rs;
  livenessTest = builtins.readFile ../../crates/crucible/tests/gate_scheduler_liveness.rs;
  schedulingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/08-scheduling.md;
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
    failuresFor "docs/rfcs/0010-crucible/08-scheduling.md" schedulingDoc [
      {
        label = "T-SCHED-7 checked off";
        needle = "- [x] **T-SCHED-7**";
      }
      {
        label = "T-SCHED-7 completion note";
        needle = "Completed by `checks.crucible.phase3.schedulerRendezvous`";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "rendezvous policy type";
        needle = "pub struct SchedulerRendezvous";
      }
      {
        label = "fixed rendezvous constructor";
        needle = "pub fn every";
      }
      {
        label = "zero rendezvous rejection";
        needle = "scheduler rendezvous interval must be nonzero";
      }
      {
        label = "rendezvous cap helper";
        needle = "pub fn rendezvous_cap_for";
      }
      {
        label = "scenario stores rendezvous";
        needle = "pub rendezvous: SchedulerRendezvous";
      }
      {
        label = "pick computes one shared rendezvous cap";
        needle = "let rendezvous_cap = self.shared_rendezvous_cap()";
      }
      {
        label = "empty quantum no decision";
        needle = "if selected_candidates.is_empty()";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "rendezvous export";
        needle = "SchedulerRendezvous";
      }
      {
        label = "rendezvous cap export";
        needle = "rendezvous_cap_for";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_rendezvous.rs" rendezvousTest [
      {
        label = "cap boundary test";
        needle = "rendezvous_cap_uses_next_shared_boundary";
      }
      {
        label = "frontier-based shared cap test";
        needle = "rendezvous_shared_cap_is_frontier_based_not_node_local";
      }
      {
        label = "zero interval test";
        needle = "rendezvous_rejects_zero_interval";
      }
      {
        label = "no empty decision test";
        needle = "single_scheduler_rendezvous_caps_without_decision_or_idle";
      }
      {
        label = "empty rendezvous RNG cursor test";
        needle = "empty_rendezvous_quantum_does_not_advance_decision_rng_cursor";
      }
      {
        label = "frequency independence test";
        needle = "rendezvous_frequency_does_not_change_delivery_order_or_configuration";
      }
      {
        label = "configuration equality assertion";
        needle = "fast_report.final_configuration";
      }
      {
        label = "delivery-order equality assertion";
        needle = "delivery_order_decisions(&fast_report)";
      }
      {
        label = "exact delivery virtual-time assertion";
        needle = "vec![(12, vec![77])]";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_scheduler_liveness.rs" livenessTest [
      {
        label = "liveness no per-quantum decision assumption";
        needle = "recorded decisions without resolved scheduler events";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/scheduler_rendezvous.rs" rendezvousTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 exposes scheduler rendezvous check";
        needle = "schedulerRendezvous = import ./phase3-scheduler-rendezvous.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 scheduler rendezvous check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-scheduler-rendezvous";
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
          name = "run-scheduler-rendezvous";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-rendezvous-target" \
              -p crucible \
              --test scheduler_rendezvous \
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
            component=crucible-scheduler
            rendezvous=exact-shared-horizon-cap
            ordering_exactness=frequency-independent
            empty_rendezvous_quantum=no-canonical-decision
            RESULT
          '';
        }
      ];
    }
