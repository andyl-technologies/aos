{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.executionLiveSnapshot",
  taskIds ? ["T-EXEC-15"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-7PIlTjQ6Cnb2k2+Qn4A49maDZSffD20krhCcwJ7od8Y=";
  };

  session = builtins.readFile ../../crates/crucible-session/src/lib.rs;
  sessionGate = builtins.readFile ../../crates/crucible-session/tests/gate_control_responsive.rs;
  gateTargetNix = builtins.readFile ./phase1-gate-target-mapping.nix;
  gateTargetRust = builtins.readFile ../../crates/crucible-harness/src/gate_targets.rs;
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

  forbiddenFailuresFor = fileLabel: content: forbidden:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    forbidden;

  failures =
    failuresFor "crates/crucible-session/src/lib.rs" session [
      {
        label = "live state kind";
        needle = "pub enum LiveStateKind";
      }
      {
        label = "lock-free live snapshot";
        needle = "pub struct LiveSnapshot";
      }
      {
        label = "atomic state kind";
        needle = "state_kind: AtomicU8";
      }
      {
        label = "atomic virtual time";
        needle = "virtual_time_ticks: AtomicU64";
      }
      {
        label = "atomic event log length";
        needle = "event_log_len: AtomicU64";
      }
      {
        label = "atomic quanta counter";
        needle = "quanta_stepped: AtomicU64";
      }
      {
        label = "copy-out view";
        needle = "pub struct LiveSnapshotView";
      }
      {
        label = "lock-free read API";
        needle = "pub fn read(&self) -> LiveSnapshotView";
      }
      {
        label = "actor-only publish helper";
        needle = "fn publish(&self, snapshot: &EngineSnapshot)";
      }
      {
        label = "session actor owns live snapshot";
        needle = "live: Arc<LiveSnapshot>";
      }
      {
        label = "observer handle API";
        needle = "pub fn live_snapshot(&self) -> Arc<LiveSnapshot>";
      }
      {
        label = "quantum publishes mirror";
        needle = "self.publish_live_snapshot();";
      }
      {
        label = "initial live snapshot test";
        needle = "session_actor_live_snapshot_starts_as_loaded_without_mailbox";
      }
      {
        label = "monotone progress live snapshot test";
        needle = "session_actor_live_snapshot_publishes_monotone_progress";
      }
    ]
    ++ failuresFor "crates/crucible-session/tests/gate_control_responsive.rs" sessionGate [
      {
        label = "implemented control-responsive latency test";
        needle = "gate_control_responsive_reads_live_snapshot_without_mailbox_roundtrip";
      }
      {
        label = "lock-free live snapshot read";
        needle = "live.read()";
      }
      {
        label = "monotone quanta assertion";
        needle = "current.quanta_stepped >= last.quanta_stepped";
      }
      {
        label = "bounded yield polling";
        needle = "for _ in 0..128";
      }
      {
        label = "event-log progress assertion";
        needle = "last.event_log_len >= last.quanta_stepped";
      }
      {
        label = "actor stop after observation";
        needle = "send_command(&sender, SessionCommand::Stop).await;";
      }
      {
        label = "bounded stop acknowledgement";
        needle = "stop command should be acknowledged within bounded actor yields";
      }
      {
        label = "resolved event publication";
        needle = "resolved_events: vec![resolved_control_event(self.quanta)]";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible-session/tests/gate_control_responsive.rs" sessionGate [
      {
        label = "ignored red placeholder";
        needle = "#[ignore";
      }
      {
        label = "placeholder pending panic";
        needle = "implementation is pending";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-gate-target-mapping.nix" gateTargetNix [
      {
        label = "session control-responsive target package";
        needle = ''package = "crucible-session";'';
      }
      {
        label = "session control-responsive test target";
        needle = ''testTarget = "gate_control_responsive";'';
      }
      {
        label = "implemented gate target marker";
        needle = "placeholder = false;";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/gate_targets.rs" gateTargetRust [
      {
        label = "harness session control-responsive target package";
        needle = ''package: "crucible-session",'';
      }
      {
        label = "harness session control-responsive test target";
        needle = ''test_target: "gate_control_responsive",'';
      }
      {
        label = "harness implemented gate target marker";
        needle = "placeholder: false,";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes live snapshot check";
        needle = "executionLiveSnapshot = import ./phase1-execution-live-snapshot.nix";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/05-execution-model.md" rfc [
      {
        label = "T-EXEC-15 checked off";
        needle = "- [x] **T-EXEC-15**";
      }
      {
        label = "T-EXEC-15 completion note";
        needle = "Completed by `crates/crucible-session/src/lib.rs`: `LiveSnapshot`";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 execution live snapshot check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-execution-live-snapshot";
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
          name = "run-execution-live-snapshot";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-execution-live-snapshot-target" \
              -p crucible-session \
              --all-targets \
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
            gate=gate:control-responsive
            mirror=lock-free-atomics
            reads=mailbox-free
            progress=monotone-quanta
            RESULT
          '';
        }
      ];
    }
