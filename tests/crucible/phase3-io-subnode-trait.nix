{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.ioSubnodeTrait",
  taskIds ? ["T-IO-1"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  ioSubnode = builtins.readFile ../../crates/crucible/src/io_subnode.rs;
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  focusedTest = builtins.readFile ../../crates/crucible/tests/io_subnode_trait.rs;
  ioDoc = builtins.readFile ../../docs/rfcs/0010-crucible/15-io-subnodes.md;
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
    failuresFor "docs/rfcs/0010-crucible/15-io-subnodes.md" ioDoc [
      {
        label = "T-IO-1 checked off";
        needle = "- [x] **T-IO-1**";
      }
      {
        label = "T-IO-1 completion note";
        needle = "Completed by `checks.crucible.phase3.ioSubnodeTrait`";
      }
      {
        label = "deterministic completion note";
        needle = "request icount, modeled latency, fixed shift";
      }
      {
        label = "outbox ordering note";
        needle = "response outbox sorted by delivery icount, sub-node, and sequence";
      }
      {
        label = "invalid shift note";
        needle = "invalid icount shifts";
      }
      {
        label = "advance_to note";
        needle = "`advance_to(limit_icount)` drains only due responses";
      }
      {
        label = "monotonic clock note";
        needle = "monotonically advancing the sub-node clock";
      }
      {
        label = "snapshot validation note";
        needle = "`snapshot`/`restore` preserve and validate the current icount";
      }
      {
        label = "no host input note";
        needle = "no host wall-clock, scheduling, filesystem-order, or inode";
      }
    ]
    ++ failuresFor "crates/crucible/src/io_subnode.rs" ioSubnode [
      {
        label = "trait";
        needle = "pub trait IoSubNode";
      }
      {
        label = "request type";
        needle = "pub struct IoSubNodeRequest";
      }
      {
        label = "completion type";
        needle = "pub struct IoSubNodeCompletion";
      }
      {
        label = "snapshot type";
        needle = "pub struct IoSubNodeSnapshot";
      }
      {
        label = "current icount clock";
        needle = "current_icount";
      }
      {
        label = "deterministic implementation";
        needle = "pub struct DeterministicIoSubNode";
      }
      {
        label = "enqueue computes completion";
        needle = "fn enqueue_request";
      }
      {
        label = "advance drains due";
        needle = "fn advance_to";
      }
      {
        label = "next exact local event";
        needle = "fn next_exact_local_event";
      }
      {
        label = "response outbox";
        needle = "fn drain_response_outbox";
      }
      {
        label = "snapshot restore";
        needle = "fn restore";
      }
      {
        label = "snapshot validator";
        needle = "validate_snapshot";
      }
      {
        label = "shift validator";
        needle = "validate_shift";
      }
      {
        label = "fixed shift completion";
        needle = "to_icount_ceil(shift)";
      }
      {
        label = "shared completion time helper";
        needle = "completion_delivery_icount";
      }
      {
        label = "modeled latency";
        needle = "modeled_latency";
      }
      {
        label = "rng draw input";
        needle = "rng_draw";
      }
      {
        label = "scheduler completion conversion";
        needle = "to_scheduler_completion";
      }
      {
        label = "deterministic backpressure";
        needle = "Backpressure";
      }
      {
        label = "clock rewind rejection";
        needle = "ClockRewind";
      }
      {
        label = "completion before clock rejection";
        needle = "CompletionBeforeClock";
      }
      {
        label = "invalid snapshot rejection";
        needle = "InvalidSnapshot";
      }
      {
        label = "invalid requester rejection";
        needle = "InvalidRequesterKind";
      }
      {
        label = "outbox sorting";
        needle = "make_contiguous";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/io_subnode.rs" ioSubnode [
      {
        label = "wall-clock dependency";
        needle = "SystemTime";
      }
      {
        label = "instant dependency";
        needle = "std::time::Instant";
      }
      {
        label = "filesystem metadata dependency";
        needle = "Metadata";
      }
      {
        label = "host path dependency";
        needle = "PathBuf";
      }
      {
        label = "random source";
        needle = "thread_rng";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "module exported";
        needle = "pub mod io_subnode";
      }
      {
        label = "trait exported";
        needle = "IoSubNode";
      }
      {
        label = "deterministic model exported";
        needle = "DeterministicIoSubNode";
      }
    ]
    ++ failuresFor "crates/crucible/tests/io_subnode_trait.rs" focusedTest [
      {
        label = "focused lifecycle test";
        needle = "uniform deterministic I/O sub-node lifecycle";
      }
      {
        label = "completion icount test";
        needle = "completion_icount_is_derived_from_request_icount_latency_and_shift";
      }
      {
        label = "ordering test";
        needle = "completions_are_ordered_by_delivery_subnode_and_sequence";
      }
      {
        label = "backpressure test";
        needle = "deterministic_backpressure_rejects_without_drop_or_reorder";
      }
      {
        label = "snapshot restore test";
        needle = "snapshot_restore_preserves_inflight_and_outbox_state";
      }
      {
        label = "monotonic clock test";
        needle = "monotonic_clock_rejects_backward_advance_and_past_completion";
      }
      {
        label = "invalid snapshot test";
        needle = "restore_rejects_structurally_invalid_public_snapshot";
      }
      {
        label = "outbox ordering across advances test";
        needle = "response_outbox_remains_in_deterministic_order_across_advances";
      }
      {
        label = "forged delivery restore test";
        needle = "restore_rejects_forged_completion_delivery_icount";
      }
      {
        label = "invalid requester live-path test";
        needle = "enqueue_rejects_non_vm_requester";
      }
      {
        label = "constructor invalid shift test";
        needle = "constructor_rejects_invalid_shift";
      }
      {
        label = "restore invalid empty shift test";
        needle = "restore_rejects_invalid_empty_snapshot_shift";
      }
      {
        label = "invalid VM node test";
        needle = "vm_nodes_are_rejected_as_io_subnodes";
      }
      {
        label = "scheduler completion test";
        needle = "scheduler_completion_preserves_exact_delivery_icount";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/io_subnode_trait.rs" focusedTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending placeholder";
        needle = "todo!";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 exposes I/O sub-node trait check";
        needle = "ioSubnodeTrait = import ./phase3-io-subnode-trait.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 I/O sub-node trait check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-io-subnode-trait";
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
          name = "run-io-subnode-trait";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-io-subnode-trait-target" \
              -p crucible \
              --test io_subnode_trait \
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
            component=crucible-io-subnode
            gate=gate:layer1-injection,gate:layer0-determinism
            uniform_io_subnode_trait=true
            deterministic_completion_model=true
            RESULT
          '';
        }
      ];
    }
