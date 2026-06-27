{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.blockCompletionModel",
  taskIds ? ["T-IO-4"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  blockSubnode = builtins.readFile ../../crates/crucible/src/block_subnode.rs;
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  focusedTest = builtins.readFile ../../crates/crucible/tests/block_subnode_completion.rs;
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
        label = "T-IO-4 checked off";
        needle = "- [x] **T-IO-4**";
      }
      {
        label = "T-IO-4 completion note";
        needle = "Completed by `checks.crucible.phase3.blockCompletionModel`";
      }
      {
        label = "formula note";
        needle = "`completion_vt = vt(request_icount) + latency(op, count, params)`";
      }
      {
        label = "deterministic latency note";
        needle = "deterministic function of operation, byte count, and configured latency parameters";
      }
      {
        label = "no host timing note";
        needle = "no host measured I/O time";
      }
      {
        label = "total order note";
        needle = "`(delivery_icount, src_node, seq)` order";
      }
    ]
    ++ failuresFor "crates/crucible/src/block_subnode.rs" blockSubnode [
      {
        label = "operation type";
        needle = "pub enum BlockSubNodeOperation";
      }
      {
        label = "latency params";
        needle = "pub struct BlockLatencyParameters";
      }
      {
        label = "latency computation";
        needle = "pub fn latency_for";
      }
      {
        label = "per-byte latency";
        needle = "per_byte";
      }
      {
        label = "completion request";
        needle = "pub struct BlockCompletionRequest";
      }
      {
        label = "completion plan";
        needle = "pub struct BlockCompletionPlan";
      }
      {
        label = "request planning";
        needle = "pub fn plan";
      }
      {
        label = "delivery icount helper";
        needle = "block_delivery_icount";
      }
      {
        label = "icount to virtual conversion";
        needle = "request_icount.to_virtual(shift)";
      }
      {
        label = "ceil conversion";
        needle = ".to_icount_ceil(shift)";
      }
      {
        label = "uniform I/O request bridge";
        needle = "into_io_request";
      }
      {
        label = "expected source bridge";
        needle = "expected_sub_node: Some(self.sub_node)";
      }
      {
        label = "expected delivery bridge";
        needle = "expected_delivery_icount: Some(self.delivery_icount)";
      }
      {
        label = "completion sorter";
        needle = "sort_block_completion_plans";
      }
      {
        label = "total order by source";
        needle = "left.sub_node.cmp(&right.sub_node)";
      }
      {
        label = "total order by sequence";
        needle = "left.sequence.cmp(&right.sequence)";
      }
      {
        label = "latency overflow";
        needle = "LatencyOverflow";
      }
      {
        label = "completion overflow";
        needle = "CompletionTimeOverflow";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/block_subnode.rs" blockSubnode [
      {
        label = "wall-clock dependency";
        needle = "SystemTime";
      }
      {
        label = "instant dependency";
        needle = "std::time::Instant";
      }
      {
        label = "thread sleep dependency";
        needle = "std::thread::sleep";
      }
      {
        label = "filesystem metadata dependency";
        needle = "std::fs::Metadata";
      }
      {
        label = "host path dependency";
        needle = "PathBuf";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "latency params exported";
        needle = "BlockLatencyParameters";
      }
      {
        label = "completion plan exported";
        needle = "BlockCompletionPlan";
      }
      {
        label = "sorter exported";
        needle = "sort_block_completion_plans";
      }
    ]
    ++ failuresFor "crates/crucible/tests/block_subnode_completion.rs" focusedTest [
      {
        label = "focused completion test";
        needle = "deterministic block sub-node completion planning";
      }
      {
        label = "formula test";
        needle = "completion_icount_uses_request_icount_operation_count_params_and_shift";
      }
      {
        label = "operation differentiation test";
        needle = "latency_model_differentiates_operation_and_byte_count";
      }
      {
        label = "total order test";
        needle = "coincident_completions_sort_by_delivery_subnode_and_sequence";
      }
      {
        label = "I/O bridge test";
        needle = "planned_completion_feeds_uniform_io_subnode_without_recomputing_host_time";
      }
      {
        label = "I/O bridge mismatch test";
        needle = "planned_completion_rejects_wrong_uniform_subnode_or_shift";
      }
      {
        label = "invalid node test";
        needle = "planner_rejects_non_disk_subnodes_and_non_vm_requesters";
      }
      {
        label = "overflow test";
        needle = "latency_and_completion_time_overflow_fail_loudly";
      }
      {
        label = "invalid shift test";
        needle = "invalid_shift_rejects_completion_planning";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/block_subnode_completion.rs" focusedTest [
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
        label = "phase3 exposes block completion check";
        needle = "blockCompletionModel = import ./phase3-block-completion-model.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 block completion model check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-block-completion-model";
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
          name = "run-block-completion-model";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-block-completion-model-target" \
              -p crucible \
              --test block_subnode_completion \
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
            component=crucible-block-completion-model
            gate=gate:layer1-injection
            formula=completion_vt_equals_vt_request_plus_latency
            latency_inputs=operation,count,configured-params
            forbidden_input=host-measured-io-time
            order=delivery_icount,src_node,seq
            RESULT
          '';
        }
      ];
    }
