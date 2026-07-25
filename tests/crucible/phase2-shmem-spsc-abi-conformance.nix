{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.shmemSpscAbiConformance",
  taskIds ? ["T-SHM-15"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  shmemGate = builtins.readFile ../../crates/crucible-shmem/tests/gate_layer1_injection.rs;
  shmemSpec = builtins.readFile ../../docs/rfcs/0010-crucible/13-shmem-abi.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

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

  failures =
    failuresFor "crates/crucible-shmem/tests/gate_layer1_injection.rs" shmemGate [
      {
        label = "SPSC loom-style model";
        needle = "assert_spsc_ring_loom_model(";
      }
      {
        label = "loom interleaving enumerator";
        needle = "fn loom_schedules(";
      }
      {
        label = "publish-before-read model";
        needle = "fn model_check_publish_before_read(";
      }
      {
        label = "free-before-overwrite model";
        needle = "fn model_check_free_before_overwrite(";
      }
      {
        label = "actual RingHeader ordering source guard";
        needle = "assert_ring_header_source_uses_rfc_13_6_orderings";
      }
      {
        label = "function-scoped source order guard";
        needle = "assert_function_source_order";
      }
      {
        label = "no lost frame property";
        needle = "NoLostFrame";
      }
      {
        label = "no duplicated frame property";
        needle = "NoDuplicatedFrame";
      }
      {
        label = "FIFO order property";
        needle = "FifoOrder";
      }
      {
        label = "no torn frame property";
        needle = "NoTornFrame";
      }
      {
        label = "no early read property";
        needle = "NoEarlyRead";
      }
      {
        label = "torn frame negative control";
        needle = "TornFrameAfterPublishedWriteIndex";
      }
      {
        label = "overwrite-before-free negative control";
        needle = "ProducerOverwriteBeforeConsumerReadIsOrdered";
      }
      {
        label = "relaxed ordering negative control";
        needle = "relaxed_everywhere_negative_control_failed";
      }
      {
        label = "missing consumer acquire negative control";
        needle = "missing_consumer_acquire_negative_control_failed";
      }
      {
        label = "missing producer acquire negative control";
        needle = "missing_producer_acquire_negative_control_failed";
      }
      {
        label = "property test driver";
        needle = "assert_spsc_ring_proptest_properties(";
      }
      {
        label = "full and empty property";
        needle = "FullEmpty";
      }
      {
        label = "wraparound property";
        needle = "Wraparound";
      }
      {
        label = "seeded random property corpus";
        needle = "assert_seeded_random_property_corpus";
      }
      {
        label = "reproducible seeded RNG";
        needle = "SeededPropertyRng::new";
      }
      {
        label = "empty queue early-read guard";
        needle = "if live_count(head, tail, capacity)? == 0";
      }
    ]
    ++ forbiddenFor "crates/crucible-shmem/tests/gate_layer1_injection.rs" shmemGate [
      {
        label = "ignored SPSC ABI conformance test";
        needle = "#[ignore";
      }
      {
        label = "placeholder panic";
        needle = "implementation is pending";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/13-shmem-abi.md" shmemSpec [
      {
        label = "T-SHM-15 checklist complete";
        needle = "- [x] **T-SHM-15**";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes shmem SPSC ABI conformance check";
        needle = "shmemSpscAbiConformance = import ./phase2-shmem-spsc-abi-conformance.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 shmem SPSC ABI conformance check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-shmem-spsc-abi-conformance";
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
          name = "run-shmem-spsc-abi-conformance";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-shmem-spsc-abi-conformance-target" \
              -p crucible-shmem \
              --test gate_layer1_injection \
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
            gate=gate:abi-conformance
            tasks=${taskList}
            rust_tests=crucible-shmem::gate_layer1_injection
            queue=Lamport-SPSC
            memory_ordering=release-acquire
            model=source-guarded-loom-style-memory-order-interleavings
            properties=NoLostFrame,NoDuplicatedFrame,FifoOrder,NoTornFrame,NoEarlyRead,FullEmpty,Wraparound
            memory_order_negative_controls=relaxed-everywhere,missing-consumer-acquire,missing-producer-acquire
            randomized_property_seeds=4
            RESULT
          '';
        }
      ];
    }
