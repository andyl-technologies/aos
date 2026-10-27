{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.spscConcurrency",
  taskIds ? ["T-HARN-18" "T-SHM-6"],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;

  shmemLib = import ./_crucible-shmem-source.nix {inherit lib;};
  shmemGate = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/crucible-qemu-shmem/tests/gate_layer1_injection.rs;
  };
  gateTargets = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/crucible-test-support/src/gate_targets.rs;
  };
  gateTargetMapping = builtins.readFile ./phase1-gate-target-mapping.nix;
  harnessTesting = builtins.readFile ../../docs/rfcs/0010-crucible/24-determinism-harness-testing.md;
  shmemSpec = builtins.readFile ../../docs/rfcs/0010-crucible/13-shmem-abi.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "crates/crucible/crucible-qemu-shmem/src/lib.rs" shmemLib [
      {
        label = "Lamport SPSC ring header";
        needle = "pub struct RingHeader";
      }
      {
        label = "default queue capacity";
        needle = "pub const DEFAULT_QUEUE_CAPACITY";
      }
      {
        label = "ring enqueue API";
        needle = "pub fn enqueue(";
      }
      {
        label = "ring dequeue API";
        needle = "pub fn dequeue(&self, entries: &[FrameEntry])";
      }
      {
        label = "delivery icount peek API";
        needle = "pub fn peek_delivery_icount(";
      }
      {
        label = "ring snapshot type";
        needle = "pub struct SpscRingSnapshot";
      }
      {
        label = "ring error type";
        needle = "pub enum SpscRingError";
      }
      {
        label = "consumer index acquire load";
        needle = "self.read_idx.load(Ordering::Acquire)";
      }
      {
        label = "producer index acquire load";
        needle = "self.write_idx.load(Ordering::Acquire)";
      }
      {
        label = "producer release publish";
        needle = ".store(tail.wrapping_add(1), Ordering::Release)";
      }
      {
        label = "consumer release free";
        needle = ".store(head.wrapping_add(1), Ordering::Release)";
      }
      {
        label = "capacity validation";
        needle = "fn validated_capacity<T>(";
      }
      {
        label = "live-count validation";
        needle = "fn live_count(";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-qemu-shmem/tests/gate_layer1_injection.rs" shmemGate [
      {
        label = "SPSC exhaustive ordering model";
        needle = "assert_spsc_ring_exhaustive_ordering_model(";
      }
      {
        label = "actual RingHeader ordering source guard";
        needle = "assert_ring_header_source_uses_rfc_13_6_orderings";
      }
      {
        label = "function-scoped RingHeader ordering guard";
        needle = "assert_function_source_order";
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
        label = "SPSC property test driver";
        needle = "assert_spsc_ring_exhaustive_trace_properties(";
      }
      {
        label = "seeded randomized property corpus";
        needle = "assert_seeded_random_property_corpus";
      }
      {
        label = "seeded RNG for reproducible randomized properties";
        needle = "SeededPropertyRng::new";
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
        label = "full and empty property";
        needle = "FullEmpty";
      }
      {
        label = "wraparound property";
        needle = "Wraparound";
      }
      {
        label = "host-independent observed vector model";
        needle = "fn run_two_vm_injection";
      }
      {
        label = "host timing negative control";
        needle = "assert_ne!(producer_skewed, consumer_skewed);";
      }
    ]
    ++ forbiddenFor "crates/crucible/crucible-qemu-shmem/tests/gate_layer1_injection.rs" shmemGate [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "placeholder panic";
        needle = "implementation is pending";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-test-support/src/gate_targets.rs" gateTargets [
      {
        label = "implemented shmem layer1 target";
        needle = "package: \"crucible-qemu-shmem\",\n        test_target: \"gate_layer1_injection\",\n        required_features: &[],";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-gate-target-mapping.nix" gateTargetMapping [
      {
        label = "implemented shmem layer1 mapping target";
        needle = "gate = \"gate:layer1-injection\";\n      package = \"crucible-qemu-shmem\";\n      testTarget = \"gate_layer1_injection\";\n      requiredFeatures = [];";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" harnessTesting [
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/13-shmem-abi.md" shmemSpec [
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes SPSC concurrency check";
        needle = "spscConcurrency = import ./phase2-spsc-concurrency.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 SPSC concurrency check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    mkCrucibleTestGate {
      pname = "crucible-phase2-spsc-concurrency";

      buildDeps = [
        pkgs.coreutils
        pkgs.sed
      ];

      phases = [
        {
          name = "run-spsc-concurrency";
          script = ''
            set -eu
            cd crates
            crucible-cargo test \
              -p crucible-qemu-shmem \
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
            gate=gate:layer1-injection
            tasks=${taskList}
            rust_tests=crucible_qemu_shmem::gate_layer1_injection
            queue=Lamport-SPSC
            memory_ordering=release-acquire
            model=source-guarded-exhaustive-memory-order-interleavings
            properties=NoLostFrame,NoDuplicatedFrame,FifoOrder,FullEmpty,Wraparound
            memory_order_negative_controls=relaxed-everywhere,missing-consumer-acquire,missing-producer-acquire
            randomized_property_seeds=4
            host_timing_negative_control=true
            RESULT
          '';
        }
      ];
    }
