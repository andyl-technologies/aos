{
  pkgs,
  lib,
}: let
  fingerprintRoot = builtins.readFile ../../crates/crucible-harness/src/fingerprint.rs;
  fingerprintDefinition = builtins.readFile ../../crates/crucible-harness/src/fingerprint/definition.rs;
  fingerprintHasher = builtins.readFile ../../crates/crucible-harness/src/fingerprint/hasher.rs;
  fingerprintObservation = builtins.readFile ../../crates/crucible-harness/src/fingerprint/observation.rs;
  fingerprintStream = builtins.readFile ../../crates/crucible-harness/src/fingerprint/stream.rs;
  fingerprintTest = builtins.readFile ../../crates/crucible-harness/tests/fingerprint_definition.rs;
  fingerprintRust = fingerprintRoot + fingerprintDefinition + fingerprintHasher + fingerprintObservation + fingerprintStream + fingerprintTest;
  determinismContract = builtins.readFile ../../docs/rfcs/0010-crucible/04-determinism-contract.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "crates/crucible-harness/src/fingerprint.rs" fingerprintRust [
      {
        label = "versioned fingerprint definition";
        needle = "EXECUTION_FINGERPRINT_DEFINITION_VERSION";
      }
      {
        label = "canonical period constant";
        needle = "CANONICAL_FINGERPRINT_PERIOD_ICOUNT";
      }
      {
        label = "content-addressed definition type";
        needle = "pub struct FingerprintDefinition";
      }
      {
        label = "canonical definition constructor";
        needle = "pub fn canonical() -> Self";
      }
      {
        label = "icount-driven cadence";
        needle = "pub struct FingerprintCadence";
      }
      {
        label = "event boundary trigger";
        needle = "pub enum FingerprintEventBoundary";
      }
      {
        label = "canonical event boundary set";
        needle = "canonical_event_boundaries";
      }
      {
        label = "definition digest event boundary set";
        needle = "write_event_boundary_set";
      }
      {
        label = "memory scope";
        needle = "pub enum MemoryFingerprintScope";
      }
      {
        label = "host observation trait";
        needle = "pub trait FingerprintObserver";
      }
      {
        label = "atomic host observation method";
        needle = "fn observe_sample";
      }
      {
        label = "atomic host observation record";
        needle = "pub struct HostFingerprintObservation";
      }
      {
        label = "sample material";
        needle = "pub struct FingerprintSampleMaterial";
      }
      {
        label = "vCPU register digest";
        needle = "pub struct VcpuRegisterDigest";
      }
      {
        label = "fixed 256-bit digest length";
        needle = "FINGERPRINT_DIGEST_BYTES";
      }
      {
        label = "invalid digest length rejection";
        needle = "InvalidDigestLength";
      }
      {
        label = "RR scheduler state";
        needle = "pub struct RrSchedulerState";
      }
      {
        label = "register and RR vCPU set validation";
        needle = "MismatchedVcpuSet";
      }
      {
        label = "current RR vCPU validation";
        needle = "CurrentVcpuMissing";
      }
      {
        label = "definition digest folded into stream";
        needle = "pub definition_digest: FingerprintDigest";
      }
      {
        label = "definition mismatch kind";
        needle = "FingerprintMismatchKind::Definition";
      }
      {
        label = "initial rolling fingerprint";
        needle = "pub fn initial_rolling_fingerprint";
      }
      {
        label = "sample hash construction";
        needle = "pub fn compute_fingerprint_sample";
      }
      {
        label = "host observation sample construction";
        needle = "pub fn observe_fingerprint_sample";
      }
      {
        label = "observed icount validation";
        needle = "ObservedIcountMismatch";
      }
      {
        label = "periodic icount sampler";
        needle = "samples_periodic_icount";
      }
      {
        label = "off-cadence rejection";
        needle = "FingerprintSampleError::OffCadence";
      }
      {
        label = "content-addressed definition test marker";
        needle = "fingerprint_definition_digest_is_stable_and_content_addressed";
      }
      {
        label = "host observation boundary test marker";
        needle = "fingerprint_observer_boundary_supplies_black_box_state";
      }
      {
        label = "observed icount mismatch test marker";
        needle = "fingerprint_observer_boundary_rejects_mismatched_icount";
      }
      {
        label = "golden definition digest";
        needle = "CANONICAL_DEFINITION_DIGEST_HEX";
      }
      {
        label = "sample state coverage test marker";
        needle = "fingerprint_sample_hashes_icount_register_memory_device_and_rr_state";
      }
      {
        label = "cadence enforcement test marker";
        needle = "fingerprint_sample_enforces_periodic_or_event_boundary_cadence";
      }
      {
        label = "per-vCPU canonicalization test marker";
        needle = "fingerprint_sample_material_sorts_vcpu_state_by_id";
      }
      {
        label = "per-vCPU set mismatch test marker";
        needle = "fingerprint_sample_material_rejects_mismatched_vcpu_sets";
      }
      {
        label = "current vCPU presence test marker";
        needle = "fingerprint_sample_material_requires_current_vcpu_in_sample";
      }
      {
        label = "canonical digest length test marker";
        needle = "fingerprint_sample_material_rejects_non_canonical_digest_lengths";
      }
      {
        label = "definition mismatch test marker";
        needle = "compare_fingerprint_streams_rejects_definition_mismatch";
      }
    ]
    ++ forbiddenFor "crates/crucible-harness/src/fingerprint.rs" fingerprintRust [
      {
        label = "host wall-clock sampling";
        needle = "SystemTime";
      }
      {
        label = "host monotonic sampling";
        needle = "Instant";
      }
      {
        label = "thread RNG";
        needle = "thread_rng";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/04-determinism-contract.md" determinismContract [
      {
        label = "T-DET-8 checklist entry";
        needle = "**T-DET-8**";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes execution fingerprint definition check";
        needle = "executionFingerprintDefinition = import ./phase1-execution-fingerprint-definition.nix";
      }
      {
        label = "single-VM fingerprint gate lists T-DET-8";
        needle = "\"T-DET-8\"";
      }
      {
        label = "single-VM fingerprint gate depends on execution fingerprint definition";
        needle = "phase1-execution-fingerprint-definition.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 execution fingerprint definition check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-execution-fingerprint-definition";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils];

      phases = [
        {
          name = "record-execution-fingerprint-definition";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            status=partial
            check=checks.crucible.phase1.executionFingerprintDefinition
            gate=gate:single-vm-fingerprint
            provisional_tasks=T-DET-8
            definition=crucible-execution-fingerprint-v1
            cadence=periodic-4096-icount-plus-event-boundaries
            period_icount=4096
            event_boundaries=horizon-advance,frame-delivery,signal-effect-boundary
            memory_scope=full-guest-memory
            register_digest_algorithm=host-observed-architectural-register-digest-v1
            memory_digest_algorithm=host-observed-full-guest-memory-digest-v1
            device_digest_algorithm=host-observed-device-state-digest-v1
            digest_bytes=32
            sample_fields=icount,registers,memory,device,rr-scheduler
            observation_boundary=host-black-box
            content_addressed=true
            implementation_scope=definition-and-model-observer
            provisional_trace_importer=crucible-qemu-fingerprint
            provisional_trace_schema=crucible.qemu.trace-fingerprint.v6
            provisional_device_component=current-non-ram-qemu-vmstate
            provisional_event_boundary_sampling=horizon-advance-live;frame-and-fault-model-only
            provisional_observation_contract_source=independent-definition-only-qemu-preflight
            independent_observation_contract=true
            full_device_state_complete=true
            task_completion=partial
            RESULT
          '';
        }
      ];
    }
