//! Execution-fingerprint definition and comparison utilities for harness gates.
//!
//! The types in this module model the comparison surface shared by
//! `gate:single-vm-fingerprint`, `gate:adversarial-determinism`, and divergence
//! bisection. The module owns the fixed content-addressed fingerprint definition
//! and rolling sample hash, while [`FingerprintObserver`] is the black-box
//! host-side observation boundary used to obtain register, memory, device, and
//! RR-scheduler state from a backend.
//!
//! Module map: `definition` owns the versioned content-addressed definition,
//! `observation` owns host-side sampling and sample construction, `stream` owns
//! stream comparison, and `hasher` owns the local stable byte accumulator.

mod definition;
mod hasher;
mod observation;
mod stream;

pub use definition::{
    CANONICAL_FINGERPRINT_PERIOD_ICOUNT, DEVICE_DIGEST_ALGORITHM,
    EXECUTION_FINGERPRINT_DEFINITION_VERSION, FINGERPRINT_DIGEST_BYTES, FINGERPRINT_HASH_ALGORITHM,
    FingerprintCadence, FingerprintDefinition, FingerprintDigest, FingerprintEventBoundary,
    FingerprintSampleTrigger, MEMORY_DIGEST_ALGORITHM, MemoryFingerprintScope,
    REGISTER_DIGEST_ALGORITHM,
};
pub use observation::{
    FingerprintObservationError, FingerprintObservationRequest, FingerprintObserver,
    FingerprintSampleError, FingerprintSampleMaterial, HostFingerprintObservation,
    RrSchedulerState, VcpuRegisterDigest, VcpuRetiredCount, compute_fingerprint_sample,
    observe_fingerprint_sample,
};
pub use stream::{
    FingerprintMismatch, FingerprintMismatchKind, FingerprintSample, FingerprintStream,
    compare_fingerprint_streams, initial_rolling_fingerprint,
};
