//! `crucible-qemu` owns host-side QEMU integration.
//!
//! Spec index: RFC-0010 files 10, 11.
//!
//! This L2 crate will build launch arguments, supervise QEMU children, map the
//! shared-memory region, speak QMP, and implement the engine backend trait
//! described by its indexed RFC-0010 files. It is an unsafe-boundary crate
//! because future implementations may cross FFI and raw descriptor boundaries.
//!
//! Module map: `launch` owns the deterministic Contract-A launch profile and
//! canonical QEMU argument construction; `single_vm_fingerprint` owns the
//! safe run-twice-and-diff hook consumed by `gate:single-vm-fingerprint`.
//!
//! Unsafe boundary discipline: descriptor, shared-memory, monitor, and FFI
//! details stay private; public callers use a safe host-driver API that
//! validates process and mapping invariants before touching raw state.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

mod launch;
mod single_vm_fingerprint;

pub use launch::{
    DeterministicLaunchProfile, DiskImageMode, GuestBackingStateMode, GuestCoreContentMode,
    GuestEntropySeed, GuestEntropySeedFile, IcountShiftSetting, InputPolicy,
    LaunchProfileCandidate, LaunchProfileError, MachineResetMode, NodeClockSkewDeclaration,
    NodeIcountShift,
};
pub use single_vm_fingerprint::{
    SINGLE_VM_FINGERPRINT_DIGEST_BYTES, SingleVmFingerprintEventBoundary,
    SingleVmFingerprintGateError, SingleVmFingerprintGateReport, SingleVmFingerprintMismatch,
    SingleVmFingerprintMismatchKind, SingleVmFingerprintRunError, SingleVmFingerprintRunOrdinal,
    SingleVmFingerprintRunRequest, SingleVmFingerprintRunner, SingleVmFingerprintSample,
    SingleVmFingerprintScenario, SingleVmFingerprintStream, SingleVmFingerprintTrigger,
    SingleVmHostProfile, compare_single_vm_fingerprint_streams, run_single_vm_fingerprint_gate,
};
