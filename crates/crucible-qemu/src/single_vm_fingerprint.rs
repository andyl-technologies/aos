//! Single-VM execution-fingerprint gate hook.
//!
//! This module owns the safe host-side contract consumed by
//! `gate:single-vm-fingerprint`: run one fixed single-VM scenario twice and
//! compare the canonical fingerprint streams byte-for-byte. Later QEMU process
//! supervision code plugs into [`SingleVmFingerprintRunner`]; the gate driver
//! here is independent of how a backend obtains register, memory, device, and
//! RR-scheduler digests.
//!
//! Module map: [`types`] owns the public scenario, stream, runner, and error
//! data contracts; [`compare`] owns first-mismatch localization; [`run`] owns
//! the run-twice gate driver.

mod compare;
mod run;
mod types;

pub use compare::{
    SingleVmFingerprintMismatch, SingleVmFingerprintMismatchKind,
    compare_single_vm_fingerprint_streams,
};
pub use run::run_single_vm_fingerprint_gate;
pub use types::{
    SINGLE_VM_FINGERPRINT_DIGEST_BYTES, SingleVmFingerprintEventBoundary,
    SingleVmFingerprintGateError, SingleVmFingerprintGateReport, SingleVmFingerprintRunError,
    SingleVmFingerprintRunOrdinal, SingleVmFingerprintRunRequest, SingleVmFingerprintRunner,
    SingleVmFingerprintSample, SingleVmFingerprintScenario, SingleVmFingerprintStream,
    SingleVmFingerprintTrigger, SingleVmHostProfile,
};
