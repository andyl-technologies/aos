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
//! the run-twice gate driver; [`trace`] imports the real QEMU trace plugin's
//! host-observed samples into the canonical stream contract.

mod compare;
mod run;
mod state_dump;
mod trace;
mod types;

pub use compare::{
    SingleVmFingerprintMismatch, SingleVmFingerprintMismatchKind,
    SingleVmFingerprintSampleDifference, compare_single_vm_fingerprint_streams,
};
pub use run::run_single_vm_fingerprint_gate;
pub use state_dump::{
    SingleVmFingerprintDivergenceStateDump, SingleVmFingerprintMemoryRegionState,
    SingleVmFingerprintRunStateDump, SingleVmFingerprintVcpuState,
};
pub use trace::{
    QEMU_TRACE_FINGERPRINT_SCHEMA, QemuTraceDefinitionPreflight, QemuTraceFingerprintDefinition,
    QemuTraceFingerprintImport, QemuTraceFingerprintImportError, QemuTraceIdentityContract,
    QemuTraceObservationContract, QemuTraceVcpuContract,
};
pub use types::{
    SINGLE_VM_FINGERPRINT_DIGEST_BYTES, SingleVmFingerprintBisectionError,
    SingleVmFingerprintBisectionReport, SingleVmFingerprintBisectionRequest,
    SingleVmFingerprintEventBoundary, SingleVmFingerprintGateError, SingleVmFingerprintGateReport,
    SingleVmFingerprintRunError, SingleVmFingerprintRunInputs, SingleVmFingerprintRunOrdinal,
    SingleVmFingerprintRunRequest, SingleVmFingerprintRunner, SingleVmFingerprintSample,
    SingleVmFingerprintSampleMaterial, SingleVmFingerprintScenario, SingleVmFingerprintStream,
    SingleVmFingerprintTrigger, SingleVmHostProfile, SingleVmNvcpuFingerprintContract,
    SingleVmNvcpuFingerprintMaterial, SingleVmQmpVcpuTopology, SingleVmRoundRobinCursor,
    SingleVmVcpuRegisterDigest, compute_single_vm_sample_rolling_fingerprint,
    initial_single_vm_rolling_fingerprint,
};
