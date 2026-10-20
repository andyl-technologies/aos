//! Forwards installed Controller Runtime DATA and admission to the sole C owner.
//!
//! The lower receiver drives its own PID1, pids, funding and independent posts
//! under the same actual original/profile. This adapter adds no callback,
//! reservation, completion token or duplicate receiving implementation.

pub use aos_sandbox_broker::controller_receiving::{
    ControllerRuntimeCredentialShapeV1, ControllerRuntimeRequestedCountsV1, ControllerRuntimeTaskEnvelopeV1,
    ControllerRuntimeStartupShapeV1, CONTROLLER_RUNTIME_BLOCKING_THREADS_V1,
    CONTROLLER_RUNTIME_ROLE_TASKS_V1, CONTROLLER_RUNTIME_STACK_BYTES_V1,
    CONTROLLER_RUNTIME_TASKS_V1,
};
pub(super) use aos_sandbox_broker::controller_receiving::ControllerRuntimeStartupAdmissionV1;
