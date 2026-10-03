//! Reexports the closed, nonauthorizing worker preparation wire.
//!
//! The shared protocol codec lets the actual Mount producer and fixed worker
//! compare identical bytes without introducing a dependency back into this
//! crate. A decoded plan or HELLO still proves no owner, lease or read grant.

pub use aos_sandbox_protocol::fuse_worker_preparation::{
    WORKER_PREPARATION_HELLO_BYTES_V1, WORKER_PREPARATION_PLAN_BYTES_V1, WorkerPreparationPlanV1,
    WorkerPreparationWireError,
};
