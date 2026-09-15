//! Protected journal ownership for runtime execution admission and effects.
//!
//! This module is source-only and is not called by controller dispatch. It
//! binds the portable runtime-backend records to one dedicated protected
//! journal, resolves exact replay before any fresh observation, and exposes
//! move-only recovery, dispatch, and completion evidence.

mod agent_store;
mod evidence;
mod owner;
mod recovery;
mod store;

pub use agent_store::{AuthenticatedJournalAgentCheckpointV1, JournalAgentStoreError};
pub use evidence::{
    JournalExecutionCompletionV1, RuntimeExecutionEvidenceError,
    completion_from_backend_observation_v1,
};
pub use owner::{
    DormantRuntimeExecutionClaimV1, DormantRuntimeExecutionOwnerErrorV1,
    DormantRuntimeExecutionOwnerV1,
};
pub use recovery::AppliedExecutionRecoveryV1;
pub use store::{
    AuthenticatedJournalExecutionRecoveryV1, ConsumedExecutionDispatchV1,
    ExecutionJournalRecoveryTokenV1, JournalRuntimeExecutionError, PreparedExecutionDispatchV1,
};
