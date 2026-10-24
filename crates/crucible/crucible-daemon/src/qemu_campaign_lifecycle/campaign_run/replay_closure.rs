//! Preserves the original campaign replay-closure source path.
//!
//! The backend-neutral owner retains the unchanged CCRC1 encoding, error
//! semantics and complete choice references. This shim keeps legacy module and
//! schema-owner aliases while native materialization stays with its adapter.

pub(crate) use crate::campaign_replay_closure::GuardedCampaignReplaySelection;
pub(crate) use crate::campaign_replay_closure::schedule_selection_ids;
pub use crate::campaign_replay_closure::{
    GuardedCampaignReplayClosure, GuardedCampaignReplayClosureError,
    validate_remote_resume_replay_closure,
};
