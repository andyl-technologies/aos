//! Keeps the actual signer anchor around the shared task-subject engine.
//!
//! The native engine is common with the fixed Root/Controller service peers;
//! this adapter preserves the existing Cache reply classification and owner.

use super::*;
use aos_sandbox_linux::pidfd::PidFdProcessIdentity;
use aos_sandbox_linux::unix_stream::UnixStreamSubjectChunk;
use crate::fixed_task_subject::{FixedTaskSubjectOriginalsV1, FixedTaskSubjectClosedV1};

impl From<FixedTaskSubjectClosedV1> for CacheCurrentSignerExchangeClosedV1 {
    fn from(error: FixedTaskSubjectClosedV1) -> Self {
        match error {
            FixedTaskSubjectClosedV1::Order => Self::Order,
            FixedTaskSubjectClosedV1::Retained => Self::Retained,
            FixedTaskSubjectClosedV1::Subject => Self::Subject,
        }
    }
}

pub(super) struct SignerSubjectOriginalsV1 {
    native: FixedTaskSubjectOriginalsV1<CacheCurrentSignerExchangeClosedV1>,
}

impl SignerSubjectOriginalsV1 {
    pub(super) fn new() -> Self { Self { native: FixedTaskSubjectOriginalsV1::new() } }

    pub(super) fn observe_once(&mut self, chunk: &UnixStreamSubjectChunk,
        anchor: Option<&SignerAnchorV1>, uid: u32, gid: u32,
    ) -> Result<(), CacheCurrentSignerExchangeClosedV1> {
        self.native.observe_cache_reply_once(chunk,
            anchor.map(|anchor| (&anchor.chunk, anchor.identity)), uid, gid)
    }

    pub(super) fn identity(&self) -> Option<PidFdProcessIdentity> { self.native.identity() }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> { self.native.failure() }
}

pub(super) struct SignerAnchorV1 {
    pub(super) chunk: UnixStreamSubjectChunk,
    pub(super) _originals: SignerSubjectOriginalsV1,
    pub(super) identity: PidFdProcessIdentity,
}
