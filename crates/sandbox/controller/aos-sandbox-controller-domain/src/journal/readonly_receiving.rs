//! Dispatches the remaining genuine role loans through the one captured readonly parser.
//!
//! Role owners construct their own checked contexts and keep their original
//! ledgers, geometry failures and suffix observers. Only Journal descendants
//! bind an actual held capture length to this closed dispatch; no callback,
//! public payer constructor or raw Journal escapes to either caller.

use super::{JournalError, JournalTransaction, RecordNamespace};

type State = std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

// Inner lifetime names are variant-local: each operation borrows exactly one
// genuine context. The outer mutable dispatch borrow can end before its owner
// inspects the retained suffix or performs the remaining physical posts.
pub(super) enum ReadonlyReceivingContextV1<'dispatch, 'borrow, 'original, 'data> {
    RootController(
        &'dispatch mut super::RootControllerReadonlyReceivingContextV1<
            'borrow, 'original, 'data,
        >,
    ),
    Cache(
        &'dispatch mut crate::cache_residency::CacheHeldReadonlyContextV1<
            'borrow,
            'original,
            'data,
        >,
    ),
}

pub(super) struct CapturedReadonlyReceivingContextV1<'dispatch, 'borrow, 'original, 'data> {
    receiver: ReadonlyReceivingContextV1<'dispatch, 'borrow, 'original, 'data>,
    captured_end: u64,
}

impl<'dispatch, 'borrow, 'original, 'data>
    ReadonlyReceivingContextV1<'dispatch, 'borrow, 'original, 'data>
{
    // The only production caller is the retained opener immediately after
    // capture_opened_prefix_once. The length is not a caller-supplied extent.
    pub(super) fn bind_captured_file_end(
        mut self,
        captured_end: u64,
    ) -> Result<
        CapturedReadonlyReceivingContextV1<'dispatch, 'borrow, 'original, 'data>,
        JournalError,
    > {
        match &mut self {
            Self::Cache(receiving) => receiving.require_captured_file_end(captured_end)?,
            Self::RootController(receiving) => receiving.require_captured_file_end(captured_end)?,
        }

        Ok(CapturedReadonlyReceivingContextV1 {
            receiver: self,
            captured_end,
        })
    }
}

impl CapturedReadonlyReceivingContextV1<'_, '_, '_, '_> {
    // This selects only a DATA disposition from the already bound closed loan.
    // The actual role's fixed payment precedes this parser entry.
    pub(super) fn retains_source_family_originals(&self) -> bool {
        matches!(&self.receiver, ReadonlyReceivingContextV1::RootController(_))
    }

    pub(super) fn before_semantic_replay(
        &mut self,
        state: &State,
        transaction: Option<&JournalTransaction>,
    ) -> Result<(), JournalError> {
        match &mut self.receiver {
            ReadonlyReceivingContextV1::RootController(receiving) => {
                receiving.before_semantic_replay(state, transaction)
            }
            ReadonlyReceivingContextV1::Cache(receiving) => {
                receiving.before_semantic_replay(state, transaction)
            }
        }
    }

    pub(super) fn observe_native_commit(
        &mut self,
        transaction: &JournalTransaction,
        begin_sequence: u64,
        commit_sequence: u64,
        begin_offset: u64,
        end_offset: u64,
    ) -> Result<(), JournalError> {
        match &mut self.receiver {
            ReadonlyReceivingContextV1::RootController(receiving) => receiving.observe_native_commit(
                transaction, begin_sequence, commit_sequence, begin_offset, end_offset,
            ),
            ReadonlyReceivingContextV1::Cache(receiving) => receiving.observe_native_commit(
                transaction,
                begin_sequence,
                commit_sequence,
                begin_offset,
                end_offset,
            ),
        }
    }

    pub(super) fn finish_native_replay(
        &mut self,
        durable_next: u64,
        durable_end: u64,
    ) -> Result<(), JournalError> {
        match &mut self.receiver {
            ReadonlyReceivingContextV1::Cache(receiving) => {
                receiving.finish_native(durable_next, durable_end, self.captured_end)
            }
            ReadonlyReceivingContextV1::RootController(receiving) => {
                receiving.finish_native_replay(durable_next, durable_end)
            }
        }
    }
}
