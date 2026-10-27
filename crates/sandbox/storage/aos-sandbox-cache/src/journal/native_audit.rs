//! Shares Cache's finite Git/Q04 audit disposition over one actual reread.
//!
//! Both observers are pure comparison DATA. One native original, full Cold
//! recipe, captured same-description cursor and ordered ordinary disposal own
//! the read. Purpose callers keep their distinct native bookends and complete
//! replay comparisons outside this mechanical owner.

use aos_sandbox_broker::canonical_journal::{
    CanonicalOrdinaryRereadDataV1, CanonicalOrdinaryRereadOriginalV1,
    coordinator::indexed_replay::{CanonicalIndexedReplayErrorV1, CanonicalIndexedReplayV1},
};
use aos_sandbox_journal::protected_storage::FileIdentity;
use aos_sandbox_ledger_replay::{
    cold::{ColdReplayOriginalV1, ColdReplayRemainderDataV1, git_prefix::CacheGitPrefixReplayDataV1},
    q04_native_history::{Q04NativeRecipeAuditDataV1, Q04NativeHistoryDataErrorV1},
};

use super::{Journal, JournalError, JournalLimits};

pub(super) enum CacheNativeAuditV1<'data> {
    Git(CacheGitPrefixReplayDataV1<'data>),
    Q04(Q04NativeRecipeAuditDataV1<'data>),
}

impl CacheNativeAuditV1<'_> {
    fn observe_once(
        &mut self,
        semantic: &mut ColdReplayOriginalV1,
        cursor: &mut CanonicalIndexedReplayV1<'_, '_>,
        identity: FileIdentity,
        limits: JournalLimits,
    ) -> Result<(), JournalError> {
        match self {
            Self::Git(audit) => semantic.observe_indexed_with_cache_git_prefix_once_v1(cursor, identity, limits, audit),
            Self::Q04(audit) => semantic.observe_indexed_with_q04_native_recipe_once_v1(cursor, identity, limits, audit),
        }.map_err(|_| JournalError::boundary())
    }

    fn failure_is_selected(&self, semantic: &ColdReplayOriginalV1) -> bool {
        match self {
            Self::Git(_) => semantic.cache_git_prefix_failure_is_selected_v1(),
            Self::Q04(_) => semantic.q04_native_recipe_failure_is_selected_v1(),
        }
    }

    fn into_ordinary_failure(self) -> Option<JournalError> {
        match self {
            Self::Git(audit) => audit.into_ordinary_failure_v1().map(JournalError::from),
            Self::Q04(audit) => audit.into_ordinary_failure_v1().map(q04_history_error),
        }
    }
}

pub(super) fn q04_history_error(cause: Q04NativeHistoryDataErrorV1) -> JournalError {
    match cause {
        Q04NativeHistoryDataErrorV1::Mechanical(cause) => JournalError::from(cause),
        cause => JournalError::Q04HistoryData(Box::new(cause)),
    }
}

impl Journal {
    pub(super) fn reread_native_audit_v1<'data>(
        &self,
        length: u64,
        mut audit: CacheNativeAuditV1<'data>,
    ) -> Result<(CanonicalOrdinaryRereadDataV1, ColdReplayRemainderDataV1, CacheNativeAuditV1<'data>), JournalError> {
        let mut native = CanonicalOrdinaryRereadOriginalV1::new();
        let mut semantic = ColdReplayOriginalV1::new();
        let body = (|| {
            // Preserve the existing bounded same-description reader. The
            // alternative captured helper adds a new early metadata refusal.
            let (identity, mut cursor) = native.begin_coordinator_ordinary_once_v1(
                self.read_view().captured_reader(length), self.limits(),
            ).map_err(JournalError::from_ordinary_native_v1)?;
            audit.observe_once(&mut semantic, &mut cursor, identity, self.limits())?;
            semantic.take_remainder_once().ok_or(JournalError::boundary())
        })();
        let native_selected = native.failure().is_some();
        let audit_selected = audit.failure_is_selected(&semantic);
        semantic.dispose_ordinary_prospective_v1();
        let current = native.dispose_ordinary_current_once_v1();
        let (upper_native, upper_semantic) = semantic.into_ordinary_errors();
        let pending = native.dispose_ordinary_pending_once_v1();
        match body {
            Ok(remainder) if current.is_ok() && pending.is_ok() => {
                let completed = native.into_completed_comparison_data_v1().map_err(|original| {
                    drop(original);
                    JournalError::boundary()
                })?;
                Ok((completed, remainder, audit))
            }
            result => {
                let body = result.err().unwrap_or(JournalError::boundary());
                let (index, physical) = match native.into_ordinary_errors_v1() {
                    Ok(errors) => errors,
                    Err(original) => {
                        drop(original);
                        return Err(body);
                    }
                };
                if audit_selected {
                    if let Some(cause) = audit.into_ordinary_failure() {
                        return Err(cause);
                    }
                }
                if native_selected {
                    if let Some(cause) = index {
                        return Err(cause.into());
                    }
                    if let Some(cause) = physical {
                        return Err(JournalError::from_ordinary_native_v1(cause));
                    }
                }
                if let Some(cause) = upper_native {
                    return Err(match cause {
                        CanonicalIndexedReplayErrorV1::Native(cause) => JournalError::from_ordinary_native_v1(cause),
                        CanonicalIndexedReplayErrorV1::Closed => JournalError::boundary(),
                    });
                }
                Err(upper_semantic.map(JournalError::from).unwrap_or(body))
            }
        }
    }
}
