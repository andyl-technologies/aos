//! Keeps the actual writable opening and its upper semantic originals together.
//!
//! Common acquisition owns the physical files, canonical parser and private
//! index. This finite upper reservoir keeps the same semantic models, returned
//! Journal, native posts and first cause. It creates no receiving allowance or
//! protected role, and accepts no raw native parts or replay-success input.

use std::path::Path;

use aos_sandbox_broker::canonical_journal::{
    CanonicalOrdinaryHeldJournalV1, CanonicalOrdinaryOpeningOriginalsV1,
    RecoveryReport as NativeRecoveryReport,
};
use aos_sandbox_journal::protected_storage::CapturedReplayPrefixPostV1;
use aos_sandbox_journal::recovery::RecoveryTailMode;

use super::super::super::super::native_backing::Selection;
use super::super::super::super::ordinary_semantics::OrdinarySemanticReplayOriginalV1;
use super::super::super::super::semantic_remainder::DomainSemanticRemainderDataV1;
use super::super::super::super::{
    JournalAuthorityInstance, ProtectedJournalCurrentnessOriginalsV1,
};
use super::captured_preparation::CapturedWriterPreparationV1;
use super::{Journal, JournalError, JournalLimits, RecoveryReport};

type Held = CanonicalOrdinaryHeldJournalV1<Selection, JournalAuthorityInstance>;

#[derive(Clone, Copy)]
pub(super) enum First {
    Native,
    Semantic,
    PrefixPost,
    Materialization,
}

/// Retains one actual writable opening through all enclosing native posts.
pub(crate) struct ProtectedWriterOpenOriginalsV1 {
    pub(super) native: CanonicalOrdinaryOpeningOriginalsV1,
    held: Option<(Held, NativeRecoveryReport)>,
    pub(super) journal: Option<Journal>,
    semantic: Option<OrdinarySemanticReplayOriginalV1>,
    remainder: Option<DomainSemanticRemainderDataV1>,
    prefix_post: Option<CapturedReplayPrefixPostV1<JournalError>>,
    prefix_result: Option<Result<(), JournalError>>,
    #[cfg(target_os = "linux")]
    pub(super) extent:
        Option<Result<crate::journal::ProtectedJournalPreopenReplayExtentV1, JournalError>>,
    #[cfg(target_os = "linux")]
    captured_append: Option<crate::journal::native_interval::captured::CapturedAppendOwnerV1>,
    pub(super) returned: Option<Result<RecoveryReport, JournalError>>,
    pub(super) captured: CapturedWriterPreparationV1,
    pub(super) selection: Option<Selection>,
    pub(super) first: Option<First>,
    pub(super) attempted: bool,
}

impl ProtectedWriterOpenOriginalsV1 {
    /// Adds only the real writable construction planes outside its resident T.
    pub(crate) fn fixed_writable_preparation_demand_v1<T>(
        directory_descriptors: u16,
        path_name_bytes: u16,
    ) -> Result<aos_sandbox_model::ResourceVector, aos_sandbox_model::AccountingError> {
        use aos_sandbox_broker::canonical_journal::CanonicalJournalInstanceDataV1;
        use aos_sandbox_model::{AccountingError, ResourceDimension as D};

        let overflow = || AccountingError::ArithmeticOverflow {
            dimension: D::MemoryBytes,
        };
        let base = CanonicalOrdinaryOpeningOriginalsV1::<()>::fixed_preparation_demand_v1::<T>(directory_descriptors, path_name_bytes)?;

        // T already contains one opening and its resident held-output slot.
        // Keep the common supplier's other working/return planes, without
        // billing those actual resident fields for a second time.
        let native =
            CanonicalOrdinaryOpeningOriginalsV1::<()>::receiving_payload_construction_bytes_v1::<
                Selection,
                JournalAuthorityInstance,
            >()
            .and_then(|bytes| {
                bytes.checked_sub(std::mem::size_of::<CanonicalOrdinaryOpeningOriginalsV1>())
            })
            .and_then(|bytes| {
                bytes.checked_sub(std::mem::size_of::<Option<(Held, NativeRecoveryReport)>>())
            })
            .ok_or_else(overflow)?;
        let semantic = OrdinarySemanticReplayOriginalV1::receiving_demand_v1()
            .map_err(|_| overflow())?
            .get(D::MemoryBytes);
        let semantic = usize::try_from(semantic)
            .ok()
            .and_then(|bytes| {
                bytes.checked_sub(std::mem::size_of::<OrdinarySemanticReplayOriginalV1>())
            })
            .and_then(|bytes| {
                bytes.checked_sub(std::mem::size_of::<DomainSemanticRemainderDataV1>())
            })
            .ok_or_else(overflow)?;
        let materialization = Journal::ordinary_materialization_receiving_bytes_v1()
            .and_then(|bytes| bytes.checked_sub(std::mem::size_of::<Journal>()))
            .ok_or_else(overflow)?;
        let instance = CanonicalJournalInstanceDataV1::<JournalAuthorityInstance>::
            payload_allocation_receiving_bytes_v1().ok_or_else(overflow)?;
        let additional = native
            .checked_add(semantic)
            .and_then(|bytes| bytes.checked_add(materialization))
            .and_then(|bytes| bytes.checked_add(instance))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(overflow)?;
        let memory = base
            .get(D::MemoryBytes)
            .checked_add(additional)
            .ok_or_else(overflow)?;
        Ok(base.with(D::MemoryBytes, memory))
    }

    pub(crate) const fn new() -> Self {
        Self {
            native: CanonicalOrdinaryOpeningOriginalsV1::new(),
            held: None,
            journal: None,
            semantic: None,
            remainder: None,
            prefix_post: None,
            prefix_result: None,
            #[cfg(target_os = "linux")]
            extent: None,
            #[cfg(target_os = "linux")]
            captured_append: None,
            returned: None,
            captured: CapturedWriterPreparationV1::new(),
            selection: None,
            first: None,
            attempted: false,
        }
    }

    /// Enters the existing immediate captured route through the same two stages.
    pub(crate) fn open_captured_once(&mut self, path: &Path, name: &str, limits: JournalLimits) {
        if self.attempted {
            return;
        }
        self.prepare_captured_once(path, name, limits);
        self.replay_prepared_once();
    }

    pub(super) fn prepare_native_inner(
        &mut self,
        path: &Path,
        name: &str,
        limits: JournalLimits,
        uid: u32,
        create: bool,
    ) -> Result<(), JournalError> {
        #[cfg(target_os = "linux")]
        {
            self.selection = Some(
                crate::journal::runtime_deployment_history::OriginalCompactionSelectionV1::capture(
                    path, name,
                ),
            );
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.selection = Some(());
        }
        self.native
            .prepare_retaining_once_v1(path, name, limits, uid, create)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        #[cfg(target_os = "linux")]
        {
            let actual = self
                .native
                .prepared_extent_v1()
                .map_err(|_| JournalError::ProtectedBoundary)?;
            self.extent = Some(
                crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(
                    actual.limits(),
                    actual.native_bytes(),
                ),
            );
            if !matches!(self.extent, Some(Ok(_))) {
                return Err(JournalError::ProtectedBoundary);
            }
        }
        Ok(())
    }

    pub(super) fn finish_open_inner(
        &mut self,
        limits: JournalLimits,
        repair: bool,
    ) -> Result<RecoveryReport, JournalError> {
        self.semantic = Some(OrdinarySemanticReplayOriginalV1::new());
        let replayed = (|| {
            let identity = self
                .native
                .prepare_parser_identity_once_v1()
                .map_err(|_| JournalError::ProtectedBoundary)?;
            let mut cursor = self
                .native
                .begin_captured_replay_with_parser_metadata_once_v1()
                .map_err(|_| JournalError::ProtectedBoundary)?;
            self.semantic
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?
                .observe_once(
                    &mut cursor,
                    identity,
                    limits,
                    None,
                    #[cfg(target_os = "linux")]
                    None,
                )
                .map_err(|_| JournalError::ProtectedBoundary)
        })();
        if replayed.is_err() {
            self.first = Some(
                if self.native.native_failure_v1().is_some()
                    || self.native.index_failure_v1().is_some()
                {
                    First::Native
                } else {
                    First::Semantic
                },
            );
        }

        // This actual post is independently owed even after a parser/semantic
        // refusal. Selection above prevents a later metadata cause masking it.
        self.prefix_result = Some(
            self.native
                .observe_captured_prefix_post_once_v1(&mut self.prefix_post),
        );
        replayed?;
        if !matches!(self.prefix_result, Some(Ok(())))
            || self.prefix_post.as_ref().is_none_or(|post| post.failure().is_some())
        {
            self.first = Some(First::PrefixPost);
            return Err(JournalError::StaleAuthoritySnapshot);
        }

        let tail = self.native.finish_replayed_tail_once_v1(if repair {
            RecoveryTailMode::RepairIncomplete
        } else {
            RecoveryTailMode::RejectIncomplete
        });
        if tail.is_err() {
            self.first = Some(First::Native);
            return Err(JournalError::ProtectedBoundary);
        }
        self.remainder = self
            .semantic
            .as_mut()
            .and_then(OrdinarySemanticReplayOriginalV1::take_remainder_once);
        self.held = self.selection.take().and_then(|selection| {
            self.native
                .take_held_with_late_payload_once_v1(selection, JournalAuthorityInstance)
        });
        let materialized = Journal::from_actual_ordinary_held_v1(
            &mut self.held,
            &mut self.remainder,
            #[cfg(target_os = "linux")]
            &mut self.captured_append,
        );
        let Some((journal, report)) = materialized else {
            self.first = Some(
                if self.native.native_failure_v1().is_some()
                    || self.native.index_failure_v1().is_some()
                {
                    First::Native
                } else {
                    First::Materialization
                },
            );
            return Err(JournalError::ProtectedBoundary);
        };
        self.journal = Some(journal);
        Ok(report)
    }

    // DATA-only borrow of the same successfully materialized native owner.
    // Purpose-specific lenders retain their own financial/currentness guards.
    pub(crate) fn journal_data_v1(&self) -> Option<&Journal> {
        if self.failure().is_some() || !matches!(self.returned, Some(Ok(_))) {
            return None;
        }
        self.journal.as_ref()
    }

    /// Projects historical metadata from the same successful captured replay.
    ///
    /// This supplies DATA only, before any optional ordinary tail repair. A
    /// caller must independently compare its current held file and reject
    /// repair when using this identity to bind the replayed prefix.
    pub(crate) fn captured_replay_file_identity_data_v1(
        &self,
    ) -> Option<aos_sandbox_journal::protected_storage::FileIdentity> {
        self.journal_data_v1()?;
        let post = self.prefix_post.as_ref()?;
        post.comparison_result().as_ref().ok()?;
        let metadata = post.metadata_result().as_ref().ok()?;
        Some(aos_sandbox_journal::protected_storage::FileIdentity::from_metadata_data_v1(metadata))
    }

    pub(crate) fn journal_mut(&mut self) -> Option<&mut Journal> {
        if self.failure().is_some() || !matches!(self.returned, Some(Ok(_))) {
            return None;
        }
        self.journal.as_mut()
    }

    /// Runs the real name bookend on whichever actual native stage still owns it.
    pub(crate) fn check_named_currentness_retaining(
        &self,
        path: &Path,
        name: &str,
        limits: JournalLimits,
        uid: u32,
        originals: &mut ProtectedJournalCurrentnessOriginalsV1,
    ) -> Result<(), JournalError> {
        if let Some(journal) = &self.journal {
            originals.begin(true)?;
            let result = (|| {
                journal.require_protected_names_with_originals(Some(originals))?;
                journal.require_protected_location_with_originals(
                    path,
                    name,
                    uid,
                    limits,
                    Some(originals),
                )
            })();
            originals.finish(result)
        } else {
            self.native
                .observe_names_retaining_v1(path, name, uid, originals)
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let native = || {
            self.native
                .native_failure_v1()
                .or_else(|| self.native.index_failure_v1())
                .or_else(|| {
                    #[cfg(target_os = "linux")]
                    {
                        self.extent
                            .as_ref()
                            .and_then(|result| result.as_ref().err())
                            .map(|cause| cause as _)
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        None
                    }
                })
        };
        let semantic = || {
            self.semantic
                .as_ref()
                .and_then(OrdinarySemanticReplayOriginalV1::failure)
        };
        let prefix = || {
            self.prefix_post
                .as_ref()
                .and_then(CapturedReplayPrefixPostV1::failure)
                .or_else(|| {
                    self.prefix_result
                        .as_ref()
                        .and_then(|result| result.as_ref().err())
                        .map(|cause| cause as _)
                })
        };
        let selected = match self.first {
            Some(First::Native) => native(),
            Some(First::Semantic) => semantic(),
            Some(First::PrefixPost) => prefix(),
            Some(First::Materialization) | None => None,
        };
        selected
            .or_else(|| {
                self.returned
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(native)
            .or_else(semantic)
            .or_else(prefix)
            .or_else(|| self.captured.failure())
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    #[test]
    fn incomplete_tail_keeps_its_original_post_before_writable_repair() {
        use std::io::Write as _;

        let executable = std::env::current_exe().unwrap();
        let directory = tempfile::Builder::new()
            .prefix("captured-writer-tail-")
            .tempdir_in(executable.parent().unwrap())
            .unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("journal");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        file.write_all(b"tail").unwrap();
        file.sync_all().unwrap();
        drop(file);

        let uid = rustix::process::geteuid().as_raw();
        let mut original = ProtectedWriterOpenOriginalsV1::new();
        original.prepare_captured_for_uid_once(
            directory.path(), "journal", JournalLimits::default(), uid, true,
        );
        assert!(original.failure().is_none(), "{:?}", original.failure());
        assert_eq!(original.native.initial_metadata_data_v1().unwrap().len(), 4);

        original.replay_prepared_once();

        let post = original.prefix_post.as_ref().unwrap();
        assert_eq!(post.metadata_result().as_ref().unwrap().len(), 4);
        assert!(post.comparison_result().is_ok());
        assert!(original.captured_opened_ready());
        let report = original.returned.as_ref().unwrap().as_ref().unwrap();
        assert_eq!(report.committed_transactions, 0);
        assert_eq!(report.truncated_bytes, 4);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);

        // Positive take is available only after the actual lower truncation
        // and sync results complete. The post retains the pre-repair length.
        let (_journal, report) = original.take_captured_opened().unwrap();

        assert_eq!(report.truncated_bytes, 4);
        assert!(original.failure().is_none());
        assert_eq!(original.prefix_post.as_ref().unwrap()
            .metadata_result().as_ref().unwrap().len(), 4);
    }

}
