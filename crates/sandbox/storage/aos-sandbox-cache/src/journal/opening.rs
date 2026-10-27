//! Retains each actual Cache writer from captured acquisition through its posts.
//!
//! Only the common opening creates the native/index bundle. Cache retains its
//! full semantic original, prefix post and materialized writer beside that
//! opening until the enclosing funded stage completes its independent names.
//! No failed result, supplied map or native file can be extracted as a writer.

use std::error::Error;
use std::path::Path;

use aos_sandbox_broker::canonical_journal::{
    CanonicalJournalInstanceDataV1, CanonicalOrdinaryOpeningOriginalsV1,
    CanonicalReplayExtentDataV1,
};
use aos_sandbox_model::ResourceVector;
use aos_sandbox_journal::{
    protected_storage::CapturedReplayPrefixPostV1, recovery::RecoveryTailMode,
};

use super::construction::{ConstructionLoanV1, ConstructionOwnerV1};
use super::semantics::{self, CacheSemanticOriginalV1, CacheSemanticRemainderV1};
use super::{
    CacheCompactionSelectionV1, CacheJournalInstanceV1, CacheWriterCurrentnessOriginalV1,
    HeldCacheJournalV1, Journal, JournalError, JournalLimits, RecoveryReport,
};

type HeldInput = Option<(HeldCacheJournalV1, RecoveryReport)>;

#[derive(Clone, Copy)]
enum First {
    Native,
    Semantic,
    PrefixPost,
    Materialization,
}

pub(crate) struct CacheWriterOpeningV1 {
    native: CanonicalOrdinaryOpeningOriginalsV1,
    held: HeldInput,
    journal: Option<Journal>,
    semantic: Option<CacheSemanticOriginalV1>,
    remainder: Option<CacheSemanticRemainderV1>,
    prefix_post: Option<CapturedReplayPrefixPostV1<JournalError>>,
    prefix_result: Option<Result<(), JournalError>>,
    preparation: Option<Result<(), JournalError>>,
    binding: Option<(JournalLimits, bool)>,
    returned: Option<Result<RecoveryReport, JournalError>>,
    first: Option<First>,
    closed: Option<JournalError>,
}

impl CacheWriterOpeningV1 {
    // T is the actual resident native stage, including this entire opening.
    // The shared constructor suppliers price their other working/return lanes;
    // subtract only the real resident fields already inside T.
    pub(crate) fn fixed_receiving_demand_v1<T>(
        directories: u16,
        path_bytes: u16,
    ) -> Result<ResourceVector, aos_sandbox_model::AccountingError> {
        use aos_sandbox_model::{AccountingError, ResourceDimension as D};

        let overflow = || AccountingError::ArithmeticOverflow {
            dimension: D::MemoryBytes,
        };
        let base = CanonicalOrdinaryOpeningOriginalsV1::<()>::fixed_preparation_demand_v1::<T>(
            directories,
            path_bytes,
        )?;
        let native =
            CanonicalOrdinaryOpeningOriginalsV1::<()>::receiving_payload_construction_bytes_v1::<
                CacheCompactionSelectionV1,
                CacheJournalInstanceV1,
            >()
            .and_then(|bytes| {
                bytes.checked_sub(std::mem::size_of::<CanonicalOrdinaryOpeningOriginalsV1>())
            })
            .and_then(|bytes| bytes.checked_sub(std::mem::size_of::<HeldInput>()))
            .ok_or_else(overflow)?;
        let semantic = semantics::receiving_demand_v1()
            .map_err(|_| overflow())?
            .get(D::MemoryBytes);
        let semantic = usize::try_from(semantic)
            .ok()
            .and_then(|bytes| bytes.checked_sub(std::mem::size_of::<CacheSemanticOriginalV1>()))
            .and_then(|bytes| bytes.checked_sub(std::mem::size_of::<CacheSemanticRemainderV1>()))
            .ok_or_else(overflow)?;
        let materialization = Journal::opening_materialization_bytes_v1()
            .and_then(|bytes| bytes.checked_sub(std::mem::size_of::<Journal>()))
            .ok_or_else(overflow)?;
        let instance = CanonicalJournalInstanceDataV1::<CacheJournalInstanceV1>::
            payload_allocation_receiving_bytes_v1().ok_or_else(overflow)?;
        let extra = native
            .checked_add(semantic)
            .and_then(|bytes| bytes.checked_add(materialization))
            .and_then(|bytes| bytes.checked_add(instance))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(overflow)?;
        let memory = base
            .get(D::MemoryBytes)
            .checked_add(extra)
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
            preparation: None,
            binding: None,
            returned: None,
            first: None,
            closed: None,
        }
    }

    // The real closed construction receiver pays the fixed physical/semantic
    // controls before this private entry. This method cannot accept paid DATA.
    pub(crate) fn prepare_once(
        &mut self,
        directory: &Path,
        name: &str,
        limits: JournalLimits,
        uid: u32,
        allow_create: bool,
    ) -> Result<(), ()> {
        if self.preparation.is_some() || self.closed.is_some() {
            self.closed = Some(JournalError::boundary());
            return Err(());
        }
        self.binding = Some((limits, allow_create));
        self.preparation = Some(
            self.native
                .prepare_retaining_once_v1(directory, name, limits, uid, allow_create)
                .map_err(|_| JournalError::boundary()),
        );
        if matches!(self.preparation, Some(Ok(()))) {
            Ok(())
        } else {
            Err(())
        }
    }

    pub(crate) fn prepared_extent(&self) -> Option<CanonicalReplayExtentDataV1> {
        if self.closed.is_some()
            || self.returned.is_some()
            || !matches!(self.preparation, Some(Ok(())))
        {
            return None;
        }
        self.native.prepared_extent_v1().ok()
    }

    // The SAME actual construction loan has admitted the captured native
    // extent before entry. Both semantic pre-growth stages borrow that loan;
    // its earlier or new debt never suppresses this opening's owed post.
    pub(crate) fn replay_once<P>(
        &mut self,
        loan: &mut ConstructionLoanV1<'_, '_, '_, '_, P>,
        owner: ConstructionOwnerV1,
        native_complete: ResourceVector,
    ) -> Result<(), ()> {
        if self.returned.is_some()
            || self.closed.is_some()
            || !matches!(self.preparation, Some(Ok(())))
        {
            self.closed = Some(JournalError::boundary());
            return Err(());
        }
        let Some((limits, allow_create)) = self.binding else {
            self.closed = Some(JournalError::boundary());
            return Err(());
        };
        self.returned = Some(self.finish_inner(loan, owner, native_complete, limits, allow_create));
        if matches!(self.returned, Some(Ok(_))) {
            Ok(())
        } else {
            Err(())
        }
    }

    fn finish_inner<P>(
        &mut self,
        loan: &mut ConstructionLoanV1<'_, '_, '_, '_, P>,
        owner: ConstructionOwnerV1,
        native_complete: ResourceVector,
        limits: JournalLimits,
        allow_create: bool,
    ) -> Result<RecoveryReport, JournalError> {
        self.semantic = Some(CacheSemanticOriginalV1::new());
        let replayed = (|| {
            let identity = self
                .native
                .prepare_parser_identity_once_v1()
                .map_err(|_| JournalError::boundary())?;
            let mut cursor = self
                .native
                .begin_captured_replay_with_parser_metadata_once_v1()
                .map_err(|_| JournalError::boundary())?;
            semantics::observe_once(
                self.semantic.as_mut().ok_or(JournalError::boundary())?,
                &mut cursor,
                identity,
                limits,
                loan,
                owner,
                native_complete,
            )
            .map_err(|_| JournalError::boundary())
        })();
        if replayed.is_err() {
            self.first = Some(if self.native_failure().is_some() {
                First::Native
            } else {
                First::Semantic
            });
        }

        self.prefix_result = Some(
            self.native
                .observe_captured_prefix_post_once_v1(&mut self.prefix_post),
        );
        replayed?;
        if !matches!(self.prefix_result, Some(Ok(())))
            || self
                .prefix_post
                .as_ref()
                .is_none_or(|post| post.failure().is_some())
        {
            self.first = Some(First::PrefixPost);
            return Err(JournalError::Mechanical(aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::StaleAuthoritySnapshot));
        }

        let tail = self.native.finish_replayed_tail_once_v1(if allow_create {
            RecoveryTailMode::RepairIncomplete
        } else {
            RecoveryTailMode::RejectIncomplete
        });
        if tail.is_err() {
            self.first = Some(First::Native);
            return Err(JournalError::boundary());
        }
        self.remainder = self
            .semantic
            .as_mut()
            .and_then(semantics::take_remainder_once);
        self.held = self.native.take_held_with_late_payload_once_v1(
            CacheCompactionSelectionV1::Other,
            CacheJournalInstanceV1,
        );
        let Some((journal, report)) =
            Journal::from_opening_originals_v1(&mut self.held, &mut self.remainder)
        else {
            self.first = Some(if self.native_failure().is_some() {
                First::Native
            } else {
                First::Materialization
            });
            return Err(JournalError::boundary());
        };
        self.journal = Some(journal);
        Ok(report)
    }

    pub(crate) fn observe_names_once(
        &self,
        directory: &Path,
        name: &str,
        limits: JournalLimits,
        uid: u32,
        originals: &mut CacheWriterCurrentnessOriginalV1,
    ) -> Result<(), JournalError> {
        match &self.journal {
            Some(journal) => {
                journal.observe_opening_names_once_v1(directory, name, uid, limits, originals)
            }
            None => self
                .native
                .observe_names_retaining_v1(directory, name, uid, originals),
        }
    }

    // The enclosing original alone calls this after its actual native post has
    // completed. A negative post leaves the whole installed writer resident.
    pub(crate) fn take_completed_once(&mut self) -> Option<(Journal, RecoveryReport)> {
        if self.failure().is_some() {
            return None;
        }
        let report = *self.returned.as_ref()?.as_ref().ok()?;
        self.journal.as_ref()?;
        self.native.retire_completed_traversal_once_v1().ok()?;
        Some((self.journal.take()?, report))
    }

    fn native_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.native
            .native_failure_v1()
            .or_else(|| self.native.index_failure_v1())
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let semantic = || {
            self.semantic
                .as_ref()
                .and_then(CacheSemanticOriginalV1::failure)
        };
        let prefix = || {
            self.prefix_post
                .as_ref()
                .and_then(CapturedReplayPrefixPostV1::failure)
                .or_else(|| {
                    self.prefix_result
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                })
        };
        let first = match self.first {
            Some(First::Native) => self.native_failure(),
            Some(First::Semantic) => semantic(),
            Some(First::PrefixPost) => prefix(),
            Some(First::Materialization) | None => None,
        };
        first
            .or_else(|| self.native_failure())
            .or_else(semantic)
            .or_else(prefix)
            .or_else(|| {
                self.preparation
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.returned
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

impl Journal {
    pub(super) fn opening_materialization_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(std::mem::size_of::<Option<(Self, RecoveryReport)>>())?
            .checked_add(std::mem::size_of::<&mut HeldInput>())?
            .checked_add(std::mem::size_of::<&mut Option<CacheSemanticRemainderV1>>())?
            .checked_add(std::mem::size_of::<
                CanonicalJournalInstanceDataV1<CacheJournalInstanceV1>,
            >())
    }

    // Both prechecks precede every take, so a missing semantic half cannot
    // consume native custody. The only producer is the completed opening above.
    pub(super) fn from_opening_originals_v1(
        native: &mut HeldInput,
        semantic: &mut Option<CacheSemanticRemainderV1>,
    ) -> Option<(Self, RecoveryReport)> {
        let (held, _) = native.as_ref()?;
        semantic.as_ref()?;
        let instance = held.instance_data_v1()?.clone();
        match (native.take(), semantic.take()) {
            (Some((held, report)), Some(remainder)) => Some((
                Self {
                    native: held,
                    cache_policy_gate: None,
                    instance,
                    remainder,
                },
                report,
            )),
            (old_native, old_semantic) => {
                *native = old_native;
                *semantic = old_semantic;
                None
            }
        }
    }
}
