//! Acquires the two supported ordinary fixed journals through the sole engine.
//!
//! Ordinary custody has no Root receiving account or selected invocation. It
//! cannot be selected because Root finance is unavailable. The caller retains
//! the existing ordinary allocation policy and its separate role admission.

use std::error::Error;
use std::path::Path;
use std::sync::Arc;

use aos_sandbox_broker::canonical_journal::coordinator::indexed_replay::CanonicalIndexedReplayErrorV1;
use aos_sandbox_broker::canonical_journal::{
    CanonicalJournalInstanceDataV1, CanonicalJournalMechanicalErrorV1,
    CanonicalOrdinaryOpeningOriginalsV1, NativeJournalDataErrorV1,
};
use aos_sandbox_broker::receiving::root_authority_journal_limits_data_v1;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::recovery::RecoveryTailMode;
use aos_sandbox_ledger_replay::cold::ColdReplayOriginalV1;

use super::super::PolicyNativeJournalErrorV1 as ErrorV1;
use super::{PolicyJournalInstanceV1, PolicyJournalStorageV1, RootPolicyJournalV1};

use crate::journal_keys::{
    POLICY_AUTHORITY_JOURNAL, POLICY_STATE_JOURNAL, PROTECTED_POLICY_ROOT as DIRECTORY,
};

#[derive(Clone, Copy)]
enum FixedOrdinaryJournalV1 {
    Authority,
    Policy,
    PolicyExisting,
}

impl FixedOrdinaryJournalV1 {
    fn name(self) -> &'static str {
        match self {
            Self::Authority => POLICY_AUTHORITY_JOURNAL,
            Self::Policy | Self::PolicyExisting => POLICY_STATE_JOURNAL,
        }
    }

    fn limits(self) -> aos_sandbox_protocol::domain_ledger::transaction::JournalLimits {
        match self {
            Self::Authority => root_authority_journal_limits_data_v1(),
            Self::Policy | Self::PolicyExisting => Default::default(),
        }
    }
}

fn native_error(cause: NativeJournalDataErrorV1) -> ErrorV1 {
    ErrorV1::Mechanical(CanonicalJournalMechanicalErrorV1::from_ordinary_native_v1(
        cause,
    ))
}

fn indexed_error(cause: CanonicalIndexedReplayErrorV1) -> ErrorV1 {
    match cause {
        CanonicalIndexedReplayErrorV1::Native(cause) => native_error(cause),
        CanonicalIndexedReplayErrorV1::Closed => ErrorV1::boundary(),
    }
}

impl RootPolicyJournalV1 {
    /// Opens the existing ordinary fixed Authority journal with UID-zero custody.
    ///
    /// This explicit ordinary acquisition creates no selected Root invocation,
    /// funding or current role loan. The actual Authority factory independently
    /// verifies its protected pins, full history and original role prerequisites.
    ///
    /// # Errors
    /// Preserves unsafe fixed ancestry, acquisition, full semantic replay,
    /// native/index, tail or same-opening transfer refusal.
    pub fn open_fixed_ordinary_authority_v1() -> Result<Self, ErrorV1> {
        Self::open_ordinary_v1(
            FixedOrdinaryJournalV1::Authority,
            true,
            #[cfg(any(test, feature = "test-fixtures"))]
            None,
        )
    }

    /// Opens only the existing ordinary fixed Authority journal.
    ///
    /// This finite successor recipe cannot create a missing Authority journal.
    /// It shares the same native/cold engine as the distinct creating recipe.
    ///
    /// # Errors
    /// Preserves missing/unsafe fixed ancestry, acquisition, complete replay,
    /// native/index, tail or same-opening transfer refusal.
    pub fn open_existing_fixed_ordinary_authority_v1() -> Result<Self, ErrorV1> {
        Self::open_ordinary_v1(
            FixedOrdinaryJournalV1::Authority,
            false,
            #[cfg(any(test, feature = "test-fixtures"))]
            None,
        )
    }

    /// Opens the supported ordinary fixed compiler-state journal.
    ///
    /// Actual publication requires the genuine private role verifier; opening
    /// does not accept supplied native parts, a map, budget or currentness DTO.
    ///
    /// # Errors
    /// Preserves unsafe fixed ancestry, acquisition, full semantic replay,
    /// native/index, tail or same-opening transfer refusal.
    pub fn open_fixed_ordinary_policy_v1() -> Result<Self, ErrorV1> {
        Self::open_ordinary_v1(
            FixedOrdinaryJournalV1::Policy,
            true,
            #[cfg(any(test, feature = "test-fixtures"))]
            None,
        )
    }

    /// Opens the existing compiler-state journal without repairing an incomplete tail.
    ///
    /// # Errors
    /// Preserves missing, unsafe, held, malformed, incomplete or pending-compaction
    /// state through the same full ordinary opening and semantic replay engine.
    pub(in crate::native) fn open_existing_fixed_ordinary_policy_v1() -> Result<Self, ErrorV1> {
        Self::open_ordinary_v1(
            FixedOrdinaryJournalV1::PolicyExisting,
            false,
            #[cfg(any(test, feature = "test-fixtures"))]
            None,
        )
    }

    /// Opens real Authority fixture files through the fixed ordinary native recipe.
    ///
    /// # Errors
    /// Preserves actual no-follow acquisition, ownership, lock and replay failures.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub(in crate::native) fn open_fixture_ordinary_authority_v1(
        directory: &Path, uid: u32,
    ) -> Result<Self, ErrorV1> {
        Self::open_ordinary_v1(FixedOrdinaryJournalV1::Authority, true, Some((directory, uid, FixedOrdinaryJournalV1::Authority.name(), FixedOrdinaryJournalV1::Authority.limits())))
    }

    /// Opens real compiler-state fixture files through the ordinary native recipe.
    ///
    /// # Errors
    /// Preserves actual no-follow acquisition, ownership, lock and replay failures.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub(in crate::native) fn open_fixture_ordinary_policy_v1(
        directory: &Path, uid: u32,
    ) -> Result<Self, ErrorV1> {
        Self::open_ordinary_v1(FixedOrdinaryJournalV1::Policy, true, Some((directory, uid, FixedOrdinaryJournalV1::Policy.name(), FixedOrdinaryJournalV1::Policy.limits())))
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    pub(in crate::native) fn open_fixture_existing_ordinary_policy_v1(
        directory: &Path, uid: u32,
    ) -> Result<Self, ErrorV1> {
        Self::open_ordinary_v1(FixedOrdinaryJournalV1::PolicyExisting, false, Some((directory, uid, FixedOrdinaryJournalV1::PolicyExisting.name(), FixedOrdinaryJournalV1::PolicyExisting.limits())))
    }

    // Fixture mutations use the actual same ordinary engine and cannot select
    // an existing selected writer or supply a replacement native original.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub(in crate::native) fn commit(
        &mut self,
        transaction: &aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction,
    ) -> Result<aos_sandbox_broker::canonical_journal::CommitResult, ErrorV1> {
        if !matches!(self.storage, PolicyJournalStorageV1::Ordinary { .. }) {
            return Err(ErrorV1::boundary());
        }
        self.commit_with_role_gate_v1(transaction, crate::native::append::PolicyMutationGateV1::Ordinary)
    }

    /// Quotes actual ordinary fixed-header and semantic construction planes.
    ///
    /// Dynamic native/prefix/index/semantic suppliers remain independent. This
    /// DATA replaces old enclosing header terms; it grants no account or entry.
    ///
    /// # Errors
    /// Returns the existing checked geometry classification on overflow.
    pub fn ordinary_fixed_construction_demand_v1() -> Result<ResourceVector, ErrorV1> {
        let composition =
            CanonicalOrdinaryOpeningOriginalsV1::<()>::receiving_payload_construction_bytes_v1::<
                (),
                PolicyJournalInstanceV1,
            >()
            .and_then(|bytes| {
                bytes.checked_add(
                CanonicalJournalInstanceDataV1::<PolicyJournalInstanceV1>::
                    payload_allocation_receiving_bytes_v1()?,
            )
            })
            .and_then(|bytes| bytes.checked_add(
                RootPolicyOrdinaryOpeningOriginalV1::construction_bytes_v1()?,
            ))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>().checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Result<Self, ErrorV1>>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(ErrorV1::geometry)?;
        ColdReplayOriginalV1::<CanonicalIndexedReplayErrorV1>::fixed_demand_v1()?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, composition))
            .map_err(|_| ErrorV1::geometry())
    }

    fn open_ordinary_v1(
        kind: FixedOrdinaryJournalV1,
        allow_create: bool,
        #[cfg(any(test, feature = "test-fixtures"))] fixture: Option<(&Path, u32, &str, aos_sandbox_protocol::domain_ledger::transaction::JournalLimits)>,
    ) -> Result<Self, ErrorV1> {
        let mut original = RootPolicyOrdinaryOpeningOriginalV1::new();
        original.open_once(
            kind,
            allow_create,
            #[cfg(any(test, feature = "test-fixtures"))]
            fixture,
        );
        original.into_result()
    }
}

fn disposed_opening_error(
    opening: CanonicalOrdinaryOpeningOriginalsV1,
    fallback: ErrorV1,
) -> ErrorV1 {
    match opening.into_ordinary_errors_v1() {
        Ok((Some(index), _)) => CanonicalJournalMechanicalErrorV1::from(index).into(),
        Ok((None, Some(native))) => native_error(native),
        Ok((None, None)) => fallback,
        Err(original) => {
            drop(original);
            fallback
        }
    }
}

/// Retains the same ordinary fixed opening until its caller releases custody.
///
/// Completed Authority/Target factories consume it at their original return
/// boundary. Ordinary startup keeps failed physical and semantic originals
/// through its independently owed final names observation.
pub(in crate::native) struct RootPolicyOrdinaryOpeningOriginalV1 {
    journal: Option<RootPolicyJournalV1>,
    converted: Option<aos_sandbox_ledger_replay::cold::ColdReplayRemainderDataV1>,
    semantic: Option<ColdReplayOriginalV1<CanonicalIndexedReplayErrorV1>>,
    opening: Option<CanonicalOrdinaryOpeningOriginalsV1>,
    body: Option<Result<(), ErrorV1>>,
    replay_failed: bool,
    disposed_opening_error: bool,
}

impl RootPolicyOrdinaryOpeningOriginalV1 {
    pub(in crate::native) fn new() -> Self {
        Self {
            journal: None,
            converted: None,
            semantic: Some(ColdReplayOriginalV1::new()),
            opening: Some(CanonicalOrdinaryOpeningOriginalsV1::new()),
            body: None,
            replay_failed: false,
            disposed_opening_error: false,
        }
    }

    // Fixed ordinary creating Authority is the only startup entry. This never
    // selects ordinary because a selected preparation or lender is unavailable.
    pub(in crate::native) fn open_startup_authority_once_v1(&mut self) {
        self.open_once(
            FixedOrdinaryJournalV1::Authority,
            true,
            #[cfg(any(test, feature = "test-fixtures"))]
            None,
        );
    }

    // The feature-gated fixture still acquires and replays its actual files.
    // It cannot install a journal or supply a completed native original.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub(in crate::native) fn open_fixture_startup_authority_once_v1(
        &mut self,
        directory: &Path,
        name: &str,
        limits: aos_sandbox_protocol::domain_ledger::transaction::JournalLimits,
        uid: u32,
    ) {
        self.open_once(
            FixedOrdinaryJournalV1::Authority,
            true,
            Some((directory, uid, name, limits)),
        );
    }

    fn open_once(
        &mut self,
        kind: FixedOrdinaryJournalV1,
        allow_create: bool,
        #[cfg(any(test, feature = "test-fixtures"))] fixture: Option<(&Path, u32, &str, aos_sandbox_protocol::domain_ledger::transaction::JournalLimits)>,
    ) {
        if self.body.is_some() {
            return;
        }
        self.body = Some(self.open_body(
            kind,
            allow_create,
            #[cfg(any(test, feature = "test-fixtures"))]
            fixture,
        ));
    }

    fn open_body(
        &mut self,
        kind: FixedOrdinaryJournalV1,
        allow_create: bool,
        #[cfg(any(test, feature = "test-fixtures"))] fixture: Option<(&Path, u32, &str, aos_sandbox_protocol::domain_ledger::transaction::JournalLimits)>,
    ) -> Result<(), ErrorV1> {
        let limits = kind.limits();
        #[cfg(any(test, feature = "test-fixtures"))]
        let limits = fixture.map_or(limits, |(_, _, _, limits)| limits);
        let opening = self.opening.as_mut().ok_or_else(ErrorV1::boundary)?;
        let semantic = self.semantic.as_mut().ok_or_else(ErrorV1::boundary)?;
        #[cfg(any(test, feature = "test-fixtures"))]
        let prepared = match fixture {
            Some((directory, uid, name, _)) => opening.prepare_fixture_ordinary_once_v1(
                directory,
                name,
                limits,
                uid,
                allow_create,
            ),
            None => opening.prepare_ordinary_once_v1(
                Path::new(DIRECTORY),
                kind.name(),
                limits,
                0,
                allow_create,
            ),
        };
        #[cfg(not(any(test, feature = "test-fixtures")))]
        let prepared = opening.prepare_ordinary_once_v1(
            Path::new(DIRECTORY),
            kind.name(),
            limits,
            0,
            allow_create,
        );
        let replayed = (|| {
            prepared.map_err(native_error)?;
            let identity = opening
                .prepare_parser_identity_once_v1()
                .map_err(native_error)?;
            let mut cursor = opening
                .begin_indexed_replay_once_v1()
                .map_err(native_error)?;
            semantic
                .observe_ordinary_indexed_once(&mut cursor, identity, limits)
                .map_err(|_| ErrorV1::boundary())?;
            self.converted = Some(
                semantic
                    .take_remainder_once()
                    .ok_or_else(ErrorV1::boundary)?,
            );
            Ok(())
        })();
        if let Err(body) = replayed {
            self.replay_failed = true;
            return Err(body);
        }

        semantic.dispose_ordinary_prospective_v1();
        opening
            .dispose_ordinary_current_once_v1()
            .map_err(native_error)?;
        let semantic = self.semantic.take().ok_or_else(ErrorV1::boundary)?;
        drop(semantic.into_ordinary_errors());
        opening
            .dispose_ordinary_pending_once_v1()
            .map_err(native_error)?;
        if let Err(projected) = opening.finish_replayed_tail_once_v1(match kind {
            FixedOrdinaryJournalV1::PolicyExisting => RecoveryTailMode::RejectIncomplete,
            _ => RecoveryTailMode::RepairIncomplete,
        }) {
            drop(self.converted.take());
            self.disposed_opening_error = true;
            return Err(native_error(projected));
        }
        let captured_native_bytes = opening
            .prepared_extent_v1()
            .map_err(native_error)?
            .native_bytes();
        let Some((writer, report)) =
            opening.take_held_with_late_payload_once_v1((), PolicyJournalInstanceV1)
        else {
            drop(self.converted.take());
            self.disposed_opening_error = true;
            return Err(ErrorV1::boundary());
        };
        let Some(original_instance) = writer.instance_data_v1() else {
            drop(self.converted.take());
            drop(writer);
            return Err(ErrorV1::boundary());
        };
        let instance = Arc::clone(original_instance.comparison_arc_v1());
        let Some(history) = self.converted.take() else {
            drop(instance);
            drop(writer);
            return Err(ErrorV1::boundary());
        };
        self.journal = Some(RootPolicyJournalV1 {
            storage: PolicyJournalStorageV1::Ordinary { writer },
            instance,
            history,
            q04_current: super::q04_readback::Q04ReadbackCustodyV1::new(),
            native_interval: None,
            captured_native_bytes: captured_native_bytes
                .checked_sub(report.truncated_bytes)
                .ok_or_else(ErrorV1::geometry)?,
            report,
        });
        Ok(())
    }

    pub(in crate::native) fn journal_v1(&self) -> Option<&RootPolicyJournalV1> {
        if !matches!(self.body, Some(Ok(()))) {
            return None;
        }
        self.journal.as_ref()
    }

    pub(in crate::native) fn journal_mut_v1(&mut self) -> Option<&mut RootPolicyJournalV1> {
        if !matches!(self.body, Some(Ok(()))) {
            return None;
        }
        self.journal.as_mut()
    }

    // Only explicit StartupHeld custody calls this fixed partial-opening post.
    // It deliberately has no healthy gate and no replacement open/transfer.
    pub(in crate::native) fn observe_untransferred_startup_names_once_v1(
        &self,
        originals: &mut aos_sandbox_broker::writer_currentness::WriterCurrentnessOriginalsV1<
            CanonicalJournalMechanicalErrorV1,
        >,
    ) -> Result<(), CanonicalJournalMechanicalErrorV1> {
        self.opening
            .as_ref()
            .ok_or(CanonicalJournalMechanicalErrorV1::ProtectedBoundary)?
            .observe_names_retaining_v1(
                Path::new(DIRECTORY),
                POLICY_AUTHORITY_JOURNAL,
                0,
                originals,
            )
    }

    pub(in crate::native) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        if self.replay_failed {
            if let Some(opening) = &self.opening {
                if let Some(cause) = opening
                    .index_failure_v1()
                    .or_else(|| opening.native_failure_v1())
                {
                    return Some(cause);
                }
            }
            if let Some(cause) = self
                .semantic
                .as_ref()
                .and_then(ColdReplayOriginalV1::failure)
            {
                return Some(cause);
            }
        }
        self.body
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn Error + 'static))
    }

    // The existing factory invokes this at its original return boundary. The
    // retained startup path instead keeps the complete same owner until final
    // posts/disposal; no opening or parser is rerun to recover a diagnostic.
    fn into_result(mut self) -> Result<RootPolicyJournalV1, ErrorV1> {
        let body = self.body.take().ok_or_else(ErrorV1::boundary)?;
        let Err(body) = body else {
            return self.journal.take().ok_or_else(ErrorV1::boundary);
        };
        if self.replay_failed {
            let mut opening = self.opening.take().ok_or_else(ErrorV1::boundary)?;
            let semantic = self.semantic.as_mut().ok_or_else(ErrorV1::boundary)?;
            let native_selected =
                opening.native_failure_v1().is_some() || opening.index_failure_v1().is_some();
            semantic.dispose_ordinary_prospective_v1();
            let current_disposal = opening.dispose_ordinary_current_once_v1();
            let semantic = self.semantic.take().ok_or_else(ErrorV1::boundary)?;
            let (upper_native, upper_semantic) = semantic.into_ordinary_errors();
            let pending_disposal = opening.dispose_ordinary_pending_once_v1();
            if let Ok((index, native)) = opening.into_ordinary_errors_v1() {
                if native_selected {
                    if let Some(cause) = index {
                        return Err(CanonicalJournalMechanicalErrorV1::from(cause).into());
                    }
                    if let Some(cause) = native {
                        return Err(native_error(cause));
                    }
                }
            }
            if let Some(cause) = upper_native {
                return Err(indexed_error(cause));
            }
            if let Some(cause) = upper_semantic {
                return Err(cause.into());
            }
            drop(current_disposal);
            drop(pending_disposal);
            return Err(body);
        }
        if self.disposed_opening_error {
            let opening = self.opening.take().ok_or_else(ErrorV1::boundary)?;
            return Err(disposed_opening_error(opening, body));
        }
        Err(body)
    }

    pub(in crate::native) fn construction_bytes_v1() -> Option<usize> {
        use std::mem::size_of;
        size_of::<Self>()
            .checked_mul(3)?
            .checked_add(size_of::<Result<(), ErrorV1>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<RootPolicyJournalV1, ErrorV1>>().checked_mul(3)?)?
            .checked_add(size_of::<(&mut Self, FixedOrdinaryJournalV1, bool)>().checked_mul(3)?)?
            .checked_add(
                size_of::<Option<ColdReplayOriginalV1<CanonicalIndexedReplayErrorV1>>>()
                    .checked_mul(3)?,
            )?
            .checked_add(size_of::<bool>().checked_mul(6)?)?
            .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
    }
}
