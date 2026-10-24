//! Retains the actual paired C/profile preopen and fixed writer acquisition.
//!
//! Only StartupOpening can create this destination. It selects the compiled
//! Controller path, limits and admitted profile UID itself; no path, native
//! tuple, provision or caller result can be imported as protected provenance.

use std::collections::BTreeMap;
use std::sync::Arc;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::recovery::RecoveryTailMode;
use aos_sandbox_protocol::domain_ledger::readonly::IdempotencyDecisionV1;

use crate::canonical_journal::{
    CanonicalOpenedWriterDataV1, CanonicalReplayExtentDataV1, CanonicalWriterCustodyDataV1,
    CanonicalWriterOpeningOriginalsV1,
};
use crate::controller_receiving::profile::{
    ControllerProfileErrorV1, ControllerSelfProfileOriginalV1,
};
use crate::controller_receiving::ControllerReceivingOriginalV1;
use crate::controller_receiving::ControllerOriginalObservationV1;

use super::recipe;
use super::writer::ControllerFixedWriterOriginalV1;
use super::ControllerBankLaunchErrorV1;

/// Owns fixed Controller preopen, acquired originals and staged replay custody.
///
/// Its constructor and successful take are private to the genuine startup
/// path. Public methods can drive only this original's fixed recipe; no method
/// manufactures a receiving account, bank completion or protected role loan.
#[must_use]
pub struct ControllerWriterOpeningOriginalV1 {
    original: Arc<ControllerReceivingOriginalV1>,
    fixed: Option<Result<ResourceVector, ControllerBankLaunchErrorV1>>,
    preopen: ControllerOriginalObservationV1,
    binding: Option<Result<(), ControllerBankLaunchErrorV1>>,
    opening: CanonicalWriterOpeningOriginalsV1,
    preparation: Option<Result<(), crate::canonical_journal::NativeJournalDataErrorV1>>,
    extent: Option<Result<CanonicalReplayExtentDataV1, crate::canonical_journal::NativeJournalDataErrorV1>>,
    replay_debit: Option<Result<ResourceVector, ControllerBankLaunchErrorV1>>,
    semantic_debit: Option<Result<(ResourceVector, ResourceVector), ControllerBankLaunchErrorV1>>,
    opened: Option<CanonicalOpenedWriterDataV1>,
    owner_debit: Option<Result<(ResourceVector, ResourceVector), ControllerBankLaunchErrorV1>>,
    durable_end: Option<Result<u64, ControllerBankLaunchErrorV1>>,
    index: BTreeMap<Vec<u8>, IdempotencyDecisionV1>,
    replay: super::replay::ControllerReplayIndexOriginalV1,
    tail: Option<Result<(), crate::canonical_journal::NativeJournalDataErrorV1>>,
    existing_only: bool,
    attempted: bool,
    taken: bool,
    process: u32,
}

impl ControllerWriterOpeningOriginalV1 {
    pub(in crate::controller_receiving) fn from_paired_startup(original: Arc<ControllerReceivingOriginalV1>) -> Self {
        Self {
            original,
            fixed: None,
            preopen: ControllerOriginalObservationV1::new(),
            binding: None,
            opening: CanonicalWriterOpeningOriginalsV1::new(),
            preparation: None,
            extent: None,
            replay_debit: None,
            semantic_debit: None,
            opened: None,
            owner_debit: None,
            durable_end: None,
            index: BTreeMap::new(),
            replay: super::replay::ControllerReplayIndexOriginalV1::new(),
            tail: None,
            existing_only: false,
            attempted: false,
            taken: false,
            process: std::process::id(),
        }
    }

    fn fixed_preparation() -> Result<ResourceVector, ControllerBankLaunchErrorV1> {
        let overflow = || ControllerBankLaunchErrorV1::Conflict;
        // The opening helper covers its own native acquisition temporaries.
        // The parent and return/construction carriers coexist with that helper.
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .ok_or_else(overflow)?;
        let parent = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| overflow())?);
        Ok(parent
            .checked_add(ControllerOriginalObservationV1::receiving_demand_v1()
                .ok_or_else(overflow)?)?
            .checked_add(CanonicalWriterOpeningOriginalsV1::additional_fixed_receiving_demand_v1(
                recipe::directory(), recipe::NAME,
            )?)?)
    }

    /// Opens only existing fixed state and rejects interrupted tails.
    ///
    /// Missing state is never created, and replay cannot repair a partial tail.
    /// The same genuine startup loan/original and complete native debit remain
    /// required; this entry changes only the fixed acquisition/recovery recipe.
    ///
    /// # Errors
    /// Retains the same acquisition/replay cause or refuses repeated entry.
    pub fn prepare_existing_once(
        &mut self,
        profile: &ControllerSelfProfileOriginalV1,
        node: [u8; 16],
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.attempted { return Err(ControllerBankLaunchErrorV1::Conflict); }
        self.existing_only = true;
        self.prepare_once(profile, node)
    }

    /// Enters this original's fixed Controller preopen and acquisition once.
    ///
    /// The native fixed debit precedes added pair/boot acquisition. Producer,
    /// pair and independent producer observations retain the old order; any
    /// failed primary still leaves its already owed second producer observed.
    ///
    /// # Errors
    /// Retains arithmetic, actual profile/pair/native failure or exact-node
    /// mismatch. Reentry neither retries native work nor replaces its cause.
    pub fn prepare_once(
        &mut self,
        profile: &ControllerSelfProfileOriginalV1,
        node: [u8; 16],
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.attempted || self.process != std::process::id() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.attempted = true;
        self.fixed = Some((|| {
            if !profile.has_same_baseline_original(&self.original) {
                return Err(ControllerBankLaunchErrorV1::Conflict);
            }
            let demand = Self::fixed_preparation()?;
            self.original.require_fixed_writer_complete(demand)?;
            Ok(demand)
        })());
        if !matches!(self.fixed, Some(Ok(_))) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.binding = Some(self.preopen.observe_once(&self.original, profile)
            .map_err(ControllerBankLaunchErrorV1::from).and_then(|pair| {
                if pair.identity.native_fields().node != node || node == [0; 16] {
                    Err(ControllerBankLaunchErrorV1::Conflict)
                } else { Ok(()) }
            }));
        if !matches!(self.binding, Some(Ok(()))) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.preparation = Some(self.opening.prepare_once(
            recipe::directory(), recipe::NAME, recipe::controller_journal_limits_v1(),
            profile.schema().identities[0], !self.existing_only,
        ));
        if !matches!(self.preparation, Some(Ok(()))) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.extent = Some(self.opening.prepared_extent());
        self.replay_debit = Some((|| {
            let extent = self.extent.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
            let fixed = self.fixed.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
            let demand = fixed.checked_add(extent.dominant_native_receiving_demand_v1()?)?
                .checked_add(extent.dominant_semantic_receiving_demand_v1()?)?
                .checked_add(super::replay::ControllerReplayIndexOriginalV1::dynamic_demand_v1(*extent)?)?;
            self.original.require_fixed_writer_complete(demand)?;
            Ok(demand)
        })());
        if !matches!(self.replay_debit, Some(Ok(_))) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(())
    }

    /// Returns this original's compiled fixed Controller limits as DATA.
    #[must_use]
    pub fn fixed_limits(&self) -> aos_sandbox_protocol::domain_ledger::transaction::JournalLimits {
        recipe::controller_journal_limits_v1()
    }

    /// Restricts the same original for actual upper semantic representations.
    ///
    /// This monotone debit DATA returns no account, permit, parser, grant or
    /// completion token. Native role admission and protected stages remain
    /// mandatory; the actual trusted upper owner computes its compiled shape.
    ///
    /// # Errors
    /// Retains overflow/capacity refusal and rejects repeated or unfunded entry.
    #[doc(hidden)]
    pub fn debit_semantic_representation_v1(
        &mut self,
        additional: ResourceVector,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.semantic_debit.is_some() || self.taken {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.semantic_debit = Some((|| {
            let previous = self.replay_debit.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or(ControllerBankLaunchErrorV1::Conflict)?;
            let complete = previous.checked_add(additional)?;
            self.original.require_fixed_writer_complete(complete)?;
            Ok((complete, additional))
        })());
        if matches!(self.semantic_debit, Some(Ok(_))) {
            Ok(())
        } else {
            Err(ControllerBankLaunchErrorV1::Conflict)
        }
    }

    /// Samples the SAME prepaid held file before its first semantic frame.
    ///
    /// # Errors
    /// Retains native Metadata/projection in the actual opening and refuses
    /// unfunded, repeated or ended entry without an arbitrary File input.
    pub fn prepare_semantic_identity_once(
        &mut self,
    ) -> Result<aos_sandbox_journal::protected_storage::FileIdentity, ControllerBankLaunchErrorV1> {
        if !matches!(self.replay_debit, Some(Ok(_))) || self.taken {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(self.opening.prepare_selected_parser_identity_once()?)
    }

    /// Borrows the SAME canonical parser at the next semantic COMMIT frontier.
    ///
    /// The upper coordinator runs its existing semantic checks between native
    /// stages; this mechanical borrow cannot enroll a Bank or emit a role loan.
    ///
    /// # Errors
    /// Retains parser or staged-index refusal and rejects unfunded preparation.
    pub fn begin_replay_once(
        &mut self,
    ) -> Result<super::replay::ControllerWriterReplayV1<'_, '_>, ControllerBankLaunchErrorV1> {
        if !matches!(self.replay_debit, Some(Ok(_))) || self.taken {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let cursor = self.opening.begin_semantic_replay_once()?;
        Ok(super::replay::ControllerWriterReplayV1::new(
            cursor, &mut self.index, &mut self.replay,
        ))
    }

    /// Moves the actual completed native replay into its trusted coordinator.
    ///
    /// The genuine upper holder must run its sole semantic replay/final gates
    /// before this boundary. Mechanical parser completion proves none of those
    /// semantics and cannot alone establish Bank enrollment or a role loan.
    ///
    /// # Errors
    /// Retains failed acquisition/replay/tail/owner debit and rejects reentry.
    pub fn take_coordinator_after_semantic_replay_once<P>(
        &mut self,
        compaction: P,
    ) -> Result<super::coordinator::ControllerCoordinatorWriterV1<P>, ControllerBankLaunchErrorV1> {
        if self.taken || self.failure().is_some() || !self.replay.is_complete() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.tail = Some(self.opening.finish_replayed_tail_once(if self.existing_only {
            RecoveryTailMode::RejectIncomplete
        } else { RecoveryTailMode::RepairIncomplete }));
        if !matches!(self.tail, Some(Ok(()))) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.opened = self.opening.take_opened_parts_once();
        self.durable_end = Some((|| {
            let original_bytes = self.extent.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ControllerBankLaunchErrorV1::Conflict)?.native_bytes();
            let report = self.opened.as_ref().ok_or(ControllerBankLaunchErrorV1::Conflict)?
                .recovery_report();
            original_bytes.checked_sub(report.truncated_bytes)
                .ok_or(ControllerBankLaunchErrorV1::Conflict)
        })());
        let durable_end = self.durable_end.as_ref().and_then(|result| result.as_ref().ok()).copied()
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        // Generic P remains the actual upper compaction selection. Price its
        // real compiled carrier HERE before any new identity/custody Arc grows.
        self.owner_debit = Some((|| {
            let previous = self.semantic_debit.as_ref().and_then(|result| result.as_ref().ok())
                .map(|(complete, _additional)| *complete)
                .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
            let bytes = std::mem::size_of::<ControllerFixedWriterOriginalV1<P>>().checked_mul(2)
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<super::identity::ControllerWriterIdentityV1>()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<super::append::ControllerAppendCustodyV1>()))
                .and_then(|bytes| bytes.checked_add(CanonicalWriterCustodyDataV1::<P>::receiving_construction_bytes_v1()?))
                .and_then(|bytes| bytes.checked_add(8 * std::mem::size_of::<usize>()))
                .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
            let owner = ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| ControllerBankLaunchErrorV1::Conflict)?);
            let demand = previous.checked_add(owner)?;
            let fixed = self.fixed.as_ref().and_then(|result| result.as_ref().ok()).copied()
                .ok_or(ControllerBankLaunchErrorV1::Conflict)?.checked_add(owner)?
                .checked_add(self.semantic_debit.as_ref().and_then(|result| result.as_ref().ok())
                    .map(|(_complete, additional)| *additional)
                    .ok_or(ControllerBankLaunchErrorV1::Conflict)?)?;
            self.original.require_fixed_writer_complete(demand)?;
            // Keep permanent owner allocations in EVERY later append bound.
            // max(old opening, new append) cannot fund two co-resident owners.
            Ok((demand, fixed))
        })());
        if !matches!(self.owner_debit, Some(Ok(_))) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let fixed = self.owner_debit.as_ref().and_then(|result| result.as_ref().ok())
            .map(|(_complete, fixed)| *fixed).ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        let opened = self.opened.take().ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        self.taken = true;
        Ok(super::coordinator::ControllerCoordinatorWriterV1::from_fixed_opening(
            ControllerFixedWriterOriginalV1::from_fixed_opening(
                opened, std::mem::take(&mut self.index), compaction, Arc::clone(&self.original),
                fixed, durable_end,
            ),
        ))
    }

    /// Retires completed traversal files after all real upper constructor posts.
    ///
    /// The same actual C writer and its settled independent native post are
    /// required. The trusted coordinator calls this after its existing whole
    /// semantic/identity/profile conjunction, without a caller success flag.
    /// Actual held Directory/Journal/Lock and every failed prefix remain owned.
    ///
    /// # Errors
    /// Refuses failed, incomplete, repeated or foreign native disposition.
    pub fn retire_completed_traversal_after_upper_posts_once_v1<P>(
        &mut self,
        writer: &super::coordinator::ControllerCoordinatorWriterV1<P>,
        post: &super::native_post::ControllerNativePostOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if !self.taken || self.failure().is_some() || !writer.fixed.has_original(&self.original)
            || !post.is_disposed_for_v1(writer.fixed.identity())
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        writer.fixed.require_healthy()?;
        self.opening.retire_completed_traversal_once_v1()?;
        Ok(())
    }

    /// Borrows the first actual retained refusal without repeating observation.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        error(&self.fixed)
            .or_else(|| self.preopen.failure())
            .or_else(|| error(&self.binding))
            .or_else(|| self.opening.failure())
            .or_else(|| error(&self.extent))
            .or_else(|| error(&self.replay_debit))
            .or_else(|| error(&self.semantic_debit))
            .or_else(|| self.replay.failure())
            .or_else(|| error(&self.durable_end))
            .or_else(|| error(&self.owner_debit))
    }
}

impl Drop for ControllerWriterOpeningOriginalV1 {
    fn drop(&mut self) {
        if self.attempted && !self.taken {
            // The real coordinator retains this entire destination on Err.
            // Abandonment must terminate before dropping a reached native
            // original, parser/index prefix or protected acquisition cause.
            std::process::abort();
        }
    }
}

fn error<T, E: std::error::Error + 'static>(
    value: &Option<Result<T, E>>,
) -> Option<&(dyn std::error::Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}
