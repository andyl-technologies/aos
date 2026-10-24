//! Retains every reached fixed opening until its same complete native transfer.

use std::error::Error;
use std::path::Path;
use std::sync::Arc;

use aos_sandbox_broker::canonical_journal::{
    CanonicalJournalMechanicalErrorV1, CanonicalReplayExtentDataV1,
};
use aos_sandbox_broker::receiving::{
    RootCoordinatorWriterV1, RootInitialReceivingOriginalV1, RootJournalFinancialOriginalV1,
    RootWriterErrorV1, RootWriterOpeningOriginalV1, RootWriterPostOriginalV1,
};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_ledger_replay::cold::{ColdReplayOriginalV1, ColdReplayRemainderDataV1};

use super::super::PolicyNativeJournalErrorV1 as ErrorV1;
use super::{PolicyJournalInstanceV1, PolicyJournalStorageV1, RootPolicyJournalV1};

/// Selects one existing fixed Root recipe without accepting a caller pathname.
#[derive(Clone, Copy)]
pub enum RootPolicyJournalPurposeV1 {
    /// Keeps the original startup Authority creation/replay recipe.
    StartupAuthority,
    /// Requires the existing current Authority journal.
    CurrentAuthority,
    /// Keeps the current compiler-state creation/replay recipe.
    CurrentPolicy,
}

/// Retains the actual fixed opening, semantic driver and every failed prefix.
///
/// The upper genuine Root receiver admits fixed and captured-variable demand
/// before these stages. This owner supplies no new budget, startup completion
/// or publication authority. Abandoning a claimed unfinished Broker opening
/// retains its existing fatal invocation fence.
pub struct RootPolicyJournalConstructionOriginalV1 {
    opening: Option<Result<RootWriterOpeningOriginalV1, RootWriterErrorV1>>,
    semantic: ColdReplayOriginalV1<RootWriterErrorV1>,
    coordinator: Option<RootCoordinatorWriterV1<()>>,
    remainder: Option<ColdReplayRemainderDataV1>,
    financial: Option<RootJournalFinancialOriginalV1>,
    preparation: Option<Result<(), RootWriterErrorV1>>,
    before: Option<Result<(), RootWriterErrorV1>>,
    replay: Option<Result<(), RootWriterErrorV1>>,
    tail: Option<Result<(), RootWriterErrorV1>>,
    after: Option<Result<(), RootWriterErrorV1>>,
    transfer: Option<ErrorV1>,
    completed: bool,
}

impl RootPolicyJournalConstructionOriginalV1 {
    /// Creates vacant destinations without allocation, native IO or a grant.
    #[must_use]
    pub fn new() -> Self {
        Self {
            opening: None,
            semantic: ColdReplayOriginalV1::new(),
            coordinator: None,
            remainder: None,
            financial: None,
            preparation: None,
            before: None,
            replay: None,
            tail: None,
            after: None,
            transfer: None,
            completed: false,
        }
    }

    /// Bounds actual fixed native, semantic, transfer and identity carriers.
    ///
    /// The genuine receiver pays this DATA before fixed capture. Dynamic held
    /// prefix/index/model suppliers remain separate; this amount is no permit.
    ///
    /// # Errors
    /// Preserves native/mechanical geometry refusal and checked overflow.
    pub fn fixed_demand_v1(purpose: RootPolicyJournalPurposeV1) -> Result<ResourceVector, ErrorV1> {
        let native = match purpose {
            RootPolicyJournalPurposeV1::StartupAuthority => {
                RootWriterOpeningOriginalV1::startup_authority_fixed_demand_v1()
            }
            RootPolicyJournalPurposeV1::CurrentAuthority => {
                RootWriterOpeningOriginalV1::current_authority_fixed_demand_v1()
            }
            RootPolicyJournalPurposeV1::CurrentPolicy => {
                RootWriterOpeningOriginalV1::current_policy_fixed_demand_v1()
            }
        }?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<RootPolicyJournalV1>().checked_mul(3)?)
            })
            .and_then(|bytes| {
                bytes.checked_add(RootCoordinatorWriterV1::<()>::receiving_construction_bytes_v1()?)
            })
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<PolicyJournalInstanceV1>()))
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<usize>()))
            .and_then(|bytes| {
                bytes.checked_add(2 * std::mem::align_of::<PolicyJournalInstanceV1>())
            })
            .and_then(|bytes| bytes.checked_add(
                std::mem::size_of::<(&Self, Result<[ResourceVector; 3], ErrorV1>)>().checked_mul(3)?
            ))
            .and_then(|bytes| {
                // Startup's real prior quotes these shared forwarding planes
                // with its own selector. Each Current writer pays them here.
                let diagnostics = match purpose {
                    RootPolicyJournalPurposeV1::StartupAuthority => 0,
                    RootPolicyJournalPurposeV1::CurrentAuthority
                    | RootPolicyJournalPurposeV1::CurrentPolicy => {
                        Self::diagnostic_control_bytes_v1()?
                    }
                };
                bytes.checked_add(diagnostics)
            })
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(ErrorV1::geometry)?;
        let final_post = if matches!(purpose, RootPolicyJournalPurposeV1::StartupAuthority) {
            let bytes = std::mem::size_of::<RootWriterPostOriginalV1>()
                .checked_mul(3)
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or_else(ErrorV1::geometry)?;
            aos_sandbox_broker::writer_currentness::WriterCurrentnessOriginalsV1::<
                aos_sandbox_broker::canonical_journal::NativeJournalDataErrorV1,
            >::fixed_demand_v1(
                Path::new("/var/lib/aos/sandbox/policy-compiler"),
                "authority.journal",
            )
            .map_err(|cause| {
                ErrorV1::Mechanical(CanonicalJournalMechanicalErrorV1::from_ordinary_native_v1(
                    cause,
                ))
            })?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
            .map_err(|_| ErrorV1::geometry())?
        } else {
            ResourceVector::ZERO
        };
        native
            .checked_add(final_post)
            .map_err(|_| ErrorV1::geometry())?
            .checked_add(ColdReplayOriginalV1::<RootWriterErrorV1>::fixed_demand_v1()?)
            .and_then(|value| value.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes)))
            .map_err(|_| ErrorV1::geometry())
    }

    // Prices the new concrete/public failure-forwarding frames. This is a
    // passive scalar supplier: it observes no owner, health, clock or native IO.
    // Startup's genuine prior consumes it once; each Current fixed writer
    // consumes it through fixed_demand. Ordinary allocation policy is separate.
    pub(in crate::native) fn diagnostic_control_bytes_v1() -> Option<usize> {
        use std::mem::size_of;

        // For each actual Construction/Journal wrapper: concrete receiver and
        // caller plus the new or_else captured-reference/pass interface. The
        // two concrete and two forwarding Result-free Option interfaces each
        // retain construction/return/caller planes; errors remain borrowed.
        let forwarding = size_of::<&Self>()
            .checked_mul(4)?
            .checked_add(size_of::<&RootPolicyJournalV1>().checked_mul(4)?)?
            .checked_add(size_of::<Option<&(dyn Error + 'static)>>().checked_mul(12)?)?;

        // This supplier and the fixed quote's new purpose-select/checked-add
        // forwarding name only scalar control planes, never namespace cells.
        forwarding
            .checked_add(size_of::<Option<usize>>().checked_mul(6)?)?
            .checked_add(size_of::<usize>().checked_mul(3)?)?
            .checked_add(size_of::<RootPolicyJournalPurposeV1>().checked_mul(3)?)
    }

    /// Claims and prepares only the same Initial's once-only fixed recipe.
    ///
    /// The actual upper fixed prefix must already be admitted. Preparation's
    /// native original independently arms the owed names post before entry.
    pub fn prepare_once(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        purpose: RootPolicyJournalPurposeV1,
    ) {
        if self.opening.is_some() || self.completed {
            initial.latch_root_refusal_v1();
            return;
        }
        self.financial = initial.financial_diagnostic_original_v1();
        if self.financial.is_none() {
            self.opening = Some(Err(RootWriterErrorV1::Closed));
            initial.latch_root_refusal_v1();
            return;
        }
        self.opening = Some(match purpose {
            RootPolicyJournalPurposeV1::StartupAuthority => {
                initial.take_startup_authority_writer_once_v1()
            }
            RootPolicyJournalPurposeV1::CurrentAuthority => {
                initial.take_current_authority_writer_once_v1()
            }
            RootPolicyJournalPurposeV1::CurrentPolicy => {
                initial.take_current_policy_writer_once_v1()
            }
        });
        if let Some(Ok(opening)) = self.opening.as_mut() {
            self.preparation = Some(opening.prepare_once());
        }
    }

    /// Borrows the actual held extent without resampling its file metadata.
    #[must_use]
    pub fn extent(&self) -> Option<&CanonicalReplayExtentDataV1> {
        self.opening.as_ref()?.as_ref().ok()?.prepared_extent()
    }

    /// Prices the same held extent's actual resident replay index.
    ///
    /// # Errors
    /// Preserves missing/failed native preparation or index geometry refusal.
    pub fn index_demand_v1(&self) -> Result<ResourceVector, ErrorV1> {
        self.opening
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or_else(ErrorV1::boundary)?
            .additional_index_demand_v1()
            .map_err(Into::into)
    }

    /// Derives native, full semantic-family, and index demand from this opening.
    ///
    /// The receiver adds these components to its actual cumulative prefix in
    /// that order. Fixed cold-construction demand remains separately paid.
    ///
    /// # Errors
    /// Preserves unavailable capture and each original geometry cause.
    pub(in crate::native) fn variable_components_v1(
        &self,
    ) -> Result<[ResourceVector; 3], ErrorV1> {
        let extent = self.extent().ok_or_else(ErrorV1::boundary)?;
        let native = extent.dominant_native_receiving_demand_v1()
            .map_err(CanonicalJournalMechanicalErrorV1::from_ordinary_native_v1)
            .map_err(ErrorV1::from)?;
        let bytes = usize::try_from(extent.native_bytes()).map_err(|_| ErrorV1::geometry())?;
        let semantic = aos_sandbox_ledger_replay::geometry::semantic_rows::semantic_representation_demand_v1(
            bytes, bytes / aos_sandbox_journal::framing::HEADER_BYTES,
        ).map_err(CanonicalJournalMechanicalErrorV1::from).map_err(ErrorV1::from)?;
        let index = self.index_demand_v1()?;
        Ok([native, semantic, index])
    }

    /// Samples original names at the caller's existing admitted pre-parser point.
    pub fn observe_names_before_once(&mut self) {
        if self.before.is_none() {
            if let Some(Ok(opening)) = self.opening.as_mut() {
                self.before = Some(opening.observe_names_before_once());
            }
        }
    }

    /// Runs the complete sole cold recipe on the same actual Root cursor.
    ///
    /// Actual variable native/index/model representation is admitted by the
    /// genuine upper receiver before entry. No key-family whitelist skips a
    /// hook. The existing native invocation guard spans its actual native IO.
    pub fn replay_once(&mut self) {
        if self.replay.is_some() || self.failure().is_some() {
            return;
        }
        self.observe_names_before_once();
        if !matches!(self.before, Some(Ok(()))) {
            return;
        }
        let Some(Ok(opening)) = self.opening.as_mut() else {
            return;
        };
        self.replay = Some((|| {
            let identity = opening.prepare_semantic_identity_once()?;
            let limits = opening
                .prepared_extent()
                .ok_or(RootWriterErrorV1::Closed)?
                .limits();
            let mut cursor = opening.begin_replay_once()?;
            self.semantic
                .observe_root_once(&mut cursor, identity, limits)
                .map_err(|_| RootWriterErrorV1::Closed)
        })());
        if matches!(self.replay, Some(Ok(()))) {
            self.tail = Some(opening.finish_tail_once());
        }
    }

    /// Completes the independently owed names post even after earlier refusal.
    pub fn finish_names_once(&mut self) {
        if self.after.is_none() {
            if let Some(Ok(opening)) = self.opening.as_mut() {
                self.after = Some(opening.finish_names_once());
            }
        }
    }

    /// Requires complete semantic/native/tail/name stages without granting a role.
    #[must_use]
    pub fn ready(&self) -> bool {
        matches!(self.preparation, Some(Ok(())))
            && matches!(self.before, Some(Ok(())))
            && matches!(self.replay, Some(Ok(())))
            && matches!(self.tail, Some(Ok(())))
            && matches!(self.after, Some(Ok(())))
            && !self.completed
            && self.failure().is_none()
    }

    /// Moves the same completed writer and historical remainder exactly once.
    ///
    /// Every fallible result is parked before taking native custody. The
    /// remainder remains the lower no-history DATA; no live challenge witness
    /// or Domain cache is reconstructed. Fixed Root recipes have the existing
    /// unrelated-to-deployment compaction disposition, represented by unit.
    #[must_use]
    pub fn take_journal_once(&mut self) -> Option<RootPolicyJournalV1> {
        if !self.ready() {
            return None;
        }
        if self.remainder.is_none() {
            self.remainder = self.semantic.take_remainder_once();
        }
        if self
            .remainder
            .as_ref()
            .is_none_or(|history| history.original_replay.challenges.is_some())
        {
            self.transfer = Some(ErrorV1::boundary());
            return None;
        }
        let Some(Ok(opening)) = self.opening.as_mut() else {
            return None;
        };
        let captured_native_bytes = opening.prepared_extent()?.native_bytes();
        if self.coordinator.is_none() {
            match opening.take_coordinator_after_semantic_replay_once(()) {
                Ok(writer) => self.coordinator = Some(writer),
                Err(cause) => {
                    self.transfer = Some(cause.into());
                    return None;
                }
            }
        }
        let report = opening.recovery_report()?;
        let parts = (
            self.coordinator.take(),
            self.remainder.take(),
            self.financial.take(),
        );
        let (writer, history, financial) = match parts {
            (Some(writer), Some(history), Some(financial)) => (writer, history, financial),
            (writer, history, financial) => {
                self.coordinator = writer;
                self.remainder = history;
                self.financial = financial;
                return None;
            }
        };
        let journal = RootPolicyJournalV1 {
            storage: PolicyJournalStorageV1::Selected { writer, financial },
            history,
            q04_current: super::q04_readback::Q04ReadbackCustodyV1::new(),
            native_interval: None,
            instance: Arc::new(PolicyJournalInstanceV1),
            captured_native_bytes: captured_native_bytes.checked_sub(report.truncated_bytes)?,
            report,
        };
        self.completed = true;
        Some(journal)
    }

    // Native prefix archives retain their original precedence, including the
    // lower opening's archived names-before/parser cause. Full Current extent
    // geometry is selected after this exact prefix and before later markers.
    pub(in crate::native) fn prefix_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.opening
            .as_ref()
            .and_then(|value| value.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| {
                self.opening
                    .as_ref()
                    .and_then(|value| value.as_ref().ok())
                    .and_then(|opening| opening.prefix_failure_v1())
            })
            .or_else(|| {
                self.preparation
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|cause| cause as _)
            })

    }

    pub(in crate::native) fn remaining_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.before
            .as_ref()
            .and_then(|value| value.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| self.semantic.failure())
            .or_else(|| {
                self.replay
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.tail
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| self.transfer.as_ref().map(|cause| cause as _))
            .or_else(|| {
                self.opening
                    .as_ref()
                    .and_then(|value| value.as_ref().ok())
                    .and_then(|opening| opening.names_post_failure_v1())
            })
            .or_else(|| {
                self.after
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|cause| cause as _)
            })

    }

    /// Borrows actual reached native causes without an invocation-wide marker.
    #[must_use]
    pub(in crate::native) fn concrete_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.prefix_failure_v1().or_else(|| self.remaining_failure_v1())
    }

    /// Borrows the original reached cause before a later invocation-wide marker.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.concrete_failure_v1().or_else(|| {
            self.opening
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .and_then(|opening| opening.failure())
        })
    }
}

impl Default for RootPolicyJournalConstructionOriginalV1 {
    fn default() -> Self {
        Self::new()
    }
}
