//! Keeps genuine fixed Root construction on its original lower receiving owner.
//!
//! Acquisition, held extent admission, original service bookends, parser and
//! independent names posts remain at their existing caller frontiers. The same
//! private native opening and sole upper semantic loop replace no policy gate.

mod serving;

pub(crate) use serving::RootJournalServingIdentityV1;

use std::error::Error;

use aos_sandbox_broker::receiving::{
    RootCoordinatorWriterV1, RootInitialReceivingOriginalV1, RootWriterErrorV1,
    RootWriterOpeningOriginalV1, RootJournalFinancialOriginalV1,
};
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};

use aos_sandbox_ledger_replay::cold::ColdReplayOriginalV1;

use super::semantic_remainder::ColdSemanticRemainderOriginalV1;
use super::*;

#[derive(Clone, Copy)]
pub(crate) enum RootJournalPurposeV1 {
    StartupAuthority,
    CurrentAuthority,
    CurrentPolicy,
}

pub(crate) struct RootJournalConstructionOriginalV1 {
    opening: Option<Result<RootWriterOpeningOriginalV1, RootWriterErrorV1>>,
    semantic: ColdReplayOriginalV1<RootWriterErrorV1>,
    conversion: ColdSemanticRemainderOriginalV1,
    coordinator: Option<RootCoordinatorWriterV1<native_backing::Selection>>,
    extent: Option<Result<ProtectedJournalPreopenReplayExtentV1, JournalError>>,
    preparation: Option<Result<(), RootWriterErrorV1>>,
    before: Option<Result<(), RootWriterErrorV1>>,
    replay: Option<Result<(), RootWriterErrorV1>>,
    tail: Option<Result<(), RootWriterErrorV1>>,
    after: Option<Result<(), RootWriterErrorV1>>,
    taken: Option<(Journal, RecoveryReport)>,
    financial: Option<RootJournalFinancialOriginalV1>,
    completed: bool,
}

impl RootJournalConstructionOriginalV1 {
    pub(crate) fn new() -> Self {
        Self {
            opening: None, semantic: ColdReplayOriginalV1::new(), extent: None,
            conversion: ColdSemanticRemainderOriginalV1::new(), coordinator: None,
            preparation: None, before: None, replay: None, tail: None, after: None,
            taken: None, financial: None, completed: false,
        }
    }

    pub(crate) fn fixed_demand_v1(purpose: RootJournalPurposeV1) -> Result<ResourceVector, JournalError> {
        let native = match purpose {
            RootJournalPurposeV1::StartupAuthority => RootWriterOpeningOriginalV1::startup_authority_fixed_demand_v1(),
            RootJournalPurposeV1::CurrentAuthority => RootWriterOpeningOriginalV1::current_authority_fixed_demand_v1(),
            RootJournalPurposeV1::CurrentPolicy => RootWriterOpeningOriginalV1::current_policy_fixed_demand_v1(),
        }.map_err(JournalError::RootNative)?;
        let invalid = || JournalError::LimitExceeded("Root fixed Journal construction");
        let bytes = std::mem::size_of::<Self>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(RootCoordinatorWriterV1::<native_backing::Selection>::receiving_construction_bytes_v1()?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<JournalAuthorityInstance>()))
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<usize>()))
            .and_then(|bytes| bytes.checked_add(2 * std::mem::align_of::<JournalAuthorityInstance>()))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or_else(invalid)?;
        let final_post = if matches!(purpose, RootJournalPurposeV1::StartupAuthority) {
            let bytes = std::mem::size_of::<aos_sandbox_broker::receiving::RootWriterPostOriginalV1>()
                .checked_mul(3).and_then(|bytes| u64::try_from(bytes).ok()).ok_or_else(invalid)?;
            aos_sandbox_broker::writer_currentness::WriterCurrentnessOriginalsV1::<
                aos_sandbox_broker::canonical_journal::NativeJournalDataErrorV1,
            >::fixed_demand_v1(Path::new("/var/lib/aos/sandbox/policy-compiler"), "authority.journal")
                .map_err(|cause| JournalError::from(CanonicalJournalMechanicalErrorV1::from_ordinary_native_v1(cause)))?
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes)).map_err(|_| invalid())?
        } else { ResourceVector::ZERO };
        let semantic = ColdReplayOriginalV1::<RootWriterErrorV1>::fixed_demand_v1()?;
        let conversion = ColdSemanticRemainderOriginalV1::receiving_demand_v1()?;
        native.checked_add(final_post).map_err(|_| invalid())?
            .checked_add(semantic)
            .and_then(|demand| demand.checked_add(conversion))
            .and_then(|demand| demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes)))
            .map_err(|_| invalid())
    }

    pub(crate) fn prepare_once(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        purpose: RootJournalPurposeV1,
    ) {
        if self.opening.is_some() { initial.latch_root_refusal_v1(); return; }
        self.financial = initial.financial_diagnostic_original_v1();
        if self.financial.is_none() {
            self.opening = Some(Err(RootWriterErrorV1::Closed));
            initial.latch_root_refusal_v1();
            return;
        }
        self.opening = Some(match purpose {
            RootJournalPurposeV1::StartupAuthority => initial.take_startup_authority_writer_once_v1(),
            RootJournalPurposeV1::CurrentAuthority => initial.take_current_authority_writer_once_v1(),
            RootJournalPurposeV1::CurrentPolicy => initial.take_current_policy_writer_once_v1(),
        });
        let Some(Ok(opening)) = self.opening.as_mut() else { return; };
        self.preparation = Some(opening.prepare_once());
        if !matches!(self.preparation, Some(Ok(()))) { return; }
        self.extent = Some(match opening.prepared_extent() {
            Some(extent) => protected_journal_preopen_replay_extent_for_prefix_v1(extent.limits(), extent.native_bytes()),
            None => Err(JournalError::ProtectedBoundary),
        });
    }

    pub(crate) fn extent(&self) -> Option<&ProtectedJournalPreopenReplayExtentV1> {
        self.extent.as_ref()?.as_ref().ok()
    }

    pub(crate) fn index_demand_v1(&self) -> Result<ResourceVector, JournalError> {
        self.opening.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?.additional_index_demand_v1()
            .map_err(JournalError::RootNative)
    }

    // Current-cut callers historically sample names before extent admission;
    // startup calls this only after its held extent and service precheck.
    pub(crate) fn observe_names_before_once(&mut self) {
        if self.before.is_some() { return; }
        if let Some(Ok(opening)) = self.opening.as_mut() {
            self.before = Some(opening.observe_names_before_once());
        }
    }

    pub(crate) fn replay_once(&mut self) {
        if self.replay.is_some() || self.failure().is_some() { return; }
        self.observe_names_before_once();
        if !matches!(self.before, Some(Ok(()))) { return; }
        let Some(Ok(opening)) = self.opening.as_mut() else { return; };
        self.replay = Some((|| {
            let identity = opening.prepare_semantic_identity_once()?;
            let limits = opening.prepared_extent().ok_or(RootWriterErrorV1::Closed)?.limits();
            let mut cursor = opening.begin_replay_once()?;
            self.semantic.observe_root_once(&mut cursor, identity, limits)
                .map_err(|_| RootWriterErrorV1::Closed)
        })());
        if matches!(self.replay, Some(Ok(()))) {
            self.tail = Some(opening.finish_tail_once());
        }
    }

    pub(crate) fn finish_names_once(&mut self) {
        if self.after.is_none() {
            if let Some(Ok(opening)) = self.opening.as_mut() {
                self.after = Some(opening.finish_names_once());
            }
        }
    }

    pub(crate) fn ready(&self) -> bool {
        matches!(self.replay, Some(Ok(()))) && matches!(self.tail, Some(Ok(())))
            && matches!(self.before, Some(Ok(()))) && matches!(self.after, Some(Ok(())))
            && self.failure().is_none()
    }

    pub(crate) fn take_opened_once(&mut self) {
        if !self.ready() || self.completed { return; }
        if !self.conversion.entered() {
            self.conversion.observe_once(&mut self.semantic.take_remainder_once());
        }
        if !self.conversion.ready() {
            return;
        }
        let Some(Ok(opening)) = self.opening.as_mut() else { return; };
        // Both recipes are fixed policy-compiler journals, not deployment files.
        if self.coordinator.is_none() {
            self.coordinator = Some(match opening.take_coordinator_after_semantic_replay_once(
                native_backing::Selection::Other,
            ) {
                Ok(writer) => writer,
                Err(cause) => { self.replay = Some(Err(cause)); return; }
            });
        }
        let Some(report) = opening.recovery_report() else { return; };
        let inputs = (self.coordinator.take(), self.conversion.take_once(), self.financial.take());
        let (writer, semantic, financial) = match inputs {
            (Some(writer), Some(semantic), Some(financial)) => (writer, semantic, financial),
            (writer, semantic, financial) => {
                self.coordinator = writer;
                self.conversion.restore_unmoved(semantic);
                self.financial = financial;
                return;
            }
        };
        let report = RecoveryReport {
            committed_transactions: report.committed_transactions,
            committed_records: report.committed_records,
            truncated_bytes: report.truncated_bytes,
        };
        self.taken = Some((Journal::from_root_coordinator_v1(
            writer, semantic, Arc::new(JournalAuthorityInstance), financial,
        ), report));
        self.completed = true;
    }

    pub(crate) fn opened_mut(&mut self) -> Option<&mut Journal> { self.taken.as_mut().map(|pair| &mut pair.0) }

    pub(crate) fn take_pair_once(&mut self) -> Option<(Journal, RecoveryReport)> { self.taken.take() }

    pub(crate) fn concrete_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.taken.as_ref().and_then(|(journal, _)| journal.retained_selected_failure_v1())
            .or_else(|| self.opening.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.opening.as_ref().and_then(|result| result.as_ref().ok()).and_then(|opening| opening.prefix_failure_v1()))
            .or_else(|| self.preparation.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.extent.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.before.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.semantic.failure())
            .or_else(|| self.replay.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.tail.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.conversion.failure())
            .or_else(|| self.opening.as_ref().and_then(|result| result.as_ref().ok()).and_then(|opening| opening.names_post_failure_v1()))
            .or_else(|| self.after.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.concrete_failure_v1()
            .or_else(|| self.opening.as_ref().and_then(|result| result.as_ref().ok()).and_then(|opening| opening.failure()))
    }
}
