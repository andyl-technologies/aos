//! Lends verified restored Producer completion to its registered durable publisher.
//!
//! The Source invokes the selected callback synchronously under its original
//! native read fence. Neither a completion DTO nor a publication storage row can
//! construct this scope. Retire remains after durable common scheduling commit.

use super::*;
use crate::node_admission::{CompleteOriginalRestorationWindow, InstalledConformancePlan};
use crucible_node_format::ContentRef;
use std::mem::size_of;

/// Publishes one actual restored Producer result under its owning Source fence.
///
/// This interface is separate from the original-execution publisher. A selected
/// target holder must retain the concrete publisher before action admission.
pub trait OriginalRestoredProducerResultPublisher {
    /// Durably publishes or reconciles the same verified target completion.
    ///
    /// # Errors
    /// Defaults to refusal. Implementations refuse changed original ownership,
    /// unavailable or uncertain durable storage, and any failed current fence.
    fn publish_original_restored_producer(
        &mut self,
        _scope: &OriginalRestoredProducerPublicationScope<'_>,
    ) -> Result<PublicationStatus, RuntimeError> {
        Err(RuntimeError::ForeignAuthority)
    }

    /// Borrows this placement's actual committed canonical root.
    ///
    /// The same Source fence remains held after publication. A portable ref,
    /// another slot or an uncertain placement cannot substitute for this loan.
    ///
    /// # Errors
    /// Defaults to refusal. Implementations refuse until this exact placement
    /// has returned Committed and every original scope still authenticates.
    fn committed_root_data<'a>(
        &'a self,
        _scope: &OriginalRestoredProducerPublicationScope<'_>,
    ) -> Result<(&'a ContentRef, &'a [u8]), RuntimeError> {
        Err(RuntimeError::ForeignAuthority)
    }
}

/// Reports concrete publisher work independently from its execution admission.
///
/// The genuine holder callback binds the fixed row to its actual publisher and
/// directory owners. Numeric equality creates no publication or runtime right.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OriginalRestoredProducerPublicationConstructionData {
    retained: usize,
    transient: usize,
    scratch: usize,
    descriptors: usize,
    report_encoded: usize,
    outcome_encoded: usize,
    slots: usize,
    requested: usize,
}

impl OriginalRestoredProducerPublicationConstructionData {
    /// Checks the independently computed concrete publisher construction axes.
    ///
    /// This constructor produces DATA only. The actual registered holder and
    /// complete current-owner observation remain mandatory before publication.
    ///
    /// # Errors
    /// Refuses empty slot coverage, arithmetic overflow, or requested bytes
    /// exceeding the unchanged construction policy.
    pub fn new_data(
        retained: usize,
        transient: usize,
        scratch: usize,
        descriptors: usize,
        report_encoded: usize,
        outcome_encoded: usize,
        slots: usize,
        maximum: usize,
    ) -> Result<Self, RuntimeError> {
        if slots == 0 {
            return Err(RuntimeError::ResourceLimit);
        }
        let requested = retained
            .checked_add(transient)
            .and_then(|bytes| bytes.checked_add(scratch))
            .filter(|bytes| *bytes <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        Ok(Self {
            retained,
            transient,
            scratch,
            descriptors,
            report_encoded,
            outcome_encoded,
            slots,
            requested,
        })
    }

    /// Returns independently retained concrete publisher construction demand.
    pub fn retained_requested_bytes_data(&self) -> usize {
        self.retained
    }

    /// Returns simultaneous concrete callback and readback work.
    pub fn maximum_simultaneous_transient_bytes_data(&self) -> usize {
        self.transient
    }

    /// Returns defining fixed callback, counter, result and borrowed views.
    pub fn counter_scratch_bytes_data(&self) -> usize {
        self.scratch
    }

    /// Returns temporary descriptors independently of retained directory owners.
    pub fn maximum_simultaneous_transient_descriptors_data(&self) -> usize {
        self.descriptors
    }

    /// Returns the same defining Source-report byte extent used by the quote.
    pub fn maximum_report_encoded_bytes_data(&self) -> usize {
        self.report_encoded
    }

    /// Returns the independently projected complete common Outcome byte extent.
    pub fn maximum_outcome_encoded_bytes_data(&self) -> usize {
        self.outcome_encoded
    }

    /// Returns the actual predeclared global operation-slot population.
    pub fn maximum_slots_data(&self) -> usize {
        self.slots
    }

    /// Returns the checked simultaneous memory commitment, without authority.
    pub fn requested_bytes_data(&self) -> usize {
        self.requested
    }
}

/// Supplies the selected Source's synchronous already-held proof fence.
///
/// Only crate-owned Source implementations can implement this interface. The
/// selected Runtime callback still authenticates its pending/completed ledger,
/// actual Window, admission row and publisher before constructing a public loan.
pub(crate) trait OriginalRestoredProducerReportFence {
    fn report_data(&self) -> (&ContentRef, &[u8]);

    fn outcome_data(&self) -> &OperationOutcome;

    fn authenticate_current_data(&self) -> Result<(), RuntimeError>;

    fn retain_committed_root_data(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
    ) -> Result<(), RuntimeError>;
}

/// Borrows one Source-verified pre-ACK report beside its actual Runtime outcome.
///
/// No constructor, Clone, deserializer or owned conversion is exposed. The
/// borrowed Source read fence remains held during every publisher callback.
pub struct OriginalRestoredProducerPublicationScope<'a> {
    window: &'a CompleteOriginalRestorationWindow,
    plan: &'a InstalledConformancePlan,
    world: &'a WorldActivation,
    original: &'a OriginalCompletedOperation<'a>,
    source: &'a dyn OriginalRestoredProducerReportFence,
    publisher: *const (),
    slot: usize,
}

impl OriginalRestoredProducerPublicationScope<'_> {
    /// Borrows the exact completion retained by the issuing Runtime.
    pub fn original_operation_data(&self) -> &OriginalCompletedOperation<'_> {
        self.original
    }

    /// Borrows the same activated target World.
    pub fn world_data(&self) -> &WorldActivation {
        self.world
    }

    /// Borrows evidence from the same installed plan allocation.
    pub fn plan_data(&self) -> ConformancePlanEvidence<'_> {
        self.plan.evidence()
    }

    /// Returns the monotone slot assigned by the real Window operation ledger.
    pub fn slot_data(&self) -> usize {
        self.slot
    }

    /// Borrows the full Source-retained canonical report and its complete ref.
    pub fn report_data(&self) -> (&ContentRef, &[u8]) {
        self.source.report_data()
    }

    /// Compares the actual target holder's retained Window allocation.
    pub fn is_original_window_data(
        &self,
        original: &Rc<CompleteOriginalRestorationWindow>,
    ) -> bool {
        std::ptr::eq(self.window, original.as_ref())
    }

    /// Compares the publisher actually registered during whole-owner admission.
    pub fn original_publisher_data(&self, publisher: *const ()) -> bool {
        !publisher.is_null() && self.publisher == publisher
    }

    /// Rechecks the same Source proof and live fence without reopening its banks.
    ///
    /// # Errors
    /// Refuses any changed original, spent or failed action, current proof or
    /// native read owner. No nested Source-association loan is acquired.
    pub fn authenticate_current_data(&self) -> Result<(), RuntimeError> {
        self.source.authenticate_current_data()
    }

    pub(crate) fn counter_scratch_data() -> usize {
        size_of::<Self>()
            + size_of::<&Self>()
            + size_of::<&dyn OriginalRestoredProducerReportFence>()
            + size_of::<&mut dyn OriginalRestoredProducerResultPublisher>()
            + size_of::<(&ContentRef, &[u8])>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Result<PublicationStatus, RuntimeError>>()
            + size_of::<Result<(&ContentRef, &[u8]), RuntimeError>>()
            + size_of::<OriginalRestoredProducerPublicationConstructionData>()
            + size_of::<Result<OriginalRestoredProducerPublicationConstructionData, RuntimeError>>()
            + size_of::<Option<usize>>()
            + size_of::<[usize; 3]>()
            + size_of::<std::array::IntoIter<usize, 3>>()
    }
}

impl ConformanceRuntime {
    /// Observes the actual restored Runtime's global retained-operation ceiling.
    ///
    /// This DATA bounds the concrete publisher's predeclared slot roster. It is
    /// not a new quota, operation grant, admission or permission to allocate.
    ///
    /// # Errors
    /// Refuses an ordinary initial collection owner rather than a genuine
    /// complete-restoration Runtime.
    pub fn original_restored_producer_operation_limit_data(&self) -> Result<usize, RuntimeError> {
        self.authenticate_complete_original_restoration_origin()?;
        Ok(self
            .runtime
            .original_restored_producer_operation_limit_data())
    }
}

impl ConformanceRuntime {
    pub(crate) fn original_restored_producer_grant_requested_storage_data(
        &self,
        grant: &crate::node_scheduling::ExecutionAdmission,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.observation_data()
            .original_restored_producer_grant_requested_storage_data(grant, maximum)
    }
}

/// Lends an actual Source-owned report while its native read remains armed.
///
/// Only the crate-owned Source fence can construct this borrowed scope. A
/// caller-supplied report, Outcome or completed operation cannot create it.
pub struct OriginalRestoredProducerReportReadScope<'a> {
    source: &'a dyn OriginalRestoredProducerReportFence,
    claim: &'a crate::node_admission::OriginalRestoredProducerExecutionClaim<'a>,
}

impl<'a> OriginalRestoredProducerReportReadScope<'a> {
    pub(crate) fn from_source_data(
        source: &'a dyn OriginalRestoredProducerReportFence,
        claim: &'a crate::node_admission::OriginalRestoredProducerExecutionClaim<'a>,
    ) -> Result<Self, RuntimeError> {
        source.authenticate_current_data()?;
        if claim.phase_data() != crate::node_admission::ProducerExecutionPhase::Publication {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(Self { source, claim })
    }

    pub(crate) fn authenticate_original_data(
        &self,
        claim: &crate::node_admission::OriginalRestoredProducerExecutionClaim<'_>,
        original: &OriginalCompletedOperation<'_>,
    ) -> Result<(), RuntimeError> {
        if !std::ptr::eq(self.claim, claim)
            || original.acknowledged()
            || !original
                .admission()
                .activation()
                .same_authority(claim.world_data())
            || self.source.outcome_data() != original.outcome()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        claim.with_original_grant_data(|grant| {
            if grant.operation() != original.admission().token().operation()
                || grant.node() != &original.admission().token().route().node
                || &grant.request() != original.admission().request()
            {
                return Err(RuntimeError::ForeignAuthority);
            }
            Ok(())
        })?;
        self.source.authenticate_current_data()
    }
}

impl ConformanceRuntime {
    /// Publishes an admitted restored Producer result before retiring its custody.
    ///
    /// The actual Source report remains borrowed under its native read fence
    /// while the registered publisher puts or reconciles its original root.
    /// Only that placement's genuine committed root reaches native Retire.
    /// Unknown publication can reconcile the same placement without repeating
    /// Begin or Poll. A later scheduling or Retire failure keeps its spent scope.
    ///
    /// # Errors
    /// Refuses changed currentness, token, publisher, Source report or native
    /// owner; missing durable commitment; scheduling refusal; or native failure.
    pub fn publish_and_acknowledge_original_restored_producer(
        &mut self,
        token: &OperationToken,
        admission: &mut crate::node_admission::OriginalRestoredProducerExecutionAdmission,
        publisher: &mut dyn OriginalRestoredProducerResultPublisher,
        launch: &crucible_node_transport::reference_packet::service::PacketNative5SourceLaunch,
        canonical_launch5: &[u8],
    ) -> Result<(), RuntimePollFailure> {
        use crate::node_admission::ProducerExecutionPhase;

        self.current_operation(token)
            .map_err(RuntimePollFailure::Admission)?;
        let world = self
            .activation
            .as_ref()
            .ok_or(RuntimePollFailure::Admission(RuntimeError::NotActivated))?;
        let claim = admission
            .begin_phase_data(
                &self.runtime,
                world,
                launch,
                canonical_launch5,
                ProducerExecutionPhase::Publication,
            )
            .map_err(RuntimePollFailure::Admission)?;
        let pointer = (publisher as *mut dyn OriginalRestoredProducerResultPublisher).cast::<()>();
        if claim
            .publisher_data()
            .map_err(RuntimePollFailure::Admission)?
            .0
            != pointer.cast_const()
        {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ));
        }
        self.graph.authenticate_current_scope().map_err(|error| {
            RuntimePollFailure::Admission(RuntimeError::SchedulerRefused(error.message))
        })?;
        let plan = self.graph.plan();
        let mut status = None;
        self.runtime
            .with_original_restored_producer_completion_data(
                token,
                &claim,
                &mut |original, read| {
                    read.authenticate_original_data(&claim, original)?;
                    let scope = OriginalRestoredProducerPublicationScope {
                        window: claim.window_data(),
                        plan,
                        world,
                        original,
                        source: read.source,
                        publisher: pointer.cast_const(),
                        slot: claim.slot_data(),
                    };
                    scope.authenticate_current_data()?;
                    let result = publisher.publish_original_restored_producer(&scope)?;
                    if result == PublicationStatus::Committed {
                        let (reference, bytes) = publisher.committed_root_data(&scope)?;
                        // The Source clones the complete reference while this exact
                        // placement and original native read are still borrowed.
                        read.source.retain_committed_root_data(reference, bytes)?;
                    }
                    scope.authenticate_current_data()?;
                    status = Some(result);
                    Ok(())
                },
            )
            .map_err(RuntimePollFailure::Admission)?;
        if status != Some(PublicationStatus::Committed) {
            claim
                .complete_retryable_publication_data()
                .map_err(RuntimePollFailure::Admission)?;
            return Err(RuntimePollFailure::Admission(
                RuntimeError::OutstandingObligations,
            ));
        }
        let receipt = self
            .runtime
            .scheduling_receipt_with_producer_claim(token, Some(&claim))
            .map_err(RuntimePollFailure::Admission)?;
        let commit = self
            .runtime
            .commit_scheduling_receipt_with_producer_claim(receipt, Some(&claim))
            .map_err(RuntimePollFailure::Admission)?;
        claim
            .complete_runtime_phase_data(&self.runtime, token)
            .map_err(RuntimePollFailure::Admission)?;
        drop(claim);

        // This distinct spent phase cannot publish another body or borrow a
        // caller-created output list as a native retirement permission.
        let retirement = admission
            .begin_phase_data(
                &self.runtime,
                world,
                launch,
                canonical_launch5,
                ProducerExecutionPhase::Retirement,
            )
            .map_err(RuntimePollFailure::Admission)?;
        self.runtime.acknowledge_scheduled_with_producer_claim(
            token,
            &commit,
            Some(&retirement),
        )?;
        retirement
            .complete_runtime_phase_data(&self.runtime, token)
            .map_err(RuntimePollFailure::Admission)
    }
}
