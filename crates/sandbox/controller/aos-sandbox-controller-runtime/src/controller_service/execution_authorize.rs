//! Runs the actual held59 Authorize and distinct first Observe on one Session.
//!
//! The enclosing genuine C18/Source/Environment interval remains live. Host
//! independently joins its local native claim and actual Storage hold; the
//! Controller's historical receipt and this private stage issue neither proof.
//! Both exchanges retain their original native outcomes until the enclosing
//! Source/C positive-disposal guard permits their exact resource retirement.

use aos_sandbox_controller_domain::{EffectFailure, Journal, ResourceReservationErrorV1};
use sha2::Digest as _;
use aos_sandbox_controller_domain::controller_execution_operation::{ControllerExecutionPositiveDisposalV1,
    ControllerExecutionReadReceivingLoanV1};
use aos_sandbox_controller_domain::controller_execution_spec_attempt::ControllerExecutionSpecAttemptV1;
use aos_sandbox_controller_domain::controller_execution_argument_receipt::{AuthenticatedControllerHostArgumentObservationV1,
    ControllerExecutionArgumentReceiptErrorV1, revalidate_authenticated_controller_host_argument_receipt_v2};
use aos_sandbox_controller_domain::environment::EnvironmentProtectedJournalOwnerV1;
use aos_sandbox_controller_domain::execution_parent_resource::{ExecutionParentResourceSourceV1,
    revalidate_execution_parent_resource_from_journal_v1};
use aos_sandbox_controller_domain::journal::JournalAppendReceivingDemandErrorV1;
use aos_sandbox_controller_domain::runtime_scope::CurrentAssignmentTarget;
use aos_sandbox_model::{ExecutionId, OperationId, ResourceDimension as D, ResourceVector, RawPairedClockSample};
use aos_sandbox_broker::paired_clock::ProtectedOwnershipClockError;
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1 as Demand;
use aos_sandbox_linux::immutable_file::SealedReadOnlyCredentialCreateOriginalsV1;
use aos_sandbox_protocol::domain_ledger::effect_history::{EffectReceipt, PublicMutationEffectHistoryV1};
use aos_sandbox_protocol::host_execution::admission_content::{
    HostExecutionAdmissionContentV5, MAXIMUM_ADMISSION_CONTENT_BYTES_V5,
};
use aos_sandbox_protocol::ProtocolValidationError;
use crate::{BrokerSessionSecurityError, DormantStorageLifecycleInventoryOwnerV1};
use aos_sandbox_broker_session_security::HostExecutionSessionReceivingOriginalV1;

use super::execution::{ControllerExecutionCompletionV1, ControllerExecutionExchangeV1,
    ControllerExecutionIntentV1, ControllerExecutionObservationV1, ExecutionDescriptorVersionV2};
use super::publication::ControllerHostPublication;
use super::plan_signer::ControllerBrokerPlanSignerV1;

type Bank = aos_sandbox_controller_domain::ControllerResourceBankOpeningV1;
type Profile = aos_sandbox_controller_domain::normal_root::ProductionControllerNormalRootProfileV1;

#[derive(Clone, Copy)]
enum ExecutionAuthorizeFrontierV2 {
    Forecast, Receipt, Parent, Clock, Intent, Lifetime, Content, AuthorizePlan,
    AuthorizeExchange, ObserveReservation, ObservePlan, ObserveExchange, ChildCompletion, FinalCurrent, SessionPost,
}

/// Holds one post initialized only after its caller's actual fixed entry.
#[derive(Default)]
pub(super) struct ExecutionClientPostSlotV1 {
    original: Option<Box<aos_sandbox_broker_session_security::ExecutionClientPostOriginalV1>>,
}

impl ExecutionClientPostSlotV1 {
    pub(super) fn receiving_demand_v1() -> Option<ResourceVector> {
        boxed_post_receiving_demand_v1::<
            aos_sandbox_broker_session_security::ExecutionClientPostOriginalV1
        >()
    }

    // Only Capture and Argument call this after their retained fixed success.
    // Neither borrowing nor an owed negative post initializes storage.
    pub(super) fn initialize_once_v1(&mut self) -> Result<(), BrokerSessionSecurityError> {
        if self.original.is_some() {
            return Err(BrokerSessionSecurityError::Currentness);
        }

        self.original = Some(Box::new(Default::default()));
        Ok(())
    }

    pub(super) fn native_mut_v1(&mut self) -> Result<
        &mut aos_sandbox_broker_session_security::ExecutionClientPostOriginalV1,
        BrokerSessionSecurityError,
    > {
        self.original
            .as_deref_mut()
            .ok_or(BrokerSessionSecurityError::Currentness)
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.as_deref()?.failure()
    }

    pub(super) fn terminal_before_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.as_deref()?.terminal_before_failure_v1()
    }

    pub(super) fn terminal_after_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.as_deref()?.terminal_after_failure_v1()
    }
}

// Preserve the canonical post's complete quote, including its two native
// carrier planes. Add the third plane, any enclosing wrapper controls, and
// actual Box/Layout carriers. The pointee is not also stored in parent Self.
fn boxed_post_receiving_demand_v1<T>() -> Option<ResourceVector> {
    use std::mem::size_of;

    let native = size_of::<aos_sandbox_broker_session_security::ExecutionClientPostOriginalV1>();
    let wrapper = size_of::<T>();

    let bytes = wrapper
        .checked_add(wrapper.checked_sub(native)?.checked_mul(2)?)?
        .checked_add(size_of::<Box<T>>().checked_mul(2)?)?
        .checked_add(size_of::<std::alloc::Layout>())?;

    aos_sandbox_broker_session_security::ExecutionClientPostOriginalV1::receiving_demand_v1()?
        .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?))
        .ok()
}

/// Owns the actual paid endpoint post through every early return.
#[derive(Default)]
pub(super) struct AcceptedSessionPostOriginalV1 {
    /// Keeps the actual fixed-endpoint native destinations.
    pub(super) native: aos_sandbox_broker_session_security::ExecutionClientPostOriginalV1,
    arm: Option<Result<(), BrokerSessionSecurityError>>,
    finish: Option<Result<(), BrokerSessionSecurityError>>,
}

impl AcceptedSessionPostOriginalV1 {
    pub(super) fn arm_once(&mut self, session: &crate::DormantAuthenticatedBrokerSessionV1) -> Result<(), EffectFailure> {
        self.arm = Some(session.arm_execution_client_post_v1(&mut self.native));
        if matches!(self.arm, Some(Ok(()))) { Ok(()) }
        else { Err(refused("actual execution endpoint post could not bind")) }
    }

    /// Finishes each entered post exactly once, including after refusal.
    ///
    /// # Errors
    /// Retains the actual native or binding refusal in this same original.
    pub(super) fn finish_once(&mut self, session: &mut crate::DormantAuthenticatedBrokerSessionV1) -> Result<(), EffectFailure> {
        if self.arm.is_none() { return Ok(()); }
        if self.finish.is_none() {
            self.finish = Some(session.finish_execution_client_post_v1(&mut self.native));
        }
        if matches!(self.finish, Some(Ok(()))) { Ok(()) }
        else { Err(refused("independently owed execution endpoint post refused")) }
    }

    /// Borrows the first entered native or binding refusal.
    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.arm.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.native.failure())
            .or_else(|| self.finish.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

/// Keeps actual entered causes beside both exact same-Session exchanges.
pub(super) struct ExecutionAuthorizeOriginalV2 {
    operation: OperationId,
    execution: ExecutionId,
    receiving: HostExecutionSessionReceivingOriginalV1,
    session_demand: Option<Result<ResourceVector, BrokerSessionSecurityError>>,
    posts: [Option<Box<AcceptedSessionPostOriginalV1>>; 2],
    refusal_before_posts: Option<EffectFailure>,
    controller_demand: Option<Result<ResourceVector, JournalAppendReceivingDemandErrorV1>>,
    admissions: [Option<Result<(), ResourceReservationErrorV1>>; 2],
    receipt_check: Option<Result<(), ControllerExecutionArgumentReceiptErrorV1>>,
    attempt_bytes: Option<Vec<u8>>,
    capture_anchor: Option<Vec<u8>>,
    capture_specification: Option<Result<bool, aos_sandbox_controller_domain::controller_execution_spec_attempt::ControllerExecutionSpecAttemptErrorV1>>,
    content: Option<Result<Vec<u8>, ProtocolValidationError>>,
    intent: Option<Result<ControllerExecutionIntentV1, EffectFailure>>,
    lifetime: super::execution_lifetime::ExecutionLifetimeOriginalV5,
    lifetime_preparation: Option<Result<(), EffectFailure>>,
    lifetime_data: Option<Result<aos_sandbox_protocol::storage_capture_lifetime::StorageCaptureExecutionLifetimeDataV2,
        super::execution::ExecutionLifetimeSourceErrorV5>>,
    lifetime_post: Option<Result<(), EffectFailure>>,
    authorization: [Option<Result<aos_sandbox_api::aos::sandbox::local::v1::BrokerAuthorizationArtifactsV1, EffectFailure>>; 2],
    exchanges: [ControllerExecutionExchangeV1; 2],
    authorized: Option<Result<ControllerExecutionCompletionV1, EffectFailure>>,
    observe: Option<Result<ControllerExecutionIntentV1, EffectFailure>>,
    observed: Option<Result<ControllerExecutionCompletionV1, EffectFailure>>,
    completed_observe_receipt: Option<EffectReceipt>,
    frontier: ExecutionAuthorizeFrontierV2,
    parent_current: Option<Result<(), aos_sandbox_controller_domain::execution_parent_resource::ExecutionParentResourceSourceErrorV1>>,
    clock_check: Option<Result<RawPairedClockSample, ProtectedOwnershipClockError>>,
    child: ChildCompletionOriginalV1,
}

impl ExecutionAuthorizeOriginalV2 {
    fn new(operation: OperationId, execution: ExecutionId) -> Self {
        Self { operation, execution, receiving: Default::default(), session_demand: None, posts: std::array::from_fn(|_| Default::default()), refusal_before_posts: None,
            controller_demand: None, admissions: [None, None], receipt_check: None,
            attempt_bytes: None, capture_anchor: None, capture_specification: None, content: None, intent: None, lifetime: Default::default(),
            lifetime_preparation: None, lifetime_data: None, lifetime_post: None,
            authorization: [None, None], exchanges: std::array::from_fn(|_| Default::default()),
            authorized: None, observe: None, observed: None, completed_observe_receipt: None,
            frontier: ExecutionAuthorizeFrontierV2::Forecast, parent_current: None, clock_check: None, child: ChildCompletionOriginalV1::default() }
    }

    fn fixed_demand_v2(specification_bytes: usize, storage_response_bytes: usize)
        -> Result<ResourceVector, EffectFailure>
    {
        Self::fixed_demand_for_v3(specification_bytes, storage_response_bytes, None)
    }

    fn content_receiving_width_v5(
        specification_bytes: usize, storage_response_bytes: usize,
        capture: Option<(usize, usize)>,
    ) -> Result<usize, EffectFailure> {
        let invalid = || refused("execution Authorize geometry overflows");
        let attempt_bytes = specification_bytes
            .checked_add(aos_sandbox_protocol::execution_spec_attempt::PREFIX_BYTES)
            .and_then(|bytes| bytes.checked_add(32)).ok_or_else(invalid)?;
        let content_bytes = match capture {
            Some((response, anchor)) => {
                if anchor == 0 || anchor > aos_sandbox_protocol::controller_capture_admission::MAXIMUM_CAPTURE_ADMISSION_ANCHOR_BYTES_V2 {
                    return Err(invalid());
                }
                aos_sandbox_protocol::host_execution::admission_content::capture_encoded_widths_v5(
                    attempt_bytes, storage_response_bytes, response)
            }
            None => aos_sandbox_protocol::host_execution::admission_content::stream_encoded_widths_v5(
                attempt_bytes, storage_response_bytes),
        }.ok_or_else(invalid)?;
        Ok(content_bytes)
    }

    fn fixed_demand_for_v3(specification_bytes: usize, storage_response_bytes: usize,
        capture: Option<(usize, usize)>) -> Result<ResourceVector, EffectFailure>
    {
        let invalid = || refused("execution Authorize geometry overflows");
        let content_bytes = Self::content_receiving_width_v5(
            specification_bytes, storage_response_bytes, capture)?;
        // Canonical spec/attempt/content/descriptor/signature originals overlap.
        // The existing bounded decoder supplies its finite collection ceiling;
        // actual strings and raw byte planes are paid separately from headers.
        // This private stage receives an already validated opaque canonical
        // attempt. Every decoded CBOR item consumes at least one of its actual
        // bytes; malformed claimed lengths cannot be introduced through it.
        let decoded = aos_sandbox_protocol::execution_spec_attempt::execution_spec_validation_model_memory_bytes_v2(
            specification_bytes).ok_or_else(invalid)?;
        let anchor_bytes = capture.map_or(0, |(_, bytes)| bytes);
        let memory = content_bytes.checked_mul(16)
            .and_then(|bytes| bytes.checked_add(anchor_bytes.checked_mul(4)?))
            .and_then(|bytes| bytes.checked_add(decoded))
            .and_then(|bytes| bytes.checked_add(3 * std::mem::size_of::<Self>()))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or_else(invalid)?;
        let credential = SealedReadOnlyCredentialCreateOriginalsV1::receiving_footprint_v1(
            "aos-host-execution-spec".len(), content_bytes).ok_or_else(invalid)?;
        let one = aos_sandbox_controller_domain::journal::ProtectedJournalCurrentnessOriginalsV1::named_demand_v1("controller.journal")
            .map_err(|error| refused(error.to_string()))?;
        let mut demand = HostExecutionSessionReceivingOriginalV1::fixed_demand_v1().ok_or_else(invalid)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, memory)
                .with(D::OpenFiles, 2)).map_err(|error| refused(error.to_string()))?;
        for _ in 0..2 {
            demand = demand.checked_add(boxed_post_receiving_demand_v1::<AcceptedSessionPostOriginalV1>()
                .ok_or_else(invalid)?).map_err(|error| refused(error.to_string()))?;
            demand = demand.checked_add(ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(credential.memory_bytes).map_err(|_| invalid())?)
                .with(D::OpenFiles, u64::try_from(credential.open_files).map_err(|_| invalid())?))
                .and_then(|value| value.checked_add(one))
                .and_then(|value| value.checked_add(one)).map_err(|error| refused(error.to_string()))?;
        }
        Ok(demand)
    }

    pub(super) fn failure_v2(&self) -> Option<super::execution::ExecutionPublicationCauseV1<'_>> {
        use super::execution::ExecutionPublicationCauseV1 as Cause;
        if self.completed_observe_receipt.is_some() { return None; }
        let selected = (|| match self.frontier {
            ExecutionAuthorizeFrontierV2::Forecast => self.posts.iter()
                .find_map(|post| post.as_deref()?.arm.as_ref()?.as_ref().err())
                .map(Cause::Session)
                .or_else(|| self.receiving.failure().map(Cause::Transport))
                .or_else(|| self.session_demand.as_ref()?.as_ref().err().map(Cause::Session))
                .or_else(|| self.controller_demand.as_ref()?.as_ref().err().map(|error| Cause::Transport(error)))
                .or_else(|| self.child.forecast.as_ref()?.as_ref().err().map(Cause::Session))
                .or_else(|| self.admissions[0].as_ref()?.as_ref().err().map(|error| Cause::Transport(error))),
            ExecutionAuthorizeFrontierV2::Receipt => self.receipt_check.as_ref()?.as_ref().err().map(|error| Cause::Transport(error)),
            ExecutionAuthorizeFrontierV2::Parent => self.parent_current.as_ref()?.as_ref().err().map(|error| Cause::Transport(error)),
            ExecutionAuthorizeFrontierV2::Clock => self.clock_check.as_ref()?.as_ref().err().map(|error| Cause::Transport(error)),
            ExecutionAuthorizeFrontierV2::Intent => self.intent.as_ref()?.as_ref().err().map(Cause::Effect),
            ExecutionAuthorizeFrontierV2::Lifetime => self.lifetime.preparation_failure().map(Cause::Transport)
                .or_else(|| self.lifetime_preparation.as_ref().and_then(|result| result.as_ref().err()).map(Cause::Effect))
                .or_else(|| self.lifetime_data.as_ref().and_then(|result| result.as_ref().err()).map(|cause| Cause::Transport(cause)))
                .or_else(|| self.lifetime.post_failure().map(Cause::Transport))
                .or_else(|| self.lifetime_post.as_ref().and_then(|result| result.as_ref().err()).map(Cause::Effect)),
            ExecutionAuthorizeFrontierV2::Content => self.capture_specification.as_ref().and_then(|value| value.as_ref().err())
                .map(|error| Cause::Transport(error)).or_else(|| self.content.as_ref()?.as_ref().err().map(|error| Cause::Transport(error))),
            ExecutionAuthorizeFrontierV2::AuthorizePlan => self.authorization[0].as_ref()?.as_ref().err().map(Cause::Effect),
            ExecutionAuthorizeFrontierV2::AuthorizeExchange => self.posts[0].as_deref()
                .and_then(|post| self.exchanges[0].publication_failure_with_post_v1(post))
                .or_else(|| self.authorized.as_ref()?.as_ref().err().map(Cause::Effect)),
            ExecutionAuthorizeFrontierV2::ObserveReservation => self.observe.as_ref()?.as_ref().err().map(Cause::Effect),
            ExecutionAuthorizeFrontierV2::ObservePlan => self.authorization[1].as_ref()?.as_ref().err().map(Cause::Effect),
            ExecutionAuthorizeFrontierV2::ObserveExchange => self.posts[1].as_deref()
                .and_then(|post| self.exchanges[1].publication_failure_with_post_v1(post))
                .or_else(|| self.observed.as_ref()?.as_ref().err().map(Cause::Effect)),
            ExecutionAuthorizeFrontierV2::ChildCompletion => self.child.failure_v1().map(Cause::Transport),
            ExecutionAuthorizeFrontierV2::SessionPost => self.posts.iter()
                .find_map(|post| post.as_deref()?.failure())
                .map(Cause::Transport),
            ExecutionAuthorizeFrontierV2::FinalCurrent => self.admissions[1].as_ref()?.as_ref().err().map(|error| Cause::Transport(error)),
        })();
        selected.or_else(|| self.refusal_before_posts.as_ref().map(Cause::Effect))
    }

    pub(super) fn debts_v2(&self) -> Option<super::execution::ExecutionPublicationDebtsV1<'_>> {
        self.exchanges[1].publication_debts().or_else(|| self.exchanges[0].publication_debts())
    }

    pub(super) fn require_positive_disposal_v2(&self,
        disposal: &ControllerExecutionPositiveDisposalV1<'_>, execution: ExecutionId,
    ) -> Result<(), EffectFailure> {
        if disposal.operation_v1() != self.operation || execution != self.execution
            || self.completed_observe_receipt.is_none()
            || !self.exchanges.iter().all(ControllerExecutionExchangeV1::completed_accepted_publication_v2)
        { return Err(refused("execution original has unfinished or mismatched native custody")); }
        Ok(())
    }
}

#[derive(Default)]
struct ChildCompletionOriginalV1 {
    forecast: Option<Result<ResourceVector, BrokerSessionSecurityError>>,
    sample: Option<Result<RawPairedClockSample, ProtectedOwnershipClockError>>,
    history_check: Option<Result<(), BrokerSessionSecurityError>>,
    append_sample: Option<Result<RawPairedClockSample, ProtectedOwnershipClockError>>,
    evidence: Option<Result<aos_sandbox_protocol::domain_ledger::execution_observe_reservation::completion::ObserveChildCompletionDataV1,
        aos_sandbox_protocol::domain_ledger::execution_observe_reservation::completion::ObserveCompletionDataErrorV1>>,
    prepared: Option<Result<Option<[aos_sandbox_controller_domain::JournalRecord; 2]>, aos_sandbox_controller_domain::ReconcilerError>>,
    transaction: Option<Result<aos_sandbox_controller_domain::JournalTransaction, aos_sandbox_protocol::domain_ledger::JournalTransactionDataError>>,
    append: Option<Result<aos_sandbox_controller_domain::CommitResult, aos_sandbox_controller_domain::JournalError>>,
    readback: Option<Result<bool, aos_sandbox_controller_domain::ReconcilerError>>,
    result: Option<Result<(), EffectFailure>>,
}

impl ChildCompletionOriginalV1 {
    fn failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.forecast.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.history_check.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.sample.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.evidence.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.prepared.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.transaction.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.append_sample.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.append.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.readback.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause as _))
    }

    fn complete_once_v1<T>(
        &mut self, journal: &mut Journal, session: &crate::DormantAuthenticatedBrokerSessionV1,
        exchanges: &[ControllerExecutionExchangeV1; 2], execution: ExecutionId, cutoff: u64,
        receipt: &EffectReceipt, admission_content: &[u8], registration_response: &[u8],
        capture_anchor: Option<&[u8]>, clock: &mut T,
    ) -> Result<(), EffectFailure>
    where T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        if self.result.is_some() { return Err(refused("first Observe child completion already entered")); }
        self.result = Some(self.complete_inner_v1(journal, session, exchanges, execution, cutoff, receipt, admission_content, registration_response, capture_anchor, clock));
        match &self.result {
            Some(Ok(())) => Ok(()),
            _ => Err(refused("first Observe child completion retains original refusal")),
        }
    }

    fn complete_inner_v1<T>(
        &mut self, journal: &mut Journal, session: &crate::DormantAuthenticatedBrokerSessionV1,
        exchanges: &[ControllerExecutionExchangeV1; 2], execution: ExecutionId, cutoff: u64,
        receipt: &EffectReceipt, admission_content: &[u8], registration_response: &[u8],
        capture_anchor: Option<&[u8]>, clock: &mut T,
    ) -> Result<(), EffectFailure>
    where T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        let authorize = exchanges[0].completed_publication_outcome_v2()?;
        let observe = exchanges[1].completed_publication_outcome_v2()?;
        let history = match session.host_execution_history_data_v1() {
            Ok(history) => { self.history_check = Some(Ok(())); history }
            Err(cause) => {
                self.history_check = Some(Err(cause));
                return Err(refused("actual Host history original is unavailable"));
            }
        };
        let reservation = journal.get(aos_sandbox_controller_domain::RecordNamespace::ControllerExecutionObserveReservation, execution.as_bytes())
            .ok_or_else(|| refused("exact retained Observe reservation is absent"))?;
        let reservation = aos_sandbox_controller_domain::controller_execution_observe_reservation::ControllerExecutionObserveReservationV1::decode(
            execution.as_bytes(), reservation).map_err(|_| refused("retained Observe reservation is corrupt"))?;
        // Full history must end at the SAME two genuinely completed owners.
        // No arbitrary later terminal or forwarded request substitutes for them.
        let stored = aos_sandbox_protocol::authenticated_session::stored_history::StoredBrokerSessionHistoryV1::decode(
            &aos_sandbox_protocol::authenticated_session::stored_history::canonical_protocol_key_v1(aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Host), history)
            .map_err(refused)?;
        let model = stored.history_model().map_err(refused)?;
        let rows = model.records();
        let last = rows.len().checked_sub(1).ok_or_else(|| refused("completed Host history is empty"))?;
        let prior = last.checked_sub(2).ok_or_else(|| refused("completed Host history lacks Authorize"))?;
        if rows[last].outcome_packet() != Some(observe.canonical_packet())
            || rows[last].request_packet() != observe.request().canonical_packet()
            || rows[prior].outcome_packet() != Some(authorize.canonical_packet())
            || rows[prior].request_packet() != authorize.request().canonical_packet()
        { return Err(refused("completed child differs from actual same-Session outcomes")); }
        self.sample = Some(clock());
        let sample = self.sample.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or_else(|| refused("completed Observe clock original refused"))?;
        let spec = journal.get(aos_sandbox_controller_domain::RecordNamespace::ControllerExecutionSpecAttempt, execution.as_bytes())
            .ok_or_else(|| refused("actual protected specification is absent"))?;
        let caf = journal.get(aos_sandbox_controller_domain::RecordNamespace::ControllerExecutionArgumentReceipt, execution.as_bytes())
            .ok_or_else(|| refused("actual protected Host argument receipt is absent"))?;
        // The complete v7 row must fit the SAME already-admitted Controller
        // native record ceiling before its companion allocation or decoding.
        let maximum = journal.configured_limits_data_v1().maximum_record_bytes;
        let complete_bytes = aos_sandbox_protocol::domain_ledger::execution_observe_reservation::completion::ObserveChildCompletionDataV1::receiving_widths_v5(
            spec.len(), caf.len(), history.len(), registration_response.len(), capture_anchor.map(<[u8]>::len))
            .and_then(|n| n.checked_add(reservation.encode().len()))
            .and_then(|n| n.checked_add(256))
            .ok_or_else(|| refused("completed Observe row size overflows"))?;
        if complete_bytes > maximum { return Err(refused("complete signed Observe history exceeds Controller row bounds")); }
        self.evidence = Some(aos_sandbox_protocol::domain_ledger::execution_observe_reservation::completion::ObserveChildCompletionDataV1::new_lifetime_v5(
            &reservation, spec, caf, history, admission_content, capture_anchor,
            sample, cutoff, receipt.as_bytes()));
        let evidence = self.evidence.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or_else(|| refused("complete signed first Observe evidence refused"))?;
        self.prepared = Some(aos_sandbox_controller_domain::reconciler::prepare_completed_execution_observe_child_v1(
            journal, &reservation, evidence, receipt.clone(), sample.wall_seconds()));
        let prepared = match self.prepared.take() {
            Some(Ok(Some(records))) => records,
            Some(Ok(None)) => { self.prepared = Some(Ok(None)); return Ok(()); }
            other => { self.prepared = other; return Err(refused("exact first Observe child preparation refused")); }
        };
        let digest: [u8; 32] = sha2::Sha256::new()
            .chain_update(b"aos.sandbox.controller.execution-observe-child-completion-tx.v1\0")
            .chain_update(reservation.encode()).chain_update(receipt.as_bytes()).finalize().into();
        self.transaction = Some(aos_sandbox_controller_domain::JournalTransaction::new(
            digest[..16].try_into().map_err(|_| refused("child completion transaction identity is invalid"))?,
            Vec::from(prepared)));
        let transaction = self.transaction.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or_else(|| refused("exact first Observe child transaction refused"))?;
        // Complete signed-history validation and row preparation can consume
        // time. Recheck the SAME original lifetime immediately before entering
        // native append; this does not renew the proof or its plan/lease.
        let sources = evidence.sources().map_err(refused)?;
        self.append_sample = Some(clock());
        let append_sample = self.append_sample.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or_else(|| refused("first Observe append retains original clock refusal"))?;
        if append_sample.host_boot_id() != sources.host_boot
            || append_sample.boottime_nanoseconds() < sample.boottime_nanoseconds()
            || append_sample.boottime_nanoseconds() >= sources.cutoff
            || append_sample.wall_seconds() < sample.wall_seconds()
            || append_sample.wall_seconds() >= sources.authority_expires_seconds
        { return Err(refused("original first Observe authority expired before native append")); }
        self.append = Some(journal.commit(transaction));
        if !matches!(self.append, Some(Ok(_))) { return Err(refused("atomic first Observe child append requires cold recovery")); }
        for row in transaction.records() {
            if journal.get(row.namespace(), row.key()) != row.value() {
                return Err(refused("completed Observe child actual row readback differs"));
            }
        }
        self.readback = Some(aos_sandbox_controller_domain::reconciler::observe_child_adoption_state_v1(journal, &reservation));
        if !matches!(self.readback, Some(Ok(true))) { return Err(refused("completed Observe child cold-state validation refused")); }
        Ok(())
    }
}

fn refused(message: impl ToString) -> EffectFailure { EffectFailure::Retryable(message.to_string()) }

fn applied(value: ControllerExecutionObservationV1) -> Result<ControllerExecutionCompletionV1, EffectFailure> {
    match value {
        ControllerExecutionObservationV1::Applied(completion) => Ok(completion),
        ControllerExecutionObservationV1::Absent | ControllerExecutionObservationV1::Pending =>
            Err(refused("authenticated execution completion is absent")),
    }
}

/// Runs both actual protected turns while the original C18/Source loan is held.
///
/// # Errors
/// Retains every entered stage in the same Host publication; the caller still
/// owes its independent Source/C posts and may not retry ambiguous requests.
#[allow(clippy::too_many_arguments)]
pub(super) fn authorize_and_observe_v2<T>(
    operation: OperationId, context: &PublicMutationEffectHistoryV1, controller: &mut Journal,
    assignment: &CurrentAssignmentTarget, environment: &mut EnvironmentProtectedJournalOwnerV1<'_, '_>,
    parent: &ExecutionParentResourceSourceV1, specification: &ControllerExecutionSpecAttemptV1,
    host: &mut ControllerHostPublication, storage: &mut DormantStorageLifecycleInventoryOwnerV1,
    signer: &ControllerBrokerPlanSignerV1, receiving: &mut ControllerExecutionReadReceivingLoanV1<'_, '_>,
    bank: &Bank, profile: &Profile, observation: &AuthenticatedControllerHostArgumentObservationV1,
    clock: &mut T,
) -> Result<ControllerExecutionCompletionV1, EffectFailure>
where T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    let execution = specification.execution();
    let storage_outcome = storage.completed_registration_outcome_v1(operation, execution)
        .ok_or_else(|| refused("actual completed Storage registration owner is absent"))?.0;
    let storage_response = match storage_outcome.result() {
        aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } => exact_body.as_slice(),
        _ => return Err(refused("actual Storage registration is not successful")),
    };
    // Only the real completed60/currentness owner lends this observation.
    // Its persisted anchor remains immutable across later Storage Session work.
    let capture = storage.completed_capture_admission_v4(operation, execution);
    let capture_widths = capture.as_ref().map(|observation|
        (observation.response_bytes_v1().len(), observation.admission_anchor_bytes_v3().len()));
    let fixed = ExecutionAuthorizeOriginalV2::fixed_demand_for_v3(
        specification.specification_bytes().len(), storage_response.len(), capture_widths)?;
    receiving.admit_stage_v1(bank, controller, profile, Demand::from_demand_v1(fixed))
        .map_err(|_| refused("same C18 cannot admit execution Authorize originals"))?;
    host.install_execution_authorize_v2(ExecutionAuthorizeOriginalV2::new(operation, execution))?;
    let (original, session, actual59) = host.execution_authorize_parts_v2()?;

    if original.posts.iter().any(Option::is_some) {
        return Err(refused("execution endpoint post storage is already initialized"));
    }

    // The actual fixed entry paid both wrappers, including failed first-arm
    // cleanup. Initialize both before either independent original is armed.
    for post in &mut original.posts {
        *post = Some(Box::new(AcceptedSessionPostOriginalV1::default()));
    }

    let result = (|| {
        original.posts[0]
            .as_deref_mut()
            .ok_or_else(|| refused("execution Authorize post is absent"))?
            .arm_once(session)?;
        original.posts[1]
            .as_deref_mut()
            .ok_or_else(|| refused("execution Observe post is absent"))?
            .arm_once(session)?;

        original.session_demand = Some(session.host_execution_authorize_observe_demand_v2(&mut original.receiving));
        if !matches!(original.session_demand, Some(Ok(_))) {
            return Err(refused("actual Host Session forecast refused"));
        }
        let limits = controller.configured_limits_data_v1();
        let value = limits.maximum_record_bytes.checked_sub(7)
            .and_then(|bytes| bytes.checked_sub(limits.maximum_key_bytes))
            .ok_or_else(|| refused("Controller execution append widths are invalid"))?;
        let shape = aos_sandbox_journal::geometry::RecordShape {
            key_bytes: limits.maximum_key_bytes, value_bytes: Some(value),
        };
        // The exact engines append one Observe reservation, three adoption rows,
        // one final public projection, then the atomic two-row child completion.
        // Replays can only reduce this sequence.
        original.controller_demand = Some(controller.append_sequence_receiving_demand_v1(
            [1, 3, 1, 2].into_iter().map(|count| Ok(std::iter::repeat_n(shape, count)))));
        original.child.forecast = Some((|| {
            let history = session.host_execution_history_data_v1()?;
            let append = original.session_demand.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(BrokerSessionSecurityError::Currentness)?.get(D::StorageBytes);
            let future_history = history.len().checked_add(usize::try_from(append)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?)
                .ok_or(BrokerSessionSecurityError::Currentness)?;
            let spec_bytes = specification.specification_bytes().len()
                .checked_add(aos_sandbox_protocol::execution_spec_attempt::PREFIX_BYTES + 32)
                .ok_or(BrokerSessionSecurityError::Currentness)?;
            let companion = aos_sandbox_protocol::domain_ledger::execution_observe_reservation::completion::ObserveChildCompletionDataV1::receiving_widths_v5(
                spec_bytes, aos_sandbox_protocol::execution_argument_receipt::MAXIMUM_RECORD_BYTES,
                future_history, storage_response.len(), capture_widths.map(|(_, anchor)| anchor))
                .ok_or(BrokerSessionSecurityError::Currentness)?;
            // Requirement DATA from the same full Effect decoder model. No history
            // bytes or companion are cloned before this SAME C18 stage is admitted.
            let memory = aos_sandbox_protocol::domain_ledger::effect_history::effect_decoding_receiving_bytes_v1(companion)
                .and_then(|value| value.checked_mul(3)).and_then(|value| u64::try_from(value).ok())
                .ok_or(BrokerSessionSecurityError::Currentness)?;
            Ok(ResourceVector::ZERO.with(D::MemoryBytes, memory))
        })());
        if !matches!(original.child.forecast, Some(Ok(_))) { return Err(refused("complete signed child-history forecast refused")); }
        let child_demand = original.child.forecast.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or_else(|| refused("complete signed child-history forecast refused"))?;
        let complete = original.session_demand.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or_else(|| refused("actual Host Session forecast refused"))?
            .checked_add(*original.controller_demand.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or_else(|| refused("actual Controller append forecast refused"))?)
            .and_then(|value| value.checked_add(child_demand))
            .map_err(|error| refused(error.to_string()))?;
        original.admissions[0] = Some(receiving.admit_stage_v1(bank, controller, profile, Demand::from_demand_v1(complete)));
        if !matches!(original.admissions[0], Some(Ok(()))) { return Err(refused("same C18 execution continuation bound refused")); }

        original.frontier = ExecutionAuthorizeFrontierV2::Receipt;
        original.receipt_check = Some(revalidate_authenticated_controller_host_argument_receipt_v2(
            controller, assignment, environment, parent, observation, actual59, clock));
        if !matches!(original.receipt_check, Some(Ok(()))) {
            return Err(refused("same actual59 native owner no longer matches its live observation"));
        }
        let actual = observation;
        let heads = specification.source_heads();
        if observation.execution() != execution || observation.create_operation() != operation
            || actual.record_digest() != observation.record_digest()
            || heads.argument_receipt != actual.record_digest()
            || heads.host_argument_custody != actual.host_custody_digest()
            || heads.host_argument_sequence != actual.host_custody_sequence()
            || specification.create_operation() != operation
        { return Err(refused("execution specification differs from the actual held59 owner")); }
        let cutoff = actual.deadline_boottime_nanoseconds().min(assignment.deadline_boottime_nanoseconds())
            .min(capture.as_ref().map_or(u64::MAX, |capture| capture.cutoff_v1()));
        original.frontier = ExecutionAuthorizeFrontierV2::Parent;
        original.parent_current = Some(revalidate_execution_parent_resource_from_journal_v1(controller, parent));
        if !matches!(original.parent_current, Some(Ok(()))) { return Err(refused("execution parent is no longer current")); }
        original.frontier = ExecutionAuthorizeFrontierV2::Clock;
        original.clock_check = Some(clock());
        if original.clock_check.as_ref().and_then(|value| value.as_ref().ok())
            .is_none_or(|sample| sample.boottime_nanoseconds() >= cutoff) {
            return Err(refused("original accepted argument cutoff expired"));
        }
        original.frontier = ExecutionAuthorizeFrontierV2::Intent;
        original.intent = Some(ControllerExecutionIntentV1::from_retained_create_attempt(
            operation, context, controller, assignment, specification));
        let intent = original.intent.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or_else(|| refused("accepted execution intent is not current"))?;
        original.frontier = ExecutionAuthorizeFrontierV2::Content;
        original.capture_specification = Some(specification.decoded_specification().map(|decoded|
            matches!(decoded.io().output_mode(), aos_sandbox_model::ExecutionOutputModeV1::Capture { .. })));
        let requires_capture = original.capture_specification.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or_else(|| refused("actual canonical execution specification refused"))?;
        if requires_capture != capture.is_some() {
            original.content = Some(Err(ProtocolValidationError::MissingField("matching actual Capture60 owner")));
            return Err(refused("Capture specification and actual Capture60 owner differ"));
        }
        if capture.is_none() {
            original.frontier = ExecutionAuthorizeFrontierV2::Lifetime;
            original.lifetime_preparation = Some(original.lifetime.prepare_once(
                assignment, controller, specification, receiving, bank, profile, clock));
            if matches!(original.lifetime_preparation, Some(Ok(()))) {
                original.lifetime_data = Some(intent.prepare_lifetime_data_v5(
                    context.project(), parent.assignment().manifest().node(), controller,
                    specification, &original.lifetime));
            }
            // The same original's second verifier remains owed even when the
            // DATA/source construction refused. It never issues a new lease.
            original.lifetime_post = Some(original.lifetime.finish_once(assignment, controller, clock));
            if !matches!(original.lifetime_preparation, Some(Ok(())))
                || !matches!(original.lifetime_data, Some(Ok(_)))
                || !matches!(original.lifetime_post, Some(Ok(()))) || !original.lifetime.completed()
            {
                return Err(refused("same original execution lifetime retains a refusal"));
            }
        }
        original.frontier = ExecutionAuthorizeFrontierV2::Content;
        original.attempt_bytes = Some(specification.canonical_bytes_v1());
        let attempt = original.attempt_bytes.as_deref()
            .ok_or_else(|| refused("canonical attempt is absent"))?;
        original.content = Some(match capture.as_ref() {
            Some(capture) => HostExecutionAdmissionContentV5::new_capture_v5(
                attempt, storage_response, capture.source_v2(), capture.response_bytes_v1()),
            None => HostExecutionAdmissionContentV5::new_stream_v5(attempt, storage_response,
                original.lifetime_data.as_ref().and_then(|result| result.as_ref().ok())
                    .ok_or_else(|| refused("actual completed lifetime is absent"))?),
        }.and_then(HostExecutionAdmissionContentV5::encode));
        // Cloning occurs only after the complete SAME18 bound, and preserves the
        // exact persisted original rather than reconstructing an old checkpoint.
        original.capture_anchor = capture.as_ref().map(|capture| capture.admission_anchor_bytes_v3().to_vec());
        let content = original.content.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or_else(|| refused("canonical Host admission content refused"))?;
        original.frontier = ExecutionAuthorizeFrontierV2::AuthorizePlan;
        let version = ExecutionDescriptorVersionV2::LifetimeAdmission;
        original.authorization[0] = Some(intent.prepare_lifetime_authorization_v5(context.project(),
            parent.assignment().manifest().node(), controller, signer, content, cutoff, clock));
        let authorization = original.authorization[0].as_ref().and_then(|value| value.as_ref().ok())
            .ok_or_else(|| refused("actual Host Authorize grant refused"))?;
        original.frontier = ExecutionAuthorizeFrontierV2::AuthorizeExchange;
        original.authorized = Some(original.exchanges[0].publish_accepted_execution_v2(session,
            intent, authorization, context.project(), controller, content, version, cutoff, clock,
            original.posts[0].as_deref_mut()
                .ok_or_else(|| refused("execution Authorize post is absent"))?)
            .and_then(applied));
        let authorized = original.authorized.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or_else(|| refused("actual held Host Authorize did not complete"))?;

        original.frontier = ExecutionAuthorizeFrontierV2::ObserveReservation;
        original.observe = Some(intent.reserve_observe_after_authorization(controller, authorized));
        let observe = original.observe.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or_else(|| refused("distinct first Observe reservation refused"))?;
        let control = aos_sandbox_protocol::host_execution::HOST_EXECUTION_CONTROL_CONTENT_V1;
        original.frontier = ExecutionAuthorizeFrontierV2::ObservePlan;
        original.authorization[1] = Some(observe.prepare_lifetime_authorization_v5(context.project(),
            parent.assignment().manifest().node(), controller, signer, control, cutoff, clock));
        let authorization = original.authorization[1].as_ref().and_then(|value| value.as_ref().ok())
            .ok_or_else(|| refused("actual first Observe grant refused"))?;
        original.frontier = ExecutionAuthorizeFrontierV2::ObserveExchange;
        original.observed = Some(original.exchanges[1].publish_accepted_execution_v2(session,
            observe, authorization, context.project(), controller, control, ExecutionDescriptorVersionV2::Ordinary, cutoff, clock,
            original.posts[1].as_deref_mut()
                .ok_or_else(|| refused("execution Observe post is absent"))?)
            .and_then(applied));
        if !matches!(original.observed, Some(Ok(_))) { return Err(refused("actual first Observe did not complete")); }
        original.frontier = ExecutionAuthorizeFrontierV2::ChildCompletion;
        let observed = original.observed.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or_else(|| refused("actual completed first Observe is absent"))?;
        original.child.complete_once_v1(controller, session, &original.exchanges, execution, cutoff,
            &observed.receipt, content, storage_response, original.capture_anchor.as_deref(), clock)?;
        original.frontier = ExecutionAuthorizeFrontierV2::FinalCurrent;
        original.admissions[1] = Some(receiving.require_current_v1(bank, controller, profile));
        if !matches!(original.admissions[1], Some(Ok(()))) { return Err(refused("same C18 final execution currentness refused")); }
        let completion = match original.observed.take() {
            Some(Ok(completion)) => completion,
            _ => return Err(refused("completed Observe is absent")),
        };
        Ok(completion)
    })();
    // Both entered posts finish even on forecast, signer, preparation,
    // transport, classification or Controller append refusal. The per-turn
    // wrapper has already finished reached turns; this never repeats native IO.
    let completion = match result {
        Ok(completion) => Some(completion),
        Err(cause) => { original.refusal_before_posts = Some(cause); None }
    };
    let post0 = original.posts[0].as_deref_mut()
        .map_or(Ok(()), |post| post.finish_once(session));
    let post1 = original.posts[1].as_deref_mut()
        .map_or(Ok(()), |post| post.finish_once(session));

    let completion = completion.ok_or_else(|| refused("execution retains its original pre-post refusal"))?;
    if post0.is_err() || post1.is_err() {
        original.frontier = ExecutionAuthorizeFrontierV2::SessionPost;
        return Err(refused("execution endpoint posts retain their original refusal"));
    }
    original.completed_observe_receipt = Some(completion.receipt.clone());
    Ok(completion)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overflow_refuses_before_any_execution_original_exists() {
        assert!(ExecutionAuthorizeOriginalV2::fixed_demand_v2(usize::MAX, 512).is_err());
        assert!(ExecutionAuthorizeOriginalV2::fixed_demand_v2(512, usize::MAX).is_err());
    }

    #[test]
    fn original_refusal_precedes_later_unentered_exchange() {
        let mut original = ExecutionAuthorizeOriginalV2::new(
            OperationId::from_bytes([12; 16]), ExecutionId::from_bytes([13; 16]));
        original.frontier = ExecutionAuthorizeFrontierV2::Content;
        original.content = Some(Err(ProtocolValidationError::MissingField("original content")));
        let pointer = original.content.as_ref().unwrap().as_ref().unwrap_err() as *const ProtocolValidationError;
        match original.failure_v2() {
            Some(super::super::execution::ExecutionPublicationCauseV1::Transport(cause)) =>
                assert_eq!(cause.downcast_ref::<ProtocolValidationError>().unwrap() as *const ProtocolValidationError, pointer),
            _ => panic!("original content refusal was replaced"),
        }
        assert!(original.completed_observe_receipt.is_none());
        assert!(!original.exchanges.iter().any(ControllerExecutionExchangeV1::completed_accepted_publication_v2));
    }

    #[test]
    fn capture_forecast_prices_anchor_and_rejects_invalid_width_before_growth() {
        let ordinary = ExecutionAuthorizeOriginalV2::fixed_demand_v2(512, 400).unwrap();
        let capture = ExecutionAuthorizeOriginalV2::fixed_demand_for_v3(512, 400, Some((256, 4096))).unwrap();
        assert!(capture.get(D::MemoryBytes) > ordinary.get(D::MemoryBytes));
        assert_eq!(capture.get(D::MetadataEntries), ordinary.get(D::MetadataEntries));
        assert!(ExecutionAuthorizeOriginalV2::fixed_demand_for_v3(512, 400, Some((256, 0))).is_err());
        assert!(ExecutionAuthorizeOriginalV2::fixed_demand_for_v3(512, 400, Some((usize::MAX, 4096))).is_err());
        assert!(ExecutionAuthorizeOriginalV2::fixed_demand_for_v3(512, 400, Some((256, usize::MAX))).is_err());
    }

    #[test]
    fn actual_specification_cause_precedes_later_content_marker() {
        let mut original = ExecutionAuthorizeOriginalV2::new(
            OperationId::from_bytes([12; 16]), ExecutionId::from_bytes([13; 16]));
        original.frontier = ExecutionAuthorizeFrontierV2::Content;
        original.capture_specification = Some(Err(
            aos_sandbox_controller_domain::controller_execution_spec_attempt::ControllerExecutionSpecAttemptErrorV1::Mismatch));
        original.content = Some(Err(ProtocolValidationError::MissingField("later boundary marker")));
        let pointer = original.capture_specification.as_ref().unwrap().as_ref().unwrap_err()
            as *const aos_sandbox_controller_domain::controller_execution_spec_attempt::ControllerExecutionSpecAttemptErrorV1;
        match original.failure_v2() {
            Some(super::super::execution::ExecutionPublicationCauseV1::Transport(cause)) => {
                let actual = cause.downcast_ref::<aos_sandbox_controller_domain::controller_execution_spec_attempt::ControllerExecutionSpecAttemptErrorV1>().unwrap();
                assert_eq!(actual as *const _, pointer);
            }
            _ => panic!("actual specification cause was replaced"),
        }
    }
    #[test]
    fn forecast_refusal_precedes_later_independently_owed_post() {
        let mut original = ExecutionAuthorizeOriginalV2::new(
            OperationId::from_bytes([12; 16]), ExecutionId::from_bytes([13; 16]));
        original.session_demand = Some(Err(BrokerSessionSecurityError::Currentness));
        original.posts[0] = Some(Box::new(AcceptedSessionPostOriginalV1::default()));
        original.posts[0].as_deref_mut().unwrap().finish =
            Some(Err(BrokerSessionSecurityError::Currentness));
        let pointer = original.session_demand.as_ref().unwrap().as_ref().unwrap_err()
            as *const BrokerSessionSecurityError;
        match original.failure_v2() {
            Some(super::super::execution::ExecutionPublicationCauseV1::Session(cause)) => assert_eq!(cause as *const _, pointer),
            _ => panic!("earlier Session forecast cause was replaced by a later post"),
        }
    }

    #[test]
    fn pure_early_refusal_stays_owned_before_post_failure() {
        let mut original = ExecutionAuthorizeOriginalV2::new(
            OperationId::from_bytes([12; 16]), ExecutionId::from_bytes([13; 16]));
        original.refusal_before_posts = Some(refused("actual earlier arithmetic refusal"));
        original.posts[0] = Some(Box::new(AcceptedSessionPostOriginalV1::default()));
        original.posts[0].as_deref_mut().unwrap().finish =
            Some(Err(BrokerSessionSecurityError::Currentness));
        let pointer = original.refusal_before_posts.as_ref().unwrap() as *const EffectFailure;
        match original.failure_v2() {
            Some(super::super::execution::ExecutionPublicationCauseV1::Effect(cause)) => assert_eq!(cause as *const _, pointer),
            _ => panic!("earlier original refusal was replaced by a later post"),
        }
    }

}
