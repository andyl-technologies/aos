//! Funds one real signed Inventory18 observation on the authorized Recover.
//!
//! The actual completed cold receiver, same Session native opening and source/
//! current-C loan are joined before any request work. The shared native IO,
//! finite two-append window and signed codecs remain the only mechanisms.

use super::*;
use std::error::Error;
use sha2::{Digest as _, Sha256};
use aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_broker_session_protocol::{BrokerSessionProtocolV1, VerifiedBrokerSessionTranscriptV1};
use aos_sandbox_linux::seqpacket::{SeqpacketSocket, StorageSeqpacketSessionOriginV1,
    RecordBindingError, StorageSeqpacketSendAttemptV1, RetainedSeqpacketReceiveErrorV1};
use crate::journal::{JournalError, ProtectedJournalCurrentnessOriginalsV1,
    StorageNativeOpeningOwnerLinkV1, ProtectedJournalPreopenReplayExtentV1};
use crate::journal::inventory_native::{self, io::{IoOriginals, Turn},
    InventoryAppendWindowOriginalV2, InventoryAppendWindowDisposalV2};
use crate::journal::broker_session_receiving::{StorageSessionGeometryRefusalV1,
    protected_session_journal_limits_v1, controller_inventory_append_encoded_bound_v1};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

const DIRECTORY: &str = crate::journal::broker_session_receiving::CONTROLLER_STORAGE_CLIENT_JOURNAL_ROOT_V1;
const METHOD: BrokerMethod = BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES;

#[derive(Clone, Copy, Eq, PartialEq, Default)]
enum Phase {
    #[default]
    Fresh,
    Captured,
    Prepared,
    Sent,
    Decoded,
    Finished,
    Complete,
    Failed,
}

#[derive(Clone, Copy)]
enum First {
    Fixed,
    Original,
    Entropy,
    Binding,
    Before,
    Socket,
    Metadata,
    Materialized,
    Extent,
    Encoded,
    Future,
    Geometry,
    Admission,
    Installation,
    CaptureAfter,
    IoGeometry,
    IoAdmission,
    Io,
    DecodeGeometry,
    DecodeAdmission,
    OutcomeGeometry,
    OutcomeAdmission,
    Predecessor,
    FinalBinding,
    FinalSocket,
    FinalAfter,
    Clock,
    DisposalClock,
    Disposal,
    ExternalSdk,
    Reentry,
}

pub(crate) struct InventoryOriginalsV1 {
    entered: bool,
    retain_cookie_originals: bool,
    socket_native: Option<Result<u64, aos_linux_descriptors::Error>>,
    final_socket_native: Option<Result<u64, aos_linux_descriptors::Error>>,
    borrowed: bool,
    phase: Phase,
    cutoff: u64,
    uid: u32,
    binding: [u8; 32],
    nonce: [u8; 16],
    entropy: Option<Result<usize, rustix::io::Errno>>,
    nonce_comparison: Option<Result<(), JournalError>>,
    shape: Option<crate::DeleteInventorySecurityShapeDataV1>,
    construction_checked: bool,
    first: Option<First>,
    fixed: Option<Result<(), ResourceReservationErrorV1>>,
    original: Option<Result<(), ResourceReservationErrorV1>>,
    binding_result: Option<Result<(), JournalError>>,
    journal: Option<StorageNativeOpeningOwnerLinkV1>,
    socket: Option<Result<StorageSeqpacketSessionOriginV1, RecordBindingError>>,
    before: ProtectedJournalCurrentnessOriginalsV1,
    before_result: Option<Result<(), JournalError>>,
    metadata: Option<std::io::Result<std::fs::Metadata>>,
    materialized: Option<Result<u64, JournalError>>,
    extent: Option<Result<ProtectedJournalPreopenReplayExtentV1, JournalError>>,
    encoded: Option<Result<u64, StorageSessionGeometryRefusalV1>>,
    future: Option<Result<ProtectedJournalPreopenReplayExtentV1, JournalError>>,
    geometry: Option<Result<ResourceVector, JournalError>>,
    admission: Option<Result<(), ResourceReservationErrorV1>>,
    window: InventoryAppendWindowOriginalV2,
    capture_after: ProtectedJournalCurrentnessOriginalsV1,
    capture_after_result: Option<Result<(), JournalError>>,
    io: IoOriginals,
    io_geometry: Option<Result<ResourceVector, JournalError>>,
    io_admission: Option<Result<(), ResourceReservationErrorV1>>,
    io_turn: Option<Turn>,
    decode_geometry: Option<Result<ResourceVector, JournalError>>,
    decode_admission: Option<Result<(), ResourceReservationErrorV1>>,
    outcome_geometry: Option<Result<ResourceVector, JournalError>>,
    outcome_admission: Option<Result<(), ResourceReservationErrorV1>>,
    predecessor: Option<Result<(), JournalError>>,
    final_binding: Option<Result<(), JournalError>>,
    final_socket: Option<Result<(), RecordBindingError>>,
    final_after: ProtectedJournalCurrentnessOriginalsV1,
    final_after_result: Option<Result<(), JournalError>>,
    clock: Option<rustix::time::Timespec>,
    deadline: Option<Result<(), JournalError>>,
    clock_disposal: Option<rustix::time::Timespec>,
    deadline_disposal: Option<Result<(), JournalError>>,
    disposal: Option<Result<(), JournalError>>,
    sdk_refusal: Option<JournalError>,
    reentry: Option<JournalError>,
    completed: bool,
    completed_boundary: Option<(u64, u64, u64, u64)>,
    outcome_request_commitment: Option<[u8; 32]>,
    outcome_body_commitment: Option<[u8; 32]>,
}

impl Default for InventoryOriginalsV1 {
    fn default() -> Self {
        Self { entered: false, retain_cookie_originals: false, socket_native: None,
            final_socket_native: None, borrowed: false, phase: Phase::Fresh, cutoff: 0, uid: 0, binding: [0; 32], nonce: [0; 16], entropy: None, nonce_comparison: None, shape: None, construction_checked: false, first: None,
            fixed: None, original: None, binding_result: None, journal: None, socket: None,
            before: ProtectedJournalCurrentnessOriginalsV1::new(), before_result: None,
            metadata: None, materialized: None, extent: None, encoded: None, future: None, geometry: None,
            admission: None, window: Default::default(), capture_after: ProtectedJournalCurrentnessOriginalsV1::new(),
            capture_after_result: None, io: IoOriginals::new(), io_geometry: None, io_admission: None, io_turn: None,
            decode_geometry: None, decode_admission: None, outcome_geometry: None, outcome_admission: None,
            predecessor: None, final_binding: None, final_socket: None,
            final_after: ProtectedJournalCurrentnessOriginalsV1::new(), final_after_result: None,
            clock: None, deadline: None, clock_disposal: None, deadline_disposal: None, disposal: None, sdk_refusal: None, reentry: None, completed: false,
            completed_boundary: None, outcome_request_commitment: None, outcome_body_commitment: None }
    }
}

impl InventoryOriginalsV1 {
    pub(in crate::controller_resource_reservation)
    fn sdk_failure_is_selected_v2(&self) -> bool {
        matches!(self.first, Some(First::ExternalSdk))
    }

    fn refuse(&mut self) {
        self.reentry.get_or_insert(JournalError::ProtectedBoundary);
        self.first.get_or_insert(First::Reentry);
        self.phase = Phase::Failed;
    }

    pub(crate) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        let Some(first) = self.first else {
            return self.io.failure();
        };
        match first {
            First::Fixed => error(&self.fixed), First::Original => error(&self.original),
            First::Entropy => error(&self.entropy).or_else(|| error(&self.nonce_comparison)),
            First::Binding => error(&self.binding_result),
            First::Before => self.before.failure().or_else(|| error(&self.before_result)),
            First::Socket => error(&self.socket_native).or_else(|| error(&self.socket)), First::Metadata => error(&self.metadata),
            First::Materialized => error(&self.materialized), First::Extent => error(&self.extent),
            First::Encoded => error(&self.encoded), First::Future => error(&self.future),
            First::Geometry => error(&self.geometry), First::Admission => error(&self.admission),
            First::Installation => self.window.failure(),
            First::CaptureAfter => self.capture_after.failure().or_else(|| error(&self.capture_after_result)),
            First::IoGeometry => error(&self.io_geometry), First::IoAdmission => error(&self.io_admission),
            First::Io => self.io.failure(), First::DecodeGeometry => error(&self.decode_geometry),
            First::DecodeAdmission => error(&self.decode_admission), First::OutcomeGeometry => error(&self.outcome_geometry),
            First::OutcomeAdmission => error(&self.outcome_admission), First::Predecessor => error(&self.predecessor),
            First::FinalBinding => error(&self.final_binding), First::FinalSocket => error(&self.final_socket_native).or_else(|| error(&self.final_socket)),
            First::FinalAfter => self.final_after.failure().or_else(|| error(&self.final_after_result)),
            First::Clock => error(&self.deadline), First::DisposalClock => error(&self.deadline_disposal), First::Disposal => error(&self.disposal).or_else(|| self.window.failure()),
            First::ExternalSdk => self.sdk_refusal.as_ref().map(|cause| cause as _),
            First::Reentry => self.reentry.as_ref().map(|cause| cause as _),
        }
    }
}

/// Borrows one finite query from its genuine Recover or reconciliation interval.
///
/// Its constructor is only on the actual authorized loan and checks the same
/// completed native cold original. The private finite source fixes its method,
/// role and receiving provenance; callers select no budget or payer.
#[doc(hidden)]
#[must_use = "retain actual SDK and Recover originals through every independent post"]
pub struct ControllerRecoveryInventoryLoanV2<'query, 'owner, 'controller, 'seed, 'completed> {
    source: RecoveryInventorySourceV2<'query, 'owner, 'controller, 'seed, 'completed>,
}

/// Preserves the existing Inventory18-only Recover native borrower.
pub type OperatorRecoverInventoryLoanV1<'query, 'owner, 'controller> =
    ControllerRecoveryInventoryLoanV2<'query, 'owner, 'controller, 'static, 'static>;

/// Borrows one finite new reconciliation inventory on the same residual.
pub type OperatorReconciliationInventoryLoanV2<'query, 'owner, 'controller, 'seed, 'completed> =
    ControllerRecoveryInventoryLoanV2<'query, 'owner, 'controller, 'seed, 'completed>;

mod reconciliation;
pub(in crate::controller_resource_reservation) use reconciliation::{RecoveryInventorySourceV2, maintenance_method_data_v2 as maintenance_context_v2};

pub(in crate::controller_resource_reservation)
fn reconciliation_inventory_method_v2(
    role: crate::controller_resource_reservation::ControllerReconciliationInventoryRoleV2,
    index: usize,
) -> Result<BrokerMethod, ResourceReservationErrorV1> {
    reconciliation::context_for_role_v2(role, index).map(|context| context.method)
}

impl<'owner, 'controller> OperatorCreateRecoveryLoanV1<'owner, 'controller> {
    /// Admits one fixed Inventory18 on the same genuinely completed cold Session.
    ///
    /// # Errors
    /// Retains authorization, original horizon, financial, foreign native owner
    /// or repeated-entry refusal before any new model or request work.
    #[doc(hidden)]
    pub fn borrow_storage_inventory_once_v1<'query>(&'query mut self,
        receiving: &ControllerInitialBrokerSessionReceivingV1, journal: &Journal,
        shape: crate::DeleteInventorySecurityShapeDataV1,
    ) -> Result<OperatorRecoverInventoryLoanV1<'query, 'owner, 'controller>, ResourceReservationErrorV1> {
        RecoveryInventorySourceV2::Storage(self).begin_query_v2(receiving, journal, shape)
    }
}

impl InventoryOriginalsV1 {
    pub(crate)
    fn is_completed_query_v2(&self) -> bool {
        self.completed && !self.borrowed && self.phase == Phase::Complete
            && self.failure_v1().is_none() && matches!(self.disposal, Some(Ok(())))
            && matches!(self.deadline_disposal, Some(Ok(())))
            && self.completed_boundary.is_some()
            && self.outcome_request_commitment.is_some() && self.outcome_body_commitment.is_some()
    }

    // The caller joins endpoint ordering to this actual positive query's last
    // native sample, rather than a later enclosing Maintenance frontier.
    pub(crate) fn completed_observed_boottime_data_v3(&self)
        -> Result<u64, ResourceReservationErrorV1> {
        if !self.is_completed_query_v2() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let sample = self.clock_disposal.ok_or(ResourceReservationErrorV1::Conflict)?;
        let seconds = u64::try_from(sample.tv_sec)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let nanos = u64::try_from(sample.tv_nsec)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        seconds.checked_mul(1_000_000_000)
            .and_then(|seconds| seconds.checked_add(nanos))
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    // Binding the genuine Root child is forbidden once the final query has
    // entered, even if it has not yet registered a completed receipt.
    pub(crate) fn has_entered_query_v3(&self) -> bool {
        self.entered || self.borrowed
    }

    // The final Source22 proof must join the cutoff captured by the actual
    // native query, rather than relabel a prebinding result with a later D.
    pub(crate) fn require_completed_cutoff_data_v3(&self, expected: u64)
        -> Result<(), ResourceReservationErrorV1> {
        if !self.is_completed_query_v2() || expected == 0 || self.cutoff != expected {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    // This borrows completed historical query identity only. Root independently
    // verifies the exact full signed slot before it can acknowledge metadata.
    pub(in crate::controller_resource_reservation)
    fn require_root_inventory_data_v1(&self, journal: &Journal,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<([u8; 16], [u8; 32]), ResourceReservationErrorV1> {
        self.require_completed_inventory_data_v2(journal, outcome, METHOD, false)
    }

    pub(in crate::controller_resource_reservation)
    fn require_completed_inventory_data_v2(&self, journal: &Journal,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        method: BrokerMethod, retained_prefix: bool,
    ) -> Result<([u8; 16], [u8; 32]), ResourceReservationErrorV1> {
        use aos_sandbox_protocol::authenticated_session::all_methods::{
            AuthenticatedBrokerMethodResultV1,
            AuthenticatedBrokerOutcomeDirectionV1,
            AuthenticatedBrokerRequestDirectionV1,
        };
        let request = outcome.request();
        let body = match outcome.result() {
            AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } => exact_body,
            _ => return Err(ResourceReservationErrorV1::Conflict),
        };
        if !self.completed || self.borrowed || self.phase != Phase::Complete
            || self.failure_v1().is_some()
            || self.journal.as_ref().is_none_or(|held| !held.matches_journal_v1(journal))
            || !matches!(self.disposal, Some(Ok(())))
            || !matches!(self.deadline_disposal, Some(Ok(())))
            || request.request_id() != self.nonce || request.session_binding() != self.binding
            || request.direction() != AuthenticatedBrokerRequestDirectionV1::ClientSend
            || outcome.direction() != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
            || request.method() != method || outcome.method() != method
            || request.authorization().is_some()
            || self.completed_boundary.is_none_or(|(next, _, _, _)|
                if retained_prefix { next >= journal.snapshot_sequence() }
                else { next != journal.snapshot_sequence() })
            || self.outcome_request_commitment != Some(Sha256::digest(request.canonical_packet()).into())
            || self.outcome_body_commitment != Some(Sha256::digest(body).into())
            || request.deadline_boottime_nanoseconds() > self.cutoff
            || !matches!(outcome.result(), AuthenticatedBrokerMethodResultV1::Success { .. }) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok((self.nonce, self.binding))
    }

    // The sibling finite lifecycle payer uses the SAME native query and sole
    // decoded model. This comparison lends no financial or effect authority.
    pub(crate) fn require_completed_inventory_model_v3(
        &self,
        journal: &Journal,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        decoded: &aos_sandbox_protocol::authenticated_session::all_methods::outcome_capture::ControllerInventoryDecodedOriginalV2,
        method: BrokerMethod,
        retained_prefix: bool,
    ) -> Result<([u8; 16], [u8; 32]), ResourceReservationErrorV1> {
        use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodResultV1;
        let coordinates = self.require_completed_inventory_data_v2(journal, outcome, method, retained_prefix)?;
        let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
            return Err(ResourceReservationErrorV1::Conflict);
        };
        if decoded.method_v2() != method
            || matches!(decoded.model_v2(),
                aos_sandbox_protocol::authenticated_session::all_methods::outcome_capture::ControllerInventoryModelDataV2::Host(inventory)
                if !inventory.__buffa_unknown_fields.is_empty())
            || decoded.body_digest_v2() != <[u8; 32]>::from(Sha256::digest(exact_body))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(coordinates)
    }

    pub(in crate::controller_resource_reservation)
    fn completed_query_boundary_v2(&self) -> Option<(u64, u64, u64, u64)> {
        if !self.is_completed_query_v2() { return None; }
        self.completed_boundary
    }
}

// The sibling Source22 lender validates its finite ordinal before this
// private adapter materializes; its actual state and payer stay borrowed
// through the unchanged native query engine.
pub(crate) fn borrow_stop_cleanup_source_inventory_once_v1<'query, 'owner, 'source>(
    source: &'query mut crate::controller_lifecycle_stop::ControllerHostStopCleanupSourceLoanV1<'owner, 'source>,
    controller: &'query mut Journal,
    index: usize,
    receiving: &ControllerInitialBrokerSessionReceivingV1,
    journal: &Journal,
    shape: crate::DeleteInventorySecurityShapeDataV1,
) -> Result<ControllerRecoveryInventoryLoanV2<'query, 'owner, 'source, 'static, 'static>,
    ResourceReservationErrorV1>
{
    source.require_inventory_ordinal_v1(controller, index)?;
    RecoveryInventorySourceV2::StopSource { source, controller, index }
        .begin_query_v2(receiving, journal, shape)
}

impl ControllerRecoveryInventoryLoanV2<'_, '_, '_, '_, '_> {
    fn state(&self) -> &InventoryOriginalsV1 { self.source.state_v2() }
    fn state_mut(&mut self) -> &mut InventoryOriginalsV1 { self.source.state_mut_v2() }

    /// Returns only the fixed method chosen by this actual private native borrower.
    pub fn method_data_v2(&self) -> BrokerMethod { self.source.context_v2().method }

    /// Distinguishes the existing Inventory18-only logical slot from an ordinary role.
    pub fn is_operator_recover_storage_data_v2(&self) -> bool { self.source.context_v2().storage_recover }


    /// Rechecks the exact compiled Security shape already paid at construction.
    ///
    /// # Errors
    /// Refuses a second check or a shape different from the genuine admission.
    #[doc(hidden)]
    pub fn require_security_construction_once_v1(&mut self,
        shape: crate::DeleteInventorySecurityShapeDataV1,
    ) -> Result<(), JournalError> {
        let state = self.state_mut();
        if state.construction_checked || state.shape != Some(shape) || state.first.is_some() {
            state.refuse();
            return Err(JournalError::ProtectedBoundary);
        }
        state.construction_checked = true;
        Ok(())
    }

    /// Borrows the actual kernel-random request ID and original authorized cutoff.
    ///
    /// # Errors
    /// Refuses failed, unpaid, or unjoined native query originals.
    #[doc(hidden)]
    pub fn query_coordinates_v1(&self) -> Result<([u8; 16], u64), JournalError> {
        let state = self.state();
        if state.first.is_some() || !state.construction_checked
            || !matches!(state.nonce_comparison, Some(Ok(()))) || state.cutoff == 0
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok((state.nonce, state.cutoff))
    }

    /// Captures and funds the same native Session and its complete future prefix.
    ///
    /// # Errors
    /// Retains all native/currentness/arithmetic/payment failures; its capture
    /// after is independently owed even if the reached primary refuses.
    #[doc(hidden)]
    pub fn capture_session_once_v1(&mut self, journal: &mut Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), JournalError> {
        if self.state().phase != Phase::Fresh || !self.state().construction_checked || self.state().first.is_some() { self.state_mut().refuse(); return Err(JournalError::ProtectedBoundary); }
        let primary = self.capture_primary(journal, socket, transcript);
        let state = self.state_mut();
        if state.before_result.is_some() {
            state.capture_after_result = Some(journal.observe_held_names_post_retaining_v1(&mut state.capture_after));
            if !matches!(state.capture_after_result, Some(Ok(()))) { state.first.get_or_insert(First::CaptureAfter); }
        }
        if primary.is_ok() && state.first.is_none() { state.phase = Phase::Captured; Ok(()) }
        else { state.phase = Phase::Failed; Err(JournalError::ProtectedBoundary) }
    }

    fn capture_primary(&mut self, journal: &mut Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), JournalError> {
        let context = self.source.context_v2();
        let state = self.state_mut();
        state.binding_result = Some(if context.matches_transcript_v2(transcript)
            && journal.configured_limits() == protected_session_journal_limits_v1()
        { Ok(()) } else { Err(JournalError::ProtectedBoundary) });
        if !matches!(state.binding_result, Some(Ok(()))) { state.first = Some(First::Binding); return Err(JournalError::ProtectedBoundary); }
        state.binding = transcript.session_binding();
        state.before_result = Some(journal.validate_held_owned_at_for_uid_retaining(context.directory, "session.journal", state.uid, &mut state.before));
        if !matches!(state.before_result, Some(Ok(()))) { state.first = Some(First::Before); return Err(JournalError::ProtectedBoundary); }
        state.journal = Some(journal.held_session_owner_link_v1());
        state.socket = Some(if state.retain_cookie_originals {
            socket.capture_storage_session_origin_retaining_v4(&mut state.socket_native)
        } else {
            socket.capture_storage_session_origin_v1()
        });
        if !matches!(state.socket, Some(Ok(_))) { state.first = Some(First::Socket); return Err(JournalError::ProtectedBoundary); }
        let (metadata, limits) = journal.held_native_receiving_metadata_v1();
        state.metadata = Some(metadata);
        let length = match state.metadata.as_ref() { Some(Ok(value)) => value.len(), _ => { state.first = Some(First::Metadata); return Err(JournalError::ProtectedBoundary); } };
        state.materialized = Some(journal.held_materialized_encoding_bytes_v1());
        let materialized = match state.materialized.as_ref() { Some(Ok(value)) => *value, _ => { state.first = Some(First::Materialized); return Err(JournalError::ProtectedBoundary); } };
        state.extent = Some(crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(limits, length.max(materialized)));
        let extent = match state.extent.as_ref() { Some(Ok(value)) => value, _ => { state.first = Some(First::Extent); return Err(JournalError::ProtectedBoundary); } };
        state.encoded = Some(controller_inventory_append_encoded_bound_v1(extent));
        let encoded = match state.encoded.as_ref() { Some(Ok(value)) => *value, _ => { state.first = Some(First::Encoded); return Err(JournalError::ProtectedBoundary); } };
        state.future = Some(extent.native_bytes.checked_add(encoded).ok_or(JournalError::JournalTooLarge)
            .and_then(|future| crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(limits, future)));
        let future = match state.future.as_ref() { Some(Ok(value)) => value, _ => { state.first = Some(First::Future); return Err(JournalError::ProtectedBoundary); } };
        state.geometry = Some(inventory_native::append_geometry_v2(journal, extent, future, encoded, context.method, context.directory));
        let demand = match state.geometry.as_ref() { Some(Ok(value)) => *value, _ => { state.first = Some(First::Geometry); return Err(JournalError::ProtectedBoundary); } };
        let admitted = self.source.reserve_additional_v1(demand);
        let state = self.state_mut();
        state.admission = Some(admitted);
        if !matches!(state.admission, Some(Ok(()))) { state.first = Some(First::Admission); return Err(JournalError::ProtectedBoundary); }
        if state.window.install_prepaid_once_v2(journal, context.directory, state.uid, encoded).is_err() {
            state.first = Some(First::Installation); return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    fn begin_io(&mut self, turn: Turn, phase: Phase, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), JournalError> {
        let context = self.source.context_v2();
        if self.state().first.is_some() || self.state().phase != phase || !self.state().io.is_idle() {
            self.state_mut().refuse(); return Err(JournalError::ProtectedBoundary);
        }
        self.source.require_current_v1().map_err(|_| JournalError::ProtectedBoundary)?;
        let network = match turn { Turn::Send => aos_sandbox_protocol::fixed_controller_inventory_request_packet_bound_v1(),
            Turn::Receive => aos_sandbox_broker_session_protocol::projection::AUTHENTICATED_RESPONSE_MAXIMUM_BYTES,
            _ => 0 };
        self.state_mut().io_geometry = Some(IoOriginals::traffic_demand(context.directory, u64::try_from(network).map_err(|_| JournalError::JournalTooLarge)?, 0));
        let demand = match self.state().io_geometry.as_ref() { Some(Ok(value)) => *value, _ => { self.state_mut().first = Some(First::IoGeometry); return Err(JournalError::ProtectedBoundary); } };
        let admitted = self.source.reserve_additional_v1(demand);
        let state = self.state_mut(); state.io_admission = Some(admitted);
        if !matches!(state.io_admission, Some(Ok(()))) { state.first = Some(First::IoAdmission); return Err(JournalError::ProtectedBoundary); }
        state.io_turn = Some(turn);
        if state.retain_cookie_originals {
            if state.io.retain_cookie_originals_once_v2().is_err() {
                state.first = Some(First::Io);
                return Err(JournalError::ProtectedBoundary);
            }
        }
        if state.io.begin(turn, journal, socket, transcript, state.journal.as_ref().ok_or(JournalError::ProtectedBoundary)?,
            state.socket.as_ref().and_then(|value| value.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)?,
            context.protocol, state.binding, context.method, context.directory, state.uid, state.cutoff).is_err() {
            state.first = Some(First::Io); return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Enters request formation behind the actual paid phase.
    ///
    /// # Errors
    /// Retains a foreign, repeated, expired or unpayable native turn.
    pub fn begin_request_preparation_once(&mut self, j: &Journal, s: &SeqpacketSocket, t: &VerifiedBrokerSessionTranscriptV1) -> Result<(), JournalError> { self.begin_io(Turn::Preparation, Phase::Captured, j, s, t) }

    /// Enters the exact request's send turn.
    ///
    /// # Errors
    /// Retains a foreign, repeated, expired or unpayable native turn.
    pub fn begin_send_once(&mut self, j: &Journal, s: &SeqpacketSocket, t: &VerifiedBrokerSessionTranscriptV1) -> Result<(), JournalError> { self.begin_io(Turn::Send, Phase::Prepared, j, s, t) }

    /// Enters the same sent request's receive turn.
    ///
    /// # Errors
    /// Retains a foreign, repeated, expired or unpayable native turn.
    pub fn begin_receive_once(&mut self, j: &Journal, s: &SeqpacketSocket, t: &VerifiedBrokerSessionTranscriptV1) -> Result<(), JournalError> { self.begin_io(Turn::Receive, Phase::Sent, j, s, t) }

    /// Enters readiness using the same cutoff and real current phase.
    ///
    /// # Errors
    /// Retains a foreign, repeated, expired or unpayable native turn.
    pub fn begin_wait_once(&mut self, j: &Journal, s: &SeqpacketSocket, t: &VerifiedBrokerSessionTranscriptV1, wants_write: bool) -> Result<(), JournalError> {
        self.begin_io(if wants_write { Turn::WaitSend } else { Turn::WaitReceive }, if wants_write { Phase::Prepared } else { Phase::Sent }, j, s, t)
    }

    /// Runs the separately prepaid after without a healthy-C or debit check.
    ///
    /// # Errors
    /// Retains the original native post or deadline refusal.
    pub fn observe_io_post_once(&mut self, j: &Journal, s: &SeqpacketSocket, t: &VerifiedBrokerSessionTranscriptV1) -> Result<(), JournalError> {
        let context = self.source.context_v2();
        let state = self.state_mut();
        let result = state.io.after(j, s, t, state.journal.as_ref().ok_or(JournalError::ProtectedBoundary)?,
            state.socket.as_ref().and_then(|value| value.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)?,
            context.protocol, state.binding, state.cutoff);
        if result.is_err() { state.first.get_or_insert(First::Io); }
        result
    }

    /// Borrows only this authorized original's immutable cutoff.
    ///
    /// # Errors
    /// Refuses a failed or absent native query phase.
    pub fn original_cutoff_data_v1(&self) -> Result<u64, JournalError> {
        if self.state().first.is_some() || self.state().cutoff == 0 { Err(JournalError::ProtectedBoundary) } else { Ok(self.state().cutoff) }
    }

    /// Disposes a successful consumed turn after its actual after observations.
    ///
    /// # Errors
    /// Retains incomplete or late native disposition.
    pub fn finish_positive_io_once(&mut self) -> Result<(), JournalError> {
        let state = self.state_mut();
        let turn = match state.io.positive_turn_v1() {
            Ok(turn) => turn,
            Err(cause) => { state.first.get_or_insert(First::Io); return Err(cause); }
        };
        if let Err(cause) = state.io.complete_consumed_turn_v1() {
            state.first.get_or_insert(First::Io);
            return Err(cause);
        }
        match turn { Turn::Preparation => state.phase = Phase::Prepared, Turn::Send => state.phase = Phase::Sent,
            Turn::Receive => state.phase = Phase::Decoded, Turn::WaitSend | Turn::WaitReceive => {} }
        state.io_turn = None;
        Ok(())
    }

    /// Holds a nonconsuming atomic send through upper raw disposal.
    ///
    /// # Errors
    /// Retains foreign socket, phase, post or deadline refusal.
    pub fn prepare_pending_send_disposal_once<'a>(&'a mut self, receipt: &StorageSeqpacketSendAttemptV1, socket: &SeqpacketSocket)
        -> Result<crate::DeleteInventoryIoDisposalV1<'a>, JournalError> { self.state_mut().io.prepare_send_pending_v1(receipt, socket) }

    /// Holds a nonconsuming receive through upper raw disposal.
    ///
    /// # Errors
    /// Retains consuming receipt, phase, post or deadline refusal.
    pub fn prepare_pending_receive_disposal_once(&mut self, receipt: &RetainedSeqpacketReceiveErrorV1)
        -> Result<crate::DeleteInventoryIoDisposalV1<'_>, JournalError> { self.state_mut().io.prepare_receive_pending_v1(receipt) }

    /// Holds a positive readiness capsule through upper disposal.
    ///
    /// # Errors
    /// Retains phase, post or deadline refusal.
    pub fn prepare_positive_wait_disposal_once(&mut self) -> Result<crate::DeleteInventoryIoDisposalV1<'_>, JournalError> { self.state_mut().io.prepare_wait_positive_v1() }

    /// Admits the reached response before its canonical or typed decoder.
    ///
    /// # Errors
    /// Retains a repeated, failed or unpayable decoder frontier.
    pub fn admit_response_decode_once(&mut self, packet: &[u8]) -> Result<(), JournalError> {
        let context = self.source.context_v2();
        if self.state().phase != Phase::Decoded || self.state().decode_geometry.is_some() || self.state().first.is_some() { self.state_mut().refuse(); return Err(JournalError::ProtectedBoundary); }
        self.state_mut().decode_geometry = Some(aos_sandbox_protocol::authenticated_session::all_methods::outcome_capture::AuthenticatedBrokerMethodOutcomeCaptureV1::controller_inventory_dynamic_receiving_demand_v1(context.method, packet.len()).ok_or(JournalError::JournalTooLarge));
        let demand = match self.state().decode_geometry.as_ref() { Some(Ok(value)) => *value, _ => { self.state_mut().first = Some(First::DecodeGeometry); return Err(JournalError::ProtectedBoundary); } };
        let paid = self.source.reserve_additional_v1(demand); self.state_mut().decode_admission = Some(paid);
        if !matches!(self.state().decode_admission, Some(Ok(()))) { self.state_mut().first = Some(First::DecodeAdmission); return Err(JournalError::ProtectedBoundary); }
        Ok(())
    }

    /// Admits outcome models under the already paid two-append native bound.
    ///
    /// # Errors
    /// Retains a repeated, failed, foreign or unpayable model frontier.
    pub fn admit_outcome_once(&mut self, stored: &[u8], request: &[u8], body: &[u8]) -> Result<(), JournalError> {
        if self.state().phase != Phase::Decoded || !matches!(self.state().decode_admission, Some(Ok(()))) || self.state().outcome_geometry.is_some() { self.state_mut().refuse(); return Err(JournalError::ProtectedBoundary); }
        let state = self.state_mut();
        state.outcome_geometry = Some(crate::journal::broker_session_receiving::outcome_demand(state.extent.as_ref().and_then(|value| value.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)?, stored, request, body)
            .map(|demand| ResourceVector::ZERO.with(D::MemoryBytes, demand.get(D::MemoryBytes))).map_err(|_| JournalError::JournalTooLarge));
        let demand = match state.outcome_geometry.as_ref() { Some(Ok(value)) => *value, _ => { state.first = Some(First::OutcomeGeometry); return Err(JournalError::ProtectedBoundary); } };
        let paid = self.source.reserve_additional_v1(demand); self.state_mut().outcome_admission = Some(paid);
        if !matches!(self.state().outcome_admission, Some(Ok(()))) { self.state_mut().first = Some(First::OutcomeAdmission); return Err(JournalError::ProtectedBoundary); }
        // These are the actual decoder inputs under this paid outcome stage.
        // The later completed borrower must present these SAME request/body
        // bytes, rather than another opaque outcome sharing only an ID.
        self.state_mut().outcome_request_commitment = Some(Sha256::digest(request).into());
        self.state_mut().outcome_body_commitment = Some(Sha256::digest(body).into());
        Ok(())
    }

    /// Checks the exact captured Session before its prepaid terminal replay.
    ///
    /// # Errors
    /// Retains a foreign or incomplete predecessor frontier.
    pub fn admit_retained_predecessor_once(&mut self, journal: &Journal) -> Result<(), JournalError> {
        let state = self.state_mut();
        if state.predecessor.is_some() { state.refuse(); return Err(JournalError::ProtectedBoundary); }
        state.predecessor = Some(if state.first.is_none() && state.phase == Phase::Decoded
            && matches!(state.outcome_admission, Some(Ok(()))) && state.journal.as_ref().is_some_and(|owner| owner.matches_journal_v1(journal))
        { Ok(()) } else { Err(JournalError::ProtectedBoundary) });
        if !matches!(state.predecessor, Some(Ok(()))) { state.first.get_or_insert(First::Predecessor); return Err(JournalError::ProtectedBoundary); }
        Ok(())
    }

    /// Runs the genuine final native after and unchanged absolute deadline.
    ///
    /// # Errors
    /// Retains repeated entry, the earlier primary and all independent afters.
    pub fn finish_native_once_v1(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), JournalError> {
        let context = self.source.context_v2();
        let state = self.state_mut();
        if state.final_binding.is_some() { state.refuse(); return Err(JournalError::ProtectedBoundary); }
        state.window.close_if_owed_v2();
        state.final_binding = Some(if state.journal.as_ref().is_some_and(|owner| owner.matches_journal_v1(journal))
            && transcript.session_binding() == state.binding && context.matches_transcript_v2(transcript)
        { Ok(()) } else { Err(JournalError::ProtectedBoundary) });
        if !matches!(state.final_binding, Some(Ok(()))) { state.first.get_or_insert(First::FinalBinding); }
        if let Some(Ok(origin)) = &state.socket { state.final_socket = Some(if state.retain_cookie_originals {
                origin.require_same_socket_retaining_v4(socket, &mut state.final_socket_native)
            } else {
                origin.require_same_socket(socket)
            });
            if !matches!(state.final_socket, Some(Ok(()))) { state.first.get_or_insert(First::FinalSocket); } }
        if state.before_result.is_some() { state.final_after_result = Some(journal.observe_held_names_post_retaining_v1(&mut state.final_after));
            if !matches!(state.final_after_result, Some(Ok(()))) { state.first.get_or_insert(First::FinalAfter); } }
        state.clock = Some(rustix::time::clock_gettime(rustix::time::ClockId::Boottime));
        state.deadline = Some(crate::journal::inventory_native::io::require_before(state.clock, state.cutoff));
        if !matches!(state.deadline, Some(Ok(()))) { state.first.get_or_insert(First::Clock); }
        if state.first.is_none() { state.phase = Phase::Finished; Ok(()) } else { state.phase = Phase::Failed; Err(JournalError::ProtectedBoundary) }
    }

    /// Holds native completion until actual successful upper scratch disposal.
    ///
    /// # Errors
    /// Retains failed, incomplete, late or unmatched native disposition.
    pub fn prepare_positive_disposal_v1<'a>(&'a mut self, journal: &'a mut Journal)
        -> Result<OperatorRecoverInventoryDisposalV1<'a>, JournalError> {
        let state = self.state_mut();
        if state.disposal.is_some() { state.refuse(); return Err(JournalError::ProtectedBoundary); }
        state.disposal = Some(if state.first.is_none() && state.phase == Phase::Finished && state.io.is_idle()
            && matches!(state.predecessor, Some(Ok(()))) && matches!(state.outcome_admission, Some(Ok(())))
            && state.journal.as_ref().is_some_and(|owner| owner.matches_journal_v1(journal))
        { Ok(()) } else { Err(JournalError::ProtectedBoundary) });
        if !matches!(state.disposal, Some(Ok(()))) { state.first.get_or_insert(First::Disposal); return Err(JournalError::ProtectedBoundary); }
        state.clock_disposal = Some(rustix::time::clock_gettime(rustix::time::ClockId::Boottime));
        state.deadline_disposal = Some(crate::journal::inventory_native::io::require_before(state.clock_disposal, state.cutoff));
        if !matches!(state.deadline_disposal, Some(Ok(()))) {
            state.first.get_or_insert(First::DisposalClock);
            return Err(JournalError::ProtectedBoundary);
        }
        let boundary = match inventory_native::completed_boundary_data_v2(journal, &state.final_after) {
            Some(boundary) => boundary,
            None => {
                state.first.get_or_insert(First::Disposal);
                return Err(JournalError::ProtectedBoundary);
            }
        };
        let native = match state.window.prepare_retirement_v2(journal) {
            Ok(native) => native,
            Err(cause) => { state.first.get_or_insert(First::Disposal); return Err(cause); }
        };
        Ok(OperatorRecoverInventoryDisposalV1 { native, boundary, before: &mut state.before,
            capture_after: &mut state.capture_after, final_after: &mut state.final_after,
            phase: &mut state.phase, completed: &mut state.completed,
            completed_boundary: &mut state.completed_boundary })
    }

    /// Records an external SDK refusal before independently owed native posts.
    #[doc(hidden)]
    pub fn mark_primary_refused_v1(&mut self) {
        self.source.retain_storage_sdk_refusal_once_v1();
        let state = self.state_mut();
        if state.first.is_none() && state.io.failure().is_some() {
            state.first = Some(First::Io);
        }
        state.sdk_refusal.get_or_insert(JournalError::ProtectedBoundary);
        state.first.get_or_insert(First::ExternalSdk);
        state.phase = Phase::Failed;
    }

    /// Borrows this actual native stage's retained first cause.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn Error + 'static)> { self.state().failure_v1() }
}

impl Drop for ControllerRecoveryInventoryLoanV2<'_, '_, '_, '_, '_> {
    fn drop(&mut self) {
        let state = self.state_mut();
        state.borrowed = false;
        if !state.completed { state.refuse(); }
    }
}

/// Keeps the successful native window exclusive through actual upper disposal.
#[doc(hidden)]
#[must_use]
pub struct OperatorRecoverInventoryDisposalV1<'positive> {
    native: InventoryAppendWindowDisposalV2<'positive>,
    boundary: (u64, u64, u64, u64),
    before: &'positive mut ProtectedJournalCurrentnessOriginalsV1,
    capture_after: &'positive mut ProtectedJournalCurrentnessOriginalsV1,
    final_after: &'positive mut ProtectedJournalCurrentnessOriginalsV1,
    phase: &'positive mut Phase,
    completed: &'positive mut bool,
    completed_boundary: &'positive mut Option<(u64, u64, u64, u64)>,
}

impl OperatorRecoverInventoryDisposalV1<'_> {
    /// Returns the actual completed native NEXT/device/inode/end as historical DATA.
    #[must_use]
    pub const fn completed_boundary_data_v2(&self) -> (u64, u64, u64, u64) {
        self.boundary
    }

    /// Completes only after the actual successful upper IO scratch was dropped.
    pub fn complete_after_upper_disposal_v1(self) {
        let Self { native, boundary, before, capture_after, final_after, phase, completed, completed_boundary } = self;
        before.settle_positive_once_v1(); capture_after.settle_positive_once_v1(); final_after.settle_positive_once_v1();
        *phase = Phase::Complete; *completed = true;
        *completed_boundary = Some(boundary);
        native.complete_after_upper_disposal();
    }
}

fn error<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}
