//! Complete signed historical DATA for one reserved first-Observe completion.
//!
//! ```text
//! AOSCOC04 | core-length:u32BE | registration-length:u32BE | selector-length:u32BE |
//! private-core | exact-registration | lifetime424-or-protected-Capture-anchor | SHA256:32
//! ```
//!
//! The private core retains the complete CSI, CAF and signed Host Session.
//! The caller must compare CSI, CAF and any Capture anchor with the actual
//! protected Controller rows. A self-selected historical checkpoint is not a
//! source pin. The sole admission-five codec reconstructs the signed descriptor
//! from those originals without retaining another full specification.

mod admission;

use aos_proto::aos::sandbox::local::v1::{ApplyHostExecutionRequestV1, BrokerMethod,
    HostExecutionActionV1, HostExecutionCompletionStatusV1, HostExecutionPhaseV1};
use aos_sandbox_core::{DecodeLimits, ObjectDigest, RawPairedClockSample};
use aos_sandbox_core::format::{decode_broker_authorization_plan, decode_ownership_lease};
use aos_sandbox_core::runtime_backend::BackendExecutionPhaseV1;
use aos_sandbox_broker_session_protocol::{BrokerSessionProtocolV1,
    BrokerSessionDurableEndpointV1, BrokerSessionDurablePhaseV1,
    BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_BYTES};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};
use super::ControllerExecutionObserveReservationV1;
use crate::authenticated_session::all_methods::{AuthenticatedBrokerMethodOutcomeV1,
    AuthenticatedBrokerMethodResultV1};
use crate::authenticated_session::historical_method::historical_terminal_outcome;
use crate::authenticated_session::stored_history::{StoredBrokerSessionHistoryV1, canonical_protocol_key_v1};
use crate::execution_argument_receipt::ControllerArgumentReceiptDataV1;
use crate::execution_evidence::{controller_execution_receipt_v1,
    decode_authorize_completion_binding_v1, decode_observe_completion_phase_v1};
use crate::execution_spec_attempt::ExecutionSpecAttemptFieldsV1;
use crate::host_execution::{decode_host_execution_outcome_v1,
    decode_host_execution_terminal_result_v1, HostExecutionTerminalResultV1};

/// Supplies synthetic signed historical DATA for dependent crate tests only.
#[cfg(any(test, feature = "test-fixtures"))]
pub mod fixture;

const MAGIC: &[u8; 8] = b"AOSCOC01";
const DOMAIN: &[u8] = b"aos.sandbox.controller.execution-observe-completion.v1\0";
const FIXED: usize = 8 + 3 * 4 + 16 + 3 * 8 + 32;
/// Bounds the entire companion using the original complete source codecs.
const MAXIMUM_CORE_COMPLETION_BYTES: usize = FIXED
    + crate::execution_spec_attempt::MAXIMUM_RECORD_BYTES
    + crate::execution_argument_receipt::MAXIMUM_RECORD_BYTES
    + crate::authenticated_session::stored_history::VALUE_FIXED_BYTES_V3
    + BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_BYTES
    + crate::authenticated_session::historical_checkpoint::MAXIMUM_BYTES;

/// Bounds the complete current Stream or Capture completion companion.
pub const MAXIMUM_COMPLETION_BYTES: usize = MAXIMUM_CORE_COMPLETION_BYTES
    + admission::WRAPPER_FIXED_BYTES
    + crate::host_execution::admission_content::MAXIMUM_LOGICAL_REGISTRATION_BYTES_V5
    + crate::controller_capture_admission::MAXIMUM_CAPTURE_ADMISSION_ANCHOR_BYTES_V2;

/// Reports inconsistent or unauthentic reserved Observe completion DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ObserveCompletionDataErrorV1 {
    /// A complete original, signed packet, exact binding or lifetime disagrees.
    #[error("invalid completed reserved execution Observe evidence")]
    Invalid,
}

/// Retains exact completed-child DATA without dispatch or currentness authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObserveChildCompletionDataV1 {
    bytes: Vec<u8>,
    authority_expires_seconds: i64,
    monitor: crate::host_execution::monitor::HostExecutionMonitorSelectorV3,
    monitor_content: crate::host_execution::HostExecutionSpecContentFieldsV1,
}

/// Borrows the exact protected source joins required by the native cold owner.
pub struct ObserveChildCompletionSourcesV1<'row> {
    /// Exact AOSCSI01 row that must still equal the protected Controller row.
    pub specification: &'row [u8],
    /// Exact AOSCAF01 row that must still equal the protected Controller row.
    pub argument_receipt: &'row [u8],
    /// Exact immutable Capture60 anchor; the native owner must compare its
    /// ControllerStorageCaptureAdmission row under the same execution key.
    pub capture_admission_anchor: Option<&'row [u8]>,
    /// Exact logical response used by the same signed admission-five codec.
    pub registration_response: &'row [u8],
    /// Complete original lifetime comparison DATA, without native authority.
    pub lifetime: crate::storage_capture_lifetime::StorageCaptureExecutionLifetimeDataV2,
    /// Original host boot bound at this completion boundary.
    pub host_boot: [u8; 16],
    /// Original positive-use cutoff, never a renewed challenge deadline.
    pub cutoff: u64,
    /// Earliest original signed Authorize/Observe plan or lease expiry.
    pub authority_expires_seconds: i64,
}

impl ObserveChildCompletionDataV1 {
    /// Prices exact current framing from the real retained input widths.
    ///
    /// The private encoder uses the same recipe. This is passive receiving
    /// geometry and supplies no admission, native source or completion grant.
    #[must_use]
    pub fn receiving_widths_v5(
        specification: usize, argument_receipt: usize, session: usize,
        registration: usize, capture_anchor: Option<usize>,
    ) -> Option<usize> {
        let core = FIXED.checked_add(specification)?.checked_add(argument_receipt)?.checked_add(session)?;
        admission::receiving_widths_v5(core, registration, capture_anchor)
    }

    /// Constructs the current companion from exact signed admission contents.
    ///
    /// # Errors
    /// Rejects canonical content, protected spec/source, signed history, receipt,
    /// original cutoff, plan/lease or first-Observe identity mismatch.
    pub fn new_lifetime_v5(
        reservation: &ControllerExecutionObserveReservationV1,
        specification: &[u8], argument_receipt: &[u8], session: &[u8],
        admission_content: &[u8], capture_anchor: Option<&[u8]>,
        sample: RawPairedClockSample, cutoff: u64, receipt: &[u8],
    ) -> Result<Self, ObserveCompletionDataErrorV1> {
        let core = encode_core(specification, argument_receipt, session, sample, cutoff)?;
        let wrapped = admission::encode(&core, admission_content, capture_anchor)?;
        Self::decode(reservation, receipt, &wrapped)
    }

    /// Decodes and completely validates original signed historical completion DATA.
    ///
    /// # Errors
    /// Rejects malformed framing, complete prior traffic or any exact signed
    /// request/outcome, protected source, receipt, lease or lifetime mismatch.
    pub fn decode(reservation: &ControllerExecutionObserveReservationV1, receipt: &[u8], bytes: &[u8])
        -> Result<Self, ObserveCompletionDataErrorV1>
    {
        let (core, registration, selector) = admission::split(bytes)?;
        let validated = validate(reservation, receipt, core, registration, selector)?;
        Ok(Self { bytes: bytes.to_vec(), authority_expires_seconds: validated.expires,
            monitor: validated.monitor, monitor_content: validated.content })
    }

    /// Borrows the complete exact canonical companion bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] { &self.bytes }

    /// Returns fixed monitor selectors from the same fully validated history.
    ///
    /// These identifiers grant no native read, dispatch or terminal authority.
    #[must_use]
    pub const fn monitor_selector_v4(&self) -> crate::host_execution::monitor::HostExecutionMonitorSelectorV3 {
        self.monitor
    }

    /// Returns the original admission-five content commitment for Query3.
    ///
    /// The same complete signed-history validation derived these fields. They
    /// convey no descriptor, live native hold or permission to repeat Apply.
    #[must_use]
    pub const fn monitor_content_v4(&self) -> crate::host_execution::HostExecutionSpecContentFieldsV1 {
        self.monitor_content
    }

    /// Borrows independently matched source rows after the same full validation.
    ///
    /// # Errors
    /// Rejects any contradiction in the complete retained companion.
    pub fn sources(&self) -> Result<ObserveChildCompletionSourcesV1<'_>, ObserveCompletionDataErrorV1> {
        let (core, registration_response, selector) = admission::split(&self.bytes)?;
        let capture_admission_anchor = selector.capture_anchor_v5();
        let lifetime = selector.lifetime_v5()?;
        let fields = split(core)?;
        Ok(ObserveChildCompletionSourcesV1 { specification: fields.specification,
            argument_receipt: fields.argument_receipt, capture_admission_anchor, registration_response, lifetime,
            host_boot: fields.host_boot, cutoff: fields.cutoff,
            authority_expires_seconds: self.authority_expires_seconds })
    }
}

fn encode_core(specification: &[u8], argument_receipt: &[u8], session: &[u8],
    sample: RawPairedClockSample, cutoff: u64) -> Result<Vec<u8>, ObserveCompletionDataErrorV1>
{
    let lengths = [specification.len(), argument_receipt.len(), session.len()];
    let size = lengths.into_iter().try_fold(FIXED, usize::checked_add).ok_or(invalid())?;
    if size > MAXIMUM_CORE_COMPLETION_BYTES { return Err(invalid()); }
    let mut bytes = Vec::with_capacity(size);
    bytes.extend_from_slice(MAGIC);
    for length in lengths {
        bytes.extend_from_slice(&u32::try_from(length).map_err(|_| invalid())?.to_be_bytes());
    }
    bytes.extend_from_slice(&sample.host_boot_id());
    bytes.extend_from_slice(&sample.wall_seconds().to_be_bytes());
    bytes.extend_from_slice(&sample.boottime_nanoseconds().to_be_bytes());
    bytes.extend_from_slice(&cutoff.to_be_bytes());
    bytes.extend_from_slice(specification);
    bytes.extend_from_slice(argument_receipt);
    bytes.extend_from_slice(session);
    let checksum = Sha256::new().chain_update(DOMAIN).chain_update(&bytes).finalize();
    bytes.extend_from_slice(&checksum);
    Ok(bytes)
}

struct Fields<'a> {
    specification: &'a [u8], argument_receipt: &'a [u8], session: &'a [u8],
    host_boot: [u8; 16], wall: i64, boottime: u64, cutoff: u64,
}

fn invalid() -> ObserveCompletionDataErrorV1 { ObserveCompletionDataErrorV1::Invalid }

fn split(bytes: &[u8]) -> Result<Fields<'_>, ObserveCompletionDataErrorV1> {
    if bytes.len() < FIXED || bytes.len() > MAXIMUM_CORE_COMPLETION_BYTES
        || bytes.get(..8) != Some(MAGIC.as_slice()) { return Err(invalid()); }
    let checksum_at = bytes.len() - 32;
    if Sha256::new().chain_update(DOMAIN).chain_update(&bytes[..checksum_at]).finalize()[..]
        != bytes[checksum_at..] { return Err(invalid()); }
    let mut at = 8;
    fn array<const N: usize>(bytes: &[u8], at: &mut usize) -> Result<[u8; N], ObserveCompletionDataErrorV1> {
        let end = at.checked_add(N).ok_or(invalid())?;
        let value = bytes.get(*at..end).ok_or(invalid())?.try_into().map_err(|_| invalid())?;
        *at = end;
        Ok(value)
    }
    let spec = u32::from_be_bytes(array(bytes, &mut at)?) as usize;
    let caf = u32::from_be_bytes(array(bytes, &mut at)?) as usize;
    let session = u32::from_be_bytes(array(bytes, &mut at)?) as usize;
    let host_boot = array(bytes, &mut at)?;
    let wall = i64::from_be_bytes(array(bytes, &mut at)?);
    let boottime = u64::from_be_bytes(array(bytes, &mut at)?);
    let cutoff = u64::from_be_bytes(array(bytes, &mut at)?);
    let spec_end = at.checked_add(spec).ok_or(invalid())?;
    let caf_end = spec_end.checked_add(caf).ok_or(invalid())?;
    let session_end = caf_end.checked_add(session).ok_or(invalid())?;
    if session_end != checksum_at { return Err(invalid()); }
    Ok(Fields { specification: bytes.get(at..spec_end).ok_or(invalid())?,
        argument_receipt: bytes.get(spec_end..caf_end).ok_or(invalid())?,
        session: bytes.get(caf_end..session_end).ok_or(invalid())?, host_boot, wall, boottime, cutoff })
}

struct ValidatedCompletionV4 {
    expires: i64,
    monitor: crate::host_execution::monitor::HostExecutionMonitorSelectorV3,
    content: crate::host_execution::HostExecutionSpecContentFieldsV1,
}

struct ValidatedTurnV4 {
    expires: i64,
    runtime: Option<ObjectDigest>,
}

fn validate(reservation: &ControllerExecutionObserveReservationV1, receipt: &[u8], bytes: &[u8], registration: &[u8], selector: admission::AdmissionSelectorV5<'_>)
    -> Result<ValidatedCompletionV4, ObserveCompletionDataErrorV1>
{
    let fields = split(bytes)?;
    if fields.host_boot == [0; 16] || fields.cutoff == 0 || fields.boottime >= fields.cutoff { return Err(invalid()); }
    let spec = ExecutionSpecAttemptFieldsV1::decode(fields.specification).map_err(|_| invalid())?;
    let canonical_specification = spec.decoded_specification().map_err(|_| invalid())?;
    let assignment = canonical_specification.resources().output_bytes().assignment();
    let expected_assignment = assignment.broker_assignment().map_err(|_| invalid())?;
    let expected_node = assignment.manifest().node();
    let caf = ControllerArgumentReceiptDataV1::decode(fields.argument_receipt).map_err(|_| invalid())?;
    if spec.execution != reservation.execution() || spec.create_operation != reservation.create_operation()
        || spec.specification_digest != reservation.specification_digest()
        || caf.execution != spec.execution || caf.create_operation != spec.create_operation
        || caf.record_digest != spec.source_heads.argument_receipt { return Err(invalid()); }
    let stored = StoredBrokerSessionHistoryV1::decode(&canonical_protocol_key_v1(BrokerSessionProtocolV1::Host), fields.session)
        .map_err(|_| invalid())?;
    if stored.protocol != BrokerSessionProtocolV1::Host || stored.endpoint != BrokerSessionDurableEndpointV1::Client {
        return Err(invalid());
    }
    let checkpoint = stored.checkpoint.as_ref().ok_or(invalid())?;
    let transcript = checkpoint.verify().map_err(|_| invalid())?;
    let history = stored.history_model().map_err(|_| invalid())?;
    let records = history.records();
    let last = records.len().checked_sub(1).ok_or(invalid())?;
    let authorize_at = last.checked_sub(2).ok_or(invalid())?;
    let mut pinned59 = false;
    for record in records.get(..authorize_at.checked_sub(1).ok_or(invalid())?).ok_or(invalid())? {
        if record.phase() == BrokerSessionDurablePhaseV1::Terminal
            && record.method() == BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2
            && record.outcome_packet().is_some_and(|packet| Sha256::digest(packet)[..] == caf.outcome_packet_digest.as_bytes()[..])
            && Sha256::digest(record.request_packet())[..] == caf.request_packet_digest.as_bytes()[..]
        {
            if pinned59 { return Err(invalid()); }
            pinned59 = true;
        }
    }
    if !pinned59 { return Err(invalid()); }
    let authorize = historical_terminal_outcome(records, authorize_at, checkpoint, &transcript).map_err(|_| invalid())?;
    let observe = historical_terminal_outcome(records, last, checkpoint, &transcript).map_err(|_| invalid())?;
    let authorizing = authorize.request().authorization().ok_or(invalid())?;
    let observing = observe.request().authorization().ok_or(invalid())?;
    if authorize.request().session_binding() != observe.request().session_binding()
        || authorize.request().client_sequence().checked_add(1) != Some(observe.request().client_sequence())
        || authorize.broker_sequence().checked_add(1) != Some(observe.broker_sequence())
        || authorizing.ownership_lease() != observing.ownership_lease()
        || authorizing.ownership_lease_signature() != observing.ownership_lease_signature()
    { return Err(invalid()); }
    let admission_source = admission::validate_source(&fields, registration, selector,
        &authorize, expected_assignment, expected_node)?;
    let authorize_expires = validate_turn(reservation, &authorize, true, fields.wall, fields.cutoff,
        reservation.authorization_receipt(), expected_assignment, expected_node, Some(&admission_source))?;
    let observe_expires = validate_turn(reservation, &observe, false, fields.wall, fields.cutoff, receipt, expected_assignment, expected_node, None)?;
    let first_observe = aos_sandbox_core::runtime_backend::BackendOperationIdV1::new(
        *reservation.observe_operation().as_bytes()).map_err(|_| invalid())?;
    let monitor = crate::host_execution::monitor::HostExecutionMonitorSelectorV3::new(
        observe_expires.runtime.ok_or_else(invalid)?, first_observe,
        admission_source.monitor_source, admission_source.monitor_source_kind)
        .map_err(|_| invalid())?;
    Ok(ValidatedCompletionV4 { expires: authorize_expires.expires.min(observe_expires.expires)
        .min(admission_source.authority_expires), monitor, content: admission_source.content })
}

fn validate_turn(reservation: &ControllerExecutionObserveReservationV1,
    outcome: &AuthenticatedBrokerMethodOutcomeV1, authorize: bool, wall: i64, cutoff: u64, receipt: &[u8], expected_assignment: aos_sandbox_core::BrokerAssignment, expected_node: aos_sandbox_core::NodeId, physical: Option<&admission::AdmissionCompletionSourceV5>)
    -> Result<ValidatedTurnV4, ObserveCompletionDataErrorV1>
{
    let operation = if authorize { reservation.create_operation() } else { reservation.observe_operation() };
    let expected_action = if authorize { HostExecutionActionV1::HOST_EXECUTION_ACTION_AUTHORIZE }
        else { HostExecutionActionV1::HOST_EXECUTION_ACTION_OBSERVE };
    if outcome.method() != BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION { return Err(invalid()); }
    let request = outcome.request();
    let apply = ApplyHostExecutionRequestV1::decode_from_slice(request.exact_body()).map_err(|_| invalid())?;
    if apply.operation_id != operation.as_bytes() || apply.execution_id != reservation.execution().as_bytes()
        || apply.source_operation_commitment != reservation.source_operation_commitment()
        || apply.action.as_known() != Some(expected_action)
        || apply.spec_transfer_version != if authorize { 5 } else { 1 }
        || request.deadline_boottime_nanoseconds() < cutoff { return Err(invalid()); }
    if let Some(physical) = physical {
        let bind = crate::host_execution::HostExecutionSpecContentFieldsV1::bind_lifetime_admission_attempt_v5;
        let fields = bind(physical.content, request.request_id(),
            *operation.as_bytes(), reservation.execution(),
            ObjectDigest::from_bytes(reservation.source_operation_commitment()));
        if apply.spec_content_bytes != fields.bytes() || apply.spec_content_digest.as_slice() != fields.digest().as_slice()
            || apply.spec_attempt_commitment.as_slice() != fields.attempt_commitment().as_slice()
            || !apply.canonical_execution_spec.is_empty()
        { return Err(invalid()); }
    }
    let authority = request.authorization().ok_or(invalid())?;
    let plan = decode_broker_authorization_plan(authority.broker_plan(), DecodeLimits::default()).map_err(|_| invalid())?;
    let lease = decode_ownership_lease(authority.ownership_lease(), DecodeLimits::default()).map_err(|_| invalid())?;
    if wall < plan.issued_seconds() || wall >= plan.expires_seconds()
        || wall < lease.authority_issued_seconds() || wall >= lease.authority_expires_seconds()
        || plan.assignment().sandbox() != lease.assignment().sandbox()
        || plan.assignment().incarnation() != lease.assignment().incarnation()
        || plan.assignment().epoch() != lease.assignment().epoch()
        || plan.assignment().digest() != lease.assignment().digest()
        || plan.node() != lease.node()
        || plan.assignment() != expected_assignment
        || plan.node() != expected_node { return Err(invalid()); }
    let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else { return Err(invalid()); };
    let body = decode_host_execution_outcome_v1(exact_body, *operation.as_bytes(), reservation.execution(),
        ObjectDigest::from_bytes(reservation.source_operation_commitment())).map_err(|_| invalid())?;
    if body.phase.as_known() != Some(HostExecutionPhaseV1::HOST_EXECUTION_PHASE_COMPLETE)
        || body.completion_status.as_known() != Some(HostExecutionCompletionStatusV1::HOST_EXECUTION_COMPLETION_STATUS_SUCCEEDED)
        { return Err(invalid()); }
    let (phase, runtime) = if authorize {
        (decode_authorize_completion_binding_v1(&body.completion_bytes, *operation.as_bytes(),
            reservation.source_operation_commitment(), *reservation.execution().as_bytes(),
            reservation.specification_digest(), body.observation_sequence).map_err(|_| invalid())?, None)
    } else {
        let observed = crate::execution_evidence::decode_observe_completion_evidence_v1(&body.completion_bytes, *operation.as_bytes(),
            reservation.source_operation_commitment(), *reservation.execution().as_bytes(),
            reservation.specification_digest(), body.observation_sequence).map_err(|_| invalid())?;
        (observed.phase(), Some(observed.runtime_v4()))
    };
    let terminal = match (authorize, phase) {
        (true, BackendExecutionPhaseV1::Authorized | BackendExecutionPhaseV1::Running) => None,
        (false, BackendExecutionPhaseV1::Running) if body.terminal_guest_result.is_empty() => None,
        (false, BackendExecutionPhaseV1::Exited | BackendExecutionPhaseV1::Canceled) => {
            let terminal = decode_host_execution_terminal_result_v1(&body.terminal_guest_result).map_err(|_| invalid())?;
            if !matches!((phase, terminal),
                (BackendExecutionPhaseV1::Exited, HostExecutionTerminalResultV1::Exited(_))
                | (BackendExecutionPhaseV1::Canceled, HostExecutionTerminalResultV1::Canceled)
                | (BackendExecutionPhaseV1::Exited, HostExecutionTerminalResultV1::Original { canceled: false, .. })
                | (BackendExecutionPhaseV1::Canceled, HostExecutionTerminalResultV1::Original { canceled: true, .. })) { return Err(invalid()); }
            Some(body.terminal_guest_result.as_slice())
        }
        _ => return Err(invalid()),
    };
    let computed = controller_execution_receipt_v1(operation.as_bytes(), *reservation.execution().as_bytes(),
        reservation.source_operation_commitment(), body.effect_commitment.as_slice().try_into().map_err(|_| invalid())?,
        body.completion_digest.as_slice().try_into().map_err(|_| invalid())?, body.observation_sequence,
        &body.completion_bytes, terminal);
    if computed.as_slice() != receipt { return Err(invalid()); }
    Ok(ValidatedTurnV4 { expires: plan.expires_seconds().min(lease.authority_expires_seconds()), runtime })
}
