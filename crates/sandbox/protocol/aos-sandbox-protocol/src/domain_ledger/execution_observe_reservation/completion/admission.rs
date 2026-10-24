//! Binds current signed admission-five contents without duplicating the spec.
//!
//! ```text
//! AOSCOC04 | core-length:u32be | registration-length:u32be | selector-length:u32be
//! | exact-private-core | exact-logical-registration-response
//! | selector[Hub lifetime424 for Stream / protected AOSCCA02 for Capture]
//! | SHA256[32]
//! ```
//!
//! The core already retains exact CSI and signed Host packets. The sole
//! admission-five codec reconstructs their exact descriptor contents from
//! those bytes and the selector; Capture also retains its full signed Storage
//! history and immutable protected Source60 anchor.

use aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_model::DecodeLimits;
use aos_sandbox_model::format::{decode_broker_authorization_plan, decode_ownership_lease};
use aos_sandbox_broker_session_protocol::{BrokerSessionDurablePhaseV1, BrokerSessionProtocolV1};
use crate::authenticated_session::all_methods::AuthenticatedBrokerMethodResultV1;
use crate::authenticated_session::historical_method::historical_terminal_outcome;
use crate::authenticated_session::stored_history::{StoredBrokerSessionHistoryV1, canonical_protocol_key_v1};
use crate::controller_capture_admission::ControllerCaptureAdmissionAnchorDataV1;
use crate::storage_output_reserve::continuation::decode_storage_output_registration_response_data_v1;

use aos_sandbox_model::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use crate::host_execution::{HostExecutionSpecContentFieldsV1,
    admission_content::{HostExecutionAdmissionContentV5, MAXIMUM_LOGICAL_REGISTRATION_BYTES_V5}};
use crate::storage_capture_lifetime::{StorageCaptureExecutionLifetimeDataV2,
    STORAGE_CAPTURE_EXECUTION_LIFETIME_BYTES_V2};

use super::{Fields, ObserveCompletionDataErrorV1, invalid};

type Result<T> = std::result::Result<T, ObserveCompletionDataErrorV1>;
const MAGIC: &[u8; 8] = b"AOSCOC04";
const DOMAIN: &[u8] = b"aos.sandbox.controller.execution-observe-completion.v4\0";
pub(super) const WRAPPER_FIXED_BYTES: usize = 8 + 3 * 4 + 32;

#[derive(Clone, Copy)]
pub(super) enum AdmissionSelectorV5<'a> {
    Stream(StorageCaptureExecutionLifetimeDataV2),
    Capture(&'a [u8]),
}

impl<'a> AdmissionSelectorV5<'a> {
    pub(super) fn capture_anchor_v5(self) -> Option<&'a [u8]> {
        match self { Self::Capture(anchor) => Some(anchor), Self::Stream(_) => None }
    }

    pub(super) fn lifetime_v5(self) -> Result<StorageCaptureExecutionLifetimeDataV2> {
        match self {
            Self::Stream(lifetime) => Ok(lifetime),
            Self::Capture(anchor) => {
                let anchor = ControllerCaptureAdmissionAnchorDataV1::decode(anchor).map_err(|_| invalid())?;
                Ok(*anchor.ongoing_source_v2().ok_or_else(invalid)?.lifetime_v2())
            }
        }
    }
}

pub(super) struct AdmissionCompletionSourceV5 {
    pub(super) content: HostExecutionSpecContentFieldsV1,
    pub(super) authority_expires: i64,
    pub(super) monitor_source: ObjectDigest,
    pub(super) monitor_source_kind: u32,
}

pub(super) fn receiving_widths_v5(core: usize, registration: usize, anchor: Option<usize>) -> Option<usize> {
    let selector = anchor.unwrap_or(STORAGE_CAPTURE_EXECUTION_LIFETIME_BYTES_V2);
    if core == 0 || core > super::MAXIMUM_CORE_COMPLETION_BYTES
        || registration == 0 || registration > MAXIMUM_LOGICAL_REGISTRATION_BYTES_V5
        || selector == 0 || selector > crate::controller_capture_admission::MAXIMUM_CAPTURE_ADMISSION_ANCHOR_BYTES_V2
    { return None; }
    WRAPPER_FIXED_BYTES.checked_add(core)?.checked_add(registration)?.checked_add(selector)
}

pub(super) fn encode(core: &[u8], admission: &[u8], anchor: Option<&[u8]>) -> Result<Vec<u8>> {
    let content = HostExecutionAdmissionContentV5::decode(admission).map_err(|_| invalid())?;
    if content.capture_source_v2().is_some() != anchor.is_some() { return Err(invalid()); }
    let selector = match anchor {
        Some(anchor) => anchor,
        None => content.lifetime_v2().canonical_bytes_v2().as_slice(),
    };
    let registration = content.storage_response_bytes();
    let total = receiving_widths_v5(core.len(), registration.len(), anchor.map(<[u8]>::len))
        .ok_or_else(invalid)?;
    if anchor.is_some_and(|bytes| bytes.get(..8) != Some(b"AOSCCA02".as_slice())) {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(total).map_err(|_| invalid())?;
    bytes.extend_from_slice(MAGIC);
    for length in [core.len(), registration.len(), selector.len()] {
        bytes.extend_from_slice(&u32::try_from(length).map_err(|_| invalid())?.to_be_bytes());
    }
    bytes.extend_from_slice(core);
    bytes.extend_from_slice(registration);
    bytes.extend_from_slice(selector);
    let digest = Sha256::new().chain_update(DOMAIN).chain_update(&bytes).finalize();
    bytes.extend_from_slice(&digest);
    Ok(bytes)
}

pub(super) fn split(bytes: &[u8]) -> Result<(&[u8], &[u8], AdmissionSelectorV5<'_>)> {
    if bytes.len() < WRAPPER_FIXED_BYTES || bytes.len() > super::MAXIMUM_COMPLETION_BYTES
        || bytes.get(..8) != Some(MAGIC.as_slice())
    { return Err(invalid()); }
    let width = |at| -> Result<usize> {
        usize::try_from(u32::from_be_bytes(bytes[at..at + 4].try_into()
            .map_err(|_| invalid())?)).map_err(|_| invalid())
    };
    let core_length = width(8)?;
    let registration_length = width(12)?;
    let selector_length = width(16)?;
    let core_end = 20_usize.checked_add(core_length).ok_or_else(invalid)?;
    let registration_end = core_end.checked_add(registration_length).ok_or_else(invalid)?;
    let selector_end = registration_end.checked_add(selector_length).ok_or_else(invalid)?;
    if core_length == 0 || core_length > super::MAXIMUM_CORE_COMPLETION_BYTES
        || registration_length == 0 || registration_length > MAXIMUM_LOGICAL_REGISTRATION_BYTES_V5
        || selector_length == 0
        || selector_length > crate::controller_capture_admission::MAXIMUM_CAPTURE_ADMISSION_ANCHOR_BYTES_V2
        || selector_end.checked_add(32) != Some(bytes.len())
    { return Err(invalid()); }
    let digest = Sha256::new().chain_update(DOMAIN).chain_update(&bytes[..selector_end]).finalize();
    if digest[..] != bytes[selector_end..] { return Err(invalid()); }
    let selector = &bytes[registration_end..selector_end];
    let selector = match selector.get(..8) {
        Some(b"AOSCLF02") if selector.len() == STORAGE_CAPTURE_EXECUTION_LIFETIME_BYTES_V2 =>
            AdmissionSelectorV5::Stream(StorageCaptureExecutionLifetimeDataV2::from_canonical_bytes_v2(selector)
                .map_err(|_| invalid())?),
        Some(b"AOSCCA02") => AdmissionSelectorV5::Capture(selector),
        _ => return Err(invalid()),
    };
    Ok((&bytes[20..core_end], &bytes[core_end..registration_end], selector))
}

pub(super) fn reconstruct_content_v5(
    fields: &Fields<'_>, registration: &[u8], selector: AdmissionSelectorV5<'_>,
) -> Result<Vec<u8>> {
    match selector {
        AdmissionSelectorV5::Stream(lifetime) =>
            HostExecutionAdmissionContentV5::new_stream_v5(fields.specification, registration, &lifetime)
                .and_then(HostExecutionAdmissionContentV5::encode).map_err(|_| invalid()),
        AdmissionSelectorV5::Capture(bytes) => {
            let anchor = ControllerCaptureAdmissionAnchorDataV1::decode(bytes).map_err(|_| invalid())?;
            HostExecutionAdmissionContentV5::new_capture_v5(fields.specification, registration,
                anchor.ongoing_source_v2().ok_or_else(invalid)?, anchor.response_bytes_v1())
                .and_then(HostExecutionAdmissionContentV5::encode).map_err(|_| invalid())
        }
    }
}

pub(super) fn validate_source(fields: &Fields<'_>, registration: &[u8], selector: AdmissionSelectorV5<'_>,
    authorize: &AuthenticatedBrokerMethodOutcomeV1, expected_assignment: aos_sandbox_model::BrokerAssignment,
    expected_node: aos_sandbox_model::NodeId) -> Result<AdmissionCompletionSourceV5>
{
    let encoded = reconstruct_content_v5(fields, registration, selector)?;
    let content = HostExecutionAdmissionContentV5::decode(&encoded).map_err(|_| invalid())?;
    if content.attempt_bytes() != fields.specification
        || content.lifetime_v2().assignment_v2() != expected_assignment
    { return Err(invalid()); }
    let authority = authorize.request().authorization().ok_or_else(invalid)?;
    let lease = decode_ownership_lease(authority.ownership_lease(), DecodeLimits::default())
        .map_err(|_| invalid())?;
    let media_type = aos_sandbox_model::MediaType::new(
        aos_sandbox_model::PortableMediaType::OwnershipLease.as_str().to_owned())
        .map_err(|_| invalid())?;
    let lease_digest = aos_sandbox_model::descriptor_for_bytes(media_type,
        authority.ownership_lease()).digest();
    content.lifetime_v2().require_original_lease_data_v2(lease_digest,
        lease.lease_generation(), lease.authority_expires_seconds(),
        lease.maximum_clock_skew_seconds()).map_err(|_| invalid())?;
    let authority_expires = match (content.capture_source_v2(), selector) {
        (None, AdmissionSelectorV5::Stream(_)) => i64::MAX,
        (Some(source), AdmissionSelectorV5::Capture(anchor)) => validate_capture_source_v5(
            fields, anchor, &content, source, expected_assignment, expected_node)?,
        _ => return Err(invalid()),
    };
    Ok(AdmissionCompletionSourceV5 {
        content: HostExecutionSpecContentFieldsV1::for_grant(&encoded), authority_expires,
        monitor_source: content.capture_source_v2().map_or_else(
            || content.lifetime_v2().digest_v2(), |source| source.source_digest_v2()),
        monitor_source_kind: if content.capture_source_v2().is_some() { 2 } else { 1 },
    })
}


fn validate_capture_source_v5(fields: &Fields<'_>, bytes: &[u8],
    content: &HostExecutionAdmissionContentV5<'_>,
    expected_source: &crate::storage_capture_grant::StorageCaptureGrantSourceV2,
    expected_assignment: aos_sandbox_model::BrokerAssignment,
    expected_node: aos_sandbox_model::NodeId) -> Result<i64>
{
    let anchor = ControllerCaptureAdmissionAnchorDataV1::decode(bytes).map_err(|_| invalid())?;
    let source = anchor.source_v1();
    let ongoing = anchor.ongoing_source_v2().ok_or_else(invalid)?;
    if ongoing.canonical_bytes_v2() != expected_source.canonical_bytes_v2()
        || anchor.response_bytes_v1() != content.capture_response_bytes_v5()
    { return Err(invalid()); }
    let attempt = crate::storage_capture_grant::decode_storage_capture_attempt_response_ongoing_v2(
        anchor.response_bytes_v1(), ongoing, false).map_err(|_| invalid())?;
    let effect_cutoff = attempt.effective_deadline_boottime_nanoseconds().ok_or_else(invalid)?;
    if fields.cutoff > effect_cutoff || fields.boottime >= effect_cutoff
        || source.host_boot_id() != fields.host_boot
        || fields.cutoff > source.original_deadline_boottime_nanoseconds()
        || fields.boottime >= source.original_deadline_boottime_nanoseconds()
    { return Err(invalid()); }
    let stored = StoredBrokerSessionHistoryV1::decode(
        &canonical_protocol_key_v1(BrokerSessionProtocolV1::Storage), anchor.storage_history_bytes_v1())
        .map_err(|_| invalid())?;
    let checkpoint = stored.checkpoint.as_ref().ok_or_else(invalid)?;
    let transcript = checkpoint.verify().map_err(|_| invalid())?;
    let history = stored.history_model().map_err(|_| invalid())?;
    let records = history.records();
    let last = records.len().checked_sub(1).ok_or_else(invalid)?;
    let reserve = historical_terminal_outcome(records, last, checkpoint, &transcript).map_err(|_| invalid())?;
    // The sole anchor codec verifies this signed60 source, request and response.
    // Reuse the same historical engine for its authority and earlier output row.
    let authority = reserve.request().authorization().ok_or_else(invalid)?;
    let plan = decode_broker_authorization_plan(authority.broker_plan(), DecodeLimits::default()).map_err(|_| invalid())?;
    let lease = decode_ownership_lease(authority.ownership_lease(), DecodeLimits::default()).map_err(|_| invalid())?;
    let authority_expires = plan.expires_seconds().min(lease.authority_expires_seconds());
    let expected_lease_assignment = aos_sandbox_model::LeaseAssignment::new(
        expected_assignment.sandbox(), expected_assignment.incarnation(),
        expected_assignment.epoch(), expected_assignment.digest(),
    ).map_err(|_| invalid())?;
    if fields.wall < plan.issued_seconds() || fields.wall < lease.authority_issued_seconds()
        || fields.wall >= authority_expires
        || plan.assignment() != expected_assignment || plan.node() != expected_node
        || lease.assignment() != expected_lease_assignment || lease.node() != expected_node
    { return Err(invalid()); }
    // Select the exact real response committed by the signed Host admission;
    // never reconstruct it from a desired row, digest or supposed native result.
    for (index, record) in records[..last].iter().enumerate() {
        if record.phase() != BrokerSessionDurablePhaseV1::Terminal
            || record.method() != BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT
        { continue; }
        let outcome = historical_terminal_outcome(records, index, checkpoint, &transcript).map_err(|_| invalid())?;
        let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result()
            else { return Err(invalid()); };
        let registration = decode_storage_output_registration_response_data_v1(exact_body).map_err(|_| invalid())?;
        if Sha256::digest(&registration.canonical_reservation).as_slice()
            != source.output_record_digest().as_bytes()
        { continue; }
        if exact_body == content.storage_response_bytes() {
            return Ok(authority_expires);
        }
    }
    Err(invalid())
}
