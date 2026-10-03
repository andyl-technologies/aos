//! Complete original Host histories and independent Root historical joins.
//!
//! ```text
//! AOSCFH04 | version:u16be=4 | reserved:u16be=0 |
//! original-length:u32be | terminal-length:u32be |
//! complete AOSHAR01 frame | complete AOSHTA01 frame |
//! SHA256(original-histories.v4 domain || preceding):32
//! ```
//!
//! The complete carrier is bounded before allocation. Its public codec checks
//! framing only. The private verifier independently joins the genuine Root's
//! fixed manifest, complete signed historical sessions, source and immutable
//! packet slots. Neither path observes current custody, authorizes a floor or
//! produces an effect, receipt, signer, live session or resend permit.

use aos_proto::aos::sandbox::local::v1::{
    BrokerMethod, ObserveHostExecutionArgumentRequestV1,
    TerminalHostExecutionArgumentNoApplyRequestV1,
};
use aos_sandbox_broker_session_protocol::{
    BrokerSessionDurableEndpointV1, BrokerSessionDurableHistoryV1,
    BrokerSessionDurablePhaseV1, BrokerSessionDurableRecordV1,
    BrokerSessionProtocolV1, BrokerSessionTrafficStateV1, VerifiedBrokerSessionTranscriptV1,
    decode_canonical_request_v1, decode_canonical_response_v1,
    verify_historical_traffic_records_v1,
};
use aos_sandbox_broker_session_protocol::manifest::{
    BROKER_SESSION_MANIFEST_BYTES, BrokerSessionManifestAudienceV1, BrokerSessionManifestV1,
};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeAdmissionV1, AuthenticatedBrokerMethodRequestAdmissionV1,
    AuthenticatedBrokerMethodRequestV1, AuthenticatedBrokerMethodResultV1,
    admit_client_received_authenticated_broker_method_outcome_v1,
    authenticated_semantic_bindings_from_envelope_v1,
    prepare_client_sent_authenticated_broker_method_request_v1,
};
use aos_sandbox_protocol::authenticated_session::historical_checkpoint::HistoricalSessionCheckpointV1;
use aos_sandbox_protocol::authenticated_session::stored_history::{
    StoredBrokerSessionHistoryV1, canonical_protocol_key_v1,
};
use aos_sandbox_protocol::host_execution_no_apply::{
    HostExecutionNoApplyRecordV1, signed_host_no_apply_terminal_outcome_digest_v2,
};
use aos_sandbox_protocol::PeerPolicy;
use buffa::Message as _;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha256};

use crate::controller_execution_argument_attempt::ControllerExecutionArgumentAttemptV1;

use super::historical_profile::{PurposeProfileV1, RootRolePinsV1};
use super::super::canonical_nv_name_v1 as nv_name;
use super::super::role_binding::{
    CreateFailureServiceRoleV1, canonical_create_failure_service_binding_v1,
};
use super::super::NvCustodyEndpointV1;

#[cfg(test)]
mod tests;

const BUNDLE_HEADER_BYTES: usize = 20;
const DIGEST_BYTES: usize = 32;
const ARCHIVE_HEADER_BYTES: usize = 30;
const BUNDLE_DOMAIN: &[u8] = b"aos.sandbox.create-failure.original-histories.v4\0";
const ORIGINAL_DOMAIN: &[u8] = b"aos.sandbox.broker-session.host-argument-archive-value.v1\0";
const TERMINAL_DOMAIN: &[u8] = b"aos.sandbox.broker-session.host-terminal-archive.v1\0";
const STABLE_ENDPOINT_DOMAIN: &[u8] = b"aos.sandbox.broker-session.stable-endpoint-identity.v2\0";
const ENDPOINT_PUBLICATION_DOMAIN: &[u8] = b"aos.sandbox.broker-session.endpoint-publication.v1\0";

/// Bounds the complete original-histories DATA carrier, including its digest.
#[doc(hidden)]
pub const FAILED_CREATE_ORIGINAL_HISTORIES_MAXIMUM_BYTES_V4: usize = 1024 * 1024;

/// Reports a noncanonical carrier or an inconsistent historical comparison.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FailedCreateOriginalHistoryErrorV4 {
    /// The exact closed DATA or independent historical join was rejected.
    #[error("invalid failed-Create original Host histories DATA")]
    Invalid,
}

type Error = FailedCreateOriginalHistoryErrorV4;

/// Borrows two complete archive frames without establishing their provenance.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FailedCreateOriginalHistoriesDataV4<'a> {
    original_request_id: [u8; 16],
    original_archive: &'a [u8],
    terminal_archive: &'a [u8],
}

impl<'a> FailedCreateOriginalHistoriesDataV4<'a> {
    /// Decodes exact bounded framing without allocating nested archive storage.
    ///
    /// # Errors
    /// Rejects excessive total size, unknown version, reserved fields, empty or
    /// overflowing lengths, trailing bytes, wrong domains/checksums, malformed
    /// nested archive framing and different original request identities.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        Ok(checked_original_histories_parts_v4(bytes)?.data)
    }

    /// Returns the shared original method-37 request identity as DATA.
    #[must_use]
    pub const fn original_request_id(&self) -> [u8; 16] {
        self.original_request_id
    }

    /// Borrows the complete original AOSHAR01 frame, including its checksum.
    #[must_use]
    pub const fn original_archive(&self) -> &'a [u8] {
        self.original_archive
    }

    /// Borrows the complete terminal AOSHTA01 frame, including its checksum.
    #[must_use]
    pub const fn terminal_archive(&self) -> &'a [u8] {
        self.terminal_archive
    }
}

/// Retains just-checked nested slices for one pure historical join.
struct CheckedOriginalHistoriesPartsV4<'a> {
    data: FailedCreateOriginalHistoriesDataV4<'a>,
    original_stored: &'a [u8],
    terminal_stored: &'a [u8],
}

fn checked_original_histories_parts_v4(
    bytes: &[u8],
) -> Result<CheckedOriginalHistoriesPartsV4<'_>, Error> {
    if bytes.len() < BUNDLE_HEADER_BYTES + DIGEST_BYTES
        || bytes.len() > FAILED_CREATE_ORIGINAL_HISTORIES_MAXIMUM_BYTES_V4
        || bytes.get(..12) != Some(b"AOSCFH04\0\x04\0\0".as_slice())
    {
        return Err(Error::Invalid);
    }
    let original_len = usize::try_from(u32::from_be_bytes(array(bytes, 12)?))
        .map_err(|_| Error::Invalid)?;
    let terminal_len = usize::try_from(u32::from_be_bytes(array(bytes, 16)?))
        .map_err(|_| Error::Invalid)?;
    let total = failed_create_original_histories_encoded_len_v4(original_len, terminal_len)?;
    if total != bytes.len() {
        return Err(Error::Invalid);
    }
    let original_end = BUNDLE_HEADER_BYTES
        .checked_add(original_len)
        .ok_or(Error::Invalid)?;
    let terminal_end = original_end.checked_add(terminal_len).ok_or(Error::Invalid)?;
    if array::<32>(bytes, terminal_end)? != digest(BUNDLE_DOMAIN, &bytes[..terminal_end]) {
        return Err(Error::Invalid);
    }

    let original_archive = &bytes[BUNDLE_HEADER_BYTES..original_end];
    let terminal_archive = &bytes[original_end..terminal_end];
    let (original_request_id, original_stored) =
        archive(original_archive, b"AOSHAR01", ORIGINAL_DOMAIN)?;
    let (terminal_original, terminal_stored) =
        archive(terminal_archive, b"AOSHTA01", TERMINAL_DOMAIN)?;
    if original_request_id != terminal_original {
        return Err(Error::Invalid);
    }

    Ok(CheckedOriginalHistoriesPartsV4 {
        data: FailedCreateOriginalHistoriesDataV4 {
            original_request_id,
            original_archive,
            terminal_archive,
        },
        original_stored,
        terminal_stored,
    })
}

/// Checks aggregate framing size before copying or allocating archive DATA.
///
/// # Errors
/// Rejects empty lengths, lengths outside u32, arithmetic overflow or a complete
/// carrier larger than the single purpose-local maximum.
#[doc(hidden)]
pub fn failed_create_original_histories_encoded_len_v4(
    original_bytes: usize,
    terminal_bytes: usize,
) -> Result<usize, Error> {
    if original_bytes == 0 || terminal_bytes == 0 {
        return Err(Error::Invalid);
    }
    u32::try_from(original_bytes).map_err(|_| Error::Invalid)?;
    u32::try_from(terminal_bytes).map_err(|_| Error::Invalid)?;
    BUNDLE_HEADER_BYTES
        .checked_add(original_bytes)
        .and_then(|size| size.checked_add(terminal_bytes))
        .and_then(|size| size.checked_add(DIGEST_BYTES))
        .filter(|size| *size <= FAILED_CREATE_ORIGINAL_HISTORIES_MAXIMUM_BYTES_V4)
        .ok_or(Error::Invalid)
}

/// Encodes two already captured complete archive frames as nonauthorizing DATA.
///
/// # Errors
/// Rejects aggregate bounds before allocation, noncanonical archive frames,
/// invalid frame checksums or different original request identities.
#[doc(hidden)]
pub fn encode_failed_create_original_histories_v4(
    original_archive: &[u8],
    terminal_archive: &[u8],
) -> Result<Vec<u8>, Error> {
    let total = failed_create_original_histories_encoded_len_v4(
        original_archive.len(),
        terminal_archive.len(),
    )?;
    let (original_id, _) = archive(original_archive, b"AOSHAR01", ORIGINAL_DOMAIN)?;
    let (terminal_id, _) = archive(terminal_archive, b"AOSHTA01", TERMINAL_DOMAIN)?;
    if original_id != terminal_id {
        return Err(Error::Invalid);
    }
    let original_len = u32::try_from(original_archive.len()).map_err(|_| Error::Invalid)?;
    let terminal_len = u32::try_from(terminal_archive.len()).map_err(|_| Error::Invalid)?;
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(b"AOSCFH04\0\x04\0\0");
    bytes.extend_from_slice(&original_len.to_be_bytes());
    bytes.extend_from_slice(&terminal_len.to_be_bytes());
    bytes.extend_from_slice(original_archive);
    bytes.extend_from_slice(terminal_archive);
    let checksum = digest(BUNDLE_DOMAIN, &bytes);
    bytes.extend_from_slice(&checksum);
    Ok(bytes)
}

/// Retains only independently reauthenticated historical original join DATA.
pub(super) struct VerifiedFailedCreateOriginalHistoriesV3 {
    original: ControllerExecutionArgumentAttemptV1,
    archive_head: ObjectDigest,
    signed_terminal_outcome: ObjectDigest,
    marker: HostExecutionNoApplyRecordV1,
}

impl VerifiedFailedCreateOriginalHistoriesV3 {
    pub(super) const fn original(&self) -> &ControllerExecutionArgumentAttemptV1 {
        &self.original
    }

    pub(super) const fn archive_head(&self) -> ObjectDigest {
        self.archive_head
    }

    pub(super) const fn signed_terminal_outcome(&self) -> ObjectDigest {
        self.signed_terminal_outcome
    }

    pub(super) const fn marker(&self) -> HostExecutionNoApplyRecordV1 {
        self.marker
    }
}

/// Independently verifies full old sessions against genuine Root-sourced pins.
///
/// The concrete Root startup must supply `expected_manifest` from its fixed
/// PID1 credential, never from this bundle or a caller-selected pin source.
/// Slot seven must retain exactly those same bytes. These comparison inputs and
/// the result grant no custody: the complete map and fresh physical floor remain
/// the concrete retained owner's responsibility.
pub(super) fn verify_original_join_v3(
    bytes: &[u8],
    expected_manifest: &[u8; BROKER_SESSION_MANIFEST_BYTES],
    slots: [&[u8]; 7],
    source: &ControllerExecutionArgumentAttemptV1,
    profile: &PurposeProfileV1,
    pins: &RootRolePinsV1,
) -> Result<VerifiedFailedCreateOriginalHistoriesV3, Error> {
    // Decode the bounded borrowed outer carrier before either shared stored
    // history decoder can allocate its canonical nested models.
    let checked = checked_original_histories_parts_v4(bytes)?;
    if slots[6] != expected_manifest || checked.data.original_request_id() != source.request_id() {
        return Err(Error::Invalid);
    }
    let manifest = BrokerSessionManifestV1::decode(expected_manifest).map_err(|_| Error::Invalid)?;
    require_manifest_and_pins(&manifest, profile, pins)?;

    let original = historical_stored_archive(checked.original_stored, &manifest)?;
    let terminal = historical_stored_archive(checked.terminal_stored, &manifest)?;
    let original_index = original.history.records().len()
        .checked_sub(1).ok_or(Error::Invalid)?;
    let original_head = &original.history.records()[original_index];
    if original_head.method() != BrokerMethod::BROKER_METHOD_HOST_OBSERVE_EXECUTION_ARGUMENT
        || original_head.phase() != BrokerSessionDurablePhaseV1::RequestPrepared
        || original_head.request_id() != source.request_id()
    {
        return Err(Error::Invalid);
    }
    let (original_request, _) = historical_request(&original, original_index)?;
    require_request_slot(&original_request, original_head, slots[0], slots[1])?;
    let original_body = ObserveHostExecutionArgumentRequestV1::decode_from_slice(
        original_request.exact_body(),
    )
    .map_err(|_| Error::Invalid)?;
    if original_body.encode_to_vec() != original_request.exact_body()
        || original_body.canonical_attempt.as_slice() != source.canonical_bytes()
    {
        return Err(Error::Invalid);
    }

    let terminal_index = terminal.history.records().len()
        .checked_sub(1).ok_or(Error::Invalid)?;
    let request_index = terminal_index.checked_sub(1).ok_or(Error::Invalid)?;
    let terminal_head = &terminal.history.records()[terminal_index];
    let terminal_prepared = &terminal.history.records()[request_index];
    if terminal_head.method() != BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY
        || terminal_head.phase() != BrokerSessionDurablePhaseV1::Terminal
        || terminal_prepared.phase() != BrokerSessionDurablePhaseV1::RequestPrepared
        || terminal_prepared.request_packet() != terminal_head.request_packet()
        || terminal_prepared.request_id() != terminal_head.request_id()
        || terminal_prepared.request_companion() != terminal_head.request_companion()
    {
        return Err(Error::Invalid);
    }
    let (terminal_request, pending) = historical_request(&terminal, request_index)?;
    require_request_slot(&terminal_request, terminal_prepared, slots[2], slots[3])?;
    let terminal_body = TerminalHostExecutionArgumentNoApplyRequestV1::decode_from_slice(
        terminal_request.exact_body(),
    )
    .map_err(|_| Error::Invalid)?;
    if terminal_body.encode_to_vec() != terminal_request.exact_body()
        || terminal_body.canonical_attempt.as_slice() != source.canonical_bytes()
        || terminal_body.original_session_binding.as_slice() != original_request.session_binding()
        || terminal_body.original_signed_request_digest.as_slice()
            != original_request.signed_request_digest()
    {
        return Err(Error::Invalid);
    }
    let packet = terminal_head.outcome_packet().ok_or(Error::Invalid)?;
    let canonical = decode_canonical_response_v1(packet).map_err(|_| Error::Invalid)?;
    if packet != slots[4] || canonical.signed_artifact().to_canonical_bytes() != slots[5] {
        return Err(Error::Invalid);
    }
    let outcome = match admit_client_received_authenticated_broker_method_outcome_v1(
        &pending,
        &terminal_request,
        packet,
        None,
        canonical.message().descriptors.len(),
        terminal.checkpoint.context(),
    )
    .map_err(|_| Error::Invalid)? {
        AuthenticatedBrokerMethodOutcomeAdmissionV1::New { outcome, .. } => outcome,
        AuthenticatedBrokerMethodOutcomeAdmissionV1::ExactReplay(_) => return Err(Error::Invalid),
    };
    if outcome.semantic_commitment() != terminal_head.outcome_semantic_binding()
        || !matches!(outcome.result(), AuthenticatedBrokerMethodResultV1::Success { .. })
    {
        return Err(Error::Invalid);
    }
    let readback = outcome.recorded_host_no_apply()
        .map_err(|_| Error::Invalid)?
        .ok_or(Error::Invalid)?;
    let marker = *readback.record();
    require_original_marker(marker, source, &original_request)?;
    let fields = marker.fields();
    if fields.terminal_request_id != terminal_request.request_id()
        || fields.terminal_session_binding != terminal_request.session_binding()
        || fields.terminal_signed_request_digest != terminal_request.signed_request_digest()
    {
        return Err(Error::Invalid);
    }

    Ok(VerifiedFailedCreateOriginalHistoriesV3 {
        original: source.clone(),
        archive_head: ObjectDigest::from_bytes(original.history.head_commitment()),
        // This existing helper commits the entire authenticated response packet,
        // not merely its signed artifact or the terminal history commitment.
        signed_terminal_outcome: signed_host_no_apply_terminal_outcome_digest_v2(&outcome),
        marker,
    })
}

struct HistoricalArchive {
    checkpoint: HistoricalSessionCheckpointV1,
    transcript: VerifiedBrokerSessionTranscriptV1,
    history: BrokerSessionDurableHistoryV1,
}

fn historical_archive(
    frame: &[u8],
    magic: &[u8; 8],
    domain: &[u8],
    manifest: &BrokerSessionManifestV1,
) -> Result<HistoricalArchive, Error> {
    let (_, stored_bytes) = archive(frame, magic, domain)?;
    historical_stored_archive(stored_bytes, manifest)
}

/// Reauthenticates complete stored history after its caller checks the frame.
fn historical_stored_archive(
    stored_bytes: &[u8],
    manifest: &BrokerSessionManifestV1,
) -> Result<HistoricalArchive, Error> {
    // The shared codec preserves V2 for old consumers; this verifier requires
    // original V3 signed hello evidence and never upgrades unsigned history.
    if stored_bytes.get(8..10) != Some(3_u16.to_be_bytes().as_slice()) {
        return Err(Error::Invalid);
    }
    let stored = StoredBrokerSessionHistoryV1::decode(
        &canonical_protocol_key_v1(BrokerSessionProtocolV1::Host),
        stored_bytes,
    )
    .map_err(|_| Error::Invalid)?;
    let checkpoint = stored.checkpoint.as_ref().ok_or(Error::Invalid)?;
    let archived_context = checkpoint.context();
    let independent_context = manifest.verification_context(
        archived_context.boot_id(),
        archived_context.client_process(),
        archived_context.broker_process(),
    )
    .map_err(|_| Error::Invalid)?;
    if independent_context != *archived_context {
        return Err(Error::Invalid);
    }
    let transcript = checkpoint.verify().map_err(|_| Error::Invalid)?;
    // Host=1 and Client=1 are the original closed namespace-47 endpoint codes.
    let stable_endpoint: [u8; 32] = Sha256::new()
        .chain_update(STABLE_ENDPOINT_DOMAIN)
        .chain_update([1, 1])
        .chain_update(manifest.binding().as_bytes())
        .finalize()
        .into();
    let publication: [u8; 32] = Sha256::new()
        .chain_update(ENDPOINT_PUBLICATION_DOMAIN)
        .chain_update([1, 1])
        .chain_update(manifest.binding().as_bytes())
        .chain_update(transcript.client_process())
        .finalize()
        .into();
    if stored.protocol != BrokerSessionProtocolV1::Host
        || stored.endpoint != BrokerSessionDurableEndpointV1::Client
        || stored.stable_endpoint_identity != stable_endpoint
        || stored.endpoint_publication != publication
    {
        return Err(Error::Invalid);
    }
    let history = stored.history_model().map_err(|_| Error::Invalid)?;
    verify_historical_traffic_records_v1(history.records(), &transcript, &independent_context)
        .map_err(|_| Error::Invalid)?;

    // All checkpoint borrows have ended; retain its already decoded hello
    // buffers instead of cloning them while dropping the stored container.
    let checkpoint = stored.checkpoint.ok_or(Error::Invalid)?;
    Ok(HistoricalArchive {
        checkpoint,
        transcript,
        history,
    })
}

fn historical_request(
    archive: &HistoricalArchive,
    index: usize,
) -> Result<(AuthenticatedBrokerMethodRequestV1, Box<BrokerSessionTrafficStateV1>), Error> {
    let record = archive.history.records().get(index).ok_or(Error::Invalid)?;
    if record.phase() != BrokerSessionDurablePhaseV1::RequestPrepared {
        return Err(Error::Invalid);
    }
    let prior = verify_historical_traffic_records_v1(
        &archive.history.records()[..index],
        &archive.transcript,
        archive.checkpoint.context(),
    )
    .map_err(|_| Error::Invalid)?;
    let canonical = decode_canonical_request_v1(record.request_packet()).map_err(|_| Error::Invalid)?;
    let bindings = authenticated_semantic_bindings_from_envelope_v1(
        canonical.message(),
        canonical.signed_artifact().method(),
    )
    .map_err(|_| Error::Invalid)?;
    let peer = archive.checkpoint.peer();
    let policy = PeerPolicy {
        uid: peer.uid,
        gid: Some(peer.gid),
        audience: archive.checkpoint.context().audience(),
    };
    // A historical deadline comparison cannot authorize a present send. The
    // original admission checks are reused solely at the retained old instant.
    let retained_time = record.request_companion().deadline_boottime_nanoseconds()
        .checked_sub(1)
        .ok_or(Error::Invalid)?;
    let (request, pending) = match prepare_client_sent_authenticated_broker_method_request_v1(
        &prior,
        record.request_packet(),
        None,
        canonical.message().descriptors.len(),
        peer,
        policy,
        retained_time,
        bindings,
        archive.checkpoint.context(),
    )
    .map_err(|_| Error::Invalid)? {
        AuthenticatedBrokerMethodRequestAdmissionV1::New { request, next_traffic } => {
            (request, next_traffic)
        }
        AuthenticatedBrokerMethodRequestAdmissionV1::ExactReplay(_) => return Err(Error::Invalid),
    };
    if request.method() != record.method()
        || request.session_binding() != record.session_binding()
        || request.request_id() != record.request_id()
        || request.client_sequence() != record.client_sequence()
        || request.maximum_response_bytes() != record.maximum_response_bytes()
        || request.semantic_commitment() != record.request_semantic_binding()
        || request.canonical_packet() != record.request_packet()
    {
        return Err(Error::Invalid);
    }
    Ok((request, pending))
}

fn require_request_slot(
    request: &AuthenticatedBrokerMethodRequestV1,
    record: &BrokerSessionDurableRecordV1,
    packet: &[u8],
    artifact: &[u8],
) -> Result<(), Error> {
    if request.canonical_packet() != packet
        || record.request_companion().signed_request().to_canonical_bytes() != artifact
    {
        return Err(Error::Invalid);
    }
    Ok(())
}

fn require_original_marker(
    marker: HostExecutionNoApplyRecordV1,
    source: &ControllerExecutionArgumentAttemptV1,
    request: &AuthenticatedBrokerMethodRequestV1,
) -> Result<(), Error> {
    let fields = marker.fields();
    if fields.execution_id != *source.execution().as_bytes()
        || fields.create_operation_id != *source.create_operation().as_bytes()
        || fields.original_request_id != source.request_id()
        || fields.host_boot_id != source.host_boot_id()
        || fields.assignment_digest != *source.assignment_digest().as_bytes()
        || fields.source_record_digest != *source.record_digest().as_bytes()
        || fields.original_session_binding != request.session_binding()
        || fields.original_signed_request_digest != request.signed_request_digest()
    {
        return Err(Error::Invalid);
    }
    Ok(())
}

fn require_manifest_and_pins(
    manifest: &BrokerSessionManifestV1,
    profile: &PurposeProfileV1,
    pins: &RootRolePinsV1,
) -> Result<(), Error> {
    if profile.endpoint != NvCustodyEndpointV1::RootCreateFailure
        || profile.node == [0; 16]
        || profile.epoch == [0; 16]
        || profile.stable_endpoint == [0; 32]
        || profile.genesis == [0; 32]
        || profile.scope == [0; 32]
        || profile.domain_binding != [0; 32]
        || profile.nv_name != nv_name(NvCustodyEndpointV1::RootCreateFailure)
        || profile.salt_name[..2] != 0x000b_u16.to_be_bytes()
        || profile.salt_name[2..] == [0; 32]
        || profile.role_pins != Some(pins.digests)
        || pins.digests.contains(&[0; 32])
        || manifest.protocol() != BrokerSessionProtocolV1::Host
        || manifest.audience() != BrokerSessionManifestAudienceV1::NodeController
        || manifest.node_id() != profile.node
    {
        return Err(Error::Invalid);
    }
    manifest.require_all_active().map_err(|_| Error::Invalid)?;
    for (index, role) in [
        CreateFailureServiceRoleV1::Controller,
        CreateFailureServiceRoleV1::Host,
        CreateFailureServiceRoleV1::Root,
    ].into_iter().enumerate() {
        let key = VerifyingKey::from_bytes(&pins.keys[index]).map_err(|_| Error::Invalid)?;
        if key.is_weak()
            || pins.assignments[index] != canonical_create_failure_service_binding_v1(
                role,
                profile.node,
                profile.epoch,
            ).map_err(|_| Error::Invalid)?
            || pins.keys[..index].contains(&pins.keys[index])
            || manifest.key_pins().iter().any(|pin| pin.public_key() == &pins.keys[index])
        {
            return Err(Error::Invalid);
        }
    }
    // A service-owner pin is not the original runtime target assignment.
    Ok(())
}

fn archive<'a>(
    bytes: &'a [u8],
    magic: &[u8; 8],
    domain: &[u8],
) -> Result<([u8; 16], &'a [u8]), Error> {
    if bytes.len() <= ARCHIVE_HEADER_BYTES + DIGEST_BYTES
        || bytes.get(..8) != Some(magic.as_slice())
        || array::<2>(bytes, 8)? != 1_u16.to_be_bytes()
    {
        return Err(Error::Invalid);
    }
    let request_id = array(bytes, 10)?;
    let stored_len = usize::try_from(u32::from_be_bytes(array(bytes, 26)?))
        .map_err(|_| Error::Invalid)?;
    let stored_end = ARCHIVE_HEADER_BYTES.checked_add(stored_len).ok_or(Error::Invalid)?;
    if request_id == [0; 16]
        || stored_len == 0
        || stored_end.checked_add(DIGEST_BYTES) != Some(bytes.len())
        || array::<32>(bytes, stored_end)? != digest(domain, &bytes[..stored_end])
    {
        return Err(Error::Invalid);
    }
    Ok((request_id, &bytes[ARCHIVE_HEADER_BYTES..stored_end]))
}

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update(domain).chain_update(bytes).finalize().into()
}

fn array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], Error> {
    let end = offset.checked_add(N).ok_or(Error::Invalid)?;
    bytes.get(offset..end)
        .and_then(|value| value.try_into().ok())
        .ok_or(Error::Invalid)
}
