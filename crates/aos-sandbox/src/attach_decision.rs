//! Protected original attach decisions, separate from current authorization.
//!
//! ```text
//! original-attach-decision-v2/<operation> => canonical closed JSON
//! original-attach-grant-v2/<pending digest> => original AOSAPG01[416]
//! ```
//!
//! Decision and endpoint commit with the accepted Operation. A retained value
//! is historical custody, not a factory for authenticated peers or grants.

use aos_sandbox_core::{OperationId, PrincipalId, ProjectId};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::attach_route_issuer::AttachRouteIssuanceErrorV1 as Error;
use crate::cli_model::provenance::OriginalPublicMutationCoordinatesV2;
use crate::{Journal, JournalRecord, JournalTransaction, RecordNamespace};

const DECISION_PREFIX: &[u8] = b"original-attach-decision-v2/";
const GRANT_PREFIX: &[u8] = b"original-attach-grant-v2/";
const TICKET_PREFIX: &[u8] = b"original-attach-ticket-v2/";
const MAXIMUM_DECISION_BYTES: usize = 128 * 1024;

/// Retains historical accepted coordinates without granting current authority.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OriginalDecisionV2 {
    version: u32,
    /// Exact canonical public request accepted under the original capability.
    pub(crate) request: Vec<u8>,
    /// Original capability, policy, controller, revocation, key, and time bounds.
    pub(crate) coordinates: OriginalPublicMutationCoordinatesV2,
    /// Original fixed server, CA, registration, and registered leaf fingerprints.
    pub(crate) public_tls_trust: [[u8; 32]; 4],
    /// Principal authenticated at original public admission.
    pub(crate) caller: PrincipalId,
    /// Registered original project boundary, not a new permission grant.
    pub(crate) project: ProjectId,
    /// Original protected admission wall time, never refreshed by consume.
    pub(crate) accepted_wall_seconds: i64,
    /// Immutable issuance coordinates after the original certificate is retained.
    pub(crate) original_ticket: Option<OriginalTicketCoordinatesV2>,
}

/// Binds the accepted decision to exact original issuance and base route bytes.
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OriginalTicketCoordinatesV2 {
    /// Commitment to the original serialized CA-signed certificate.
    pub(crate) certificate_digest: [u8; 32],
    /// Original certificate's Ed25519 holder public key.
    pub(crate) holder_public_key: [u8; 32],
    /// Inclusive original certificate validity start.
    pub(crate) valid_after: u64,
    /// Exclusive immutable certificate expiry.
    pub(crate) expires_at: u64,
    /// Original authenticated protected Host route commitment.
    pub(crate) base_route_digest: [u8; 32],
    /// Commitment to the original dedicated-key AOSAPG01 receipt.
    pub(crate) pending_grant_digest: [u8; 32],
}

/// Encodes original checked coordinates without constructing mutation authority.
///
/// # Errors
/// Rejects empty request/trust or an oversized private decision encoding.
pub(crate) fn encode_original_decision(
    request: &[u8],
    coordinates: OriginalPublicMutationCoordinatesV2,
    public_tls_trust: [[u8; 32]; 4],
    caller: PrincipalId,
    project: ProjectId,
    accepted_wall_seconds: i64,
) -> Result<Vec<u8>, Error> {
    if request.is_empty() || public_tls_trust.iter().any(|digest| digest == &[0; 32]) {
        return Err(Error::DurableRecord);
    }
    let bytes = serde_json::to_vec(&OriginalDecisionV2 {
        version: 2,
        request: request.to_vec(),
        coordinates,
        public_tls_trust,
        caller,
        project,
        accepted_wall_seconds,
        original_ticket: None,
    })
    .map_err(|_| Error::DurableRecord)?;
    if bytes.len() > MAXIMUM_DECISION_BYTES {
        return Err(Error::DurableRecord);
    }
    Ok(bytes)
}

/// Constructs the decision row committed atomically with the original endpoint.
///
/// # Errors
/// Rejects malformed or unbound original decisions.
pub(crate) fn decision_record(
    operation: OperationId,
    bytes: Vec<u8>,
) -> Result<JournalRecord, Error> {
    decode_decision(&bytes)?
        .original_ticket
        .ok_or(Error::DurableRecord)?;
    Ok(JournalRecord::put(
        RecordNamespace::PublicAttachRoute,
        decision_key(operation),
        bytes,
    ))
}

/// Adds exact original issuance coordinates to the already checked decision.
///
/// # Errors
/// Rejects malformed/already-bound data, absent route, or invalid holder shape.
pub(crate) fn bind_issued_decision(
    checked: &[u8],
    certificate: &[u8],
    route_digest: [u8; 32],
    original_grant: &[u8; 416],
) -> Result<Vec<u8>, Error> {
    let mut decision = decode_decision(checked)?;
    if decision.original_ticket.is_some() || route_digest == [0; 32] {
        return Err(Error::DurableRecord);
    }
    let line = std::str::from_utf8(certificate).map_err(|_| Error::DurableRecord)?;
    let cert = ssh_key::Certificate::from_openssh(line).map_err(|_| Error::DurableRecord)?;
    decision.original_ticket = Some(OriginalTicketCoordinatesV2 {
        certificate_digest: Sha256::digest(certificate).into(),
        holder_public_key: cert.public_key().ed25519().ok_or(Error::DurableRecord)?.0,
        valid_after: cert.valid_after(),
        expires_at: cert.valid_before(),
        base_route_digest: route_digest,
        pending_grant_digest: Sha256::digest(original_grant).into(),
    });
    serde_json::to_vec(&decision).map_err(|_| Error::DurableRecord)
}

/// Loads original issuance coordinates from protected accepted custody.
///
/// # Errors
/// Rejects unavailable journal custody or missing/malformed accepted decisions.
pub(crate) fn original_ticket_coordinates(
    journal: &Journal,
    operation: OperationId,
) -> Result<OriginalTicketCoordinatesV2, Error> {
    journal
        .ensure_protected_authority()
        .map_err(|_| Error::DurableRecord)?;
    let bytes = journal
        .get(RecordNamespace::PublicAttachRoute, &decision_key(operation))
        .ok_or(Error::DurableRecord)?;
    decode_decision(bytes)?
        .original_ticket
        .ok_or(Error::DurableRecord)
}

/// Loads historical accepted coordinates, never current authorization.
///
/// # Errors
/// Rejects unavailable custody, missing decisions, or incomplete issuance.
pub(crate) fn original_decision(
    journal: &Journal,
    operation: OperationId,
) -> Result<OriginalDecisionV2, Error> {
    journal
        .ensure_protected_authority()
        .map_err(|_| Error::DurableRecord)?;
    let bytes = journal
        .get(RecordNamespace::PublicAttachRoute, &decision_key(operation))
        .ok_or(Error::DurableRecord)?;
    let decision = decode_decision(bytes)?;
    decision.original_ticket.ok_or(Error::DurableRecord)?;
    Ok(decision)
}

/// Borrows the exact original ticket retained before its first Host binding.
///
/// # Errors
/// Rejects missing, foreign, noncanonical, or unavailable ticket custody.
pub(crate) fn original_ticket(journal: &Journal, operation: OperationId) -> Result<&[u8], Error> {
    journal
        .ensure_protected_authority()
        .map_err(|_| Error::DurableRecord)?;
    let bytes = journal
        .get(RecordNamespace::PublicAttachRoute, &ticket_key(operation))
        .ok_or(Error::DurableRecord)?;
    let ticket = aos_sandbox_core::public_attach_ticket::PublicAttachTicketBindingV2::decode(bytes)
        .map_err(|_| Error::DurableRecord)?;
    if ticket.operation_id != *operation.as_bytes()
        || ticket.encode().map_err(|_| Error::DurableRecord)? != bytes
    {
        return Err(Error::DurableRecord);
    }
    Ok(bytes)
}

/// Streams bounded original ticket data without constructing authorization.
///
/// # Errors
/// Rejects unavailable protected custody or malformed/foreign canonical rows.
/// Each item is historical data; current owner checks remain mandatory.
pub(crate) fn original_ticket_records(
    journal: &Journal,
) -> Result<
    impl Iterator<
        Item = Result<
            (
                OperationId,
                aos_sandbox_core::public_attach_ticket::PublicAttachTicketBindingV2,
            ),
            Error,
        >,
    > + '_,
    Error,
> {
    journal
        .ensure_protected_authority()
        .map_err(|_| Error::DurableRecord)?;
    Ok(journal
        .records(RecordNamespace::PublicAttachRoute)
        .filter_map(|(key, bytes)| {
            let suffix = key.strip_prefix(TICKET_PREFIX)?;
            Some((|| {
                let operation =
                    OperationId::from_bytes(suffix.try_into().map_err(|_| Error::DurableRecord)?);
                let ticket =
                    aos_sandbox_core::public_attach_ticket::PublicAttachTicketBindingV2::decode(
                        bytes,
                    )
                    .map_err(|_| Error::DurableRecord)?;
                if ticket.operation_id != *operation.as_bytes()
                    || ticket.encode().map_err(|_| Error::DurableRecord)? != bytes
                {
                    return Err(Error::DurableRecord);
                }
                Ok((operation, ticket))
            })())
        }))
}

/// Rejoins immutable original custody with an independently checked current request.
///
/// # Errors
/// Rejects foreign request/scope/key/trust, expiry or changed policy/revocation.
/// Historical session/clock commitments remain untouched across reconnect.
pub(crate) fn retained_decision_record(
    journal: &Journal,
    operation: OperationId,
    currently_checked: &[u8],
) -> Result<JournalRecord, Error> {
    journal
        .ensure_protected_authority()
        .map_err(|_| Error::DurableRecord)?;
    let original = journal
        .get(RecordNamespace::PublicAttachRoute, &decision_key(operation))
        .ok_or(Error::DurableRecord)?;
    let retained = decode_decision(original)?;
    let checked = decode_decision(currently_checked)?;
    let ticket = retained.original_ticket.ok_or(Error::DurableRecord)?;
    let now = u64::try_from(checked.accepted_wall_seconds).map_err(|_| Error::DurableRecord)?;
    // The current request must independently authorize the same original cut.
    // Rotation/revocation/policy changes do not silently replace its coordinates.
    if retained.request != checked.request
        || !same_original_scope(&retained.coordinates, &checked.coordinates)
        || retained.public_tls_trust != checked.public_tls_trust
        || retained.caller != checked.caller
        || retained.project != checked.project
        || now < ticket.valid_after
        || now >= ticket.expires_at
        || checked.accepted_wall_seconds < retained.coordinates.capability_not_before
        || checked.accepted_wall_seconds >= retained.coordinates.capability_expires_at
        || checked.accepted_wall_seconds < retained.coordinates.policy_not_before
        || checked.accepted_wall_seconds >= retained.coordinates.policy_expires_at
    {
        return Err(Error::DurableRecord);
    }
    decision_record(operation, original.to_vec())
}

/// Commits the exact protected original accepted decision bytes.
///
/// # Errors
/// Rejects stale journal custody or missing/malformed original decisions.
pub(crate) fn decision_digest(
    journal: &Journal,
    operation: OperationId,
) -> Result<[u8; 32], Error> {
    journal
        .ensure_protected_authority()
        .map_err(|_| Error::DurableRecord)?;
    let bytes = journal
        .get(RecordNamespace::PublicAttachRoute, &decision_key(operation))
        .ok_or(Error::DurableRecord)?;
    decode_decision(bytes)?;
    Ok(Sha256::digest(bytes).into())
}

/// Retains an exact original signed receipt before its first Host dispatch.
///
/// # Errors
/// Rejects substitution, unavailable protected state or ambiguous durability.
pub(crate) fn retain_original_grant(
    journal: &mut Journal,
    pending_digest: [u8; 32],
    grant: &[u8; 416],
) -> Result<(), Error> {
    journal
        .ensure_protected_authority()
        .map_err(|_| Error::DurableRecord)?;
    let key = grant_key(pending_digest);
    if let Some(previous) = journal.get(RecordNamespace::PublicAttachRoute, &key) {
        return if previous == grant {
            Ok(())
        } else {
            Err(Error::DurableRecord)
        };
    }
    let transaction = JournalTransaction::new(
        OperationId::new().into_bytes(),
        vec![JournalRecord::put(
            RecordNamespace::PublicAttachRoute,
            key.clone(),
            grant.to_vec(),
        )],
    )
    .map_err(|_| Error::DurableRecord)?;
    // commit poisons ambiguous durability; never use its diagnostic map as a
    // successful readback. Reopen/replay is the only recovery from that state.
    journal
        .commit(&transaction)
        .map_err(|_| Error::DurableRecord)?;
    journal
        .ensure_protected_authority()
        .map_err(|_| Error::DurableRecord)?;
    if journal.get(RecordNamespace::PublicAttachRoute, &key) != Some(grant.as_slice()) {
        return Err(Error::DurableRecord);
    }
    Ok(())
}

/// Loads original receipt bytes without re-signing or reconstructing a grant.
///
/// # Errors
/// Rejects unavailable protected journal custody or missing/wrong-sized data.
pub(crate) fn original_grant(
    journal: &Journal,
    pending_digest: [u8; 32],
) -> Result<[u8; 416], Error> {
    journal
        .ensure_protected_authority()
        .map_err(|_| Error::DurableRecord)?;
    journal
        .get(
            RecordNamespace::PublicAttachRoute,
            &grant_key(pending_digest),
        )
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(Error::DurableRecord)
}

/// Retains immutable post-issuance carrier bytes before Host binding.
///
/// # Errors
/// Rejects invalid data, operation substitution, conflicting bytes or durability.
pub(crate) fn retain_original_ticket(
    journal: &mut Journal,
    operation: OperationId,
    bytes: &[u8],
) -> Result<(), Error> {
    let ticket = aos_sandbox_core::public_attach_ticket::PublicAttachTicketBindingV2::decode(bytes)
        .map_err(|_| Error::DurableRecord)?;
    if ticket.operation_id != *operation.as_bytes() {
        return Err(Error::DurableRecord);
    }
    journal
        .ensure_protected_authority()
        .map_err(|_| Error::DurableRecord)?;
    let key = ticket_key(operation);
    if let Some(previous) = journal.get(RecordNamespace::PublicAttachRoute, &key) {
        return if previous == bytes {
            Ok(())
        } else {
            Err(Error::DurableRecord)
        };
    }
    let transaction = JournalTransaction::new(
        OperationId::new().into_bytes(),
        vec![JournalRecord::put(
            RecordNamespace::PublicAttachRoute,
            key.clone(),
            bytes.to_vec(),
        )],
    )
    .map_err(|_| Error::DurableRecord)?;
    journal
        .commit(&transaction)
        .map_err(|_| Error::DurableRecord)?;
    journal
        .ensure_protected_authority()
        .map_err(|_| Error::DurableRecord)?;
    if journal.get(RecordNamespace::PublicAttachRoute, &key) != Some(bytes) {
        return Err(Error::DurableRecord);
    }
    Ok(())
}

fn decode_decision(bytes: &[u8]) -> Result<OriginalDecisionV2, Error> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_DECISION_BYTES {
        return Err(Error::DurableRecord);
    }
    let value: OriginalDecisionV2 =
        serde_json::from_slice(bytes).map_err(|_| Error::DurableRecord)?;
    if value.version != 2 || serde_json::to_vec(&value).map_err(|_| Error::DurableRecord)? != bytes
    {
        return Err(Error::DurableRecord);
    }
    if let Some(ticket) = value.original_ticket {
        if [ticket.certificate_digest, ticket.holder_public_key, ticket.base_route_digest, ticket.pending_grant_digest]
            .iter().any(|digest| digest == &[0; 32]) || ticket.valid_after == 0
            || ticket.expires_at <= ticket.valid_after
            || ticket.expires_at - ticket.valid_after > u64::from(aos_sandbox_core::public_attach_route::PUBLIC_ATTACH_CERTIFICATE_MAXIMUM_SECONDS_V1) {
            return Err(Error::DurableRecord);
        }
    }
    Ok(value)
}

/// Names the dedicated original-decision row without constructing authority.
pub(crate) fn decision_key(operation: OperationId) -> Vec<u8> {
    let mut key = DECISION_PREFIX.to_vec();
    key.extend_from_slice(operation.as_bytes());
    key
}

pub(crate) fn same_original_scope(
    original: &OriginalPublicMutationCoordinatesV2,
    checked: &OriginalPublicMutationCoordinatesV2,
) -> bool {
    // Current authorize() has independently checked the authenticated channel.
    // Historical session/clock coordinates are retained, not compared as if a
    // reconnect had to revive the original session or reconstruct its proof.
    original.capability == checked.capability
        && original.revocation_scope == checked.revocation_scope
        && original.revocation_generation == checked.revocation_generation
        && original.policy_digest == checked.policy_digest
        && original.policy_generation == checked.policy_generation
        && original.controller == checked.controller
        && original.controller_generation == checked.controller_generation
        && original.capability_not_before == checked.capability_not_before
        && original.capability_expires_at == checked.capability_expires_at
        && original.policy_not_before == checked.policy_not_before
        && original.policy_expires_at == checked.policy_expires_at
        && original.channel_binding == checked.channel_binding
}

fn grant_key(pending_digest: [u8; 32]) -> Vec<u8> {
    let mut key = GRANT_PREFIX.to_vec();
    key.extend_from_slice(&pending_digest);
    key
}

fn ticket_key(operation: OperationId) -> Vec<u8> {
    let mut key = TICKET_PREFIX.to_vec();
    key.extend_from_slice(operation.as_bytes());
    key
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    fn coordinates() -> OriginalPublicMutationCoordinatesV2 {
        OriginalPublicMutationCoordinatesV2 {
            capability: [1; 16],
            revocation_scope: [2; 16],
            revocation_generation: 1,
            policy_digest: [3; 32],
            policy_generation: 1,
            controller: [4; 16],
            controller_generation: 1,
            capability_not_before: 90,
            capability_expires_at: 300,
            policy_not_before: 80,
            policy_expires_at: 400,
            channel_binding: [5; 32],
            session_commitment: [6; 32],
            authorization_revision: [21; 32],
        }
    }

    fn current(coordinates: OriginalPublicMutationCoordinatesV2, now: i64) -> Vec<u8> {
        encode_original_decision(
            b"original-request",
            coordinates,
            [[7; 32]; 4],
            PrincipalId::from_bytes([8; 16]),
            ProjectId::from_bytes([9; 16]),
            now,
        )
        .unwrap()
    }

    fn retained() -> Vec<u8> {
        let mut value = decode_decision(&current(coordinates(), 100)).unwrap();
        value.original_ticket = Some(OriginalTicketCoordinatesV2 {
            certificate_digest: [10; 32],
            holder_public_key: [11; 32],
            valid_after: 100,
            expires_at: 200,
            base_route_digest: [12; 32],
            pending_grant_digest: [13; 32],
        });
        serde_json::to_vec(&value).unwrap()
    }

    #[test]
    fn cold_replay_preserves_original_bytes_with_a_new_tls_session() {
        let directory =
            std::env::temp_dir().join(format!("aos-original-attach-{}", OperationId::new()));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = std::fs::metadata(&directory).unwrap().uid();
        let operation = OperationId::from_bytes([14; 16]);
        let original = retained();
        let (mut journal, _) = Journal::open_protected_at_uid(
            &directory,
            "decision.journal",
            crate::JournalLimits::default(),
            uid,
        )
        .unwrap();
        let transaction = JournalTransaction::new(
            [15; 16],
            vec![decision_record(operation, original.clone()).unwrap()],
        )
        .unwrap();
        journal.commit(&transaction).unwrap();
        let mut grant = [0; 416];
        grant[..8].copy_from_slice(b"AOSAPG01");
        retain_original_grant(&mut journal, [16; 32], &grant).unwrap();
        drop(journal);

        let (mut reopened, _) = Journal::open_protected_at_uid(
            &directory,
            "decision.journal",
            crate::JournalLimits::default(),
            uid,
        )
        .unwrap();
        let mut reconnected = coordinates();
        reconnected.session_commitment = [17; 32];
        reconnected.authorization_revision = [22; 32];
        let replay =
            retained_decision_record(&reopened, operation, &current(reconnected, 150)).unwrap();
        assert_eq!(replay.value(), Some(original.as_slice()));
        assert_eq!(original_grant(&reopened, [16; 32]).unwrap(), grant);
        retain_original_grant(&mut reopened, [16; 32], &grant).unwrap();
        grant[300] = 1;
        assert!(retain_original_grant(&mut reopened, [16; 32], &grant).is_err());

        for now in [99, 200, 301] {
            assert!(
                retained_decision_record(&reopened, operation, &current(reconnected, now)).is_err()
            );
        }
        reconnected.channel_binding = [18; 32];
        assert!(
            retained_decision_record(&reopened, operation, &current(reconnected, 150)).is_err()
        );
        reconnected = coordinates();
        reconnected.revocation_generation += 1;
        assert!(
            retained_decision_record(&reopened, operation, &current(reconnected, 150)).is_err()
        );
        let mut foreign = decode_decision(&current(coordinates(), 150)).unwrap();
        foreign.caller = PrincipalId::from_bytes([19; 16]);
        assert!(
            retained_decision_record(&reopened, operation, &serde_json::to_vec(&foreign).unwrap())
                .is_err()
        );
        foreign.caller = PrincipalId::from_bytes([8; 16]);
        foreign.project = ProjectId::from_bytes([20; 16]);
        assert!(
            retained_decision_record(&reopened, operation, &serde_json::to_vec(&foreign).unwrap())
                .is_err()
        );
        assert_eq!(
            reopened.get(RecordNamespace::PublicAttachRoute, &decision_key(operation)),
            Some(original.as_slice())
        );
        drop(reopened);
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn partial_unknown_and_unbound_decisions_cannot_be_accepted_records() {
        let bytes = retained();
        for length in 0..bytes.len() {
            assert!(decode_decision(&bytes[..length]).is_err());
        }
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["unknown"] = true.into();
        assert!(decode_decision(&serde_json::to_vec(&value).unwrap()).is_err());
        assert!(decision_record(OperationId::new(), current(coordinates(), 100)).is_err());
    }
}
