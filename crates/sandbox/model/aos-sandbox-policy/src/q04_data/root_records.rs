//! Canonical Root Q04 record grammar and nonissuing capacity recipes.
//!
//! These exact key/phase/decision encodings contain historical DATA. Native
//! Authority independently supplies actual owner/currentness/eligibility and
//! never accepts a shaped future record as evidence that an event occurred.

use super::{
    PolicyQ04DataErrorV1, Q04AcknowledgementKindV1, encode_q04_acknowledgement_data_v1, fixed,
};
use aos_sandbox_model::{ObjectDigest, RecordNamespace};
use aos_sandbox_protocol::domain_ledger::create_q04_history::{
    DECISION_BYTES, PHASE_BYTES, Q04CutIdentityV1, Q04PhaseOwnerV1, Q04PhaseRecordV1,
    Q04RootDecisionV1,
};
use aos_sandbox_protocol::domain_ledger::transaction::JournalRecord;

/// Selects one existing fixed Root Q04 key shape as nonauthorizing DATA.
#[derive(Clone, Copy)]
pub enum RootQ04RecordKeyV1 {
    /// Names the original immutable cut.
    Cut,
    /// Names one of the seven Root phases.
    Phase(u8),
    /// Names the Root decision record.
    Decision,
    /// Names one of the four authenticated ACK packets.
    Packet(u8),
    /// Names the complete Claim framing record.
    ClaimIndex,
    /// Names one bounded Claim chunk.
    ClaimChunk(u16),
}

impl RootQ04RecordKeyV1 {
    /// Returns the unchanged fixed key domain.
    #[must_use]
    pub fn prefix(self) -> &'static [u8] {
        match self {
            Self::Cut => b"\0aos-q04-root-cut-v1\0",
            Self::Phase(_) => b"\0aos-q04-root-phase-v1\0",
            Self::Decision => b"\0aos-q04-root-decision-v1\0",
            Self::Packet(_) => b"\0aos-q04-root-packet-v1\0",
            Self::ClaimIndex => b"\0aos-q04-root-claim-index-v1\0",
            Self::ClaimChunk(_) => b"\0aos-q04-root-claim-v1\0",
        }
    }

    /// Decodes a canonical Root Q04 key without native provenance.
    ///
    /// # Errors
    /// Refuses a foreign prefix, zero nonce, unsupported phase or wrong width.
    pub fn decode_key_v1(bytes: &[u8]) -> Result<(Self, [u8; 16]), PolicyQ04DataErrorV1> {
        for shape in [
            Self::Cut,
            Self::Phase(1),
            Self::Decision,
            Self::Packet(1),
            Self::ClaimIndex,
            Self::ClaimChunk(0),
        ] {
            let Some(tail) = bytes.strip_prefix(shape.prefix()) else {
                continue;
            };
            let suffix = match shape {
                Self::Phase(_) | Self::Packet(_) => 1,
                Self::ClaimChunk(_) => 2,
                _ => 0,
            };
            if tail.len() != 16 + suffix {
                return Err(PolicyQ04DataErrorV1::ChangedCut);
            }
            let nonce: [u8; 16] = tail[..16]
                .try_into()
                .map_err(|_| PolicyQ04DataErrorV1::Bounds)?;
            if nonce == [0; 16] {
                return Err(PolicyQ04DataErrorV1::ChangedCut);
            }
            let value = match shape {
                Self::Phase(_) if (1..=7).contains(&tail[16]) => Self::Phase(tail[16]),
                Self::Packet(_) if (1..=4).contains(&tail[16]) => Self::Packet(tail[16]),
                Self::Phase(_) | Self::Packet(_) => return Err(PolicyQ04DataErrorV1::ChangedCut),
                Self::ClaimChunk(_) => Self::ClaimChunk(u16::from_be_bytes([tail[16], tail[17]])),
                _ => shape,
            };
            return Ok((value, nonce));
        }
        Err(PolicyQ04DataErrorV1::ChangedCut)
    }

    /// Encodes the selected canonical key and supplied historical nonce.
    ///
    /// # Errors
    /// Refuses zero nonce, unsupported phase or bounded allocation failure.
    pub fn encode(self, nonce: [u8; 16]) -> Result<Vec<u8>, PolicyQ04DataErrorV1> {
        let prefix = self.prefix();
        if nonce == [0; 16]
            || matches!(
                self,
                Self::Phase(0 | 8..=u8::MAX) | Self::Packet(0 | 5..=u8::MAX)
            )
        {
            return Err(PolicyQ04DataErrorV1::ChangedCut);
        }
        let mut key = Vec::new();
        key.try_reserve_exact(prefix.len() + 18)?;
        key.extend_from_slice(prefix);
        key.extend_from_slice(&nonce);
        match self {
            Self::Phase(phase) | Self::Packet(phase) => key.push(phase),
            Self::ClaimChunk(chunk) => key.extend_from_slice(&chunk.to_be_bytes()),
            _ => {}
        }
        Ok(key)
    }
}

/// Encodes an existing Root row as passive canonical DATA.
///
/// # Errors
/// Refuses noncanonical fields, exhausted bounds or actual allocation failure.
pub fn root_record(
    key: RootQ04RecordKeyV1,
    identity: &Q04CutIdentityV1,
    value: &[u8],
) -> Result<JournalRecord, PolicyQ04DataErrorV1> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(value.len())?;
    bytes.extend_from_slice(value);
    Ok(JournalRecord::put(
        RecordNamespace::DesiredState,
        key.encode(identity.nonce())?,
        bytes,
    ))
}

/// Derives one fixed-width nonzero representative for capacity preflight.
///
/// # Errors
/// Refuses noncanonical fields, exhausted bounds or actual allocation failure.
pub fn capacity_shape_digest(
    identity: &Q04CutIdentityV1,
    field: u8,
) -> Result<ObjectDigest, PolicyQ04DataErrorV1> {
    use sha2::{Digest as _, Sha256};

    let digest = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.create-q04.capacity-shape.v1\0")
            .chain_update(identity.bytes())
            .chain_update([field])
            .finalize()
            .into(),
    );
    if digest.as_bytes() == &[0; 32] {
        return Err(PolicyQ04DataErrorV1::ChangedCut);
    }
    Ok(digest)
}

/// Derives the unchanged Root Claim-group transaction identifier.
///
/// # Errors
/// Refuses noncanonical fields, exhausted bounds or actual allocation failure.
pub fn root_claim_group_id(
    identity: &Q04CutIdentityV1,
    group: u16,
    intent: ObjectDigest,
) -> Result<[u8; 16], PolicyQ04DataErrorV1> {
    use sha2::{Digest as _, Sha256};

    let digest = Sha256::new()
        .chain_update(b"aos.sandbox.create-q04.transaction.root-claim-group.v1\0")
        .chain_update(identity.digest().as_bytes())
        .chain_update(group.to_be_bytes())
        .chain_update(intent.as_bytes())
        .finalize();
    let id = fixed(&digest, 0);
    if id == [0; 16] {
        return Err(PolicyQ04DataErrorV1::ChangedCut);
    }
    Ok(id)
}

/// Builds the existing canonical Root phase from comparison fields.
///
/// # Errors
/// Refuses noncanonical fields, exhausted bounds or actual allocation failure.
#[allow(clippy::too_many_arguments)]
pub fn root_phase_record(
    identity: &Q04CutIdentityV1,
    phase: u8,
    transaction: [u8; 16],
    before: ObjectDigest,
    predecessor: Option<ObjectDigest>,
    events: [ObjectDigest; 5],
    pairs: [ObjectDigest; 6],
    acknowledgement: Option<ObjectDigest>,
) -> Result<Q04PhaseRecordV1, PolicyQ04DataErrorV1> {
    let mut body = [0; PHASE_BYTES];
    body[16..48].copy_from_slice(identity.digest().as_bytes());
    body[48..64].copy_from_slice(&identity.stage_id());
    if let Some(predecessor) = predecessor {
        body[64..96].copy_from_slice(predecessor.as_bytes());
    }
    for (index, event) in events.into_iter().enumerate() {
        body[96 + index * 32..128 + index * 32].copy_from_slice(event.as_bytes());
    }
    for (index, pair) in pairs.into_iter().enumerate() {
        if index % 2 == 0 || phase >= 6 {
            body[288 + index * 32..320 + index * 32].copy_from_slice(pair.as_bytes());
        }
    }
    if let Some(acknowledgement) = acknowledgement {
        body[480..512].copy_from_slice(acknowledgement.as_bytes());
    }
    body[512..544].copy_from_slice(before.as_bytes());
    body[544..560].copy_from_slice(&transaction);
    Ok(Q04PhaseRecordV1::from_body(
        Q04PhaseOwnerV1::Root,
        phase,
        body,
        identity,
    )?)
}

/// Builds the existing canonical Root decision from comparison fields.
///
/// # Errors
/// Refuses noncanonical fields, exhausted bounds or actual allocation failure.
pub fn root_decision_record(
    identity: &Q04CutIdentityV1,
    earlier_authority_transaction: [u8; 16],
    state_commit_sequence: u64,
    authority_before_sequence: u64,
    source_held: ObjectDigest,
    cache_held: ObjectDigest,
) -> Result<Q04RootDecisionV1, PolicyQ04DataErrorV1> {
    let mut body = [0; DECISION_BYTES];
    body[16..48].copy_from_slice(identity.digest().as_bytes());
    body[48..64].copy_from_slice(&earlier_authority_transaction);
    body[64..80].copy_from_slice(&identity.publication_id());
    body[80..112].copy_from_slice(identity.policy_transaction().as_bytes());
    body[112..120].copy_from_slice(&state_commit_sequence.to_be_bytes());
    body[120..152].copy_from_slice(identity.policy_current().as_bytes());
    body[152..184].copy_from_slice(identity.binding().as_bytes());
    body[184..216].copy_from_slice(identity.gate_identity().as_bytes());
    body[216..248].copy_from_slice(source_held.as_bytes());
    body[248..280].copy_from_slice(cache_held.as_bytes());
    body[280..312].copy_from_slice(identity.cache_quota().as_bytes());
    body[312..320].copy_from_slice(&authority_before_sequence.to_be_bytes());
    body[320..352].copy_from_slice(identity.before_controller_rows().as_bytes());
    Ok(Q04RootDecisionV1::from_body(body, identity)?)
}

/// Builds a nonauthenticating fixed-width future ACK capacity representative.
///
/// # Errors
/// Refuses noncanonical fields, exhausted bounds or actual allocation failure.
pub fn root_capacity_acknowledgement(
    output: &mut Vec<u8>,
    kind: Q04AcknowledgementKindV1,
    identity: &Q04CutIdentityV1,
    controller_before_sequence: u64,
    consumed_gate: ObjectDigest,
    pairs: [ObjectDigest; 6],
) -> Result<(), PolicyQ04DataErrorV1> {
    if !output.is_empty() {
        return Err(PolicyQ04DataErrorV1::ChangedCut);
    }
    let frames = match kind {
        Q04AcknowledgementKindV1::Policy => 9,
        Q04AcknowledgementKindV1::Release => 15,
        Q04AcknowledgementKindV1::Settlement => 20,
        Q04AcknowledgementKindV1::Clearance => 27,
    };
    let next_sequence = controller_before_sequence
        .checked_add(frames)
        .ok_or(PolicyQ04DataErrorV1::Bounds)?;
    let clear_fields = if kind == Q04AcknowledgementKindV1::Clearance {
        Some([
            capacity_shape_digest(identity, 9)?,
            capacity_shape_digest(identity, 10)?,
            capacity_shape_digest(identity, 11)?,
            capacity_shape_digest(identity, 12)?,
        ])
    } else {
        None
    };
    encode_q04_acknowledgement_data_v1(
        output,
        kind,
        identity,
        next_sequence,
        consumed_gate,
        pairs,
        clear_fields,
    )?;
    output.extend_from_slice(&[0; 64]);
    Ok(())
}
