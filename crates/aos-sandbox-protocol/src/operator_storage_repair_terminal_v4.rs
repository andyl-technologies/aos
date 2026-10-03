//! Signed terminal Repair continuation on the existing operator socket.
//!
//! These packets are claims, not authority constructors. Only the actual
//! Storage runtime/sidecar owner may issue a witness while retaining its cut;
//! Controller must independently pin that owner and retain the same child.
//! Physical V3 Prepare/Execute packets are unchanged.
//!
//! ```text
//! request = AOSORH04 | mode:u8 | zero[7] | request[16] | deadline:u64be
//!           | controller-generation:u64be | intent[364] | controller-cut[32]
//!           | query[16] | query-packet[32] | proof[32] | owner-pair[32]
//!           | inventory-digest[32] | signature[64] | inventory-length:u32be
//!           | exact-inventory
//! witness = AOSORW04 | request-cut[32] | owner[16] | owner-generation:u64be
//!           | controller-generation:u64be | epoch:u64be | runtime-cut[32]
//!           | inventory-digest[32] | signature[64]
//! settlement = AOSORA04 | disposition:u8 | zero[7] | request[16]
//!              | deadline:u64be | controller-generation:u64be
//!              | witness-digest[32] | terminal-commit[32] | receipt[32]
//!              | signature[64]
//! ```

use aos_sandbox_core::operator_recovery_effect::OPERATOR_RECOVERY_EFFECT_INTENT_BYTES;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

/// Maximum bounded terminal request, including complete Inventory.
pub const MAXIMUM_TERMINAL_REQUEST_BYTES_V4: usize = crate::MAXIMUM_RESPONSE_BYTES as usize + 1024;
/// Size of a signed owner-held witness.
pub const TERMINAL_WITNESS_BYTES_V4: usize = 208;
/// Size of an exact signed Controller settlement.
pub const TERMINAL_SETTLEMENT_BYTES_V4: usize = 208;
const REQUEST_HEADER: usize = 652;
const REQUEST_DOMAIN: &[u8] = b"aos.sandbox.operator-repair-held-request.v4\0";
const CUT_DOMAIN: &[u8] = b"aos.sandbox.operator-repair-held-cut.v4\0";
const INVENTORY_DOMAIN: &[u8] = b"aos.sandbox.operator-repair-held-inventory.v4\0";
const WITNESS_DOMAIN: &[u8] = b"aos.sandbox.operator-repair-held-witness.v4\0";
const SETTLEMENT_DOMAIN: &[u8] = b"aos.sandbox.operator-repair-held-settlement.v4\0";

/// Rejects an invalid canonical terminal packet or independently pinned signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid version-four Repair terminal continuation")]
pub struct RepairTerminalProtocolErrorV4;

/// Chooses fresh heldness or recovery of the same original cut.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairTerminalModeV4 {
    /// Atomically revalidates Inventory and reserves a new owner-held cut.
    Hold,
    /// Reacquires only an existing exact unresolved cut without new physical Apply.
    Recover,
}

/// Carries a Controller-signed original cut and its exact Inventory preimage.
pub struct RepairTerminalRequestV4 {
    header: [u8; REQUEST_HEADER],
    inventory: Vec<u8>,
}

impl RepairTerminalRequestV4 {
    /// Signs a bounded original request using an existing Controller Repair role.
    ///
    /// # Errors
    ///
    /// Rejects sentinel identities/generations/cuts, empty or oversized Inventory.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        mode: RepairTerminalModeV4,
        request: [u8; 16],
        deadline: u64,
        controller_generation: u64,
        intent: [u8; OPERATOR_RECOVERY_EFFECT_INTENT_BYTES],
        controller_cut: [u8; 32],
        query: [u8; 16],
        query_packet: [u8; 32],
        proof: [u8; 32],
        owner_pair: [u8; 32],
        inventory: Vec<u8>,
        key: &SigningKey,
    ) -> Result<Self, RepairTerminalProtocolErrorV4> {
        if request == [0; 16]
            || query == [0; 16]
            || deadline == 0
            || controller_generation == 0
            || intent == [0; OPERATOR_RECOVERY_EFFECT_INTENT_BYTES]
            || [controller_cut, query_packet, proof, owner_pair].contains(&[0; 32])
            || inventory.is_empty()
            || inventory.len() > crate::MAXIMUM_RESPONSE_BYTES as usize
        {
            return Err(RepairTerminalProtocolErrorV4);
        }
        let mode = match mode {
            RepairTerminalModeV4::Hold => 1,
            RepairTerminalModeV4::Recover => 2,
        };
        let mut header = [0; REQUEST_HEADER];
        let fields: &[&[u8]] = &[
            b"AOSORH04", &[mode], &[0; 7], &request,
            &deadline.to_be_bytes(), &controller_generation.to_be_bytes(),
            &intent, &controller_cut, &query, &query_packet, &proof, &owner_pair,
            &inventory_digest_v4(&inventory),
        ];
        let mut offset = 0;
        for field in fields {
            header[offset..offset + field.len()].copy_from_slice(field);
            offset += field.len();
        }
        let signature = key.sign(&message(REQUEST_DOMAIN, &header[..588]));
        header[588..].copy_from_slice(&signature.to_bytes());

        Ok(Self { header, inventory })
    }

    /// Decodes and verifies a packet against the independently configured Controller pin.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical bounds, a wrong key generation or signature, and a
    /// mismatched Inventory preimage. This does not establish a Storage hold.
    pub fn verify(
        bytes: &[u8],
        key: &VerifyingKey,
        generation: u64,
    ) -> Result<Self, RepairTerminalProtocolErrorV4> {
        if bytes.len() < REQUEST_HEADER + 4 || bytes.len() > MAXIMUM_TERMINAL_REQUEST_BYTES_V4
        {
            return Err(RepairTerminalProtocolErrorV4);
        }

        let header = array::<REQUEST_HEADER>(bytes, 0)?;
        Self::verify_retained_signed_header(&header, key, generation)?;
        let length = u32::from_be_bytes(array(bytes, REQUEST_HEADER)?) as usize;
        let expected_length = (REQUEST_HEADER + 4)
            .checked_add(length)
            .ok_or(RepairTerminalProtocolErrorV4)?;
        if bytes.len() != expected_length
            || length == 0
            || length > crate::MAXIMUM_RESPONSE_BYTES as usize
        {
            return Err(RepairTerminalProtocolErrorV4);
        }

        let inventory = bytes[REQUEST_HEADER + 4..].to_vec();
        if inventory_digest_v4(&inventory) != array(&header, 556)? {
            return Err(RepairTerminalProtocolErrorV4);
        }

        Ok(Self { header, inventory })
    }

    /// Verifies retained signed claims without reconstructing live Inventory.
    ///
    /// This historical view cannot establish heldness: its Inventory preimage
    /// is deliberately absent. Storage must separately reacquire its actual
    /// runtime and reobserve the full preimage from a live request.
    ///
    /// # Errors
    ///
    /// Rejects changed bounds, sentinel fields, generation or signature.
    pub fn verify_retained_signed_header(
        bytes: &[u8],
        key: &VerifyingKey,
        generation: u64,
    ) -> Result<Self, RepairTerminalProtocolErrorV4> {
        let header = array::<REQUEST_HEADER>(bytes, 0)?;
        if bytes.len() != REQUEST_HEADER
            || &header[..8] != b"AOSORH04"
            || !matches!(header[8], 1 | 2)
            || header[9..16] != [0; 7]
            || array::<16>(&header, 16)? == [0; 16]
            || array::<16>(&header, 444)? == [0; 16]
            || u64::from_be_bytes(array(&header, 32)?) == 0
            || generation == 0
            || u64::from_be_bytes(array(&header, 40)?) != generation
            || header[48..412] == [0; OPERATOR_RECOVERY_EFFECT_INTENT_BYTES]
            || [412, 460, 492, 524, 556].into_iter().any(|offset| {
                fixed::<32>(&header[offset..offset + 32]) == [0; 32]
            })
        {
            return Err(RepairTerminalProtocolErrorV4);
        }
        key.verify_strict(
            &message(REQUEST_DOMAIN, &header[..588]),
            &Signature::from_bytes(&array(&header, 588)?),
        ).map_err(|_| RepairTerminalProtocolErrorV4)?;

        Ok(Self { header, inventory: Vec::new() })
    }

    /// Returns the mode without granting a new physical attempt.
    #[must_use]
    pub fn mode(&self) -> RepairTerminalModeV4 {
        if self.header[8] == 1 {
            RepairTerminalModeV4::Hold
        } else {
            RepairTerminalModeV4::Recover
        }
    }

    /// Returns the original outer request identity.
    #[must_use]
    pub fn request_id(&self) -> [u8; 16] {
        fixed(&self.header[16..32])
    }

    /// Returns the kernel-boottime continuation deadline.
    #[must_use]
    pub fn deadline(&self) -> u64 {
        u64::from_be_bytes(fixed(&self.header[32..40]))
    }

    /// Returns the independently pinned Controller generation.
    #[must_use]
    pub fn controller_generation(&self) -> u64 {
        u64::from_be_bytes(fixed(&self.header[40..48]))
    }

    /// Returns the original signed Repair intent.
    #[must_use]
    pub fn signed_intent(&self) -> [u8; OPERATOR_RECOVERY_EFFECT_INTENT_BYTES] {
        fixed(&self.header[48..412])
    }

    /// Returns the exact Controller predecessor cut commitment.
    #[must_use]
    pub fn controller_cut(&self) -> [u8; 32] {
        fixed(&self.header[412..444])
    }

    /// Returns the exact physically revalidated Inventory preimage.
    #[must_use]
    pub fn inventory(&self) -> &[u8] {
        &self.inventory
    }

    /// Returns the signed complete Inventory commitment, including in historical claims.
    #[must_use]
    pub fn inventory_digest(&self) -> [u8; 32] {
        fixed(&self.header[556..588])
    }

    /// Returns the sealed Controller proof commitment.
    #[must_use]
    pub fn proof_digest(&self) -> [u8; 32] {
        fixed(&self.header[492..524])
    }

    /// Returns the exact owner evidence/receipt pair commitment.
    #[must_use]
    pub fn owner_pair_digest(&self) -> [u8; 32] {
        fixed(&self.header[524..556])
    }

    /// Returns a stable cut commitment independent of reconnect coordinates.
    #[must_use]
    pub fn cut_digest(&self) -> [u8; 32] {
        digest(CUT_DOMAIN, &self.header[40..588])
    }

    /// Returns the fixed signed claims retained by the owner sidecar.
    #[must_use]
    pub fn signed_header(&self) -> &[u8] {
        &self.header
    }

    /// Encodes the canonical request and Inventory preimage.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = self.header.to_vec();
        bytes.extend_from_slice(&(self.inventory.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.inventory);
        bytes
    }
}

/// Carries a signed actual-owner held cut; wire validation alone is nonauthorizing.
pub struct RepairTerminalWitnessV4([u8; TERMINAL_WITNESS_BYTES_V4]);

impl RepairTerminalWitnessV4 {
    /// Signs only the witness fields selected under actual Storage owner custody.
    ///
    /// # Errors
    ///
    /// Rejects sentinel owner/epoch/cuts or a zero owner generation.
    pub fn sign(
        request: &RepairTerminalRequestV4,
        owner: [u8; 16],
        owner_generation: u64,
        epoch: u64,
        runtime_cut: [u8; 32],
        key: &SigningKey,
    ) -> Result<Self, RepairTerminalProtocolErrorV4> {
        if owner == [0; 16] || owner_generation == 0 || epoch == 0 || runtime_cut == [0; 32] {
            return Err(RepairTerminalProtocolErrorV4);
        }
        let mut bytes = [0; TERMINAL_WITNESS_BYTES_V4];
        let fields: &[&[u8]] = &[
            b"AOSORW04", &request.cut_digest(), &owner,
            &owner_generation.to_be_bytes(), &request.controller_generation().to_be_bytes(),
            &epoch.to_be_bytes(), &runtime_cut, &request.inventory_digest(),
        ];
        let mut offset = 0;
        for field in fields {
            bytes[offset..offset + field.len()].copy_from_slice(field);
            offset += field.len();
        }

        let signature = key.sign(&message(WITNESS_DOMAIN, &bytes[..144]));
        bytes[144..].copy_from_slice(&signature.to_bytes());

        Ok(Self(bytes))
    }

    /// Verifies the exact original request and independently pinned owner role.
    ///
    /// # Errors
    ///
    /// Rejects changed request/owner/generation/Inventory or an invalid signature.
    pub fn verify(
        bytes: &[u8],
        request: &RepairTerminalRequestV4,
        owner: [u8; 16],
        generation: u64,
        key: &VerifyingKey,
    ) -> Result<Self, RepairTerminalProtocolErrorV4> {
        let packet = array::<TERMINAL_WITNESS_BYTES_V4>(bytes, 0)?;
        if bytes.len() != TERMINAL_WITNESS_BYTES_V4 || &packet[..8] != b"AOSORW04"
            || packet[8..40] != request.cut_digest()
            || packet[40..56] != owner
            || owner == [0; 16]
            || generation == 0
            || u64::from_be_bytes(array(&packet, 56)?) != generation
            || u64::from_be_bytes(array(&packet, 64)?) != request.controller_generation()
            || u64::from_be_bytes(array(&packet, 72)?) == 0
            || array::<32>(&packet, 80)? == [0; 32]
            || packet[112..144] != request.inventory_digest()
        {
            return Err(RepairTerminalProtocolErrorV4);
        }
        key.verify_strict(
            &message(WITNESS_DOMAIN, &packet[..144]),
            &Signature::from_bytes(&array(&packet, 144)?),
        ).map_err(|_| RepairTerminalProtocolErrorV4)?;

        Ok(Self(packet))
    }

    /// Returns the original signed witness bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the epoch retained in the actual owner sidecar.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        u64::from_be_bytes(fixed(&self.0[72..80]))
    }

    /// Returns the exact signed witness commitment.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        digest(WITNESS_DOMAIN, &self.0)
    }
}

/// Distinguishes exact durable public decisions from definite no-commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairTerminalDispositionV4 {
    /// The exact six-record Controller successor is durably present.
    Committed,
    /// The exact predecessor remains and the original successor is definitely absent.
    NotCommitted,
    /// The four-row original-precondition failure decision is durably present.
    ///
    /// Physical Storage Repair completed; the original public Operation cannot
    /// advance its replaced predecessor. This is not physical absence or rollback.
    OriginalPreconditionReplaced,
}

/// Carries the exact Controller writer's signed settlement ACK.
pub struct RepairTerminalSettlementV4([u8; TERMINAL_SETTLEMENT_BYTES_V4]);

impl RepairTerminalSettlementV4 {
    /// Signs a settlement only after actual protected Controller readback.
    ///
    /// # Errors
    ///
    /// Rejects sentinel request/deadline/generation or missing terminal commitments.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        disposition: RepairTerminalDispositionV4,
        request: [u8; 16],
        deadline: u64,
        generation: u64,
        witness: &RepairTerminalWitnessV4,
        terminal_commit: [u8; 32],
        receipt: [u8; 32],
        key: &SigningKey,
    ) -> Result<Self, RepairTerminalProtocolErrorV4> {
        if request == [0; 16]
            || deadline == 0
            || generation == 0
            || terminal_commit == [0; 32]
            || receipt == [0; 32]
        {
            return Err(RepairTerminalProtocolErrorV4);
        }

        let disposition = match disposition {
            RepairTerminalDispositionV4::Committed => 1,
            RepairTerminalDispositionV4::NotCommitted => 2,
            RepairTerminalDispositionV4::OriginalPreconditionReplaced => 3,
        };
        let mut bytes = [0; TERMINAL_SETTLEMENT_BYTES_V4];
        let fields: &[&[u8]] = &[
            b"AOSORA04", &[disposition], &[0; 7], &request,
            &deadline.to_be_bytes(), &generation.to_be_bytes(),
            &witness.digest(), &terminal_commit, &receipt,
        ];
        let mut offset = 0;
        for field in fields {
            bytes[offset..offset + field.len()].copy_from_slice(field);
            offset += field.len();
        }

        let signature = key.sign(&message(SETTLEMENT_DOMAIN, &bytes[..144]));
        bytes[144..].copy_from_slice(&signature.to_bytes());

        Ok(Self(bytes))
    }

    /// Verifies a signed ACK against the existing Controller pin and original witness.
    ///
    /// # Errors
    ///
    /// Rejects a different original request/generation/witness or signature.
    pub fn verify(
        bytes: &[u8],
        request: &RepairTerminalRequestV4,
        witness: &RepairTerminalWitnessV4,
        key: &VerifyingKey,
    ) -> Result<Self, RepairTerminalProtocolErrorV4> {
        let packet = array::<TERMINAL_SETTLEMENT_BYTES_V4>(bytes, 0)?;
        if bytes.len() != TERMINAL_SETTLEMENT_BYTES_V4
            || &packet[..8] != b"AOSORA04"
            || packet[9..16] != [0; 7]
            || !matches!(packet[8], 1 | 2 | 3)
            || packet[16..32] != request.request_id()
            || u64::from_be_bytes(array(&packet, 40)?) != request.controller_generation()
            || packet[48..80] != witness.digest()
            || u64::from_be_bytes(array(&packet, 32)?) == 0
            || u64::from_be_bytes(array(&packet, 32)?) > request.deadline()
            || array::<32>(&packet, 80)? == [0; 32]
            || array::<32>(&packet, 112)? == [0; 32]
        {
            return Err(RepairTerminalProtocolErrorV4);
        }
        key.verify_strict(
            &message(SETTLEMENT_DOMAIN, &packet[..144]),
            &Signature::from_bytes(&array(&packet, 144)?),
        ).map_err(|_| RepairTerminalProtocolErrorV4)?;

        Ok(Self(packet))
    }

    /// Returns the authenticated settlement disposition.
    #[must_use]
    pub fn disposition(&self) -> RepairTerminalDispositionV4 {
        match self.0[8] {
            1 => RepairTerminalDispositionV4::Committed,
            3 => RepairTerminalDispositionV4::OriginalPreconditionReplaced,
            _ => RepairTerminalDispositionV4::NotCommitted,
        }
    }

    /// Returns the original canonical ACK bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the exact kernel-boottime ACK deadline.
    #[must_use]
    pub fn deadline(&self) -> u64 {
        u64::from_be_bytes(fixed(&self.0[32..40]))
    }

    /// Returns the exact terminal transaction commitment acknowledged by Controller.
    #[must_use]
    pub fn terminal_commit(&self) -> [u8; 32] {
        fixed(&self.0[80..112])
    }

    /// Returns the exact terminal receipt commitment acknowledged by Controller.
    #[must_use]
    pub fn receipt_digest(&self) -> [u8; 32] {
        fixed(&self.0[112..144])
    }
}

/// Verifies the owner-signed readback of one exact Controller ACK.
///
/// This historical readback does not establish live heldness or authorize a
/// new Apply. The owner emits it only after durable settlement of that ACK.
///
/// # Errors
///
/// Rejects any substituted ACK, wrong size, owner key or signature.
pub fn verify_terminal_release_v4(
    bytes: &[u8],
    ack: &[u8],
    owner: &VerifyingKey,
) -> Result<(), RepairTerminalProtocolErrorV4> {
    if ack.len() != TERMINAL_SETTLEMENT_BYTES_V4
        || bytes.len() != TERMINAL_SETTLEMENT_BYTES_V4 + 64
        || &bytes[..TERMINAL_SETTLEMENT_BYTES_V4] != ack
    {
        return Err(RepairTerminalProtocolErrorV4);
    }
    owner.verify_strict(
        &message(b"aos.sandbox.operator-repair-owner-release.v4\0", ack),
        &Signature::from_bytes(&array(bytes, TERMINAL_SETTLEMENT_BYTES_V4)?),
    ).map_err(|_| RepairTerminalProtocolErrorV4)
}

/// Commits complete physical Inventory bytes under the terminal domain.
#[must_use]
pub fn inventory_digest_v4(bytes: &[u8]) -> [u8; 32] {
    digest(INVENTORY_DOMAIN, bytes)
}

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update(domain).chain_update(bytes).finalize().into()
}

fn message(domain: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(domain.len() + bytes.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(bytes);
    message
}

fn array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], RepairTerminalProtocolErrorV4> {
    let end = offset.checked_add(N).ok_or(RepairTerminalProtocolErrorV4)?;
    bytes.get(offset..end)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(RepairTerminalProtocolErrorV4)
}

fn fixed<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut result = [0; N];
    result.copy_from_slice(bytes);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // These fixtures exercise canonical claims only, never actual heldness.
    fn request(mode: RepairTerminalModeV4, id: [u8; 16], deadline: u64) -> RepairTerminalRequestV4 {
        RepairTerminalRequestV4::sign(
            mode, id, deadline, 3, [4; OPERATOR_RECOVERY_EFFECT_INTENT_BYTES],
            [5; 32], [6; 16], [7; 32], [8; 32], [9; 32],
            b"exact inventory preimage".to_vec(), &SigningKey::from_bytes(&[1; 32]),
        ).unwrap()
    }

    #[test]
    fn reconnect_changes_only_outer_coordinates_and_never_recreates_inventory() {
        let original = request(RepairTerminalModeV4::Hold, [10; 16], 100);
        let reconnect = request(RepairTerminalModeV4::Recover, [11; 16], 200);
        let controller = SigningKey::from_bytes(&[1; 32]).verifying_key();

        assert_eq!(original.cut_digest(), reconnect.cut_digest());
        assert_ne!(original.signed_header(), reconnect.signed_header());
        let historical = RepairTerminalRequestV4::verify_retained_signed_header(
            original.signed_header(), &controller, 3,
        ).unwrap();

        assert!(historical.inventory().is_empty());
        assert_eq!(historical.inventory_digest(), original.inventory_digest());
        assert!(RepairTerminalRequestV4::verify(&historical.encode(), &controller, 3).is_err());
        assert_eq!(
            RepairTerminalRequestV4::verify(&reconnect.encode(), &controller, 3).unwrap().mode(),
            RepairTerminalModeV4::Recover,
        );
    }

    #[test]
    fn request_rejects_truncation_extra_bytes_wrong_roles_and_substituted_preimage() {
        let original = request(RepairTerminalModeV4::Hold, [10; 16], 100);
        let controller = SigningKey::from_bytes(&[1; 32]).verifying_key();
        let wrong_key = SigningKey::from_bytes(&[2; 32]).verifying_key();
        let encoded = original.encode();

        for end in [0, 8, 588, REQUEST_HEADER, encoded.len() - 1] {
            assert!(RepairTerminalRequestV4::verify(&encoded[..end], &controller, 3).is_err());
        }
        assert!(RepairTerminalRequestV4::verify(&encoded, &wrong_key, 3).is_err());
        assert!(RepairTerminalRequestV4::verify(&encoded, &controller, 4).is_err());

        let mut extra = encoded.clone();
        extra.push(0);
        assert!(RepairTerminalRequestV4::verify(&extra, &controller, 3).is_err());

        let mut replaced = encoded;
        replaced[REQUEST_HEADER + 4] ^= 1;
        assert!(RepairTerminalRequestV4::verify(&replaced, &controller, 3).is_err());
    }

    #[test]
    fn valid_signature_does_not_allow_sentinel_or_reserved_header_claims() {
        let key = SigningKey::from_bytes(&[1; 32]);
        let original = request(RepairTerminalModeV4::Hold, [10; 16], 100);
        for (start, end) in [(16, 32), (32, 40), (48, 412), (412, 444), (556, 588)] {
            let mut header = original.header;
            header[start..end].fill(0);
            let signature = key.sign(&message(REQUEST_DOMAIN, &header[..588]));
            header[588..].copy_from_slice(&signature.to_bytes());

            assert!(RepairTerminalRequestV4::verify_retained_signed_header(
                &header, &key.verifying_key(), 3,
            ).is_err());
        }

        let mut header = original.header;
        header[9] = 1;
        let signature = key.sign(&message(REQUEST_DOMAIN, &header[..588]));
        header[588..].copy_from_slice(&signature.to_bytes());
        assert!(RepairTerminalRequestV4::verify_retained_signed_header(
            &header, &key.verifying_key(), 3,
        ).is_err());
    }

    #[test]
    fn witness_requires_exact_cut_owner_epoch_and_complete_signed_frame() {
        let owner_key = SigningKey::from_bytes(&[2; 32]);
        let original = request(RepairTerminalModeV4::Hold, [10; 16], 100);
        let witness = RepairTerminalWitnessV4::sign(&original, [12; 16], 13, 14, [15; 32], &owner_key).unwrap();

        let verified = RepairTerminalWitnessV4::verify(
            witness.as_bytes(), &original, [12; 16], 13, &owner_key.verifying_key(),
        ).unwrap();
        assert_eq!(verified.epoch(), 14);
        assert!(RepairTerminalWitnessV4::verify(
            witness.as_bytes(), &original, [16; 16], 13, &owner_key.verifying_key(),
        ).is_err());
        assert!(RepairTerminalWitnessV4::verify(
            &witness.as_bytes()[..207], &original, [12; 16], 13, &owner_key.verifying_key(),
        ).is_err());

        for offset in [8, 72, 80, 112, 144] {
            let mut changed = witness.0;
            changed[offset] ^= 1;
            assert!(RepairTerminalWitnessV4::verify(
                &changed, &original, [12; 16], 13, &owner_key.verifying_key(),
            ).is_err());
        }
    }

    #[test]
    fn exact_ack_and_owner_release_cannot_be_replaced_by_old_success() {
        let controller = SigningKey::from_bytes(&[1; 32]);
        let owner = SigningKey::from_bytes(&[2; 32]);
        let original = request(RepairTerminalModeV4::Hold, [10; 16], 100);
        let witness = RepairTerminalWitnessV4::sign(&original, [12; 16], 13, 14, [15; 32], &owner).unwrap();
        let ack = RepairTerminalSettlementV4::sign(
            RepairTerminalDispositionV4::NotCommitted, original.request_id(), 100, 3,
            &witness, [16; 32], [17; 32], &controller,
        ).unwrap();

        assert_eq!(RepairTerminalSettlementV4::verify(
            ack.as_bytes(), &original, &witness, &controller.verifying_key(),
        ).unwrap().disposition(), RepairTerminalDispositionV4::NotCommitted);
        let renewed = RepairTerminalSettlementV4::sign(
            RepairTerminalDispositionV4::Committed, original.request_id(), 101, 3,
            &witness, [16; 32], [17; 32], &controller,
        ).unwrap();
        assert!(RepairTerminalSettlementV4::verify(
            renewed.as_bytes(), &original, &witness, &controller.verifying_key(),
        ).is_err());

        let mut readback = ack.as_bytes().to_vec();
        let signature = owner.sign(&message(b"aos.sandbox.operator-repair-owner-release.v4\0", ack.as_bytes()));
        readback.extend_from_slice(&signature.to_bytes());
        assert!(verify_terminal_release_v4(&readback, ack.as_bytes(), &owner.verifying_key()).is_ok());
        assert!(verify_terminal_release_v4(&readback[..271], ack.as_bytes(), &owner.verifying_key()).is_err());
        readback[8] = 1;
        assert!(verify_terminal_release_v4(&readback, ack.as_bytes(), &owner.verifying_key()).is_err());
    }

    #[test]
    fn failure_disposition_is_signed_and_cannot_reuse_success_ack() {
        let controller = SigningKey::from_bytes(&[1; 32]);
        let owner = SigningKey::from_bytes(&[2; 32]);
        let original = request(RepairTerminalModeV4::Hold, [10; 16], 100);
        let witness = RepairTerminalWitnessV4::sign(
            &original, [12; 16], 13, 14, [15; 32], &owner,
        ).unwrap();
        let failure = RepairTerminalSettlementV4::sign(
            RepairTerminalDispositionV4::OriginalPreconditionReplaced,
            original.request_id(), 100, 3, &witness, [16; 32], [17; 32], &controller,
        ).unwrap();

        assert_eq!(RepairTerminalSettlementV4::verify(
            failure.as_bytes(), &original, &witness, &controller.verifying_key(),
        ).unwrap().disposition(), RepairTerminalDispositionV4::OriginalPreconditionReplaced);

        for disposition in [1, 2, 4] {
            let mut substituted = failure.as_bytes().to_vec();
            substituted[8] = disposition;
            assert!(RepairTerminalSettlementV4::verify(
                &substituted, &original, &witness, &controller.verifying_key(),
            ).is_err());
        }
    }

    #[test]
    fn inventory_ceiling_is_complete_not_a_truncated_prefix() {
        let controller = SigningKey::from_bytes(&[1; 32]);
        let mut original = request(RepairTerminalModeV4::Hold, [10; 16], 100);
        original.inventory = vec![21; crate::MAXIMUM_RESPONSE_BYTES as usize];
        original.header[556..588].copy_from_slice(&inventory_digest_v4(&original.inventory));
        let signature = controller.sign(&message(REQUEST_DOMAIN, &original.header[..588]));
        original.header[588..].copy_from_slice(&signature.to_bytes());

        assert_eq!(RepairTerminalRequestV4::verify(
            &original.encode(), &controller.verifying_key(), 3,
        ).unwrap().inventory().len(), crate::MAXIMUM_RESPONSE_BYTES as usize);

        original.inventory.push(21);
        original.header[556..588].copy_from_slice(&inventory_digest_v4(&original.inventory));
        let signature = controller.sign(&message(REQUEST_DOMAIN, &original.header[..588]));
        original.header[588..].copy_from_slice(&signature.to_bytes());
        assert!(RepairTerminalRequestV4::verify(
            &original.encode(), &controller.verifying_key(), 3,
        ).is_err());
    }
}
