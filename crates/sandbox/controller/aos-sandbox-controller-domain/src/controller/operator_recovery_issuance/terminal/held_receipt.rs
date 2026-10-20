//! Version-two terminal receipt and exact predecessor custody.
//!
//! Existing physical/public receipt derivation remains authoritative. This
//! envelope adds the independently signed actual-held witness and original
//! Controller cut, and archives exact current/Effect/Operation bytes alongside
//! the existing predecessor projection. Neither codec constructs authority.
//!
//! ```text
//! receipt = AOSOTL02 | derived-AOSOTL01[336] | signed-held-header[652]
//!           | owner-witness[208] | predecessor-sequence:u64be | checksum[32]
//! archive = AOSOAR02 | completion-wall:i64be | receipt-digest[32]
//!           | length+old-archive | length+current | length+Effect
//!           | length+Operation | checksum[32]
//! ```

use aos_sandbox_protocol::operator_storage_repair_terminal_v4::RepairTerminalRequestV4;

use super::super::transport::HeldStorageTerminalV4;
use super::ledger_receipt::BoundRepairLedgerReceiptV1;
use super::*;

const RECEIPT_BYTES: usize = 1244;
const RECEIPT_DOMAIN: &[u8] = b"aos.sandbox.operator-repair-held-ledger-receipt.v2\0";
const ARCHIVE_DOMAIN: &[u8] = b"aos.sandbox.operator-repair-held-predecessor.v2\0";

pub(super) struct HeldRepairLedgerReceiptV2([u8; RECEIPT_BYTES]);

pub(super) struct ExactRepairPredecessorV2 {
    pub(super) completion_wall_seconds: i64,
    pub(super) projection: Vec<u8>,
    pub(super) current: Vec<u8>,
    pub(super) effect: Vec<u8>,
    pub(super) operation: Vec<u8>,
}

impl HeldRepairLedgerReceiptV2 {
    pub(super) fn bind(
        derived: BoundRepairLedgerReceiptV1,
        held: &HeldStorageTerminalV4<'_>,
        predecessor_sequence: u64,
    ) -> Result<Self, OperatorRecoveryIssuanceErrorV1> {
        let request = held.request();
        if request.proof_digest() != derived.proof_digest
            || request.signed_header()[444..460] != derived.fresh_request_id
            || request.signed_header()[460..492] != derived.fresh_packet_digest
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        let mut bytes = [0; RECEIPT_BYTES];
        bytes[..8].copy_from_slice(b"AOSOTL02");
        bytes[8..344].copy_from_slice(&derived.encode());
        bytes[344..996].copy_from_slice(request.signed_header());
        bytes[996..1204].copy_from_slice(held.witness().as_bytes());
        bytes[1204..1212].copy_from_slice(&predecessor_sequence.to_be_bytes());
        let checksum = hash(RECEIPT_DOMAIN, &[&bytes[..1212]]);
        bytes[1212..].copy_from_slice(&checksum);
        Ok(Self(bytes))
    }

    pub(super) fn verify(
        bytes: &[u8],
        signer: &ProtectedOperatorRecoverySignerV1,
        owner: &ProtectedStorageRepairReceiptVerifierV2,
    ) -> Result<Self, OperatorRecoveryIssuanceErrorV1> {
        let bytes: [u8; RECEIPT_BYTES] = bytes.try_into().map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        if &bytes[..8] != b"AOSOTL02"
            || bytes[1212..] != hash(RECEIPT_DOMAIN, &[&bytes[..1212]])
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        let derived = BoundRepairLedgerReceiptV1::decode(&bytes[8..344])?;
        let request = RepairTerminalRequestV4::verify_retained_signed_header(
            &bytes[344..996], signer.verifier(), signer.generation(),
        ).map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        owner.verify_terminal_witness_v4(&bytes[996..1204], &request)?;
        if request.proof_digest() != derived.proof_digest
            || request.signed_header()[444..460] != derived.fresh_request_id
            || request.signed_header()[460..492] != derived.fresh_packet_digest
            || u64::from_be_bytes(super::super::take_array(&bytes, 1204)?) == 0
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        Ok(Self(bytes))
    }

    pub(super) fn as_bytes(&self) -> &[u8] { &self.0 }

    pub(super) fn digest(&self) -> [u8; 32] { hash(RECEIPT_DOMAIN, &[&self.0]) }

    pub(super) fn derived(&self) -> Result<BoundRepairLedgerReceiptV1, OperatorRecoveryIssuanceErrorV1> {
        BoundRepairLedgerReceiptV1::decode(&self.0[8..344])
    }

    pub(super) fn predecessor_sequence(&self) -> Result<u64, OperatorRecoveryIssuanceErrorV1> {
        Ok(u64::from_be_bytes(super::super::take_array(&self.0, 1204)?))
    }

    pub(super) fn controller_cut(&self) -> [u8; 32] {
        let mut digest = [0; 32];
        digest.copy_from_slice(&self.0[344 + 412..344 + 444]);
        digest
    }

    pub(super) fn retained_request(&self, signer: &ProtectedOperatorRecoverySignerV1) -> Result<RepairTerminalRequestV4, OperatorRecoveryIssuanceErrorV1> {
        RepairTerminalRequestV4::verify_retained_signed_header(&self.0[344..996], signer.verifier(), signer.generation())
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)
    }

    pub(super) fn verify_exact_archive(
        &self,
        bytes: &[u8],
        predecessor_head: [u8; 32],
    ) -> Result<ExactRepairPredecessorV2, OperatorRecoveryIssuanceErrorV1> {
        // Journal replay has already enforced its configured record bound.
        // Each nested length must also fit the exact retained frame; no
        // allocation occurs until all four ranges have been checked.
        if bytes.len() < 48 + 4 * 4 + 32 || &bytes[..8] != b"AOSOAR02"
            || bytes[16..48] != self.digest()
            || bytes[bytes.len() - 32..] != hash(ARCHIVE_DOMAIN, &[&bytes[..bytes.len() - 32]])
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        let mut cursor = 48;
        let mut ranges = Vec::with_capacity(4);
        for _ in 0..4 {
            let length = u32::from_be_bytes(super::super::take_array(bytes, cursor)?) as usize;
            cursor = cursor.checked_add(4).ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
            let end = cursor.checked_add(length).filter(|end| *end <= bytes.len() - 32)
                .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
            if length == 0 { return Err(OperatorRecoveryIssuanceErrorV1::Binding); }
            ranges.push(cursor..end);
            cursor = end;
        }
        if cursor != bytes.len() - 32 { return Err(OperatorRecoveryIssuanceErrorV1::Binding); }
        let projection = self.derived()?.verify_exact_predecessor_archive_bytes(&bytes[ranges[0].clone()], predecessor_head)?;
        let current = bytes[ranges[1].clone()].to_vec();
        if hash(CURRENT_HEAD_DOMAIN_V2, &[&current]) != predecessor_head {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        Ok(ExactRepairPredecessorV2 {
            completion_wall_seconds: i64::from_be_bytes(super::super::take_array(bytes, 8)?),
            projection, current,
            effect: bytes[ranges[2].clone()].to_vec(), operation: bytes[ranges[3].clone()].to_vec(),
        })
    }
}

pub(super) fn exact_predecessor_archive(
    receipt: &HeldRepairLedgerReceiptV2,
    old_archive: &[u8],
    current: &[u8],
    effect: &[u8],
    operation: &[u8],
    completion_wall_seconds: i64,
) -> Result<Vec<u8>, OperatorRecoveryIssuanceErrorV1> {
    let mut bytes = b"AOSOAR02".to_vec();
    bytes.extend_from_slice(&completion_wall_seconds.to_be_bytes());
    bytes.extend_from_slice(&receipt.digest());
    for field in [old_archive, current, effect, operation] {
        if field.is_empty() {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        bytes.extend_from_slice(&u32::try_from(field.len()).map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?.to_be_bytes());
        bytes.extend_from_slice(field);
    }
    bytes.extend_from_slice(&hash(ARCHIVE_DOMAIN, &[&bytes]));
    Ok(bytes)
}
