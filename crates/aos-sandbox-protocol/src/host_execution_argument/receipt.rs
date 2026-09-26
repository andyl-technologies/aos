//! Canonical Host argument-observation receipts for methods 37 and 38.
//!
//! AOSHAR01 carries a Host-attested fresh Guest packet. AOSHQR01 carries only
//! historical digests after cold recovery; decoding either format is structural
//! and never substitutes for an authenticated Host broker outcome.
//!
//! ```text
//! AOSHAR01 || AOSCIA02[336] || runtime-handle[32] || Host-custody[32]
//!          || custody-sequence:u64be || Guest-session[32]
//!          || request-SHA256[32] || packet-SHA256[32] || ARG_MAX:u64be
//!          || request-length:u16be || packet-length:u16be
//!          || exact-Guest-request || exact-signed-Guest-packet
//!          || SHA256(domain || preceding)[32]
//! AOSHQR01 || AOSCIA02[336] || status:u8 || request-SHA256[32]
//!          || packet-SHA256[32] || Host-custody[32] || sequence:u64be
//!          || SHA256(domain || preceding)[32]
//! ```

use aos_sandbox_agent::{GuestRuntimeArgumentObserveRequestV1, GuestRuntimeArgumentReadbackV1};
use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::semantics::host_execution_argument::canonical_attempt_request_id_v1;

use super::HOST_EXECUTION_ARGUMENT_ATTEMPT_BYTES_V1;

const FRESH_MAGIC: &[u8; 8] = b"AOSHAR01";
const HISTORICAL_MAGIC: &[u8; 8] = b"AOSHQR01";
const FRESH_DOMAIN: &[u8] = b"aos.sandbox.host-argument-fresh-receipt.v1\0";
const HISTORICAL_DOMAIN: &[u8] = b"aos.sandbox.host-argument-historical-receipt.v1\0";
const MAXIMUM_GUEST_REQUEST_BYTES: usize = 512;
const MAXIMUM_SIGNED_GUEST_PACKET_BYTES: usize = 1024;
const FRESH_FIXED_BYTES: usize = 556;
const HISTORICAL_BYTES: usize = 481;

/// Maximum bounded canonical Host argument-observation receipt size.
pub const MAXIMUM_HOST_ARGUMENT_FRESH_RECEIPT_BYTES_V1: usize =
    FRESH_FIXED_BYTES + MAXIMUM_GUEST_REQUEST_BYTES + MAXIMUM_SIGNED_GUEST_PACKET_BYTES;

/// Reports malformed or internally inconsistent Host argument receipt bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HostExecutionArgumentReceiptErrorV1 {
    /// The receipt is not canonical or its Guest request and packet disagree.
    #[error("Host argument receipt is not canonical")]
    InvalidReceipt,
}

/// Retains a structurally checked fresh Host observation without granting authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostExecutionArgumentFreshReceiptV1 {
    source: [u8; HOST_EXECUTION_ARGUMENT_ATTEMPT_BYTES_V1],
    runtime_handle: ObjectDigest,
    custody_digest: ObjectDigest,
    custody_sequence: u64,
    session_binding: ObjectDigest,
    request_digest: ObjectDigest,
    packet_digest: ObjectDigest,
    argument_limit_bytes: u64,
    canonical_request: Vec<u8>,
    signed_packet: Vec<u8>,
}

impl HostExecutionArgumentFreshReceiptV1 {
    /// Builds a receipt from an already verified Guest packet and protected Host custody.
    ///
    /// This constructor is nonauthorizing. The caller must verify the Guest
    /// signature with the fixed protected peer key, retain the live session,
    /// revalidate Host currentness, and sign the broker outcome separately.
    ///
    /// # Errors
    ///
    /// Rejects a mismatched source, session, runtime, packet, or custody field.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source: [u8; HOST_EXECUTION_ARGUMENT_ATTEMPT_BYTES_V1],
        runtime_handle: ObjectDigest,
        custody_digest: ObjectDigest,
        custody_sequence: u64,
        request: &GuestRuntimeArgumentObserveRequestV1,
        signed_packet: &[u8],
        verified: &GuestRuntimeArgumentReadbackV1,
    ) -> Result<Self, HostExecutionArgumentReceiptErrorV1> {
        let canonical_request = request.encode();
        let request_digest = ObjectDigest::from_bytes(Sha256::digest(&canonical_request).into());
        let packet_digest = ObjectDigest::from_bytes(Sha256::digest(signed_packet).into());
        let receipt = Self {
            source,
            runtime_handle,
            custody_digest,
            custody_sequence,
            session_binding: request.session().digest(),
            request_digest,
            packet_digest,
            argument_limit_bytes: verified.evidence().runtime_limit_bytes(),
            canonical_request,
            signed_packet: signed_packet.to_vec(),
        };
        if verified.packet_digest() != packet_digest
            || verified.evidence().runtime_profile() != request.profile()
            || verified.evidence().runtime_profile_commitment() != request.profile_commitment()
            || !receipt.is_consistent()
        {
            return Err(HostExecutionArgumentReceiptErrorV1::InvalidReceipt);
        }
        Ok(receipt)
    }

    /// Decodes a canonical receipt for later comparison to an authenticated outcome.
    ///
    /// The Guest signature is not independently verified here. The Controller
    /// must pin the Host broker role, key generation, original signed attempt,
    /// and protected source before accepting the Host attestation.
    ///
    /// # Errors
    ///
    /// Rejects malformed bounds, source, duplicate fields, packet, or checksum.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, HostExecutionArgumentReceiptErrorV1> {
        if bytes.len() < FRESH_FIXED_BYTES
            || bytes.len() > MAXIMUM_HOST_ARGUMENT_FRESH_RECEIPT_BYTES_V1
            || bytes.get(..8) != Some(FRESH_MAGIC.as_slice())
        {
            return Err(HostExecutionArgumentReceiptErrorV1::InvalidReceipt);
        }
        let mut cursor = &bytes[8..];
        let source = take::<HOST_EXECUTION_ARGUMENT_ATTEMPT_BYTES_V1>(&mut cursor)?;
        let runtime_handle = ObjectDigest::from_bytes(take(&mut cursor)?);
        let custody_digest = ObjectDigest::from_bytes(take(&mut cursor)?);
        let custody_sequence = u64::from_be_bytes(take(&mut cursor)?);
        let session_binding = ObjectDigest::from_bytes(take(&mut cursor)?);
        let request_digest = ObjectDigest::from_bytes(take(&mut cursor)?);
        let packet_digest = ObjectDigest::from_bytes(take(&mut cursor)?);
        let argument_limit_bytes = u64::from_be_bytes(take(&mut cursor)?);
        let request_length = usize::from(u16::from_be_bytes(take(&mut cursor)?));
        let packet_length = usize::from(u16::from_be_bytes(take(&mut cursor)?));
        if request_length > MAXIMUM_GUEST_REQUEST_BYTES
            || packet_length > MAXIMUM_SIGNED_GUEST_PACKET_BYTES
            || cursor.len() != request_length + packet_length + 32
        {
            return Err(HostExecutionArgumentReceiptErrorV1::InvalidReceipt);
        }
        let canonical_request = take_slice(&mut cursor, request_length)?.to_vec();
        let signed_packet = take_slice(&mut cursor, packet_length)?.to_vec();
        let checksum = take::<32>(&mut cursor)?;
        if !cursor.is_empty()
            || checksum != receipt_checksum(FRESH_DOMAIN, &bytes[..bytes.len() - 32])
        {
            return Err(HostExecutionArgumentReceiptErrorV1::InvalidReceipt);
        }
        let receipt = Self {
            source,
            runtime_handle,
            custody_digest,
            custody_sequence,
            session_binding,
            request_digest,
            packet_digest,
            argument_limit_bytes,
            canonical_request,
            signed_packet,
        };
        if !receipt.is_consistent() {
            return Err(HostExecutionArgumentReceiptErrorV1::InvalidReceipt);
        }
        Ok(receipt)
    }

    /// Encodes the exact canonical Host-signed response body content.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            FRESH_FIXED_BYTES + self.canonical_request.len() + self.signed_packet.len(),
        );
        bytes.extend_from_slice(FRESH_MAGIC);
        bytes.extend_from_slice(&self.source);
        bytes.extend_from_slice(self.runtime_handle.as_bytes());
        bytes.extend_from_slice(self.custody_digest.as_bytes());
        bytes.extend_from_slice(&self.custody_sequence.to_be_bytes());
        bytes.extend_from_slice(self.session_binding.as_bytes());
        bytes.extend_from_slice(self.request_digest.as_bytes());
        bytes.extend_from_slice(self.packet_digest.as_bytes());
        bytes.extend_from_slice(&self.argument_limit_bytes.to_be_bytes());
        bytes.extend_from_slice(&(self.canonical_request.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&(self.signed_packet.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.canonical_request);
        bytes.extend_from_slice(&self.signed_packet);
        bytes.extend_from_slice(&receipt_checksum(FRESH_DOMAIN, &bytes));
        bytes
    }

    /// Borrows the exact Controller attempt echoed by the Host.
    #[must_use]
    pub const fn source(&self) -> &[u8; HOST_EXECUTION_ARGUMENT_ATTEMPT_BYTES_V1] {
        &self.source
    }

    /// Returns the protected Host runtime handle attested at observation.
    #[must_use]
    pub const fn runtime_handle(&self) -> ObjectDigest {
        self.runtime_handle
    }

    /// Returns the exact protected Host observation value digest.
    #[must_use]
    pub const fn custody_digest(&self) -> ObjectDigest {
        self.custody_digest
    }

    /// Returns the Host journal sequence after observation custody.
    #[must_use]
    pub const fn custody_sequence(&self) -> u64 {
        self.custody_sequence
    }

    /// Returns the retained Guest session binding attested by the Host.
    #[must_use]
    pub const fn session_binding(&self) -> ObjectDigest {
        self.session_binding
    }

    /// Borrows the exact Guest challenge sent on that retained session.
    #[must_use]
    pub fn canonical_request(&self) -> &[u8] {
        &self.canonical_request
    }

    /// Borrows the exact signed Guest packet retained by the Host.
    #[must_use]
    pub fn signed_packet(&self) -> &[u8] {
        &self.signed_packet
    }

    /// Returns the Host-attested measured Guest argument limit.
    #[must_use]
    pub const fn argument_limit_bytes(&self) -> u64 {
        self.argument_limit_bytes
    }

    /// Returns the raw digest of the Guest challenge.
    #[must_use]
    pub const fn request_digest(&self) -> ObjectDigest {
        self.request_digest
    }

    /// Returns the raw digest of the signed Guest packet.
    #[must_use]
    pub const fn packet_digest(&self) -> ObjectDigest {
        self.packet_digest
    }

    fn is_consistent(&self) -> bool {
        let Ok(request) = GuestRuntimeArgumentObserveRequestV1::decode(&self.canonical_request)
        else {
            return false;
        };
        canonical_attempt_request_id_v1(&self.source).is_ok()
            && self.runtime_handle.as_bytes() != &[0; 32]
            && self.custody_digest.as_bytes() != &[0; 32]
            && self.custody_sequence != 0
            && self.session_binding == request.session().digest()
            && self.source[184..216] == *request.runtime().assignment_digest().as_bytes()
            && self.request_digest.as_bytes() == Sha256::digest(&self.canonical_request).as_slice()
            && self.packet_digest.as_bytes() == Sha256::digest(&self.signed_packet).as_slice()
            && packet_limit(&self.signed_packet, &self.canonical_request)
                == Some(self.argument_limit_bytes)
            && self.argument_limit_bytes != 0
    }
}

/// Distinguishes missing, quarantined, and historical original attempts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum HistoricalHostArgumentStatusV1 {
    /// No Host one-shot attempt was committed.
    Absent = 0,
    /// A challenge was committed, but no exact signed packet was retained.
    Pending = 1,
    /// An exact signed packet was retained; this is historical audit only.
    Complete = 2,
}

/// Reports only cold historical Host custody, never fresh ARG_MAX evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostExecutionArgumentHistoricalReceiptV1 {
    source: [u8; HOST_EXECUTION_ARGUMENT_ATTEMPT_BYTES_V1],
    status: HistoricalHostArgumentStatusV1,
    request_digest: ObjectDigest,
    packet_digest: ObjectDigest,
    custody_digest: ObjectDigest,
    custody_sequence: u64,
}

impl HostExecutionArgumentHistoricalReceiptV1 {
    /// Constructs a digest-only historical readback.
    ///
    /// # Errors
    ///
    /// Rejects malformed original source or a status/digest combination that
    /// could disguise a pending attempt as absence or a fresh observation.
    pub fn new(
        source: [u8; HOST_EXECUTION_ARGUMENT_ATTEMPT_BYTES_V1],
        status: HistoricalHostArgumentStatusV1,
        request_digest: ObjectDigest,
        packet_digest: ObjectDigest,
        custody_digest: ObjectDigest,
        custody_sequence: u64,
    ) -> Result<Self, HostExecutionArgumentReceiptErrorV1> {
        let receipt = Self {
            source,
            status,
            request_digest,
            packet_digest,
            custody_digest,
            custody_sequence,
        };
        if !receipt.is_consistent() {
            return Err(HostExecutionArgumentReceiptErrorV1::InvalidReceipt);
        }
        Ok(receipt)
    }

    /// Decodes one bounded canonical historical reply.
    ///
    /// # Errors
    ///
    /// Rejects an altered source, unsupported status, inconsistent digest, or checksum.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, HostExecutionArgumentReceiptErrorV1> {
        if bytes.len() != HISTORICAL_BYTES || bytes.get(..8) != Some(HISTORICAL_MAGIC.as_slice()) {
            return Err(HostExecutionArgumentReceiptErrorV1::InvalidReceipt);
        }
        let mut cursor = &bytes[8..];
        let source = take::<HOST_EXECUTION_ARGUMENT_ATTEMPT_BYTES_V1>(&mut cursor)?;
        let status = match take::<1>(&mut cursor)?[0] {
            0 => HistoricalHostArgumentStatusV1::Absent,
            1 => HistoricalHostArgumentStatusV1::Pending,
            2 => HistoricalHostArgumentStatusV1::Complete,
            _ => return Err(HostExecutionArgumentReceiptErrorV1::InvalidReceipt),
        };
        let request_digest = ObjectDigest::from_bytes(take(&mut cursor)?);
        let packet_digest = ObjectDigest::from_bytes(take(&mut cursor)?);
        let custody_digest = ObjectDigest::from_bytes(take(&mut cursor)?);
        let custody_sequence = u64::from_be_bytes(take(&mut cursor)?);
        let checksum = take::<32>(&mut cursor)?;
        if !cursor.is_empty()
            || checksum != receipt_checksum(HISTORICAL_DOMAIN, &bytes[..bytes.len() - 32])
        {
            return Err(HostExecutionArgumentReceiptErrorV1::InvalidReceipt);
        }
        Self::new(
            source,
            status,
            request_digest,
            packet_digest,
            custody_digest,
            custody_sequence,
        )
    }

    /// Encodes the canonical digest-only historical reply.
    #[must_use]
    pub fn canonical_bytes(&self) -> [u8; HISTORICAL_BYTES] {
        let mut bytes = [0; HISTORICAL_BYTES];
        bytes[..8].copy_from_slice(HISTORICAL_MAGIC);
        bytes[8..344].copy_from_slice(&self.source);
        bytes[344] = self.status as u8;
        bytes[345..377].copy_from_slice(self.request_digest.as_bytes());
        bytes[377..409].copy_from_slice(self.packet_digest.as_bytes());
        bytes[409..441].copy_from_slice(self.custody_digest.as_bytes());
        bytes[441..449].copy_from_slice(&self.custody_sequence.to_be_bytes());
        let checksum = receipt_checksum(HISTORICAL_DOMAIN, &bytes[..449]);
        bytes[449..].copy_from_slice(&checksum);
        bytes
    }

    /// Borrows the exact original Controller attempt named by the query.
    #[must_use]
    pub const fn source(&self) -> &[u8; HOST_EXECUTION_ARGUMENT_ATTEMPT_BYTES_V1] {
        &self.source
    }

    /// Returns the historical status, which never confers fresh authority.
    #[must_use]
    pub const fn status(&self) -> HistoricalHostArgumentStatusV1 {
        self.status
    }

    /// Returns the original Guest challenge digest, when one was committed.
    #[must_use]
    pub const fn request_digest(&self) -> ObjectDigest {
        self.request_digest
    }

    /// Returns the historical packet digest, when one was committed.
    #[must_use]
    pub const fn packet_digest(&self) -> ObjectDigest {
        self.packet_digest
    }

    /// Returns the Host protected custody value digest, when present.
    #[must_use]
    pub const fn custody_digest(&self) -> ObjectDigest {
        self.custody_digest
    }

    /// Returns the Host protected custody sequence, when present.
    #[must_use]
    pub const fn custody_sequence(&self) -> u64 {
        self.custody_sequence
    }

    fn is_consistent(&self) -> bool {
        if canonical_attempt_request_id_v1(&self.source).is_err() {
            return false;
        }
        let zero = &[0; 32];
        match self.status {
            HistoricalHostArgumentStatusV1::Absent => {
                self.request_digest.as_bytes() == zero
                    && self.packet_digest.as_bytes() == zero
                    && self.custody_digest.as_bytes() == zero
                    && self.custody_sequence == 0
            }
            HistoricalHostArgumentStatusV1::Pending => {
                self.request_digest.as_bytes() != zero
                    && self.packet_digest.as_bytes() == zero
                    && self.custody_digest.as_bytes() != zero
                    && self.custody_sequence != 0
            }
            HistoricalHostArgumentStatusV1::Complete => {
                self.request_digest.as_bytes() != zero
                    && self.packet_digest.as_bytes() != zero
                    && self.custody_digest.as_bytes() != zero
                    && self.custody_sequence != 0
            }
        }
    }
}

fn packet_limit(packet: &[u8], request: &[u8]) -> Option<u64> {
    if request.len() > MAXIMUM_GUEST_REQUEST_BYTES
        || packet.len() > MAXIMUM_SIGNED_GUEST_PACKET_BYTES
        || packet.get(..8)? != b"AOSARP01"
    {
        return None;
    }
    let length = usize::from(u16::from_be_bytes(packet.get(8..10)?.try_into().ok()?));
    if length != request.len() || packet.len() != 8 + 2 + length + 8 + 64 {
        return None;
    }
    if packet.get(10..10 + length)? != request {
        return None;
    }
    Some(u64::from_be_bytes(
        packet.get(10 + length..18 + length)?.try_into().ok()?,
    ))
}

fn receipt_checksum(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(domain)
        .chain_update(bytes)
        .finalize()
        .into()
}

fn take<const N: usize>(
    cursor: &mut &[u8],
) -> Result<[u8; N], HostExecutionArgumentReceiptErrorV1> {
    take_slice(cursor, N)?
        .try_into()
        .map_err(|_| HostExecutionArgumentReceiptErrorV1::InvalidReceipt)
}

fn take_slice<'a>(
    cursor: &mut &'a [u8],
    length: usize,
) -> Result<&'a [u8], HostExecutionArgumentReceiptErrorV1> {
    let (head, tail) = cursor
        .split_at_checked(length)
        .ok_or(HostExecutionArgumentReceiptErrorV1::InvalidReceipt)?;
    *cursor = tail;
    Ok(head)
}

#[cfg(test)]
mod tests {
    use aos_sandbox_agent::{
        AgentRuntimeBindingV1, AgentSessionBindingV1, verify_guest_runtime_argument_readback_v1,
    };
    use aos_sandbox_core::{
        AssignmentEpoch, DesiredGeneration, FeatureRef, IncarnationId, NamespaceGeneration,
        SandboxId,
    };
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;

    fn source() -> [u8; HOST_EXECUTION_ARGUMENT_ATTEMPT_BYTES_V1] {
        let mut bytes = [0; HOST_EXECUTION_ARGUMENT_ATTEMPT_BYTES_V1];
        bytes[..8].copy_from_slice(b"AOSCIA02");
        bytes[8..56].fill(1);
        bytes[56..248].fill(2);
        bytes[184..216].fill(5);
        bytes[248..304].fill(3);
        let digest: [u8; 32] = Sha256::new()
            .chain_update(b"aos.sandbox.controller-argument-attempt.v1\0")
            .chain_update(&bytes[..304])
            .finalize()
            .into();
        bytes[304..].copy_from_slice(&digest);
        bytes
    }

    fn fresh_receipt() -> HostExecutionArgumentFreshReceiptV1 {
        let runtime = AgentRuntimeBindingV1::new(
            SandboxId::from_bytes([1; 16]),
            IncarnationId::from_bytes([2; 16]),
            AssignmentEpoch::new(3),
            ObjectDigest::from_bytes([5; 32]),
            DesiredGeneration::new(4),
            NamespaceGeneration::new(5),
            [6; 16],
        )
        .unwrap();
        let request = GuestRuntimeArgumentObserveRequestV1::new(
            runtime,
            AgentSessionBindingV1::from_digest(ObjectDigest::from_bytes([7; 32])).unwrap(),
            ObjectDigest::from_bytes([8; 32]),
            [9; 32],
            FeatureRef::new("aos.sandbox.runtime.linux-systemd", 1, 0).unwrap(),
            ObjectDigest::from_bytes([10; 32]),
        )
        .unwrap();
        let request_bytes = request.encode();
        let mut packet = Vec::new();
        packet.extend_from_slice(b"AOSARP01");
        packet.extend_from_slice(&(request_bytes.len() as u16).to_be_bytes());
        packet.extend_from_slice(&request_bytes);
        packet.extend_from_slice(&131_072_u64.to_be_bytes());
        let signing_key = SigningKey::from_bytes(&[11; 32]);
        let mut message = b"aos.sandbox.guest-argument-readback.v1\0".to_vec();
        message.extend_from_slice(&packet);
        packet.extend_from_slice(&signing_key.sign(&message).to_bytes());
        let verified = verify_guest_runtime_argument_readback_v1(
            &packet,
            &request,
            &signing_key.verifying_key(),
        )
        .unwrap();
        HostExecutionArgumentFreshReceiptV1::new(
            source(),
            ObjectDigest::from_bytes([12; 32]),
            ObjectDigest::from_bytes([13; 32]),
            14,
            &request,
            &packet,
            &verified,
        )
        .unwrap()
    }

    #[test]
    fn fresh_receipt_is_bounded_and_rejects_substitutions() {
        let receipt = fresh_receipt();
        let bytes = receipt.canonical_bytes();
        assert!(bytes.len() < 4096);
        assert_eq!(
            HostExecutionArgumentFreshReceiptV1::decode_canonical(&bytes).unwrap(),
            receipt
        );

        for position in [
            40,
            8 + 184,
            8 + 336 + 64,
            8 + 336 + 72,
            500,
            bytes.len() - 33,
        ] {
            let mut changed = bytes.clone();
            changed[position] ^= 1;
            assert!(HostExecutionArgumentFreshReceiptV1::decode_canonical(&changed).is_err());
        }
        assert!(
            HostExecutionArgumentFreshReceiptV1::decode_canonical(&bytes[..bytes.len() - 1])
                .is_err()
        );
    }

    #[test]
    fn historical_receipt_is_digest_only_and_status_consistent() {
        let fresh = fresh_receipt();
        let historical = HostExecutionArgumentHistoricalReceiptV1::new(
            *fresh.source(),
            HistoricalHostArgumentStatusV1::Complete,
            fresh.request_digest(),
            fresh.packet_digest(),
            fresh.custody_digest(),
            fresh.custody_sequence(),
        )
        .unwrap();
        let bytes = historical.canonical_bytes();
        assert_eq!(bytes.len(), HISTORICAL_BYTES);
        assert_eq!(
            HostExecutionArgumentHistoricalReceiptV1::decode_canonical(&bytes).unwrap(),
            historical
        );
        assert!(
            HostExecutionArgumentHistoricalReceiptV1::new(
                *fresh.source(),
                HistoricalHostArgumentStatusV1::Pending,
                fresh.request_digest(),
                fresh.packet_digest(),
                fresh.custody_digest(),
                fresh.custody_sequence(),
            )
            .is_err()
        );
        let mut changed = bytes;
        changed[344] = 0;
        assert!(HostExecutionArgumentHistoricalReceiptV1::decode_canonical(&changed).is_err());
    }
}
