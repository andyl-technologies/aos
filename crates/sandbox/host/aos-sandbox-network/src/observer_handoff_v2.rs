//! Encodes the original Netd-to-observer public handoff as passive DATA.
//!
//! ```text
//! AOSNOH03 || version:u16=3 || purpose:u16 || total:u32 ||
//! boot:16 || source:16 || worker:16 || prebirth:32 || request:16 ||
//! effect:32 || ordinal:u64 || lengths:[u32;9] || reserved:4 ||
//! public-evidence:[device:u64,inode:u64,length:u64,sha256:32;6] || sections
//! ```
//!
//! The nine sections are the exact signed request, plan/signature,
//! ownership-lease/signature, original current/operation fences, original
//! pending effect and ordinary observation request. Six original public rights
//! accompany this record. Native Source provenance and read admission are
//! mandatory independent obligations; no decoder supplies them.
//! A fixed zero-right 528-byte header precedes the full six-right record.
//! It is the identical prefix, permits exact preallocation and supplies no D
//! or read authority. The earlier single-record H02 grammar is rejected.

use aos_sandbox_broker::ProtectedBrokerPublicCredentialSnapshot;
use aos_sandbox_broker::receiving::NetworkChildOperationBindingDataV2;
use aos_sandbox_protocol::session::{
    MAXIMUM_AUTHORIZATION_SIGNATURE_BYTES, MAXIMUM_BROKER_PLAN_BYTES, MAXIMUM_OWNERSHIP_LEASE_BYTES,
};

pub(crate) const HEADER_BYTES: usize = 528;
const SECTION_LIMITS: [usize; 9] = [
    aos_sandbox_protocol::MAXIMUM_REQUEST_BYTES,
    MAXIMUM_BROKER_PLAN_BYTES,
    MAXIMUM_AUTHORIZATION_SIGNATURE_BYTES,
    MAXIMUM_OWNERSHIP_LEASE_BYTES,
    MAXIMUM_AUTHORIZATION_SIGNATURE_BYTES,
    408 + 255,
    408 + 255,
    554,
    184 + 512 * 1024,
];

/// Maximum DATA width from the nine existing canonical section codecs.
pub(crate) const MAXIMUM_HANDOFF_BYTES: usize = HEADER_BYTES
    + SECTION_LIMITS[0]
    + SECTION_LIMITS[1]
    + SECTION_LIMITS[2]
    + SECTION_LIMITS[3]
    + SECTION_LIMITS[4]
    + SECTION_LIMITS[5]
    + SECTION_LIMITS[6]
    + SECTION_LIMITS[7]
    + SECTION_LIMITS[8];

/// Carries comparison and exact-allocation DATA from the fixed bootstrap header.
pub(crate) struct ObserverHandoffHeaderDataV3 {
    pub(crate) total_bytes: usize,
    section_lengths: [usize; 9],
    boot: [u8; 16],
    source_invocation: [u8; 16],
    worker_invocation: [u8; 16],
    prebirth_digest: [u8; 32],
    request_id: [u8; 16],
    effect_digest: [u8; 32],
    operation_ordinal: u64,
    credentials: [ProtectedBrokerPublicCredentialSnapshot; 6],
}

impl ObserverHandoffHeaderDataV3 {
    /// Returns the nine checked extents solely for exact receiving allocation.
    pub(crate) const fn section_lengths_data_v3(&self) -> [usize; 9] {
        self.section_lengths
    }

    /// Checks the one canonical fixed header without allocating a body.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != HEADER_BYTES
            || &bytes[..8] != b"AOSNOH03"
            || bytes[8..12] != [0, 3, 0, 2]
            || bytes[188..192] != [0; 4]
        {
            return None;
        }
        let mut section_lengths = [0; 9];
        for (index, length) in section_lengths.iter_mut().enumerate() {
            let begin = 152 + index * 4;
            *length = usize::try_from(u32::from_be_bytes(bytes[begin..begin + 4].try_into().ok()?))
                .ok()?;
        }
        let total_bytes = observer_handoff_length_data_v2(section_lengths)?;
        if usize::try_from(u32::from_be_bytes(bytes[12..16].try_into().ok()?)).ok()? != total_bytes
        {
            return None;
        }
        let evidence = std::array::from_fn::<_, 6, _>(|index| {
            let begin = 192 + index * 56;
            ProtectedBrokerPublicCredentialSnapshot::decode_network_handoff_data_v2(
                &bytes[begin..begin + 56],
            )
        });
        let [Some(a), Some(b), Some(c), Some(d), Some(e), Some(f)] = evidence else {
            return None;
        };
        let header = Self {
            total_bytes,
            section_lengths,
            boot: bytes[16..32].try_into().ok()?,
            source_invocation: bytes[32..48].try_into().ok()?,
            worker_invocation: bytes[48..64].try_into().ok()?,
            prebirth_digest: bytes[64..96].try_into().ok()?,
            request_id: bytes[96..112].try_into().ok()?,
            effect_digest: bytes[112..144].try_into().ok()?,
            operation_ordinal: u64::from_be_bytes(bytes[144..152].try_into().ok()?),
            credentials: [a, b, c, d, e, f],
        };
        if header.boot == [0; 16]
            || header.source_invocation == [0; 16]
            || header.worker_invocation == [0; 16]
            || header.prebirth_digest == [0; 32]
            || header.request_id == [0; 16]
            || header.effect_digest == [0; 32]
            || header.operation_ordinal == 0
        {
            return None;
        }
        Some(header)
    }

    /// Compares header coordinates with the actual native Source programme.
    pub(crate) fn matches_native(&self, native: NetworkChildOperationBindingDataV2) -> bool {
        native.purpose == 2
            && self.boot == native.boot
            && self.source_invocation == native.source_invocation
            && self.worker_invocation == native.worker_invocation
            && self.prebirth_digest == native.prebirth_digest
            && self.request_id == native.request_id
            && self.effect_digest == native.effect_digest
            && self.operation_ordinal == native.operation_ordinal
    }
}

/// Quotes the sole canonical nine extents without allocation or authority.
pub(crate) fn observer_handoff_length_data_v2(lengths: [usize; 9]) -> Option<usize> {
    let mut total = HEADER_BYTES;
    for (length, maximum) in lengths.into_iter().zip(SECTION_LIMITS) {
        if length == 0 || length > maximum {
            return None;
        }
        total = total.checked_add(length)?;
    }
    Some(total)
}

/// Borrows one structurally valid handoff without granting read permission.
pub(crate) struct ObserverHandoffDataV2<'record> {
    pub(crate) boot: [u8; 16],
    pub(crate) source_invocation: [u8; 16],
    pub(crate) worker_invocation: [u8; 16],
    pub(crate) prebirth_digest: [u8; 32],
    pub(crate) request_id: [u8; 16],
    pub(crate) effect_digest: [u8; 32],
    pub(crate) operation_ordinal: u64,
    pub(crate) credentials: [ProtectedBrokerPublicCredentialSnapshot; 6],
    pub(crate) sections: [&'record [u8]; 9],
}

impl<'record> ObserverHandoffDataV2<'record> {
    /// Decodes only the closed record shape and exact bounded section extents.
    pub(crate) fn decode(bytes: &'record [u8]) -> Option<Self> {
        let header = ObserverHandoffHeaderDataV3::decode(bytes.get(..HEADER_BYTES)?)?;
        if bytes.len() != header.total_bytes {
            return None;
        }
        let mut sections = [&[][..]; 9];
        let mut offset = HEADER_BYTES;
        for (index, section) in sections.iter_mut().enumerate() {
            let length = header.section_lengths[index];
            let end = offset.checked_add(length)?;
            *section = bytes.get(offset..end)?;
            offset = end;
        }
        if offset != bytes.len() {
            return None;
        }
        let data = Self {
            boot: header.boot,
            source_invocation: header.source_invocation,
            worker_invocation: header.worker_invocation,
            prebirth_digest: header.prebirth_digest,
            request_id: header.request_id,
            effect_digest: header.effect_digest,
            operation_ordinal: header.operation_ordinal,
            credentials: header.credentials,
            sections,
        };
        Some(data)
    }

    /// Compares every operation coordinate against the authentic native840.
    pub(crate) fn matches_native(&self, native: NetworkChildOperationBindingDataV2) -> bool {
        native.purpose == 2
            && self.boot == native.boot
            && self.source_invocation == native.source_invocation
            && self.worker_invocation == native.worker_invocation
            && self.prebirth_digest == native.prebirth_digest
            && self.request_id == native.request_id
            && self.effect_digest == native.effect_digest
            && self.operation_ordinal == native.operation_ordinal
    }
}

/// Encodes exact borrowed originals for the actual parent transport.
///
/// Inputs remain DATA. Only the parent caller holding the genuine same-F loan,
/// completed signed admission and live Source may send them as an O handoff.
pub(crate) fn encode_observer_handoff_data_v2(
    binding: NetworkChildOperationBindingDataV2,
    credentials: [ProtectedBrokerPublicCredentialSnapshot; 6],
    sections: [&[u8]; 9],
) -> Option<Vec<u8>> {
    if binding.purpose != 2 {
        return None;
    }
    let total = observer_handoff_length_data_v2(sections.map(<[u8]>::len))?;
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(b"AOSNOH03");
    bytes.extend_from_slice(&[0, 3, 0, 2]);
    bytes.extend_from_slice(&u32::try_from(total).ok()?.to_be_bytes());
    bytes.extend_from_slice(&binding.boot);
    bytes.extend_from_slice(&binding.source_invocation);
    bytes.extend_from_slice(&binding.worker_invocation);
    bytes.extend_from_slice(&binding.prebirth_digest);
    bytes.extend_from_slice(&binding.request_id);
    bytes.extend_from_slice(&binding.effect_digest);
    bytes.extend_from_slice(&binding.operation_ordinal.to_be_bytes());
    for section in sections {
        bytes.extend_from_slice(&u32::try_from(section.len()).ok()?.to_be_bytes());
    }
    bytes.extend_from_slice(&[0; 4]);
    for evidence in credentials {
        bytes.extend_from_slice(&evidence.device().to_be_bytes());
        bytes.extend_from_slice(&evidence.inode().to_be_bytes());
        bytes.extend_from_slice(&u64::try_from(evidence.bytes()).ok()?.to_be_bytes());
        bytes.extend_from_slice(&evidence.sha256());
    }
    for section in sections {
        bytes.extend_from_slice(section);
    }
    ObserverHandoffDataV2::decode(&bytes)?;
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> NetworkChildOperationBindingDataV2 {
        NetworkChildOperationBindingDataV2 {
            purpose: 2,
            boot: [1; 16],
            source_invocation: [2; 16],
            worker_invocation: [3; 16],
            prebirth_digest: [4; 32],
            request_id: [5; 16],
            effect_digest: [6; 32],
            operation_ordinal: 7,
            native_limits: [8, 9, 10],
            source_probe_count: 11,
        }
    }

    fn credentials() -> [ProtectedBrokerPublicCredentialSnapshot; 6] {
        std::array::from_fn(|index| {
            let mut bytes = [0; 56];
            bytes[0..8].copy_from_slice(&1_u64.to_be_bytes());
            bytes[8..16].copy_from_slice(&(index as u64 + 1).to_be_bytes());
            bytes[16..24].copy_from_slice(&32_u64.to_be_bytes());
            bytes[24..56].fill(index as u8 + 1);
            ProtectedBrokerPublicCredentialSnapshot::decode_network_handoff_data_v2(&bytes).unwrap()
        })
    }

    #[test]
    fn passive_roundtrip_preserves_role_order_and_refuses_other_operation_affinity() {
        let native = binding();
        let original_credentials = credentials();
        let bytes =
            encode_observer_handoff_data_v2(native, original_credentials, [b"x"; 9]).unwrap();
        let decoded = ObserverHandoffDataV2::decode(&bytes).unwrap();

        assert!(decoded.matches_native(native));
        assert_eq!(decoded.credentials, original_credentials);
        assert_eq!(decoded.sections, [&b"x"[..]; 9]);
        let changed = NetworkChildOperationBindingDataV2 {
            operation_ordinal: 8,
            ..native
        };
        assert!(!decoded.matches_native(changed));
    }

    #[test]
    fn malformed_extents_reserved_bytes_and_trailing_data_never_decode() {
        let bytes = encode_observer_handoff_data_v2(binding(), credentials(), [b"x"; 9]).unwrap();
        let mut altered = bytes.clone();
        altered[152..156].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(ObserverHandoffDataV2::decode(&altered).is_none());

        let mut altered = bytes.clone();
        altered[188] = 1;
        assert!(ObserverHandoffDataV2::decode(&altered).is_none());

        let mut altered = bytes;
        altered.push(0);
        let length = altered.len() as u32;
        altered[12..16].copy_from_slice(&length.to_be_bytes());
        assert!(ObserverHandoffDataV2::decode(&altered).is_none());
    }

    #[test]
    fn header_quotes_exact_full_extent_and_rejects_the_single_record_grammar() {
        let bytes = encode_observer_handoff_data_v2(binding(), credentials(), [b"x"; 9]).unwrap();
        let header = ObserverHandoffHeaderDataV3::decode(&bytes[..HEADER_BYTES]).unwrap();
        assert_eq!(header.total_bytes, bytes.len());
        assert!(header.matches_native(binding()));
        assert_eq!(observer_handoff_length_data_v2([1; 9]), Some(bytes.len()));
        assert!(ObserverHandoffDataV2::decode(&bytes[..HEADER_BYTES]).is_none());

        let mut old = bytes.clone();
        old[..8].copy_from_slice(b"AOSNOH02");
        old[8..10].copy_from_slice(&2_u16.to_be_bytes());
        assert!(ObserverHandoffHeaderDataV3::decode(&old[..HEADER_BYTES]).is_none());
        assert!(ObserverHandoffDataV2::decode(&old).is_none());

        let mut oversized = bytes;
        let invalid = u32::try_from(SECTION_LIMITS[8] + 1).unwrap();
        oversized[184..188].copy_from_slice(&invalid.to_be_bytes());
        assert!(ObserverHandoffHeaderDataV3::decode(&oversized[..HEADER_BYTES]).is_none());
    }
}
