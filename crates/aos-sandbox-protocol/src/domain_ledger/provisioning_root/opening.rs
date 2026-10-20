//! Shares the exact fixed Root continuation opening codec.
//!
//! Every purpose retains its own public DATA type and fixed magic/domain. This
//! private recipe handles only the common fixed integer layout. It supplies no
//! admission, financial owner, clock provenance or deadline renewal.

use aos_sandbox_core::bounded_codec::BoundedReader;
use sha2::{Digest as _, Sha256};
use crate::domain_ledger::create_storage_history::HistoryErrorV1;

pub(super) const QUERY_BYTES: usize = 112;

#[derive(Clone, Copy)]
pub(super) struct QueryFieldsV1 {
    pub controller_nonce: [u8; 16],
    pub original_boot: [u8; 16],
    pub original_boottime_ns: u64,
    pub original_cutoff_ns: u64,
    pub subject_bytes: u64,
    pub subject_digest: [u8; 32],
    pub controller_next: u64,
    pub controller_end: u64,
}

/// Shares the nonce, original clock and bounded subject prefix without a C cut.
#[derive(Clone, Copy)]
pub(super) struct QueryEnvelopeFieldsV2 {
    pub controller_nonce: [u8; 16],
    pub original_boot: [u8; 16],
    pub original_boottime_ns: u64,
    pub original_cutoff_ns: u64,
    pub subject_bytes: u64,
    pub subject_digest: [u8; 32],
}

pub(super) const QUERY_ENVELOPE_BYTES_V2: usize = 96;

impl QueryEnvelopeFieldsV2 {
    fn read(input: &mut BoundedReader<'_, HistoryErrorV1>, magic: &[u8; 8])
        -> Result<Self, HistoryErrorV1> {
        if input.array::<8>()? != *magic { return Err(HistoryErrorV1::Malformed); }
        let value = Self {
            controller_nonce: input.array()?, original_boot: input.array()?,
            original_boottime_ns: input.u64()?, original_cutoff_ns: input.u64()?,
            subject_bytes: input.u64()?, subject_digest: input.array()?,
        };
        Ok(value)
    }

    fn validate(self) -> Result<(), HistoryErrorV1> {
        if self.controller_nonce == [0; 16] || self.original_boot == [0; 16]
            || self.original_boottime_ns == 0 || self.original_cutoff_ns <= self.original_boottime_ns
            || self.subject_bytes == 0 || self.subject_digest == [0; 32] {
            return Err(HistoryErrorV1::Malformed);
        }
        Ok(())
    }

    pub(super) fn decode(bytes: &[u8], magic: &[u8; 8]) -> Result<Self, HistoryErrorV1> {
        let mut input = BoundedReader::new(bytes, |_| HistoryErrorV1::Extent);
        let value = Self::read(&mut input, magic)?;
        input.finish()?;
        value.validate()?;
        Ok(value)
    }

    pub(super) fn encode(self, magic: &[u8; 8])
        -> Result<[u8; QUERY_ENVELOPE_BYTES_V2], HistoryErrorV1> {
        self.validate()?;
        let mut output = [0; QUERY_ENVELOPE_BYTES_V2];
        output[..8].copy_from_slice(magic);
        output[8..24].copy_from_slice(&self.controller_nonce);
        output[24..40].copy_from_slice(&self.original_boot);
        output[40..48].copy_from_slice(&self.original_boottime_ns.to_be_bytes());
        output[48..56].copy_from_slice(&self.original_cutoff_ns.to_be_bytes());
        output[56..64].copy_from_slice(&self.subject_bytes.to_be_bytes());
        output[64..96].copy_from_slice(&self.subject_digest);
        Ok(output)
    }

    pub(super) fn digest(self, magic: &[u8; 8], domain: &[u8]) -> Result<[u8; 32], HistoryErrorV1> {
        Ok(Sha256::new().chain_update(domain).chain_update(self.encode(magic)?).finalize().into())
    }
}

impl QueryFieldsV1 {
    fn envelope(self) -> QueryEnvelopeFieldsV2 {
        QueryEnvelopeFieldsV2 { controller_nonce: self.controller_nonce,
            original_boot: self.original_boot, original_boottime_ns: self.original_boottime_ns,
            original_cutoff_ns: self.original_cutoff_ns, subject_bytes: self.subject_bytes,
            subject_digest: self.subject_digest }
    }

    pub(super) fn decode(bytes: &[u8], magic: &[u8; 8]) -> Result<Self, HistoryErrorV1> {
        let mut input = BoundedReader::new(bytes, |_| HistoryErrorV1::Extent);
        let envelope = QueryEnvelopeFieldsV2::read(&mut input, magic)?;
        let value = Self { controller_nonce: envelope.controller_nonce,
            original_boot: envelope.original_boot, original_boottime_ns: envelope.original_boottime_ns,
            original_cutoff_ns: envelope.original_cutoff_ns, subject_bytes: envelope.subject_bytes,
            subject_digest: envelope.subject_digest, controller_next: input.u64()?, controller_end: input.u64()? };
        input.finish()?;
        value.validate()?;
        Ok(value)
    }

    fn validate(self) -> Result<(), HistoryErrorV1> {
        self.envelope().validate()?;
        if self.controller_next == 0 || self.controller_end == 0 { return Err(HistoryErrorV1::Malformed); }
        Ok(())
    }

    pub(super) fn encode(self, magic: &[u8; 8]) -> Result<[u8; QUERY_BYTES], HistoryErrorV1> {
        self.validate()?;
        let mut output = [0; QUERY_BYTES];
        output[..QUERY_ENVELOPE_BYTES_V2].copy_from_slice(&self.envelope().encode(magic)?);
        output[96..104].copy_from_slice(&self.controller_next.to_be_bytes());
        output[104..112].copy_from_slice(&self.controller_end.to_be_bytes());
        Ok(output)
    }

    pub(super) fn digest(self, magic: &[u8; 8], domain: &[u8]) -> Result<[u8; 32], HistoryErrorV1> {
        Ok(Sha256::new().chain_update(domain).chain_update(self.encode(magic)?).finalize().into())
    }
}

pub(super) use crate::domain_ledger::create_storage_history::continuation::framing::hash_fields;

/// Holds common fixed temporal reply DATA under each distinct purpose magic.
pub(super) struct TemporalAdmissionFieldsV2<const N: usize> {
    pub root_nonce: [u8; 16],
    pub controller_nonce: [u8; 16],
    pub query_digest: [u8; 32],
    pub original_boot: [u8; 16],
    pub original_boottime_ns: u64,
    pub original_cutoff_ns: u64,
    pub observed_wall_seconds: i64,
    pub observed_boottime_ns: u64,
    pub cutoff_ns: u64,
    pub authority_expiries: [i64; N],
}

impl<const N: usize> TemporalAdmissionFieldsV2<N> {
    fn validate(&self) -> Result<(), HistoryErrorV1> {
        if self.root_nonce == [0; 16] || self.controller_nonce == [0; 16]
            || self.query_digest == [0; 32] || self.original_boot == [0; 16]
            || self.original_boottime_ns == 0
            || self.original_boottime_ns > self.observed_boottime_ns
            || self.observed_boottime_ns >= self.cutoff_ns
            || self.cutoff_ns > self.original_cutoff_ns
            || self.authority_expiries.iter().any(|expiry| self.observed_wall_seconds >= *expiry) {
            return Err(HistoryErrorV1::Malformed);
        }
        Ok(())
    }

    pub(super) fn decode(bytes: &[u8], magic: &[u8; 8]) -> Result<Self, HistoryErrorV1> {
        let mut input = BoundedReader::new(bytes, |_| HistoryErrorV1::Extent);
        if input.array::<8>()? != *magic { return Err(HistoryErrorV1::Malformed); }
        let mut value = Self {
            root_nonce: input.array()?, controller_nonce: input.array()?,
            query_digest: input.array()?, original_boot: input.array()?,
            original_boottime_ns: input.u64()?, original_cutoff_ns: input.u64()?,
            observed_wall_seconds: input.i64()?, observed_boottime_ns: input.u64()?,
            cutoff_ns: input.u64()?, authority_expiries: [0; N],
        };
        for expiry in &mut value.authority_expiries { *expiry = input.i64()?; }
        input.finish()?;
        value.validate()?;
        Ok(value)
    }

    pub(super) fn encode<const BYTES: usize>(&self, magic: &[u8; 8])
        -> Result<[u8; BYTES], HistoryErrorV1> {
        self.validate()?;
        if N.checked_mul(8).and_then(|width| width.checked_add(128)) != Some(BYTES) {
            return Err(HistoryErrorV1::Extent);
        }
        let mut output = [0; BYTES];
        output[..8].copy_from_slice(magic);
        output[8..24].copy_from_slice(&self.root_nonce);
        output[24..40].copy_from_slice(&self.controller_nonce);
        output[40..72].copy_from_slice(&self.query_digest);
        output[72..88].copy_from_slice(&self.original_boot);
        output[88..96].copy_from_slice(&self.original_boottime_ns.to_be_bytes());
        output[96..104].copy_from_slice(&self.original_cutoff_ns.to_be_bytes());
        output[104..112].copy_from_slice(&self.observed_wall_seconds.to_be_bytes());
        output[112..120].copy_from_slice(&self.observed_boottime_ns.to_be_bytes());
        output[120..128].copy_from_slice(&self.cutoff_ns.to_be_bytes());
        for (index, expiry) in self.authority_expiries.iter().enumerate() {
            let start = 128 + index * 8;
            output[start..start + 8].copy_from_slice(&expiry.to_be_bytes());
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_ledger::provisioning_root::host_launch::HostResourceAdmissionDataV1;

    #[test]
    fn acquisition_prefix_keeps_legacy_opening_bytes_and_exact_widths() {
        let fields = QueryFieldsV1 {
            controller_nonce: [1; 16], original_boot: [2; 16],
            original_boottime_ns: 10, original_cutoff_ns: 40,
            subject_bytes: 150, subject_digest: [3; 32], controller_next: 7, controller_end: 99,
        };
        let legacy = [
            b"AOSHLQ01".as_slice(), &[1; 16], &[2; 16], &10_u64.to_be_bytes(),
            &40_u64.to_be_bytes(), &150_u64.to_be_bytes(), &[3; 32],
            &7_u64.to_be_bytes(), &99_u64.to_be_bytes(),
        ].concat();

        assert_eq!(fields.encode(b"AOSHLQ01").unwrap().as_slice(), legacy);
        let decoded = QueryFieldsV1::decode(&legacy, b"AOSHLQ01").unwrap();
        assert_eq!(decoded.controller_next, 7);
        assert_eq!(decoded.controller_end, 99);

        let acquisition = fields.envelope().encode(b"AOSANQ02").unwrap();
        assert_eq!(acquisition.len(), 96);
        assert_eq!(&acquisition[8..], &legacy[8..96]);
        assert!(QueryFieldsV1::decode(&acquisition, b"AOSANQ02").is_err());
        assert!(QueryEnvelopeFieldsV2::decode(&legacy, b"AOSHLQ01").is_err());
        assert!(QueryEnvelopeFieldsV2::decode(&acquisition, b"AOSHLQ01").is_err());
    }

    #[test]
    fn shared_temporal_codec_preserves_start_wire_and_accepted_expiry() {
        let admission = HostResourceAdmissionDataV1 {
            root_nonce: [1; 16], controller_nonce: [2; 16], query_digest: [3; 32],
            original_boot: [4; 16], original_boottime_ns: 10,
            original_cutoff_ns: 40, observed_wall_seconds: 100,
            observed_boottime_ns: 20, cutoff_ns: 30,
            policy_expires_seconds: 200, lease_expires_seconds: 180,
            accepted_expires_seconds: 150,
        };
        let mut legacy = Vec::from(&b"AOSHLT01"[..]);
        for field in [&admission.root_nonce[..], &admission.controller_nonce,
            &admission.query_digest, &admission.original_boot] {
            legacy.extend_from_slice(field);
        }
        for field in [admission.original_boottime_ns.to_be_bytes(),
            admission.original_cutoff_ns.to_be_bytes(), admission.observed_wall_seconds.to_be_bytes(),
            admission.observed_boottime_ns.to_be_bytes(), admission.cutoff_ns.to_be_bytes(),
            admission.policy_expires_seconds.to_be_bytes(), admission.lease_expires_seconds.to_be_bytes(),
            admission.accepted_expires_seconds.to_be_bytes()] {
            legacy.extend_from_slice(&field);
        }

        assert_eq!(admission.encode_v1().unwrap().as_slice(), legacy);
        assert_eq!(HostResourceAdmissionDataV1::decode_v1(&legacy).unwrap(), admission);

        let expired = HostResourceAdmissionDataV1 { accepted_expires_seconds: 100, ..admission };
        assert!(expired.encode_v1().is_err());
        legacy[144..152].copy_from_slice(&100_i64.to_be_bytes());
        assert!(HostResourceAdmissionDataV1::decode_v1(&legacy).is_err());
    }
}
