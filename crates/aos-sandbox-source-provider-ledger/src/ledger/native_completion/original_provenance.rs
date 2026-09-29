//! Immutable original Source dispatch provenance, without owner authority.
//!
//! ```text
//! Root1_length:u32be | exact_signed_Root1 | claims_length:u32be | unsigned_claims |
//! raw_pair[48] | original_deadline:u64be | narrowed_deadline:u64be |
//! diagnostic_sequence:u64be | configuration[32] | four_fixed_ByteWitnesses[505]
//! ```
//!
//! Decoding joins archived DATA only. It neither authenticates signatures or a
//! clock nor establishes physical admission, currentness, custody, or dispatch.

use aos_sandbox_core::{ObjectDigest, RawPairedClockSample};
use aos_sandbox_source_provider_protocol::native_held_completion::{
    MAXIMUM_NATIVE_HELD_CONTROL_BYTES_V1, NativeHeldControlKindV1,
    frame::{NativeHeldSignerV1, SignedNativeHeldControlV1},
    witness::{NativeHeldByteWitnessV1, NativeHeldRecordFamilyV1, native_held_record_byte_digest_v1},
};
use aos_sandbox_source_provider_protocol::{
    MAXIMUM_STORAGE_ZFS_HOLD_REQUEST_PACKET_BYTES_V1, SignedSourceProviderRequestV1,
    SourceProviderMethod, StorageNativeAcquireRequestV2,
    StorageZfsHoldTransportRequestV1, decode_acquire_request, digest_signed_request,
};

use super::super::LedgerFormatErrorV1;
use super::super::codec::{Decoder, Encoder};
use super::super::format;
use super::super::model::{
    AcquisitionKeyV1, AttemptKeyV1, AttemptRecordV1, DecodedRecordV1, ProviderAttemptStateV1,
};
use super::clock::{conservative_deadline, decode_raw_pair, encode_raw_pair};

const MAXIMUM_ROOT_BYTES: usize = MAXIMUM_NATIVE_HELD_CONTROL_BYTES_V1;
const MAXIMUM_CLAIMS_BYTES: usize = MAXIMUM_STORAGE_ZFS_HOLD_REQUEST_PACKET_BYTES_V1;
const FIXED_BYTES: usize = 617;
const FAMILIES: [NativeHeldRecordFamilyV1; 4] = [
    NativeHeldRecordFamilyV1::ProviderAttempt,
    NativeHeldRecordFamilyV1::ProviderAcquisition,
    NativeHeldRecordFamilyV1::ProviderHolder,
    NativeHeldRecordFamilyV1::ProviderHistory,
];

/// Bounds the exact original provenance tail independently of journal framing.
pub const MAXIMUM_ORIGINAL_SOURCE_PROVENANCE_BYTES_V5: usize =
    FIXED_BYTES + MAXIMUM_ROOT_BYTES + MAXIMUM_CLAIMS_BYTES;

// This family cannot silently widen when an upstream archive ceiling changes.
const _: () = assert!(MAXIMUM_ORIGINAL_SOURCE_PROVENANCE_BYTES_V5 == 30_123);

/// Supplies untrusted immutable original provenance DATA to the pure codec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginalSourceProvenanceClaimsV5 {
    /// Retains exact signed original RootPrepared bytes, including its signer.
    pub root_prepared: SignedNativeHeldControlV1,
    /// Retains the original unsigned Storage stage claims, never a send permit.
    pub claims: StorageZfsHoldTransportRequestV1,
    /// Retains the original raw clock claims, not a live kernel clock adapter.
    pub initial: RawPairedClockSample,
    /// Names the exclusive original authorization cutoff in local BOOTTIME.
    pub original_deadline: u64,
    /// Names the exclusive staged cutoff derived from the same original pair.
    pub narrowed_deadline: u64,
    /// Retains a diagnostic sequence, not physical transaction membership.
    pub journal_sequence: u64,
    /// Commits the original owner configuration; current configuration is separate.
    pub configuration: ObjectDigest,
    /// Retains Attempt, Acquisition, Holder, and History byte witnesses in order.
    pub records: [NativeHeldByteWitnessV1; 4],
}

/// Retains canonical original Source DATA without constructing trusted provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginalSourceProvenanceV5 {
    data: OriginalSourceProvenanceClaimsV5,
}

impl OriginalSourceProvenanceV5 {
    /// Checks bounded canonical DATA and the joins available in this archive.
    ///
    /// The original Attempt is deliberately not supplied here. Its authorization
    /// expiry and exact request ID require `validate_original_attempt_claims`;
    /// passing either method is not a protected owner or admission proof.
    ///
    /// # Errors
    ///
    /// Rejects wrong Root kind/scope/signer, stage sequence, subject witnesses,
    /// sentinel commitments, malformed cutoffs, or oversized canonical archives.
    pub fn new_untrusted(
        data: OriginalSourceProvenanceClaimsV5,
    ) -> Result<Self, LedgerFormatErrorV1> {
        let root = &data.root_prepared;
        let scope = root.scope();
        scope
            .validate_root_only()
            .map_err(|_| invalid("original Source Root scope"))?;
        let NativeHeldSignerV1::SourceProvider(signer) = root.prepared().signer() else {
            return Err(invalid("original Source Root signer"));
        };
        let (provider, acquisition) = data.claims.provider_acquisition();
        let (holder, session) = data.claims.holder_session();
        if root.kind() != NativeHeldControlKindV1::RootPrepared
            || data.claims.sequence() != 1
            || signer.authority_id() != holder
            || scope.original_source_session != session
            || scope.provider_acquisition != acquisition
            || data.configuration.as_bytes() == &[0; 32]
            || data.journal_sequence == 0
            || root.to_canonical_bytes().len() > MAXIMUM_ROOT_BYTES
            || data.claims.to_canonical_bytes().len() > MAXIMUM_CLAIMS_BYTES
        {
            return Err(invalid("original Source archive bindings"));
        }

        let initial = data.initial;
        let original_delta = data
            .original_deadline
            .checked_sub(initial.boottime_nanoseconds());
        if initial.wall_seconds() < 0
            || initial.wall_seconds() > data.claims.validity().0
            || data.narrowed_deadline != conservative_deadline(initial, data.claims.validity().1)?
            || data.narrowed_deadline > data.original_deadline
            || !original_delta.is_some_and(|delta| delta > 0 && delta % 1_000_000_000 == 0)
        {
            return Err(invalid("original Source clock claims"));
        }

        for (record, family) in data.records.iter().zip(FAMILIES) {
            if record.family() != family || record.digest().as_bytes() == &[0; 32] {
                return Err(invalid("original Source witness family or digest"));
            }
        }
        // The last 16 bytes retain the request ID for the separate original Attempt join.
        let request_id = data.records[0]
            .key()
            .get(80..96)
            .ok_or(invalid("original Source Attempt key"))?;
        let mut request_id_array = [0; 16];
        request_id_array.copy_from_slice(request_id);
        let expected_attempt = format::attempt_key(&AttemptKeyV1 {
            provider_id: provider,
            holder_id: holder,
            root_record_key_id: signer.key_id(),
            method: SourceProviderMethod::Acquire as u8,
            request_id: request_id_array,
        });
        let expected_acquisition = format::acquisition_key(&AcquisitionKeyV1 {
            provider_id: provider,
            holder_id: holder,
            acquisition_id: acquisition,
        });
        if data.records[0].key() != expected_attempt
            || data.records[1].key() != expected_acquisition
            || data.records[2].key() != format::session_key(provider, holder)
            || data.records[3].key() != format::session_history_key(provider, holder, session)
        {
            return Err(invalid("original Source witness subjects"));
        }
        Ok(Self { data })
    }

    /// Returns immutable archived claims, not a verified owner graph.
    #[must_use]
    pub const fn claims(&self) -> &OriginalSourceProvenanceClaimsV5 {
        &self.data
    }

    /// Encodes the exact bounded DATA tail without a journal identity envelope.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let root = self.data.root_prepared.to_canonical_bytes();
        let claims = self.data.claims.to_canonical_bytes();
        let mut body = Encoder::with_capacity(FIXED_BYTES + root.len() + claims.len());
        body.u32(root.len() as u32);
        body.bytes(&root);
        body.u32(claims.len() as u32);
        body.bytes(&claims);
        encode_raw_pair(self.data.initial, &mut body);
        body.u64(self.data.original_deadline);
        body.u64(self.data.narrowed_deadline);
        body.u64(self.data.journal_sequence);
        body.digest(self.data.configuration);
        for witness in &self.data.records {
            body.bytes(&witness.to_canonical_bytes());
        }
        body.as_slice().to_vec()
    }

    /// Decodes exact canonical archived DATA and joins its available subjects.
    ///
    /// # Errors
    ///
    /// Rejects truncation, excessive lengths, invalid nested DATA, changed subjects
    /// or cutoffs, and noncanonical or trailing bytes. No signature is verified.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, LedgerFormatErrorV1> {
        if !(FIXED_BYTES..=MAXIMUM_ORIGINAL_SOURCE_PROVENANCE_BYTES_V5).contains(&bytes.len()) {
            return Err(invalid("original Source provenance width"));
        }
        let mut body = Decoder::new(bytes);
        let root_len = body.bounded_len(MAXIMUM_ROOT_BYTES)?;
        let root_prepared = SignedNativeHeldControlV1::from_canonical_bytes(body.take(root_len)?)
            .map_err(|_| invalid("original Source Root encoding"))?;
        let claims_len = body.bounded_len(MAXIMUM_CLAIMS_BYTES)?;
        let claims = StorageZfsHoldTransportRequestV1::from_canonical_bytes(body.take(claims_len)?)
            .map_err(|_| invalid("original Source stage encoding"))?;
        let initial = decode_raw_pair(&mut body)?;
        let original_deadline = body.u64()?;
        let narrowed_deadline = body.u64()?;
        let journal_sequence = body.u64()?;
        let configuration = body.digest()?;
        let mut records = Vec::with_capacity(4);
        for family in FAMILIES {
            let witness = NativeHeldByteWitnessV1::from_canonical_bytes(
                family,
                body.take(36 + family.key_bytes())?,
            )
            .map_err(|_| invalid("original Source witness encoding"))?;
            records.push(witness);
        }
        body.finish()?;
        let records = records
            .try_into()
            .map_err(|_| invalid("original Source witness count"))?;
        let result = Self::new_untrusted(OriginalSourceProvenanceClaimsV5 {
            root_prepared,
            claims,
            initial,
            original_deadline,
            narrowed_deadline,
            journal_sequence,
            configuration,
            records,
        })?;
        if result.to_canonical_bytes() != bytes {
            return Err(invalid("original Source provenance canonicality"));
        }
        Ok(result)
    }

    /// Joins the actual original Attempt's canonical DATA and authorization expiry.
    ///
    /// This checks no signature trust, journal origin, currentness, live clock,
    /// configuration, custody, or complete owner graph. Callers must obtain and
    /// validate those independently before a protected effect.
    ///
    /// # Errors
    ///
    /// Rejects a changed original Reserved Attempt, request/signer/session/catalog
    /// join, original byte witness, boot/wall bounds, or authorization cutoff.
    pub fn validate_original_attempt_claims(
        &self,
        attempt: &AttemptRecordV1,
    ) -> Result<(), LedgerFormatErrorV1> {
        let data = &self.data;
        let signed = SignedSourceProviderRequestV1::from_canonical_bytes(&attempt.signed_request)
            .map_err(|_| invalid("original Source Acquire encoding"))?;
        let root = decode_acquire_request(signed.subject())
            .map_err(|_| invalid("original Source Acquire subject"))?;
        let NativeHeldSignerV1::SourceProvider(signer) = data.root_prepared.prepared().signer() else {
            return Err(invalid("original Source Root signer"));
        };
        StorageNativeAcquireRequestV2::new_native_v3(data.claims.clone(), signed.clone())
            .map_err(|_| invalid("original Source stage/Acquire join"))?;
        let key = format::attempt_key(&AttemptKeyV1 {
            provider_id: attempt.provider.authority_id(),
            holder_id: attempt.holder.authority_id(),
            root_record_key_id: attempt.root_record_signer.key_id(),
            method: attempt.method as u8,
            request_id: attempt.request_id,
        });
        let bytes = format::encode_attempt(attempt);
        let DecodedRecordV1::Attempt(canonical) = format::decode_record(&key, &bytes)? else {
            return Err(invalid("original Source Attempt record kind"));
        };
        if canonical != *attempt {
            return Err(invalid("original Source Attempt canonicality"));
        }
        let witness = native_held_record_byte_digest_v1(FAMILIES[0], &key, &bytes)
            .map_err(|_| invalid("original Source Attempt witness"))?;
        if attempt.revision != 1
            || attempt.state != ProviderAttemptStateV1::Reserved
            || attempt.method != SourceProviderMethod::Acquire
            || attempt.provider.authority_id() != data.claims.provider_acquisition().0
            || attempt.holder.authority_id() != data.claims.holder_session().0
            || attempt.session_binding != data.claims.holder_session().1
            || attempt.attempt_digest != data.claims.attempt().1
            || attempt.root_record_signer != *signer
            || signed.signer() != signer
            || digest_signed_request(&signed) != data.root_prepared.scope().original_root_request
            || attempt.signed_request_digest != digest_signed_request(&signed)
            || attempt.request_id != root.request_id()
            || attempt.deadline_seconds != root.deadline_seconds()
            || data.initial.host_boot_id() != root.boot_id()
            || data.initial.wall_seconds() < attempt.verified_at_seconds
            || data.records[0].key() != key
            || data.records[0].digest() != witness
            || data.original_deadline != conservative_deadline(
                data.initial,
                root.deadline_seconds().min(attempt.current_valid_until_seconds),
            )?
        {
            return Err(invalid("original Source Attempt/archive join"));
        }
        Ok(())
    }
}

fn invalid(message: &'static str) -> LedgerFormatErrorV1 {
    LedgerFormatErrorV1::Corrupt(message)
}
