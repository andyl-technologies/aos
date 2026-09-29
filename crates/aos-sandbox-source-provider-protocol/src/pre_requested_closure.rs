//! Query-independent, pre-Requested Source no-escape closure DATA.
//!
//! These canonical claims and signatures do not establish a protected archive,
//! original clock or carrier, current signer eligibility, physical membership,
//! never-Requested/never-Issued evidence, dispatch permission or pin retirement.
//! The actual owners must establish those facts independently.
//!
//! ```text
//! AOSPSC01 | kind:u8=1 | version:u8=1 | reserved[6]=0 |
//! provider[16] | holder[16] | original_digests[7][32] |
//! admission_tx[16] | admission_sequence:u64be |
//! first_cold_tx[16] | first_cold_sequence:u64be |
//! challenge_cut[32] | challenge_sequence:u64be | staged_claims[32] |
//! Challenge_absence_witness[76] | terminal_record_digests[4][32] |
//! terminal_witnesses[132+135+99+139] | ProviderOutcome_signer[120] |
//! signature[64] (signed only)
//! subject=1101, prepared=1221, signed=1285
//! ```

use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};

use crate::crypto::{
    SourceProviderKeyUsageV1, SourceProviderSignature, SourceProviderSignatureError,
    SourceProviderSigningKeyV1, decode_signer, encode_signer, sign_bytes, verify_bytes,
};
use crate::native_held_completion::{
    NativeHeldCompletionErrorV1,
    witness::{NativeHeldByteWitnessV1, NativeHeldRecordFamilyV1 as Family},
};

const MAGIC: &[u8; 8] = b"AOSPSC01";
const KIND: u8 = 1;
const HEADER: [u8; 8] = [KIND, 1, 0, 0, 0, 0, 0, 0];
const SIGNER_BYTES: usize = 120;
const SIGNATURE_BYTES: usize = 64;
const CHALLENGE_WITNESS_BYTES: usize = 36 + 40;
const TERMINAL_WITNESS_BYTES: [usize; 4] = [36 + 96, 36 + 99, 36 + 63, 36 + 103];
const SUBJECT_BYTES: usize = 16
    + 32
    + 7 * 32
    + 48
    + 40
    + 32
    + CHALLENGE_WITNESS_BYTES
    + 4 * 32
    + TERMINAL_WITNESS_BYTES[0]
    + TERMINAL_WITNESS_BYTES[1]
    + TERMINAL_WITNESS_BYTES[2]
    + TERMINAL_WITNESS_BYTES[3];
const SIGNATURE_DOMAIN: &[u8] = b"aos-source-provider-pre-requested-closure.v1\0";
const DIGEST_DOMAIN: &[u8] = b"aos-source-provider-pre-requested-closure-digest.v1\0";
const TERMINAL_FAMILIES: [Family; 4] = [
    Family::ProviderAttempt,
    Family::ProviderAcquisition,
    Family::ProviderHolder,
    Family::ProviderHistory,
];
const TERMINAL_KEY_SUBJECT_BYTES: [usize; 4] = [65, 64, 32, 64];

/// Fixes the complete prepared closure width, including its signer reference.
pub const PREPARED_SOURCE_NO_ESCAPE_CLOSURE_BYTES_V1: usize = SUBJECT_BYTES + SIGNER_BYTES;

/// Fixes the complete signed, query-independent closure width.
pub const SIGNED_SOURCE_NO_ESCAPE_CLOSURE_BYTES_V1: usize =
    PREPARED_SOURCE_NO_ESCAPE_CLOSURE_BYTES_V1 + SIGNATURE_BYTES;

const _: () = assert!(SUBJECT_BYTES == 1101);
const _: () = assert!(CHALLENGE_WITNESS_BYTES == 76);
const _: () = assert!(TERMINAL_WITNESS_BYTES[0] == 132);
const _: () = assert!(TERMINAL_WITNESS_BYTES[1] == 135);
const _: () = assert!(TERMINAL_WITNESS_BYTES[2] == 99);
const _: () = assert!(TERMINAL_WITNESS_BYTES[3] == 139);
const _: () = assert!(PREPARED_SOURCE_NO_ESCAPE_CLOSURE_BYTES_V1 == 1221);
const _: () = assert!(SIGNED_SOURCE_NO_ESCAPE_CLOSURE_BYTES_V1 == 1285);

/// Reports a malformed closure claim or failed cryptographic comparison.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SourceNoEscapeClosureErrorV1 {
    /// A canonical framing, identity, sequence or role invariant failed.
    #[error("noncanonical Source no-escape closure: {0}")]
    Noncanonical(&'static str),
    /// The independently supplied signer differs from the retained reference.
    #[error("Source no-escape closure signer mismatch")]
    SignerMismatch,
    /// The existing fixed-family witness codec rejected the claim.
    #[error("invalid Source no-escape closure witness: {0}")]
    Witness(#[from] NativeHeldCompletionErrorV1),
    /// The existing signer codec or signature verification failed.
    #[error("Source no-escape closure signature failed: {0}")]
    Signature(#[from] SourceProviderSignatureError),
}

/// Carries untrusted original and terminal Source commitments without authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceNoEscapeClosureClaimsV1 {
    /// Names the original Source provider authority.
    pub provider_id: [u8; 16],
    /// Names the original holder authority.
    pub holder_id: [u8; 16],
    /// Commits the original authenticated session.
    pub original_session: ObjectDigest,
    /// Names the original acquisition.
    pub acquisition_id: ObjectDigest,
    /// Commits the exact original signed Acquire request.
    pub original_signed_request: ObjectDigest,
    /// Names the original Source attempt.
    pub original_attempt: ObjectDigest,
    /// Names the original admitted Source5 capacity record.
    pub original_source_floor: ObjectDigest,
    /// Commits the original signed RootPrepared control.
    pub original_root_prepared: ObjectDigest,
    /// Commits the original Applying acquisition's Ledger record value.
    pub original_applying: ObjectDigest,
    /// Reports the original admission transaction identity as DATA.
    pub admission_transaction: [u8; 16],
    /// Reports that admission's physical commit sequence as DATA.
    pub admission_sequence: u64,
    /// Reports the first cold transaction identity as DATA.
    pub first_cold_transaction: [u8; 16],
    /// Reports the first cold physical commit sequence as DATA.
    pub first_cold_sequence: u64,
    /// Commits a claimed complete challenge-owner cut without proving it.
    pub challenge_cut: ObjectDigest,
    /// Reports the separate challenge sequence; an empty journal may use zero.
    pub challenge_sequence: u64,
    /// Commits the original unsigned staged challenge claims.
    pub staged_claims: ObjectDigest,
    /// Claims absence at the exact registered challenge key, without evidence.
    pub challenge_absence: NativeHeldByteWitnessV1,
    /// Commits the terminal Faulted acquisition's Ledger record value.
    pub faulted_acquisition: ObjectDigest,
    /// Commits the terminal Retired attempt's Ledger record value.
    pub retired_attempt: ObjectDigest,
    /// Commits the original holder after its pending attempt was cleared.
    pub cleared_session: ObjectDigest,
    /// Commits the exact original session-history successor.
    pub session_history_successor: ObjectDigest,
    /// Lists terminal Attempt, Acquisition, Holder and History byte witnesses.
    pub terminal_records: [NativeHeldByteWitnessV1; 4],
}

/// Retains canonical unsigned closure DATA and its fixed ProviderOutcome signer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedSourceNoEscapeClosureV1 {
    claims: SourceNoEscapeClosureClaimsV1,
    signer: SourceProviderSigningKeyV1,
    canonical: [u8; PREPARED_SOURCE_NO_ESCAPE_CLOSURE_BYTES_V1],
}

impl PreparedSourceNoEscapeClosureV1 {
    /// Validates bounded closure claims without creating a protected owner.
    ///
    /// # Errors
    /// Rejects sentinel fields, impossible sequence ordering, a foreign signer,
    /// substituted witness families or source identities, or noncanonical keys.
    pub fn new_untrusted(
        claims: SourceNoEscapeClosureClaimsV1,
        signer: SourceProviderSigningKeyV1,
    ) -> Result<Self, SourceNoEscapeClosureErrorV1> {
        validate_claims(&claims, &signer)?;
        let canonical = encode_prepared(&claims, &signer)?;

        Ok(Self {
            claims,
            signer,
            canonical,
        })
    }

    /// Decodes only the exact prepared DATA shape, not physical provenance.
    ///
    /// # Errors
    /// Rejects another frame width or header, malformed fixed fields or witnesses,
    /// an invalid signer reference, or any noncanonical re-encoding.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, SourceNoEscapeClosureErrorV1> {
        require_header(bytes, PREPARED_SOURCE_NO_ESCAPE_CLOSURE_BYTES_V1)?;

        let claims = SourceNoEscapeClosureClaimsV1 {
            provider_id: array_at(bytes, 16)?,
            holder_id: array_at(bytes, 32)?,
            original_session: digest_at(bytes, 48)?,
            acquisition_id: digest_at(bytes, 80)?,
            original_signed_request: digest_at(bytes, 112)?,
            original_attempt: digest_at(bytes, 144)?,
            original_source_floor: digest_at(bytes, 176)?,
            original_root_prepared: digest_at(bytes, 208)?,
            original_applying: digest_at(bytes, 240)?,
            admission_transaction: array_at(bytes, 272)?,
            admission_sequence: u64::from_be_bytes(array_at(bytes, 288)?),
            first_cold_transaction: array_at(bytes, 296)?,
            first_cold_sequence: u64::from_be_bytes(array_at(bytes, 312)?),
            challenge_cut: digest_at(bytes, 320)?,
            challenge_sequence: u64::from_be_bytes(array_at(bytes, 352)?),
            staged_claims: digest_at(bytes, 360)?,
            challenge_absence: decode_witness(bytes, 392, CHALLENGE_WITNESS_BYTES, Family::Challenge)?,
            faulted_acquisition: digest_at(bytes, 468)?,
            retired_attempt: digest_at(bytes, 500)?,
            cleared_session: digest_at(bytes, 532)?,
            session_history_successor: digest_at(bytes, 564)?,
            terminal_records: [
                decode_witness(bytes, 596, TERMINAL_WITNESS_BYTES[0], TERMINAL_FAMILIES[0])?,
                decode_witness(bytes, 728, TERMINAL_WITNESS_BYTES[1], TERMINAL_FAMILIES[1])?,
                decode_witness(bytes, 863, TERMINAL_WITNESS_BYTES[2], TERMINAL_FAMILIES[2])?,
                decode_witness(bytes, 962, TERMINAL_WITNESS_BYTES[3], TERMINAL_FAMILIES[3])?,
            ],
        };
        let signer = decode_signer(slice_at(bytes, SUBJECT_BYTES, SIGNER_BYTES)?)?;
        let prepared = Self::new_untrusted(claims, signer)?;
        if prepared.canonical.as_slice() != bytes {
            return Err(noncanonical("prepared re-encoding"));
        }

        Ok(prepared)
    }

    /// Borrows the fixed canonical prepared DATA bytes.
    #[must_use]
    pub const fn as_canonical_bytes(&self) -> &[u8; PREPARED_SOURCE_NO_ESCAPE_CLOSURE_BYTES_V1] {
        &self.canonical
    }

    /// Copies the fixed canonical prepared DATA bytes.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        self.canonical.to_vec()
    }

    /// Borrows validated claims without establishing their protected origin.
    #[must_use]
    pub const fn claims(&self) -> &SourceNoEscapeClosureClaimsV1 {
        &self.claims
    }

    /// Borrows the fixed role reference without resolving current eligibility.
    #[must_use]
    pub const fn signer(&self) -> &SourceProviderSigningKeyV1 {
        &self.signer
    }
}

/// Carries a query-independent signature claim, not a protected closure readback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedSourceNoEscapeClosureV1 {
    prepared: PreparedSourceNoEscapeClosureV1,
    signature: SourceProviderSignature,
}

impl SignedSourceNoEscapeClosureV1 {
    /// Signs exact prepared DATA with a caller-owned matching key.
    ///
    /// This stateless operation is not a production one-shot custody latch or
    /// permission to attest never-Requested/never-Issued owner state.
    ///
    /// # Errors
    /// Rejects a signing key whose fingerprint differs from the retained signer.
    pub fn sign(
        prepared: &PreparedSourceNoEscapeClosureV1,
        signing_key: &SigningKey,
    ) -> Result<Self, SourceNoEscapeClosureErrorV1> {
        let signature = sign_bytes(
            SIGNATURE_DOMAIN,
            KIND,
            &prepared.canonical[..SUBJECT_BYTES],
            &prepared.signer,
            signing_key,
        )?;

        Ok(Self {
            prepared: prepared.clone(),
            signature,
        })
    }

    /// Decodes exact signed DATA without resolving or verifying a signer.
    ///
    /// # Errors
    /// Rejects another width/header, invalid prepared claims, or noncanonical
    /// bytes. A parsed signature is still an unverified claim, including zero.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, SourceNoEscapeClosureErrorV1> {
        require_header(bytes, SIGNED_SOURCE_NO_ESCAPE_CLOSURE_BYTES_V1)?;
        let prepared = PreparedSourceNoEscapeClosureV1::from_canonical_bytes(slice_at(
            bytes,
            0,
            PREPARED_SOURCE_NO_ESCAPE_CLOSURE_BYTES_V1,
        )?)?;
        let signed = Self {
            prepared,
            signature: SourceProviderSignature::from_bytes(array_at(
                bytes,
                PREPARED_SOURCE_NO_ESCAPE_CLOSURE_BYTES_V1,
            )?),
        };
        if signed.to_canonical_bytes() != bytes {
            return Err(noncanonical("signed re-encoding"));
        }

        Ok(signed)
    }

    /// Copies the exact signed closure DATA bytes.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = self.prepared.to_canonical_bytes();
        bytes.extend_from_slice(self.signature.as_bytes());
        bytes
    }

    /// Borrows the retained prepared DATA, not a prepared owner token.
    #[must_use]
    pub const fn prepared(&self) -> &PreparedSourceNoEscapeClosureV1 {
        &self.prepared
    }

    /// Borrows the signature claim without establishing current eligibility.
    #[must_use]
    pub const fn signature(&self) -> &SourceProviderSignature {
        &self.signature
    }

    /// Verifies the exact independent signer pin and strict signature as DATA.
    ///
    /// Success does not prove an actual archive, live role, owner cut, absent
    /// challenge, Root terminal, dispatch permission or pin retirement.
    ///
    /// # Errors
    /// Rejects signer substitution, a mismatched fingerprint, invalid or weak
    /// public-key material, or an invalid signature over the retained subject.
    pub fn verify(
        &self,
        expected_signer: &SourceProviderSigningKeyV1,
        public_key: &[u8; 32],
    ) -> Result<(), SourceNoEscapeClosureErrorV1> {
        if &self.prepared.signer != expected_signer {
            return Err(SourceNoEscapeClosureErrorV1::SignerMismatch);
        }

        verify_bytes(
            SIGNATURE_DOMAIN,
            KIND,
            &self.prepared.canonical[..SUBJECT_BYTES],
            &self.prepared.signer,
            &self.signature,
            public_key,
        )?;
        Ok(())
    }

    /// Commits the immutable exact signed closure bytes in their own domain.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        let bytes = self.to_canonical_bytes();
        let digest = Sha256::new()
            .chain_update(DIGEST_DOMAIN)
            .chain_update((SIGNED_SOURCE_NO_ESCAPE_CLOSURE_BYTES_V1 as u32).to_be_bytes())
            .chain_update(bytes)
            .finalize();
        ObjectDigest::from_bytes(digest.into())
    }
}

fn validate_claims(
    claims: &SourceNoEscapeClosureClaimsV1,
    signer: &SourceProviderSigningKeyV1,
) -> Result<(), SourceNoEscapeClosureErrorV1> {
    if claims.provider_id == [0; 16]
        || claims.holder_id == [0; 16]
        || claims.admission_transaction == [0; 16]
        || claims.first_cold_transaction == [0; 16]
        || claims.admission_transaction == claims.first_cold_transaction
    {
        return Err(noncanonical("source or transaction identity"));
    }
    if [
        claims.original_session,
        claims.acquisition_id,
        claims.original_signed_request,
        claims.original_attempt,
        claims.original_source_floor,
        claims.original_root_prepared,
        claims.original_applying,
        claims.challenge_cut,
        claims.staged_claims,
        claims.faulted_acquisition,
        claims.retired_attempt,
        claims.cleared_session,
        claims.session_history_successor,
    ]
    .into_iter()
    .any(|digest| digest.as_bytes() == &[0; 32])
    {
        return Err(noncanonical("sentinel record commitment"));
    }

    // Intervening independently funded appends are allowed; only the real
    // owner can compare the first cold commit with its actual before cut +9.
    let earliest_cold = claims
        .admission_sequence
        .checked_add(9)
        .ok_or_else(|| noncanonical("physical sequence overflow"))?;
    if claims.admission_sequence == 0 || claims.first_cold_sequence < earliest_cold {
        return Err(noncanonical("physical sequence ordering"));
    }
    if signer.usage() != SourceProviderKeyUsageV1::ProviderOutcome
        || signer.authority_id() != claims.provider_id
    {
        return Err(noncanonical("ProviderOutcome signer authority"));
    }

    validate_witness(&claims.challenge_absence, Family::Challenge)?;
    if claims.challenge_absence.digest().as_bytes() != &[0; 32] {
        return Err(noncanonical("challenge absence claim"));
    }
    for (index, witness) in claims.terminal_records.iter().enumerate() {
        validate_witness(witness, TERMINAL_FAMILIES[index])?;
        if witness.digest().as_bytes() == &[0; 32] {
            return Err(noncanonical("sentinel terminal byte witness"));
        }

        let subject = key_subject(witness, TERMINAL_KEY_SUBJECT_BYTES[index])?;
        if subject.get(..16) != Some(claims.provider_id.as_slice())
            || subject.get(16..32) != Some(claims.holder_id.as_slice())
        {
            return Err(noncanonical("terminal witness source identities"));
        }
        if index == 1 && subject.get(32..64) != Some(claims.acquisition_id.as_bytes().as_slice()) {
            return Err(noncanonical("terminal witness acquisition"));
        }
        if index == 3 && subject.get(32..64) != Some(claims.original_session.as_bytes().as_slice()) {
            return Err(noncanonical("terminal witness original session"));
        }
    }
    Ok(())
}

fn encode_prepared(
    claims: &SourceNoEscapeClosureClaimsV1,
    signer: &SourceProviderSigningKeyV1,
) -> Result<[u8; PREPARED_SOURCE_NO_ESCAPE_CLOSURE_BYTES_V1], SourceNoEscapeClosureErrorV1> {
    let mut bytes = Vec::with_capacity(PREPARED_SOURCE_NO_ESCAPE_CLOSURE_BYTES_V1);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&HEADER);
    bytes.extend_from_slice(&claims.provider_id);
    bytes.extend_from_slice(&claims.holder_id);
    for digest in [
        claims.original_session,
        claims.acquisition_id,
        claims.original_signed_request,
        claims.original_attempt,
        claims.original_source_floor,
        claims.original_root_prepared,
        claims.original_applying,
    ] {
        bytes.extend_from_slice(digest.as_bytes());
    }
    bytes.extend_from_slice(&claims.admission_transaction);
    bytes.extend_from_slice(&claims.admission_sequence.to_be_bytes());
    bytes.extend_from_slice(&claims.first_cold_transaction);
    bytes.extend_from_slice(&claims.first_cold_sequence.to_be_bytes());
    bytes.extend_from_slice(claims.challenge_cut.as_bytes());
    bytes.extend_from_slice(&claims.challenge_sequence.to_be_bytes());
    bytes.extend_from_slice(claims.staged_claims.as_bytes());
    bytes.extend_from_slice(&claims.challenge_absence.to_canonical_bytes());
    for digest in [
        claims.faulted_acquisition,
        claims.retired_attempt,
        claims.cleared_session,
        claims.session_history_successor,
    ] {
        bytes.extend_from_slice(digest.as_bytes());
    }
    for witness in &claims.terminal_records {
        bytes.extend_from_slice(&witness.to_canonical_bytes());
    }
    encode_signer(&mut bytes, signer);

    bytes
        .try_into()
        .map_err(|_| noncanonical("prepared encoding width"))
}

fn validate_witness(
    witness: &NativeHeldByteWitnessV1,
    family: Family,
) -> Result<(), SourceNoEscapeClosureErrorV1> {
    // Immutable witnesses already retain canonical keys; this checks placement.
    if witness.family() != family {
        return Err(noncanonical("fixed witness family"));
    }
    Ok(())
}

fn key_subject(
    witness: &NativeHeldByteWitnessV1,
    length: usize,
) -> Result<&[u8], SourceNoEscapeClosureErrorV1> {
    let start = witness
        .key()
        .len()
        .checked_sub(length)
        .ok_or_else(|| noncanonical("witness key subject width"))?;
    witness
        .key()
        .get(start..)
        .ok_or_else(|| noncanonical("witness key subject"))
}

fn decode_witness(
    bytes: &[u8],
    start: usize,
    width: usize,
    family: Family,
) -> Result<NativeHeldByteWitnessV1, SourceNoEscapeClosureErrorV1> {
    Ok(NativeHeldByteWitnessV1::from_canonical_bytes(
        family,
        slice_at(bytes, start, width)?,
    )?)
}

fn require_header(bytes: &[u8], width: usize) -> Result<(), SourceNoEscapeClosureErrorV1> {
    if bytes.len() != width
        || bytes.get(..8) != Some(MAGIC.as_slice())
        || bytes.get(8..16) != Some(HEADER.as_slice())
    {
        return Err(noncanonical("closure width or header"));
    }
    Ok(())
}

fn slice_at(
    bytes: &[u8],
    start: usize,
    width: usize,
) -> Result<&[u8], SourceNoEscapeClosureErrorV1> {
    let end = start
        .checked_add(width)
        .ok_or_else(|| noncanonical("field offset overflow"))?;
    bytes
        .get(start..end)
        .ok_or_else(|| noncanonical("truncated fixed field"))
}

fn array_at<const N: usize>(
    bytes: &[u8],
    start: usize,
) -> Result<[u8; N], SourceNoEscapeClosureErrorV1> {
    slice_at(bytes, start, N)?
        .try_into()
        .map_err(|_| noncanonical("fixed field width"))
}

fn digest_at(bytes: &[u8], start: usize) -> Result<ObjectDigest, SourceNoEscapeClosureErrorV1> {
    Ok(ObjectDigest::from_bytes(array_at(bytes, start)?))
}

fn noncanonical(reason: &'static str) -> SourceNoEscapeClosureErrorV1 {
    SourceNoEscapeClosureErrorV1::Noncanonical(reason)
}

#[cfg(test)]
#[path = "pre_requested_closure/tests.rs"]
mod tests;
