//! Frames Root's admitted use and completed signing result as comparison DATA.
//!
//! ```text
//! UseAdmitted[216] = AOSXUM01 | UseReserved[32] | phase7[32] |
//!                    second-Source[32] | second-Cache[32] | U-claim[16] |
//!                    canonical-plan[32] | canonical-signing-statement[32]
//! SignedBound[160] = AOSXBD01 | signed-bundle[32] | total:u64be |
//!                    request-id[16] | request-body[32] | plan[32] | signature[32]
//! native-receipt = original-record | head[40] | names[48] | NEXT[8] | end[8]
//! signed-bundle = AOSXSB01 | plan-length:u32be | signature-length:u32be |
//!                 request-body-length:u32be | plan | signature | request-body
//! ```
//!
//! The shared history envelope binds each body to its exact predecessor, lane
//! and accepted seed. These formats carry no signer, paid owner or current cut.
//! Actual producers must retain their independent native reads, same original
//! deadline and all owed posts before appending or sending these bytes.

use sha2::{Digest as _, Sha256};

use super::{HEAD_BYTES, HistoryErrorV1, RECORD_OVERHEAD_BYTES, nonzero, reader};

pub(in crate::domain_ledger) mod framing;
mod receipt;

pub use receipt::{ContinuationKindV1, ContinuationNativeReceiptDataV1};

/// Specifies the exact admitted-use body width.
pub const USE_ADMITTED_BODY_BYTES_V1: usize = 216;
/// Specifies the exact signed-result binding body width.
pub const SIGNED_BOUND_BODY_BYTES_V1: usize = 160;
/// Specifies the complete Root revision-three record width.
pub const USE_ADMITTED_RECORD_BYTES_V1: usize = RECORD_OVERHEAD_BYTES + USE_ADMITTED_BODY_BYTES_V1;
/// Specifies the complete Root revision-four record width.
pub const SIGNED_BOUND_RECORD_BYTES_V1: usize = RECORD_OVERHEAD_BYTES + SIGNED_BOUND_BODY_BYTES_V1;
/// Specifies the complete Root admitted-use native receipt width.
pub const USE_ADMITTED_RECEIPT_BYTES_V1: usize = USE_ADMITTED_RECORD_BYTES_V1 + HEAD_BYTES + 64;
/// Specifies the complete Root signed-result native receipt width.
pub const SIGNED_BOUND_RECEIPT_BYTES_V1: usize = SIGNED_BOUND_RECORD_BYTES_V1 + HEAD_BYTES + 64;
/// Specifies the length prefix for the three original signed-result fields.
pub const SIGNED_PREPARATION_PREFIX_BYTES_V1: usize = 20;

/// Records the independently checked successor and both new current proofs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UseAdmittedBodyDataV1 {
    /// The actual Controller UseReserved record checksum.
    pub use_reserved: [u8; 32],
    /// The named commitment of the exact received phase-seven payload.
    pub current_proofs: [u8; 32],
    /// The new independently verified Source packet commitment.
    pub source_current: [u8; 32],
    /// The new independently verified Cache packet commitment.
    pub cache_current: [u8; 32],
    /// The exact purpose-fifteen claim read from the same Controller bank.
    pub use_claim: [u8; 16],
    /// The SHA-256 of the exact canonical unsigned broker plan.
    pub unsigned_plan: [u8; 32],
    /// The SHA-256 of the exact canonical signing statement.
    pub signing_statement: [u8; 32],
}

impl UseAdmittedBodyDataV1 {
    /// Decodes the complete fixed body without authenticating its observations.
    ///
    /// # Errors
    /// Rejects a changed magic, width, trailing bytes or zero comparison fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, HistoryErrorV1> {
        let mut input = reader(bytes);
        if input.array::<8>()? != *b"AOSXUM01" {
            return Err(HistoryErrorV1::Malformed);
        }
        let value = Self {
            use_reserved: input.array()?,
            current_proofs: input.array()?,
            source_current: input.array()?,
            cache_current: input.array()?,
            use_claim: input.array()?,
            unsigned_plan: input.array()?,
            signing_statement: input.array()?,
        };
        input.finish()?;
        value.encode()?;
        Ok(value)
    }

    /// Encodes the fixed observation joins into caller-owned bounded storage.
    ///
    /// # Errors
    /// Rejects zero record, proof or claim identities.
    pub fn encode(self) -> Result<[u8; USE_ADMITTED_BODY_BYTES_V1], HistoryErrorV1> {
        nonzero(&self.use_claim)?;
        let mut bytes = [0; USE_ADMITTED_BODY_BYTES_V1];
        bytes[..8].copy_from_slice(b"AOSXUM01");
        for (index, field) in [
            self.use_reserved,
            self.current_proofs,
            self.source_current,
            self.cache_current,
        ]
        .iter()
        .enumerate()
        {
            nonzero(field)?;
            bytes[8 + index * 32..40 + index * 32].copy_from_slice(field);
        }
        nonzero(&self.unsigned_plan)?;
        nonzero(&self.signing_statement)?;
        bytes[136..152].copy_from_slice(&self.use_claim);
        bytes[152..184].copy_from_slice(&self.unsigned_plan);
        bytes[184..].copy_from_slice(&self.signing_statement);
        Ok(bytes)
    }
}

/// Binds the original request to the complete already-produced signing bundle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignedBoundBodyDataV1 {
    /// The domain-separated commitment of all three exact bundle fields.
    pub bundle: [u8; 32],
    /// The complete encoded bundle length, including its fixed prefix.
    pub bundle_bytes: u64,
    /// The actual stable Prepare request identity.
    pub request_id: [u8; 16],
    /// The SHA-256 of the exact Prepare request body.
    pub request_body: [u8; 32],
    /// The SHA-256 of the canonical signed broker-plan bytes.
    pub plan: [u8; 32],
    /// The SHA-256 of the canonical detached signature artifact bytes.
    pub signature: [u8; 32],
}

impl SignedBoundBodyDataV1 {
    /// Decodes the exact fixed binding without verifying a signature or request.
    ///
    /// # Errors
    /// Rejects malformed framing, zero joins or an absent complete bundle.
    pub fn decode(bytes: &[u8]) -> Result<Self, HistoryErrorV1> {
        let mut input = reader(bytes);
        if input.array::<8>()? != *b"AOSXBD01" {
            return Err(HistoryErrorV1::Malformed);
        }
        let value = Self {
            bundle: input.array()?,
            bundle_bytes: input.u64()?,
            request_id: input.array()?,
            request_body: input.array()?,
            plan: input.array()?,
            signature: input.array()?,
        };
        input.finish()?;
        value.encode()?;
        Ok(value)
    }

    /// Encodes the exact fixed binding without allocating or invoking a signer.
    ///
    /// # Errors
    /// Rejects zero request or artifact identities or an empty bundle.
    pub fn encode(self) -> Result<[u8; SIGNED_BOUND_BODY_BYTES_V1], HistoryErrorV1> {
        for field in [
            &self.bundle,
            &self.request_body,
            &self.plan,
            &self.signature,
        ] {
            nonzero(field)?;
        }
        nonzero(&self.request_id)?;
        if self.bundle_bytes <= SIGNED_PREPARATION_PREFIX_BYTES_V1 as u64 {
            return Err(HistoryErrorV1::Extent);
        }
        let mut bytes = [0; SIGNED_BOUND_BODY_BYTES_V1];
        bytes[..8].copy_from_slice(b"AOSXBD01");
        bytes[8..40].copy_from_slice(&self.bundle);
        bytes[40..48].copy_from_slice(&self.bundle_bytes.to_be_bytes());
        bytes[48..64].copy_from_slice(&self.request_id);
        bytes[64..96].copy_from_slice(&self.request_body);
        bytes[96..128].copy_from_slice(&self.plan);
        bytes[128..].copy_from_slice(&self.signature);
        Ok(bytes)
    }
}

/// Borrows the original plan, detached signature and exact Prepare request body.
///
/// The original Ownership lease remains in the accepted Ready bundle. It is
/// never replaced or reissued by this transfer. The actual receiver verifies
/// both existing artifacts and reconstructs the same semantic request itself.
#[derive(Clone, Copy)]
pub struct SignedPreparationBundleDataV1<'bytes> {
    /// The canonical broker-plan bytes from the actual signing preparation.
    pub plan: &'bytes [u8],
    /// The actual completed canonical detached signature artifact.
    pub signature: &'bytes [u8],
    /// The exact Prepare body carrying its actual stable request identity.
    pub request_body: &'bytes [u8],
}

impl<'bytes> SignedPreparationBundleDataV1<'bytes> {
    /// Borrows all three exact fields under independently derived per-field bounds.
    ///
    /// Bounds are comparison DATA, never receiving admission. The actual owner
    /// must fund the complete raw transfer before buffering or this decoder.
    ///
    /// # Errors
    /// Rejects changed framing, empty or excessive fields, truncation or tails.
    pub fn decode(bytes: &'bytes [u8], maxima: [usize; 3]) -> Result<Self, HistoryErrorV1> {
        let [plan, signature, request_body] = framing::decode_fields(bytes, b"AOSXSB01", maxima)?;
        Ok(Self {
            plan,
            signature,
            request_body,
        })
    }

    /// Measures the complete canonical packet without introducing a global cap.
    ///
    /// # Errors
    /// Rejects empty fields, wire-width excess or total-size overflow.
    pub fn encoded_bytes(self) -> Result<usize, HistoryErrorV1> {
        framing::fields_bytes(self.fields())
    }

    /// Writes only the original three fields into an exact prepaid destination.
    ///
    /// # Errors
    /// Rejects invalid field lengths or a nonexact output extent before copying.
    pub fn encode_into(self, output: &mut [u8]) -> Result<(), HistoryErrorV1> {
        framing::encode_fields(b"AOSXSB01", self.fields(), output)
    }

    /// Commits the canonical prefix and all original bytes without a packet copy.
    ///
    /// # Errors
    /// Rejects invalid lengths before hashing. This grants no signature authority.
    pub fn commitment(self) -> Result<[u8; 32], HistoryErrorV1> {
        self.encoded_bytes()?;
        let mut digest = Sha256::new()
            .chain_update(b"aos.sandbox.create-storage.signed-bundle.v1\0")
            .chain_update(b"AOSXSB01");
        for field in self.fields() {
            digest.update((field.len() as u32).to_be_bytes());
        }
        for field in self.fields() {
            digest.update(field);
        }
        Ok(digest.finalize().into())
    }

    /// Compares all exact fields with Root's already-committed binding DATA.
    ///
    /// # Errors
    /// Rejects a differing bundle length, commitment, plan, signature or request.
    /// Request-ID and semantic verification remain with the actual Core decoder.
    pub fn require_bound(self, bound: SignedBoundBodyDataV1) -> Result<(), HistoryErrorV1> {
        bound.encode()?;
        if bound.bundle != self.commitment()?
            || bound.bundle_bytes
                != u64::try_from(self.encoded_bytes()?).map_err(|_| HistoryErrorV1::Extent)?
            || bound.request_body != <[u8; 32]>::from(Sha256::digest(self.request_body))
            || bound.plan != <[u8; 32]>::from(Sha256::digest(self.plan))
            || bound.signature != <[u8; 32]>::from(Sha256::digest(self.signature))
        {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(())
    }

    fn fields(self) -> [&'bytes [u8]; 3] {
        [self.plan, self.signature, self.request_body]
    }
}

/// Borrows Root's actual use receipt and both exact unsigned signing inputs.
///
/// The genuine Controller must authenticate the original Root flight, repeat
/// its independent semantic/key/cutoff checks and retain the actual U borrower.
/// Decoding this transfer never grants a private-key use or a Storage request.
#[derive(Clone, Copy)]
pub struct UseAdmissionTransferDataV1<'bytes> {
    /// The exact actual Root revision-three record/head/native return bytes.
    pub receipt: &'bytes [u8; USE_ADMITTED_RECEIPT_BYTES_V1],
    /// The canonical unsigned broker-plan bytes already prepared by Root.
    pub plan: &'bytes [u8],
    /// The canonical signing statement from that same actual preparation.
    pub statement: &'bytes [u8],
}

impl<'bytes> UseAdmissionTransferDataV1<'bytes> {
    /// Borrows the exact receipt and bounded actual signing inputs.
    ///
    /// # Errors
    /// Rejects changed framing, excessive or empty fields, receipt/plan/statement
    /// substitution, malformed native DATA, truncation or trailing bytes.
    pub fn decode(
        bytes: &'bytes [u8],
        lane: [u8; 16],
        plan_maximum: usize,
        statement_maximum: usize,
    ) -> Result<Self, HistoryErrorV1> {
        let [receipt, plan, statement] = framing::decode_fields(
            bytes,
            b"AOSXUMR1",
            [
                USE_ADMITTED_RECEIPT_BYTES_V1,
                plan_maximum,
                statement_maximum,
            ],
        )?;
        let value = Self {
            receipt: receipt.try_into().map_err(|_| HistoryErrorV1::Extent)?,
            plan,
            statement,
        };
        value.body(lane)?;
        Ok(value)
    }

    /// Checks the exact unsigned inputs against the original admitted-use row.
    ///
    /// # Errors
    /// Rejects a malformed receipt or changed canonical plan/statement bytes.
    pub fn body(self, lane: [u8; 16]) -> Result<UseAdmittedBodyDataV1, HistoryErrorV1> {
        let receipt = ContinuationNativeReceiptDataV1::decode(
            self.receipt,
            lane,
            ContinuationKindV1::UseAdmitted,
        )?;
        let record = receipt.record_data(lane, ContinuationKindV1::UseAdmitted)?;
        let body = UseAdmittedBodyDataV1::decode(record.body())?;
        if body.unsigned_plan != <[u8; 32]>::from(Sha256::digest(self.plan))
            || body.signing_statement != <[u8; 32]>::from(Sha256::digest(self.statement))
        {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(body)
    }

    /// Measures the complete transfer using actual canonical input widths.
    ///
    /// # Errors
    /// Rejects malformed receipt/data joins, empty fields or wire-size overflow.
    pub fn encoded_bytes(self, lane: [u8; 16]) -> Result<usize, HistoryErrorV1> {
        self.body(lane)?;
        framing::fields_bytes([self.receipt.as_slice(), self.plan, self.statement])
    }

    /// Copies the exact original fields into an already-paid destination.
    ///
    /// # Errors
    /// Rejects changed body/input joins or a nonexact output extent before copying.
    pub fn encode_into(self, lane: [u8; 16], output: &mut [u8]) -> Result<(), HistoryErrorV1> {
        self.body(lane)?;
        framing::encode_fields(
            b"AOSXUMR1",
            [self.receipt.as_slice(), self.plan, self.statement],
            output,
        )
    }
}

#[cfg(test)]
mod tests;
