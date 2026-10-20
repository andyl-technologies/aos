//! Binds positive Prepare outcomes and original held-owner releases as DATA.
//!
//! ```text
//! outcome-bundle = AOSXOB01 | request-length:u32be | outcome-length:u32be |
//!                  exact-signed-request | exact-signed-outcome
//! Controller9/phase8 body[376] = AOSXCO01 | original Root/U/artifact joins |
//!                                actual Session terminal snapshot/position
//! Root5 body[104] = AOSXRO01 | Controller9[32] | prepared-receipt[32] | bundle[32]
//! Source2/Cache2 body[104] = AOSXSR01/AOSXKR01 | Root5[32] | Held[32] | Controller9[32]
//! Controller10/phase9 body[248] = AOSXHR01 | Root5[32] | Source2[32] | Cache2[32] |
//!   committed-U[32] | U-binding[32] | actual-bank-commit[16] | names[48] | NEXT[8] | end[8]
//! Root6 body[136] = AOSXCL01 | Controller10[32] | Source2[32] | Cache2[32] | committed-U[32]
//! release-proofs = AOSXRL01 | lengths[3 * u32be] | Controller10-receipt[492] |
//!                  Source2-receipt[348] | Cache2-receipt[348]
//! ```
//!
//! These schemas describe the positive prepared route. Ambiguity, failed native
//! posts and unproved disposal retain the original reservation; none of these
//! decoders establishes a terminal, current Session, U commit or released hold.
//! The actual independent owner must read and verify every named native return.

use sha2::{Digest as _, Sha256};

use super::super::protected_names::ProtectedJournalNamesV1;
use super::continuation::framing::{
    decode_commitments, decode_fields, encode_commitments, encode_fields, encode_fields_range, fields_bytes,
};
use super::continuation::{ContinuationKindV1, ContinuationNativeReceiptDataV1};
use super::{HistoryErrorV1, OwnerV1, RECORD_OVERHEAD_BYTES, nonzero, reader};

/// Specifies the original Controller outcome body extent.
pub const CONTROLLER_OUTCOME_BODY_BYTES_V1: usize = 376;
/// Specifies the Controller revision-nine record extent.
pub const CONTROLLER_OUTCOME_RECORD_BYTES_V1: usize =
    RECORD_OVERHEAD_BYTES + CONTROLLER_OUTCOME_BODY_BYTES_V1;
/// Specifies the Controller revision-nine native receipt extent.
pub const CONTROLLER_OUTCOME_RECEIPT_BYTES_V1: usize = CONTROLLER_OUTCOME_RECORD_BYTES_V1 + 104;
/// Specifies the Root revision-five outcome body extent.
pub const ROOT_OUTCOME_BODY_BYTES_V1: usize = 104;
/// Specifies the Root revision-five record extent.
pub const ROOT_OUTCOME_RECORD_BYTES_V1: usize = RECORD_OVERHEAD_BYTES + ROOT_OUTCOME_BODY_BYTES_V1;
/// Specifies the Root revision-five native receipt extent.
pub const ROOT_OUTCOME_RECEIPT_BYTES_V1: usize = ROOT_OUTCOME_RECORD_BYTES_V1 + 104;
/// Specifies each original held-owner release body extent.
pub const RELEASED_BODY_BYTES_V1: usize = 104;
/// Specifies each held-owner revision-two record extent.
pub const RELEASED_RECORD_BYTES_V1: usize = RECORD_OVERHEAD_BYTES + RELEASED_BODY_BYTES_V1;
/// Specifies each held-owner revision-two native receipt extent.
pub const RELEASED_RECEIPT_BYTES_V1: usize = RELEASED_RECORD_BYTES_V1 + 104;
/// Specifies the Controller handoff-retained body extent.
pub const HANDOFF_RETAINED_BODY_BYTES_V1: usize = 248;
/// Specifies the Controller revision-ten record extent.
pub const HANDOFF_RETAINED_RECORD_BYTES_V1: usize =
    RECORD_OVERHEAD_BYTES + HANDOFF_RETAINED_BODY_BYTES_V1;
/// Specifies the Controller revision-ten native receipt extent.
pub const HANDOFF_RETAINED_RECEIPT_BYTES_V1: usize = HANDOFF_RETAINED_RECORD_BYTES_V1 + 104;
/// Specifies the Root revision-six close body extent.
pub const ROOT_CLOSED_BODY_BYTES_V1: usize = 136;
/// Specifies the Root revision-six record extent.
pub const ROOT_CLOSED_RECORD_BYTES_V1: usize = RECORD_OVERHEAD_BYTES + ROOT_CLOSED_BODY_BYTES_V1;
/// Specifies the Root revision-six native receipt extent.
pub const ROOT_CLOSED_RECEIPT_BYTES_V1: usize = ROOT_CLOSED_RECORD_BYTES_V1 + 104;
/// Specifies the exact complete release-proof transfer extent.
pub const RELEASE_PROOFS_BYTES_V1: usize =
    20 + HANDOFF_RETAINED_RECEIPT_BYTES_V1 + 2 * RELEASED_RECEIPT_BYTES_V1;

/// Records the original positive outcome and actual Session terminal readback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerOutcomeBodyDataV1 {
    /// The actual Root revision-four signing binding checksum.
    pub signed_bound: [u8; 32],
    /// The actual Root revision-three use admission checksum.
    pub use_admitted: [u8; 32],
    /// The original purpose-fifteen reserved claim identity.
    pub use_claim: [u8; 16],
    /// The SHA-256 of the complete original signed Session request packet.
    pub request_packet: [u8; 32],
    /// The SHA-256 of the complete original signed Session outcome packet.
    pub outcome_packet: [u8; 32],
    /// The existing authenticated Session signed-request digest.
    pub signed_request: [u8; 32],
    /// The existing positive Storage prepared-receipt digest.
    pub prepared_receipt: [u8; 32],
    /// The actual retained Session journal's physical-name coordinates.
    pub session_names: ProtectedJournalNamesV1,
    /// The actual Session journal next sequence after terminal readback.
    pub session_after_next: u64,
    /// The actual Session durable byte end after terminal readback.
    pub session_after_end: u64,
    /// The actual stored terminal replacement-head digest.
    pub session_head: [u8; 32],
    /// The actual stored terminal generation, not the advancement's expected input.
    pub session_generation: u64,
    /// The actual stored terminal revision, not an inferred increment.
    pub session_revision: u64,
    /// The actual stored terminal state commitment.
    pub session_commitment: [u8; 32],
    /// The original authenticated Prepare request identity.
    pub request_id: [u8; 16],
}

impl ControllerOutcomeBodyDataV1 {
    /// Decodes the complete positive outcome comparison fields.
    ///
    /// # Errors
    /// Rejects changed framing, zero identities, absent native positions or tails.
    pub fn decode(bytes: &[u8]) -> Result<Self, HistoryErrorV1> {
        let mut input = reader(bytes);
        if input.array::<8>()? != *b"AOSXCO01" {
            return Err(HistoryErrorV1::Malformed);
        }
        let value = Self {
            signed_bound: input.array()?,
            use_admitted: input.array()?,
            use_claim: input.array()?,
            request_packet: input.array()?,
            outcome_packet: input.array()?,
            signed_request: input.array()?,
            prepared_receipt: input.array()?,
            session_names: ProtectedJournalNamesV1::from_bytes(input.bytes(48)?)
                .map_err(|_| HistoryErrorV1::Malformed)?,
            session_after_next: input.u64()?,
            session_after_end: input.u64()?,
            session_head: input.array()?,
            session_generation: input.u64()?,
            session_revision: input.u64()?,
            session_commitment: input.array()?,
            request_id: input.array()?,
        };
        input.finish()?;
        value.encode()?;
        Ok(value)
    }

    /// Encodes the original outcome fields into fixed caller-owned storage.
    ///
    /// # Errors
    /// Rejects absent artifact joins, physical names or terminal positions.
    pub fn encode(self) -> Result<[u8; CONTROLLER_OUTCOME_BODY_BYTES_V1], HistoryErrorV1> {
        let mut bytes = [0; CONTROLLER_OUTCOME_BODY_BYTES_V1];
        bytes[..8].copy_from_slice(b"AOSXCO01");
        nonzero(&self.use_claim)?;
        nonzero(&self.request_id)?;
        bytes[8..40].copy_from_slice(&self.signed_bound);
        bytes[40..72].copy_from_slice(&self.use_admitted);
        bytes[72..88].copy_from_slice(&self.use_claim);
        for (index, field) in [
            self.request_packet,
            self.outcome_packet,
            self.signed_request,
            self.prepared_receipt,
        ]
        .iter()
        .enumerate()
        {
            bytes[88 + index * 32..120 + index * 32].copy_from_slice(field);
        }
        for field in [
            &self.signed_bound,
            &self.use_admitted,
            &self.request_packet,
            &self.outcome_packet,
            &self.signed_request,
            &self.prepared_receipt,
            &self.session_head,
            &self.session_commitment,
        ] {
            nonzero(field)?;
        }
        require_position(
            self.session_names,
            self.session_after_next,
            self.session_after_end,
        )?;
        if self.session_generation == 0 || self.session_revision == 0 {
            return Err(HistoryErrorV1::Extent);
        }
        bytes[216..264].copy_from_slice(&self.session_names.to_bytes());
        bytes[264..272].copy_from_slice(&self.session_after_next.to_be_bytes());
        bytes[272..280].copy_from_slice(&self.session_after_end.to_be_bytes());
        bytes[280..312].copy_from_slice(&self.session_head);
        bytes[312..320].copy_from_slice(&self.session_generation.to_be_bytes());
        bytes[320..328].copy_from_slice(&self.session_revision.to_be_bytes());
        bytes[328..360].copy_from_slice(&self.session_commitment);
        bytes[360..].copy_from_slice(&self.request_id);
        Ok(bytes)
    }
}

/// Borrows both original signed Session packets for independent verification.
#[derive(Clone, Copy)]
pub struct OutcomeBundleDataV1<'bytes> {
    /// The original complete signed Prepare request packet.
    pub request: &'bytes [u8],
    /// The original complete signed positive outcome packet.
    pub outcome: &'bytes [u8],
}

impl<'bytes> OutcomeBundleDataV1<'bytes> {
    /// Borrows the exact packets under the existing request and raw outcome bounds.
    ///
    /// # Errors
    /// Rejects changed framing, empty or excessive fields, truncation or tails.
    pub fn decode(bytes: &'bytes [u8], maxima: [usize; 2]) -> Result<Self, HistoryErrorV1> {
        let [request, outcome] = decode_fields(bytes, b"AOSXOB01", maxima)?;
        Ok(Self { request, outcome })
    }

    /// Measures both exact packets and their fixed sixteen-byte framing.
    ///
    /// # Errors
    /// Rejects empty packets, wire-width excess or total-size overflow.
    pub fn encoded_bytes(self) -> Result<usize, HistoryErrorV1> {
        fields_bytes([self.request, self.outcome])
    }

    /// Encodes both original packets into an exact prepaid destination.
    ///
    /// # Errors
    /// Rejects invalid lengths or a nonexact output extent before copying.
    pub fn encode_into(self, output: &mut [u8]) -> Result<(), HistoryErrorV1> {
        encode_fields(b"AOSXOB01", [self.request, self.outcome], output)
    }

    /// Copies an exact range of the canonical encoding into bounded storage.
    ///
    /// This delegates the same framing engine as [`Self::encode_into`]. It can
    /// cross the prefix, request and outcome boundaries without allocating or
    /// cloning either original packet.
    ///
    /// # Errors
    /// Rejects invalid packet widths, overflow or a range past the encoded end
    /// before changing the output.
    pub fn encode_range_into_v1(self, offset: usize, output: &mut [u8]) -> Result<(), HistoryErrorV1> {
        encode_fields_range(b"AOSXOB01", [self.request, self.outcome], offset, output)
    }

    /// Hashes the complete canonical encoding for its existing transfer index.
    ///
    /// This raw transfer digest is distinct from the named outcome commitment.
    /// Only the fixed framing prefix is materialized; both packets stay borrowed.
    ///
    /// # Errors
    /// Rejects empty packets, excessive wire widths or total-size overflow.
    pub fn transfer_digest_v1(self) -> Result<[u8; 32], HistoryErrorV1> {
        let mut prefix = [0; 16];
        self.encode_range_into_v1(0, &mut prefix)?;
        Ok(Sha256::new().chain_update(prefix).chain_update(self.request)
            .chain_update(self.outcome).finalize().into())
    }

    /// Commits both original packets without making a second packet allocation.
    ///
    /// # Errors
    /// Rejects invalid packet lengths before hashing.
    pub fn commitment(self) -> Result<[u8; 32], HistoryErrorV1> {
        self.encoded_bytes()?;
        Ok(Sha256::new()
            .chain_update(b"aos.sandbox.create-storage.outcome-bundle.v1\0")
            .chain_update(b"AOSXOB01")
            .chain_update((self.request.len() as u32).to_be_bytes())
            .chain_update((self.outcome.len() as u32).to_be_bytes())
            .chain_update(self.request)
            .chain_update(self.outcome)
            .finalize()
            .into())
    }

    /// Compares both exact packets with the Controller's already-recorded DATA.
    ///
    /// # Errors
    /// Rejects malformed body DATA or a substituted request or outcome packet.
    /// Actual authentication, semantic receipt and Session replay remain required.
    pub fn require_recorded(self, body: ControllerOutcomeBodyDataV1) -> Result<(), HistoryErrorV1> {
        self.encoded_bytes()?;
        body.encode()?;
        if body.request_packet != <[u8; 32]>::from(Sha256::digest(self.request))
            || body.outcome_packet != <[u8; 32]>::from(Sha256::digest(self.outcome))
        {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(())
    }
}

/// Records Root's actual independent verification of the complete outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootOutcomeBodyDataV1 {
    /// The actual Controller revision-nine outcome record checksum.
    pub controller_outcome: [u8; 32],
    /// The independently verified positive Storage prepared-receipt digest.
    pub prepared_receipt: [u8; 32],
    /// The named commitment of both complete signed Session packets.
    pub outcome_bundle: [u8; 32],
}

impl RootOutcomeBodyDataV1 {
    /// Decodes all exact Root outcome joins without proving verification occurred.
    ///
    /// # Errors
    /// Rejects changed magic, extent or absent comparison identities.
    pub fn decode(bytes: &[u8]) -> Result<Self, HistoryErrorV1> {
        let [controller_outcome, prepared_receipt, outcome_bundle] =
            decode_commitments(bytes, b"AOSXRO01")?;
        Ok(Self {
            controller_outcome,
            prepared_receipt,
            outcome_bundle,
        })
    }

    /// Encodes the fixed independently verified outcome joins.
    ///
    /// # Errors
    /// Rejects an absent record, receipt or bundle commitment.
    pub fn encode(self) -> Result<[u8; ROOT_OUTCOME_BODY_BYTES_V1], HistoryErrorV1> {
        encode_commitments(
            b"AOSXRO01",
            [
                self.controller_outcome,
                self.prepared_receipt,
                self.outcome_bundle,
            ],
        )
    }
}

/// Records release by the same original Source or Cache Held owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleasedBodyDataV1 {
    /// The actual independently committed Root revision-five outcome checksum.
    pub root_outcome: [u8; 32],
    /// The exact original same-owner Held record checksum.
    pub held: [u8; 32],
    /// The actual Controller revision-nine outcome checksum.
    pub controller_outcome: [u8; 32],
}

impl ReleasedBodyDataV1 {
    /// Decodes one exact owner-specific release without releasing native custody.
    ///
    /// # Errors
    /// Rejects another owner or magic, malformed extent or absent joins.
    pub fn decode(bytes: &[u8], owner: OwnerV1) -> Result<Self, HistoryErrorV1> {
        let [root_outcome, held, controller_outcome] =
            decode_commitments(bytes, release_magic(owner)?)?;
        Ok(Self {
            root_outcome,
            held,
            controller_outcome,
        })
    }

    /// Encodes the original held-owner release with a distinct owner discriminator.
    ///
    /// # Errors
    /// Rejects another owner or an absent original held or outcome checksum.
    pub fn encode(self, owner: OwnerV1) -> Result<[u8; RELEASED_BODY_BYTES_V1], HistoryErrorV1> {
        encode_commitments(
            release_magic(owner)?,
            [self.root_outcome, self.held, self.controller_outcome],
        )
    }
}

/// Records actual positive U commit and both original held-owner releases.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandoffRetainedBodyDataV1 {
    /// The actual Root revision-five outcome checksum.
    pub root_outcome: [u8; 32],
    /// The actual Source revision-two Released record checksum.
    pub source_released: [u8; 32],
    /// The actual Cache revision-two Released record checksum.
    pub cache_released: [u8; 32],
    /// The SHA-256 of the exact actual committed U claim bytes.
    pub committed_use_claim: [u8; 32],
    /// The SHA-256 of the immutable actual U binding bytes.
    pub use_binding: [u8; 32],
    /// The deterministic original U binding's actual positive commit transaction.
    pub bank_commit: [u8; 16],
    /// The actual retained bank writer's physical-name coordinates.
    pub bank_names: ProtectedJournalNamesV1,
    /// The actual native next sequence after positive U commit readback.
    pub bank_after_next: u64,
    /// The actual native durable end after positive U commit readback.
    pub bank_after_end: u64,
}

impl HandoffRetainedBodyDataV1 {
    /// Decodes the exact terminal joins without equating them to live disposal.
    ///
    /// # Errors
    /// Rejects changed magic, absent joins or native positions, truncation or tails.
    pub fn decode(bytes: &[u8]) -> Result<Self, HistoryErrorV1> {
        let mut input = reader(bytes);
        if input.array::<8>()? != *b"AOSXHR01" {
            return Err(HistoryErrorV1::Malformed);
        }
        let value = Self {
            root_outcome: input.array()?,
            source_released: input.array()?,
            cache_released: input.array()?,
            committed_use_claim: input.array()?,
            use_binding: input.array()?,
            bank_commit: input.array()?,
            bank_names: ProtectedJournalNamesV1::from_bytes(input.bytes(48)?)
                .map_err(|_| HistoryErrorV1::Malformed)?,
            bank_after_next: input.u64()?,
            bank_after_end: input.u64()?,
        };
        input.finish()?;
        value.encode()?;
        Ok(value)
    }

    /// Encodes the actual positive settlement joins into fixed storage.
    ///
    /// # Errors
    /// Rejects absent joins, a missing commit identity or invalid native positions.
    pub fn encode(self) -> Result<[u8; HANDOFF_RETAINED_BODY_BYTES_V1], HistoryErrorV1> {
        let mut bytes = [0; HANDOFF_RETAINED_BODY_BYTES_V1];
        bytes[..8].copy_from_slice(b"AOSXHR01");
        for (index, field) in [
            self.root_outcome,
            self.source_released,
            self.cache_released,
            self.committed_use_claim,
            self.use_binding,
        ]
        .iter()
        .enumerate()
        {
            nonzero(field)?;
            bytes[8 + index * 32..40 + index * 32].copy_from_slice(field);
        }
        nonzero(&self.bank_commit)?;
        require_position(self.bank_names, self.bank_after_next, self.bank_after_end)?;
        bytes[168..184].copy_from_slice(&self.bank_commit);
        bytes[184..232].copy_from_slice(&self.bank_names.to_bytes());
        bytes[232..240].copy_from_slice(&self.bank_after_next.to_be_bytes());
        bytes[240..].copy_from_slice(&self.bank_after_end.to_be_bytes());
        Ok(bytes)
    }
}

/// Records Root's actual final independent readback of the settled continuation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootClosedBodyDataV1 {
    /// The actual Controller revision-ten HandoffRetained record checksum.
    pub handoff_retained: [u8; 32],
    /// The actual Source Released record checksum.
    pub source_released: [u8; 32],
    /// The actual Cache Released record checksum.
    pub cache_released: [u8; 32],
    /// The SHA-256 of the independently read actual committed U claim.
    pub committed_use_claim: [u8; 32],
}

impl RootClosedBodyDataV1 {
    /// Decodes the exact final joins without renewing any original permission.
    ///
    /// # Errors
    /// Rejects changed magic or extent or an absent final comparison identity.
    pub fn decode(bytes: &[u8]) -> Result<Self, HistoryErrorV1> {
        let [
            handoff_retained,
            source_released,
            cache_released,
            committed_use_claim,
        ] = decode_commitments(bytes, b"AOSXCL01")?;
        Ok(Self {
            handoff_retained,
            source_released,
            cache_released,
            committed_use_claim,
        })
    }

    /// Encodes the already-verified final original-owner joins.
    ///
    /// # Errors
    /// Rejects an absent terminal, release or committed claim identity.
    pub fn encode(self) -> Result<[u8; ROOT_CLOSED_BODY_BYTES_V1], HistoryErrorV1> {
        encode_commitments(
            b"AOSXCL01",
            [
                self.handoff_retained,
                self.source_released,
                self.cache_released,
                self.committed_use_claim,
            ],
        )
    }
}

/// Borrows all three actual native terminal receipts without duplicating them.
#[derive(Clone, Copy)]
pub struct ReleaseProofsDataV1<'bytes> {
    /// The actual Controller revision-ten HandoffRetained native receipt.
    pub controller: &'bytes [u8; HANDOFF_RETAINED_RECEIPT_BYTES_V1],
    /// The actual Source revision-two Released native receipt.
    pub source: &'bytes [u8; RELEASED_RECEIPT_BYTES_V1],
    /// The actual Cache revision-two Released native receipt.
    pub cache: &'bytes [u8; RELEASED_RECEIPT_BYTES_V1],
}

impl<'bytes> ReleaseProofsDataV1<'bytes> {
    /// Borrows the exact fixed receipts and checks each closed owner schema.
    ///
    /// # Errors
    /// Rejects changed framing, widths, owner schemas, native positions or tails.
    pub fn decode(bytes: &'bytes [u8], lane: [u8; 16]) -> Result<Self, HistoryErrorV1> {
        let [controller, source, cache] = decode_fields(
            bytes,
            b"AOSXRL01",
            [
                HANDOFF_RETAINED_RECEIPT_BYTES_V1,
                RELEASED_RECEIPT_BYTES_V1,
                RELEASED_RECEIPT_BYTES_V1,
            ],
        )?;
        let value = Self {
            controller: controller.try_into().map_err(|_| HistoryErrorV1::Extent)?,
            source: source.try_into().map_err(|_| HistoryErrorV1::Extent)?,
            cache: cache.try_into().map_err(|_| HistoryErrorV1::Extent)?,
        };
        value.records(lane)?;
        Ok(value)
    }

    /// Encodes only the original fixed receipts into the exact prepaid extent.
    ///
    /// # Errors
    /// Rejects invalid receipts or a nonexact destination before copying.
    pub fn encode_into(self, lane: [u8; 16], output: &mut [u8]) -> Result<(), HistoryErrorV1> {
        self.records(lane)?;
        encode_fields(
            b"AOSXRL01",
            [
                self.controller.as_slice(),
                self.source.as_slice(),
                self.cache.as_slice(),
            ],
            output,
        )
    }

    /// Checks the exact original Held, outcome and terminal comparison joins.
    ///
    /// The caller supplies retained same-lane originals and must independently
    /// reread the actual Controller, Source, Cache and committed bank suffixes.
    /// These equality checks alone prove neither currentness nor disposal.
    ///
    /// # Errors
    /// Rejects a changed original Held/outcome, terminal predecessor or release.
    pub fn require_links(
        self,
        lane: [u8; 16],
        root_outcome: [u8; 32],
        controller_outcome: [u8; 32],
        source_held: [u8; 32],
        cache_held: [u8; 32],
    ) -> Result<HandoffRetainedBodyDataV1, HistoryErrorV1> {
        for field in [
            &root_outcome,
            &controller_outcome,
            &source_held,
            &cache_held,
        ] {
            nonzero(field)?;
        }
        let [controller, source, cache] = self.records(lane)?;
        let terminal = HandoffRetainedBodyDataV1::decode(controller.body())?;
        let source_body = ReleasedBodyDataV1::decode(source.body(), OwnerV1::Source)?;
        let cache_body = ReleasedBodyDataV1::decode(cache.body(), OwnerV1::Cache)?;
        if controller.coordinates().predecessor != controller_outcome
            || source.coordinates().predecessor != source_held
            || cache.coordinates().predecessor != cache_held
            || terminal.root_outcome != root_outcome
            || terminal.source_released != source.checksum()
            || terminal.cache_released != cache.checksum()
            || source_body
                != (ReleasedBodyDataV1 {
                    root_outcome,
                    held: source_held,
                    controller_outcome,
                })
            || cache_body
                != (ReleasedBodyDataV1 {
                    root_outcome,
                    held: cache_held,
                    controller_outcome,
                })
        {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(terminal)
    }

    fn records(
        self,
        lane: [u8; 16],
    ) -> Result<[super::RecordEnvelopeV1<'bytes>; 3], HistoryErrorV1> {
        let mut records = [None; 3];
        for ((record, bytes), kind) in records
            .iter_mut()
            .zip([
                self.controller.as_slice(),
                self.source.as_slice(),
                self.cache.as_slice(),
            ])
            .zip([
                ContinuationKindV1::HandoffRetained,
                ContinuationKindV1::SourceReleased,
                ContinuationKindV1::CacheReleased,
            ])
        {
            *record = Some(
                ContinuationNativeReceiptDataV1::decode(bytes, lane, kind)?
                    .record_data(lane, kind)?,
            );
        }
        // Fixed destructuring keeps every original borrow without a growable collection.
        let [Some(controller), Some(source), Some(cache)] = records else {
            return Err(HistoryErrorV1::Malformed);
        };
        Ok([controller, source, cache])
    }
}

fn release_magic(owner: OwnerV1) -> Result<&'static [u8; 8], HistoryErrorV1> {
    match owner {
        OwnerV1::Source => Ok(b"AOSXSR01"),
        OwnerV1::Cache => Ok(b"AOSXKR01"),
        _ => Err(HistoryErrorV1::Malformed),
    }
}

fn require_position(
    names: ProtectedJournalNamesV1,
    next: u64,
    end: u64,
) -> Result<(), HistoryErrorV1> {
    ProtectedJournalNamesV1::from_bytes(&names.to_bytes())
        .map_err(|_| HistoryErrorV1::Malformed)?;
    if next == 0 || end == 0 {
        return Err(HistoryErrorV1::Extent);
    }
    Ok(())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod range_encoding_tests {
    use super::*;

    #[test]
    fn every_range_matches_the_complete_canonical_outcome_encoding() {
        let bundle = OutcomeBundleDataV1 { request: b"request", outcome: b"outcome" };
        let mut complete = vec![0; bundle.encoded_bytes().unwrap()];
        bundle.encode_into(&mut complete).unwrap();
        let decoded = OutcomeBundleDataV1::decode(&complete, [7, 7]).unwrap();
        assert_eq!(decoded.request, b"request");
        assert_eq!(decoded.outcome, b"outcome");
        assert_eq!(&complete[..16], b"AOSXOB01\0\0\0\x07\0\0\0\x07");

        for start in 0..=complete.len() {
            for end in start..=complete.len() {
                let mut range = vec![0; end - start];
                bundle.encode_range_into_v1(start, &mut range).unwrap();
                assert_eq!(range, complete[start..end]);
            }
        }
        assert_eq!(bundle.transfer_digest_v1().unwrap(), <[u8; 32]>::from(Sha256::digest(&complete)));
        assert_ne!(bundle.transfer_digest_v1().unwrap(), bundle.commitment().unwrap());
    }

    #[test]
    fn invalid_outcome_ranges_leave_the_actual_destination_unchanged() {
        let bundle = OutcomeBundleDataV1 { request: b"request", outcome: b"outcome" };
        let mut destination = [0x5a; 2];

        assert!(bundle.encode_range_into_v1(bundle.encoded_bytes().unwrap() - 1, &mut destination).is_err());
        assert_eq!(destination, [0x5a; 2]);
        assert!(bundle.encode_range_into_v1(usize::MAX, &mut destination).is_err());
        assert_eq!(destination, [0x5a; 2]);
    }
}
