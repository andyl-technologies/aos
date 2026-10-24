//! Encodes a fresh independently signed Cache observation for CurrentProofs.
//!
//! ```text
//! AOSXKC01 | lane16 | RootOpen-checksum32 | RootNonce16 | Ready32 |
//! CacheHeld-checksum32 | signer-generation8 | clock-provenance16 |
//! boot16 | wall-i64be | BOOTTIME-u64be | observed-Cache-body808 | signature64
//! ```
//!
//! The nested existing Cache representation describes a fresh observed snapshot:
//! its HOLD coordinates are the receipt's post-Held coordinates, rather than
//! the original body's pre-Held coordinates. All other frozen coordinates must
//! match exactly. These codecs and public-key checks supply comparison DATA;
//! forwarded Hello bytes, a signature and historical Held DATA cannot construct
//! a live original, paid operation, Root permission or held writer.

use aos_sandbox_model::{RawClockProvenance, RawPairedClockSample};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};

use super::{CacheHeldBodyDataV1, CacheHeldReceiptDataV1, CacheJournalDataV1, CACHE_HELD_BODY_BYTES_V1};
use super::super::{HistoryErrorV1, reader};
use super::super::root_open::RootHelloDataV1;

const MAGIC: &[u8; 8] = b"AOSXKC01";
const DOMAIN: &[u8] = b"aos.sandbox.create-storage.cache-current-proof.v1\0";

/// Identifies the fixed native Cache current-proof paired-clock reader as DATA.
pub const CACHE_CURRENT_PROOF_CLOCK_PROVENANCE_BYTES_V1: [u8; 16] = *b"AOSXKC01clock001";

/// Holds the exact fresh Cache comparison-body width.
pub const CACHE_CURRENT_PROOF_BODY_BYTES_V1: usize = 192 + CACHE_HELD_BODY_BYTES_V1;
/// Holds the exact fresh independently signed Cache packet width.
pub const CACHE_CURRENT_PROOF_PACKET_BYTES_V1: usize = CACHE_CURRENT_PROOF_BODY_BYTES_V1 + 64;
/// Holds the exact stack preimage width used by the same signing/public verifier.
pub const CACHE_CURRENT_PROOF_PREIMAGE_BYTES_V1: usize = DOMAIN.len() + CACHE_CURRENT_PROOF_BODY_BYTES_V1;

/// Commits the exact original challenge bytes independently of transport role.
///
/// The fixed Root-first and Controller request magics are excluded. Actual
/// callers retain their own authenticated Hello/held-original checks; a digest
/// of supplied bytes never authenticates Root or authorizes a signer operation.
#[must_use]
pub fn current_cache_challenge_digest_v1(
    hello: &[u8; super::super::root_open::ROOT_HELLO_FRAME_BYTES_V1],
    held: &[u8; super::CACHE_HELD_RECEIPT_BYTES_V1],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.create-storage.cache-current-challenge.v1\0");
    digest.update(hello);
    digest.update(held);
    digest.finalize().into()
}

/// Describes one fresh Cache observation without authenticating its acquisition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheCurrentProofBodyDataV1 {
    /// The same original Create lane, independent from its accepted operation.
    pub lane: [u8; 16],
    /// The exact RootOpen envelope checksum from the first authenticated Hello.
    pub root_open_checksum: [u8; 32],
    /// Root's independent immutable nonce for that same open exchange.
    pub root_nonce: [u8; 16],
    /// The same original complete Ready bundle commitment.
    pub ready: [u8; 32],
    /// The exact original CacheHeld record checksum carried by that Ready.
    pub cache_held_checksum: [u8; 32],
    /// The separately provisioned independent Cache signer key generation.
    pub signer_generation: u64,
    /// Fresh paired-clock DATA from the actual paid Cache observation.
    pub sample: RawPairedClockSample,
    /// The exact fresh observed snapshot using the established Cache subcodec.
    pub snapshot: CacheHeldBodyDataV1,
}

impl CacheCurrentProofBodyDataV1 {
    /// Decodes the fixed body without native observation or dynamic allocation.
    ///
    /// # Errors
    /// Refuses nonexact extent, foreign purpose, malformed fields or a sample
    /// outside the original Controller cutoff. Root cutoff checks are separate.
    pub fn decode(bytes: &[u8]) -> Result<Self, HistoryErrorV1> {
        let mut input = reader(bytes);
        if input.array::<8>()? != *MAGIC {
            return Err(HistoryErrorV1::Malformed);
        }
        let lane = input.array()?;
        let root_open_checksum = input.array()?;
        let root_nonce = input.array()?;
        let ready = input.array()?;
        let cache_held_checksum = input.array()?;
        let signer_generation = input.u64()?;
        let provenance = RawClockProvenance::new_untrusted(input.array()?)
            .map_err(|_| HistoryErrorV1::Malformed)?;
        let boot = input.array()?;
        let wall = i64::from_be_bytes(input.array()?);
        let boottime = input.u64()?;
        let sample = RawPairedClockSample::new_untrusted(provenance, boot, wall, boottime)
            .map_err(|_| HistoryErrorV1::Malformed)?;
        let snapshot = CacheHeldBodyDataV1::decode(input.bytes(CACHE_HELD_BODY_BYTES_V1)?)?;
        input.finish()?;
        let value = Self {
            lane, root_open_checksum, root_nonce, ready, cache_held_checksum,
            signer_generation, sample, snapshot,
        };
        value.validate()?;
        Ok(value)
    }

    /// Encodes this fixed comparison body without heap allocation.
    ///
    /// # Errors
    /// Refuses malformed nested fields, zero identities or a stale sample.
    pub fn encode(self) -> Result<[u8; CACHE_CURRENT_PROOF_BODY_BYTES_V1], HistoryErrorV1> {
        self.validate()?;
        let mut bytes = [0; CACHE_CURRENT_PROOF_BODY_BYTES_V1];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..24].copy_from_slice(&self.lane);
        bytes[24..56].copy_from_slice(&self.root_open_checksum);
        bytes[56..72].copy_from_slice(&self.root_nonce);
        bytes[72..104].copy_from_slice(&self.ready);
        bytes[104..136].copy_from_slice(&self.cache_held_checksum);
        bytes[136..144].copy_from_slice(&self.signer_generation.to_be_bytes());
        bytes[144..160].copy_from_slice(&self.sample.provenance().as_bytes());
        bytes[160..176].copy_from_slice(&self.sample.host_boot_id());
        bytes[176..184].copy_from_slice(&self.sample.wall_seconds().to_be_bytes());
        bytes[184..192].copy_from_slice(&self.sample.boottime_nanoseconds().to_be_bytes());
        bytes[192..].copy_from_slice(&self.snapshot.encode()?);
        Ok(bytes)
    }

    /// Compares the frozen Held snapshot with exact post-Held HOLD coordinates.
    ///
    /// # Errors
    /// Refuses a changed association, Source checksum, other writer, physical
    /// head, partition, quotas, counts, floor or exact post-Held receipt.
    pub fn compare_held_data(self, held: CacheHeldReceiptDataV1<'_>) -> Result<(), HistoryErrorV1> {
        let envelope = held.body(self.lane)?;
        let mut expected = envelope;
        expected.hold = CacheJournalDataV1 {
            names: held.hold_names, next: held.hold_after_next, end: held.hold_after_end,
        };
        let record = super::super::RecordEnvelopeV1::decode(
            held.record,
            super::super::KeyV1::new(self.lane, super::super::OwnerV1::Cache, 1)?,
            super::super::PhaseV1::new(super::super::OwnerV1::Cache, 1)?,
        )?;
        if self.snapshot != expected || self.cache_held_checksum != record.checksum() {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(())
    }

    /// Compares Root correlation and both original cutoffs as passive DATA.
    ///
    /// # Errors
    /// Refuses a different RootOpen, nonce, Ready, lane, seed, Controller nonce,
    /// boot or a sample outside Root's immutable original clock interval.
    pub fn compare_root_hello_data(self, hello: RootHelloDataV1<'_>) -> Result<(), HistoryErrorV1> {
        let root = hello.body;
        let association = self.snapshot.association;
        let sampled = self.sample.boottime_nanoseconds();
        if self.lane != root.open.lane || self.root_open_checksum != hello.checksum
            || self.root_nonce != root.root_nonce || self.ready != root.open.ready
            || association.seed != root.open.seed
            || association.controller_nonce != root.open.controller_nonce
            || self.sample.host_boot_id() != root.boot
            || sampled < root.started || sampled >= root.cutoff
        {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(())
    }

    fn validate(self) -> Result<(), HistoryErrorV1> {
        // Reuse the sole existing nested validator, including full physical
        // genesis/current rules, canonical names and accepted association.
        self.snapshot.validate()?;
        let wall = u64::try_from(self.sample.wall_seconds())
            .map_err(|_| HistoryErrorV1::Malformed)?;
        let association = self.snapshot.association;
        let sampled = self.sample.boottime_nanoseconds();
        if self.lane == [0; 16] || self.root_open_checksum == [0; 32]
            || self.root_nonce == [0; 16] || self.ready == [0; 32]
            || self.cache_held_checksum == [0; 32] || self.signer_generation == 0
            || self.sample.provenance().as_bytes() != CACHE_CURRENT_PROOF_CLOCK_PROVENANCE_BYTES_V1
            || self.sample.host_boot_id() != association.boot
            || sampled < association.started || sampled >= association.cutoff
            || wall < self.snapshot.clock_floor
        {
            return Err(HistoryErrorV1::Malformed);
        }
        Ok(())
    }
}

/// Preserves malformed DATA or an independent public-key verification failure.
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum CacheCurrentProofDataErrorV1 {
    /// The exact body or original comparisons are malformed.
    #[error(transparent)]
    History(#[from] HistoryErrorV1),
    /// The packet is not signed by the separately selected Cache key generation.
    #[error("Cache current proof signer or signature differs")]
    Signature,
}

/// Constructs the sole fixed purpose-separated signing preimage as DATA.
///
/// This function has no private key and supplies no signing or effect grant.
#[must_use]
pub fn current_cache_proof_preimage_v1(
    body: &[u8; CACHE_CURRENT_PROOF_BODY_BYTES_V1],
) -> [u8; CACHE_CURRENT_PROOF_PREIMAGE_BYTES_V1] {
    let mut bytes = [0; CACHE_CURRENT_PROOF_PREIMAGE_BYTES_V1];
    bytes[..DOMAIN.len()].copy_from_slice(DOMAIN);
    bytes[DOMAIN.len()..].copy_from_slice(body);
    bytes
}

/// Retains the actual fixed verifier's partial model and signing preimage.
///
/// The caller separately retains its received packet and genuine Root/native
/// posts. This inert owner supplies no key, receiving budget or acceptance.
#[must_use]
pub struct CacheCurrentProofVerifyCaptureV1 {
    body: Option<Result<CacheCurrentProofBodyDataV1, HistoryErrorV1>>,
    signature: Option<Signature>,
    preimage: Option<[u8; CACHE_CURRENT_PROOF_PREIMAGE_BYTES_V1]>,
    verification: Option<Result<(), ed25519_dalek::SignatureError>>,
    completion: Option<Result<(), CacheCurrentProofDataErrorV1>>,
    entered: bool,
    closed: bool,
    taken: bool,
}

impl CacheCurrentProofVerifyCaptureV1 {
    /// Creates fixed empty destinations without allocation or verification.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            body: None, signature: None, preimage: None, verification: None,
            completion: None, entered: false, closed: false, taken: false,
        }
    }

    /// Reports the actual additional constructor temporary layout as DATA.
    #[must_use]
    pub const fn construction_inline_bytes_v1() -> usize {
        std::mem::size_of::<Self>()
    }

    /// Prices named additional fixed decode/preimage temporaries as DATA.
    ///
    /// The parent separately pays its actual inline capture and received packet.
    /// This sum covers the capture constructor, decoded outer fields/value,
    /// nested Cache value, returned preimage and parsed signature temporaries.
    #[must_use]
    pub fn receiving_additional_inline_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(std::mem::size_of::<CacheCurrentProofBodyDataV1>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<CacheHeldBodyDataV1>())?
            .checked_add(CACHE_CURRENT_PROOF_PREIMAGE_BYTES_V1)?
            .checked_add(std::mem::size_of::<Signature>())
    }

    /// Prices the one fixed Dalek internal-error allocation, if reached.
    ///
    /// The verifier has no attacker-sized error text or dynamic preimage.
    #[must_use]
    pub const fn receiving_additional_heap_bytes_v1() -> Option<usize> { Some(256) }

    /// Reports no namespace growth for fixed verification destinations.
    ///
    /// The owner and optional Dalek error box use their separate byte bounds.
    #[must_use]
    pub const fn receiving_metadata_cells_v1() -> Option<usize> { Some(0) }

    /// Borrows the earliest actual decoder, crypto or completion failure.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.body.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.verification.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.completion.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.closed.then_some(&VERIFY_CLOSED as &(dyn std::error::Error + 'static)))
    }

    /// Borrows only a complete public-key-verified comparison body.
    #[must_use]
    pub fn body(&self) -> Option<&CacheCurrentProofBodyDataV1> {
        if self.closed || self.taken || !matches!(self.completion, Some(Ok(()))) {
            return None;
        }
        self.body.as_ref()?.as_ref().ok()
    }

    /// Moves the complete comparison body once without cloning any native owner.
    #[must_use]
    pub fn take_body_once(&mut self) -> Option<CacheCurrentProofBodyDataV1> {
        self.body()?;
        self.taken = true;
        self.body.take()?.ok()
    }
}

impl Default for CacheCurrentProofVerifyCaptureV1 {
    fn default() -> Self { Self::new() }
}

#[derive(Debug, thiserror::Error)]
#[error("Cache current proof verification is closed")]
struct VerifyClosed;
const VERIFY_CLOSED: VerifyClosed = VerifyClosed;

/// Verifies the new-purpose packet into the caller's retained fixed capture.
///
/// The actual Root retains its fixed credential, received packet, original Hello,
/// native held checks and both cutoff observations. This produces DATA only.
///
/// # Errors
/// Retains the actual partial model, preimage and cryptographic Result before
/// returning a classification. A refused second entry never overwrites them.
pub fn verify_current_cache_proof_retaining_v1(
    packet: &[u8],
    public_key: &VerifyingKey,
    generation: u64,
    capture: &mut CacheCurrentProofVerifyCaptureV1,
) -> Result<(), CacheCurrentProofDataErrorV1> {
    if capture.entered {
        capture.closed = true;
        return Err(CacheCurrentProofDataErrorV1::Signature);
    }
    capture.entered = true;
    capture.completion = Some((|| {
        if packet.len() != CACHE_CURRENT_PROOF_PACKET_BYTES_V1 {
            return Err(HistoryErrorV1::Extent.into());
        }
        let body_bytes: &[u8; CACHE_CURRENT_PROOF_BODY_BYTES_V1] = packet[..CACHE_CURRENT_PROOF_BODY_BYTES_V1]
            .try_into().map_err(|_| HistoryErrorV1::Extent)?;
        capture.body = Some(CacheCurrentProofBodyDataV1::decode(body_bytes));
        let body = match capture.body.as_ref() {
            Some(Ok(body)) => body,
            Some(Err(cause)) => return Err(CacheCurrentProofDataErrorV1::History(*cause)),
            None => return Err(CacheCurrentProofDataErrorV1::History(HistoryErrorV1::Malformed)),
        };
        if body.signer_generation != generation {
            return Err(CacheCurrentProofDataErrorV1::Signature);
        }
        let signature_bytes: &[u8; 64] = packet[CACHE_CURRENT_PROOF_BODY_BYTES_V1..].try_into()
            .map_err(|_| HistoryErrorV1::Extent)?;
        capture.signature = Some(Signature::from_bytes(signature_bytes));
        capture.preimage = Some(current_cache_proof_preimage_v1(body_bytes));
        let preimage = capture.preimage.as_ref().ok_or(CacheCurrentProofDataErrorV1::Signature)?;
        let signature = capture.signature.as_ref().ok_or(CacheCurrentProofDataErrorV1::Signature)?;
        capture.verification = Some(public_key.verify_strict(preimage, signature));
        match capture.verification {
            Some(Ok(())) => Ok(()),
            _ => Err(CacheCurrentProofDataErrorV1::Signature),
        }
    })());
    capture.completion.as_ref().copied()
        .ok_or(CacheCurrentProofDataErrorV1::Signature)?
}

/// Immediately verifies the same packet for an ordinary DATA-only caller.
///
/// # Errors
/// Refuses wrong extent, malformed body, a different generation or signature.
pub fn verify_current_cache_proof_v1(
    packet: &[u8],
    public_key: &VerifyingKey,
    generation: u64,
) -> Result<CacheCurrentProofBodyDataV1, CacheCurrentProofDataErrorV1> {
    let mut capture = CacheCurrentProofVerifyCaptureV1::new();
    verify_current_cache_proof_retaining_v1(packet, public_key, generation, &mut capture)?;
    capture.take_body_once().ok_or(CacheCurrentProofDataErrorV1::Signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    fn body() -> CacheCurrentProofBodyDataV1 {
        let snapshot = super::super::tests::body();
        CacheCurrentProofBodyDataV1 {
            lane: [22; 16], root_open_checksum: [23; 32], root_nonce: [24; 16],
            ready: [25; 32], cache_held_checksum: [26; 32], signer_generation: 27,
            sample: RawPairedClockSample::new_untrusted(
                RawClockProvenance::new_untrusted(CACHE_CURRENT_PROOF_CLOCK_PROVENANCE_BYTES_V1).unwrap(), snapshot.association.boot,
                19, snapshot.association.started,
            ).unwrap(),
            snapshot,
        }
    }

    #[test]
    fn frozen_comparison_requires_exact_receipt_hold_coordinates_and_every_other_writer() {
        let original = body().snapshot;
        let lane = body().lane;
        let (record, latest_head) = super::super::tests::record(original, lane);
        let receipt = CacheHeldReceiptDataV1 {
            record: &record, latest_head, hold_names: original.hold.names,
            hold_after_next: 5, hold_after_end: 1000,
        };
        let receipt_bytes = receipt.encode(lane).unwrap();
        let receipt = CacheHeldReceiptDataV1::decode(&receipt_bytes, lane).unwrap();
        let mut current = body();
        current.cache_held_checksum = latest_head[8..].try_into().unwrap();
        current.snapshot.hold.next = receipt.hold_after_next;
        current.snapshot.hold.end = receipt.hold_after_end;

        current.compare_held_data(receipt).unwrap();
        let mut old = current;
        old.snapshot.hold = original.hold;
        assert!(old.compare_held_data(receipt).is_err());
        let mut changed = current;
        changed.snapshot.authority.next += 1;
        assert!(changed.compare_held_data(receipt).is_err());
        let mut changed = current;
        changed.snapshot.hold.next += 1;
        assert!(changed.compare_held_data(receipt).is_err());
    }

    #[test]
    fn bad_independent_signature_keeps_the_actual_preimage_model_and_crypto_cause() {
        let expected = body();
        let body_bytes = expected.encode().unwrap();
        assert_eq!(body_bytes.len(), 1000);
        let key = SigningKey::from_bytes(&[30; 32]);
        let mut packet = [0; CACHE_CURRENT_PROOF_PACKET_BYTES_V1];
        packet[..CACHE_CURRENT_PROOF_BODY_BYTES_V1].copy_from_slice(&body_bytes);
        packet[CACHE_CURRENT_PROOF_BODY_BYTES_V1..].copy_from_slice(
            &key.sign(&current_cache_proof_preimage_v1(&body_bytes)).to_bytes(),
        );
        assert_eq!(verify_current_cache_proof_v1(&packet, &key.verifying_key(), 27).unwrap(), expected);
        packet[CACHE_CURRENT_PROOF_BODY_BYTES_V1] ^= 1;
        let mut capture = CacheCurrentProofVerifyCaptureV1::new();

        assert!(verify_current_cache_proof_retaining_v1(
            &packet, &key.verifying_key(), 27, &mut capture,
        ).is_err());
        assert_eq!(capture.body.as_ref().unwrap().as_ref().unwrap(), &expected);
        assert_eq!(capture.preimage.as_ref().unwrap(), &current_cache_proof_preimage_v1(&body_bytes));
        let actual_error = capture.failure().unwrap().downcast_ref::<ed25519_dalek::SignatureError>().unwrap() as *const _;
        let actual_preimage = capture.preimage.as_ref().unwrap().as_ptr();
        assert!(verify_current_cache_proof_retaining_v1(
            &packet, &key.verifying_key(), 27, &mut capture,
        ).is_err());
        assert_eq!(capture.preimage.as_ref().unwrap().as_ptr(), actual_preimage);
        assert_eq!(capture.failure().unwrap().downcast_ref::<ed25519_dalek::SignatureError>().unwrap() as *const _, actual_error);
        assert!(capture.take_body_once().is_none());
    }
}
