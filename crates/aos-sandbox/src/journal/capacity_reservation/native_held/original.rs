//! Root-only original funding with immutable unsigned Root1 and AdmissionCut.
//!
//! ```text
//! AOSJCR01 | version:u16be=5 | namespace:u8=40 | purpose:u8=8 | reserved[2]
//! native_body[204] | admission[16] | P_length:u32be | exact_unsigned_Root1
//! C_length:u32be | exact_AdmissionCut | identity[32]
//! ```
//!
//! The identity hashes the domain, u32be payload length and exact preceding
//! bytes. Retention provides replay provenance, not a physical-origin, current
//! signer, hot-custody or append grant. Only the named held writer may admit it.

use aos_sandbox_protocol::mount_source_acquisition_state::native_held_completion::{
    MAXIMUM_ROOT_NATIVE_CUT_BYTES_V1, MAXIMUM_ROOT_NATIVE_HELD_SIDECAR_BYTES_V2,
    RootNativeCutKindV1, RootNativeCutV1, RootNativeHeldGraphV2, original_root_remaining_v5,
    has_original_pending_closed_cut_v5, validate_original_root_preparation_v5,
};
use aos_sandbox_source_provider_protocol::native_held_completion::{
    NativeHeldControlKindV1, frame::PreparedNativeHeldControlV1,
};
use sha2::{Digest as _, Sha256};

use super::super::super::{JournalError, JournalLimits, JournalRecord, RecordNamespace};
use super::super::{reservation_key, take};
use super::{
    NativeHeldCapacityPurposeV3, NativeHeldCapacityRequestV3, binding_bytes, decode_bindings,
    invalid,
};

/// Fixes the exact original unsigned Root1 width, including its original signer.
pub const ORIGINAL_ROOT_PREPARED_BYTES_V5: usize = 1_066;

/// Bounds the variable retained floor including both length words and identity.
pub const ORIGINAL_ROOT_CAPACITY_MAXIMUM_VALUE_BYTES_V5: usize =
    274 + ORIGINAL_ROOT_PREPARED_BYTES_V5 + MAXIMUM_ROOT_NATIVE_CUT_BYTES_V1;

const DOMAIN: &[u8] = b"aos.sandbox.journal.root-original-native-capacity.v5\0";
const LEGACY_VALUE_BYTES: u64 = 4 * 1024 * 1024;

/// Retains canonical original native funding without constructing IO authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginalRootCapacityRecordV5 {
    request: NativeHeldCapacityRequestV3,
    admission: [u8; 16],
    prepared: PreparedNativeHeldControlV1,
    cut: RootNativeCutV1,
    identity: [u8; 32],
}

impl OriginalRootCapacityRecordV5 {
    /// Constructs bounded original-family DATA with exact retained provenance.
    ///
    /// # Errors
    ///
    /// Rejects non-Root bindings, malformed original Root1/cut, changed admission,
    /// checkpoint, scope or fixed width. Owner graphs remain separately required.
    pub fn new(
        request: NativeHeldCapacityRequestV3,
        admission: [u8; 16],
        prepared: PreparedNativeHeldControlV1,
        cut: RootNativeCutV1,
    ) -> Result<Self, JournalError> {
        request.validate()?;
        if request.purpose != NativeHeldCapacityPurposeV3::Root
            || admission == [0; 16]
            || cut.kind() != RootNativeCutKindV1::Admission
            || cut.capture_transaction() != admission
            || prepared.kind() != NativeHeldControlKindV1::RootPrepared
            || prepared.to_canonical_bytes().len() != ORIGINAL_ROOT_PREPARED_BYTES_V5
            || prepared.scope().mount_attempt.as_bytes() != &request.owner_id
            || prepared.scope().original_root_request.as_bytes() != &request.artifact_digest
            || prepared.digest().as_bytes() != &request.checkpoint_digest
            || cut.original_attempt(request.owner_id).record_digest != request.owner_digest
            || cut.head().record_digest != request.chain_head_digest
            || cut.acquisition().acquire.operation_id != request.operation_id
        {
            return Err(invalid("original Root native retained bindings"));
        }
        let mut value = Self {
            request,
            admission,
            prepared,
            cut,
            identity: [0; 32],
        };
        value.identity = identity(&value.payload()?)?;
        Ok(value)
    }

    /// Derives original bindings and a fresh complete native envelope.
    ///
    /// Every floor transfer retains the same P/C/admission; no current graph can
    /// remint those originals. The named writer must additionally compare the
    /// actual owner edge, all retained debt and its opened limits before escape.
    ///
    /// # Errors
    ///
    /// Rejects missing original rows, cut/witness/archive mismatches, a terminal
    /// prefix, or any unchanged opened per-append limit that cannot fund a branch.
    pub fn for_graph(
        graph: &RootNativeHeldGraphV2,
        prepared: PreparedNativeHeldControlV1,
        cut: RootNativeCutV1,
        limits: JournalLimits,
    ) -> Result<Self, JournalError> {
        let attempt = *prepared.scope().mount_attempt.as_bytes();
        validate_original_root_preparation_v5(graph, attempt, &prepared, &cut)
            .map_err(|_| invalid("original Root preparation/current graph join"))?;
        let count = original_root_remaining_v5(graph, attempt)
            .map_err(|_| invalid("original Root native remaining prefix"))?;
        let sidecar = graph
            .sidecars()
            .get(&attempt)
            .ok_or(invalid("original Root sidecar absent"))?;
        let phase = sidecar.suffix().phase();
        // Consumed Pending permanently spent the one heavy legacy branch.
        // A later Head advance cannot reserve that same branch a second time.
        let pending_closed = has_original_pending_closed_cut_v5(graph, sidecar)
            .map_err(|_| invalid("original Root Pending Closed cut"))?;
        let extra_owners = !pending_closed
            && (matches!(phase, 0..=2)
                || (matches!(phase, 10 | 11)
                    && sidecar.response_transaction() == [0; 16]
                    && sidecar
                        .suffix()
                        .control(NativeHeldControlKindV1::ProviderHeld)
                        .is_none()));
        let (frames, bytes) = envelope(
            count,
            extra_owners,
            prepared.to_canonical_bytes().len(),
            cut.to_canonical_bytes()
                .map_err(|_| invalid("original Root cut encoding"))?
                .len(),
            limits,
        )?;
        let original = graph
            .legacy()
            .provider_attempts
            .get(&attempt)
            .ok_or(invalid("original Root Attempt absent"))?;
        let request = NativeHeldCapacityRequestV3 {
            purpose: NativeHeldCapacityPurposeV3::Root,
            owner_id: attempt,
            owner_digest: cut.original_attempt(attempt).record_digest,
            operation_id: cut.acquisition().acquire.operation_id,
            artifact_digest: original.signed_request_digest,
            checkpoint_digest: *prepared.digest().as_bytes(),
            chain_head_digest: cut.head().record_digest,
            future_transactions: count,
            terminal_records: frames,
            terminal_bytes: bytes,
            poison_records: frames,
            poison_bytes: bytes,
        };
        Self::new(request, cut.capture_transaction(), prepared, cut)
    }

    /// Checks retained original provenance and fresh whole-branch geometry.
    ///
    /// # Errors
    ///
    /// Rejects any change to the current whole graph, original joins or envelope.
    pub fn validate_graph(
        &self,
        graph: &RootNativeHeldGraphV2,
        limits: JournalLimits,
    ) -> Result<(), JournalError> {
        let derived = Self::for_graph(graph, self.prepared.clone(), self.cut.clone(), limits)?;
        if derived != *self {
            return Err(invalid(
                "original Root floor does not describe complete current prefix",
            ));
        }
        Ok(())
    }

    /// Rejoins unchanged original funding across an independently funded stutter.
    ///
    /// Opened-limit checks remain the held writer's obligation. This pure join
    /// checks exact retained provenance/count; it grants no ordinary edge.
    ///
    /// # Errors
    /// Rejects changed originals, native phase/count or archive/witness joins.
    pub fn validate_preserved_graph(
        &self,
        graph: &RootNativeHeldGraphV2,
    ) -> Result<(), JournalError> {
        validate_original_root_preparation_v5(
            graph,
            self.request.owner_id,
            &self.prepared,
            &self.cut,
        )
        .map_err(|_| invalid("original Root preserved preparation/cut join"))?;
        if original_root_remaining_v5(graph, self.request.owner_id)
            .map_err(|_| invalid("original Root preserved prefix"))?
            != self.request.future_transactions
        {
            return Err(invalid("ordinary edge changed native count"));
        }
        Ok(())
    }

    /// Returns native-only remaining accounting DATA.
    #[must_use]
    pub const fn request(&self) -> NativeHeldCapacityRequestV3 {
        self.request
    }

    /// Returns the immutable actual original admission transaction.
    #[must_use]
    pub const fn admission_transaction_id(&self) -> [u8; 16] {
        self.admission
    }

    /// Returns the domain-separated exact floor identity.
    #[must_use]
    pub const fn reservation_id(&self) -> [u8; 32] {
        self.identity
    }

    /// Returns retained unsigned Root1, never a private signer or hot permit.
    #[must_use]
    pub const fn original_prepared(&self) -> &PreparedNativeHeldControlV1 {
        &self.prepared
    }

    /// Returns the exact immutable original companion cut.
    #[must_use]
    pub const fn admission_cut(&self) -> &RootNativeCutV1 {
        &self.cut
    }

    /// Encodes exact bounded DATA for the named writer's independent comparison.
    ///
    /// # Errors
    ///
    /// Rejects an impossible retained canonical encoding or width overflow.
    pub fn to_journal_record(&self) -> Result<JournalRecord, JournalError> {
        let mut value = self.payload()?;
        value.extend_from_slice(&self.identity);
        Ok(JournalRecord::put(
            RecordNamespace::GlobalCapacityReservation,
            reservation_key(self.identity),
            value,
        ))
    }

    /// Decodes a self-bound original floor without claiming physical origin.
    ///
    /// # Errors
    ///
    /// Rejects foreign namespace/deletion, malformed lengths, noncanonical nested
    /// data, unknown family, swapped originals or a substituted key/identity.
    pub fn from_journal_record(record: &JournalRecord) -> Result<Self, JournalError> {
        if record.namespace() != RecordNamespace::GlobalCapacityReservation {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        Self::decode(
            record.key(),
            record.value().ok_or(JournalError::InvalidTransaction)?,
        )
    }

    pub(in crate::journal) fn decode(key: &[u8], bytes: &[u8]) -> Result<Self, JournalError> {
        if !(274 + ORIGINAL_ROOT_PREPARED_BYTES_V5..=ORIGINAL_ROOT_CAPACITY_MAXIMUM_VALUE_BYTES_V5)
            .contains(&bytes.len())
            || &bytes[..8] != b"AOSJCR01"
            || bytes[8..14] != [0, 5, 40, 8, 0, 0]
        {
            return Err(invalid("original Root capacity envelope"));
        }
        let mut offset = 14;
        let request = decode_bindings(NativeHeldCapacityPurposeV3::Root, bytes, &mut offset);
        let admission = take::<16>(bytes, &mut offset);
        let p_len = u32::from_be_bytes(take::<4>(bytes, &mut offset)) as usize;
        if p_len != ORIGINAL_ROOT_PREPARED_BYTES_V5 {
            return Err(invalid("original Root prepared width"));
        }
        let prepared = PreparedNativeHeldControlV1::from_canonical_bytes(
            bytes
                .get(offset..offset + p_len)
                .ok_or(invalid("original Root prepared length"))?,
        )
        .map_err(|_| invalid("original Root prepared encoding"))?;
        offset += p_len;
        // The bounded cut header is required before reading its length word.
        if bytes.len().saturating_sub(offset) < 36 {
            return Err(invalid("original Root cut length word"));
        }
        let c_len = u32::from_be_bytes(take::<4>(bytes, &mut offset)) as usize;
        if c_len > MAXIMUM_ROOT_NATIVE_CUT_BYTES_V1
            || bytes.len().checked_sub(offset + 32) != Some(c_len)
        {
            return Err(invalid("original Root cut width"));
        }
        let cut = RootNativeCutV1::from_canonical_bytes(&bytes[offset..offset + c_len])
            .map_err(|_| invalid("original Root cut encoding"))?;
        offset += c_len;
        let candidate = take::<32>(bytes, &mut offset);
        let decoded = Self::new(request, admission, prepared, cut)?;
        if candidate != decoded.identity
            || key != reservation_key(candidate).as_slice()
            || decoded.to_journal_record()?.value() != Some(bytes)
        {
            return Err(invalid("original Root capacity key or canonical identity"));
        }
        Ok(decoded)
    }

    fn payload(&self) -> Result<Vec<u8>, JournalError> {
        let p = self.prepared.to_canonical_bytes();
        let c = self
            .cut
            .to_canonical_bytes()
            .map_err(|_| invalid("original Root cut encoding"))?;
        let mut bytes = b"AOSJCR01".to_vec();
        bytes.extend_from_slice(&[0, 5, 40, 8, 0, 0]);
        bytes.extend_from_slice(&binding_bytes(&self.request));
        bytes.extend_from_slice(&self.admission);
        bytes.extend_from_slice(&(p.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&p);
        bytes.extend_from_slice(&(c.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&c);
        if bytes.len() + 32 > ORIGINAL_ROOT_CAPACITY_MAXIMUM_VALUE_BYTES_V5 {
            return Err(invalid("original Root retained floor bound"));
        }
        Ok(bytes)
    }
}

fn identity(payload: &[u8]) -> Result<[u8; 32], JournalError> {
    let length = u32::try_from(payload.len()).map_err(|_| JournalError::JournalTooLarge)?;
    let mut digest = Sha256::new();
    digest.update(DOMAIN);
    digest.update(length.to_be_bytes());
    digest.update(payload);
    Ok(digest.finalize().into())
}

fn envelope(
    count: u32,
    extra_owners: bool,
    p: usize,
    c: usize,
    limits: JournalLimits,
) -> Result<(u32, u64), JournalError> {
    if !(1..=7).contains(&count) {
        return Err(invalid("original Root native count"));
    }
    let floor = 274 + p + c;
    let delta = floor
        .checked_sub(266)
        .ok_or(invalid("original Root floor geometry"))? as u64;
    let n = u64::from(count);
    // One CAS OR final no-interest branch. They cannot coexist. Every remaining
    // R is bounded independently; this is a conservative cap, not an attainable
    // maximum. Positive retained byte growth is bounded by this append cap.
    let branch = u64::from(extra_owners);
    let frames = 3 * count - 1 + 3 * u32::from(extra_owners);
    let bytes = 905 * n - 420
        + 442 * branch
        + n * MAXIMUM_ROOT_NATIVE_HELD_SIDECAR_BYTES_V2 as u64
        + branch * 3 * LEGACY_VALUE_BYTES
        + (n - 1) * delta;
    let maximum_payload = if extra_owners {
        12_743_285_u64 + delta
    } else {
        159_881 + floor as u64
    };
    let maximum_value = if extra_owners {
        LEGACY_VALUE_BYTES as usize
    } else {
        MAXIMUM_ROOT_NATIVE_HELD_SIDECAR_BYTES_V2
    };
    if limits.maximum_key_bytes < 75
        || limits.maximum_record_bytes < 7 + 75 + maximum_value
        || limits.maximum_records_per_transaction < if extra_owners { 6 } else { 3 }
        || (limits.maximum_transaction_bytes as u64) < maximum_payload
    {
        return Err(JournalError::LimitExceeded(
            "original Root native branch geometry",
        ));
    }
    Ok((frames, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maximal_original_floor_and_cas_branch_transfer_are_fully_framed() {
        let limits = JournalLimits::default();
        let p = ORIGINAL_ROOT_PREPARED_BYTES_V5;
        let c = MAXIMUM_ROOT_NATIVE_CUT_BYTES_V1;

        let (initial_frames, initial_bytes) = envelope(7, true, p, c, limits).unwrap();
        let (before_frames, before_bytes) = envelope(5, true, p, c, limits).unwrap();
        let (after_frames, after_bytes) = envelope(4, false, p, c, limits).unwrap();

        assert_eq!((initial_frames, initial_bytes), (23, 13_861_575));
        assert_eq!((before_frames, before_bytes), (17, 13_488_877));
        assert_eq!((after_frames, after_bytes), (11, 719_174));
        assert_eq!(6 + after_frames, before_frames);
        assert_eq!(12_769_703 + after_bytes, before_bytes);
    }

    #[test]
    fn a_small_opened_transaction_limit_cannot_fund_cas() {
        let limits = JournalLimits {
            maximum_transaction_bytes: 12_769_086,
            ..JournalLimits::default()
        };
        assert!(
            envelope(
                5,
                true,
                ORIGINAL_ROOT_PREPARED_BYTES_V5,
                MAXIMUM_ROOT_NATIVE_CUT_BYTES_V1,
                limits
            )
            .is_err()
        );
    }

    #[test]
    fn maximal_closed_store_encodes_three_records_and_transfers_the_full_native_two_debt() {
        use crate::journal::{JournalTransaction, encoded_transaction_append_bytes};
        use aos_sandbox_protocol::mount_source_acquisition_state::native_held_completion::
            native_root_sidecar_key_v2;

        let limits = JournalLimits::default();
        let p = ORIGINAL_ROOT_PREPARED_BYTES_V5;
        let c = MAXIMUM_ROOT_NATIVE_CUT_BYTES_V1;
        let (old_records, old_bytes) = envelope(3, false, p, c, limits).unwrap();
        let (next_records, next_bytes) = envelope(2, false, p, c, limits).unwrap();
        // Width DATA measures actual framing; the canonical owner/floor vector
        // separately exercises derive_continuation and check_transfer.
        let transaction = JournalTransaction::new(
            [1; 16],
            vec![
                JournalRecord::put(
                    RecordNamespace::MountSourceAcquisition,
                    native_root_sidecar_key_v2([1; 32]).unwrap(),
                    vec![0; MAXIMUM_ROOT_NATIVE_HELD_SIDECAR_BYTES_V2],
                ),
                JournalRecord::delete(
                    RecordNamespace::GlobalCapacityReservation,
                    reservation_key([2; 32]),
                ),
                JournalRecord::put(
                    RecordNamespace::GlobalCapacityReservation,
                    reservation_key([3; 32]),
                    vec![0; ORIGINAL_ROOT_CAPACITY_MAXIMUM_VALUE_BYTES_V5],
                ),
            ],
        )
        .unwrap();

        let appended = encoded_transaction_append_bytes(&transaction).unwrap();

        assert_eq!(transaction.records().len(), 3);
        assert_eq!(transaction.records()[0].key().len(), 68);
        assert_eq!(transaction.records()[1].key().len(), 75);
        assert_eq!((old_records, next_records), (8, 5));
        assert_eq!(3 + next_records, old_records);
        assert_eq!(transaction.records().len() + 2, 5);
        assert!(appended + next_bytes <= old_bytes);
    }

    #[test]
    fn maximal_pending_transaction_encodes_real_six_record_frames_without_double_reserve() {
        use crate::journal::{JournalTransaction, encoded_transaction_append_bytes};
        use aos_sandbox_protocol::mount_source_acquisition_state::{
            acquisition_key, provider_attempt_key, provider_head_key,
            native_held_completion::native_root_sidecar_key_v2,
        };

        let limits = JournalLimits::default();
        let p = ORIGINAL_ROOT_PREPARED_BYTES_V5;
        let c = MAXIMUM_ROOT_NATIVE_CUT_BYTES_V1;
        let (old_frames, old_bytes) = envelope(6, true, p, c, limits).unwrap();
        let (next_frames, next_bytes) = envelope(3, false, p, c, limits).unwrap();
        let namespace = RecordNamespace::MountSourceAcquisition;
        // Width fixtures intentionally carry no owner or floor authority. The
        // actual journal encoder, including DEL and begin/end frames, measures
        // the maximal six-record geometry independently of scalar arithmetic.
        let transaction = JournalTransaction::new(
            [1; 16],
            vec![
                JournalRecord::put(
                    namespace,
                    provider_attempt_key([1; 32]),
                    vec![0; LEGACY_VALUE_BYTES as usize],
                ),
                JournalRecord::put(
                    namespace,
                    acquisition_key([2; 32]),
                    vec![0; LEGACY_VALUE_BYTES as usize],
                ),
                JournalRecord::put(
                    namespace,
                    provider_head_key([3; 16], [4; 16]),
                    vec![0; LEGACY_VALUE_BYTES as usize],
                ),
                JournalRecord::put(
                    namespace,
                    native_root_sidecar_key_v2([1; 32]).unwrap(),
                    vec![0; MAXIMUM_ROOT_NATIVE_HELD_SIDECAR_BYTES_V2],
                ),
                JournalRecord::delete(
                    RecordNamespace::GlobalCapacityReservation,
                    reservation_key([5; 32]),
                ),
                JournalRecord::put(
                    RecordNamespace::GlobalCapacityReservation,
                    reservation_key([6; 32]),
                    vec![0; ORIGINAL_ROOT_CAPACITY_MAXIMUM_VALUE_BYTES_V5],
                ),
            ],
        )
        .unwrap();

        let append_bytes = encoded_transaction_append_bytes(&transaction).unwrap();

        assert_eq!(transaction.records().len(), 6);
        assert_eq!((old_frames, next_frames), (20, 8));
        assert!(6 + next_frames <= old_frames);
        // The envelopes count records. Each physical transaction also carries
        // Begin/Commit, so compare full frame budgets separately.
        let append_frames = transaction.records().len() as u32 + 2;
        assert_eq!(append_frames, 8);
        assert!(append_frames + next_frames + 2 * 3 <= old_frames + 2 * 6);
        assert!(append_bytes + next_bytes <= old_bytes);
        let (_, double_reserved) = envelope(3, true, p, c, limits).unwrap();
        assert!(append_bytes + double_reserved > old_bytes);
    }
}
