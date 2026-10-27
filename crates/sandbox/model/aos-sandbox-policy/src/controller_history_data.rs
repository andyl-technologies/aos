//! Derives and compares saved Controller history geometry without native authority.
//!
//! The original Ready bundle and receipts describe exact frame keys, phases,
//! predecessors, correlations and native coordinates. This module owns their
//! pure comparison recipe once. Real readonly owners retain every healthy,
//! protected, physical, native replay, purpose, financial and postcheck gate.

use std::collections::BTreeMap;
use std::fs::Metadata;
use std::mem::size_of;

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as MechanicalError;
use aos_sandbox_model::ResourceVector;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1, KeyV1, OwnerV1, PhaseV1,
    ready::{InputsReadyNativeReceiptDataV1, ReadyBundleDataV1},
};
use aos_sandbox_protocol::domain_ledger::transaction::{JournalRecord, JournalTransaction};
use aos_sandbox_model::RecordNamespace;

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;
type ReplayOriginalV1<'data> = (
    aos_sandbox_protocol::domain_ledger::create_storage_history::controller_intent::ControllerIntentBodyDataV1<'data>,
    aos_sandbox_protocol::domain_ledger::create_storage_history::ready::ControllerAdmissionDataV1<'data>,
);
type LaneArgumentsV1<'data, const N: usize> = (
    &'data State,
    [u8; 16],
    [(Result<KeyV1, HistoryErrorV1>, &'data [u8]); N],
);

/// Describes Controller history coordinates and widths from immutable bundle DATA.
///
/// These values supply no currentness, native custody, receiving admission or
/// append authority. Construction allocates no encoded record or model.
pub struct ControllerHistoryGeometryV1 {
    /// Records the before and three successive native `(next sequence, byte end)` coordinates.
    pub positions: [(u64, u64); 4],
    /// Retains the exact Intent and AssignmentPlanned head encodings.
    pub heads: [[u8; 40]; 2],
    /// Bounds the original two-pair copy backing in bytes.
    pub copy_bytes: u64,
    /// Records the original Intent body width for accepted-Create replay.
    pub accepted_bytes: u64,
    /// Records the summed compiler-origin, policy-source and specification widths.
    pub compiler_bytes: u64,
}

impl ControllerHistoryGeometryV1 {
    /// Derives the original Intent, Planned and InputsReady comparison geometry.
    ///
    /// # Errors
    /// Rejects malformed frames, mismatched lane/names/predecessors/correlations,
    /// inconsistent receipt coordinates or checked-width arithmetic failure.
    pub fn from_bundle(
        bundle: ReadyBundleDataV1<'_>,
        receipt: InputsReadyNativeReceiptDataV1<'_>,
    ) -> Result<Self, MechanicalError> {
        use aos_sandbox_protocol::domain_ledger::create_storage_history::{
            LatestHeadV1, RecordEnvelopeV1, KEY_BYTES,
            controller_intent::ControllerIntentBodyDataV1,
            ready::IntentNativeReceiptDataV1,
        };
        let invalid = || MechanicalError::ProtectedBoundary;
        let key = |revision| KeyV1::new(bundle.lane, OwnerV1::Controller, revision)
            .map_err(|_| invalid());
        let phase = |value| PhaseV1::new(OwnerV1::Controller, value).map_err(|_| invalid());
        let intent = RecordEnvelopeV1::decode(bundle.intent_record, key(1)?, phase(1)?)
            .map_err(|_| invalid())?;
        let planned = RecordEnvelopeV1::decode(bundle.assignment_planned, key(2)?, phase(12)?)
            .map_err(|_| invalid())?;
        let inputs = RecordEnvelopeV1::decode(receipt.record, key(3)?, phase(2)?)
            .map_err(|_| invalid())?;
        let original = ControllerIntentBodyDataV1::decode(intent.body())
            .map_err(|_| invalid())?.identity;
        let accepted_bytes = u64::try_from(intent.body().len()).map_err(|_| invalid())?;
        let compiler_bytes = [bundle.compiler_origin, bundle.policy_sources, bundle.specification]
            .into_iter().try_fold(0_u64, |total, bytes| {
                total.checked_add(u64::try_from(bytes.len()).map_err(|_| invalid())?)
                    .ok_or_else(invalid)
            })?;
        let native = IntentNativeReceiptDataV1::decode(bundle.intent_native_receipt)
            .map_err(|_| invalid())?;
        if original.lane != bundle.lane || original.j_names != receipt.names
            || native.names != receipt.names || intent.coordinates().predecessor != [0; 32]
            || planned.coordinates().predecessor != intent.checksum()
            || inputs.coordinates().predecessor != planned.checksum()
            || planned.coordinates().correlation != intent.coordinates().correlation
            || inputs.coordinates().correlation != intent.coordinates().correlation
        {
            return Err(invalid());
        }
        let append = |bytes| {
            aos_sandbox_journal::geometry::encoded_transaction_append_bytes([
                aos_sandbox_journal::geometry::RecordShape { key_bytes: KEY_BYTES, value_bytes: Some(bytes) },
                aos_sandbox_journal::geometry::RecordShape { key_bytes: KEY_BYTES, value_bytes: Some(40) },
            ].into_iter()).map_err(|_| invalid())
        };
        let start = (original.j_commit.checked_add(1).ok_or_else(invalid)?, original.j_end);
        let after_intent = (start.0.checked_add(4).ok_or_else(invalid)?,
            start.1.checked_add(append(bundle.intent_record.len())?).ok_or_else(invalid)?);
        let after_planned = (after_intent.0.checked_add(4).ok_or_else(invalid)?,
            after_intent.1.checked_add(append(bundle.assignment_planned.len())?).ok_or_else(invalid)?);
        let after_inputs = (after_planned.0.checked_add(4).ok_or_else(invalid)?,
            after_planned.1.checked_add(append(receipt.record.len())?).ok_or_else(invalid)?);
        if start.0 == 0 || native.after_next != after_intent.0 || native.after_end != after_intent.1
            || receipt.after_next != after_inputs.0 || receipt.after_end != after_inputs.1
        {
            return Err(invalid());
        }
        let heads = [native.latest_head,
            LatestHeadV1::new(2, planned.checksum()).map_err(|_| invalid())?.encode()];
        let copy_bytes = bundle.intent_record.len().checked_add(bundle.assignment_planned.len())
            .and_then(|bytes| bytes.checked_add(2 * (40 + 2 * KEY_BYTES
                + 2 * size_of::<JournalRecord>())))
            .and_then(|bytes| bytes.checked_mul(2)).ok_or_else(invalid)?;
        Ok(Self { positions: [start, after_intent, after_planned, after_inputs], heads,
            copy_bytes: u64::try_from(copy_bytes).map_err(|_| invalid())?, accepted_bytes, compiler_bytes })
    }
}

#[allow(dead_code)]
struct ReadonlyFixedFramesV1<Extent, E> {
    bundles: [ReadyBundleDataV1<'static>; 2],
    receipts: [InputsReadyNativeReceiptDataV1<'static>; 4],
    hellos: [aos_sandbox_protocol::domain_ledger::create_storage_history::root_open::RootHelloDataV1<'static>; 2],
    proofs: [aos_sandbox_protocol::domain_ledger::create_storage_history::current_proofs::CurrentProofsDataV1<'static>; 2],
    frames: [aos_sandbox_protocol::domain_ledger::create_storage_history::transport::FrameEnvelopeV1<'static>; 2],
    keys: [KeyV1; 24],
    records: [aos_sandbox_protocol::domain_ledger::create_storage_history::RecordEnvelopeV1<'static>; 12],
    readers: [aos_sandbox_model::bounded_codec::BoundedReader<'static, HistoryErrorV1>; 16],
    hashers: [sha2::Sha256; 8],
    extents: [Extent; 2],
    transactions: [JournalTransaction; 6],
    record_constructors: [JournalRecord; 12],
    history_geometry: [ControllerHistoryGeometryV1; 2],
    demands: [ResourceVector; 8],
    results: [Result<ResourceVector, E>; 8],
    positions: [(u64, u64); 4],
    metadata: [Result<Metadata, std::io::Error>; 2],
}


/// Decodes the original Controller Intent and admission from the same bundle.
///
/// Framing and decode order match the original replay entry. Decoded DATA does
/// not create accepted-Create, publication, Controller or Root authority.
///
/// # Errors
/// Rejects the original Intent key/phase/envelope/body or admission encoding.
pub fn decode_replay_original_v1<'data>(bundle: ReadyBundleDataV1<'data>)
    -> Result<(aos_sandbox_protocol::domain_ledger::create_storage_history::controller_intent::ControllerIntentBodyDataV1<'data>,
        aos_sandbox_protocol::domain_ledger::create_storage_history::ready::ControllerAdmissionDataV1<'data>), MechanicalError>
{
    let intent = aos_sandbox_protocol::domain_ledger::create_storage_history::RecordEnvelopeV1::decode(
        bundle.intent_record, KeyV1::new(bundle.lane, OwnerV1::Controller, 1).map_err(|_| MechanicalError::ProtectedBoundary)?,
        PhaseV1::new(OwnerV1::Controller, 1).map_err(|_| MechanicalError::ProtectedBoundary)?)
        .map_err(|_| MechanicalError::ProtectedBoundary)?;
    let original = aos_sandbox_protocol::domain_ledger::create_storage_history::controller_intent::ControllerIntentBodyDataV1::decode(intent.body())
        .map_err(|_| MechanicalError::ProtectedBoundary)?;
    let admission = aos_sandbox_protocol::domain_ledger::create_storage_history::ready::ControllerAdmissionDataV1::decode(
        bundle.controller_admission).map_err(|_| MechanicalError::ProtectedBoundary)?;
    Ok((original, admission))
}

/// Compares every exact member of the initial Controller lane history.
///
/// # Errors
/// Rejects malformed history keys, substituted/missing members or an extra row
/// in the selected lane. Other namespaces and decoded lanes remain ignored.
pub fn require_bundle_history_data_v1(
    state: &State,
    lane: [u8; 16],
    intent: &[u8],
    planned: &[u8],
    receipt: aos_sandbox_protocol::domain_ledger::create_storage_history::ready::InputsReadyNativeReceiptDataV1<'_>,
) -> Result<(), MechanicalError> {
    use aos_sandbox_protocol::domain_ledger::create_storage_history::{KeyV1, OwnerV1};
    let expected = [
        (KeyV1::new(lane, OwnerV1::Controller, 1), intent),
        (KeyV1::new(lane, OwnerV1::Controller, 2), planned),
        (KeyV1::new(lane, OwnerV1::Controller, 3), receipt.record.as_slice()),
        (KeyV1::new(lane, OwnerV1::Controller, 0), receipt.latest_head.as_slice()),
    ];
    require_lane_history_data_v1(state, lane, expected)
}

/// Compares a selected lane against an exact ordered DATA roster.
///
/// Expected key-construction failures remain in the roster; they are not
/// promoted to an earlier failure before the original state scan.
///
/// # Errors
/// Rejects an invalid encountered history key, unmatched selected-lane row or
/// a final observed count different from the expected roster length.
pub fn require_lane_history_data_v1<const N: usize>(state: &State, lane: [u8; 16],
    expected: [(Result<aos_sandbox_protocol::domain_ledger::create_storage_history::KeyV1,
        aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1>, &[u8]); N],
) -> Result<(), MechanicalError> {
    use aos_sandbox_protocol::domain_ledger::create_storage_history::KeyV1;
    let mut reached = 0;
    for ((namespace, key), bytes) in state {
        if *namespace != RecordNamespace::CreateStorageHistory {
            continue;
        }
        let observed = KeyV1::decode(key).map_err(|_| MechanicalError::ProtectedBoundary)?;
        if observed.lane() != lane {
            continue;
        }
        if !expected.iter().any(|(key, value)| {
            key.as_ref().is_ok_and(|key| key.encode() == observed.encode())
                && bytes.as_slice() == *value
        }) {
            return Err(MechanicalError::ProtectedBoundary);
        }
        reached += 1;
    }
    if reached != expected.len() {
        return Err(MechanicalError::ProtectedBoundary);
    }
    Ok(())
}

/// Compares the original Outcome or Closed continuation rows as passive DATA.
///
/// # Errors
/// Rejects malformed lane keys, wrong owners/revisions, changed head or later
/// transaction rows, missing required transaction records or a count mismatch.
pub fn require_continuation_history_data_v1<const N: usize>(
    state: &State,
    lane: [u8; 16],
    receipt: aos_sandbox_protocol::domain_ledger::create_storage_history::continuation::ContinuationNativeReceiptDataV1<'_>,
    later: [&JournalTransaction; N],
) -> Result<(), MechanicalError> {
    use aos_sandbox_protocol::domain_ledger::create_storage_history::{KeyV1, OwnerV1};
    let mut reached = 0;
    for ((namespace, key), value) in state {
        if *namespace != RecordNamespace::CreateStorageHistory { continue; }
        let key = KeyV1::decode(key).map_err(|_| MechanicalError::ProtectedBoundary)?;
        if key.lane() != lane { continue; }
        if key.owner() != OwnerV1::Controller || key.revision() > (5 + N as u64) {
            return Err(MechanicalError::ProtectedBoundary);
        }
        if key.revision() == 0 {
            if value.as_slice() != receipt.latest_head { return Err(MechanicalError::ProtectedBoundary); }
        } else if key.revision() >= 6 {
            let row = later[usize::try_from(key.revision() - 6).map_err(|_| MechanicalError::ProtectedBoundary)?]
                .records().first().ok_or(MechanicalError::ProtectedBoundary)?;
            if row.key() != key.encode().as_slice() || row.value() != Some(value.as_slice()) {
                return Err(MechanicalError::ProtectedBoundary);
            }
        }
        reached += 1;
    }
    if reached != 6 + N { return Err(MechanicalError::ProtectedBoundary); }
    Ok(())
}

/// Bounds the original seventeen-field roster using the caller's actual types.
///
/// `Extent` and `E` must be the concrete extent and error types of the actual
/// caller. This passive quote grants no receiving allowance or native role.
#[must_use]
pub fn readonly_fixed_frame_bytes_v1<Extent, E>() -> Option<usize> {
    size_of::<ReadonlyFixedFramesV1<Extent, E>>().checked_mul(2)
}

/// Bounds the canonical geometry/decode calls and concrete error projections.
///
/// The caller supplies its actual geometry and replay-decode error types. The
/// original resident seventeen-field roster is supplied separately once.
#[must_use]
pub fn geometry_and_decode_control_bytes_v1<GeometryError, DecodeError>() -> Option<usize> {
    size_of::<(ReadyBundleDataV1<'static>, InputsReadyNativeReceiptDataV1<'static>)>()
        .checked_mul(3)?
        .checked_add(size_of::<Result<ControllerHistoryGeometryV1, MechanicalError>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<ControllerHistoryGeometryV1, GeometryError>>().checked_mul(3)?)?
        .checked_add(size_of::<ReadyBundleDataV1<'static>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<ReplayOriginalV1<'static>, MechanicalError>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<ReplayOriginalV1<'static>, DecodeError>>().checked_mul(3)?)?
        .checked_add(size_of::<MechanicalError>().checked_mul(6)?)?
        .checked_add(size_of::<GeometryError>().checked_mul(3)?)?
        .checked_add(size_of::<DecodeError>().checked_mul(3)?)?
        .checked_add(size_of::<Option<usize>>().checked_mul(6)?)
}

/// Bounds both initial bundle and four-row lane comparison interfaces.
///
/// `E` is the actual caller's flat projected error. The bundle's internal lane
/// call has no second native-error projection.
#[must_use]
pub fn bundle_comparison_control_bytes_v1<E>() -> Option<usize> {
    type BundleArguments = (&'static State, [u8; 16], &'static [u8], &'static [u8],
        InputsReadyNativeReceiptDataV1<'static>);
    size_of::<BundleArguments>().checked_mul(3)?
        .checked_add(size_of::<LaneArgumentsV1<'static, 4>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), MechanicalError>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<(), E>>().checked_mul(3)?)?
        .checked_add(size_of::<MechanicalError>().checked_mul(3)?)?
        .checked_add(size_of::<E>().checked_mul(3)?)?
        .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
}

/// Bounds the actual `N`-row comparison and its flat projected error interface.
#[must_use]
pub fn lane_comparison_control_bytes_v1<const N: usize, E>() -> Option<usize> {
    size_of::<LaneArgumentsV1<'static, N>>().checked_mul(3)?
        .checked_add(size_of::<Result<(), MechanicalError>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), E>>().checked_mul(3)?)?
        .checked_add(size_of::<MechanicalError>().checked_mul(3)?)?
        .checked_add(size_of::<E>().checked_mul(3)?)?
        .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
}

/// Bounds the actual continuation transaction roster and flat error interface.
#[must_use]
pub fn continuation_comparison_control_bytes_v1<const N: usize, E>() -> Option<usize> {
    type Receipt = aos_sandbox_protocol::domain_ledger::create_storage_history::continuation::ContinuationNativeReceiptDataV1<'static>;
    size_of::<(&'static State, [u8; 16], Receipt, [&'static JournalTransaction; N])>()
        .checked_mul(3)?
        .checked_add(size_of::<Result<(), MechanicalError>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), E>>().checked_mul(3)?)?
        .checked_add(size_of::<MechanicalError>().checked_mul(3)?)?
        .checked_add(size_of::<E>().checked_mul(3)?)?
        .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
}

#[cfg(test)]
mod tests;
