//! Pure exact native Release-fence admission and status-capacity provenance.
//!
//! The same native row fences future export while preserving its original
//! Acquire artifacts. A separate status-only reservation protects one
//! descriptor-free Pending/Unavailable completion, not physical retirement.
//! These structural bindings confer no journal, signing or custody authority.

use std::collections::BTreeMap;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    SignedSourceProviderRequestV1, SourceProviderMethod, SourceProviderStatus,
    decode_release_request,
};
use sha2::{Digest as _, Sha256};

use super::{
    NativeAcquireCompletionRecordV2, NativeAcquireCompletionStateV2, native_completion_key_v2,
};
use crate::ledger::LedgerFormatErrorV1;
use crate::ledger::format::{
    acquisition_key, attempt_key, authority_key, decode_record, encode_native_completion_v2,
    record_digest, release_key, session_history_key, session_key,
};
use crate::ledger::model::{
    AcquisitionKeyV1, AcquisitionRecordV1, AttemptKeyV1, AttemptRecordV1, DecodedRecordV1,
    HolderSessionHeadRecordV1, ProviderAcquisitionStateV1, ProviderAttemptStateV1,
    ProviderReleaseStateV1, ReleaseKeyV1, ReleaseRecordV1,
};

/// Counts the three status owner rows and only this suffix's capacity deletion.
pub const NATIVE_RELEASE_STATUS_TERMINAL_RECORDS_V1: u32 = 4;

/// Bounds the separate native Release status suffix including journal framing.
///
/// Owner bounds include their keys and conservative nine-byte mutation frames;
/// the namespace-46 deletion contributes seven payload bytes and its 72-byte
/// key. Every record and Begin/Commit adds 72 bytes; their payload adds 40.
pub const NATIVE_RELEASE_STATUS_TERMINAL_BYTES_V1: u64 =
    crate::ledger::format::MAXIMUM_NATIVE_RELEASE_STATUS_OWNER_BYTES_V1 as u64
        + 7
        + 72
        + 72 * (NATIVE_RELEASE_STATUS_TERMINAL_RECORDS_V1 as u64 + 2)
        + 40;

/// Describes one exact, nonauthorizing native Release status suffix binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeReleaseStatusCapacityBindingV1 {
    /// Domain-separated owner identity, distinct from either Acquire owner.
    pub owner_id: [u8; 32],
    /// Purpose-specific digest of the unchanged canonical native cleanup carrier.
    pub owner_digest: ObjectDigest,
    /// Exact Release effect identity, never the original Acquire effect.
    pub operation_id: [u8; 16],
    /// Exact current Release attempt, never the original Acquire attempt.
    pub artifact_digest: ObjectDigest,
    /// Exact signed Root Release request digest.
    pub checkpoint_digest: ObjectDigest,
    /// Original session of this Release request, not the Acquire session.
    pub chain_head_digest: ObjectDigest,
}

/// Binds exact reserved or completed native Release status lineage.
///
/// The caller authenticates the complete graph, including original Acquire
/// history. This join deliberately leaves the original native cleanup floor
/// untouched and cannot authorize a Complete or BackendReleased result.
/// Completed Pending/Unavailable remains verifiable after suffix settlement;
/// a protected capacity consumer must independently require Reserved.
///
/// # Errors
///
/// Rejects foreign lineage, absent original artifacts, or any outcome other
/// than Reserved or immutable Pending/Unavailable.
pub fn native_release_status_capacity_binding_v1(
    acquisition: &AcquisitionRecordV1,
    native: &NativeAcquireCompletionRecordV2,
    original_acquire: &AttemptRecordV1,
    release: &ReleaseRecordV1,
    attempt: &AttemptRecordV1,
    session: &HolderSessionHeadRecordV1,
) -> Result<NativeReleaseStatusCapacityBindingV1, LedgerFormatErrorV1> {
    release_status_binding(
        acquisition,
        native,
        original_acquire,
        release,
        attempt,
        session,
        &encode_native_completion_v2(native),
    )
}

pub(crate) fn release_status_binding(
    acquisition: &AcquisitionRecordV1,
    native: &NativeAcquireCompletionRecordV2,
    original_acquire: &AttemptRecordV1,
    release: &ReleaseRecordV1,
    attempt: &AttemptRecordV1,
    session: &HolderSessionHeadRecordV1,
    canonical_native: &[u8],
) -> Result<NativeReleaseStatusCapacityBindingV1, LedgerFormatErrorV1> {
    native.validate_provider_graph(original_acquire, acquisition)?;
    crate::ledger::reducer::validate_release_join(acquisition, release, attempt)?;
    let signed = SignedSourceProviderRequestV1::from_canonical_bytes(&attempt.signed_request)
        .map_err(|_| LedgerFormatErrorV1::Corrupt("native Release signed original request"))?;
    let root = decode_release_request(signed.subject())
        .map_err(|_| LedgerFormatErrorV1::Corrupt("native Release original request"))?;
    // A held terminal keeps the original status result as historical evidence
    // after genuine Released reducers. Its immutable identity is unchanged;
    // this is never an outstanding status-floor admission.
    let held = if crate::ledger::native_held_completion::graph::is_held(canonical_native) {
        let held = crate::ledger::native_held_completion::SourceNativeHeldCompletionRecordV1::from_canonical_bytes(
            &native_completion_key_v2(native.acquisition_id), canonical_native,
        )?;
        if held.original() != native {
            return Err(LedgerFormatErrorV1::Corrupt("held status actual carrier"));
        }
        Some(held)
    } else {
        if encode_native_completion_v2(native) != canonical_native {
            return Err(LedgerFormatErrorV1::Corrupt("legacy status actual carrier"));
        }
        None
    };
    let historical_terminal = held
        .as_ref()
        .is_some_and(|held| held.suffix().phase() == 10)
        && acquisition.state == ProviderAcquisitionStateV1::Released
        && release.state == ProviderReleaseStateV1::Tombstone
        && native_release_status_is_completed_v1(attempt);
    if (!matches!(
        acquisition.state,
        ProviderAcquisitionStateV1::Releasing | ProviderAcquisitionStateV1::Faulted
    ) && !historical_terminal)
        || native.state != NativeAcquireCompletionStateV2::CleanupRequired
        || native.canonical_request.is_none()
        || native.accepted_reply.is_none()
        || native.original_clock.is_none()
        || acquisition.lease_id.is_none()
        || acquisition.lease_id != Some(release.lease_id)
        || acquisition.lease_digest != Some(release.lease_digest)
        || release.backend_id != acquisition.backend_id
        || acquisition.lease_attempt_digest != Some(native.attempt_digest)
        || attempt.method != SourceProviderMethod::Release
        || !(attempt.state == ProviderAttemptStateV1::Reserved
            || native_release_status_is_completed_v1(attempt))
        || (release.state != ProviderReleaseStateV1::Intent && !historical_terminal)
        || release.effect_attempt_digest != attempt.attempt_digest
        || session.provider != attempt.provider
        || session.holder != attempt.holder
        || session.session_binding != attempt.session_binding
        || (attempt.state == ProviderAttemptStateV1::Reserved
            && session.pending_attempt_digest != Some(attempt.attempt_digest))
        || signed.method() != SourceProviderMethod::Release
        || root.acquisition_id() != acquisition.acquisition_id
        || root.lease_id() != release.lease_id
        || root.lease_digest() != release.lease_digest
        || root.session_binding() != attempt.session_binding
    {
        return Err(LedgerFormatErrorV1::Corrupt(
            "native Release status suffix lineage",
        ));
    }
    let mut owner = Sha256::new();
    owner.update(b"aos.sandbox.source-provider.native-release-status-owner.v1\0");
    owner.update(native.provider_id);
    owner.update(native.holder_id);
    owner.update(native.acquisition_id.as_bytes());
    owner.update(release.effect_id);
    // A canonical Faulted observation may advance the Release row's revision
    // and acquisition-record digest. Neither settles the status obligation.
    // Bind the immutable native carrier instead; all exact Release provenance
    // remains independently joined below and in the capacity recovery fields.
    let mut status_owner = Sha256::new();
    status_owner.update(b"aos.sandbox.source-provider.native-release-status-carrier.v1\0");
    status_owner.update(record_digest(canonical_native)?.as_bytes());
    Ok(NativeReleaseStatusCapacityBindingV1 {
        owner_id: owner.finalize().into(),
        owner_digest: ObjectDigest::from_bytes(status_owner.finalize().into()),
        operation_id: release.effect_id,
        artifact_digest: attempt.attempt_digest,
        checkpoint_digest: attempt.signed_request_digest,
        chain_head_digest: attempt.session_binding,
    })
}

/// Validates exactly the seven owner-row native Active-to-Release admission.
///
/// Both graphs pass the ordinary strict structural successor validator. This
/// extra shape restriction is the sole exception to the ordinary six-row
/// ceiling; it admits no deletions, no no-dispatch identity and no terminal
/// result. The capacity PUT belongs to the protected owner, not this codec.
///
/// # Errors
///
/// Rejects any extra/missing row, wrong phase, changed original artifacts or
/// Release/request/session/lease mismatch.
pub fn validate_native_release_admission_v1(
    current: &BTreeMap<Vec<u8>, Vec<u8>>,
    prospective: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<(), LedgerFormatErrorV1> {
    crate::validate_prospective_transition(
        current
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
        prospective
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
    )?;
    let changed = prospective
        .iter()
        .filter(|(key, value)| current.get(*key) != Some(*value))
        .map(|(key, _)| key.clone())
        .collect::<std::collections::BTreeSet<_>>();
    if changed.len() != 7 || current.keys().any(|key| !prospective.contains_key(key)) {
        return Err(LedgerFormatErrorV1::Corrupt(
            "native Release admission row set",
        ));
    }
    let native = changed
        .iter()
        .find_map(
            |key| match decode_record(key, prospective.get(key)?).ok()? {
                DecodedRecordV1::NativeCompletion(native) => Some(native),
                _ => None,
            },
        )
        .ok_or(LedgerFormatErrorV1::Corrupt(
            "native Release admission marker",
        ))?;
    let native_key = native_completion_key_v2(native.acquisition_id);
    let predecessor = match current
        .get(&native_key)
        .map(|bytes| decode_record(&native_key, bytes))
        .transpose()?
    {
        Some(DecodedRecordV1::NativeCompletion(row)) => row,
        _ => {
            return Err(LedgerFormatErrorV1::Corrupt(
                "native Release predecessor marker",
            ));
        }
    };
    if predecessor.state != NativeAcquireCompletionStateV2::Active
        || predecessor.advance(NativeAcquireCompletionStateV2::CleanupRequired)? != native
    {
        return Err(LedgerFormatErrorV1::Corrupt(
            "native Release original artifact change",
        ));
    }
    validate_release_admission_rows(
        current,
        prospective,
        &native,
        &encode_native_completion_v2(&native),
    )?;
    Ok(())
}

// Shared exact Release/request/lease comparison. The held caller has already
// checked its actual terminal carrier and which native predecessor is present.
pub(crate) fn validate_release_admission_rows(
    current: &BTreeMap<Vec<u8>, Vec<u8>>,
    prospective: &BTreeMap<Vec<u8>, Vec<u8>>,
    native: &NativeAcquireCompletionRecordV2,
    canonical_native: &[u8],
) -> Result<NativeReleaseStatusCapacityBindingV1, LedgerFormatErrorV1> {
    let native_key = native_completion_key_v2(native.acquisition_id);
    let changed = current
        .keys()
        .chain(prospective.keys())
        .filter(|key| current.get(*key) != prospective.get(*key))
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let acquisition_key = acquisition_key(&AcquisitionKeyV1 {
        provider_id: native.provider_id,
        holder_id: native.holder_id,
        acquisition_id: native.acquisition_id,
    });
    let acquisition = match decode_record(
        &acquisition_key,
        prospective
            .get(&acquisition_key)
            .ok_or(LedgerFormatErrorV1::Corrupt("native Release acquisition"))?,
    )? {
        DecodedRecordV1::Acquisition(row) => row,
        _ => {
            return Err(LedgerFormatErrorV1::Corrupt(
                "native Release acquisition type",
            ));
        }
    };
    let old_acquisition = match decode_record(
        &acquisition_key,
        current
            .get(&acquisition_key)
            .ok_or(LedgerFormatErrorV1::Corrupt(
                "native Release predecessor acquisition",
            ))?,
    )? {
        DecodedRecordV1::Acquisition(row) => row,
        _ => {
            return Err(LedgerFormatErrorV1::Corrupt(
                "native Release predecessor acquisition type",
            ));
        }
    };
    let release_key = release_key(&ReleaseKeyV1 {
        provider_id: native.provider_id,
        holder_id: native.holder_id,
        acquisition_id: native.acquisition_id,
    });
    if current.contains_key(&release_key)
        || old_acquisition.state != ProviderAcquisitionStateV1::Active
    {
        return Err(LedgerFormatErrorV1::Corrupt(
            "native Release admission is not fresh",
        ));
    }
    let release = match decode_record(
        &release_key,
        prospective
            .get(&release_key)
            .ok_or(LedgerFormatErrorV1::Corrupt("native Release intent"))?,
    )? {
        DecodedRecordV1::Release(row) => row,
        _ => return Err(LedgerFormatErrorV1::Corrupt("native Release intent type")),
    };
    let attempts = prospective
        .iter()
        .filter_map(|(key, value)| match decode_record(key, value).ok()? {
            DecodedRecordV1::Attempt(attempt) => Some(attempt),
            _ => None,
        })
        .collect::<Vec<_>>();
    let original = attempts
        .iter()
        .find(|row| row.attempt_digest == native.attempt_digest)
        .ok_or(LedgerFormatErrorV1::Corrupt(
            "native Release original Acquire",
        ))?;
    let attempt = attempts
        .iter()
        .find(|row| row.attempt_digest == release.attempt_digest)
        .ok_or(LedgerFormatErrorV1::Corrupt(
            "native Release current attempt",
        ))?;
    let mut expected_acquisition = old_acquisition.clone();
    expected_acquisition.revision =
        expected_acquisition
            .revision
            .checked_add(1)
            .ok_or(LedgerFormatErrorV1::Corrupt(
                "native Release acquisition revision exhausted",
            ))?;
    expected_acquisition.state = ProviderAcquisitionStateV1::Releasing;
    expected_acquisition.current_attempt_digest = attempt.attempt_digest;
    expected_acquisition.release_effect_id = Some(release.effect_id);
    if acquisition != expected_acquisition {
        return Err(LedgerFormatErrorV1::Corrupt(
            "native Release original lease change",
        ));
    }
    let session_key = session_key(native.provider_id, native.holder_id);
    let session = match decode_record(
        &session_key,
        prospective
            .get(&session_key)
            .ok_or(LedgerFormatErrorV1::Corrupt("native Release session"))?,
    )? {
        DecodedRecordV1::Session(row) => row,
        _ => return Err(LedgerFormatErrorV1::Corrupt("native Release session type")),
    };
    let binding = release_status_binding(
        &acquisition,
        &native,
        original,
        &release,
        attempt,
        &session,
        canonical_native,
    )?;
    let mut expected = [
        acquisition_key,
        release_key,
        session_key,
        authority_key(native.provider_id),
        attempt_key(&AttemptKeyV1 {
            provider_id: native.provider_id,
            holder_id: native.holder_id,
            root_record_key_id: attempt.root_record_signer.key_id(),
            method: SourceProviderMethod::Release as u8,
            request_id: attempt.request_id,
        }),
        session_history_key(
            native.provider_id,
            native.holder_id,
            session.session_binding,
        ),
    ]
    .into_iter()
    .collect::<std::collections::BTreeSet<_>>();
    if current.get(&native_key) != prospective.get(&native_key) {
        expected.insert(native_key);
    }
    if changed != expected || expected.iter().any(|key| !prospective.contains_key(key)) {
        return Err(LedgerFormatErrorV1::Corrupt(
            "native Release exact seven owner rows",
        ));
    }
    Ok(binding)
}

/// Identifies only the two immutable descriptor-free native status outcomes.
#[must_use]
pub fn native_release_status_is_completed_v1(attempt: &AttemptRecordV1) -> bool {
    attempt.method == SourceProviderMethod::Release
        && attempt.state == ProviderAttemptStateV1::Completed
        && matches!(
            attempt.status,
            Some(SourceProviderStatus::Pending | SourceProviderStatus::Unavailable)
        )
}
