//! Exact cold terminal companions, retained transitions and owner-only proposals.
//!
//! Complete graph and explicit mutation inputs remain DATA. Physical admission,
//! copied-floor validity, challenge absence and current Root ACK are not inferred.

use std::collections::{BTreeMap, BTreeSet};

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    SourceProviderMethod, SignedSourceProviderRequestV1, decode_acquire_request,
    native_held_completion::witness::native_held_record_byte_digest_v1,
};
use sha2::{Digest as _, Sha256};

use super::{
    SourcePreRequestedColdArchiveV1 as Archive, SourcePreRequestedColdPhaseV1 as Phase,
    SourcePreRequestedColdTransactionV1, corrupt,
};
use crate::ledger::{
    LedgerFormatErrorV1, format,
    model::{
        AcquisitionKeyV1, AcquisitionRecordV1, AttemptKeyV1, AttemptRecordV1,
        DecodedRecordV1, HolderSessionHeadRecordV1,
        ProviderAcquisitionStateV1 as Acquisition, ProviderAttemptStateV1 as Attempt,
    },
    native_completion::{
        self, OriginalSourceProvenanceV5, derive_original_source_pre_requested_retirement_v1,
        original_source_owner::apply_exact_puts,
    },
    native_held_completion::{graph as held_graph, transition},
};

type Records = BTreeMap<Vec<u8>, Vec<u8>>;
const STAGED_DOMAIN: &[u8] = b"aos-source-provider-pre-requested-staged-claims.v1\0";

// Both complete graphs have passed the shared current core before structural
// transition checks. Decode and join every cold row before any legacy scan can
// skip it; an envelope hint alone never establishes a retained cold owner.
pub(crate) fn validated_archives(
    records: &Records,
) -> Result<BTreeMap<Vec<u8>, Archive>, LedgerFormatErrorV1> {
    let mut archives = BTreeMap::new();
    for (key, bytes) in records {
        if super::is_cold(bytes) {
            let archive = Archive::from_canonical_bytes(key, bytes)?;
            validate_companions(records, &archive)?;
            archives.insert(key.clone(), archive);
        }
    }

    Ok(archives)
}

/// Validates complete cold-profile owner DATA without a legacy admission seal.
///
/// # Errors
///
/// Rejects duplicate/oversize/noncanonical rows, inconsistent terminal companions
/// or any other failure of the shared complete current graph checks.
pub fn validate_original_source_pre_requested_cold_records_v1<'record>(
    records: impl IntoIterator<Item = (&'record [u8], &'record [u8])>,
) -> Result<(), LedgerFormatErrorV1> {
    let records = crate::collect_bounded_records(records)?;
    crate::validate_current_records(&records)?;
    Ok(())
}

/// Classifies one exact cold archive in a completely validated owner graph.
///
/// # Errors
///
/// Rejects an absent or foreign profile, malformed complete graph, changed
/// terminal dependencies or inconsistent historical Holder reconstruction.
pub fn classify_original_source_pre_requested_cold_v1<'record>(
    records: impl IntoIterator<Item = (&'record [u8], &'record [u8])>,
    acquisition_id: ObjectDigest,
) -> Result<Archive, LedgerFormatErrorV1> {
    let records = crate::collect_bounded_records(records)?;
    crate::validate_current_records(&records)?;
    read_archive(
        &records,
        &native_completion::native_completion_key_v2(acquisition_id),
    )
}

/// Checks exactly five original closure owner PUTs as nonauthorizing DATA.
///
/// Typed provenance is compared to real before bytes here, but is not proof that
/// opaque copied F, its admission or either physical writer cut was protected.
///
/// # Errors
///
/// Rejects a non-Applying origin, changed provenance/configuration, duplicate,
/// deleting/noop/foreign PUTs, incorrect retirement bytes or invalid after graph.
pub fn propose_original_source_pre_requested_closed_v1<'record, 'change>(
    before: impl IntoIterator<Item = (&'record [u8], &'record [u8])>,
    changes: impl IntoIterator<Item = (&'change [u8], Option<&'change [u8]>)>,
    provenance: &OriginalSourceProvenanceV5,
    configuration: ObjectDigest,
) -> Result<SourcePreRequestedColdTransactionV1, LedgerFormatErrorV1> {
    let before = crate::collect_bounded_records(before)?;
    let retirement = derive_original_source_pre_requested_retirement_v1(
        views(&before),
        provenance,
        configuration,
    )?;
    let original = retirement.original();
    let key = native_completion::native_completion_key_v2(original.acquisition_id);
    let mut expected = BTreeSet::from([key.clone()]);
    expected.extend(
        retirement
            .mutations()
            .iter()
            .map(|mutation| mutation.key().to_vec()),
    );
    let after = apply_exact_puts(&before, changes, &expected)?;
    let archive = read_archive(&after, &key)?;
    validate_initial_transition(&before, &after, &key, &archive)?;

    let claims = archive.prepared().claims();
    let staged = provenance.claims().claims.to_canonical_bytes();
    let staged_digest = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(STAGED_DOMAIN)
            .chain_update((staged.len() as u32).to_be_bytes())
            .chain_update(staged)
            .finalize()
            .into(),
    );
    if claims.provider_id != original.provider.authority_id()
        || claims.holder_id != original.holder.authority_id()
        || claims.original_session != original.session_binding
        || claims.acquisition_id != original.acquisition_id
        || claims.original_signed_request != original.root_request_digest
        || claims.original_attempt != original.attempt_digest
        || claims.original_root_prepared != original.root_prepared_digest
        || claims.original_applying != original.reservation_acquisition_digest
        || claims.staged_claims != staged_digest
        || claims.challenge_absence.key().get(8..)
            != Some(provenance.claims().claims.attempt().0.as_slice())
    {
        return Err(corrupt("cold exact original provenance joins"));
    }

    finish_proposal(&before, after, expected, archive)
}

/// Checks only a phase1-to2 archive PUT retaining exact F and preparation.
///
/// # Errors
///
/// Rejects another phase, changed original DATA, invalid graph, unrelated,
/// duplicate/deleting/noop PUTs or a signature claim over another preparation.
pub fn propose_original_source_pre_requested_closure_stored_v1<'record, 'change>(
    before: impl IntoIterator<Item = (&'record [u8], &'record [u8])>,
    changes: impl IntoIterator<Item = (&'change [u8], Option<&'change [u8]>)>,
    acquisition_id: ObjectDigest,
) -> Result<SourcePreRequestedColdTransactionV1, LedgerFormatErrorV1> {
    propose_singleton(
        before,
        changes,
        acquisition_id,
        Phase::ClosedPrepared,
        Phase::ClosureStored,
    )
}

/// Checks only a phase2-to3 archive PUT retaining exact F, preparation and Z.
///
/// This checks ACK DATA shape and stable Source joins, not the live query,
/// signer pin, Root terminal, physical floor deletion or pin discharge.
///
/// # Errors
///
/// Rejects another phase, changed archive or terminal DATA, malformed ACK
/// references, invalid graph or anything but the exact singleton owner PUT.
pub fn propose_original_source_pre_requested_root_acknowledged_v1<'record, 'change>(
    before: impl IntoIterator<Item = (&'record [u8], &'record [u8])>,
    changes: impl IntoIterator<Item = (&'change [u8], Option<&'change [u8]>)>,
    acquisition_id: ObjectDigest,
) -> Result<SourcePreRequestedColdTransactionV1, LedgerFormatErrorV1> {
    propose_singleton(
        before,
        changes,
        acquisition_id,
        Phase::ClosureStored,
        Phase::RootAcknowledged,
    )
}

fn propose_singleton<'record, 'change>(
    before: impl IntoIterator<Item = (&'record [u8], &'record [u8])>,
    changes: impl IntoIterator<Item = (&'change [u8], Option<&'change [u8]>)>,
    acquisition_id: ObjectDigest,
    old_phase: Phase,
    new_phase: Phase,
) -> Result<SourcePreRequestedColdTransactionV1, LedgerFormatErrorV1> {
    let before = crate::collect_bounded_records(before)?;
    crate::validate_current_records(&before)?;
    let key = native_completion::native_completion_key_v2(acquisition_id);
    let old = read_archive(&before, &key)?;
    let expected = BTreeSet::from([key.clone()]);
    let after = apply_exact_puts(&before, changes, &expected)?;
    let archive = read_archive(&after, &key)?;
    if old.phase() != old_phase || archive.phase() != new_phase {
        return Err(corrupt("cold proposal phase"));
    }
    validate_retained_transition(&before, &after, &key, &old, &archive)?;
    finish_proposal(&before, after, expected, archive)
}

fn finish_proposal(
    before: &Records,
    after: Records,
    expected: BTreeSet<Vec<u8>>,
    archive: Archive,
) -> Result<SourcePreRequestedColdTransactionV1, LedgerFormatErrorV1> {
    crate::validate_current_records(&after)?;
    crate::validate_transition_structure(before, &after)?;
    let mutations = transition::exact_mutations(before, &after, &expected)?;
    Ok(SourcePreRequestedColdTransactionV1 { archive, mutations })
}

struct Companions {
    attempt: AttemptRecordV1,
    acquisition: AcquisitionRecordV1,
    history: HolderSessionHeadRecordV1,
    keys: [Vec<u8>; 4],
}

impl Companions {
    fn read(records: &Records, archive: &Archive) -> Result<Self, LedgerFormatErrorV1> {
        let claims = archive.prepared().claims();
        let attempt_key = claims.terminal_records[0].key();
        let DecodedRecordV1::Attempt(attempt) = decode(records, attempt_key)? else {
            return Err(corrupt("cold terminal Attempt kind"));
        };
        let keys = [
            format::attempt_key(&AttemptKeyV1 {
                provider_id: claims.provider_id,
                holder_id: claims.holder_id,
                root_record_key_id: attempt.root_record_signer.key_id(),
                method: SourceProviderMethod::Acquire as u8,
                request_id: attempt.request_id,
            }),
            format::acquisition_key(&AcquisitionKeyV1 {
                provider_id: claims.provider_id,
                holder_id: claims.holder_id,
                acquisition_id: claims.acquisition_id,
            }),
            format::session_key(claims.provider_id, claims.holder_id),
            format::session_history_key(
                claims.provider_id,
                claims.holder_id,
                claims.original_session,
            ),
        ];
        if keys
            .iter()
            .zip(&claims.terminal_records)
            .any(|(key, witness)| key != witness.key())
        {
            return Err(corrupt("cold independently derived companion keys"));
        }
        let DecodedRecordV1::Acquisition(acquisition) = decode(records, &keys[1])? else {
            return Err(corrupt("cold terminal Acquisition kind"));
        };
        let DecodedRecordV1::SessionHistory(history) = decode(records, &keys[3])? else {
            return Err(corrupt("cold terminal History kind"));
        };
        Ok(Self {
            attempt,
            acquisition,
            history,
            keys,
        })
    }
}

pub(crate) fn validate_companions(
    records: &Records,
    archive: &Archive,
) -> Result<(), LedgerFormatErrorV1> {
    let rows = Companions::read(records, archive)?;
    let claims = archive.prepared().claims();
    let attempt = &rows.attempt;
    let acquisition = &rows.acquisition;
    let history = &rows.history;
    if attempt.revision != 2
        || attempt.state != Attempt::Retired
        || attempt.method != SourceProviderMethod::Acquire
        || attempt.status.is_some()
        || attempt.response_sequence.is_some()
        || attempt.response_digest.is_some()
        || attempt.result_digest.is_some()
        || attempt.completed_at_seconds.is_some()
        || !attempt.completed_response.is_empty()
        || attempt.recovery_predecessor_attempt_digest.is_some()
        || attempt.attempt_digest != claims.original_attempt
        || attempt.signed_request_digest != claims.original_signed_request
        || attempt.session_binding != claims.original_session
        || acquisition.revision != 2
        || acquisition.state != Acquisition::Faulted
        || acquisition.acquisition_id != claims.acquisition_id
        || acquisition.effect_attempt_digest != claims.original_attempt
        || acquisition.current_attempt_digest != claims.original_attempt
        || acquisition.provider != attempt.provider
        || acquisition.holder != attempt.holder
        || acquisition.normalized_intent.digest() != attempt.operation_intent_digest
        || attempt.provider.authority_id() != claims.provider_id
        || attempt.holder.authority_id() != claims.holder_id
        || history.provider != attempt.provider
        || history.holder != attempt.holder
        || history.session_binding != claims.original_session
        || history.revision < 3
        || history.pending_attempt_digest.is_some()
        || history.next_request_sequence
            != attempt.request_sequence.checked_add(1)
                .ok_or(corrupt("cold original request sequence overflow"))?
        || history.next_acquisition_sequence
            != attempt.acquisition_sequence.checked_add(1)
                .ok_or(corrupt("cold original acquisition sequence overflow"))?
        || history.root_process_instance != attempt.root_process_instance
        || history.provider_process_instance != attempt.provider_process_instance
        || history.signer_set_commitment != attempt.signer_set_commitment
        || archive.prepared().signer() != &history.signers[3]
        || attempt.root_record_signer != history.signers[1]
    {
        return Err(corrupt("cold exact terminal owner shape"));
    }
    require_unleased_original(acquisition)?;
    held_graph::validate_dispatch(acquisition, claims.original_session, claims.original_attempt)?;
    let signed = SignedSourceProviderRequestV1::from_canonical_bytes(&attempt.signed_request)
        .map_err(|_| corrupt("cold original signed Acquire"))?;
    let root = decode_acquire_request(signed.subject())
        .map_err(|_| corrupt("cold original Acquire subject"))?;
    let projected_intent = crate::NormalizedAcquisitionIntentV1::from_original_acquire_request(
        &root,
        history.provider.clone(),
        history.holder.clone(),
        root.node_id(),
        history.boot_id,
        history.route_id,
        history.route_generation,
        history.route_digest,
        history.resource_namespace_digest,
        history.revocation_generation,
        history.revocation_digest,
    )
    .map_err(|_| corrupt("cold original historical intent projection"))?;
    if root.native_catalog().is_none() || acquisition.normalized_intent != projected_intent {
        return Err(corrupt("cold original V3 Acquire normalization"));
    }

    let holder_bytes = format::encode_session(history);
    let values = [
        value_at(records, &rows.keys[0])?,
        value_at(records, &rows.keys[1])?,
        holder_bytes.as_slice(),
        value_at(records, &rows.keys[3])?,
    ];
    let digests = [
        claims.retired_attempt,
        claims.faulted_acquisition,
        claims.cleared_session,
        claims.session_history_successor,
    ];
    for ((witness, bytes), expected_digest) in
        claims.terminal_records.iter().zip(values).zip(digests)
    {
        let actual = native_held_record_byte_digest_v1(witness.family(), witness.key(), bytes)
            .map_err(|_| corrupt("cold terminal byte witness format"))?;
        if witness.digest() != actual || format::record_digest(bytes)? != expected_digest {
            return Err(corrupt("cold actual terminal byte commitments"));
        }
    }
    if archive.phase() == Phase::ClosedPrepared {
        let DecodedRecordV1::Session(current) = decode(records, &rows.keys[2])? else {
            return Err(corrupt("cold phase1 Holder kind"));
        };
        if current != *history {
            return Err(corrupt("cold phase1 current Holder changed"));
        }
    }

    let mut applying = acquisition.clone();
    applying.revision = 1;
    applying.state = Acquisition::Applying;
    let applying_bytes = format::encode_acquisition(&applying);
    format::decode_record(&rows.keys[1], &applying_bytes)?;
    if format::record_digest(&applying_bytes)? != claims.original_applying {
        return Err(corrupt("cold original Applying inverse bytes"));
    }
    Ok(())
}

fn require_unleased_original(acquisition: &AcquisitionRecordV1) -> Result<(), LedgerFormatErrorV1> {
    if acquisition.lease_id.is_some()
        || acquisition.lease_digest.is_some()
        || acquisition.lease_attempt_digest.is_some()
        || acquisition.lease_issue_generation != 0
        || !acquisition.lease_history.is_empty()
        || !acquisition.signed_lease.is_empty()
        || acquisition.proof_class != 0
        || acquisition.proof_digest.as_bytes() != &[0; 32]
        || acquisition.resource_commitment.as_bytes() != &[0; 32]
        || acquisition.backend_evidence.is_some()
        || acquisition.reopen_identity.is_some()
        || acquisition.source_root.is_some()
        || acquisition.release_effect_id.is_some()
        || acquisition.native_no_dispatch_reservation_digest.is_some()
    {
        return Err(corrupt("cold exact original unleased acquisition"));
    }
    Ok(())
}

// The structural caller validates both complete graphs. The exact proposal
// additionally checks this before validating its after graph. Neither route
// infers no escape from a logically absent native row.
pub(crate) fn validate_initial_transition(
    before: &Records,
    after: &Records,
    key: &[u8],
    archive: &Archive,
) -> Result<(), LedgerFormatErrorV1> {
    if before.contains_key(key) || archive.phase() != Phase::ClosedPrepared {
        return Err(corrupt("cold initial native identity/phase"));
    }
    let terminal = Companions::read(after, archive)?;
    let DecodedRecordV1::Attempt(attempt) = decode(before, &terminal.keys[0])? else {
        return Err(corrupt("cold initial Attempt kind"));
    };
    let DecodedRecordV1::Acquisition(acquisition) = decode(before, &terminal.keys[1])? else {
        return Err(corrupt("cold initial Acquisition kind"));
    };
    let DecodedRecordV1::Session(holder) = decode(before, &terminal.keys[2])? else {
        return Err(corrupt("cold initial Holder kind"));
    };
    let DecodedRecordV1::SessionHistory(history) = decode(before, &terminal.keys[3])? else {
        return Err(corrupt("cold initial History kind"));
    };
    let claims = archive.prepared().claims();
    if attempt.revision != 1
        || attempt.state != Attempt::Reserved
        || acquisition.revision != 1
        || acquisition.state != Acquisition::Applying
        || holder != history
        || holder.pending_attempt_digest != Some(attempt.attempt_digest)
        || holder.session_binding != claims.original_session
        || attempt.attempt_digest != claims.original_attempt
        || attempt.signed_request_digest != claims.original_signed_request
        || format::record_digest(value_at(before, &terminal.keys[1])?)? != claims.original_applying
        || archive.prepared().signer() != &holder.signers[3]
    {
        return Err(corrupt("cold initial exact Applying cut"));
    }
    require_unleased_original(&acquisition)?;
    held_graph::validate_dispatch(&acquisition, holder.session_binding, attempt.attempt_digest)?;
    let values = held_graph::retire_pending_quartet(&attempt, &acquisition, &holder)?;

    let mut expected = before.clone();
    for (owner_key, value) in terminal.keys.iter().zip(values) {
        expected.insert(owner_key.clone(), value);
    }
    expected.insert(key.to_vec(), value_at(after, key)?.to_vec());
    if expected != *after {
        return Err(corrupt("cold exact initial five-owner change"));
    }

    let owner_keys = terminal.keys.into_iter().chain([key.to_vec()]).collect();
    transition::exact_mutations(before, after, &owner_keys)?;
    validate_companions(after, archive)
}

pub(crate) fn validate_retained_transition(
    before: &Records,
    after: &Records,
    key: &[u8],
    old: &Archive,
    new: &Archive,
) -> Result<(), LedgerFormatErrorV1> {
    let keys = &old.prepared().claims().terminal_records;
    // Original History is frozen even when the ordinary core would permit
    // rewriting a was-current History alongside its mutable Holder.
    for index in [0, 1, 3] {
        if before.get(keys[index].key()) != after.get(keys[index].key()) {
            return Err(corrupt("cold frozen terminal dependency changed"));
        }
    }
    if old.phase() == Phase::ClosedPrepared
        && before.get(keys[2].key()) != after.get(keys[2].key())
    {
        return Err(corrupt("cold phase1 original Holder changed"));
    }
    if old == new {
        return Ok(());
    }
    let valid_edge = matches!(
        (old.phase(), new.phase()),
        (Phase::ClosedPrepared, Phase::ClosureStored)
            | (Phase::ClosureStored, Phase::RootAcknowledged)
    );
    if !valid_edge
        || old.initial_source_floor_bytes() != new.initial_source_floor_bytes()
        || old.prepared() != new.prepared()
        || (old.signed().is_some() && old.signed() != new.signed())
    {
        return Err(corrupt("cold retained archive discontinuity"));
    }
    let expected = BTreeSet::from([key.to_vec()]);
    transition::exact_mutations(before, after, &expected)?;
    Ok(())
}

fn read_archive(records: &Records, key: &[u8]) -> Result<Archive, LedgerFormatErrorV1> {
    Archive::from_canonical_bytes(key, value_at(records, key)?)
}

fn decode(records: &Records, key: &[u8]) -> Result<DecodedRecordV1, LedgerFormatErrorV1> {
    format::decode_record(key, value_at(records, key)?)
}

fn value_at<'records>(
    records: &'records Records,
    key: &[u8],
) -> Result<&'records [u8], LedgerFormatErrorV1> {
    records
        .get(key)
        .map(Vec::as_slice)
        .ok_or(corrupt("cold mandatory row absent"))
}

fn views(records: &Records) -> impl Iterator<Item = (&[u8], &[u8])> {
    records.iter().map(|(key, bytes)| (key.as_slice(), bytes.as_slice()))
}
