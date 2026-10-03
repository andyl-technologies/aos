//! Exact Source companion keys, complete graph checks and before-image witnesses.

// Cold DATA vectors live here only to reuse the unchanged private held graph
// fixtures. Production cold ownership remains in native_completion.
#[cfg(test)]
#[path = "../native_completion/pre_requested_cold/tests.rs"]
mod pre_requested_cold_tests;

use super::{SourceNativeHeldCompletionRecordV1 as Record, corrupt, evidence};
use crate::ledger::{
    LedgerFormatErrorV1, format,
    model::{
        AcquisitionKeyV1, AcquisitionRecordV1, AttemptKeyV1, AttemptRecordV1,
        AuthorityHeadRecordV1, CatalogHeadRecordV1, DecodedRecordV1, HolderSessionHeadRecordV1,
    },
    native_completion,
};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    AcquireSourceRequestV1, StorageZfsHoldTransportRequestV1, decode_acquire_request,
    native_held_completion::{
        NativeHeldOwnerV1 as Owner, NativeHeldSectionTagV1 as Tag,
        frame::PreparedNativeHeldControlV1,
        witness::{
            NativeHeldByteWitnessV1, NativeHeldOwnerWitnessV1, NativeHeldRecordFamilyV1 as Family,
            NativeHeldGenerationClaimV1, ProviderNativeHeldWitnessV1,
            native_held_record_byte_digest_v1,
        },
    },
};
use sha2::{Digest as _, Sha256};
use std::{borrow::Cow, collections::BTreeMap};

pub(super) type Records = BTreeMap<Vec<u8>, Vec<u8>>;

/// Checks this explicit held graph without yielding a legacy recovery/admission handle.
///
/// The shared structural core checks the complete current graph and dispatches
/// native predicates on the actual canonical profile. Signatures' eligibility,
/// actual writer cuts and the separate challenge owner remain runtime obligations.
///
/// # Errors
///
/// Rejects duplicate/oversize/noncanonical rows, broken companion graphs, a
/// no-dispatch lineage, changed original requests or inconsistent held artifacts.
pub fn validate_native_held_records_v1<'a>(
    records: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
) -> Result<(), LedgerFormatErrorV1> {
    let records = collect(records)?;
    validate(&records)
}

/// Derives phase-four witness and Complete-artifact DATA from actual before rows.
///
/// Cookies and sequences remain comparison claims. The protected caller and
/// the unchanged transition proposer still hold/validate the complete graph.
///
/// # Errors
///
/// Rejects anything except original Active phase4, changed selected bindings,
/// incomplete companions, a non-Spent challenge or an invalid Complete artifact.
pub fn derive_provider_held_preparation_data_v5<'rows>(
    records: impl IntoIterator<Item = (&'rows [u8], &'rows [u8])>,
    acquisition: ObjectDigest,
    original_spent: &[u8],
    root_local_cookie: std::num::NonZeroU64,
    storage_local_cookie: std::num::NonZeroU64,
    completion_sequence: u64,
    challenge_sequence: u64,
    selected: &aos_sandbox_source_provider_protocol::native_held_completion::SourceSelectedNativeExecutionInputDataV1,
) -> Result<(ProviderNativeHeldWitnessV1, ObjectDigest), LedgerFormatErrorV1> {
    let records = collect(records)?;
    let native_key = native_completion::native_completion_key_v2(acquisition);
    let record = Record::from_canonical_bytes(
        &native_key,
        records.get(&native_key).ok_or(corrupt("held phase4 native missing"))?,
    )?;
    if record.suffix().phase() != 4
        || record.original().state != native_completion::NativeAcquireCompletionStateV2::Active
        || selected.fields().scope != evidence::full_scope(&record)?
        || selected.fields().provider_id != record.original().provider_id
        || selected.fields().holder_id != record.original().holder_id
        || completion_sequence == 0
        || challenge_sequence == 0
    {
        return Err(corrupt("held actual phase4 selected binding"));
    }
    validate_challenge(&record, Some(original_spent), true)?;
    let rows = Companions::read(&records, &record)?;
    let artifact = rows.validate_and_artifact(&record)?;
    if artifact.as_bytes() == &[0; 32]
        || selected.fields().normalized_intent_digest != rows.acquisition.normalized_intent.digest()
        || selected.fields().publication != publication_digest(&rows.catalog)
        || selected.fields().binding != record.original().binding_digest
    {
        return Err(corrupt("held complete artifact/publication"));
    }

    let families = [
        Family::ProviderAuthority, Family::ProviderAttempt, Family::ProviderAcquisition,
        Family::ProviderHolder, Family::ProviderHistory, Family::ProviderNative,
    ];
    let mut witnesses = Vec::with_capacity(7);
    for (family, key) in families.into_iter().zip(&rows.keys) {
        let value = records.get(key).ok_or(corrupt("held phase4 witness missing"))?;
        witnesses.push(NativeHeldByteWitnessV1::new(
            family, key.clone(), native_held_record_byte_digest_v1(family, key, value)?,
        ).map_err(super::schema_error)?);
    }
    let challenge_key = challenge_key(&record);
    witnesses.push(NativeHeldByteWitnessV1::new(
        Family::Challenge, challenge_key.clone(),
        native_held_record_byte_digest_v1(Family::Challenge, &challenge_key, original_spent)?,
    ).map_err(super::schema_error)?);
    let records = witnesses.try_into().map_err(|_| corrupt("held seven witnesses"))?;
    Ok((ProviderNativeHeldWitnessV1 {
        root_local_cookie: root_local_cookie.get(),
        storage_local_cookie: storage_local_cookie.get(),
        completion_sequence,
        challenge_sequence,
        authority: rows.authority.provider,
        native_namespace: rows.catalog.resource_namespace_digest,
        catalog_head: NativeHeldGenerationClaimV1 {
            generation: rows.catalog.catalog_generation, digest: rows.catalog.catalog_digest,
        },
        catalog_floor: NativeHeldGenerationClaimV1 {
            generation: rows.catalog.catalog_floor_generation, digest: rows.catalog.catalog_floor_digest,
        },
        head_commitment: catalog_commitment(&rows.catalog),
        publication: publication_digest(&rows.catalog),
        selected_manifest: selected.digest(),
        backend_manifest: selected.fields().backend_enrollment,
        verifier_manifest: selected.fields().dedicated_enrollment,
        records,
    }, artifact))
}

pub(super) fn collect<'a>(
    records: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
) -> Result<Records, LedgerFormatErrorV1> {
    crate::collect_bounded_records(records)
}

pub(crate) fn is_held(value: &[u8]) -> bool {
    value.get(8..10) == Some(8_u16.to_be_bytes().as_slice())
}

pub(super) fn validate(records: &Records) -> Result<(), LedgerFormatErrorV1> {
    crate::validate_current_records(records)?;
    Ok(())
}

pub(crate) fn validate_original_cut(
    records: &Records,
    key: &[u8],
    bytes: &[u8],
) -> Result<(), LedgerFormatErrorV1> {
    let record = Record::from_canonical_bytes(key, bytes)?;
    Companions::read(records, &record)?.validate(&record)
}

pub(super) struct Companions {
    pub(super) authority: AuthorityHeadRecordV1,
    pub(super) attempt: AttemptRecordV1,
    pub(super) acquisition: AcquisitionRecordV1,
    pub(super) holder: HolderSessionHeadRecordV1,
    pub(super) history: HolderSessionHeadRecordV1,
    pub(super) catalog: CatalogHeadRecordV1,
    pub(super) keys: [Vec<u8>; 6],
}

// The original history authenticates the retained request. The current Holder
// is independently paired to its own history by the complete graph core.
pub(super) struct TerminalHeldArchive;

impl TerminalHeldArchive {
    pub(super) fn read(record: &Record) -> Result<Self, LedgerFormatErrorV1> {
        use aos_sandbox_source_provider_protocol::native_held_completion::{
            NativeHeldControlKindV1 as Kind, recovery::NativeHeldRecoveryModeV1 as Mode,
        };

        let terminal = record.suffix.control(Kind::RootTerminalRecorded).is_some()
            || record.suffix.controls().iter().any(|control| {
                control.kind() == Kind::RootRecoveryQuery
                    && evidence::query(control.prepared())
                        .is_ok_and(|query| query.mode == Mode::RecordRootTerminal)
            });
        if record.suffix.phase() != 10
            || record.suffix.prepared().is_some()
            || !terminal
            || evidence::settlement(record)?.is_none()
            || (record.suffix.control(Kind::ProviderSettled).is_none()
                && record.suffix.control(Kind::ProviderRecoveryState).is_none())
        {
            return Err(corrupt("held complete terminal archive"));
        }
        Ok(Self)
    }
}

// A marked cold original is a historical canonical comparison only. Its
// unique Requested/Prepared predecessor cannot recreate a live owner cut.
pub(super) fn cold_unleased_original<'record>(
    record: &'record Record,
    rows: &Companions,
) -> Result<
    Option<Cow<'record, native_completion::NativeAcquireCompletionRecordV2>>,
    LedgerFormatErrorV1,
> {
    use crate::ledger::model::{
        ProviderAcquisitionStateV1 as Acquisition, ProviderAttemptStateV1 as Attempt,
    };
    use aos_sandbox_source_provider_protocol::native_held_completion::assertion::{
        NativeHeldDispositionV1 as Disposition, RootNativeObservationV1 as Observation,
    };
    use native_completion::NativeAcquireCompletionStateV2 as Outer;

    let original = match record.original.state {
        Outer::Requested | Outer::Prepared => Cow::Borrowed(&record.original),
        Outer::CleanupRequired if rows.attempt.state == Attempt::Retired => {
            TerminalHeldArchive::read(record)?;
            let mut previous = record.original.clone();
            previous.state = if previous.accepted_reply.is_some() {
                Outer::Prepared
            } else {
                Outer::Requested
            };
            previous.revision = previous
                .revision
                .checked_sub(1)
                .filter(|revision| *revision != 0)
                .ok_or(corrupt("held cold cleanup predecessor revision"))?;
            previous.validate_canonical_artifacts()?;
            if previous.advance(Outer::CleanupRequired)? != record.original {
                return Err(corrupt("held exact cold cleanup predecessor"));
            }
            Cow::Owned(previous)
        }
        _ => return Ok(None),
    };

    let mut reservation = rows.acquisition.clone();
    if record.suffix.phase() == 10 {
        TerminalHeldArchive::read(record)?;
        let root =
            evidence::root_disposition(record)?.ok_or(corrupt("held cold Closed disposition"))?;
        if rows.attempt.state != Attempt::Retired
            || reservation.state != Acquisition::Faulted
            || root.disposition != Disposition::Closed
            || root.observation != Observation::PreparedOnly
            || evidence::artifact(record)?.as_bytes() != &[0; 32]
            || evidence::storage_assertion(record)?.is_none()
            || (rows.holder.session_binding == record.original.session_binding
                && rows.holder.pending_attempt_digest == Some(record.original.attempt_digest))
        {
            return Err(corrupt("held cold terminal scheduling was not retired"));
        }
        reservation.revision = reservation
            .revision
            .checked_sub(1)
            .filter(|revision| *revision != 0)
            .ok_or(corrupt("held retired reservation revision"))?;
        reservation.state = Acquisition::Applying;
    } else if rows.attempt.state != Attempt::Reserved
        || reservation.state != Acquisition::Applying
        || rows.holder != rows.history
        || rows.holder.pending_attempt_digest != Some(record.original.attempt_digest)
    {
        return Err(corrupt("held original occupied scheduling cut"));
    }
    if reservation.current_attempt_digest != record.original.attempt_digest
        || reservation.effect_attempt_digest != record.original.attempt_digest
        || reservation.lease_id.is_some()
        || reservation.lease_digest.is_some()
        || reservation.lease_attempt_digest.is_some()
        || reservation.lease_issue_generation != 0
        || !reservation.lease_history.is_empty()
        || !reservation.signed_lease.is_empty()
        || reservation.proof_class != 0
        || reservation.proof_digest.as_bytes() != &[0; 32]
        || reservation.resource_commitment.as_bytes() != &[0; 32]
        || reservation.backend_evidence.is_some()
        || reservation.reopen_identity.is_some()
        || reservation.source_root.is_some()
        || reservation.release_effect_id.is_some()
        || record.original.reservation_acquisition_digest
            != Some(format::record_digest(&format::encode_acquisition(
                &reservation,
            ))?)
    {
        return Err(corrupt("held full original unleased Applying reservation"));
    }
    Ok(Some(original))
}

pub(super) fn pending_retirement_rows(
    before: &Records,
    previous: &Record,
    next: &Record,
) -> Result<Records, LedgerFormatErrorV1> {
    use crate::ledger::model::{
        ProviderAcquisitionStateV1 as Acquisition, ProviderAttemptStateV1 as Attempt,
    };
    use native_completion::NativeAcquireCompletionStateV2 as Outer;

    let rows = Companions::read(before, previous)?;
    cold_unleased_original(previous, &rows)?;
    TerminalHeldArchive::read(next)?;
    if previous.suffix.phase() != 9
        || previous.suffix.prepared().is_some()
        || !matches!(previous.original.state, Outer::Requested | Outer::Prepared)
        || rows.attempt.state != Attempt::Reserved
        || rows.acquisition.state != Acquisition::Applying
        || rows.holder != rows.history
        || rows.holder.session_binding != previous.original.session_binding
        || rows.holder.pending_attempt_digest != Some(rows.attempt.attempt_digest)
        || rows.holder.next_request_sequence
            != rows
                .attempt
                .request_sequence
                .checked_add(1)
                .ok_or(corrupt("held retirement request sequence"))?
    {
        return Err(corrupt("held exact pending retirement before cut"));
    }

    let values = retire_pending_quartet(&rows.attempt, &rows.acquisition, &rows.holder)?;
    let mut result = before.clone();
    for (key, value) in rows.keys[1..5].iter().zip(values) {
        result.insert(key.clone(), value);
    }
    result.insert(rows.keys[5].clone(), next.to_canonical_bytes()?);
    Ok(result)
}

// Callers establish their own exact before cut. This shared transformation
// preserves every unrelated field and never constructs a native carrier.
pub(crate) fn retire_pending_quartet(
    attempt: &AttemptRecordV1,
    acquisition: &AcquisitionRecordV1,
    holder: &HolderSessionHeadRecordV1,
) -> Result<[Vec<u8>; 4], LedgerFormatErrorV1> {
    use crate::ledger::model::{
        ProviderAcquisitionStateV1 as Acquisition, ProviderAttemptStateV1 as Attempt,
    };

    let mut attempt = attempt.clone();
    let mut acquisition = acquisition.clone();
    let mut holder = holder.clone();

    attempt.revision = next_revision(attempt.revision)?;
    attempt.state = Attempt::Retired;
    acquisition.revision = next_revision(acquisition.revision)?;
    acquisition.state = Acquisition::Faulted;
    holder.revision = next_revision(holder.revision)?;
    holder.pending_attempt_digest = None;

    Ok([
        format::encode_attempt(&attempt),
        format::encode_acquisition(&acquisition),
        format::encode_session(&holder),
        format::encode_session_history(&holder),
    ])
}

pub(super) fn validate_pending_retirement(
    before: &Records,
    after: &Records,
    previous: &Record,
    next: &Record,
) -> Result<(), LedgerFormatErrorV1> {
    if pending_retirement_rows(before, previous, next)? != *after {
        return Err(corrupt("held exact five-owner pending retirement"));
    }
    Ok(())
}

pub(crate) fn validate_retained_transition(
    before: &Records,
    after: &Records,
    key: &[u8],
    old: &[u8],
    new: &[u8],
) -> Result<(), LedgerFormatErrorV1> {
    use native_completion::NativeAcquireCompletionStateV2 as Outer;

    let previous = Record::from_canonical_bytes(key, old)?;
    let next = Record::from_canonical_bytes(key, new)?;
    let rows = Companions::read(before, &previous)?;
    let terminal = previous.suffix.phase() == 10;
    if terminal {
        TerminalHeldArchive::read(&previous)?;
        let cold = cold_unleased_original(&previous, &rows)?.is_some();
        if previous.suffix != next.suffix
            || after.get(&rows.keys[1]) != before.get(&rows.keys[1])
            || (cold && after.get(&rows.keys[2]) != before.get(&rows.keys[2]))
        {
            return Err(corrupt("held terminal original dependencies changed"));
        }
    }
    if previous.suffix == next.suffix {
        if previous.original == next.original {
            if !terminal && before != after {
                return Err(corrupt("held in-flight archive freezes unrelated changes"));
            }
        } else if previous.original.advance(Outer::CleanupRequired)? != next.original {
            return Err(corrupt("held exact original custody marker"));
        }
    } else if terminal
        || previous.suffix.flight() != next.suffix.flight()
        || !next
            .suffix
            .controls()
            .starts_with(previous.suffix.controls())
    {
        return Err(corrupt("held retained archive rewrite"));
    }
    Ok(())
}

fn next_revision(revision: u64) -> Result<u64, LedgerFormatErrorV1> {
    revision
        .checked_add(1)
        .ok_or(corrupt("held owner revision exhausted"))
}

impl Companions {
    pub(super) fn read(records: &Records, record: &Record) -> Result<Self, LedgerFormatErrorV1> {
        let keys = companion_keys(record)?;
        let decoded = |index: usize| {
            format::decode_record(
                &keys[index],
                records
                    .get(&keys[index])
                    .ok_or(corrupt("held mandatory companion missing"))?,
            )
        };
        let DecodedRecordV1::Authority(authority) = decoded(0)? else {
            return Err(corrupt("held authority kind"));
        };
        let DecodedRecordV1::Attempt(attempt) = decoded(1)? else {
            return Err(corrupt("held attempt kind"));
        };
        let DecodedRecordV1::Acquisition(acquisition) = decoded(2)? else {
            return Err(corrupt("held acquisition kind"));
        };
        let DecodedRecordV1::Session(holder) = decoded(3)? else {
            return Err(corrupt("held holder kind"));
        };
        let DecodedRecordV1::SessionHistory(history) = decoded(4)? else {
            return Err(corrupt("held history kind"));
        };
        let catalog_key =
            format::catalog_key(record.original.provider_id, acquisition.catalog_generation);
        let DecodedRecordV1::Catalog(catalog) = format::decode_record(
            &catalog_key,
            records
                .get(&catalog_key)
                .ok_or(corrupt("held selected catalog missing"))?,
        )?
        else {
            return Err(corrupt("held selected catalog kind"));
        };
        Ok(Self {
            authority,
            attempt,
            acquisition,
            holder,
            history,
            catalog,
            keys,
        })
    }

    fn validate(&self, record: &Record) -> Result<(), LedgerFormatErrorV1> {
        self.validate_and_artifact(record).map(|_| ())
    }

    fn validate_and_artifact(&self, record: &Record) -> Result<ObjectDigest, LedgerFormatErrorV1> {
        let original = &record.original;
        let signed = original
            .canonical_request
            .as_ref()
            .ok_or(corrupt("held original request missing"))?;
        let root = decode_acquire_request(signed.request().signed_root_request().subject())
            .map_err(|_| corrupt("held Root subject"))?;
        validate_dispatch(
            &self.acquisition,
            original.session_binding,
            original.attempt_digest,
        )?;
        if self.attempt.signed_request
            != signed.request().signed_root_request().to_canonical_bytes()
            || !self
                .acquisition
                .normalized_intent
                .matches_original_acquire_request(&root)
            || self.history.session_binding != original.session_binding
            || self.history.signers[1] != *signed.request().signed_root_request().signer()
            || self.history.signers[3] != *signed.signer()
            || self.catalog.provider != self.acquisition.provider
            || self.catalog.resource_namespace_digest != self.acquisition.resource_namespace_digest
            || self.catalog.catalog_digest != self.acquisition.catalog_digest
            || original.publication_head != catalog_commitment(&self.catalog)
        {
            return Err(corrupt("held original dispatch/lineage/session/catalog"));
        }
        original.validate_provider_graph(&self.attempt, &self.acquisition)?;
        validate_original_selection(
            &self.acquisition,
            &self.catalog,
            &root,
            signed.request().claims(),
        )?;
        let cold_original = cold_unleased_original(record, self)?;
        // Only the validated cold lineage uses its historical zero-artifact
        // original. Hot cleanup retains the unchanged full Complete join.
        let actual_artifact = crate::ledger::completion::original_native_complete_artifact(
            cold_original.as_deref().unwrap_or(original),
            &self.attempt,
            &self.acquisition,
        )?;
        let claimed_artifact = evidence::artifact(record)?;
        if (evidence::has_artifact_claim(record) || record.suffix.phase() == 10)
            && claimed_artifact != actual_artifact
        {
            return Err(corrupt("held exact completed response artifact"));
        }
        Ok(actual_artifact)
    }
}

pub(super) fn companion_keys(record: &Record) -> Result<[Vec<u8>; 6], LedgerFormatErrorV1> {
    let value = &record.original;
    let root = value
        .canonical_request
        .as_ref()
        .ok_or(corrupt("held original key request"))?
        .request()
        .signed_root_request();
    Ok([
        format::authority_key(value.provider_id),
        format::attempt_key(&AttemptKeyV1 {
            provider_id: value.provider_id,
            holder_id: value.holder_id,
            root_record_key_id: root.signer().key_id(),
            method: aos_sandbox_source_provider_protocol::SourceProviderMethod::Acquire as u8,
            request_id: value.root_request_id,
        }),
        format::acquisition_key(&AcquisitionKeyV1 {
            provider_id: value.provider_id,
            holder_id: value.holder_id,
            acquisition_id: value.acquisition_id,
        }),
        format::session_key(value.provider_id, value.holder_id),
        format::session_history_key(value.provider_id, value.holder_id, value.session_binding),
        native_completion::native_completion_key_v2(value.acquisition_id),
    ])
}

// Matches the existing AcquirePlan's immutable original lineage, including
// explicit absent lease fields. Capacity cannot convert a no-dispatch identity.
pub(super) fn original_lineage(value: &AcquisitionRecordV1, session: ObjectDigest) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.source-provider.acquire-lineage.v1\0")
            .chain_update(value.provider.authority_id())
            .chain_update(value.holder.authority_id())
            .chain_update(session.as_bytes())
            .chain_update(value.effect_attempt_digest.as_bytes())
            .chain_update(value.acquisition_id.as_bytes())
            .chain_update(value.effect_id)
            .chain_update([0; 16])
            .chain_update([0; 32])
            .chain_update(value.backend_id)
            .finalize()
            .into(),
    )
}

pub(crate) fn validate_dispatch(
    value: &AcquisitionRecordV1,
    session: ObjectDigest,
    attempt: ObjectDigest,
) -> Result<(), LedgerFormatErrorV1> {
    let dispatch = crate::identity::acquire_native_dispatch_id_v2(
        value.normalized_intent.digest(),
        value.catalog_generation,
        value.catalog_digest,
        attempt,
    );
    if value.backend_id != dispatch
        || value.backend_lineage_digest != original_lineage(value, session)
        || value.native_no_dispatch_reservation_digest.is_some()
    {
        return Err(corrupt("held original dispatch backend/lineage"));
    }
    Ok(())
}

// Original Applying has only unsigned stage claims. It shares this exact
// selection/catalog join with the existing held path, without inventing N.
pub(crate) fn validate_original_selection(
    acquisition: &AcquisitionRecordV1,
    catalog: &CatalogHeadRecordV1,
    root: &AcquireSourceRequestV1,
    claims: &StorageZfsHoldTransportRequestV1,
) -> Result<(), LedgerFormatErrorV1> {
    let (resource, _) = claims
        .catalog()
        .select_under_head(
            acquisition.catalog_generation,
            acquisition.catalog_digest,
            acquisition.resource_namespace_digest,
            claims.selection().0,
        )
        .map_err(|_| corrupt("held exact native catalog selection"))?;
    if (
        acquisition.resource_id,
        acquisition.resource_generation,
        acquisition.resource_digest,
        acquisition.selection_generation,
        acquisition.selection_digest,
    ) != (
        resource.resource_id(),
        resource.resource_generation(),
        resource.resource_digest(),
        resource.selection_generation(),
        resource.selection_digest(),
    ) {
        return Err(corrupt("held original selected resource"));
    }
    if let Some(native) = root.native_catalog() {
        if native.resource_namespace_digest() != catalog.resource_namespace_digest
            || native.head() != (catalog.catalog_generation, catalog.catalog_digest)
            || native.floor() != (catalog.catalog_floor_generation, catalog.catalog_floor_digest)
            || native.current_head_commitment() != catalog_commitment(catalog)
            || native.canonical_publication_digest() != publication_digest(catalog)
            || claims.selection().1 != catalog_commitment(catalog)
        {
            return Err(corrupt("held original seven catalog claims"));
        }
    }
    Ok(())
}

fn catalog_commitment(value: &CatalogHeadRecordV1) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.source-provider.current-catalog-publication-head.v1\0")
            .chain_update(format::encode_catalog(value))
            .finalize()
            .into(),
    )
}

fn publication_digest(value: &CatalogHeadRecordV1) -> ObjectDigest {
    ObjectDigest::from_bytes(Sha256::digest(&value.canonical_publication).into())
}

pub(super) fn validate_prepared_witness(
    control: &PreparedNativeHeldControlV1,
    before: &Records,
    record: &Record,
    challenge: Option<&[u8]>,
) -> Result<(), LedgerFormatErrorV1> {
    let Some(bytes) = control.section(Tag::Witness) else {
        return Ok(());
    };
    let NativeHeldOwnerWitnessV1::Provider(witness) =
        NativeHeldOwnerWitnessV1::from_canonical_bytes(Owner::Provider, bytes)
            .map_err(super::schema_error)?
    else {
        return Err(corrupt("held concrete Source witness"));
    };
    let rows = Companions::read(before, record)?;
    validate_witness_fields(&witness, &rows)?;
    let families = [
        Family::ProviderAuthority,
        Family::ProviderAttempt,
        Family::ProviderAcquisition,
        Family::ProviderHolder,
        Family::ProviderHistory,
        Family::ProviderNative,
    ];
    for ((family, key), actual) in families
        .into_iter()
        .zip(rows.keys)
        .zip(&witness.records[..6])
    {
        let bytes = before
            .get(&key)
            .ok_or(corrupt("held witness before row missing"))?;
        require_witness(actual, family, &key, Some(bytes))?;
    }
    require_witness(
        &witness.records[6],
        Family::Challenge,
        &challenge_key(record),
        challenge,
    )
}

fn validate_witness_fields(
    witness: &ProviderNativeHeldWitnessV1,
    rows: &Companions,
) -> Result<(), LedgerFormatErrorV1> {
    if witness.authority != rows.authority.provider
        || witness.native_namespace != rows.catalog.resource_namespace_digest
        || (witness.catalog_head.generation, witness.catalog_head.digest)
            != (rows.catalog.catalog_generation, rows.catalog.catalog_digest)
        || (
            witness.catalog_floor.generation,
            witness.catalog_floor.digest,
        ) != (
            rows.catalog.catalog_floor_generation,
            rows.catalog.catalog_floor_digest,
        )
        || witness.head_commitment != catalog_commitment(&rows.catalog)
        || witness.publication != publication_digest(&rows.catalog)
    {
        return Err(corrupt("held witness actual catalog fields"));
    }
    Ok(())
}

pub(super) fn require_witness(
    witness: &NativeHeldByteWitnessV1,
    family: Family,
    key: &[u8],
    value: Option<&[u8]>,
) -> Result<(), LedgerFormatErrorV1> {
    let digest = value
        .map(|value| {
            native_held_record_byte_digest_v1(family, key, value).map_err(super::schema_error)
        })
        .transpose()?
        .unwrap_or(ObjectDigest::from_bytes([0; 32]));
    if witness.family() != family || witness.key() != key || witness.digest() != digest {
        return Err(corrupt("held witness exact canonical before value"));
    }
    Ok(())
}

pub(crate) fn challenge_key(record: &Record) -> Vec<u8> {
    [b"AOSZHK01".as_slice(), &record.original.challenge].concat()
}

pub(crate) fn validate_challenge(
    record: &Record,
    bytes: Option<&[u8]>,
    spent: bool,
) -> Result<(), LedgerFormatErrorV1> {
    let bytes = bytes.ok_or(corrupt("held original challenge row missing"))?;
    let original = &record.original;
    if original.challenge_issued_seconds <= 0
        || original
            .challenge_valid_until_seconds
            .checked_sub(original.challenge_issued_seconds)
            .is_none_or(|remaining| !(1..=60).contains(&remaining))
    {
        return Err(corrupt("held original challenge lifetime"));
    }
    // Comparison of the existing exact 296-byte value is intentionally local:
    // this does not open, write or fabricate the separate physical journal.
    let mut expected = b"AOSZHC01".to_vec();
    expected.extend_from_slice(&1_u16.to_be_bytes());
    expected.extend_from_slice(&[0; 6]);
    expected.extend_from_slice(&original.challenge);
    expected.extend_from_slice(&original.provider_id);
    expected.extend_from_slice(&original.holder_id);
    for digest in [
        original.session_binding,
        original.attempt_digest,
        original.acquisition_id,
        original.binding_digest,
        original.publication_head,
    ] {
        expected.extend_from_slice(digest.as_bytes());
    }
    expected.extend_from_slice(&original.challenge_issued_seconds.to_be_bytes());
    expected.extend_from_slice(&original.challenge_valid_until_seconds.to_be_bytes());
    expected.push(if spent { 2 } else { 1 });
    expected.extend_from_slice(&[0; 7]);
    expected.extend_from_slice(if spent {
        original.receipt_digest.as_bytes()
    } else {
        &[0; 32]
    });
    if bytes != expected || (spent && original.receipt_digest.as_bytes() == &[0; 32]) {
        return Err(corrupt("held original challenge issue/spend bytes"));
    }
    Ok(())
}
