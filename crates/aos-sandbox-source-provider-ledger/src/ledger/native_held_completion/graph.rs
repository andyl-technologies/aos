//! Exact Source companion keys, complete graph checks and before-image witnesses.

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
    decode_acquire_request,
    native_held_completion::{
        NativeHeldOwnerV1 as Owner, NativeHeldSectionTagV1 as Tag,
        frame::PreparedNativeHeldControlV1,
        witness::{
            NativeHeldByteWitnessV1, NativeHeldOwnerWitnessV1, NativeHeldRecordFamilyV1 as Family,
            ProviderNativeHeldWitnessV1, native_held_record_byte_digest_v1,
        },
    },
    provider_response_artifact_digest_v1,
};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

pub(super) type Records = BTreeMap<Vec<u8>, Vec<u8>>;

/// Checks this explicit held graph without yielding a legacy recovery/admission handle.
///
/// The legacy graph predicates inspect only the unchanged original field
/// projection. Every held witness and mutation comparison uses the real held
/// canonical bytes, not that mechanical projection. Signatures' eligibility,
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

pub(super) fn collect<'a>(
    records: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
) -> Result<Records, LedgerFormatErrorV1> {
    let mut result = Records::new();
    let mut total = 0_usize;
    for (key, value) in records {
        total = total
            .checked_add(8)
            .and_then(|v| v.checked_add(key.len()))
            .and_then(|v| v.checked_add(value.len()))
            .ok_or(LedgerFormatErrorV1::LimitExceeded("held graph bytes"))?;
        if result.len() >= crate::limits::MAXIMUM_LEDGER_RECORDS
            || total > crate::limits::MAXIMUM_LEDGER_GRAPH_BYTES
        {
            return Err(LedgerFormatErrorV1::LimitExceeded("held graph bounds"));
        }
        if result.insert(key.to_vec(), value.to_vec()).is_some() {
            return Err(corrupt("duplicate held graph key"));
        }
    }
    Ok(result)
}

pub(super) fn is_held(value: &[u8]) -> bool {
    value.get(8..10) == Some(8_u16.to_be_bytes().as_slice())
}

pub(super) fn legacy_projection(records: &Records) -> Result<Records, LedgerFormatErrorV1> {
    records
        .iter()
        .map(|(key, bytes)| {
            let value = if is_held(bytes) {
                let held = Record::from_canonical_bytes(key, bytes)?;
                format::encode_native_completion_v2(&held.original)
            } else {
                bytes.clone()
            };
            Ok((key.clone(), value))
        })
        .collect()
}

pub(super) fn validate(records: &Records) -> Result<(), LedgerFormatErrorV1> {
    let projection = legacy_projection(records)?;
    // The returned legacy data graph is deliberately discarded. It cannot be
    // passed to a runtime caller as validation of held-profile admission.
    crate::validate_prospective_records(
        projection.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
    )?;
    for (key, value) in records {
        if is_held(value) {
            let record = Record::from_canonical_bytes(key, value)?;
            let rows = Companions::read(records, &record)?;
            rows.validate(&record)?;
        }
    }
    Ok(())
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
            || self.holder != self.history
            || self.holder.session_binding != original.session_binding
            || self.holder.signers[1] != *signed.request().signed_root_request().signer()
            || self.holder.signers[3] != *signed.signer()
            || self.catalog.provider != self.acquisition.provider
            || self.catalog.resource_namespace_digest != self.acquisition.resource_namespace_digest
            || self.catalog.catalog_digest != self.acquisition.catalog_digest
            || original.publication_head != catalog_commitment(&self.catalog)
        {
            return Err(corrupt("held original dispatch/lineage/session/catalog"));
        }
        original.validate_provider_graph(&self.attempt, &self.acquisition)?;
        let claims = signed.request().claims();
        let catalog = claims.catalog();
        let (resource, _) = catalog
            .select_under_head(
                self.acquisition.catalog_generation,
                self.acquisition.catalog_digest,
                self.acquisition.resource_namespace_digest,
                original.binding_digest,
            )
            .map_err(|_| corrupt("held exact native catalog selection"))?;
        if (
            self.acquisition.resource_id,
            self.acquisition.resource_generation,
            self.acquisition.resource_digest,
            self.acquisition.selection_generation,
            self.acquisition.selection_digest,
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
            if native.resource_namespace_digest() != self.catalog.resource_namespace_digest
                || native.head() != (self.catalog.catalog_generation, self.catalog.catalog_digest)
                || native.floor()
                    != (
                        self.catalog.catalog_floor_generation,
                        self.catalog.catalog_floor_digest,
                    )
                || native.current_head_commitment() != catalog_commitment(&self.catalog)
                || native.canonical_publication_digest() != publication_digest(&self.catalog)
                || original.publication_head != catalog_commitment(&self.catalog)
            {
                return Err(corrupt("held original seven catalog claims"));
            }
        }
        let actual_artifact =
            if original.state == native_completion::NativeAcquireCompletionStateV2::Active {
                // Cold recovery can discard unescaped3, never the original Complete
                // rows. Derive A here even when the intermediate suffix has no A field.
                provider_response_artifact_digest_v1(
                    self.attempt.method,
                    &self.attempt.completed_response,
                )
            } else {
                ObjectDigest::from_bytes([0; 32])
            };
        let claimed_artifact = evidence::artifact(record)?;
        if claimed_artifact.as_bytes() != &[0; 32] && claimed_artifact != actual_artifact {
            return Err(corrupt("held exact completed response artifact"));
        }
        Ok(())
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

pub(super) fn validate_dispatch(
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

pub(super) fn challenge_key(record: &Record) -> Vec<u8> {
    [b"AOSZHK01".as_slice(), &record.original.challenge].concat()
}

pub(super) fn validate_challenge(
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
