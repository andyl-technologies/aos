//! Pure original Source Applying/Requested classification and exact owner joins.
//!
//! Complete canonical owner graphs and explicit PUT lists are comparison DATA.
//! They establish neither protected configuration origin, physical admission,
//! current signatures, a live clock, floor geometry, nor dispatch permission.
//! Requested reuses the existing held8 reducer; this module owns no new carrier.

use std::collections::{BTreeMap, BTreeSet};

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    SignedSourceProviderRequestV1, SourceProviderAuthorityV1, decode_acquire_request,
    native_held_completion::{
        NativeHeldControlKindV1,
        witness::native_held_record_byte_digest_v1,
    },
};

use super::pre_requested_cold::OriginalSourcePreRequestedRetirementV1;
use super::{NativeAcquireCompletionStateV2, OriginalSourceProvenanceV5};
use crate::ledger::{
    LedgerFormatErrorV1, format,
    model::{
        AcquisitionRecordV1, AttemptRecordV1, AuthorityHeadRecordV1, CatalogHeadRecordV1,
        DecodedRecordV1, HolderSessionHeadRecordV1, ProviderAcquisitionStateV1,
        ProviderAuthorityStateV1,
    },
    native_held_completion::{
        SourceNativeHeldCompletionRecordV1, SourceNativeHeldMutationV1, SourceNativeHeldStepV1,
        graph, propose_native_held_transition_v1, transition,
    },
};

type Records = BTreeMap<Vec<u8>, Vec<u8>>;

/// Names only the two original prefixes covered by this DATA leaf.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginalSourceOwnerPrefixV5 {
    /// The original four owners exist; the native carrier is absent.
    Applying,
    /// Existing held8 retains original Root1 and exact signedN at phase0.
    Requested,
}

/// Describes exact original owner bindings without a protected authority seal.
///
/// Fields are ordinary comparison DATA, including configuration and prefix.
/// A future writer must rederive them from its complete actual owner graph and
/// separately prove all physical membership, floor geometry and live custody.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginalSourceOwnerDataV5 {
    /// Names the classified original Applying or Requested prefix.
    pub prefix: OriginalSourceOwnerPrefixV5,
    /// Retains the complete original Provider authority claim.
    pub provider: SourceProviderAuthorityV1,
    /// Retains the complete original holder authority claim.
    pub holder: SourceProviderAuthorityV1,
    /// Names the original acquisition, never a replacement lineage.
    pub acquisition_id: ObjectDigest,
    /// Names the exact original Applying effect operation.
    pub operation_id: [u8; 16],
    /// Uses Ledger record_digest of actual original Applying bytes.
    pub reservation_acquisition_digest: ObjectDigest,
    /// Commits the actual original Reserved Attempt artifact.
    pub attempt_digest: ObjectDigest,
    /// Commits the exact original signed V3 Root Acquire.
    pub root_request_digest: ObjectDigest,
    /// Names the unchanged original current holder session.
    pub session_binding: ObjectDigest,
    /// Commits the exact signed original RootPrepared archive.
    pub root_prepared_digest: ObjectDigest,
    /// Retains the explicitly compared configuration DATA commitment.
    pub configuration_digest: ObjectDigest,
    /// Names the actual selected original catalog head.
    pub catalog_head: (u64, ObjectDigest),
    /// Names the selected current resource namespace.
    pub resource_namespace_digest: ObjectDigest,
    /// Retains the independently checked dispatch backend identity.
    pub backend_id: [u8; 32],
    /// Retains the exact original AcquirePlan lineage commitment.
    pub backend_lineage_digest: ObjectDigest,
    /// Commits the actual original normalized Acquire intent.
    pub normalized_intent_digest: ObjectDigest,
    /// Commits exact signedN only at Requested; absence is not a no-escape proof.
    pub native_request_digest: Option<ObjectDigest>,
}

/// Retains a bounded exact owner-only proposal as nonauthorizing DATA.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginalSourceOwnerTransactionV5 {
    data: OriginalSourceOwnerDataV5,
    mutations: Vec<SourceNativeHeldMutationV1>,
}

/// Retains the historical quartet from an accepted exact Applying proposal.
///
/// This comparison seed is DATA. It is never a current owner graph, physical
/// admission receipt or a restored original owner capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginalSourceAdmissionComparisonV5 {
    data: OriginalSourceOwnerDataV5,
    quartet: [SourceNativeHeldMutationV1; 4],
}

impl OriginalSourceAdmissionComparisonV5 {
    /// Borrows the accepted original immutable binding comparison DATA.
    #[must_use]
    pub const fn original(&self) -> &OriginalSourceOwnerDataV5 {
        &self.data
    }

    pub(crate) fn quartet(&self) -> &[SourceNativeHeldMutationV1; 4] {
        &self.quartet
    }
}

impl OriginalSourceOwnerTransactionV5 {
    /// Borrows derived original comparison DATA, not protected admission.
    #[must_use]
    pub const fn data(&self) -> &OriginalSourceOwnerDataV5 {
        &self.data
    }

    /// Borrows exact canonical owner mutations in sorted key order.
    #[must_use]
    pub fn mutations(&self) -> &[SourceNativeHeldMutationV1] {
        &self.mutations
    }

    /// Copies the bounded historical quartet only from an exact Applying proposal.
    ///
    /// # Errors
    ///
    /// Rejects a Requested proposal or an impossible Applying mutation shape.
    pub fn admission_comparison(
        &self,
    ) -> Result<OriginalSourceAdmissionComparisonV5, LedgerFormatErrorV1> {
        if self.data.prefix != OriginalSourceOwnerPrefixV5::Applying {
            return Err(corrupt(
                "original Source comparison requires accepted Applying",
            ));
        }

        let quartet = self
            .mutations
            .clone()
            .try_into()
            .map_err(|_| corrupt("original Source comparison quartet"))?;
        Ok(OriginalSourceAdmissionComparisonV5 {
            data: self.data.clone(),
            quartet,
        })
    }
}

/// Classifies the complete owner graph's exact original Applying/Requested DATA.
///
/// The caller supplies every namespace41 owner row and an expected configuration
/// commitment as DATA. No floor accounting, physical membership, authentication,
/// currentness or hot owner capability is returned.
///
/// # Errors
///
/// Rejects malformed or disconnected complete graphs, changed original witnesses,
/// configuration/authority/catalog/Session joins, non-dispatch lineage, or any
/// native profile or phase other than exact initial held8 Requested.
pub fn classify_original_source_owner_v5<'record>(
    records: impl IntoIterator<Item = (&'record [u8], &'record [u8])>,
    provenance: &OriginalSourceProvenanceV5,
    configuration: ObjectDigest,
) -> Result<OriginalSourceOwnerDataV5, LedgerFormatErrorV1> {
    let records = crate::collect_bounded_records(records)?;
    classify(&records, provenance, configuration).map(|(_, data)| data)
}

/// Checks exactly four original Applying owner PUTs against the complete before graph.
///
/// Proposed changes remain explicit so duplicate, redundant and deleting writes
/// cannot disappear into a materialized map. The result contains no floor row or
/// physical admission proof; its four original witnesses describe post-join DATA.
///
/// # Errors
///
/// Rejects wrong/missing/duplicate/noop PUTs, deletion or foreign keys, reused
/// Attempt/acquisition/native identity, replaced or occupied Session, discontinuous
/// counters/projection, invalid graphs or owner transaction bounds.
pub fn propose_original_source_applying_v5<'record, 'change>(
    before: impl IntoIterator<Item = (&'record [u8], &'record [u8])>,
    changes: impl IntoIterator<Item = (&'change [u8], Option<&'change [u8]>)>,
    provenance: &OriginalSourceProvenanceV5,
    configuration: ObjectDigest,
) -> Result<OriginalSourceOwnerTransactionV5, LedgerFormatErrorV1> {
    let before = crate::collect_bounded_records(before)?;
    crate::validate_current_records(&before)?;

    let keys = original_keys(provenance);
    let expected = keys.iter().cloned().collect();
    let after = apply_exact_puts(&before, changes, &expected)?;
    let (rows, data) = classify(&after, provenance, configuration)?;

    if data.prefix != OriginalSourceOwnerPrefixV5::Applying
        || before.contains_key(&keys[0])
        || before.contains_key(&keys[1])
        || before.contains_key(&super::native_completion_key_v2(data.acquisition_id))
    {
        return Err(corrupt("original Source Applying identity was not absent"));
    }

    validate_reservation_head(&before, &rows, &keys)?;
    crate::validate_transition_structure(&before, &after)?;
    let mutations = transition::exact_mutations(&before, &after, &expected)?;

    Ok(OriginalSourceOwnerTransactionV5 { data, mutations })
}

/// Checks exactly one original Requested held8 PUT using the existing full reducer.
///
/// SignedN, Root1, original Applying and all four original owner bytes remain
/// exact. This DATA join cannot authorize N signing, challenge issuance, physical
/// floor transfer, journal commit or Storage dispatch.
///
/// # Errors
///
/// Rejects anything but original Applying to initial Requested, a changed archive,
/// stage/clock/signer/owner binding, duplicate/noop/deleting/foreign writes, or a
/// failed existing native-held Requested reducer/admission comparison.
pub fn propose_original_source_requested_v5<'record, 'change>(
    before: impl IntoIterator<Item = (&'record [u8], &'record [u8])>,
    changes: impl IntoIterator<Item = (&'change [u8], Option<&'change [u8]>)>,
    provenance: &OriginalSourceProvenanceV5,
    configuration: ObjectDigest,
) -> Result<OriginalSourceOwnerTransactionV5, LedgerFormatErrorV1> {
    let before = crate::collect_bounded_records(before)?;
    let (_, original) = classify(&before, provenance, configuration)?;
    if original.prefix != OriginalSourceOwnerPrefixV5::Applying {
        return Err(corrupt("original Source Requested before prefix"));
    }

    let key = super::native_completion_key_v2(original.acquisition_id);
    let expected = BTreeSet::from([key]);
    let after = apply_exact_puts(&before, changes, &expected)?;
    let (_, data) = classify(&after, provenance, configuration)?;
    if data.prefix != OriginalSourceOwnerPrefixV5::Requested {
        return Err(corrupt("original Source Requested after prefix"));
    }

    let proposed = propose_native_held_transition_v1(
        record_views(&before),
        record_views(&after),
        data.acquisition_id,
        SourceNativeHeldStepV1::Requested,
        None,
    )?;
    let admission = proposed
        .admission()
        .ok_or(corrupt("original Source Requested admission DATA"))?;

    if admission.provider() != &data.provider
        || admission.holder() != &data.holder
        || admission.acquisition_id() != data.acquisition_id
        || admission.operation_id() != data.operation_id
        || admission.reservation_acquisition_digest() != data.reservation_acquisition_digest
        || admission.attempt_digest() != data.attempt_digest
        || admission.root_request_digest() != data.root_request_digest
        || admission.session_binding() != data.session_binding
        || Some(admission.native_request_digest()) != data.native_request_digest
        || admission.root_prepared_digest() != data.root_prepared_digest
        || admission.catalog_head() != data.catalog_head
        || admission.resource_namespace_digest() != data.resource_namespace_digest
        || admission.backend_id() != data.backend_id
        || admission.backend_lineage_digest() != data.backend_lineage_digest
        || admission.normalized_intent_digest() != data.normalized_intent_digest
    {
        return Err(corrupt("original Source Requested derived binding"));
    }

    Ok(OriginalSourceOwnerTransactionV5 {
        data,
        mutations: proposed.mutations().to_vec(),
    })
}

struct OriginalRows {
    attempt: AttemptRecordV1,
    acquisition: AcquisitionRecordV1,
    holder: HolderSessionHeadRecordV1,
    authority: AuthorityHeadRecordV1,
    catalog: CatalogHeadRecordV1,
}

/// Derives only the four original retirement candidate PUTs as comparison DATA.
///
/// The semantic Attempt, Acquisition, Holder and History order permits the
/// existing Source transaction-identity preparation before the closure embeds
/// that identity. The quartet alone is not a valid prospective Faulted graph.
///
/// # Errors
///
/// Rejects any before graph other than exact original Applying, changed
/// provenance/configuration, exhausted revisions or invalid mutation bounds.
pub fn derive_original_source_pre_requested_retirement_v1<'record>(
    before: impl IntoIterator<Item = (&'record [u8], &'record [u8])>,
    provenance: &OriginalSourceProvenanceV5,
    configuration: ObjectDigest,
) -> Result<OriginalSourcePreRequestedRetirementV1, LedgerFormatErrorV1> {
    let before = crate::collect_bounded_records(before)?;
    let (rows, original) = classify(&before, provenance, configuration)?;
    if original.prefix != OriginalSourceOwnerPrefixV5::Applying {
        return Err(corrupt("original Source retirement requires Applying"));
    }

    let keys = original_keys(provenance);
    let values = graph::retire_pending_quartet(&rows.attempt, &rows.acquisition, &rows.holder)?;
    let mut candidates = before.clone();
    for (key, value) in keys.iter().zip(values) {
        candidates.insert(key.clone(), value);
    }

    let expected = keys.iter().cloned().collect();
    let mutations = transition::exact_mutations(&before, &candidates, &expected)?;
    let semantic: Vec<_> = keys
        .iter()
        .map(|key| {
            mutations
                .iter()
                .find(|mutation| mutation.key() == key.as_slice())
                .cloned()
                .ok_or(corrupt("original Source retirement quartet"))
        })
        .collect::<Result<_, _>>()?;
    let semantic = semantic
        .try_into()
        .map_err(|_| corrupt("original Source retirement quartet width"))?;

    Ok(OriginalSourcePreRequestedRetirementV1::from_parts(
        original, semantic,
    ))
}

fn classify(
    records: &Records,
    provenance: &OriginalSourceProvenanceV5,
    configuration: ObjectDigest,
) -> Result<(OriginalRows, OriginalSourceOwnerDataV5), LedgerFormatErrorV1> {
    // Validate every canonical row before selecting this original identity.
    crate::validate_current_records(records)?;

    let data = provenance.claims();
    if configuration.as_bytes() == &[0; 32] || configuration != data.configuration {
        return Err(corrupt("original Source configuration DATA"));
    }

    let keys = original_keys(provenance);
    let rows = read_original_rows(records, &keys)?;
    provenance.validate_original_attempt_claims(&rows.attempt)?;
    for witness in &data.records {
        let bytes = records
            .get(witness.key())
            .ok_or(corrupt("original Source witness row absent"))?;
        let actual = native_held_record_byte_digest_v1(witness.family(), witness.key(), bytes)
            .map_err(|_| corrupt("original Source witness format"))?;
        if witness.digest() != actual {
            return Err(corrupt("original Source witness actual bytes"));
        }
    }

    validate_applying_rows(&rows, provenance)?;
    graph::validate_dispatch(
        &rows.acquisition,
        rows.holder.session_binding,
        rows.attempt.attempt_digest,
    )?;
    let signed = SignedSourceProviderRequestV1::from_canonical_bytes(&rows.attempt.signed_request)
        .map_err(|_| corrupt("original Source Acquire DATA"))?;
    let root = decode_acquire_request(signed.subject())
        .map_err(|_| corrupt("original Source Acquire subject"))?;
    graph::validate_original_selection(&rows.acquisition, &rows.catalog, &root, &data.claims)?;

    let applying_bytes = records
        .get(&keys[1])
        .ok_or(corrupt("original Source Applying bytes"))?;
    let applying_digest = format::record_digest(applying_bytes)?;
    let native_key = super::native_completion_key_v2(rows.acquisition.acquisition_id);
    let (prefix, native_request_digest) = match records.get(&native_key) {
        None => (OriginalSourceOwnerPrefixV5::Applying, None),
        Some(bytes) => {
            let held = SourceNativeHeldCompletionRecordV1::from_canonical_bytes(&native_key, bytes)?;
            validate_requested_archive(&held, &rows, provenance, applying_digest)?;
            (
                OriginalSourceOwnerPrefixV5::Requested,
                Some(held.original().native_request_digest),
            )
        }
    };

    let binding = OriginalSourceOwnerDataV5 {
        prefix,
        provider: rows.acquisition.provider.clone(),
        holder: rows.acquisition.holder.clone(),
        acquisition_id: rows.acquisition.acquisition_id,
        operation_id: rows.acquisition.effect_id,
        reservation_acquisition_digest: applying_digest,
        attempt_digest: rows.attempt.attempt_digest,
        root_request_digest: rows.attempt.signed_request_digest,
        session_binding: rows.holder.session_binding,
        root_prepared_digest: data.root_prepared.digest(),
        configuration_digest: configuration,
        catalog_head: (rows.catalog.catalog_generation, rows.catalog.catalog_digest),
        resource_namespace_digest: rows.catalog.resource_namespace_digest,
        backend_id: rows.acquisition.backend_id,
        backend_lineage_digest: rows.acquisition.backend_lineage_digest,
        normalized_intent_digest: rows.acquisition.normalized_intent.digest(),
        native_request_digest,
    };

    Ok((rows, binding))
}

fn read_original_rows(
    records: &Records,
    keys: &[Vec<u8>; 4],
) -> Result<OriginalRows, LedgerFormatErrorV1> {
    let decode = |key: &[u8]| {
        let bytes = records
            .get(key)
            .ok_or(corrupt("original Source owner absent"))?;
        format::decode_record(key, bytes)
    };
    let DecodedRecordV1::Attempt(attempt) = decode(&keys[0])? else {
        return Err(corrupt("original Source Attempt kind"));
    };
    let DecodedRecordV1::Acquisition(acquisition) = decode(&keys[1])? else {
        return Err(corrupt("original Source Applying kind"));
    };
    let DecodedRecordV1::Session(holder) = decode(&keys[2])? else {
        return Err(corrupt("original Source Holder kind"));
    };
    let DecodedRecordV1::SessionHistory(history) = decode(&keys[3])? else {
        return Err(corrupt("original Source History kind"));
    };
    if history != holder {
        return Err(corrupt("original Source current History"));
    }

    let authority_key = format::authority_key(acquisition.provider.authority_id());
    let catalog_key = format::catalog_key(
        acquisition.provider.authority_id(),
        acquisition.catalog_generation,
    );
    let DecodedRecordV1::Authority(authority) = decode(&authority_key)? else {
        return Err(corrupt("original Source authority kind"));
    };
    let DecodedRecordV1::Catalog(catalog) = decode(&catalog_key)? else {
        return Err(corrupt("original Source catalog kind"));
    };

    Ok(OriginalRows {
        attempt,
        acquisition,
        holder,
        authority,
        catalog,
    })
}

fn validate_applying_rows(
    rows: &OriginalRows,
    provenance: &OriginalSourceProvenanceV5,
) -> Result<(), LedgerFormatErrorV1> {
    let acquisition = &rows.acquisition;
    let attempt = &rows.attempt;
    let holder = &rows.holder;
    let authority = &rows.authority;
    let catalog = &rows.catalog;
    let signed = SignedSourceProviderRequestV1::from_canonical_bytes(&attempt.signed_request)
        .map_err(|_| corrupt("original Source signed Acquire"))?;
    let root = decode_acquire_request(signed.subject())
        .map_err(|_| corrupt("original Source Acquire"))?;
    // Holder retains process identity, not node identity. The signed subject
    // supplies node DATA; a future owner still verifies its protected origin.
    let projected_intent = crate::NormalizedAcquisitionIntentV1::from_original_acquire_request(
        &root,
        holder.provider.clone(),
        holder.holder.clone(),
        root.node_id(),
        holder.boot_id,
        holder.route_id,
        holder.route_generation,
        holder.route_digest,
        holder.resource_namespace_digest,
        holder.revocation_generation,
        holder.revocation_digest,
    )
    .map_err(|_| corrupt("original Source current intent projection"))?;

    if acquisition.revision != 1
        || acquisition.state != ProviderAcquisitionStateV1::Applying
        || acquisition.current_attempt_digest != attempt.attempt_digest
        || acquisition.effect_attempt_digest != attempt.attempt_digest
        || acquisition.lease_id.is_some()
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
        || acquisition.normalized_intent != projected_intent
        || attempt.recovery_predecessor_attempt_digest.is_some()
        || holder.revision < 2
        || holder.provider != acquisition.provider
        || holder.holder != acquisition.holder
        || holder.session_binding != attempt.session_binding
        || holder.pending_attempt_digest != Some(attempt.attempt_digest)
        || holder.next_request_sequence != next_sequence(attempt.request_sequence)?
        || holder.next_acquisition_sequence != next_sequence(attempt.acquisition_sequence)?
        || holder.boot_id != provenance.claims().initial.host_boot_id()
        || holder.root_process_instance != attempt.root_process_instance
        || holder.provider_process_instance != attempt.provider_process_instance
        || holder.signer_set_commitment != attempt.signer_set_commitment
        || authority.state != ProviderAuthorityStateV1::Active
        || authority.provider != acquisition.provider
        || authority.provider_hello_signer != holder.signers[2]
        || authority.provider_outcome_signer != holder.signers[3]
        || authority.catalog_generation != catalog.catalog_generation
        || authority.catalog_digest != catalog.catalog_digest
        || authority.resource_namespace_digest != catalog.resource_namespace_digest
        || catalog.provider != acquisition.provider
        || catalog.resource_namespace_digest != acquisition.resource_namespace_digest
        || catalog.catalog_digest != acquisition.catalog_digest
        || holder.resource_namespace_digest != catalog.resource_namespace_digest
        || holder.route_id != authority.route_id
        || holder.route_generation != authority.route_generation
        || holder.route_digest != authority.route_digest
        || holder.trust_generation != authority.trust_generation
        || holder.trust_digest != authority.trust_digest
        || holder.revocation_generation != authority.revocation_generation
        || holder.revocation_digest != authority.revocation_digest
        || attempt.proof_class_capabilities != authority.proof_class_capabilities
        || attempt.supports_recursive != authority.supports_recursive
        || attempt.supports_kernel_coupled != authority.supports_kernel_coupled
        || attempt.verified_at_seconds < authority.valid_from_seconds
        || attempt.current_valid_until_seconds > authority.valid_until_seconds
    {
        return Err(corrupt("original Source exact Applying/current projection"));
    }

    Ok(())
}

fn validate_requested_archive(
    held: &SourceNativeHeldCompletionRecordV1,
    rows: &OriginalRows,
    provenance: &OriginalSourceProvenanceV5,
    applying_digest: ObjectDigest,
) -> Result<(), LedgerFormatErrorV1> {
    let original = held.original();
    let data = provenance.claims();
    let signed = original
        .canonical_request
        .as_ref()
        .ok_or(corrupt("original Source signedN absent"))?;
    let clock = original
        .original_clock
        .ok_or(corrupt("original Source Requested clock absent"))?;

    if original.revision != 1
        || original.state != NativeAcquireCompletionStateV2::Requested
        || held.suffix().phase() != 0
        || held.suffix().prepared().is_some()
        || held.suffix().controls() != [data.root_prepared.clone()]
        || held.suffix().controls()[0].kind() != NativeHeldControlKindV1::RootPrepared
        || signed.request().claims() != &data.claims
        || signed.request().signed_root_request().to_canonical_bytes() != rows.attempt.signed_request
        || signed.signer() != &rows.holder.signers[3]
        || original.reservation_acquisition_digest != Some(applying_digest)
        || clock.initial() != data.initial
        || clock.deadline() != data.narrowed_deadline
    {
        return Err(corrupt("original Source exact Requested archive"));
    }

    Ok(())
}

fn validate_reservation_head(
    before: &Records,
    rows: &OriginalRows,
    keys: &[Vec<u8>; 4],
) -> Result<(), LedgerFormatErrorV1> {
    let after = &rows.holder;
    let request = &rows.attempt;

    if let Some(bytes) = before.get(&keys[2]) {
        let DecodedRecordV1::Session(previous) = format::decode_record(&keys[2], bytes)? else {
            return Err(corrupt("original Source prior Holder kind"));
        };
        if previous.pending_attempt_digest.is_some()
            || previous.session_binding != after.session_binding
            || previous.next_request_sequence != request.request_sequence
            || previous.next_acquisition_sequence > request.acquisition_sequence
        {
            return Err(corrupt("original Source prior idle Session"));
        }

        let mut expected = previous;
        expected.revision = expected
            .revision
            .checked_add(1)
            .ok_or(corrupt("original Source Holder revision"))?;
        expected.next_request_sequence = next_sequence(request.request_sequence)?;
        expected.next_acquisition_sequence = next_sequence(request.acquisition_sequence)?;
        expected.pending_attempt_digest = Some(request.attempt_digest);

        if expected != *after {
            return Err(corrupt("original Source exact reserved Holder"));
        }
    } else {
        if before.contains_key(&keys[3])
            || after.revision != 2
            || after.session_generation != 1
            || after.predecessor_session_binding.is_some()
            || after.supersession_evidence_digest.is_some()
            || after.request_sequence_floor != 1
            || after.response_sequence_floor != 1
            || after.acquisition_sequence_floor != 1
            || after.next_response_sequence != 1
            || after.last_completed_attempt_digest.is_some()
        {
            return Err(corrupt("original Source initial absent Holder"));
        }

        let cold_archives = super::pre_requested_cold::graph::validated_archives(before)?;
        for (key, bytes) in before {
            if cold_archives.contains_key(key) {
                continue;
            }
            if let DecodedRecordV1::SessionHistory(history) = crate::decode_current_record(key, bytes)?
                && history.provider.authority_id() == after.provider.authority_id()
                && history.holder.authority_id() == after.holder.authority_id()
            {
                return Err(corrupt("original Source absent Holder retained another History"));
            }
        }
    }

    Ok(())
}

pub(super) fn apply_exact_puts<'change>(
    before: &Records,
    changes: impl IntoIterator<Item = (&'change [u8], Option<&'change [u8]>)>,
    expected: &BTreeSet<Vec<u8>>,
) -> Result<Records, LedgerFormatErrorV1> {
    let mut puts = BTreeMap::new();
    let mut bytes = 0_usize;

    for (key, value) in changes {
        let value = value.ok_or(corrupt("original Source owner deletion"))?;
        if !expected.contains(key)
            || puts.contains_key(key)
            || before.get(key).is_some_and(|old| old.as_slice() == value)
        {
            return Err(corrupt("original Source extra/duplicate/noop owner PUT"));
        }

        // This is existing Ledger mutation framing, not journal admission or
        // the separate physical floor row's complete transaction geometry.
        bytes = bytes
            .checked_add(9)
            .and_then(|sum| sum.checked_add(key.len()))
            .and_then(|sum| sum.checked_add(value.len()))
            .ok_or(LedgerFormatErrorV1::LimitExceeded(
                "original Source owner transaction bytes",
            ))?;
        if puts.len() >= crate::limits::MAXIMUM_TRANSACTION_RECORDS
            || bytes > crate::limits::MAXIMUM_TRANSACTION_BYTES
        {
            return Err(LedgerFormatErrorV1::LimitExceeded(
                "original Source owner transaction bounds",
            ));
        }

        puts.insert(key.to_vec(), value.to_vec());
    }

    if puts.keys().cloned().collect::<BTreeSet<_>>() != *expected {
        return Err(corrupt("original Source missing owner PUT"));
    }

    let mut after = before.clone();
    after.extend(puts);
    Ok(after)
}

fn original_keys(provenance: &OriginalSourceProvenanceV5) -> [Vec<u8>; 4] {
    provenance
        .claims()
        .records
        .each_ref()
        .map(|witness| witness.key().to_vec())
}

fn record_views(records: &Records) -> impl Iterator<Item = (&[u8], &[u8])> {
    records
        .iter()
        .map(|(key, value)| (key.as_slice(), value.as_slice()))
}

fn next_sequence(value: u64) -> Result<u64, LedgerFormatErrorV1> {
    value
        .checked_add(1)
        .filter(|next| *next != u64::MAX)
        .ok_or(corrupt("original Source sequence exhausted"))
}

fn corrupt(reason: &'static str) -> LedgerFormatErrorV1 {
    LedgerFormatErrorV1::Corrupt(reason)
}
