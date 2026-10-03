//! Shared pure Source ordinary-capacity bindings and complete owner obligations.
//!
//! This module owns actual canonical owner eligibility, not Journal floor codecs,
//! framing, protected configuration, signature trust or funding capabilities.
//! Complete union adapters must independently match every returned obligation.

use std::collections::{BTreeMap, BTreeSet};

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use super::{
    LedgerFormatErrorV1, format,
    model::*,
    native_completion::{
        self, NativeAcquireCompletionRecordV2, NativeAcquireCompletionStateV2,
        OriginalSourceAdmissionComparisonV5, OriginalSourceProvenanceV5,
        SourcePreRequestedColdArchiveV1,
        release_fence::{
            NativeReleaseStatusCapacityBindingV1, native_release_status_capacity_binding_v1,
            native_release_status_is_completed_v1,
        },
    },
    native_held_completion::{
        OriginalSourceContinuationDataV5, SourceNativeHeldCompletionRecordV1,
        derive_original_source_continuations_v5, native_held_release_status_binding_v1,
        validate_original_source_admission_provenance_v5,
        validate_original_source_current_origin_v5,
    },
};

mod original;
pub use original::{
    OriginalSourceChallengeDataV5, OriginalSourceRetirementComparisonV5,
    SourceCapacityOwnerEdgeDataV5, SourceCapacityOwnerEdgeKindV5,
    compare_original_source_capacity_owner_edge_v5,
    validate_original_source_challenge_data_bounds_v5,
};

/// Names the existing ordinary Source obligation, independently of its floor codec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceOrdinaryCapacityKindV1 {
    /// Retains the five-record proofless Applying terminal obligation.
    NoDispatchAcquire,
    /// Retains original Acquire cleanup until genuine Released/Tombstone.
    LegacyDispatchAcquire,
    /// Retains separate descriptor-free native Release status.
    NativeReleaseStatus,
}

/// Contains ordinary nonauthorizing six-field owner binding DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceCapacityBindingFieldsV1 {
    /// Contains the existing domain-separated owner identity.
    pub owner_id: [u8; 32],
    /// Commits the exact purpose-specific original owner value.
    pub owner_digest: ObjectDigest,
    /// Names the actual Acquire or Release effect.
    pub operation_id: [u8; 16],
    /// Names the actual request's Attempt.
    pub artifact_digest: ObjectDigest,
    /// Names that Attempt's exact signed Root request.
    pub checkpoint_digest: ObjectDigest,
    /// Names that request's original Session history.
    pub chain_head_digest: ObjectDigest,
}

/// Retains a derived ordinary obligation without a public constructor or grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceOrdinaryCapacityBindingV1 {
    kind: SourceOrdinaryCapacityKindV1,
    acquisition: ObjectDigest,
    fields: SourceCapacityBindingFieldsV1,
}

impl SourceOrdinaryCapacityBindingV1 {
    /// Returns the unchanged ordinary policy family.
    #[must_use]
    pub const fn kind(&self) -> SourceOrdinaryCapacityKindV1 {
        self.kind
    }

    /// Returns the actual acquisition that owns this obligation.
    #[must_use]
    pub const fn acquisition(&self) -> ObjectDigest {
        self.acquisition
    }

    /// Returns comparison fields, never a protected recovery binding or grant.
    #[must_use]
    pub const fn fields(&self) -> SourceCapacityBindingFieldsV1 {
        self.fields
    }
}

/// Borrows untrusted original comparison inputs, never an owner exclusion list.
#[derive(Clone, Copy)]
pub struct OriginalSourceOwnerOriginInputV5<'a> {
    /// Borrows a quartet copied only by an exact Applying proposer.
    pub comparison: &'a OriginalSourceAdmissionComparisonV5,
    /// Borrows immutable provenance independently joined to current owner bytes.
    pub provenance: &'a OriginalSourceProvenanceV5,
    /// Borrows an exact final-edge comparison if own debt was already retired.
    pub retirement: Option<&'a OriginalSourceRetirementComparisonV5>,
}

/// Names an actual canonical nonlegacy carrier in the complete owner cut.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceCapacityProfileV1 {
    /// Contains the complete actual held carrier.
    Held(SourceNativeHeldCompletionRecordV1),
    /// Contains the distinct validated pre-Requested closure archive.
    PreRequestedCold(SourcePreRequestedColdArchiveV1),
}

/// Retains the complete validated owner cut and every actual ordinary obligation.
pub struct SourceCapacityOwnerDataV1 {
    records: BTreeMap<Vec<u8>, Vec<u8>>,
    graph_digest: ObjectDigest,
    ordinary: Vec<SourceOrdinaryCapacityBindingV1>,
    profiles: BTreeMap<ObjectDigest, SourceCapacityProfileV1>,
    profile_owner_ids: BTreeMap<ObjectDigest, [u8; 32]>,
    originals: BTreeMap<ObjectDigest, OriginalSourceContinuationDataV5>,
    retired: BTreeMap<ObjectDigest, OriginalSourceRetirementComparisonV5>,
}

impl SourceCapacityOwnerDataV1 {
    /// Borrows all canonical current rows, not just selected-owner companions.
    pub fn records(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        views(&self.records)
    }

    /// Returns the complete canonical graph commitment.
    #[must_use]
    pub const fn graph_digest(&self) -> ObjectDigest {
        self.graph_digest
    }

    /// Borrows all ordinary obligations that require actual floors.
    #[must_use]
    pub fn ordinary_bindings(&self) -> &[SourceOrdinaryCapacityBindingV1] {
        &self.ordinary
    }

    /// Borrows every actual held or cold profile.
    pub fn profiles(&self) -> impl Iterator<Item = (&ObjectDigest, &SourceCapacityProfileV1)> {
        self.profiles.iter()
    }

    /// Returns the existing dispatch-domain identity of an actual profile owner.
    #[must_use]
    pub fn profile_owner_id(&self, acquisition: ObjectDigest) -> Option<[u8; 32]> {
        self.profile_owner_ids.get(&acquisition).copied()
    }

    /// Borrows complete reducer-derived continuation DATA for each original owner.
    pub fn originals(
        &self,
    ) -> impl Iterator<Item = (&ObjectDigest, &OriginalSourceContinuationDataV5)> {
        self.originals.iter()
    }

    /// Reports only a retained exact final-edge comparison, not current custody.
    #[must_use]
    pub fn retirement(
        &self,
        acquisition: ObjectDigest,
    ) -> Option<&OriginalSourceRetirementComparisonV5> {
        self.retired.get(&acquisition)
    }

    /// Reports real original origins, including retained retired lineages.
    #[must_use]
    pub fn is_original(&self, acquisition: ObjectDigest) -> bool {
        self.originals.contains_key(&acquisition) || self.retired.contains_key(&acquisition)
    }

    /// Borrows exact retained retired origins without requiring future forecasts.
    pub fn retired_originals(
        &self,
    ) -> impl Iterator<Item = (&ObjectDigest, &OriginalSourceRetirementComparisonV5)> {
        self.retired.iter()
    }
}

/// Derives the unchanged native Acquire ordinary binding from actual owner rows.
///
/// This helper is shared by legacy Source request production and complete union
/// derivation. It does not authenticate the surrounding graph or a physical floor.
///
/// # Errors
///
/// Rejects nonnative or foreign lineage, an ineligible Applying/native phase,
/// changed original Attempt/history, or a missing original reservation digest.
pub fn derive_native_acquire_ordinary_binding_v1(
    acquisition: &AcquisitionRecordV1,
    attempt: &AttemptRecordV1,
    session: &HolderSessionHeadRecordV1,
    native: Option<&NativeAcquireCompletionRecordV2>,
) -> Result<SourceOrdinaryCapacityBindingV1, LedgerFormatErrorV1> {
    let dispatch = is_dispatch(acquisition);
    let phase_matches = if dispatch && native.is_some() {
        native.is_some_and(|record| {
            record.canonical_request.is_some()
                && record.validate_provider_graph(attempt, acquisition).is_ok()
        })
    } else {
        acquisition.state == ProviderAcquisitionStateV1::Applying
            && attempt.state == ProviderAttemptStateV1::Reserved
            && session.pending_attempt_digest == Some(attempt.attempt_digest)
    };
    if !phase_matches
        || (!is_no_dispatch(acquisition) && !dispatch)
        || ((!dispatch || native.is_none())
            && acquisition.current_attempt_digest != attempt.attempt_digest)
        || acquisition.effect_attempt_digest != attempt.attempt_digest
        || session.session_binding != attempt.session_binding
        || acquisition.provider != attempt.provider
        || acquisition.holder != attempt.holder
        || session.provider != attempt.provider
        || session.holder != attempt.holder
    {
        return Err(corrupt("native capacity equivocation"));
    }

    let kind = if dispatch {
        SourceOrdinaryCapacityKindV1::LegacyDispatchAcquire
    } else {
        SourceOrdinaryCapacityKindV1::NoDispatchAcquire
    };
    let owner_digest = match native {
        Some(record) if dispatch => record
            .reservation_acquisition_digest
            .ok_or(corrupt("native original capacity digest"))?,
        _ => format::record_digest(&format::encode_acquisition(acquisition))?,
    };
    let fields = SourceCapacityBindingFieldsV1 {
        owner_id: acquire_owner_id(acquisition, dispatch),
        owner_digest,
        operation_id: acquisition.effect_id,
        artifact_digest: attempt.attempt_digest,
        checkpoint_digest: attempt.signed_request_digest,
        chain_head_digest: session.session_binding,
    };
    Ok(SourceOrdinaryCapacityBindingV1 {
        kind,
        acquisition: acquisition.acquisition_id,
        fields,
    })
}

/// Compares genuine legacy dispatch cleanup retirement in an already checked graph.
///
/// CleanupRequired alone is not retirement, Storage absence or lease authority.
///
/// # Errors
///
/// Rejects Released without its actual native carrier, Tombstone or Release Attempt.
pub fn legacy_dispatch_capacity_is_retired_v1(
    acquisition: &AcquisitionRecordV1,
    native: Option<&NativeAcquireCompletionRecordV2>,
    release: Option<&ReleaseRecordV1>,
    attempt: Option<&AttemptRecordV1>,
) -> Result<bool, LedgerFormatErrorV1> {
    if acquisition.state != ProviderAcquisitionStateV1::Released {
        return Ok(false);
    }
    let native = native.ok_or(corrupt("native terminal completion missing"))?;
    let release = release.ok_or(corrupt("native terminal release missing"))?;
    let attempt = attempt.ok_or(corrupt("native terminal release attempt missing"))?;

    if native.state != NativeAcquireCompletionStateV2::CleanupRequired
        || release.state != ProviderReleaseStateV1::Tombstone
    {
        return Err(corrupt("native terminal phase contradiction"));
    }
    super::reducer::validate_release_join(acquisition, release, attempt)?;
    Ok(true)
}

/// Derives complete ordinary obligations and original continuations from actual rows.
///
/// The complete canonical graph is validated before any origin/profile selection.
/// Matching provenance and historical quartet DATA confers no physical membership,
/// configuration origin, signature eligibility, currentness or custody.
///
/// # Errors
///
/// Rejects incomplete/foreign/noncanonical graphs, missing or duplicate original
/// bindings, unsupported retirement evidence, missing ordinary lineage and bounded
/// origin retention or projected logical-counter exhaustion.
pub fn derive_source_capacity_owner_data_v1<'record>(
    complete_owner_rows: impl IntoIterator<Item = (&'record [u8], &'record [u8])>,
    original_origins: &[OriginalSourceOwnerOriginInputV5<'_>],
) -> Result<SourceCapacityOwnerDataV1, LedgerFormatErrorV1> {
    bound_original_origins(original_origins)?;
    let records = crate::collect_bounded_records(complete_owner_rows)?;
    bound_retained_graphs(&records, original_origins.len())?;
    let graph_digest = crate::validate_current_records(&records)?.graph_digest();

    let mut acquisitions = BTreeMap::new();
    let mut attempts = BTreeMap::new();
    let mut histories = BTreeMap::new();
    let mut sessions = BTreeMap::new();
    let mut natives = BTreeMap::new();
    let mut releases = BTreeMap::new();
    let mut profiles = BTreeMap::new();

    for (key, value) in &records {
        if value.get(8..10) == Some(9_u16.to_be_bytes().as_slice()) {
            let archive = native_completion::classify_original_source_pre_requested_cold_v1(
                views(&records),
                SourcePreRequestedColdArchiveV1::from_canonical_bytes(key, value)?
                    .prepared()
                    .claims()
                    .acquisition_id,
            )?;
            profiles.insert(
                archive.prepared().claims().acquisition_id,
                SourceCapacityProfileV1::PreRequestedCold(archive),
            );
            continue;
        }
        let decoded = if value.get(8..10) == Some(8_u16.to_be_bytes().as_slice()) {
            let held = SourceNativeHeldCompletionRecordV1::from_canonical_bytes(key, value)?;
            let native = held.original().clone();
            profiles.insert(native.acquisition_id, SourceCapacityProfileV1::Held(held));
            DecodedRecordV1::NativeCompletion(native)
        } else {
            format::decode_record(key, value)?
        };
        match decoded {
            DecodedRecordV1::Acquisition(row) => {
                acquisitions.insert(row.acquisition_id, row);
            }
            DecodedRecordV1::Attempt(row) => {
                attempts.insert(row.attempt_digest, row);
            }
            DecodedRecordV1::SessionHistory(row) => {
                histories.insert(
                    (
                        row.provider.authority_id(),
                        row.holder.authority_id(),
                        row.session_binding,
                    ),
                    row,
                );
            }
            DecodedRecordV1::Session(row) => {
                sessions.insert(
                    (row.provider.authority_id(), row.holder.authority_id()),
                    row,
                );
            }
            DecodedRecordV1::NativeCompletion(row) => {
                natives.insert(row.acquisition_id, row);
            }
            DecodedRecordV1::Release(row) => {
                releases.insert(row.acquisition_id, row);
            }
            DecodedRecordV1::Authority(_) | DecodedRecordV1::Catalog(_) => {}
        }
    }

    let profile_owner_ids = profiles
        .keys()
        .map(|identifier| {
            let acquisition = acquisitions
                .get(identifier)
                .ok_or(corrupt("native profile acquisition missing"))?;
            Ok((*identifier, acquire_owner_id(acquisition, true)))
        })
        .collect::<Result<BTreeMap<_, _>, LedgerFormatErrorV1>>()?;

    let mut originals = BTreeMap::new();
    let mut retired = BTreeMap::new();
    for origin in original_origins {
        validate_original_source_admission_provenance_v5(
            origin.comparison,
            origin.provenance,
            origin.comparison.original().configuration_digest,
        )?;
        let acquisition = origin.comparison.original().acquisition_id;
        if !acquisitions.contains_key(&acquisition)
            || originals.contains_key(&acquisition)
            || retired.contains_key(&acquisition)
        {
            return Err(corrupt("original Source origin duplicate or foreign acquisition"));
        }
        let cold = matches!(
            profiles.get(&acquisition),
            Some(SourceCapacityProfileV1::PreRequestedCold(_))
        );
        validate_original_source_current_origin_v5(
            views(&records),
            origin.comparison,
            origin.provenance,
            origin.comparison.original().configuration_digest,
        )?;
        if let Some(retirement) = origin.retirement {
            retirement.validate_current(&records, origin)?;
            retired.insert(acquisition, retirement.clone());
            if !cold {
                // Exact retired fault DATA can have no possible future branch.
                // It remains a real original, never a legacy owner exclusion bit.
                continue;
            }
        }
        let continuation = derive_original_source_continuations_v5(
            views(&records),
            if cold {
                None
            } else {
                Some(origin.comparison)
            },
            origin.provenance,
            origin.comparison.original().configuration_digest,
        )?;
        originals.insert(acquisition, continuation);
    }

    let mut ordinary = Vec::new();
    for acquisition in acquisitions.values() {
        let identifier = acquisition.acquisition_id;
        let native = natives.get(&identifier);
        if !originals.contains_key(&identifier)
            && !retired.contains_key(&identifier)
            && !profiles.contains_key(&identifier)
        {
            let required = if is_dispatch(acquisition) {
                legacy_dispatch_capacity_is_retired_v1(
                    acquisition,
                    native,
                    releases.get(&identifier),
                    attempts.get(&acquisition.current_attempt_digest),
                )
                .map(|retired| !retired)?
            } else {
                acquisition.state == ProviderAcquisitionStateV1::Applying
                    && is_no_dispatch(acquisition)
            };
            if required {
                let attempt_digest = native
                    .filter(|_| is_dispatch(acquisition))
                    .map_or(acquisition.current_attempt_digest, |row| row.attempt_digest);
                let attempt = attempts
                    .get(&attempt_digest)
                    .ok_or(corrupt("native capacity attempt"))?;
                let history = match native {
                    Some(row) => histories.get(&(
                        acquisition.provider.authority_id(),
                        acquisition.holder.authority_id(),
                        row.session_binding,
                    )),
                    None => sessions.get(&(
                        acquisition.provider.authority_id(),
                        acquisition.holder.authority_id(),
                    )),
                }
                .ok_or(corrupt("native capacity original session"))?;
                ordinary.push(derive_native_acquire_ordinary_binding_v1(
                    acquisition,
                    attempt,
                    history,
                    native,
                )?);
            }
        }

        if !is_dispatch(acquisition)
            || !matches!(
                acquisition.state,
                ProviderAcquisitionStateV1::Releasing | ProviderAcquisitionStateV1::Faulted
            )
        {
            continue;
        }
        let Some(release) = releases.get(&identifier) else {
            continue;
        };
        let attempt = attempts
            .get(&release.attempt_digest)
            .ok_or(corrupt("native Release capacity current attempt"))?;
        let binding = if matches!(
            profiles.get(&identifier),
            Some(SourceCapacityProfileV1::Held(_))
        ) {
            native_held_release_status_binding_v1(views(&records), identifier)?
        } else {
            let native = native.ok_or(corrupt("native Release capacity marker"))?;
            let original = attempts
                .get(&native.attempt_digest)
                .ok_or(corrupt("native Release capacity original Acquire"))?;
            let history = histories
                .get(&(
                    attempt.provider.authority_id(),
                    attempt.holder.authority_id(),
                    attempt.session_binding,
                ))
                .ok_or(corrupt("native Release capacity request session"))?;
            native_release_status_capacity_binding_v1(
                acquisition,
                native,
                original,
                release,
                attempt,
                history,
            )?
        };
        if attempt.state == ProviderAttemptStateV1::Reserved {
            ordinary.push(release_binding(identifier, binding));
        } else if !native_release_status_is_completed_v1(attempt) {
            return Err(corrupt("native Release capacity terminal contradiction"));
        }
    }

    Ok(SourceCapacityOwnerDataV1 {
        records,
        graph_digest,
        ordinary,
        profiles,
        profile_owner_ids,
        originals,
        retired,
    })
}

fn bound_retained_graphs(
    records: &BTreeMap<Vec<u8>, Vec<u8>>,
    origin_count: usize,
) -> Result<(), LedgerFormatErrorV1> {
    let graph_bytes = records.iter().try_fold(0_usize, |total, (key, value)| {
        total
            .checked_add(key.len())
            .and_then(|sum| sum.checked_add(value.len()))
            .ok_or(LedgerFormatErrorV1::LimitExceeded("original Source retained graphs"))
    })?;
    // The accepted continuation engine retains one complete current graph per
    // origin. This caps duplicated graph payload before invoking it, not exact
    // RAM usage: base rows, origins and transient templates have separate bounds.
    let retained_bytes = graph_bytes
        .checked_mul(origin_count)
        .ok_or(LedgerFormatErrorV1::LimitExceeded("original Source retained graphs"))?;
    if retained_bytes > crate::limits::MAXIMUM_LEDGER_GRAPH_BYTES {
        return Err(LedgerFormatErrorV1::LimitExceeded("original Source retained graphs"));
    }
    Ok(())
}

fn bound_original_origins(
    origins: &[OriginalSourceOwnerOriginInputV5<'_>],
) -> Result<(), LedgerFormatErrorV1> {
    if origins.len() > crate::limits::MAXIMUM_LEDGER_RECORDS {
        return Err(LedgerFormatErrorV1::LimitExceeded("original Source origin count"));
    }
    let mut bytes = 0_usize;
    let mut identities = BTreeSet::new();
    for origin in origins {
        if !identities.insert(origin.comparison.original().acquisition_id) {
            return Err(corrupt("original Source origin duplicate acquisition"));
        }
        for mutation in origin.comparison.quartet() {
            bytes = bytes
                .checked_add(mutation.key().len())
                .and_then(|total| total.checked_add(mutation.after().len()))
                .ok_or(LedgerFormatErrorV1::LimitExceeded("original Source origin bytes"))?;
        }
        bytes = bytes
            .checked_add(origin.provenance.to_canonical_bytes().len())
            .and_then(|total| {
                total.checked_add(origin.retirement.map_or(
                    0,
                    OriginalSourceRetirementComparisonV5::retained_bytes,
                ))
            })
            .ok_or(LedgerFormatErrorV1::LimitExceeded("original Source origin bytes"))?;
        if bytes > crate::limits::MAXIMUM_LEDGER_GRAPH_BYTES {
            return Err(LedgerFormatErrorV1::LimitExceeded("original Source origin bytes"));
        }
    }
    Ok(())
}

fn acquire_owner_id(acquisition: &AcquisitionRecordV1, dispatch: bool) -> [u8; 32] {
    let domain: &[u8] = if dispatch {
        b"aos.sandbox.source-provider.native-dispatch-capacity-owner.v2\0"
    } else {
        b"aos.sandbox.source-provider.native-capacity-owner.v1\0"
    };
    Sha256::new()
        .chain_update(domain)
        .chain_update(acquisition.provider.authority_id())
        .chain_update(acquisition.holder.authority_id())
        .chain_update(acquisition.acquisition_id.as_bytes())
        .finalize()
        .into()
}

fn is_dispatch(acquisition: &AcquisitionRecordV1) -> bool {
    acquisition.backend_id == crate::identity::acquire_native_dispatch_id_v2(
        acquisition.normalized_intent.digest(),
        acquisition.catalog_generation,
        acquisition.catalog_digest,
        acquisition.effect_attempt_digest,
    )
}

fn is_no_dispatch(acquisition: &AcquisitionRecordV1) -> bool {
    acquisition.backend_id == crate::identity::acquire_native_no_dispatch_id_v1(
        acquisition.normalized_intent.digest(),
        acquisition.catalog_generation,
        acquisition.catalog_digest,
    )
}

fn release_binding(
    acquisition: ObjectDigest,
    binding: NativeReleaseStatusCapacityBindingV1,
) -> SourceOrdinaryCapacityBindingV1 {
    SourceOrdinaryCapacityBindingV1 {
        kind: SourceOrdinaryCapacityKindV1::NativeReleaseStatus,
        acquisition,
        fields: SourceCapacityBindingFieldsV1 {
            owner_id: binding.owner_id,
            owner_digest: binding.owner_digest,
            operation_id: binding.operation_id,
            artifact_digest: binding.artifact_digest,
            checkpoint_digest: binding.checkpoint_digest,
            chain_head_digest: binding.chain_head_digest,
        },
    }
}

fn views(records: &BTreeMap<Vec<u8>, Vec<u8>>) -> impl Iterator<Item = (&[u8], &[u8])> {
    records
        .iter()
        .map(|(key, value)| (key.as_slice(), value.as_slice()))
}

fn corrupt(message: &'static str) -> LedgerFormatErrorV1 {
    LedgerFormatErrorV1::Corrupt(message)
}

#[cfg(test)]
mod tests;
