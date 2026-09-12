//! Durable provider ownership selection, validation, and recovery.
//!
//! Each owner binds a persistent logical resource to an exact provider identity
//! and the stable terminal handler core checked for its plan. During adoption,
//! the replacement record temporarily retains the sealed authority and complete
//! source evidence needed to recover or reject a partial transfer. The runtime
//! separately re-observes an execution assignment at each admission;
//! its provider, interface, and implementation must match the sealed core, while
//! its runtime capability incarnation may rotate between transactions.
//! Canonical ledger record schemas live in the focused `records` submodule.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    ActiveNativeConsumer, GenerationAbilityStoreError, NativeConsumerRequirement,
    NativeInventoryState, NativeNoOpResourceObservation, NativeQualifiedResource,
    NativeResourceLedger, canonical_artifacts, canonicalize_native_ledger, exact_terminal_result,
    load_native_resource_ledger, save_native_resource_ledger, validate_generation_name,
};
use aos_ability_model::{ArtifactReference, ResourceId, ResourceLifetime};
use aos_ability_runtime::bundle::ReloadablePlanBundle;
use aos_ability_runtime::execution::{ExecutionTransaction, OperationStatus, TransactionSummary};
use aos_ability_validate::CheckedEffectPlan;

mod records;

pub(in crate::config_eval::ability_store) use records::{
    NativeLinkedAdoptionVerification, NativeProviderAdoptionReceipt, NativeProviderClaim,
    NativeProviderEstablishment, NativeProviderHandlerIdentity, NativeProviderIdentity,
    NativeProviderOwner,
};

// One thousand authenticated recovery attempts already represents prolonged
// operator-visible failure while keeping one owner's provenance comfortably
// below the ledger's global 8 MiB encoding limit.
const NATIVE_PROVIDER_CLAIM_MAX_COUNT: usize = 1_024;

mod selection;

pub(super) use selection::{
    NativeProviderSelection, artifacts_from_endpoint, handler_from_endpoint,
    operation_provider_identity, retained_provider_owner_for_teardown, selected_provider_owners,
    selected_retained_provider_owners,
};
#[cfg(test)]
pub(super) use selection::{
    assignment_from_endpoint, endpoint_matches_selected_owner, operation_provider_owner,
    unique_provider_owner_selections,
};

mod finalization;
mod observed;
mod recovery;

impl NativeInventoryState {
    pub(in crate::config_eval::ability_store) fn has_provider_adoptions(&self) -> bool {
        !self.adoptions.is_empty()
    }

    pub(in crate::config_eval::ability_store) fn is_current_consumer(
        &self,
        consumer: &ActiveNativeConsumer,
    ) -> bool {
        self.has_current_journal_identity(&consumer.generation, &consumer.transaction)
    }
}

fn authenticate_retained_provenance_artifacts(
    plan: &CheckedEffectPlan,
    artifacts: &[ArtifactReference],
    provenance: &str,
) -> Result<(), GenerationAbilityStoreError> {
    let canonical = canonical_artifacts(artifacts)?;
    if canonical != artifacts || artifacts != plan.required_runtime_artifacts() {
        return Err(GenerationAbilityStoreError::Conflict(format!(
            "{provenance} artifacts differ from its retained checked plan"
        )));
    }

    Ok(())
}

fn current_claim_digest(
    claim: &NativeProviderClaim,
) -> Result<aos_contract::Sha256Digest, GenerationAbilityStoreError> {
    let bytes = aos_contract::canonical::to_vec(claim).map_err(|source| {
        GenerationAbilityStoreError::Operation(anyhow::anyhow!(
            "encoding authenticated native owner claim: {source:#}"
        ))
    })?;
    Ok(aos_contract::Sha256Digest::separated(
        "aos.ability.native-provider-claim/v1",
        bytes,
    ))
}

fn validate_receipt_artifact_union(
    source_artifacts: &[ArtifactReference],
    establishment_artifacts: &[ArtifactReference],
) -> Result<(), GenerationAbilityStoreError> {
    if canonical_artifacts(source_artifacts)? != source_artifacts
        || canonical_artifacts(establishment_artifacts)? != establishment_artifacts
        || establishment_artifacts
            .iter()
            .any(|artifact| !source_artifacts.contains(artifact))
    {
        return Err(GenerationAbilityStoreError::Conflict(
            "provider adoption receipt artifact union omits exact source establishment artifacts"
                .to_string(),
        ));
    }

    Ok(())
}

fn append_provider_claim(
    owner: &mut NativeProviderOwner,
    claim: NativeProviderClaim,
) -> Result<bool, GenerationAbilityStoreError> {
    if owner.claim_by.contains(&claim) {
        return Ok(false);
    }
    if owner.claim_by.len() >= NATIVE_PROVIDER_CLAIM_MAX_COUNT {
        return Err(GenerationAbilityStoreError::Conflict(format!(
            "native provider owner claim chain exceeds the {}-entry limit",
            NATIVE_PROVIDER_CLAIM_MAX_COUNT
        )));
    }

    owner.claim_by.push(claim);
    canonicalize_provider_claim_chain(owner)?;
    Ok(true)
}

fn canonicalize_provider_claim_chain(
    owner: &mut NativeProviderOwner,
) -> Result<(), GenerationAbilityStoreError> {
    if owner.claim_by.len() > NATIVE_PROVIDER_CLAIM_MAX_COUNT {
        return Err(GenerationAbilityStoreError::Conflict(format!(
            "native provider owner claim chain exceeds the {}-entry limit",
            NATIVE_PROVIDER_CLAIM_MAX_COUNT
        )));
    }

    let mut claims = Vec::with_capacity(owner.claim_by.len());
    for mut claim in owner.claim_by.drain(..) {
        validate_generation_name(&claim.generation)?;
        claim.artifacts = canonical_artifacts(&claim.artifacts)?;
        if claim.operation.plan != claim.plan || claim.attempt == 0 {
            return Err(GenerationAbilityStoreError::Conflict(
                "native provider owner claim provenance is malformed".to_string(),
            ));
        }
        let bytes = aos_contract::canonical::to_vec(&claim).map_err(|source| {
            GenerationAbilityStoreError::Conflict(format!(
                "encoding native provider owner claim provenance: {source}"
            ))
        })?;
        claims.push((bytes, claim));
    }
    claims.sort_by(|(left, _), (right, _)| left.cmp(right));
    if claims.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(GenerationAbilityStoreError::Conflict(
            "native provider owner claim chain contains duplicate provenance".to_string(),
        ));
    }
    owner.claim_by = claims.into_iter().map(|(_, claim)| claim).collect();
    align_unestablished_owner_to_initial_claim(owner)
}

fn align_unestablished_owner_to_initial_claim(
    owner: &mut NativeProviderOwner,
) -> Result<(), GenerationAbilityStoreError> {
    if owner.established_by.is_some() || owner.claim_by.is_empty() {
        return Ok(());
    }
    let claim = owner.claim_by.first().ok_or_else(|| {
        GenerationAbilityStoreError::Conflict(
            "unestablished provider owner lost its initial claim provenance".to_string(),
        )
    })?;
    owner.generation = claim.generation.clone();
    owner.transaction = claim.transaction.clone();
    owner.plan = claim.plan;
    owner.artifacts = claim.artifacts.clone();
    Ok(())
}

fn successful_operation_attempts(
    summary: &TransactionSummary,
) -> Result<BTreeMap<aos_ability_model::ScopedOperationKey, u32>, GenerationAbilityStoreError> {
    summary
        .operations()
        .iter()
        .filter(|operation| operation.status() == OperationStatus::Succeeded)
        .map(|operation| {
            let attempt = operation.attempt().ok_or_else(|| {
                GenerationAbilityStoreError::Conflict(
                    "successful native operation lacks its admitted attempt identity".to_string(),
                )
            })?;
            Ok((operation.operation().operation.clone(), attempt.get()))
        })
        .collect()
}

fn require_owner_assignment<'a>(
    checked: Option<&'a NativeProviderHandlerIdentity>,
    execution: Option<&aos_ability_model::ProviderAssignment>,
) -> Result<&'a NativeProviderHandlerIdentity, GenerationAbilityStoreError> {
    let checked = checked.ok_or_else(|| {
        GenerationAbilityStoreError::Conflict(
            "native provider ownership requires a sealed checked handler assignment".to_string(),
        )
    })?;
    let execution = execution.ok_or_else(|| {
        GenerationAbilityStoreError::Conflict(
            "native provider ownership requires a fresh execution assignment".to_string(),
        )
    })?;
    if execution.provider != checked.provider
        || execution.interface != checked.interface
        || execution.implementation != checked.implementation
    {
        return Err(GenerationAbilityStoreError::Conflict(
            "native provider ownership differs from the freshly admitted implementation"
                .to_string(),
        ));
    }
    Ok(checked)
}

/// Validates, deduplicates, and sorts durable owner records canonically.
///
/// # Errors
///
/// Returns an error when an owner or adoption receipt has inconsistent
/// identity evidence, a generation name is invalid, artifacts conflict, or
/// multiple owners claim one logical resource.
pub(super) fn canonicalize_native_owners(
    owners: &mut [NativeProviderOwner],
) -> Result<(), GenerationAbilityStoreError> {
    let mut resources = BTreeSet::new();
    for owner in owners.iter_mut() {
        owner.physical.validate()?;
        if owner.resource.provider != owner.identity.provider
            || owner.identity.state_format.artifact != owner.identity.implementation.artifact
        {
            return Err(GenerationAbilityStoreError::Conflict(
                "native provider owner has inconsistent exact identity evidence".to_string(),
            ));
        }
        validate_generation_name(&owner.generation)?;
        owner.artifacts = canonical_artifacts(&owner.artifacts)?;
        if owner.claim_by.is_empty() && owner.established_by.is_none() {
            return Err(GenerationAbilityStoreError::Conflict(
                "native provider owner lacks claim and establishment provenance".to_string(),
            ));
        }
        canonicalize_provider_claim_chain(owner)?;
        if let Some(establishment) = &mut owner.established_by {
            validate_generation_name(&establishment.generation)?;
            establishment.artifacts = canonical_artifacts(&establishment.artifacts)?;
            if establishment.generation != owner.generation
                || establishment.transaction != owner.transaction
                || establishment.plan != owner.plan
                || establishment.operation.plan != establishment.plan
                || establishment.attempt == 0
                || establishment.artifacts != owner.artifacts
            {
                return Err(GenerationAbilityStoreError::Conflict(
                    "native provider owner establishment differs from its durable owner row"
                        .to_string(),
                ));
            }
        } else if let Some(claim) = owner.claim_by.first()
            && (claim.generation != owner.generation
                || claim.transaction != owner.transaction
                || claim.plan != owner.plan
                || claim.artifacts != owner.artifacts)
        {
            return Err(GenerationAbilityStoreError::Conflict(
                "native provider owner claim differs from its durable owner row".to_string(),
            ));
        }
        if let Some(receipt) = &mut owner.adoption {
            if receipt.source.provider != owner.identity.provider
                || receipt.source.state_format.descriptor != owner.identity.state_format.descriptor
            {
                return Err(GenerationAbilityStoreError::Conflict(
                    "native provider adoption receipt has inconsistent source evidence".to_string(),
                ));
            }
            validate_generation_name(&receipt.source_generation)?;
            receipt.source_artifacts = canonical_artifacts(&receipt.source_artifacts)?;
            receipt.source_establishment.artifacts =
                canonical_artifacts(&receipt.source_establishment.artifacts)?;
            match (&receipt.consumer_requirement, &receipt.linked_verification) {
                (None, None) => {}
                (None, Some(verification)) | (Some(_), Some(verification)) => {
                    validate_generation_name(&verification.generation)?;
                }
                (Some(_), None) => {
                    return Err(GenerationAbilityStoreError::Conflict(
                        "native provider adoption verification is only partially recorded"
                            .to_string(),
                    ));
                }
            }
        }
        if !resources.insert(owner.resource.clone()) {
            return Err(GenerationAbilityStoreError::Conflict(
                "native resource ledger contains ambiguous provider ownership".to_string(),
            ));
        }
    }
    owners.sort_by(|left, right| {
        left.resource
            .cmp(&right.resource)
            .then_with(|| left.identity.provider.cmp(&right.identity.provider))
    });
    Ok(())
}

#[cfg(test)]
mod tests;
