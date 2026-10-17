//! Durable originals, positive probe provenance, expiry and revocation fences.

use anyhow::{ensure, Result};
use aos_hub_core::{
    storage_work::{
        binding_custody::*, StorageBindingPublication, StorageBindingSnapshot,
        StorageCredentialMaterial,
    },
    topology_probe::StorageCredentialProbeEvidence,
};
use serde::{Deserialize, Serialize};

/// Private material and its permanent original probe identity.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HeldCredential {
    pub(super) original: StorageCredentialCustodyProbe,
    pub(super) material: Option<StorageCredentialMaterial>,
    pub(super) material_not_after: i64,
    pub(super) positive: Option<StorageCredentialProbeEvidence>,
    pub(super) pending: bool,
    pub(super) revoked: bool,
}

impl HeldCredential {
    pub(super) fn new(stage: StorageCredentialCustodyStage) -> Self {
        Self {
            original: stage.request,
            material: Some(stage.material),
            material_not_after: stage.material_not_after,
            positive: None,
            pending: false,
            revoked: false,
        }
    }

    pub(super) fn require_probe(
        &self,
        request: &StorageCredentialCustodyProbe,
        now: i64,
    ) -> Result<()> {
        request.validate(&self.original.snapshot.deployment_id, now)?;
        request.matches_original(&self.original)?;
        ensure!(
            !self.revoked && self.material.is_some() && now < self.material_not_after,
            "credential custody original material unavailable"
        );
        Ok(())
    }

    pub(super) fn require_adoption(
        &self,
        expected: &StorageBindingSnapshot,
        now: i64,
    ) -> Result<()> {
        expected.validate(&self.original.snapshot.deployment_id, now)?;
        ensure!(
            !self.revoked
                && !self.pending
                && self.material.is_some()
                && now < self.material_not_after
                && self.positive.as_ref().is_some_and(|proof| proof.valid),
            "credential custody lacks current positive material proof"
        );
        let original = &self.original.snapshot;
        ensure!(
            original.credentials.len() == 1,
            "credential custody retained original invalid"
        );
        let mut binding = expected.clone();
        binding.credentials = original.credentials.clone();
        binding.issued_at = original.issued_at;
        binding.expires_at = original.expires_at;
        ensure!(
            binding == *original && expected.credentials.contains(&original.credentials[0]),
            "credential custody current binding or reference changed"
        );
        Ok(())
    }

    pub(super) fn publication(
        &self,
        snapshot: StorageBindingSnapshot,
        now: i64,
    ) -> Result<StorageBindingPublication> {
        let material = self
            .material
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("credential custody material absent"))?;
        let publication = StorageBindingPublication {
            snapshot,
            materials: vec![StorageCredentialMaterial {
                selector: material.selector.clone(),
                value_base64: material.value_base64.clone(),
            }],
        };
        publication.validate(&self.original.snapshot.deployment_id, now)?;
        Ok(publication)
    }

    pub(super) fn accept_replacement(&self, request: &StorageCredentialCustodyProbe) -> Result<()> {
        let original = &self.original.snapshot;
        let next = &request.snapshot;
        ensure!(
            original.credentials.len() == 1 && next.credentials.len() == 1,
            "credential custody retained original invalid"
        );
        let old_reference = &original.credentials[0];
        let next_reference = &next.credentials[0];
        ensure!(
            original.binding_id == next.binding_id
                && original.binding_stable_id == next.binding_stable_id
                && next.binding_resource_version >= original.binding_resource_version
                && next_reference.purpose == old_reference.purpose
                && next_reference.generation >= old_reference.generation,
            "credential custody original identity or generation regressed"
        );
        if next_reference.generation == old_reference.generation {
            ensure!(
                next_reference == old_reference
                    && request.head_resource_version >= self.original.head_resource_version
                    && (!self.revoked
                        || next.binding_resource_version > original.binding_resource_version),
                "credential custody revision was changed or revoked"
            );
            if next.binding_resource_version == original.binding_resource_version {
                ensure!(
                    next.binding_spec_revision()? == original.binding_spec_revision()?,
                    "credential custody binding coordinates changed without revision"
                );
            }
            if request.operation_id == self.original.operation_id {
                request.matches_original(&self.original)?;
            } else {
                ensure!(
                    !self.pending
                        && request.head_resource_version > self.original.head_resource_version,
                    "credential custody new task cannot erase original unknown probe"
                );
            }
        }
        Ok(())
    }

    pub(super) fn expire(&mut self, now: i64) -> bool {
        if now >= self.material_not_after && self.material.is_some() {
            self.material = None;
            return true;
        }
        false
    }

    pub(super) fn renew_validated(
        &mut self,
        expected: &StorageBindingSnapshot,
        now: i64,
    ) -> Result<()> {
        self.require_adoption(expected, now)?;
        self.material_not_after = now
            .checked_add(MAX_CREDENTIAL_CUSTODY_SECONDS)
            .ok_or_else(|| anyhow::anyhow!("credential custody renewal overflow"))?;
        Ok(())
    }

    pub(super) fn revoke(&mut self) {
        self.revoked = true;
        self.material = None;
    }
}
