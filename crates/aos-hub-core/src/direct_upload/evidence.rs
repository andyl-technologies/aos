//! Closed final placement evidence and exact original-admission correlation.

use anyhow::{ensure, Result};

use super::*;

impl DirectVerifiedStageEvidence {
    /// Checks bounded parsed private-stage proof structure without provider dispatch.
    ///
    /// # Errors
    /// Returns an error for malformed source, manifests, incarnations or projection.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            valid_direct_identity(&self.session_id)
                && valid_direct_digest(&self.logical_fingerprint)
                && valid_direct_digest(&self.operation_id)
                && valid_direct_digest(&self.sha256)
                && self.part_count <= MAX_DIRECT_PARTS
                && self.byte_size.get() <= MAX_DIRECT_OBJECT_BYTES
                && !self.placements.is_empty()
                && self.placements.len() <= MAX_DIRECT_PLACEMENTS,
            "invalid direct verified stage identity"
        );
        let mut previous = 0;
        for item in &self.placements {
            item.placement.validate()?;
            ensure!(
                item.placement.placement_id.get() > previous
                    && item.manifest.placement == item.placement
                    && item.manifest.part_count == self.part_count
                    && valid_direct_digest(&item.manifest.manifest_digest)
                    && valid_direct_digest(&item.verification_operation_id),
                "invalid direct verified stage destination"
            );
            incarnation(&item.staging_incarnation)?;
            previous = item.placement.placement_id.get();
        }
        if let Some(projection) = &self.projection {
            projection.validate()?;
            let (sha, size) = projection.source_identity();
            ensure!(
                sha == self.sha256 && u64::from(size) == self.byte_size.get(),
                "direct stage projection source mismatch"
            );
        }
        encode_direct_control(self)?;
        Ok(())
    }

    /// Correlates every verified private stage to the exact retained admission.
    ///
    /// # Errors
    /// Returns an error for changed sources, missing destinations or foreign
    /// incarnation kinds/authorities. Native must still apply current ACL/barriers.
    pub fn validate_against(
        &self,
        admission: &DirectUploadAdmission,
        deployment: &str,
    ) -> Result<()> {
        self.validate()?;
        admission.validate(deployment)?;
        ensure!(
            self.session_id == admission.session_id
                && self.logical_fingerprint == admission.logical_fingerprint
                && self.sha256 == admission.intent.expected_sha256
                && self.byte_size == admission.intent.byte_size
                && self.part_count == admission.intent.part_count()?
                && self.placements.len() == admission.placements.len(),
            "direct verified stage admission mismatch"
        );
        for (item, original) in self.placements.iter().zip(&admission.placements) {
            ensure!(
                item.placement == original.public_ref(deployment)?,
                "direct verified stage placement mismatch"
            );
            match (&original.physical, &item.staging_incarnation) {
                (
                    DirectPhysicalContext::DeploymentR2 { .. },
                    DirectObjectIncarnation::ProviderVersion { .. },
                ) => {}
                (
                    DirectPhysicalContext::External { write_cohort, .. },
                    DirectObjectIncarnation::GuardStamp { stamp },
                ) => {
                    ensure!(
                        stamp.physical_authority_id == write_cohort.authority.authority_id,
                        "direct verified stage guard authority mismatch"
                    );
                }
                _ => anyhow::bail!("direct verified stage incarnation kind mismatch"),
            }
        }
        Ok(())
    }
}

impl DirectCompletionEvidence {
    /// Validates bounded structural evidence without attesting provider effects.
    ///
    /// # Errors
    /// Returns a value-free error for malformed identities, counts, projection,
    /// revisions, manifests or object incarnation records.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            valid_direct_identity(&self.session_id)
                && valid_direct_digest(&self.logical_fingerprint)
                && valid_direct_digest(&self.operation_id)
                && valid_direct_digest(&self.sha256)
                && self.byte_size.get() <= MAX_DIRECT_OBJECT_BYTES
                && self.part_count <= MAX_DIRECT_PARTS,
            "invalid direct completion identity"
        );
        ensure!(
            !self.placements.is_empty() && self.placements.len() <= MAX_DIRECT_PLACEMENTS,
            "invalid direct completion placement count"
        );
        let mut previous = 0;
        for item in &self.placements {
            for counter in [
                item.placement_id,
                item.placement_resource_version,
                item.write_spec_version,
                item.binding_id,
                item.binding_resource_version,
                item.binding_write_revision,
            ] {
                ensure!(
                    (1..=i64::MAX as u64).contains(&counter.get()),
                    "invalid direct completion counter"
                );
            }
            item.manifest.placement.validate()?;
            ensure!(
                item.placement_id.get() > previous
                    && item.manifest.placement.placement_id == item.placement_id
                    && item.manifest.part_count == self.part_count
                    && valid_direct_digest(&item.manifest.manifest_digest)
                    && valid_direct_digest(&item.promotion_operation_id)
                    && valid_direct_etag(&item.final_etag),
                "invalid direct completion placement evidence"
            );
            previous = item.placement_id.get();
            incarnation(&item.staging_incarnation)?;
            incarnation(&item.final_incarnation)?;
        }
        if let Some(projection) = &self.projection {
            projection.validate()?;
            let (sha, size) = projection.source_identity();
            ensure!(
                sha == self.sha256 && u64::from(size) == self.byte_size.get(),
                "direct parsed projection source mismatch"
            );
        }
        encode_direct_control(self)?;
        Ok(())
    }

    /// Checks every required destination and source against retained admission.
    ///
    /// The caller must first authenticate the broker result and check current
    /// business ACL/CAS; provider receipts and unknown fences stay at the broker.
    ///
    /// # Errors
    /// Returns an error for changed original source, placement snapshots,
    /// checksum commitments or inappropriate physical incarnation kinds.
    pub fn validate_against(
        &self,
        admission: &DirectUploadAdmission,
        deployment: &str,
    ) -> Result<()> {
        self.validate()?;
        admission.validate(deployment)?;
        ensure!(
            self.session_id == admission.session_id
                && self.logical_fingerprint == admission.logical_fingerprint
                && self.sha256 == admission.intent.expected_sha256
                && self.byte_size == admission.intent.byte_size
                && self.part_count == admission.intent.part_count()?
                && self.placements.len() == admission.placements.len(),
            "direct completion admission mismatch"
        );
        for (item, original) in self.placements.iter().zip(&admission.placements) {
            ensure!(
                item.placement_id == original.placement_id
                    && item.placement_resource_version == original.placement_resource_version
                    && item.write_spec_version == original.write_spec_version
                    && item.binding_id == original.binding_id
                    && item.binding_resource_version == original.binding_resource_version
                    && item.binding_write_revision == original.binding_write_revision
                    && item.manifest.placement == original.public_ref(deployment)?,
                "direct completion destination mismatch"
            );
            ensure!(
                item.promotion_operation_id
                    == direct_destination_promotion_operation_id(
                        &DirectSessionRef {
                            session_id: self.session_id.clone(),
                            logical_fingerprint: self.logical_fingerprint.clone()
                        },
                        item.placement_id,
                        &self.operation_id
                    )?,
                "direct completion original promotion operation mismatch"
            );
            for identity in [&item.staging_incarnation, &item.final_incarnation] {
                match (&original.physical, identity) {
                    (
                        DirectPhysicalContext::DeploymentR2 { .. },
                        DirectObjectIncarnation::ProviderVersion { .. },
                    ) => {}
                    (
                        DirectPhysicalContext::External { write_cohort, .. },
                        DirectObjectIncarnation::GuardStamp { stamp },
                    ) => {
                        ensure!(
                            stamp.physical_authority_id == write_cohort.authority.authority_id,
                            "direct completion guard authority mismatch"
                        );
                    }
                    _ => anyhow::bail!("direct completion incarnation kind mismatch"),
                }
            }
        }
        Ok(())
    }
}

impl DirectUploadLogicalReply {
    /// Checks all metadata-only reply arrays and their aggregate part budget.
    ///
    /// # Errors
    /// Returns an error for excessive size/counts or malformed admission/status.
    pub fn validate(&self, deployment: &str) -> Result<()> {
        ensure!(
            self.admissions.len() <= MAX_DIRECT_BATCH_ITEMS
                && self.sessions.len() <= MAX_DIRECT_BATCH_ITEMS
                && self.session_summaries.len() <= MAX_DIRECT_BATCH_ITEMS
                && self.authorizations.len() <= MAX_DIRECT_BATCH_ITEMS
                && self.errors.len() <= MAX_DIRECT_BATCH_ITEMS,
            "direct logical reply count exceeds limit"
        );
        for admission in &self.admissions {
            admission.validate(deployment)?;
        }
        let mut summary_sessions = std::collections::BTreeSet::new();
        for summary in &self.session_summaries {
            ensure!(
                summary_sessions.insert(&summary.session.session_id),
                "direct summary session duplicated"
            );
            let admission = self
                .admissions
                .iter()
                .find(|original| original.session_id == summary.session.session_id)
                .ok_or_else(|| anyhow::anyhow!("direct summary original absent"))?;
            summary.status(admission, deployment)?;
            let authorization = self
                .authorizations
                .iter()
                .find(|item| item.session == summary.session)
                .ok_or_else(|| anyhow::anyhow!("direct summary authorization absent"))?;
            let intent = authorization
                .complete_intent
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("direct summary complete original absent"))?;
            intent.fingerprint()?;
            ensure!(
                intent.session == summary.session
                    && intent.operation_id == authorization.operation_id
                    && Some(intent.expected_resource_version)
                        == authorization.expected_resource_version,
                "direct summary complete authorization mismatch"
            );
            ensure!(
                !self
                    .sessions
                    .iter()
                    .any(|status| status.session == summary.session),
                "direct summary repeats full status"
            );
        }
        let mut count = 0usize;
        for status in &self.sessions {
            status.validate()?;
            count = count
                .checked_add(status.parts.len())
                .ok_or_else(|| anyhow::anyhow!("direct logical reply part overflow"))?;
        }
        ensure!(
            count <= MAX_DIRECT_BATCH_PARTS,
            "direct logical reply part budget exceeded"
        );
        for item in &self.authorizations {
            item.session.validate()?;
            ensure!(
                valid_direct_digest(&item.operation_id),
                "invalid direct logical authorization operation"
            );
        }
        ensure!(
            self.baseline_permissions.len() <= MAX_DIRECT_BATCH_ITEMS * MAX_DIRECT_PLACEMENTS,
            "direct baseline permission count exceeds limit"
        );
        let mut unique = std::collections::BTreeSet::new();
        for permission in &self.baseline_permissions {
            permission.validate()?;
            let binding = &permission.binding;
            ensure!(
                binding.deployment_id == deployment
                    && unique.insert((
                        &binding.session.session_id,
                        binding.placement.placement_id.get()
                    )),
                "direct baseline permission audience or duplicate mismatch"
            );
            let authorization = self
                .authorizations
                .iter()
                .find(|item| item.session == binding.session)
                .ok_or_else(|| {
                    anyhow::anyhow!("direct baseline permission authorization absent")
                })?;
            let intent = authorization.complete_intent.as_ref().ok_or_else(|| {
                anyhow::anyhow!("direct baseline permission complete intent absent")
            })?;
            ensure!(
                binding.complete_operation_id == authorization.operation_id
                    && intent.operation_id == authorization.operation_id
                    && intent.session == authorization.session
                    && authorization.expected_resource_version
                        == Some(intent.expected_resource_version)
                    && binding.complete_intent_digest == intent.fingerprint()?
                    && intent
                        .manifests
                        .iter()
                        .any(|item| item.placement == binding.placement),
                "direct baseline permission original intent mismatch"
            );
        }
        encode_direct_control(self)?;
        Ok(())
    }
}

fn incarnation(value: &DirectObjectIncarnation) -> Result<()> {
    match value {
        DirectObjectIncarnation::ProviderVersion { version } => {
            ensure!(
                !version.is_empty()
                    && version.len() <= 1024
                    && !version.chars().any(char::is_control),
                "invalid direct provider object version"
            );
        }
        DirectObjectIncarnation::GuardStamp { .. } => {}
    }
    Ok(())
}
