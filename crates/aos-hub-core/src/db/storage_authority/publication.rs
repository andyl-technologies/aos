//! Exact reviewed metadata assembled for the paired authority control ledger.
//!
//! Full attestation membership is retained even when admission selects a subset.
//! Credential references are compared as opaque identities; this module never
//! resolves them or claims that provider permissions have been exercised.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{ensure, Context, Result};

use super::{unix_now, Database};
use crate::storage_authority::control::{StorageAuthorityPublication, MAX_AUTHORITY_MEMBERS};
use crate::storage_authority::{
    ApproveStorageAuthorityAlias, AssociateStorageAuthorityBinding, PhysicalStorageAuthorityId,
    StorageAuthorityAdmissionState, StorageAuthorityHost, StorageAuthorityRemoteWatermark,
};

impl Database {
    /// Builds the current reviewed publication without reading credential secrets.
    ///
    /// The executor and namespace are deployment configuration, not values
    /// inferred from a request, provider response, or binding display label.
    /// Historical writer revisions remain pinned even if the default for new
    /// plans moves. Their attested credentials must still be current and valid.
    ///
    /// # Errors
    /// Returns an error for absent decisions, malformed facts, stale binding or
    /// credential revisions, expired evidence, aggregate byte overflow, scope
    /// mismatch, or SQL failure.
    pub async fn storage_authority_publication(
        &self,
        authority_id: &PhysicalStorageAuthorityId,
        namespace: &str,
        executor: &str,
    ) -> Result<StorageAuthorityPublication> {
        let authority = self
            .physical_storage_authority(authority_id)
            .await?
            .context("physical authority does not exist")?;
        let desired = self
            .desired_storage_authority_admission(authority_id)
            .await?
            .context("authority has no reviewed desired admission")?;
        let mut publication = StorageAuthorityPublication {
            authority,
            aliases: Vec::new(),
            associations: Vec::new(),
            attestation: None,
            admission: desired.specification.clone(),
            generation: desired.generation,
            digest: desired.digest.clone(),
        };

        if desired.specification.state == StorageAuthorityAdmissionState::Admitted {
            let attestation = self
                .storage_authority_attestation(
                    desired
                        .specification
                        .attestation_id
                        .as_deref()
                        .context("admission lacks attestation")?,
                )
                .await?
                .context("reviewed attestation disappeared")?;
            ensure!(
                attestation.credentials.len() <= MAX_AUTHORITY_MEMBERS
                    && desired.specification.association_ids.len() <= MAX_AUTHORITY_MEMBERS,
                "authority publication has too many reviewed members"
            );
            let association_ids: BTreeSet<_> = attestation
                .credentials
                .iter()
                .map(|member| member.association_id.as_str())
                .chain(
                    desired
                        .specification
                        .association_ids
                        .iter()
                        .map(String::as_str),
                )
                .collect();
            let mut aliases = BTreeMap::new();
            for association_id in association_ids {
                let association = self
                    .binding_storage_authority_association(association_id)
                    .await?
                    .context("reviewed association disappeared")?;
                let alias = self
                    .physical_storage_alias(&association.alias_id)
                    .await?
                    .context("reviewed alias disappeared")?;
                self.validate_publication_binding(&association, &alias)
                    .await?;
                aliases.insert(alias.alias_id.clone(), alias);
                publication.associations.push(association);
            }
            for member in &attestation.credentials {
                let association = publication
                    .associations
                    .iter()
                    .find(|association| association.association_id == member.association_id)
                    .context("attestation association is missing")?;
                let credential = self
                    .current_binding_credential(association.binding_id, &member.purpose)
                    .await?
                    .context("attested credential head disappeared")?;
                ensure!(
                    credential.generation == member.generation
                        && credential.secret_version_ref == member.secret_version_ref
                        && credential.credential_fingerprint == member.credential_fingerprint
                        && credential.validation_state == "valid",
                    "attested credential is no longer current and validated"
                );
                if member.purpose == "write" {
                    let writer = self
                        .binding_write_revision(
                            association.binding_id,
                            association.binding_write_revision,
                        )
                        .await?
                        .context("reviewed writer revision disappeared")?;
                    ensure!(
                        writer.write_credential_purpose == member.purpose
                            && writer.write_credential_generation == member.generation
                            && writer.write_credential_version_ref == member.secret_version_ref,
                        "reviewed writer differs from attested credential"
                    );
                }
            }
            publication.aliases = aliases.into_values().collect();
            publication.attestation = Some(attestation);
        }

        publication.validate(namespace, executor)?;
        publication.validate_admission_time(unix_now())?;
        ensure!(
            self.desired_storage_authority_admission(authority_id)
                .await?
                .as_ref()
                == Some(&desired),
            "authority desired state changed while assembling publication"
        );
        Ok(publication)
    }

    /// Rechecks delivered facts and atomically acknowledges the exact desired head.
    ///
    /// This records metadata delivery only. Fresh provider execution admission
    /// requires its own authority and credential validation at the I/O boundary.
    ///
    /// # Errors
    /// Returns an error if facts, desired state, or authenticated remote state
    /// differ from the publication, or acknowledgement persistence fails.
    pub async fn reconcile_storage_authority_publication(
        &self,
        publication: &StorageAuthorityPublication,
        remote: &StorageAuthorityRemoteWatermark,
        namespace: &str,
        executor: &str,
    ) -> Result<()> {
        let current = self
            .storage_authority_publication(&publication.authority.authority_id, namespace, executor)
            .await?;
        ensure!(
            &current == publication,
            "authority facts changed during control exchange"
        );
        self.reconcile_storage_authority_watermark(remote).await
    }

    async fn validate_publication_binding(
        &self,
        association: &AssociateStorageAuthorityBinding,
        alias: &ApproveStorageAuthorityAlias,
    ) -> Result<()> {
        let binding = self
            .binding(association.binding_id)
            .await?
            .context("reviewed binding disappeared")?;
        let (host_kind, host_bytes) = match &alias.spec.host {
            StorageAuthorityHost::Dns(host) => ("dns", host.as_bytes().to_vec()),
            StorageAuthorityHost::Ipv4(bytes) => ("ipv4", bytes.to_vec()),
            StorageAuthorityHost::Ipv6(bytes) => ("ipv6", bytes.to_vec()),
        };
        ensure!(
            binding.kind == "s3"
                && !binding.is_instance_default
                && binding.stable_id == association.binding_stable_id
                && binding.resource_version == association.binding_resource_version
                && binding.object_prefix.as_deref() == Some(association.binding_prefix.as_str())
                && binding.object_bucket.as_deref() == Some(alias.spec.bucket.as_str())
                && binding.endpoint_scheme.as_deref() == Some("https")
                && binding.endpoint_host_kind.as_deref() == Some(host_kind)
                && binding.endpoint_host_bytes.as_deref() == Some(host_bytes.as_slice())
                && binding.endpoint_port == Some(i64::from(alias.spec.port)),
            "reviewed binding no longer matches exact physical coordinates and revision"
        );
        Ok(())
    }
}
