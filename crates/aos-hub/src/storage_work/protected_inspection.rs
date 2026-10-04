//! Native correlation of guarded inspection receipts with current SQL authority.
//!
//! The authenticated Worker retains the physical source guard through its read.
//! Native checks the returned closure against independently accepted profiles,
//! current publication membership and exact binding material before using rows.
//! A guard incarnation is never converted into a provider version.

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::{
    db::BindingRecord,
    direct_upload::{DirectExternalStorageCapabilities, DirectProtectedProfile},
    mirror_inspection::{MirrorPackProjection, MirrorPackTreeProjection, MirrorPackTreeQuery},
    storage_authority::lease::{LeaseCohort, LeaseEffect, LeasePurpose},
    storage_work::{
        protected_inspection::ProtectedInspectionSource, StorageBindingSnapshot,
        StorageObjectIdentity, StorageWorkOperation, StorageWorkOutcome, StorageWorkPlan,
        StorageWorkResult,
    },
};

use super::HybridSurfaceFetch;

impl HybridSurfaceFetch {
    /// Selects the actual accepted stored-source profile, without widening mirrors.
    ///
    /// # Errors
    /// Refuses absent or expired acceptance, changed SQL publication membership,
    /// binding material, credential heads or an ambiguous protected profile.
    pub(super) async fn stored_inspection_profile(&self) -> Result<String> {
        if self.binding.kind == "deployment_r2" && self.binding.is_instance_default {
            return self.work.mirror_managed_profile_digest();
        }
        current_external_profile(self, &self.binding, None)
            .await?
            .context("stored External pack lacks an accepted protected profile")?
            .digest()
    }
}

async fn current_external_profile(
    fetch: &HybridSurfaceFetch,
    binding: &BindingRecord,
    plan: Option<&StorageWorkPlan>,
) -> Result<Option<DirectProtectedProfile>> {
    ensure!(
        matches!(binding.kind.as_str(), "s3" | "r2") && !binding.is_instance_default,
        "protected inspection requires an External binding"
    );
    let Some(acceptances) = &fetch.work.mirror_profiles else {
        return Ok(None);
    };
    let now = aos_hub_core::clock::now_unix_secs();
    let origin = fetch.work.executor_origin()?;
    let Some(selected_profile) = select_external_profile(
        acceptances,
        &fetch.work.deployment_id,
        &origin,
        binding,
        u64::try_from(now)?,
    )?
    else {
        return Ok(None);
    };
    let DirectProtectedProfile::External { profile, .. } = &selected_profile else {
        anyhow::bail!("External inspection profile changed kind");
    };
    profile.validate()?;
    let snapshot = fetch.work.acknowledged_binding_snapshot(binding.id)?;
    let credentials = fetch
        .db
        .list_current_binding_credentials(binding.id)
        .await?;
    fetch
        .work
        .validate_published_binding_snapshot(binding, &credentials, &snapshot.revision()?)?;
    validate_window(
        acceptances,
        &origin,
        &selected_profile,
        &snapshot,
        plan,
        now,
    )?;
    let read = &profile.read_cohort;
    let publication = fetch
        .db
        .storage_authority_publication(
            &read.authority.authority_id,
            &read.authority.guard_namespace_id,
            &read.executor_identity,
        )
        .await?;
    let current_read = LeaseCohort::from_publication(
        &publication,
        &read.executor_identity,
        &read.association.association_id,
        LeasePurpose::Read,
        &read.admitted_prefix,
        read.allowed_effects.clone(),
    )?;
    ensure!(
        current_read == *read,
        "External inspection read publication changed"
    );
    // SQL reads can outlive an original. Re-sample after the last await instead
    // of retaining the admission time as permission for the returned rows.
    let observed_at = aos_hub_core::clock::now_unix_secs();
    ensure!(
        observed_at >= now,
        "inspection clock moved backward during SQL observation"
    );
    validate_window(
        acceptances,
        &origin,
        &selected_profile,
        &snapshot,
        plan,
        observed_at,
    )?;
    Ok(Some(selected_profile))
}

fn select_external_profile(
    acceptances: &crate::direct_upload::authority::NativeDirectUploadAcceptances,
    deployment: &str,
    origin: &str,
    binding: &BindingRecord,
    now: u64,
) -> Result<Option<DirectProtectedProfile>> {
    // Applicability survives audience and clock drift. Only current verified
    // audience membership below can authorize the retained protected domain.
    if !acceptances.protects_external_binding(binding.id, &binding.stable_id) {
        return Ok(None);
    }
    let profiles = acceptances.profiles(deployment, origin, now)?;
    let mut selected = profiles.into_iter().filter(|candidate| match candidate {
        DirectProtectedProfile::External { profile, .. } => {
            let association = &profile.selector.association;
            association.binding_id.get() == binding.id
                || association.binding_stable_id == binding.stable_id
        }
        _ => false,
    });
    let selected_profile = selected
        .next()
        .context("retained External inspection domain has no current accepted profile")?;
    ensure!(
        selected.next().is_none(),
        "External inspection profile is ambiguous"
    );
    Ok(Some(selected_profile))
}

fn validate_window(
    acceptances: &crate::direct_upload::authority::NativeDirectUploadAcceptances,
    origin: &str,
    selected: &DirectProtectedProfile,
    snapshot: &StorageBindingSnapshot,
    plan: Option<&StorageWorkPlan>,
    now: i64,
) -> Result<()> {
    let DirectProtectedProfile::External { profile, .. } = selected else {
        anyhow::bail!("External inspection profile changed kind");
    };
    let latest = now
        .checked_add(profile.clock_uncertainty.get())
        .context("inspection clock bound overflowed")?;
    ensure!(
        acceptances
            .profiles(&snapshot.deployment_id, origin, u64::try_from(latest)?)?
            .contains(selected),
        "External inspection acceptance expired"
    );
    validate_snapshot(profile, snapshot, latest)?;
    if let Some(plan) = plan {
        snapshot.authorizes(plan, &snapshot.deployment_id, latest)?;
        ensure!(
            latest < plan.expires_at,
            "protected inspection original expired"
        );
    }
    ensure!(
        latest < profile.read_cohort.attestation_valid_until.get(),
        "External inspection read attestation expired"
    );
    Ok(())
}

fn validate_snapshot(
    profile: &DirectExternalStorageCapabilities,
    snapshot: &StorageBindingSnapshot,
    now: i64,
) -> Result<()> {
    snapshot.validate(&snapshot.deployment_id, now)?;
    let association = &profile.selector.association;
    let credential = &profile.selector.read_credential;
    ensure!(
        snapshot.access_mode == "private"
            && snapshot.binding_id == association.binding_id.get()
            && snapshot.binding_stable_id == association.binding_stable_id
            && snapshot.binding_resource_version == association.binding_resource_version.get()
            && snapshot.object_prefix == association.binding_prefix
            && snapshot
                .credentials
                .iter()
                .any(|reference| reference.purpose == "read"
                    && u64::try_from(reference.generation).ok()
                        == Some(credential.generation.get())
                    && reference.secret_version_ref == credential.secret_version_ref
                    && reference.fingerprint == credential.credential_fingerprint),
        "External inspection binding or read credential changed"
    );
    // Current SQL publication assembly checks the alias against the binding's
    // real endpoint/bucket. That check cannot be replaced by this selector.
    Ok(())
}

pub(super) fn validate_pack_cursor(
    query: &MirrorPackTreeQuery,
    projection: &MirrorPackTreeProjection,
) -> Result<()> {
    if projection.pair.pack.guarded_source.is_some()
        || projection.pair.index.guarded_source.is_some()
    {
        let commitment = projection.pair.source_commitment()?;
        ensure!(
            query
                .cursor
                .as_ref()
                .is_none_or(|cursor| cursor.source_commitment == commitment),
            "guarded pack continuation names another source incarnation"
        );
    }
    Ok(())
}

fn validate_source(
    plan: &StorageWorkPlan,
    path: &str,
    source: &StorageObjectIdentity,
    guarded: Option<&ProtectedInspectionSource>,
    profile: Option<&DirectExternalStorageCapabilities>,
) -> Result<()> {
    match profile {
        None => ensure!(
            guarded.is_none(),
            "Managed inspection returned External guard evidence"
        ),
        Some(profile) => {
            let guarded = guarded.context("External inspection omitted its source closure")?;
            guarded.validate_identity(
                plan,
                path,
                &profile.selector.association.binding_prefix,
                source,
            )?;
            let read = &profile.read_cohort;
            ensure!(
                guarded.scope.guard_namespace_id == read.authority.guard_namespace_id
                    && guarded.scope.physical_authority_id == read.authority.authority_id
                    && read.allowed_effects.contains(&LeaseEffect::Read)
                    && contained(&read.admitted_prefix, &guarded.scope.full_key),
                "External inspection source escaped its accepted physical read domain"
            );
        }
    }
    Ok(())
}

fn validate_pair(
    plan: &StorageWorkPlan,
    pair: &MirrorPackProjection,
    profile: Option<&DirectExternalStorageCapabilities>,
) -> Result<()> {
    pair.source_commitment()?;
    for source in [&pair.pack, &pair.index] {
        let identity = StorageObjectIdentity {
            key: plan.object_key(&source.path)?,
            provider_version: None,
            etag: source.etag.clone(),
            size: source.size,
        };
        validate_source(
            plan,
            &source.path,
            &identity,
            source.guarded_source.as_ref(),
            profile,
        )?;
    }
    Ok(())
}

fn contained(prefix: &str, key: &str) -> bool {
    prefix.is_empty()
        || prefix == key
        || key
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

pub(super) fn validate_source_shape(
    path: &str,
    source: &StorageObjectIdentity,
    guarded: Option<&ProtectedInspectionSource>,
) -> Result<()> {
    if let Some(guarded) = guarded {
        guarded.validate_for(&guarded.scope.full_key, source.size, &source.etag)?;
        ensure!(
            source.provider_version.is_none(),
            "guarded source has a fabricated provider version"
        );
        if aos_hub_core::storage_work::admitted_oci_blob_path(path) {
            ensure!(
                Some(guarded.closure.sha256.as_str()) == path.rsplit('/').next(),
                "guarded OCI closure has another content digest"
            );
        }
    }
    Ok(())
}

pub(super) async fn check_hash_resume(
    fetch: &HybridSurfaceFetch,
    plan: &StorageWorkPlan,
) -> Result<()> {
    let StorageWorkOperation::HashOciRange {
        path,
        start,
        total,
        strong_etag,
        expected_provider_version,
        guarded_source,
        ..
    } = &plan.operation
    else {
        anyhow::bail!("hash resume check names another operation");
    };
    let selected = if fetch.binding.kind == "deployment_r2" && fetch.binding.is_instance_default {
        None
    } else {
        current_external_profile(fetch, &fetch.binding, Some(plan)).await?
    };
    if let Some(DirectProtectedProfile::External { profile, .. }) = &selected {
        ensure!(
            *start == 0 || guarded_source.is_some(),
            "protected hash continuation omitted its original source closure"
        );
        if let Some(guarded) = guarded_source {
            let identity = StorageObjectIdentity {
                key: plan.object_key(path)?,
                size: *total,
                etag: strong_etag.clone(),
                provider_version: expected_provider_version.clone(),
            };
            validate_source(plan, path, &identity, Some(guarded), Some(profile))?;
        }
    } else {
        ensure!(
            guarded_source.is_none(),
            "unprotected hash cannot adopt guarded source evidence"
        );
    }
    Ok(())
}

pub(super) async fn validate_current(
    fetch: &HybridSurfaceFetch,
    plan: &StorageWorkPlan,
    result: &StorageWorkResult,
    binding: &BindingRecord,
) -> Result<()> {
    if !matches!(
        plan.operation,
        StorageWorkOperation::Head { .. }
            | StorageWorkOperation::HashOciRange { .. }
            | StorageWorkOperation::FilterGitTreeEntries { .. }
            | StorageWorkOperation::InspectOciRange { .. }
            | StorageWorkOperation::InspectStoredGitPack { .. }
            | StorageWorkOperation::FilterStoredGitPackTree { .. }
    ) {
        return Ok(());
    }
    let selected = if binding.kind == "deployment_r2" && binding.is_instance_default {
        None
    } else {
        current_external_profile(fetch, binding, Some(plan)).await?
    };
    let profile = match &selected {
        Some(DirectProtectedProfile::External { profile, .. }) => Some(profile),
        None => None,
        _ => anyhow::bail!("inspection selected another profile kind"),
    };
    match (&plan.operation, &result.outcome) {
        (
            StorageWorkOperation::Head { path },
            StorageWorkOutcome::Head {
                object,
                guarded_source,
            },
        ) => {
            validate_source(plan, path, object, guarded_source.as_ref(), profile)?;
        }
        (
            StorageWorkOperation::HashOciRange {
                path,
                guarded_source: original,
                ..
            },
            StorageWorkOutcome::OciRangeHashed {
                source,
                guarded_source,
                ..
            },
        ) => {
            validate_source(plan, path, source, guarded_source.as_ref(), profile)?;
            ensure!(
                original
                    .as_ref()
                    .is_none_or(|original| Some(original) == guarded_source.as_ref()),
                "protected hash reply changed the frozen source closure"
            );
        }
        (
            StorageWorkOperation::FilterGitTreeEntries { oid, .. },
            StorageWorkOutcome::GitTreeEntries {
                source,
                guarded_source,
                ..
            },
        ) => {
            let loose = aos_registry_surface::object::Oid::from_hex(oid)?.loose_path();
            let shard = aos_registry_surface::object_bundle::shard_path(&oid[..2])?;
            let path = if source.key == plan.object_key(&loose)? {
                &loose
            } else {
                &shard
            };
            validate_source(plan, path, source, guarded_source.as_ref(), profile)?;
        }
        (
            StorageWorkOperation::InspectOciRange { path, .. },
            StorageWorkOutcome::OciRange {
                source,
                guarded_source,
                ..
            },
        ) => {
            validate_source(plan, path, source, guarded_source.as_ref(), profile)?;
        }
        (
            StorageWorkOperation::InspectStoredGitPack {
                protected_profile_digest,
                ..
            },
            StorageWorkOutcome::GitPackProjection { projection },
        ) => {
            if binding.kind != "deployment_r2" {
                let selected = selected
                    .as_ref()
                    .context("stored External pack lacks protected acceptance")?;
                ensure!(
                    selected.digest()? == *protected_profile_digest,
                    "stored pack profile changed"
                );
            }
            validate_pair(plan, projection, profile)?;
        }
        (
            StorageWorkOperation::FilterStoredGitPackTree { query },
            StorageWorkOutcome::GitPackTreeProjection { projection },
        ) => {
            if binding.kind != "deployment_r2" {
                let selected = selected
                    .as_ref()
                    .context("stored External tree lacks protected acceptance")?;
                ensure!(
                    selected.digest()? == query.protected_profile_digest,
                    "stored tree profile changed"
                );
            }
            validate_pair(plan, &projection.pair, profile)?;
            validate_pack_cursor(query, projection)?;
        }
        (_, StorageWorkOutcome::NotFound) => {}
        _ => anyhow::bail!("protected inspection returned another result"),
    }
    Ok(())
}

#[cfg(test)]
mod tests;
