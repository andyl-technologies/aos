//! Native correlation of guarded and immutable-version reads with SQL authority.
//!
//! The authenticated Worker retains the physical source guard through its read.
//! Native checks the returned closure against independently accepted profiles,
//! current publication membership and exact binding material before using rows.
//! Versioned results additionally carry authenticated completed-read evidence;
//! a bare provider version never substitutes for that evidence, and a guard
//! incarnation is never converted into a provider version.

use anyhow::{Context as _, Result, ensure};
use aos_hub_core::{
    db::BindingRecord,
    direct_upload::{DirectExternalStorageCapabilities, DirectProtectedProfile},
    mirror_inspection::{MirrorPackProjection, MirrorPackTreeProjection, MirrorPackTreeQuery},
    storage_authority::lease::{LeaseCohort, LeaseEffect, LeasePurpose},
    storage_work::{
        StorageBindingSnapshot, StorageObjectIdentity, StorageWorkOperation, StorageWorkOutcome,
        StorageWorkPlan, StorageWorkResult, protected_inspection::ProtectedInspectionSource,
    },
};
use base64::Engine as _;
use sha2::Digest as _;

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
        || projection.pair.pack.provider_version.is_some()
        || projection.pair.index.provider_version.is_some()
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
    validate_source_observed(plan, path, source, guarded, profile, &[])
}

fn validate_source_observed(
    plan: &StorageWorkPlan,
    path: &str,
    source: &StorageObjectIdentity,
    guarded: Option<&ProtectedInspectionSource>,
    profile: Option<&DirectExternalStorageCapabilities>,
    versioned: &[aos_hub_core::storage_work::protected_inspection::VersionedInspectionSource],
) -> Result<()> {
    match profile {
        None => ensure!(
            guarded.is_none(),
            "Managed inspection returned External guard evidence"
        ),
        Some(profile) => {
            if guarded.is_none() && source.provider_version.is_some() {
                let evidence = versioned
                    .iter()
                    .find(|evidence| evidence.source == *source)
                    .context(
                        "External versioned inspection omitted its authenticated completed read",
                    )?;
                evidence.validate_identity(
                    plan,
                    path,
                    &profile.selector.association.binding_prefix,
                    source,
                )?;
                validate_versioned_scope(evidence, profile)?;
                return Ok(());
            }
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
    versioned: &[aos_hub_core::storage_work::protected_inspection::VersionedInspectionSource],
) -> Result<()> {
    pair.source_commitment()?;
    for source in [&pair.pack, &pair.index] {
        let identity = StorageObjectIdentity {
            key: plan.object_key(&source.path)?,
            provider_version: source.provider_version.clone(),
            etag: source.etag.clone(),
            size: source.size,
        };
        validate_source_observed(
            plan,
            &source.path,
            &identity,
            source.guarded_source.as_ref(),
            profile,
            versioned,
        )?;
        if source.provider_version.is_some() {
            ensure!(
                versioned.iter().any(|evidence| evidence.source == identity
                    && evidence.range.is_none()
                    && evidence.sha256 == source.sha256),
                "versioned pair digest lacks complete-read evidence"
            );
        }
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
            *start == 0
                || guarded_source.is_some()
                || expected_provider_version
                    .as_deref()
                    .is_some_and(|version| version != "null"
                        && aos_hub_core::storage_work::valid_provider_version(version)),
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
        StorageWorkOperation::InspectMetadata { .. }
            | StorageWorkOperation::InspectMetadataObjects { .. }
            | StorageWorkOperation::InspectGitObject { .. }
            | StorageWorkOperation::InspectGitObjects { .. }
            | StorageWorkOperation::InspectDocumentation { .. }
            | StorageWorkOperation::InspectDocumentationContent { .. }
            | StorageWorkOperation::Head { .. }
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
    ensure!(
        result.versioned_sources.len() <= 128,
        "versioned inspection evidence exceeds bound"
    );
    if !result.versioned_sources.is_empty() {
        let accepted = selected
            .as_ref()
            .context("versioned inspection lacks current accepted profile")?;
        let external = profile.context("versioned inspection has no External Read domain")?;
        let commitment = accepted.digest()?;
        let domain = &result.versioned_sources[0].configured_domain_digest;
        for evidence in &result.versioned_sources {
            evidence.validate()?;
            ensure!(
                evidence.producer_profile_digest == commitment
                    && &evidence.configured_domain_digest == domain,
                "versioned inspection producer profile or installed domain differs"
            );
            validate_versioned_scope(evidence, external)?;
            let path = evidence
                .source
                .key
                .strip_prefix(&format!("{}/", plan.placement_prefix))
                .or_else(|| {
                    plan.placement_prefix
                        .is_empty()
                        .then_some(evidence.source.key.as_str())
                })
                .context("versioned evidence escaped current placement")?;
            evidence.validate_identity(
                plan,
                path,
                &external.selector.association.binding_prefix,
                &evidence.source,
            )?;
            validate_versioned_selection(plan, path, evidence)?;
        }
    }
    match (&plan.operation, &result.outcome) {
        (
            StorageWorkOperation::Head { path },
            StorageWorkOutcome::Head {
                object,
                guarded_source,
            },
        ) => {
            validate_source_observed(
                plan,
                path,
                object,
                guarded_source.as_ref(),
                profile,
                &result.versioned_sources,
            )?;
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
            validate_source_observed(
                plan,
                path,
                source,
                guarded_source.as_ref(),
                profile,
                &result.versioned_sources,
            )?;
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
            validate_source_observed(
                plan,
                path,
                source,
                guarded_source.as_ref(),
                profile,
                &result.versioned_sources,
            )?;
        }
        (
            StorageWorkOperation::InspectOciRange { path, .. },
            StorageWorkOutcome::OciRange {
                source,
                guarded_source,
                content_base64,
                ..
            },
        ) => {
            validate_source_observed(
                plan,
                path,
                source,
                guarded_source.as_ref(),
                profile,
                &result.versioned_sources,
            )?;
            if source.provider_version.is_some() {
                validate_versioned_content(source, content_base64, &result.versioned_sources)?;
            }
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
            validate_pair(plan, projection, profile, &result.versioned_sources)?;
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
            validate_pair(plan, &projection.pair, profile, &result.versioned_sources)?;
            validate_pack_cursor(query, projection)?;
        }
        (
            StorageWorkOperation::InspectMetadata { path },
            StorageWorkOutcome::Metadata {
                source,
                content_base64,
            },
        ) => {
            if source.provider_version.is_some() {
                validate_source_observed(
                    plan,
                    path,
                    source,
                    None,
                    profile,
                    &result.versioned_sources,
                )?;
                validate_versioned_content(source, content_base64, &result.versioned_sources)?;
            }
        }
        (
            StorageWorkOperation::InspectMetadataObjects { .. },
            StorageWorkOutcome::MetadataObjects { page },
        ) => {
            for entry in &page.objects {
                if let Some(document) = &entry.document {
                    if document.source.provider_version.is_some() {
                        validate_source_observed(
                            plan,
                            &entry.path,
                            &document.source,
                            None,
                            profile,
                            &result.versioned_sources,
                        )?;
                        validate_versioned_content(
                            &document.source,
                            &document.content_base64,
                            &result.versioned_sources,
                        )?;
                    }
                }
            }
        }
        (
            StorageWorkOperation::InspectGitObject { .. },
            StorageWorkOutcome::GitObject { source, .. },
        ) => {
            if source.provider_version.is_some() {
                validate_versioned_result_source(plan, source, profile, &result.versioned_sources)?;
            }
        }
        (
            StorageWorkOperation::InspectGitObjects { .. },
            StorageWorkOutcome::GitObjects { objects },
        ) => {
            for object in objects {
                if object.source.provider_version.is_some() {
                    validate_versioned_result_source(
                        plan,
                        &object.source,
                        profile,
                        &result.versioned_sources,
                    )?;
                }
            }
        }
        (
            StorageWorkOperation::InspectDocumentation { .. },
            StorageWorkOutcome::Documentation { .. },
        )
        | (
            StorageWorkOperation::InspectDocumentationContent { .. },
            StorageWorkOutcome::DocumentationContent { .. },
        ) => {
            // Existing result acceptance checks every selected DTO. Completed
            // versioned source evidence above is additionally bound to the actual
            // current Read profile; no source body crosses this boundary.
        }
        (_, StorageWorkOutcome::NotFound) => {}
        _ => anyhow::bail!("protected inspection returned another result"),
    }
    Ok(())
}

#[cfg(test)]
mod tests;

fn validate_versioned_scope(
    evidence: &aos_hub_core::storage_work::protected_inspection::VersionedInspectionSource,
    profile: &DirectExternalStorageCapabilities,
) -> Result<()> {
    let read = &profile.read_cohort;
    ensure!(
        evidence.scope.guard_namespace_id == read.authority.guard_namespace_id
            && evidence.scope.physical_authority_id == read.authority.authority_id
            && read.allowed_effects.contains(&LeaseEffect::Read)
            && contained(&read.admitted_prefix, &evidence.scope.full_key),
        "versioned inspection escaped accepted physical Read domain"
    );
    Ok(())
}

fn validate_versioned_selection(
    plan: &StorageWorkPlan,
    path: &str,
    evidence: &aos_hub_core::storage_work::protected_inspection::VersionedInspectionSource,
) -> Result<()> {
    use StorageWorkOperation as Op;
    let git_path = |oids: &[String]| {
        oids.iter().any(|oid| {
            aos_registry_surface::object::Oid::from_hex(oid)
                .is_ok_and(|oid| oid.loose_path() == path)
                || oid.get(..2).is_some_and(|prefix| {
                    aos_registry_surface::object_bundle::shard_path(prefix)
                        .is_ok_and(|shard| shard == path)
                })
        })
    };
    let selected = match &plan.operation {
        Op::Head { path: selected } => {
            ensure!(
                evidence.metadata_only,
                "HEAD returned fabricated body evidence"
            );
            selected == path
        }
        Op::HashOciRange {
            path: selected,
            start,
            end,
            total,
            strong_etag,
            expected_provider_version,
            guarded_source,
            ..
        } => {
            ensure!(
                !evidence.metadata_only
                    && guarded_source.is_none()
                    && evidence.range == Some((*start, *end))
                    && *total == evidence.source.size
                    && strong_etag == &evidence.source.etag
                    && expected_provider_version == &evidence.source.provider_version,
                "versioned hash changed its original source or interval"
            );
            selected == path
        }
        Op::InspectMetadata { path: selected } => selected == path,
        Op::InspectMetadataObjects { paths, cursor } => paths
            .get(*cursor..)
            .is_some_and(|paths| paths.iter().any(|selected| selected == path)),
        Op::InspectGitObject { oid } | Op::FilterGitTreeEntries { oid, .. } => {
            git_path(std::slice::from_ref(oid))
        }
        Op::InspectGitObjects { oids } => git_path(oids),
        Op::InspectOciRange {
            path: selected,
            start,
            end,
        } => {
            ensure!(
                evidence.range == Some((*start, *end)),
                "versioned OCI result interval differs"
            );
            selected == path
        }
        Op::InspectStoredGitPack { index_path, .. } => {
            path == index_path
                || aos_registry_surface::pack_index::companion_pack_path(index_path).as_deref()
                    == Some(path)
        }
        Op::FilterStoredGitPackTree { query } => {
            path == query.index_path
                || aos_registry_surface::pack_index::companion_pack_path(&query.index_path)
                    .as_deref()
                    == Some(path)
        }
        Op::InspectDocumentation { artifact, .. }
        | Op::InspectDocumentationContent { artifact, .. } => {
            path == format!(
                "{}.narinfo",
                aos_registry_surface::store::store_path_hash(&artifact.store_path)?
            ) || path.starts_with("nar/")
                && path.ends_with(".nar")
                && evidence.source.size == artifact.nar_size
                && evidence.sha256
                    == aos_registry_surface::store::canonical_digest_hex(&artifact.nar_hash)?
        }
        _ => false,
    };
    ensure!(
        selected,
        "versioned completed source is outside signed semantic selection"
    );
    if !matches!(plan.operation, Op::Head { .. }) {
        ensure!(
            !evidence.metadata_only,
            "semantic result lacks actual byte-read evidence"
        );
    }
    if !matches!(
        plan.operation,
        Op::InspectOciRange { .. } | Op::HashOciRange { .. }
    ) {
        ensure!(
            evidence.range.is_none(),
            "versioned semantic source was not fully consumed"
        );
    }
    Ok(())
}

fn validate_versioned_result_source(
    plan: &StorageWorkPlan,
    source: &StorageObjectIdentity,
    profile: Option<&DirectExternalStorageCapabilities>,
    versioned: &[aos_hub_core::storage_work::protected_inspection::VersionedInspectionSource],
) -> Result<()> {
    let path = source
        .key
        .strip_prefix(&format!("{}/", plan.placement_prefix))
        .or_else(|| {
            plan.placement_prefix
                .is_empty()
                .then_some(source.key.as_str())
        })
        .context("versioned result escaped its placement")?;
    validate_source_observed(plan, path, source, None, profile, versioned)
}

fn validate_versioned_content(
    source: &StorageObjectIdentity,
    content_base64: &str,
    versioned: &[aos_hub_core::storage_work::protected_inspection::VersionedInspectionSource],
) -> Result<()> {
    let evidence = versioned
        .iter()
        .find(|evidence| evidence.source == *source)
        .context("versioned compact content lacks completed-read evidence")?;
    // These bytes are already the bounded semantic control result. No provider
    // body is fetched here to manufacture a second source observation.
    let bytes = base64::engine::general_purpose::STANDARD.decode(content_base64)?;
    ensure!(
        !evidence.metadata_only && hex::encode(sha2::Sha256::digest(&bytes)) == evidence.sha256,
        "versioned compact content differs from its completed read digest"
    );
    Ok(())
}
