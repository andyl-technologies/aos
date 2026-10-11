//! Joins actual installed Mirror cohorts to the accepted profile and List export.

use std::path::Path;

use anyhow::{Context as _, Result, ensure};
use aos_hub_core::{
    direct_upload::DirectProtectedExternalProfile,
    storage_authority::lease::{LeaseCohort, LeaseEffect, LeasePurpose},
};

use super::{
    assembly,
    observations::{Domain, ListExport, MirrorConfig, ObjectConfig},
    selection::*,
};

pub(super) fn validate(
    base: &Path,
    selected: &ExternalMirrorReviewSelection,
    protected: &DirectProtectedExternalProfile,
    public: &str,
) -> Result<Domain> {
    let bytes = assembly::read(base, &selected.inputs.configuration, 256 * 1024)?;
    let configuration: serde_json::Value = serde_json::from_slice(&bytes)?;
    let bindings = configuration
        .get("bindings")
        .and_then(serde_json::Value::as_object)
        .context("Mirror installed bindings absent")?;
    let text = |name: &str| -> Result<&str> {
        bindings
            .get(name)
            .and_then(serde_json::Value::as_str)
            .context("Mirror installed binding absent")
    };
    ensure!(
        text("HUB_EXTERNAL_MIRROR_FUNCTIONAL_PROBE")? == "1"
            && text("HUB_EXTERNAL_MIRROR_FUNCTIONAL_REVIEWER_PUBLIC_KEY")? == public
            && text("HUB_EXTERNAL_MIRROR_FUNCTIONAL_REVIEWER_KEY_ID")? == selected.reviewer_key_id
            && text("HUB_DEPLOYMENT_ID")? == selected.deployment_id
            && text("HUB_DIRECT_UPLOAD_PUBLIC_ORIGIN")? == selected.public_origin,
        "Mirror functional reviewer or installed audience differs"
    );
    aos_hub_core::mirror_acceptance::external_controlled::require_distinct_external_mirror_reviewer(
        public, text("HUB_DIRECT_UPLOAD_QUALIFICATION_PUBLIC_KEY")?)?;
    if let Some(hosted) = bindings.get("HUB_MIRROR_QUALIFICATION_PUBLIC_KEY") {
        aos_hub_core::mirror_acceptance::external_controlled::require_distinct_external_mirror_reviewer(
            public, hosted.as_str().context("Mirror Hosted verifier malformed")?)?;
    }
    ensure!(
        configuration
            .get("kvNamespaces")
            .and_then(|value| value.get("HUB_EXTERNAL_MIRROR_FUNCTIONAL_ACCEPTANCE"))
            .is_some_and(|value| value.as_str().is_some_and(|value| !value.is_empty())),
        "Mirror dedicated initial KV binding absent"
    );
    let conformance = assembly::read(base, &selected.inputs.conformance_key, 4096)?;
    ensure!(
        std::str::from_utf8(&conformance)?.trim() == text("HUB_DIRECT_UPLOAD_CONFORMANCE_KEY")?,
        "Mirror Clock key differs from installed conformance verifier"
    );
    let object: ObjectConfig = serde_json::from_str(text("HUB_EXTERNAL_OBJECT_CONSUMER")?)?;
    let mirror: MirrorConfig = serde_json::from_str(text("HUB_EXTERNAL_MIRROR_CONSUMER")?)?;
    ensure!(
        object.version == 1
            && mirror.version == 1
            && !mirror.domains.is_empty()
            && mirror.domains.len() <= 16
            && !object.cohorts.is_empty()
            && object.cohorts.len() <= 32
            && !object.publications.is_empty()
            && object.publications.len() <= 16
            && !object.aliases.is_empty()
            && object.aliases.len() <= 256,
        "Mirror installed domain bounds differ"
    );
    let matching = mirror
        .domains
        .into_iter()
        .filter(|domain| domain.profile == *protected)
        .collect::<Vec<_>>();
    ensure!(
        matching.len() == 1,
        "Mirror installed prerequisite domain absent or ambiguous"
    );
    let domain = matching
        .into_iter()
        .next()
        .context("Mirror domain absent")?;
    let current: ListExport = assembly::document(base, &selected.inputs.list_export)?;
    domain.issuer_installation.validate()?;
    current
        .publication
        .validate(&object.guard_namespace_id, &object.executor_identity)?;
    ensure!(
        current.version == 1
            && current.list_cohort == domain.list_cohort
            && current.issuer_installation == domain.issuer_installation
            && domain.issuer_installation.authority == protected.profile.write_cohort.authority
            && domain.issuer_installation.executor_identity == object.executor_identity
            && object.issuer_key_id == protected.profile.issuer_key_id
            && object.issuer_public_key == protected.profile.issuer_public_key
            && object.timing_profile == protected.profile.timing_profile
            && object.clock_uncertainty == protected.profile.clock_uncertainty.get(),
        "Mirror actual current export or installed issuer differs"
    );

    for cohort in [
        &protected.profile.read_cohort,
        &protected.profile.write_cohort,
        &domain.list_cohort,
    ] {
        // Reconstruction uses the production shared publication primitive; the
        // reviewer does not mint an equivalent synthetic cohort from SQL fields.
        let projected = LeaseCohort::from_publication(
            &current.publication,
            &object.executor_identity,
            &cohort.association.association_id,
            cohort.credential.purpose,
            &cohort.admitted_prefix,
            cohort.allowed_effects.clone(),
        )?;
        ensure!(
            &projected == cohort
                && object.cohorts.iter().filter(|item| *item == cohort).count() == 1
                && object.publications.contains(&current.publication)
                && object.aliases.contains(&cohort.alias)
                && cohort.publication_digest
                    == aos_hub_core::mirror_work::digest(&current.publication)?,
            "Mirror cohort differs from actual installed current publication"
        );
    }
    let read = &protected.profile.read_cohort;
    let list = &domain.list_cohort;
    ensure!(
        list.association == read.association
            && list.alias == read.alias
            && list.authority == read.authority
            && list.admitted_prefix == read.admitted_prefix
            && list.credential.purpose == LeasePurpose::List
            && list.allowed_effects == vec![LeaseEffect::List],
        "Mirror List selection differs from accepted physical scope"
    );
    let segments: Vec<_> = selected.placement_prefix.split('/').collect();
    ensure!(
        segments.len() == 3
            && segments[0] == ".aos-mirror-qualification"
            && segments[2] == "final"
            && segments[1].len() == 32
            && segments[1]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && selected.upstream_base
                == format!("https://aos.andyl.org:4778/fleet-mirror/{}", segments[1]),
        "Mirror upstream differs from the reserved fixture root"
    );
    Ok(domain)
}
