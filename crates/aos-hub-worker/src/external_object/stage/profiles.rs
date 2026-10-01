//! Requested public-only profiles from actual protected private bindings.
//!
//! The surrounding signed fresh challenge is owned by the direct broker. This
//! helper resolves no client coordinates and exposes no secrets/global history.
//! Configuration remains a provider qualification prerequisite, not its proof.

use std::{collections::BTreeSet, io};

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::{
    DirectExternalProfileSelector, DirectExternalStorageCapabilities,
};
use aos_hub_core::storage_authority::lease::LeaseInteger;
use worker::Env;

use super::super::config::configured;
use super::{config, executor::validate_domain_publication};

/// Resolves only exact server-selected profiles against current protected state.
///
/// Native must independently compare every public profile pin; authentication
/// and configuration do not prove provider policy or exclusive writer closure.
///
/// # Errors
/// Returns a value-free failure for duplicate/foreign selectors, disabled
/// qualification, changed credentials, stale binding or oversized public output.
pub(crate) async fn resolve_external_profiles(
    env: &Env,
    selectors: &[DirectExternalProfileSelector],
) -> Result<Vec<DirectExternalStorageCapabilities>> {
    ensure!(
        selectors.len() <= 16,
        "external profile selector bound exceeded"
    );
    if selectors.is_empty() {
        return Ok(Vec::new());
    }
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let object =
        configured(env)?.ok_or_else(|| anyhow::anyhow!("external object consumer disabled"))?;
    let config = config::configured(env, &object)?
        .ok_or_else(|| anyhow::anyhow!("external stage consumer disabled"))?;
    let mut seen = BTreeSet::new();
    let mut profiles = Vec::with_capacity(selectors.len());
    let mut validity = Vec::with_capacity(selectors.len());
    for selector in selectors {
        selector.validate()?;
        ensure!(
            seen.insert(selector.fingerprint()?),
            "duplicate external profile selector"
        );
        let mut domains = config.domains.iter().filter(|domain| {
            domain.write_cohort.authority.authority_id == selector.physical_authority_id
                && domain.write_cohort.association == selector.association
                && domain.write_credential == selector.write_credential
                && domain.read_credential == selector.read_credential
                && domain.presign_credential == selector.presign_credential
        });
        let domain = domains
            .next()
            .ok_or_else(|| anyhow::anyhow!("external profile is not independently configured"))?;
        ensure!(
            domains.next().is_none(),
            "external profile selector is ambiguous"
        );
        let publication = crate::hybrid_binding::resolve_for_delivery(
            env,
            selector.association.binding_id.get(),
            selector.association.binding_resource_version.get(),
        )
        .await?;
        validate_domain_publication(
            domain,
            &publication,
            &deployment,
            object.clock().observed_at,
        )?;
        validity.push((
            publication.snapshot.issued_at,
            publication.snapshot.expires_at,
        ));
        let profile = DirectExternalStorageCapabilities {
            selector: selector.clone(),
            issuer_installation: domain.issuer_installation.clone(),
            issuer_key_id: object.issuer_key_id.clone(),
            issuer_public_key: object.issuer_public_key.clone(),
            write_cohort: domain.write_cohort.clone(),
            read_cohort: domain.read_cohort.clone(),
            private_stage_policy: domain.private_stage_policy.clone(),
            staging_prefix: domain.staging_prefix.clone(),
            checksum_algorithm: domain.checksum_algorithm,
            maximum_grant_lifetime: domain.maximum_grant_lifetime,
            provider_contract_id: domain.provider_contract.contract_id.clone(),
            provider_contract_evidence_digest: domain.provider_contract.evidence_digest.clone(),
            timing_profile: object.timing_profile.clone(),
            clock_uncertainty: LeaseInteger::new(object.clock_uncertainty)?,
        };
        profile.validate()?;
        profiles.push(profile);
        serde_json::to_writer(&mut ProfileSizeBudget(0), &profiles)
            .map_err(|_| anyhow::anyhow!("external profiles exceed reply bound"))?;
    }
    // All awaits, material parsing and profile hashing finish before this cheap
    // observation. The broker must separately bind its fresh signed challenge.
    let now = object.clock().observed_at;
    ensure!(
        validity
            .iter()
            .all(|(issued, expires)| *issued <= now.saturating_add(5) && now <= *expires),
        "external binding expired during profile resolution"
    );
    Ok(profiles)
}

// Counts encoded bytes without allocating a complete public reply. The core
// challenge encoder separately bounds its request/profile envelope before copy.
struct ProfileSizeBudget(usize);

impl io::Write for ProfileSizeBudget {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .filter(|size| *size <= 64 * 1024)
            .ok_or_else(|| io::Error::other("external profiles exceed reply bound"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
