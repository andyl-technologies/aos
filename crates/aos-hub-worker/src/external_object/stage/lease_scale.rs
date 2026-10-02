//! Protected read-only acquisition measurements for the local scale fixture.
//!
//! This module is compiled only by `do-e2e`. It selects an existing configured
//! cohort, invokes the real renewal cache, and returns lease commitments rather
//! than tokens. It admits no provider effect or new cohort. The process labels
//! and selected source still require the collector's actual process/module join.
//!
//! ```text
//! request = {version, run_id, nonce, source_digest, configuration_digest,
//!            cohort_digest, issued_at, expires_at}
//! fixture = {version, run_id, isolate_label, installations}
//! ```

use anyhow::{ensure, Result};
use aos_hub_core::storage_authority::lease::{control::IssuerInstallation, LeaseClock};
use aos_hub_core::storage_work::StorageWorkKey;
use serde::{Deserialize, Serialize};

use super::super::protocol::{digest, digest_string};

pub(crate) const PATH: &str = "/__hub/lease-scale-acquire";
const REQUEST_DOMAIN: &[u8] = b"aos-local-lease-scale-request-v1\0";
const REPLY_DOMAIN: &[u8] = b"aos-local-lease-scale-reply-v1\0";
const BODY_LIMIT: usize = 4096;
const SIGNATURE_HEADER: &str = "x-aos-lease-scale-signature";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeRequest {
    version: u8,
    run_id: String,
    nonce: String,
    source_digest: String,
    configuration_digest: String,
    cohort_digest: String,
    issued_at: i64,
    expires_at: i64,
}

impl ProbeRequest {
    fn check(&self, source: &str, configuration: &str, run: &str, clock: LeaseClock) -> Result<()> {
        let latest = clock
            .observed_at
            .checked_add(clock.uncertainty)
            .ok_or_else(|| anyhow::anyhow!("probe clock overflow"))?;
        ensure!(
            self.version == 1
                && hexadecimal(&self.run_id, 32)
                && hexadecimal(&self.nonce, 64)
                && digest_string(&self.source_digest)
                && digest_string(&self.configuration_digest)
                && digest_string(&self.cohort_digest),
            "probe shape differs"
        );
        ensure!(
            self.source_digest == source
                && self.configuration_digest == configuration
                && self.run_id == run,
            "probe context differs"
        );
        ensure!(
            clock.uncertainty >= 0
                && self.issued_at >= 0
                && clock.observed_at >= self.issued_at
                && latest < self.expires_at
                && self
                    .expires_at
                    .checked_sub(self.issued_at)
                    .is_some_and(|span| (1..=30).contains(&span)),
            "probe original window expired or rolled back"
        );
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureConfiguration {
    version: u8,
    run_id: String,
    isolate_label: String,
    installations: Vec<IssuerInstallation>,
}

impl FixtureConfiguration {
    fn validate(&self, object: &super::super::config::Config) -> Result<()> {
        object.validate()?;
        ensure!(
            self.version == 1
                && hexadecimal(&self.run_id, 32)
                && hexadecimal(&self.isolate_label, 32)
                && !self.installations.is_empty()
                && self.installations.len() <= 16
                && object.cohorts.len() == 32
                && object.clock_uncertainty == 2
                && matches!(object.timing_profile.maximum_lifetime.get(), 8 | 120),
            "scale fixture requires exact configured geometry"
        );
        let mut identities = std::collections::BTreeSet::new();
        for installation in &self.installations {
            installation.validate()?;
            ensure!(
                installation.executor_identity == object.executor_identity
                    && identities.insert(digest(installation)?)
                    && object
                        .cohorts
                        .iter()
                        .any(|cohort| cohort.authority == installation.authority),
                "fixture installation differs, repeats, or has no configured cohort"
            );
        }
        for cohort in &object.cohorts {
            ensure!(
                self.installations
                    .iter()
                    .filter(|installation| installation.authority == cohort.authority)
                    .count()
                    == 1,
                "configured cohort has no unique installed issuer"
            );
        }
        Ok(())
    }
}

fn hexadecimal(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn domain_body(domain: &[u8], body: &[u8]) -> Result<Vec<u8>> {
    ensure!(body.len() <= BODY_LIMIT, "probe body exceeds bound");
    let mut bytes = Vec::with_capacity(domain.len() + body.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(body);
    Ok(bytes)
}

#[cfg(target_arch = "wasm32")]
mod runtime {
    use super::*;
    use aos_hub_core::storage_authority::lease::EpochLeaseFloor;
    use futures_util::future::{select, Either};
    use futures_util::pin_mut;
    use sha2::{Digest as _, Sha256};
    use worker::{Env, Method, Request, Response};

    pub(crate) async fn fetch(request: Request, env: &Env) -> worker::Result<Response> {
        match execute(request, env).await {
            Ok(response) => Ok(response),
            Err(_) => Response::error("lease acquisition measurement refused", 409),
        }
    }

    async fn execute(mut request: Request, env: &Env) -> Result<Response> {
        ensure!(
            request.method() == Method::Post && request.url()?.query().is_none(),
            "probe transport differs"
        );
        let signature = request
            .headers()
            .get(SIGNATURE_HEADER)?
            .ok_or_else(|| anyhow::anyhow!("probe signature absent"))?;
        let declared = request
            .headers()
            .get("content-length")?
            .ok_or_else(|| anyhow::anyhow!("probe length absent"))?
            .parse::<usize>()?;
        ensure!(declared <= BODY_LIMIT, "probe request exceeds bound");
        let body = crate::direct_digest::read_bounded_native(
            Response::from_stream(request.stream()?)?,
            BODY_LIMIT,
        )
        .await?;
        ensure!(body.len() == declared, "probe framing differs");
        let key = StorageWorkKey::new(env.secret("HUB_STORAGE_WORK_KEY")?.to_string())?;
        key.verify_body(&signature, &domain_body(REQUEST_DOMAIN, &body)?)?;
        let request: ProbeRequest = serde_json::from_slice(&body)?;
        ensure!(
            serde_json::to_vec(&request)? == body,
            "probe request is not canonical"
        );
        let source = option_env!("AOS_HUB_WORKER_SOURCE_DIGEST")
            .filter(|source| digest_string(source))
            .ok_or_else(|| anyhow::anyhow!("compiled probe source absent"))?;
        let object = super::super::super::config::configured(env)?
            .ok_or_else(|| anyhow::anyhow!("configured cohorts absent"))?;
        let raw = env.var("HUB_LEASE_SCALE_FIXTURE")?.to_string();
        ensure!(
            raw.len() <= 128 * 1024,
            "fixture configuration exceeds bound"
        );
        let fixture: FixtureConfiguration = serde_json::from_str(&raw)?;
        fixture.validate(&object)?;
        let configuration = digest(&(&object, &fixture))?;
        request.check(source, &configuration, &fixture.run_id, object.clock())?;
        let cohort = object.cohort(&request.cohort_digest)?;
        let installation = fixture
            .installations
            .iter()
            .find(|installation| installation.authority == cohort.authority)
            .ok_or_else(|| anyhow::anyhow!("configured issuer absent"))?;
        let prefix = &cohort.admitted_prefix;
        let latest = object
            .clock()
            .observed_at
            .checked_add(object.clock_uncertainty)
            .ok_or_else(|| anyhow::anyhow!("probe clock overflow"))?;
        let remaining = u64::try_from(
            request
                .expires_at
                .checked_sub(latest)
                .ok_or_else(|| anyhow::anyhow!("probe deadline overflow"))?,
        )?;
        let acquire = super::super::planning::acquire_configured_lease(
            env,
            &object,
            installation,
            cohort,
            prefix,
        );
        let deadline = worker::Delay::from(std::time::Duration::from_secs(remaining));
        pin_mut!(acquire, deadline);
        let token = match select(acquire, deadline).await {
            Either::Left((result, _)) => result?,
            Either::Right(_) => anyhow::bail!("probe original deadline elapsed"),
        };
        request.check(source, &configuration, &fixture.run_id, object.clock())?;
        // This temporary cache-validation floor is never persisted, handed to
        // an effect executor, or used to claim physical namespace readiness.
        let scope = if prefix.is_empty() {
            "lease-cache-probe".to_owned()
        } else {
            format!("{prefix}/lease-cache-probe")
        };
        let floor = EpochLeaseFloor::initialize_fresh_guard(
            cohort.authority.clone(),
            object.executor_identity.clone(),
            scope.clone(),
            &object.timing_profile,
            object.clock(),
        )?;
        let effect = *cohort
            .allowed_effects
            .first()
            .ok_or_else(|| anyhow::anyhow!("configured effect absent"))?;
        let payload = object
            .verifier()?
            .validate_lease(
                token.as_bytes(),
                cohort,
                &object.timing_profile,
                &floor,
                &scope,
                effect,
                object.clock(),
            )?
            .payload;
        let encoded = serde_json::to_vec(&serde_json::json!({
            "version": 1, "runId": fixture.run_id, "isolateLabel": fixture.isolate_label,
            "nonce": request.nonce, "requestSha256": hex::encode(Sha256::digest(&body)),
            "sourceDigest": source, "configurationDigest": configuration,
            "cohortDigest": request.cohort_digest, "leaseDigest": hex::encode(Sha256::digest(token.as_bytes())),
            "leaseSequence": payload.lease_sequence.get(), "issuedAt": payload.issued_at.get(),
            "notAfter": payload.not_after.get(), "attestationValidUntil": cohort.attestation_valid_until.get(),
            "maximumLifetime": object.timing_profile.maximum_lifetime.get(),
            "clockUncertainty": object.clock_uncertainty, "observedAt": object.clock().observed_at,
        }))?;
        request.check(source, &configuration, &fixture.run_id, object.clock())?;
        let signature = key.sign_body(&domain_body(REPLY_DOMAIN, &encoded)?)?;
        let mut response = Response::from_bytes(encoded)?;
        response
            .headers_mut()
            .set("content-type", "application/json")?;
        response.headers_mut().set(SIGNATURE_HEADER, &signature)?;
        Ok(response)
    }
}

#[cfg(target_arch = "wasm32")]
pub(crate) use runtime::fetch;

#[cfg(test)]
mod tests;
