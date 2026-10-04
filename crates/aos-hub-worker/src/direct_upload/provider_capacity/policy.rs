//! One installed capacity for participating configured provider requests.
//!
//! The policy only restricts scheduling. Each caller authenticates its own
//! qualification or installed domain before comparing the actual bound here.
//! It cannot replace acceptance, manufacture a measured peak or grant a lease.
//!
//! ```text
//! HUB_PROVIDER_CAPACITY_POLICY = {version:1, deployment_id, source_digest,
//!                                script_version, maximum_provider_requests}
//! ```

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub(crate) mod request;

const MAX_POLICY_BYTES: usize = 4096;

/// Initial source-bound scheduling policy for participating configured requests.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Policy {
    pub(crate) version: u8,
    pub(crate) deployment_id: String,
    pub(crate) source_digest: String,
    pub(crate) script_version: String,
    pub(crate) maximum_provider_requests: u32,
}

impl Policy {
    /// Distinguishes an absent binding from a present binding with the wrong type.
    pub(crate) fn parse_binding(
        present: bool,
        raw: Option<&str>,
        deployment: &str,
        source: &str,
        script: &str,
    ) -> Result<Option<Self>> {
        if !present {
            ensure!(raw.is_none(), "absent capacity binding supplied a value");
            return Ok(None);
        }
        let raw =
            raw.ok_or_else(|| anyhow::anyhow!("provider capacity policy must be a JSON string"))?;
        Self::parse(raw, deployment, source, script).map(Some)
    }

    /// Decodes a bounded policy for the actual installed source and script.
    pub(crate) fn parse(raw: &str, deployment: &str, source: &str, script: &str) -> Result<Self> {
        ensure!(
            raw.len() <= MAX_POLICY_BYTES,
            "provider capacity policy oversized"
        );
        let policy: Self = serde_json::from_str(raw)?;
        ensure!(
            policy.version == 1
                && policy.deployment_id == deployment
                && policy.source_digest == source
                && aos_hub_core::direct_upload::valid_direct_digest(source)
                && policy.script_version == script
                && !deployment.is_empty()
                && !script.is_empty()
                && (1..=32).contains(&policy.maximum_provider_requests),
            "provider capacity policy differs from the installed source"
        );
        Ok(policy)
    }

    /// Requires equality with a genuinely qualified whole-isolate maximum.
    pub(crate) fn exact(&self, qualified: u32) -> Result<u32> {
        ensure!(
            self.maximum_provider_requests == qualified,
            "provider capacity differs from qualified configured maximum"
        );
        Ok(qualified)
    }

    /// Restricts an installed domain's admitted upper bound without widening it.
    pub(crate) fn bounded(&self, admitted: u32, minimum: u32) -> Result<u32> {
        ensure!(
            minimum > 0
                && minimum <= self.maximum_provider_requests
                && self.maximum_provider_requests <= admitted
                && admitted <= 32,
            "provider capacity exceeds admitted domain or required reservation"
        );
        Ok(self.maximum_provider_requests)
    }

    /// Commits actual initial scheduling facts without attesting their qualification.
    pub(crate) fn commitment(&self) -> Result<String> {
        Ok(hex::encode(Sha256::digest(serde_json::to_vec(&(
            "aos.shared-provider-capacity-policy.v1",
            self,
        ))?)))
    }
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn installed(env: &worker::Env) -> Result<Option<Policy>> {
    let binding = wasm_bindgen::JsValue::from_str("HUB_PROVIDER_CAPACITY_POLICY");
    let present = js_sys::Reflect::has(env.as_ref(), &binding)
        .map_err(|_| anyhow::anyhow!("provider capacity policy presence unavailable"))?;
    if !present {
        return Ok(None);
    }
    let raw = js_sys::Reflect::get(
        env.as_ref(),
        &binding,
    )
    .map_err(|_| anyhow::anyhow!("provider capacity policy unavailable"))?;
    let raw = raw.as_string();
    let source = option_env!("AOS_HUB_WORKER_SOURCE_DIGEST")
        .ok_or_else(|| anyhow::anyhow!("provider capacity source identity absent"))?;
    Policy::parse_binding(
        true,
        raw.as_deref(),
        &env.var("HUB_DEPLOYMENT_ID")?.to_string(),
        source,
        &crate::direct_upload::config::runtime_script_version(env)?,
    )
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn configure_exact(env: &worker::Env, qualified: u32) -> Result<()> {
    let maximum = match installed(env)? {
        Some(policy) => policy.exact(qualified)?,
        None => qualified,
    };
    super::configure(maximum)
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn configure_bounded(env: &worker::Env, admitted: u32, minimum: u32) -> Result<()> {
    let maximum = match installed(env)? {
        Some(policy) => policy.bounded(admitted, minimum)?,
        None => {
            ensure!(
                admitted >= minimum,
                "provider reservation exceeds installed bound"
            );
            admitted
        }
    };
    super::configure(maximum)
}

#[cfg(test)]
mod tests;
