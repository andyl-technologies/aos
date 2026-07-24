//! Provisioning-input authorization and first-boot extraction.
//!
//! Fetchers write exact user-data bytes without interpreting them. This module
//! is the only path that turns those bytes into an evaluator-visible
//! `host.nix` or transient storage definitions. The trust decision therefore
//! precedes every destructive interpretation.
//!
//! ```json
//! {
//!   "schema": "aos.provisioning/v1",
//!   "host_nix": {
//!     "url": "https://config.example/hosts/i-123.nix",
//!     "sha256": "0123456789abcdef..."
//!   },
//!   "storage": {
//!     "partitions": [
//!       {
//!         "label": "var",
//!         "type": "var",
//!         "size_min_bytes": 4294967296,
//!         "grow": true,
//!         "format": "ext4"
//!       }
//!     ]
//!   }
//! }
//! ```

use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::config_trust::{PROVISIONING_SIGNATURE_NAMESPACE, authenticate_config_payload};

use super::http::MetadataHttp;
use super::repart::{StoragePlan, render_storage_plan};
use super::stash::{Stash, sha256_hex};

/// Provisioning-bundle schema identifier.
pub const PROVISIONING_SCHEMA: &str = "aos.provisioning/v1";
/// Raw user-data filename written by the fetch phase.
pub const RAW_USER_DATA_FILE: &str = "user-data";
/// Detached signature over the exact raw user-data bytes.
pub const RAW_USER_DATA_SIGNATURE_FILE: &str = "user-data.sig";
/// Authorization record consumed by stage 2.
pub const PROVISIONING_RESULT_FILE: &str = ".provisioning-result.json";

/// Trust policy applied to provisioning input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProvisioningTrust {
    /// Trust successful delivery by the detected deployment platform.
    Platform,
    /// Require an SSHSIG over the complete input.
    Signed,
}

impl ProvisioningTrust {
    /// Stable serialized policy name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Platform => "platform",
            Self::Signed => "signed",
        }
    }
}

impl FromStr for ProvisioningTrust {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "platform" => Ok(Self::Platform),
            "signed" => Ok(Self::Signed),
            _ => bail!("unknown provisioning trust policy '{value}'"),
        }
    }
}

/// Complete authenticated provisioning bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningBundle {
    /// Must equal [`PROVISIONING_SCHEMA`].
    pub schema: String,
    /// Operator host configuration source.
    pub host_nix: HostNixSource,
    /// Optional typed first-boot storage plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<StoragePlan>,
}

/// Inline or content-pinned host configuration source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostNixSource {
    /// Inline literal Nix. Exactly one of `inline` and `url` is required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inline: Option<String>,
    /// URL for a larger host module.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Mandatory lowercase-hex SHA-256 pin when `url` is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// Result of accepting provisioning input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningResult {
    /// Applied trust policy.
    pub trust_mode: ProvisioningTrust,
    /// Detected platform that delivered the input.
    pub platform_id: String,
    /// SHA-256 of the exact authorized input bytes.
    pub input_sha256: String,
    /// SHA-256 of the exact stage-2 `host.nix`.
    pub host_nix_sha256: String,
    /// Matching trusted-key fingerprint in signed mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    /// Whether a custom storage plan was rendered.
    pub storage_plan_rendered: bool,
}

/// Options for provisioning authorization.
pub struct AuthorizeOptions {
    /// Metadata stash root.
    pub stash_dir: PathBuf,
    /// Measured boot keeps `/var` raw for the LUKS enrollment path.
    pub measured_boot: bool,
    /// Measured policy selected by the image.
    pub trust: ProvisioningTrust,
    /// Public signed-mode anchors available in initrd.
    pub trusted_config_key_dirs: Vec<PathBuf>,
}

/// Authorize the fetched input and produce `host.nix` plus optional repart
/// definitions.
///
/// No user-data is a successful no-op, selecting the image-baked layout. A
/// missing fetch result, malformed bundle, trust failure, content-pin failure,
/// or invalid declared storage plan is fail-closed.
///
/// # Errors
///
/// Returns an error for every failed prerequisite or authorization step. On
/// error, no evaluator-visible host file or transient repart directory remains.
pub async fn run_authorize(
    opts: &AuthorizeOptions,
    http: &dyn MetadataHttp,
) -> Result<Option<ProvisioningResult>> {
    let stash = Stash::open(&opts.stash_dir)?;
    stash.clear_authorized_outputs()?;
    match authorize_inner(&stash, opts, http).await {
        Ok(result) => Ok(result),
        Err(error) => {
            stash
                .clear_authorized_outputs()
                .context("clearing partial provisioning outputs after authorization failure")?;
            Err(error)
        }
    }
}

async fn authorize_inner(
    stash: &Stash,
    opts: &AuthorizeOptions,
    http: &dyn MetadataHttp,
) -> Result<Option<ProvisioningResult>> {
    // A completed fetch record distinguishes "no user-data" from a transport
    // failure that left the stash incomplete.
    if !stash.dir().join(".metadata-result.json").is_file() {
        bail!("metadata fetch did not complete; refusing first-boot provisioning");
    }

    let raw_path = stash.dir().join(RAW_USER_DATA_FILE);
    if !raw_path.is_file() {
        return Ok(None);
    }
    let raw = std::fs::read(&raw_path).context("reading fetched user-data")?;
    let sig = std::fs::read_to_string(stash.dir().join(RAW_USER_DATA_SIGNATURE_FILE)).ok();
    let env = stash.read_platform_env()?;

    let signer = match opts.trust {
        ProvisioningTrust::Platform => None,
        ProvisioningTrust::Signed => Some(
            authenticate_config_payload(
                &raw,
                sig.as_deref(),
                &opts.trusted_config_key_dirs,
                PROVISIONING_SIGNATURE_NAMESPACE,
            )
            .map_err(anyhow::Error::new)
            .context("authorizing signed provisioning input")?
            .operator_key,
        ),
    };

    let (host_nix, storage) = parse_authorized_input(&raw, http).await?;
    let host_nix_sha256 = sha256_hex(&host_nix);

    let storage_plan_rendered = match storage {
        Some(plan) => {
            render_storage_plan(stash.dir(), &plan, opts.measured_boot)?;
            true
        }
        None => false,
    };
    std::fs::write(stash.dir().join("host.nix"), &host_nix).context("writing accepted host.nix")?;

    let result = ProvisioningResult {
        trust_mode: opts.trust,
        platform_id: env.platform_id,
        input_sha256: sha256_hex(&raw),
        host_nix_sha256,
        signer,
        storage_plan_rendered,
    };
    let encoded = serde_json::to_vec_pretty(&result).context("serializing provisioning result")?;
    std::fs::write(stash.dir().join(PROVISIONING_RESULT_FILE), encoded)
        .context("writing provisioning result")?;
    Ok(Some(result))
}

/// Verify that stage 2 is consuming the exact host bytes accepted in initrd.
///
/// # Errors
///
/// Returns an error when the record or host file is missing, malformed, or has
/// a different SHA-256.
pub fn verify_host_binding(stash_dir: &Path) -> Result<()> {
    let record: ProvisioningResult = serde_json::from_slice(
        &std::fs::read(stash_dir.join(PROVISIONING_RESULT_FILE))
            .context("reading provisioning result")?,
    )
    .context("parsing provisioning result")?;
    let host = std::fs::read(stash_dir.join("host.nix")).context("reading accepted host.nix")?;
    let actual = sha256_hex(&host);
    if actual != record.host_nix_sha256 {
        bail!(
            "accepted host.nix hash mismatch: expected {}, got {}",
            record.host_nix_sha256,
            actual
        );
    }
    Ok(())
}

async fn parse_authorized_input(
    raw: &[u8],
    http: &dyn MetadataHttp,
) -> Result<(Vec<u8>, Option<StoragePlan>)> {
    match serde_json::from_slice::<serde_json::Value>(raw) {
        Ok(value)
            if value.get("schema").is_some()
                || value.get("host_nix").is_some()
                || value.get("storage").is_some() =>
        {
            let bundle: ProvisioningBundle =
                serde_json::from_value(value).context("parsing aos.provisioning/v1 bundle")?;
            if bundle.schema != PROVISIONING_SCHEMA {
                bail!(
                    "unsupported provisioning schema '{}'; expected '{}'",
                    bundle.schema,
                    PROVISIONING_SCHEMA
                );
            }
            let host_nix = resolve_host_nix(bundle.host_nix, http).await?;
            Ok((host_nix, bundle.storage))
        }
        Ok(_) | Err(_) => Ok((raw.to_vec(), None)),
    }
}

async fn resolve_host_nix(source: HostNixSource, http: &dyn MetadataHttp) -> Result<Vec<u8>> {
    match (source.inline, source.url, source.sha256) {
        (Some(inline), None, None) => Ok(inline.into_bytes()),
        (None, Some(url), Some(sha256)) => http
            .get_pinned(&url, &sha256, &[])
            .await
            .with_context(|| format!("fetching pinned host.nix {url}"))?
            .into_ok_body()
            .ok_or_else(|| anyhow::anyhow!("pinned host.nix {url} returned no body")),
        (Some(_), Some(_), _) => bail!("host_nix must set exactly one of inline or url"),
        (None, Some(_), None) => bail!("host_nix.url requires sha256"),
        (Some(_), None, Some(_)) => bail!("host_nix.inline must not set sha256"),
        (None, None, _) => bail!("host_nix must set exactly one of inline or url"),
    }
}
