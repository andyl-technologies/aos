//! Exact-`host.nix` authorization and the restricted first-boot projection.
//!
//! Fetchers write user-data bytes without interpreting them. Authorization
//! authenticates those complete bytes and promotes them, unchanged, to
//! `host.nix`. A separate restricted Nix evaluation then projects only
//! `aos.provisioning` from that module and hands the resulting JSON to the
//! strict Rust storage validator.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::config_trust::{CONFIG_SIGNATURE_NAMESPACE, authenticate_config_payload};

use super::repart::{
    FALLBACK_LABEL, OPERATOR_LABEL, PENDING_LABEL, ProvisioningPlan, render_provisioning_plan,
};
use super::stash::{Stash, sha256_hex};

/// Raw user-data filename written by the fetch phase.
pub const RAW_USER_DATA_FILE: &str = "user-data";
/// Detached signature over the exact raw user-data bytes.
pub const RAW_USER_DATA_SIGNATURE_FILE: &str = "user-data.sig";
/// Authorization record consumed by stage 2.
pub const PROVISIONING_RESULT_FILE: &str = ".provisioning-result.json";

/// Trust policy applied to `host.nix`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProvisioningTrust {
    /// Trust successful delivery by the detected deployment platform.
    Platform,
    /// Require an SSHSIG over the complete `host.nix`.
    Signed,
}

impl ProvisioningTrust {
    /// Returns the stable serialized policy name.
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

/// Result of accepting exact `host.nix` bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningResult {
    /// Applied trust policy.
    pub trust_mode: ProvisioningTrust,
    /// Detected platform that delivered the input.
    pub platform_id: String,
    /// SHA-256 of the exact authorized `host.nix` bytes.
    pub host_nix_sha256: String,
    /// Matching trusted-key fingerprint in signed mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
}

/// Options for exact-`host.nix` authorization.
pub struct AuthorizeOptions {
    /// Metadata stash root.
    pub stash_dir: PathBuf,
    /// Measured policy selected by the image.
    pub trust: ProvisioningTrust,
    /// Public signed-mode anchors available in initrd.
    pub trusted_config_key_dirs: Vec<PathBuf>,
}

/// Options for the restricted one-time provisioning evaluation.
pub struct EvalProvisioningOptions {
    /// Metadata stash root containing the accepted `host.nix`, when present.
    pub stash_dir: PathBuf,
    /// ABI-pinned base module library embedded in the image.
    pub base_lib: PathBuf,
    /// Scratch directory made visible to restricted evaluation.
    pub eval_root: PathBuf,
    /// Whether measured boot requires `/var` to remain raw.
    pub measured_boot: bool,
    /// Existing committed source when evaluating advisory post-commit drift.
    pub committed_source: Option<ProvisioningSource>,
}

/// Provenance arm recorded in the durable GPT marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProvisioningSource {
    /// Storage intent came from authenticated `host.nix`.
    Operator,
    /// No host input existed, so the image schema defaults were used.
    Fallback,
}

impl ProvisioningSource {
    /// Returns the stable source name used by files and CLI arguments.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Fallback => "fallback",
        }
    }

    /// Returns the durable GPT label for this source.
    pub fn committed_label(self) -> &'static str {
        match self {
            Self::Operator => OPERATOR_LABEL,
            Self::Fallback => FALLBACK_LABEL,
        }
    }
}

impl FromStr for ProvisioningSource {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "operator" => Ok(Self::Operator),
            "fallback" => Ok(Self::Fallback),
            _ => bail!("unknown provisioning source '{value}'"),
        }
    }
}

/// Authorizes fetched user-data as literal `host.nix`.
///
/// No user-data is a successful no-op. Any present payload is copied byte for
/// byte after the selected trust policy succeeds. There is no second storage
/// language and no JSON envelope to unwrap.
///
/// # Errors
///
/// Returns an error when fetch did not complete, signature authentication
/// fails, or authorized outputs cannot be replaced.
pub fn run_authorize(opts: &AuthorizeOptions) -> Result<Option<ProvisioningResult>> {
    let stash = Stash::open(&opts.stash_dir)?;
    stash.clear_authorized_outputs()?;
    match authorize_inner(&stash, opts) {
        Ok(result) => Ok(result),
        Err(error) => {
            stash
                .clear_authorized_outputs()
                .context("clearing partial provisioning outputs after authorization failure")?;
            Err(error)
        }
    }
}

fn authorize_inner(stash: &Stash, opts: &AuthorizeOptions) -> Result<Option<ProvisioningResult>> {
    if !stash.dir().join(".metadata-result.json").is_file() {
        bail!("metadata fetch did not complete; refusing first-boot provisioning");
    }

    let raw_path = stash.dir().join(RAW_USER_DATA_FILE);
    if !raw_path.is_file() {
        return Ok(None);
    }
    let raw = std::fs::read(&raw_path).context("reading fetched host.nix")?;
    let sig = std::fs::read_to_string(stash.dir().join(RAW_USER_DATA_SIGNATURE_FILE)).ok();
    let env = stash.read_platform_env()?;

    let signer = match opts.trust {
        ProvisioningTrust::Platform => None,
        ProvisioningTrust::Signed => Some(
            authenticate_config_payload(
                &raw,
                sig.as_deref(),
                &opts.trusted_config_key_dirs,
                CONFIG_SIGNATURE_NAMESPACE,
            )
            .map_err(anyhow::Error::new)
            .context("authorizing signed host.nix")?
            .operator_key,
        ),
    };

    std::fs::write(stash.dir().join("host.nix"), &raw).context("writing accepted host.nix")?;
    let result = ProvisioningResult {
        trust_mode: opts.trust,
        platform_id: env.platform_id,
        host_nix_sha256: sha256_hex(&raw),
        signer,
    };
    let encoded = serde_json::to_vec_pretty(&result).context("serializing authorization result")?;
    std::fs::write(stash.dir().join(PROVISIONING_RESULT_FILE), encoded)
        .context("writing authorization result")?;
    Ok(Some(result))
}

/// Evaluates and renders the closed `aos.provisioning` projection.
///
/// When no `host.nix` was delivered, the same evaluator supplies the schema
/// defaults. The command enables restricted evaluation and disables
/// import-from-derivation; only the scratch root, base library, and accepted
/// host file are admitted.
///
/// # Errors
///
/// Returns an error when the restricted evaluator fails, emits malformed JSON,
/// or the strict Rust validation or renderer rejects the projection.
pub fn run_eval_provisioning(opts: &EvalProvisioningOptions) -> Result<ProvisioningPlan> {
    std::fs::create_dir_all(&opts.eval_root)
        .with_context(|| format!("creating eval root {}", opts.eval_root.display()))?;
    let host_path = opts.stash_dir.join("host.nix");
    let operator_modules = if host_path.is_file() {
        format!("[ (import {}) ]", nix_path(&host_path))
    } else {
        "[]".to_string()
    };
    let entry = opts.eval_root.join("provisioning-entry.nix");
    let expression = format!(
        "# Generated by aos metadata eval-provisioning; do not edit.\n\
         let\n\
        \x20 baseLib = import {base};\n\
        \x20 system = baseLib.evalProvisioningConfig {{\n\
        \x20   operatorModules = {operators};\n\
        \x20 }};\n\
         in {{\n\
        \x20 schema = \"aos.provisioning-plan/v1\";\n\
        \x20 storage = system.config.aos.provisioning.storage;\n\
         }}\n",
        base = nix_path(&opts.base_lib),
        operators = operator_modules,
    );
    std::fs::write(&entry, expression).with_context(|| format!("writing {}", entry.display()))?;

    let mut command = Command::new("nix-instantiate");
    command
        .args(["--store", "dummy://", "--eval", "--strict", "--json"])
        .args(["--option", "restrict-eval", "true"])
        .args(["--option", "allow-import-from-derivation", "false"])
        .arg("-I")
        .arg(&opts.eval_root)
        .arg("-I")
        .arg(&opts.base_lib);
    if host_path.is_file() {
        command.arg("-I").arg(&host_path);
    }
    let output = command
        .arg(&entry)
        .output()
        .context("spawning restricted provisioning evaluation")?;
    if !output.status.success() {
        bail!(
            "restricted provisioning evaluation failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let plan: ProvisioningPlan =
        serde_json::from_slice(&output.stdout).context("parsing evaluated provisioning plan")?;
    let source = if host_path.is_file() {
        ProvisioningSource::Operator
    } else {
        ProvisioningSource::Fallback
    };
    if let Some(committed) = opts.committed_source
        && committed != source
    {
        bail!(
            "current storage source '{}' differs from committed source '{}'",
            source.as_str(),
            committed.as_str()
        );
    }
    let marker_label = opts
        .committed_source
        .map_or(PENDING_LABEL, ProvisioningSource::committed_label);
    render_provisioning_plan(&opts.stash_dir, &plan, opts.measured_boot, marker_label)?;
    std::fs::write(
        opts.stash_dir.join("provisioning-source"),
        format!("{}\n", source.as_str()),
    )
    .context("writing provisioning source")?;
    Ok(plan)
}

/// Verifies that stage 2 is consuming the exact host bytes accepted in initrd.
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

fn nix_path(path: &Path) -> String {
    path.to_string_lossy().replace(' ', "\\ ")
}
