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
use aos_metadata::{Stash, stash::sha256_hex};
use aos_storage_provisioning::{
    CanonicalProvisioningPlan, CanonicalProvisioningSource, ProvisioningMarkerObservation,
    ProvisioningMarkerState, canonicalize_provisioning_plan,
    validate_provisioning_marker_observation,
};
use rand::RngCore as _;
use serde::{Deserialize, Serialize};

use crate::config_trust::{CONFIG_SIGNATURE_NAMESPACE, authenticate_config_payload};

use super::repart::ProvisioningPlan;

/// Raw user-data filename written by the fetch phase.
pub const RAW_USER_DATA_FILE: &str = "user-data";
/// Detached signature over the exact raw user-data bytes.
pub const RAW_USER_DATA_SIGNATURE_FILE: &str = "user-data.sig";
/// Authorization record consumed by stage 2.
pub const PROVISIONING_RESULT_FILE: &str = ".provisioning-result.json";

fn generate_marker_uuid() -> String {
    let mut bytes = [0_u8; 16];
    // This UUID is generated once while authoring the durable provisioning
    // plan and is then carried as checked input. It is not a simulation or
    // replay decision.
    #[allow(clippy::disallowed_methods)]
    rand::rng().fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

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
    /// Platform that supplied the exact input bytes.
    pub platform_id: String,
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
    /// Typed durable marker state observed by the selected storage provider.
    pub marker: ProvisioningMarkerObservation,
    /// Exact evaluator executable supplied by the authenticated runtime artifact.
    pub nix_instantiate: PathBuf,
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
    clear_authorized_outputs(&stash)?;
    match authorize_inner(&stash, opts) {
        Ok(result) => Ok(result),
        Err(error) => {
            clear_authorized_outputs(&stash)
                .context("clearing partial provisioning outputs after authorization failure")?;
            Err(error)
        }
    }
}

fn clear_authorized_outputs(stash: &Stash) -> Result<()> {
    for file in ["host.nix", PROVISIONING_RESULT_FILE] {
        let path = stash.dir().join(file);
        if path.exists() {
            std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
        }
    }
    Ok(())
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
        platform_id: opts.platform_id.clone(),
        host_nix_sha256: sha256_hex(&raw),
        signer,
    };
    let encoded = serde_json::to_vec_pretty(&result).context("serializing authorization result")?;
    std::fs::write(stash.dir().join(PROVISIONING_RESULT_FILE), encoded)
        .context("writing authorization result")?;
    Ok(Some(result))
}

/// Evaluates and validates the closed `aos.provisioning` projection.
///
/// When no `host.nix` was delivered, the same evaluator supplies the schema
/// defaults. The command enables restricted evaluation and disables
/// import-from-derivation; only the scratch root, base library, and accepted
/// host file are admitted.
///
/// # Errors
///
/// Returns an error when the restricted evaluator fails, emits malformed JSON,
/// or strict semantic validation rejects the projection.
pub fn run_eval_provisioning(opts: &EvalProvisioningOptions) -> Result<CanonicalProvisioningPlan> {
    evaluate_canonical_provisioning_plan(opts)
}

/// Evaluates one authenticated provisioning intent into the canonical ability plan.
///
/// Returns the typed runtime value without materializing provider-specific
/// repart definitions or a cross-provider plan file.
///
/// # Errors
///
/// Returns an error when restricted evaluation fails, the intent violates the
/// closed storage policy, or marker-derived UUID normalization fails.
pub fn evaluate_canonical_provisioning_plan(
    opts: &EvalProvisioningOptions,
) -> Result<CanonicalProvisioningPlan> {
    let EvaluatedProvisioning {
        plan,
        source,
        marker_uuid,
    } = evaluate_provisioning(opts)?;
    canonicalize_provisioning_plan(plan, source, opts.measured_boot, &marker_uuid)
}

struct EvaluatedProvisioning {
    plan: ProvisioningPlan,
    source: CanonicalProvisioningSource,
    marker_uuid: String,
}

fn evaluate_provisioning(opts: &EvalProvisioningOptions) -> Result<EvaluatedProvisioning> {
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
        "# Generated by the typed storage-provisioning evaluator; do not edit.\n\
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

    let mut command = Command::new(&opts.nix_instantiate);
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
        CanonicalProvisioningSource::Operator
    } else {
        CanonicalProvisioningSource::Fallback
    };
    let marker_uuid = marker_uuid_for_source(&opts.marker, source)?;

    Ok(EvaluatedProvisioning {
        plan,
        source,
        marker_uuid,
    })
}

fn marker_uuid_for_source(
    marker: &ProvisioningMarkerObservation,
    source: CanonicalProvisioningSource,
) -> Result<String> {
    validate_provisioning_marker_observation(marker)?;
    match marker.state {
        ProvisioningMarkerState::Absent => Ok(generate_marker_uuid()),
        ProvisioningMarkerState::Completed => {
            let committed = marker.source.context("completed marker has no source")?;
            if committed != source {
                bail!("current storage source differs from the committed provisioning source");
            }
            marker
                .marker_uuid
                .clone()
                .context("completed marker has no UUID")
        }
        ProvisioningMarkerState::Pending => {
            bail!("pending provisioning marker requires explicit recovery")
        }
        ProvisioningMarkerState::Indeterminate => {
            bail!("provisioning marker state is indeterminate")
        }
    }
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

#[cfg(test)]
mod marker_tests {
    use super::*;

    fn marker(
        state: ProvisioningMarkerState,
        source: Option<CanonicalProvisioningSource>,
        marker_uuid: Option<&str>,
    ) -> ProvisioningMarkerObservation {
        ProvisioningMarkerObservation {
            schema: "aos.storage.provisioning-marker-observation/v1".into(),
            state,
            source,
            marker_uuid: marker_uuid.map(str::to_string),
        }
    }

    #[test]
    fn completed_marker_must_match_the_selected_source() {
        let observed = marker(
            ProvisioningMarkerState::Completed,
            Some(CanonicalProvisioningSource::Operator),
            Some("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"),
        );

        assert!(marker_uuid_for_source(&observed, CanonicalProvisioningSource::Fallback).is_err());
        assert_eq!(
            marker_uuid_for_source(&observed, CanonicalProvisioningSource::Operator)
                .expect("matching committed marker"),
            "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        );
    }

    #[test]
    fn unfinished_marker_states_fail_closed() {
        for state in [
            ProvisioningMarkerState::Pending,
            ProvisioningMarkerState::Indeterminate,
        ] {
            let observed = marker(state, None, None);
            assert!(
                marker_uuid_for_source(&observed, CanonicalProvisioningSource::Fallback).is_err()
            );
        }
    }
}
