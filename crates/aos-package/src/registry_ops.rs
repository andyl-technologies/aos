//! Registry management operations (`apr` / `apm registry`).
//!
//! This module implements the producer-side `apr` command surface for
//! maintaining AOS package registries. A registry is a git repository
//! (SHA-256 object format) whose working tree holds `registry.toml`,
//! per-package metadata under `packages/<letter>/<name>.toml`, closure
//! adjacency lists under `closures/`, and the committed signing-key roster
//! `keys.toml`. Commands operate on local authoring clones stored at
//! `~/.local/share/apm/registries/<name>/`.
//!
//! The subcommand families map onto the registry git workflow as follows:
//!
//! - **Lifecycle**: [`create`] initializes a new authoring clone;
//!   [`local_registries`] and [`authoring_clone_precious`] support
//!   `apr list`/`apr remove` over clones that have no consumer config.
//! - **Publishing**: [`publish`] introspects a Nix store path and records it
//!   in package TOML and `store/` realisation records for every
//!   closure member; [`unpublish`] removes packages, versions, or platform
//!   entries. Both commit the change (optionally SSH-signed) unless
//!   `--no-commit` is given. [`run_store`] maintains the realisation graph
//!   directly (bless/revoke/verify/backfill).
//! - **Query and integrity**: [`show`], [`packages`], [`verify`] (closure
//!   consistency), and [`validate`] (cache reachability over HTTP).
//! - **Git workflow**: [`status`], [`log`], [`diff`], [`run_branch`],
//!   [`push`], [`pull`], and [`merge`] wrap git in the registry clone.
//!   Network transports keep the host git configuration visible while all
//!   other invocations run hermetically (see `crate::gitcmd`).
//! - **Releases**: [`release`] / [`release_registry_tree`] create the signed
//!   semver release tag and generate full/delta pack artifacts for the
//!   static dumb-HTTP origin; [`tag`] and [`sign`] manage signed tags
//!   directly.
//! - **Channels**: [`run_channel`] initializes and advances 256-partition
//!   rollout channels whose partitions are signed tag payloads stored under
//!   `.git/channels/`.
//! - **Keys and trust**: [`run_keys`] manages the committed `keys.toml`
//!   roster (generate/register/add/retire, including re-signing tags after
//!   a retirement); [`run_trust`] manages the consumer-side pinned trust
//!   store.
//! - **Distribution**: [`run_cache`] generates and uploads the static Nix
//!   binary cache; [`run_origin`] uploads the static git origin files;
//!   [`run_web`] generates and uploads the static no-JS web surface.
//!
//! After any operation that adds commits or moves refs, the static
//! dumb-HTTP object store metadata is refreshed so plain-file origins stay
//! cloneable.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use aos_cache::AuthOptions;
use aos_core::nar::info as narinfo;
use aos_core::nix::aos_nix_env;
use aos_doc_model::{
    ActivationEffect, ActivationKind, ConfinementSummary, CredentialContract, DOCUMENT_FORMAT,
    DOCUMENT_SCHEMA, DocumentationIdentity, DocumentedPackage, DocumentedValue, OptionDocument,
    OptionOwner, OptionType, PackageDocumentation, PathSegment, ProseBlock, RuntimeCapability,
    RuntimeConfigArtifact, RuntimeListener, RuntimeSurface, RuntimeUnit, Section, Visibility,
};
use clap::ValueEnum as _;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use aos_core::output::{OutputMode, Printer};

use crate::config::ApmConfig;
use crate::provenance::{
    TrustedProvenanceKey, builder_id as provenance_builder_id, digest_map as provenance_digest_map,
    sha256_hex_payload, sign_statement_dsse_jsonl,
};
use crate::registry::channel::{self, PartitionMap};
use crate::registry::keys::{self, KeysToml, RevokedKey, RosterKey};
use crate::registry::membership::{CacheMembership, HeadMembership};
use crate::registry::nixcache;
use crate::registry::objectstore;
use crate::registry::pack;
use crate::registry::parse::{
    ImageCompression, ImageDelivery, ImageInfoReference, ImageStoreReference, ImageTarget,
    ImageUkiIdentity, ImageVerificationState,
};
use crate::registry::sb_certs::{self, RevokedSbCert, SbCert, SbCertsToml};
use crate::registry::state;
use crate::registry::static_upload;
use crate::registry::store::{self, DepEdge, NarBytes, Realisation, StoreMap, UpsertOutcome};
use crate::registry::tuf;
use crate::registry::verify::{TagTarget, parse_tag_object, verify_name_binding};
use crate::registry::webgen::{self, WebConfig};
use crate::security::{
    KeySource, KeyStore, TrustedKey, key_fingerprint, parse_signing_key, verify_tag_signature,
};
use crate::sshkey;
use crate::types::{
    AttestationMeta, BpfLsmPolicyMeta, CacheEntry, ConfigModuleMeta, ConfigOptionDeclaration,
    ConfigOutputMeta, ConfinementClass, DocumentationArtifactMeta, ExposeArtifactMeta, ExposeMeta,
    FEATURE_ATTESTATION_V1, FEATURE_CAPABILITY_ROUTES_V1, FEATURE_CONFIG_MODULE_V1,
    FEATURE_CONFIG_V1, FEATURE_EBPF_NET_POLICY_V1, FEATURE_EXPOSE_ARTIFACT_V1, FEATURE_EXPOSE_V1,
    FEATURE_MAC_PROFILE_V1, FEATURE_NETWORK_POLICY_V1, FEATURE_OPTIONAL_CREDENTIALS_V1,
    FEATURE_PACKAGE_DOCUMENTATION_V1, FEATURE_PERMISSIONS_V1, FEATURE_RECOVERY_UKIS_V1,
    FEATURE_RELOAD_V1, FEATURE_REQUIRES_V1, FEATURE_UKI_SLOTS_V1, ModuleAbiCompat, OwnedRoot,
    PACKAGE_META_FORMAT, PermissionsMeta, RecoveryBundleComponent, RecoveryBundleComponentId,
    RecoveryBundleManifest, RecoveryUkiEntry, RegistryConfig, RegistryFile, RegistryRootConfig,
    RegistryUploadAuthConfig, RootContribution, SbatEntry, SigningKeySource, SigningKeySpec,
    SysrootUkiEntry, UkiSlot, package_name_bucket, rfc0001_metadata_requires_provenance,
    validate_attestation_meta, validate_branch_name, validate_channel_name,
    validate_config_module_meta, validate_config_output_meta, validate_documentation_artifact_meta,
    validate_expose_artifact_meta, validate_expose_meta_for_package, validate_git_ref_name,
    validate_package_name, validate_permissions_meta, validate_platform_name,
    validate_registry_name,
};
use crate::{
    BranchCommand, CacheCommand, CacheUploadAuthArgs, ChangeCommand, ChannelCommand, KeysCommand,
    OriginCommand, SbCertsCommand, StoreCommand, TrustCommand, UploadConfigField, WebCommand,
};

#[cfg(not(test))]
const CHECKMODULE_ENV: &str = "AOS_CHECKMODULE";
#[cfg(not(test))]
const SEMODULE_PACKAGE_ENV: &str = "AOS_SEMODULE_PACKAGE";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishExposeManifest {
    expose: ExposeMeta,
    permissions: PermissionsMeta,
    #[serde(default)]
    mac: Option<PublishMacProfileManifest>,
    #[serde(default, rename = "kernel")]
    _kernel: Option<Value>,
    #[serde(default, rename = "firewall")]
    _firewall: Option<Value>,
    #[serde(default, rename = "confinement")]
    _confinement: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishMacProfileManifest {
    version: u32,
    package: String,
    backend: String,
    #[serde(rename = "securityLabel")]
    security_label: String,
    #[serde(rename = "defaultDeny")]
    default_deny: bool,
    #[serde(rename = "profilePath")]
    profile_path: Option<String>,
}

/// Builder-authored config-module claims copied into the trusted companion
/// output. Publish treats these fields as assertions to cross-check against
/// the module's mechanically derived interface, never as the authority for
/// declarations or contribution paths.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishConfigModuleManifest {
    schema: String,
    module_abi_compat: ModuleAbiCompat,
    #[serde(default)]
    declares: Vec<String>,
    #[serde(default)]
    owns_roots: Vec<OwnedRoot>,
    #[serde(default)]
    contributes: Vec<RootContribution>,
    #[serde(default)]
    artifacts: crate::types::ConfigModuleArtifacts,
    #[serde(default)]
    provides_capabilities: Vec<String>,
    #[serde(default)]
    dependencies: Vec<String>,
    #[serde(default)]
    documentation: PublishDocumentationManifest,
}

/// Package-authored enrichment that cannot be inferred from option/expose
/// declarations. It is closed data copied into the trusted config companion;
/// the canonical document model performs the final deep validation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishDocumentationManifest {
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    sections: BTreeMap<String, PublishDocumentationSection>,
    #[serde(default)]
    options: BTreeMap<String, PublishOptionDocumentation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishDocumentationSection {
    title: String,
    blocks: Vec<ProseBlock>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishOptionDocumentation {
    #[serde(default)]
    activation: Option<ActivationEffect>,
    #[serde(default)]
    deprecated: Option<String>,
    #[serde(default)]
    replacement: Option<Vec<PathSegment>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct DerivedOptionDeclaration {
    path: Vec<String>,
    #[serde(rename = "pathStr")]
    path_str: String,
    #[serde(rename = "typeSig")]
    type_sig: String,
    #[serde(rename = "type")]
    option_type: OptionType,
    #[serde(default)]
    description: String,
    #[serde(default)]
    default: Option<DocumentedValue>,
    #[serde(default)]
    example: Option<DocumentedValue>,
    visibility: Visibility,
    #[serde(default, rename = "readOnly")]
    read_only: bool,
    #[serde(default)]
    contributable: bool,
    owner: String,
}

#[derive(Debug)]
struct PublishedDocumentation {
    metadata: DocumentationArtifactMeta,
    info: StorePathInfo,
}

#[derive(Debug)]
struct PublishedConfigModule {
    metadata: ConfigModuleMeta,
    authored: PublishConfigModuleManifest,
    declarations: Vec<DerivedOptionDeclaration>,
}

#[derive(Debug)]
struct CompiledSelinuxProfile {
    module: Vec<u8>,
    profile: Vec<u8>,
}

/// Resolve the registry storage directory for a given registry name.
fn registry_dir(config: &ApmConfig, registry: Option<&str>) -> Result<PathBuf> {
    let name = resolve_registry_name(config, registry)?;
    Ok(config.scope.registries_path().join(&name))
}

/// Resolve which registry to operate on.
///
/// If `registry` is specified, use it. Otherwise, if there is exactly one
/// registry, use it. Otherwise bail with an error.
fn resolve_registry_name(config: &ApmConfig, registry: Option<&str>) -> Result<String> {
    if let Some(name) = registry {
        validate_registry_name(name)?;
        return Ok(name.to_string());
    }

    // Check the registries storage directory for available clones.
    let registries_path = config.scope.registries_path();
    if registries_path.is_dir() {
        let mut names: Vec<String> = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&registries_path) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    if let Some(name) = entry.file_name().to_str() {
                        if validate_registry_name(name).is_ok() {
                            names.push(name.to_string());
                        }
                    }
                }
            }
        }
        if names.len() == 1 {
            return names
                .into_iter()
                .next()
                .context("single discovered registry name disappeared");
        }
        if names.len() > 1 {
            bail!(
                "multiple registries found ({}). Use --registry to specify one.",
                names.join(", ")
            );
        }
    }

    // Fall back to configured registries.
    if config.registries.len() == 1 {
        return Ok(config.registries[0].0.name.clone());
    }
    if config.registries.is_empty() {
        bail!("no registries configured. Add one with `apr create <name>` or `apr add <url>`.");
    }
    let names: Vec<&str> = config
        .registries
        .iter()
        .map(|(c, _)| c.name.as_str())
        .collect();
    bail!(
        "multiple registries configured ({}). Use --registry to specify one.",
        names.join(", ")
    );
}

/// Run a git command in the registry directory, returning stdout.
///
/// Runs hermetically (see [`crate::gitcmd`]): host git configuration is
/// hidden. Network transport commands must use [`git_transport`] instead.
fn git(dir: &Path, args: &[&str]) -> Result<String> {
    let output = crate::registry::porcelain::dispatch(dir, args)
        .with_context(|| format!("running git {} in {}", args.join(" "), dir.display()))?;
    if !output.success {
        bail!("git {} failed: {}", args.join(" "), output.stderr);
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Run a git network-transport command (push, pull) in the registry
/// directory, returning stdout.
///
/// Unlike [`git`], the host configuration stays visible: credential
/// helpers, proxies, and URL rewrites live there.
fn git_transport(dir: &Path, args: &[&str]) -> Result<String> {
    let output = crate::registry::porcelain::dispatch(dir, args)
        .with_context(|| format!("running git {} in {}", args.join(" "), dir.display()))?;
    if !output.success {
        bail!("git {} failed: {}", args.join(" "), output.stderr);
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Run a git command in the registry directory, returning raw stdout bytes.
fn git_raw(dir: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = crate::registry::porcelain::dispatch(dir, args)
        .with_context(|| format!("running git {} in {}", args.join(" "), dir.display()))?;
    if !output.success {
        bail!("git {} failed: {}", args.join(" "), output.stderr);
    }
    Ok(output.stdout)
}

/// Build a `nix`/`nix-store` command with the AOS Nix environment applied.
fn nix_command(program: &str) -> Command {
    let mut command = Command::new(program);
    command.envs(aos_nix_env());
    command
}

/// Run a git command that is allowed to fail, returning (success, stdout, stderr).
#[allow(dead_code)]
fn git_try(dir: &Path, args: &[&str]) -> Result<(bool, String, String)> {
    let output = crate::registry::porcelain::dispatch(dir, args)
        .with_context(|| format!("running git {} in {}", args.join(" "), dir.display()))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok((output.success, stdout, output.stderr.trim().to_string()))
}

/// A registry clone present in the scope's registry-storage directory but
/// absent from the consumer configuration (`registries.d/`).
///
/// These are typically authoring clones made by `apr create`, which never
/// writes a `registries.d` entry; without this struct `apr list` would not
/// surface them at all.
#[derive(Debug)]
pub struct LocalRegistry {
    /// Directory name, which doubles as the registry name.
    pub name: String,
    /// Absolute path to the clone.
    pub path: PathBuf,
    /// URL of the `origin` remote, when the clone is a git repository that
    /// has one configured.
    pub origin: Option<String>,
    /// Number of package definition files under `packages/`.
    pub packages: usize,
}

/// List registry clones under `registries_path` whose name is not in
/// `configured`.
///
/// Returns entries sorted by name. Missing or unreadable directories yield an
/// empty list: this feeds an informational `apr list` section, not an
/// integrity check.
pub fn local_registries(registries_path: &Path, configured: &[&str]) -> Vec<LocalRegistry> {
    let Ok(entries) = std::fs::read_dir(registries_path) else {
        return Vec::new();
    };

    let mut found = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if configured.contains(&name.as_str()) {
            continue;
        }
        let origin = git(&path, &["remote", "get-url", "origin"]).ok();
        let packages = count_package_tomls(&path.join("packages"));
        found.push(LocalRegistry {
            name,
            path,
            origin,
            packages,
        });
    }
    found.sort_by(|a, b| a.name.cmp(&b.name));
    found
}

/// Count `.toml` files anywhere under `dir`.
fn count_package_tomls(dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut count = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            count += count_package_tomls(&path);
        } else if path.extension().is_some_and(|ext| ext == "toml") {
            count += 1;
        }
    }
    count
}

/// Explain why deleting `dir` would lose work, if it would.
///
/// A directory under the registry-storage path is an authoring clone when it
/// contains a `.git` entry — consumer-side syncs only materialise plain files
/// there. Such a clone is precious when it holds uncommitted changes, has no
/// remote at all (every commit exists only here), or has commits unreachable
/// from any remote-tracking ref. Returns `Ok(None)` for consumer-extracted
/// directories and fully pushed clones.
///
/// # Errors
///
/// Fails when the directory looks like a git repository but git cannot
/// inspect it (e.g. a corrupted clone).
pub fn authoring_clone_precious(dir: &Path) -> Result<Option<String>> {
    if !dir.join(".git").exists() {
        return Ok(None);
    }

    let status = git(dir, &["status", "--porcelain"])?;
    if !status.is_empty() {
        return Ok(Some("uncommitted changes".to_string()));
    }

    if git(dir, &["remote"])?.is_empty() {
        return Ok(Some(
            "commits that exist nowhere else (no remote is configured)".to_string(),
        ));
    }

    let unpushed = git(
        dir,
        &["rev-list", "--count", "--branches", "--not", "--remotes"],
    )?;
    let unpushed: u64 = unpushed
        .parse()
        .with_context(|| format!("parsing unpushed commit count {unpushed:?}"))?;
    if unpushed > 0 {
        return Ok(Some(format!(
            "{unpushed} commit{} not pushed to any remote",
            if unpushed == 1 { "" } else { "s" },
        )));
    }

    Ok(None)
}

/// Parse a Nix store path into (name, version).
///
/// Format: `/nix/store/{hash}-{name}-{version}`
fn parse_store_path(store_path: &str) -> (String, String) {
    let basename = store_path.rsplit('/').next().unwrap_or(store_path);
    // Skip the hash prefix (32 chars + dash).
    let name_version = if basename.len() >= 33 {
        &basename[33..]
    } else {
        basename
    };

    // Split into name and version. The version is the last segment that
    // starts with a digit.
    let parts: Vec<&str> = name_version.split('-').collect();
    let mut name_parts = Vec::new();
    let mut version_parts = Vec::new();
    let mut in_version = false;

    for part in &parts {
        if !in_version
            && part
                .chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
        {
            in_version = true;
        }
        if in_version {
            version_parts.push(*part);
        } else {
            name_parts.push(*part);
        }
    }

    let name = if name_parts.is_empty() {
        name_version.to_string()
    } else {
        name_parts.join("-")
    };
    let version = version_parts.join("-");

    (
        name,
        if version.is_empty() {
            "0.0.0".into()
        } else {
            version
        },
    )
}

/// Get the first letter of a name for directory bucketing.
fn first_letter(name: &str) -> String {
    package_name_bucket(name)
}

/// Get the default platform string.
#[allow(dead_code)]
fn default_platform() -> String {
    if cfg!(target_arch = "x86_64") {
        "x86_64-linux".to_string()
    } else if cfg!(target_arch = "aarch64") {
        "aarch64-linux".to_string()
    } else {
        "x86_64-linux".to_string()
    }
}

/// Runs one stable `nix-store --query` operation for the supplied paths.
fn nix_store_query(query: &str, store_paths: &[&str]) -> Result<Vec<String>> {
    let output = nix_command("nix-store")
        .args(["--query", query])
        .args(store_paths)
        .output()
        .with_context(|| format!("running nix-store --query {query}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "nix-store --query {query} failed for {}: {}",
            store_paths.join(", "),
            stderr.trim()
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}

/// Runs a single-path `nix-store --query` operation that must return one value.
fn single_nix_store_query(query: &str, store_path: &str) -> Result<String> {
    let values = nix_store_query(query, &[store_path])?;
    if let [value] = values.as_slice() {
        return Ok(value.clone());
    }

    bail!(
        "nix-store --query {query} returned {} values for {store_path}; expected one",
        values.len()
    )
}

/// Parses ordered NAR sizes returned for an ordered set of store paths.
fn parse_nar_sizes(store_paths: &[String]) -> Result<Vec<u64>> {
    let paths: Vec<&str> = store_paths.iter().map(String::as_str).collect();
    let values = nix_store_query("--size", &paths)?;
    if values.len() != store_paths.len() {
        bail!(
            "nix-store --query --size returned {} values for {} paths",
            values.len(),
            store_paths.len()
        );
    }

    values
        .iter()
        .zip(store_paths)
        .map(|(value, path)| {
            value
                .parse::<u64>()
                .with_context(|| format!("parsing NAR size {value:?} for {path}"))
        })
        .collect()
}

/// Introspects a store path using stable `nix-store --query` operations.
fn introspect_store_path(store_path: &str) -> Result<StorePathInfo> {
    let nar_hash = single_nix_store_query("--hash", store_path)?;
    let nar_size = single_nix_store_query("--size", store_path)?
        .parse::<u64>()
        .with_context(|| format!("parsing NAR size for {store_path}"))?;

    let references = nix_store_query("--references", &[store_path])?
        .into_iter()
        .filter(|reference| reference != store_path)
        .map(|reference| extract_hash(&reference).to_string())
        .collect();

    let closure_paths = nix_store_query("--requisites", &[store_path])?;
    if closure_paths.is_empty() {
        bail!("nix-store --query --requisites returned no paths for {store_path}");
    }
    let closure_size =
        parse_nar_sizes(&closure_paths)?
            .into_iter()
            .try_fold(0_u64, |total, size| {
                total
                    .checked_add(size)
                    .ok_or_else(|| anyhow::anyhow!("closure size overflow for {store_path}"))
            })?;

    Ok(StorePathInfo {
        path: store_path.to_string(),
        nar_hash,
        nar_size,
        references,
        closure_size,
    })
}

/// Return metadata for the derivation that produced `store_path`, if known.
fn introspect_deriver(store_path: &str) -> Result<Option<StorePathInfo>> {
    let output = nix_command("nix-store")
        .args(["-q", "--deriver", store_path])
        .output()
        .with_context(|| format!("querying deriver for {store_path}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "nix-store --query --deriver failed for {store_path}: {}",
            stderr.trim()
        );
    }

    let deriver = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let Some(store_dir) = store_dir_from_store_path(store_path) else {
        return Ok(None);
    };
    if deriver.is_empty()
        || deriver == "unknown-deriver"
        || store_dir_from_store_path(&deriver) != Some(store_dir)
    {
        return Ok(None);
    }
    if !Path::new(&deriver).exists() {
        return Ok(None);
    }

    introspect_store_path(&deriver)
        .with_context(|| format!("introspecting source derivation {deriver}"))
        .map(Some)
}

/// Return the store directory portion of a Nix store path.
fn store_dir_from_store_path(path: &str) -> Option<&str> {
    let (dir, name) = path.trim_end_matches('/').rsplit_once('/')?;
    let (hash, _) = name.split_once('-')?;
    if hash.len() == 32 && hash.chars().all(|ch| ch.is_ascii_alphanumeric()) {
        Some(dir)
    } else {
        None
    }
}

/// Metadata returned by `nix-store --query` for a single store path.
#[derive(Debug)]
struct StorePathInfo {
    path: String,
    nar_hash: String,
    nar_size: u64,
    references: Vec<String>,
    closure_size: u64,
}

const RELEASE_POLICY_RELATIVE_PATH: &str = "nix-support/aos-release-policy";

/// Enforces package-authored restrictions on publishing a store-path root.
///
/// Roots whose complete runtime closure contains no AOS release-policy file
/// retain the generic publication behavior. When any closure member is marked
/// internal, an indexed policy on the aggregate root must directly reference
/// that exact component and its identity-matched corresponding-source companion
/// so static cache generation cannot omit either artifact.
fn read_release_policy(store_path: &Path) -> Result<Option<BTreeMap<String, String>>> {
    let policy_path = store_path.join(RELEASE_POLICY_RELATIVE_PATH);
    if !policy_path.exists() {
        return Ok(None);
    }
    let policy_text = fs::read_to_string(&policy_path)
        .with_context(|| format!("reading release policy {}", policy_path.display()))?;
    let mut policy = BTreeMap::new();
    for (index, line) in policy_text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or_else(|| {
            anyhow::anyhow!(
                "malformed release policy {} line {}",
                policy_path.display(),
                index + 1
            )
        })?;
        if key.is_empty()
            || value.is_empty()
            || policy.insert(key.to_owned(), value.to_owned()).is_some()
        {
            bail!(
                "malformed or duplicate field in release policy {} line {}",
                policy_path.display(),
                index + 1
            );
        }
    }
    if policy.get("policy_version").map(String::as_str) != Some("1") {
        bail!(
            "unsupported or missing policy_version in {}",
            policy_path.display()
        );
    }
    Ok(Some(policy))
}

fn validate_store_path_release_policy(info: &StorePathInfo) -> Result<()> {
    let closure_paths = runtime_closure_paths(&info.path)?;
    validate_store_path_release_policy_in_closure(info, &closure_paths)
}

fn validate_store_path_release_policy_in_closure(
    info: &StorePathInfo,
    closure_paths: &[String],
) -> Result<()> {
    let mut restricted = Vec::new();
    for member in closure_paths {
        let member_path = Path::new(member);
        let Some(policy) = read_release_policy(member_path)? else {
            continue;
        };
        match policy.get("standalone_release").map(String::as_str) {
            Some("false") => {
                if policy.get("artifact_role").map(String::as_str) != Some("internal-component") {
                    bail!("restricted closure member {member} has an invalid artifact_role");
                }
                let identity = policy.get("corresponding_source_identity").ok_or_else(|| {
                    anyhow::anyhow!(
                        "restricted closure member {member} lacks corresponding_source_identity"
                    )
                })?;
                restricted.push((member.clone(), identity.clone()));
            }
            Some("true") => {}
            _ => bail!("release policy for {member} must set standalone_release=true or false"),
        }
    }
    if restricted.is_empty() {
        return Ok(());
    }

    let root_path = Path::new(&info.path);
    let root_policy = read_release_policy(root_path)?.ok_or_else(|| {
        anyhow::anyhow!(
            "publication root {} contains restricted internal component(s) but has no aggregate release policy",
            info.path
        )
    })?;
    if root_policy.get("standalone_release").map(String::as_str) != Some("true")
        || root_policy.get("artifact_role").map(String::as_str) != Some("aggregate-release-root")
    {
        bail!(
            "publication root {} contains restricted internal component(s) but is not an aggregate release root",
            info.path
        );
    }
    let pair_count: usize = root_policy
        .get("pair_count")
        .ok_or_else(|| anyhow::anyhow!("aggregate release policy lacks pair_count"))?
        .parse()
        .context("parsing aggregate release policy pair_count")?;
    if pair_count != restricted.len() {
        bail!(
            "aggregate release policy declares {pair_count} pair(s), but closure contains {} restricted component(s)",
            restricted.len()
        );
    }
    let mut paired_members = HashSet::new();
    for index in 1..=pair_count {
        let component_field = format!("pair_{index}_component_path");
        let source_field = format!("pair_{index}_corresponding_source_path");
        let identity_field = format!("pair_{index}_identity");
        let component_path = root_policy
            .get(&component_field)
            .ok_or_else(|| anyhow::anyhow!("aggregate release policy lacks {component_field}"))?;
        let source_path = root_policy
            .get(&source_field)
            .ok_or_else(|| anyhow::anyhow!("aggregate release policy lacks {source_field}"))?;
        let identity = root_policy
            .get(&identity_field)
            .ok_or_else(|| anyhow::anyhow!("aggregate release policy lacks {identity_field}"))?;
        if !paired_members.insert(component_path.as_str()) {
            bail!("aggregate release policy repeats restricted member `{component_path}`");
        }
        if !restricted.iter().any(|(member, required_identity)| {
            member == component_path && required_identity == identity
        }) {
            bail!(
                "aggregate release policy pair {index} does not match a restricted closure member and identity"
            );
        }
        for (field, required_path) in [
            (component_field.as_str(), component_path.as_str()),
            (source_field.as_str(), source_path.as_str()),
        ] {
            if !Path::new(required_path).exists() {
                bail!("aggregate release policy names missing {field} `{required_path}`");
            }
            let required_hash = extract_hash(required_path);
            if !info
                .references
                .iter()
                .any(|reference| reference == required_hash)
            {
                bail!(
                    "release root {} does not directly retain {field} `{required_path}`; refusing publication",
                    info.path
                );
            }
        }
        let source_info = fs::read_to_string(
            Path::new(source_path).join("nix-support/qemu-crucible-source-build-info"),
        )
        .with_context(|| format!("reading corresponding-source identity from {source_path}"))?;
        if !source_info
            .lines()
            .any(|line| line == format!("qemu_build_id={identity}"))
        {
            bail!(
                "corresponding source `{source_path}` does not match restricted component identity `{identity}`"
            );
        }
    }
    Ok(())
}

fn runtime_closure_paths(store_path: &str) -> Result<Vec<String>> {
    let output = nix_command("nix-store")
        .args(["-qR", store_path])
        .output()
        .with_context(|| format!("running nix-store -qR {store_path}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("nix-store -qR failed for {store_path}: {}", stderr.trim());
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

/// Compute the full transitive closure of a store path.
///
/// Returns a list of `(store_hash, Vec<direct_dep_hashes>)` pairs in
/// dependency order (leaves first, root last).  Uses `nix-store -qR` to
/// enumerate the closure and `nix-store -q --references` for each member.
fn compute_closure(store_path: &str) -> Result<Vec<(String, Vec<String>)>> {
    let closure_paths = runtime_closure_paths(store_path)?;

    // For each path in the closure, get its direct references.
    let mut result = Vec::with_capacity(closure_paths.len());
    for path in &closure_paths {
        let ref_output = nix_command("nix-store")
            .args(["-q", "--references", path])
            .output()
            .with_context(|| format!("running nix-store -q --references {path}"))?;

        let refs: Vec<String> = if ref_output.status.success() {
            String::from_utf8_lossy(&ref_output.stdout)
                .lines()
                .filter(|l| !l.is_empty() && *l != path)
                .map(|l| extract_hash(l).to_string())
                .collect()
        } else {
            Vec::new()
        };

        result.push((extract_hash(path).to_string(), refs));
    }

    Ok(result)
}

/// Extract the store path hash from a full store path.
fn extract_hash(store_path: &str) -> &str {
    let basename = store_path.rsplit('/').next().unwrap_or(store_path);
    basename.split('-').next().unwrap_or(basename)
}

// ---------------------------------------------------------------------------
// store/ realisation-graph writing (RFC-0005)
// ---------------------------------------------------------------------------

/// Per-member NAR metadata for a runtime closure.
struct ClosureMemberNar {
    path: String,
    nar_hash: String,
    nar_size: u64,
}

/// Introspects every member of a store path's runtime closure.
fn introspect_closure_nars(store_path: &str) -> Result<Vec<ClosureMemberNar>> {
    let paths = nix_store_query("--requisites", &[store_path])?;
    if paths.is_empty() {
        bail!("nix-store --query --requisites returned no closure members for {store_path}");
    }

    // nix-store emits one result for each input path in positional order.
    // Validate the cardinality before associating metadata with paths so an
    // incomplete query can never produce a plausible but incorrect manifest.
    let path_refs: Vec<&str> = paths.iter().map(String::as_str).collect();
    let hashes = nix_store_query("--hash", &path_refs)?;
    let sizes = parse_nar_sizes(&paths)?;
    if hashes.len() != paths.len() {
        bail!(
            "nix-store --query --hash returned {} values for {} closure members",
            hashes.len(),
            paths.len()
        );
    }

    Ok(paths
        .into_iter()
        .zip(hashes)
        .zip(sizes)
        .map(|((path, nar_hash), nar_size)| ClosureMemberNar {
            path,
            nar_hash,
            nar_size,
        })
        .collect())
}

/// Run `nix store make-content-addressed --json` over a closure root and
/// return the input-addressed → content-addressed store-path-hash map for
/// every member it rewrites.
///
/// This is how the producer learns each member's CA realisation and the
/// dependency CA pins, consistently for the whole closure in one pass. It
/// realises CA paths in the local store as a side effect.
fn make_content_addressed(store_path: &str) -> Result<HashMap<String, String>> {
    let output = nix_command("nix")
        .args([
            "--extra-experimental-features",
            "nix-command ca-derivations",
            "store",
            "make-content-addressed",
            "--json",
            store_path,
        ])
        .output()
        .with_context(|| format!("running nix store make-content-addressed on {store_path}"))?;
    if !output.status.success() {
        bail!(
            "nix store make-content-addressed failed for {store_path}: {}",
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }
    let json: Value = serde_json::from_str(&String::from_utf8_lossy(&output.stdout))
        .with_context(|| format!("parsing make-content-addressed JSON for {store_path}"))?;
    let rewrites = json
        .get("rewrites")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("make-content-addressed output missing 'rewrites'"))?;
    Ok(rewrites
        .iter()
        .filter_map(|(ia_path, ca_path)| {
            ca_path.as_str().map(|ca| {
                (
                    extract_hash(ia_path).to_string(),
                    extract_hash(ca).to_string(),
                )
            })
        })
        .collect())
}

/// Counts of realisation-graph mutations performed by [`write_store_files`].
#[derive(Debug, Default, Clone, Copy)]
struct StoreWriteReport {
    /// Paths that gained their first record.
    created: usize,
    /// Paths that gained an additional realisation.
    blessed: usize,
    /// Paths whose realisation was already present, unchanged.
    unchanged: usize,
    /// Whether content addresses were filled.
    content_addressed: bool,
}

impl StoreWriteReport {
    fn merge(&mut self, other: StoreWriteReport) {
        self.created += other.created;
        self.blessed += other.blessed;
        self.unchanged += other.unchanged;
        self.content_addressed |= other.content_addressed;
    }

    fn summary(&self) -> String {
        format!(
            "{} created, {} blessed, {} unchanged{}",
            self.created,
            self.blessed,
            self.unchanged,
            if self.content_addressed {
                " (content-addressed)"
            } else {
                ""
            },
        )
    }
}

/// Write `store/` realisation records for every member of a store path's
/// runtime closure (RFC-0005).
///
/// Records each member's exact NAR bytes and dependency edges; when
/// `content_addressed`, also its CA realisation and pinned dependency CAs
/// (from `nix store make-content-addressed`). A member already recorded with
/// *different* content for the same realisation fails the whole write unless
/// `bless` is set - an unexpected mismatch at publish time is exactly the
/// divergence the graph exists to surface, so it is never merged silently.
///
/// When `content_addressed` is requested but the local Nix cannot compute CA
/// paths, the member records are still written input-addressed and a warning
/// is printed (the graph stays valid for IA consumers).
fn write_store_files(
    dir: &Path,
    store_path: &str,
    content_addressed: bool,
    bless: bool,
    printer: &Printer,
) -> Result<StoreWriteReport> {
    let closure = compute_closure(store_path)?;
    let nars = introspect_closure_nars(store_path)?;
    let nar_by_hash: HashMap<&str, &ClosureMemberNar> =
        nars.iter().map(|m| (extract_hash(&m.path), m)).collect();

    let ca_by_hash: HashMap<String, String> = if content_addressed {
        match make_content_addressed(store_path) {
            Ok(map) => map,
            Err(err) => {
                printer.warning(&format!(
                    "content-addressing unavailable for {store_path}; writing \
                     input-addressed records only ({err:#})"
                ));
                HashMap::new()
            }
        }
    } else {
        HashMap::new()
    };
    let filled_ca = !ca_by_hash.is_empty();

    let mut report = StoreWriteReport {
        content_addressed: filled_ca,
        ..Default::default()
    };

    for (ia_hash, dep_hashes) in &closure {
        let Some(member) = nar_by_hash.get(ia_hash.as_str()) else {
            bail!("no NAR metadata for closure member {ia_hash} of {store_path}");
        };
        let nar = NarBytes::from_hash(&member.nar_hash, member.nar_size)
            .with_context(|| format!("building NAR entry for {}", member.path))?;
        let deps = dep_hashes
            .iter()
            .map(|dep| DepEdge {
                dep_ia: dep.clone(),
                dep_ca: ca_by_hash.get(dep).cloned(),
            })
            .collect();
        let realisation = Realisation {
            nar,
            ca: ca_by_hash.get(ia_hash).cloned(),
            deps,
        };

        match store::upsert_realisation(dir, ia_hash, realisation.clone(), bless)? {
            UpsertOutcome::Created => report.created += 1,
            UpsertOutcome::AlreadyPresent => report.unchanged += 1,
            UpsertOutcome::Blessed => report.blessed += 1,
            UpsertOutcome::Conflict(existing) => {
                let existing = existing
                    .iter()
                    .map(|r| match &r.ca {
                        Some(ca) => format!("ca:sha256:{ca} nar:sha256:{}", r.nar.sha256_nix32),
                        None => format!("nar:sha256:{}", r.nar.sha256_nix32),
                    })
                    .collect::<Vec<_>>()
                    .join("; ");
                bail!(
                    "{} is already recorded with different content\n  registry: {existing}\n  local:    nar:sha256:{}\n\
                     A publish-time mismatch is exactly what the store/ graph exists to catch:\n\
                     either the local rebuild legitimately diverged (re-run with --bless to\n\
                     add this realisation) or one of the two builds cannot be trusted.",
                    member.path,
                    realisation.nar.sha256_nix32,
                );
            }
        }
    }

    Ok(report)
}

/// Collect every unique `store_path` from the registry's package TOML
/// files (runtime closure roots only - sources and images are covered by
/// their own TOML hashes, not the graph).
fn collect_package_store_paths(dir: &Path) -> Result<Vec<String>> {
    let packages_dir = dir.join("packages");
    let mut paths = std::collections::BTreeSet::new();
    if !packages_dir.is_dir() {
        return Ok(Vec::new());
    }

    for letter_entry in std::fs::read_dir(&packages_dir)
        .with_context(|| format!("reading {}", packages_dir.display()))?
    {
        let letter_path = letter_entry?.path();
        if !letter_path.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(&letter_path)
            .with_context(|| format!("reading {}", letter_path.display()))?
        {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            let value: toml::Value =
                toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;
            let Some(versions) = value.get("versions").and_then(|v| v.as_array()) else {
                continue;
            };
            for version in versions {
                let Some(platforms) = version.get("platforms").and_then(|v| v.as_table()) else {
                    continue;
                };
                for platform in platforms.values() {
                    if let Some(sp) = platform.get("store_path").and_then(|v| v.as_str()) {
                        paths.insert(sp.to_string());
                    }
                }
            }
        }
    }

    Ok(paths.into_iter().collect())
}

/// Whether the `GIT_AUTHOR_*`/`GIT_COMMITTER_*` environment variables fully
/// specify a commit identity. They take precedence over any git config and
/// are how hermetic environments (VM tests, build sandboxes) provide one.
fn env_commit_identity() -> bool {
    [
        "GIT_AUTHOR_NAME",
        "GIT_AUTHOR_EMAIL",
        "GIT_COMMITTER_NAME",
        "GIT_COMMITTER_EMAIL",
    ]
    .iter()
    .all(|var| std::env::var_os(var).is_some_and(|value| !value.is_empty()))
}

/// Read `key` from the host's global git config, failing when it is unset.
///
/// Registry commits record who published, so a missing identity is a setup
/// error, not something to paper over with a placeholder.
fn host_identity_value(key: &str) -> Result<String> {
    host_global_config_value(key).ok_or_else(|| {
        anyhow::anyhow!(
            "registry commits record the maintainer's identity, but git {key} is not set.\n\
             Set it with `git config --global {key} <value>`."
        )
    })
}

/// Read `key` from the host's global git configuration, returning `None`
/// when the config or key is absent or empty.
///
/// "Global" matches what `git config --global` resolves, which is *two*
/// files: the classic `~/.gitconfig` and the XDG
/// `$XDG_CONFIG_HOME/git/config` (defaulting to `~/.config/git/config`).
/// libgit2's [`git2::Config::find_global`] locates only the former, so the
/// XDG file is loaded explicitly via [`git2::Config::find_xdg`]. Skipping it
/// makes identities kept solely under `~/.config/git/config` — the
/// home-manager default — invisible. When both files set `key`, the `global`
/// level outranks `xdg`, exactly as git prioritizes the two.
fn host_global_config_value(key: &str) -> Option<String> {
    let mut config = git2::Config::new().ok()?;
    let mut loaded = false;
    if let Ok(path) = git2::Config::find_xdg() {
        loaded |= config
            .add_file(&path, git2::ConfigLevel::XDG, false)
            .is_ok();
    }
    if let Ok(path) = git2::Config::find_global() {
        loaded |= config
            .add_file(&path, git2::ConfigLevel::Global, false)
            .is_ok();
    }
    if !loaded {
        return None;
    }
    let value = config.get_string(key).ok()?;
    (!value.is_empty()).then_some(value)
}

/// Check that a commit identity is available, without touching any repo.
///
/// Used by [`create`] to refuse before creating anything on disk.
fn require_commit_identity() -> Result<()> {
    if env_commit_identity() {
        return Ok(());
    }
    for key in ["user.email", "user.name"] {
        host_identity_value(key)?;
    }
    Ok(())
}

/// Ensure the maintainer's identity is available for commits in `dir`.
///
/// Registry git invocations are hermetic (see [`crate::gitcmd`]), so an
/// identity living only in the maintainer's global config is invisible to
/// them; capture it into the clone, preserving commit attribution.
///
/// # Errors
///
/// Fails when no identity is configured in the environment, the clone, or
/// the host's global config.
fn ensure_commit_identity(dir: &Path) -> Result<()> {
    if env_commit_identity() {
        return Ok(());
    }

    for key in ["user.email", "user.name"] {
        if git(dir, &["config", key]).is_ok() {
            continue;
        }
        let host = host_identity_value(key)?;
        git(dir, &["config", key, &host])?;
    }
    Ok(())
}

/// Render `path` relative to the registry root as a UTF-8 string suitable
/// for `git add -- <path>`.
fn registry_relative_path(dir: &Path, path: &Path) -> Result<String> {
    let rel = path
        .strip_prefix(dir)
        .with_context(|| format!("{} is not under {}", path.display(), dir.display()))?;
    rel.to_str()
        .map(ToString::to_string)
        .ok_or_else(|| anyhow::anyhow!("registry path is not UTF-8: {}", path.display()))
}

/// Commit whatever is currently staged, SSH-signing the commit when
/// `signing_key` points at an OpenSSH private key.
fn commit_staged_registry(dir: &Path, message: &str, signing_key: Option<&str>) -> Result<()> {
    let _commit_lock = RegistryPublishLock::acquire_or_join_current_process(dir)?;
    validate_staged_package_toml_provenance_requirements(dir)?;
    if staged_package_provenance_transparency_validation_needed(dir)? {
        validate_staged_package_provenance_transparency_log(dir)?;
    }

    match signing_key {
        Some(key) => create_signed_commit(dir, message, key)?,
        None => {
            git(dir, &["commit", "-m", message])?;
        }
    }
    Ok(())
}

/// Create an SSH-signed commit of the current index, attaching the armored
/// signature in the `gpgsig-sha256` header git uses for SHA-256 repositories.
///
/// The signed payload is the commit object without the signature header, which
/// is exactly what [`crate::security::verify_commit_signature`] reconstructs.
fn create_signed_commit(dir: &Path, message: &str, signing_key: &str) -> Result<()> {
    let repo = git2::Repository::open(dir)
        .with_context(|| format!("opening git repository at {}", dir.display()))?;
    let mut index = repo.index().context("opening index")?;
    let tree_oid = index.write_tree().context("writing tree")?;
    let tree = repo.find_tree(tree_oid).context("reading tree")?;
    let sig = git2_identity(&repo)?;
    let parents = match repo.head() {
        Ok(head) => vec![head.peel_to_commit().context("reading HEAD commit")?],
        Err(_) => Vec::new(),
    };
    let parent_refs: Vec<&git2::Commit> = parents.iter().collect();

    let buffer = repo
        .commit_create_buffer(&sig, &sig, message, &tree, &parent_refs)
        .context("building commit object")?;
    let buffer_str = std::str::from_utf8(&buffer).context("commit object is not valid UTF-8")?;
    let armored = crate::security::sign_payload_signature(
        Path::new(signing_key),
        "git",
        buffer_str.as_bytes(),
    )?;
    let commit_oid = repo
        .commit_signed(buffer_str, &armored, Some("gpgsig-sha256"))
        .context("writing signed commit")?;

    // commit_signed writes the object but does not move any ref.
    update_head_target(&repo, commit_oid)?;
    Ok(())
}

/// Resolve the commit/tagger identity the way git does: repository (and
/// global) config first, then the `GIT_AUTHOR_*`/`GIT_COMMITTER_*` environment
/// variables that [`ensure_commit_identity`] leaves in place rather than
/// copying into config.
fn git2_identity(repo: &git2::Repository) -> Result<git2::Signature<'static>> {
    if let Ok(sig) = repo.signature() {
        return Ok(sig);
    }
    let name = std::env::var("GIT_AUTHOR_NAME")
        .or_else(|_| std::env::var("GIT_COMMITTER_NAME"))
        .map_err(|_| anyhow::anyhow!("no commit identity configured (user.name unset)"))?;
    let email = std::env::var("GIT_AUTHOR_EMAIL")
        .or_else(|_| std::env::var("GIT_COMMITTER_EMAIL"))
        .map_err(|_| anyhow::anyhow!("no commit identity configured (user.email unset)"))?;
    git2::Signature::now(&name, &email).context("building commit identity")
}

/// Point the current branch (or the unborn HEAD's target) at `oid`.
fn update_head_target(repo: &git2::Repository, oid: git2::Oid) -> Result<()> {
    let refname = match repo.head() {
        Ok(head) => head.name().context("HEAD has no name")?.to_string(),
        Err(_) => repo
            .find_reference("HEAD")
            .context("reading HEAD")?
            .symbolic_target()
            .context("reading HEAD symbolic target")?
            .context("HEAD is not symbolic")?
            .to_string(),
    };
    repo.reference(&refname, oid, true, "apr signed commit")
        .with_context(|| format!("updating {refname}"))?;
    Ok(())
}

/// Create a git commit for a constrained set of registry paths.
fn commit_registry_paths(
    dir: &Path,
    message: &str,
    paths: &[PathBuf],
    signing_key: Option<&str>,
) -> Result<()> {
    if paths.is_empty() {
        bail!("no registry paths supplied for commit");
    }

    let _commit_lock = RegistryPublishLock::acquire_or_join_current_process(dir)?;
    ensure_commit_identity(dir)?;

    let relative_paths = paths
        .iter()
        .map(|path| registry_relative_path(dir, path))
        .collect::<Result<Vec<_>>>()?;

    let mut args: Vec<&str> = vec!["add", "-A", "--"];
    args.extend(relative_paths.iter().map(String::as_str));
    git(dir, &args).with_context(|| {
        format!(
            "running git add for {} constrained path(s) in {}",
            relative_paths.len(),
            dir.display()
        )
    })?;

    commit_staged_registry(dir, message, signing_key)
}

/// Create a git commit in the registry directory.
///
/// When `signing_key` is the path to an OpenSSH Ed25519 private key, the
/// commit is SSH-signed (`gpg.format=ssh`), matching the tag-signing setup
/// in [`sign_tag`]. Clients verify head-commit signatures during sync, so
/// commits on registries with a non-empty trust roster should always be
/// signed.
fn commit_registry(dir: &Path, message: &str, signing_key: Option<&str>) -> Result<()> {
    let _commit_lock = RegistryPublishLock::acquire_or_join_current_process(dir)?;
    ensure_commit_identity(dir)?;
    git(dir, &["add", "-A"])?;
    commit_staged_registry(dir, message, signing_key)
}

/// Refresh the static dumb-HTTP object indexes after refs or commits change.
fn refresh_registry_object_store(dir: &Path) -> Result<()> {
    let _publish_lock = RegistryPublishLock::acquire_or_join_current_process(dir)?;
    objectstore::assert_sha256(dir)?;
    let releases = semver_tag_versions(dir)?;
    for release in &releases {
        objectstore::write_release_objects(dir, release, &release.to_string())
            .with_context(|| format!("preparing release object dir for {release}"))?;
    }
    objectstore::write_alternates(dir, &releases)?;
    objectstore::ensure_loose_completeness(dir)?;
    objectstore::write_index_bundles(dir)?;
    objectstore::refresh_server_info(dir)?;
    persist_image_publication_receipt(dir)?;
    Ok(())
}

/// List the registry's release versions: every git tag whose name parses
/// as semver, sorted ascending and deduplicated.
fn semver_tag_versions(dir: &Path) -> Result<Vec<semver::Version>> {
    let tags = git(dir, &["tag", "--list"])?;
    Ok(semver_versions_from_tag_list(&tags))
}

fn semver_versions_from_tag_list(tags: &str) -> Vec<semver::Version> {
    let mut versions: Vec<semver::Version> = tags
        .lines()
        .filter_map(|tag| semver::Version::parse(tag.trim()).ok())
        .collect();
    versions.sort();
    versions.dedup();
    versions
}

/// Read and parse registry.toml from a registry directory.
fn read_registry_toml(dir: &Path) -> Result<Option<RegistryRootConfig>> {
    let path = dir.join("registry.toml");
    if !path.exists() {
        return Ok(None);
    }
    let content =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let config: RegistryRootConfig =
        toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;
    Ok(Some(config))
}

/// Whether a registry records content addresses in its `store/` graph
/// (`[registry] content_addressed`, RFC-0005). Defaults to `true` when the
/// file is missing or unparsable.
fn registry_content_addressed(dir: &Path) -> bool {
    match read_registry_toml(dir) {
        Ok(Some(config)) => config.registry.content_addressed,
        _ => true,
    }
}

/// Resolves the mirror cache URLs committed in a registry's `registry.toml`.
///
/// Flattens the committed `[caches]` cache stack and returns the entries sorted
/// by descending priority, or an empty
/// list when the file is missing, unparsable, or lists no caches.
pub fn resolve_mirrors(dir: &Path) -> Vec<CacheEntry> {
    match read_registry_toml(dir) {
        Ok(Some(config)) => {
            let mut caches = config.cache_entries();
            caches.sort_by(|a, b| b.priority.cmp(&a.priority));
            caches
        }
        _ => Vec::new(),
    }
}

/// Resolves mirror cache URLs from the committed `registry.toml` plus the
/// consumer's client-side cache overrides.
///
/// The client-configured caches from `registries.d` are merged with the
/// committed entries and the combined list is sorted by descending
/// priority.
pub fn resolve_mirrors_for_registry(
    dir: &Path,
    registry: &crate::types::RegistryConfig,
) -> Vec<CacheEntry> {
    let mut caches = registry.caches.clone();
    caches.extend(resolve_mirrors(dir));
    caches.sort_by(|a, b| b.priority.cmp(&a.priority));
    caches
}

/// Build the initial `keys.toml` roster for `apr create`.
///
/// Without `--trust-key` the roster is empty. A provided trust key must
/// belong to `registry_name`; its roster id defaults to `"initial"`.
fn initial_keys_roster(
    registry_name: &str,
    trust_key: Option<&str>,
    trust_key_id: Option<&str>,
) -> Result<KeysToml> {
    let mut roster = KeysToml::default();

    let Some(trust_key) = trust_key else {
        if trust_key_id.is_some() {
            bail!("--trust-key-id requires --trust-key");
        }
        return Ok(roster);
    };

    let trust_key_id = trust_key_id.unwrap_or("initial");
    validate_roster_key_id(trust_key_id)?;

    let (key_registry, _algorithm, _public_key) = parse_signing_key(trust_key)?;
    if key_registry != registry_name {
        bail!(
            "--trust-key belongs to registry '{}', expected '{}'",
            key_registry,
            registry_name,
        );
    }

    roster.active.push(RosterKey {
        id: trust_key_id.to_string(),
        key: trust_key.to_string(),
    });
    Ok(roster)
}

// ---------------------------------------------------------------------------
// Registry Lifecycle
// ---------------------------------------------------------------------------

/// `apr create <NAME>` — initializes a new registry authoring clone.
///
/// Creates a SHA-256 git repository at `<registries>/<NAME>` with `stable`
/// as the default branch, containing a skeleton `registry.toml`, an empty
/// `packages/` tree, and a `keys.toml` roster (seeded from `--trust-key` /
/// `--trust-key-id` when given). The initial commit is SSH-signed when a
/// `--key` or `--key-id` is supplied, the static dumb-HTTP object store is
/// refreshed, and `--remote` configures an `origin` remote on the clone.
///
/// # Errors
///
/// Fails when the registry directory already exists; when `--trust-key` is
/// given without a signing key (clients verify head-commit signatures from
/// first contact, so a seeded roster requires a signed root commit); when
/// no git commit identity is configured; when the trust key id is invalid;
/// when the trust key belongs to a different registry; or when a git
/// invocation or file write fails.
#[allow(clippy::too_many_arguments)]
pub async fn create(
    config: &ApmConfig,
    name: &str,
    remote: Option<&str>,
    trust_key: Option<&str>,
    trust_key_id: Option<&str>,
    key: Option<&str>,
    key_id: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    validate_registry_name(name)?;
    let dir = config.scope.registries_path().join(name);

    if dir.exists() {
        bail!("registry '{name}' already exists at {}", dir.display());
    }

    let roster = initial_keys_roster(name, trust_key, trust_key_id)?;

    // A registry seeded with a trust roster must start with a signed
    // commit: clients verify head-commit signatures from first contact,
    // and an unsigned root commit would never validate. Refuse before
    // creating anything on disk.
    if trust_key.is_some() && key.is_none() && key_id.is_none() {
        bail!(
            "--trust-key seeds a trust roster, so the initial commit must be signed: \
             pass --key <path> (or --key-id <id>) with the maintainer's private key"
        );
    }

    // The initial commit needs a maintainer identity; likewise refuse
    // before creating anything on disk.
    require_commit_identity()?;

    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;

    printer.info(&format!("Initializing registry '{name}'..."));

    git(&dir, &["init", "--object-format=sha256"])?;
    git(&dir, &["symbolic-ref", "HEAD", "refs/heads/stable"])?;
    objectstore::assert_sha256(&dir)?;

    ensure_commit_identity(&dir)?;

    // Create initial directory structure.
    std::fs::create_dir_all(dir.join("packages"))?;

    // Write a default registry.toml.
    let registry_toml = format!(
        r#"[registry]
name = "{name}"
description = ""
"#
    );
    std::fs::write(dir.join("registry.toml"), &registry_toml)?;
    keys::write_keys_toml(&dir, &roster)?;

    let signing_key = if key.is_some() || key_id.is_some() {
        Some(resolve_producer_signing_key(
            config, &dir, name, key, key_id,
        )?)
    } else {
        None
    };

    // Initial commit.
    commit_registry(
        &dir,
        &format!("Initialize registry '{name}'"),
        signing_key.as_ref().map(|k| k.path()),
    )?;
    refresh_registry_object_store(&dir)
        .context("refreshing dumb-HTTP object store after registry creation")?;

    // Set remote if specified.
    if let Some(url) = remote {
        git(&dir, &["remote", "add", "origin", url])?;
        printer.kv("Remote", url);
    }

    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "action": "create",
            "registry": name,
            "path": dir.display().to_string(),
            "remote": remote,
            "current": current_git_branch(&dir)?,
            "head": current_git_head(&dir)?,
            "branches": git_branch_entries(&dir)?,
            "trust_key_id": trust_key.map(|_| trust_key_id.unwrap_or("initial")),
        }));
        return Ok(());
    }

    printer.success(&format!("Registry '{name}' created at {}", dir.display()));

    Ok(())
}

// ---------------------------------------------------------------------------
// Publish / Unpublish
// ---------------------------------------------------------------------------

/// `apr publish <STORE_PATH>` — records a built Nix store path in the
/// registry.
///
/// Introspects the store path (NAR hash and size, closure size, direct
/// references, and the source derivation when known), writes or merges the
/// entry in `packages/<letter>/<name>.toml`, and regenerates the closure
/// adjacency file under `closures/`. Unless `--no-commit` is set, the
/// touched paths are committed (SSH-signed when `--key`/`--key-id` is
/// given) and the dumb-HTTP object store is refreshed.
///
/// Package name, version, and platform are parsed from the store path
/// basename and can each be overridden. `--image-payload`, `--image-disk`,
/// `--image-info`, `--image-format`, and `--image-uki` groups attach explicit
/// cache artifacts and their exact canonical UKI to the platform entry;
/// `--sysroot` marks
/// the package as a system root, `--previous` records the predecessor
/// version for delta upgrades, and `--source-drv` records explicit source
/// provenance for prebuilt binaries whose deriver is not visible to Nix.
/// `--expose-manifest` records the RFC-0001 expose and permission metadata
/// rendered by the package builder. Exposed packages also emit DSSE-wrapped
/// provenance, so they must be published with `--key-id`; a raw `--key` has
/// no stable roster id for the DSSE builder identity.
///
/// `--config-module` publishes the package's config-only companion output.
/// `--config-base-lib` is required with it and records the exact options
/// library used by the restricted, no-IFD options-only evaluation. The signed
/// provenance binds the payload, config output, base lib, and (when present)
/// expose manifest in one statement.
///
/// # Errors
///
/// Fails when required package distribution metadata is missing, empty, or a
/// legacy placeholder; when the registry has no writable authoring clone;
/// when the package name is not safe for registry package paths; when the
/// platform name is not safe for package metadata; when the image arguments are not
/// given in triples or their files/metadata disagree, when the `nix path-info` /
/// `nix-store` queries fail for the store path, when `--expose-manifest`
/// cannot be parsed or validated, when the config output references a
/// derivation, when authored config metadata disagrees with the mechanically
/// evaluated/scanned interface, or when a file write, the commit, or the
/// object-store refresh fails. Policy-bearing internal components also fail
/// when published directly, and aggregate roots fail unless their restricted
/// component and corresponding source are direct runtime references.
///
#[allow(clippy::too_many_arguments)]
pub async fn publish(
    config: &ApmConfig,
    store_path: &str,
    name_override: Option<&str>,
    version_override: Option<&str>,
    platform_override: Option<&str>,
    description: Option<&str>,
    homepage: Option<&str>,
    license: Option<&str>,
    maintainer: Option<&str>,
    sysroot: bool,
    previous: Option<&str>,
    source_drv: Option<&str>,
    image_payload_paths: &[String],
    image_disk_paths: &[String],
    image_info_paths: &[String],
    image_formats: &[String],
    image_uki_paths: &[String],
    expose_manifest_path: Option<&str>,
    config_module_path: Option<&str>,
    config_base_lib_path: Option<&str>,
    config_dependencies: &[String],
    bless: bool,
    no_ca: bool,
    no_commit: bool,
    message: Option<&str>,
    key: Option<&str>,
    key_id: Option<&str>,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let description = required_publish_metadata(description, "--description", "No description")?;
    let license = required_publish_metadata(license, "--license", "unknown")?;
    let maintainer = required_publish_metadata(maintainer, "--maintainer", "unknown")?;

    let name = resolve_registry_name(config, registry)?;
    let dir = config.scope.registries_path().join(&name);
    ensure_writable_registry_clone(&name, &dir)?;
    if let Some(name) = name_override {
        validate_package_name(name)?;
    }
    let signing_key = if key.is_some() || key_id.is_some() {
        Some(resolve_producer_signing_key(
            config, &dir, &name, key, key_id,
        )?)
    } else {
        None
    };

    // Validate explicit image artifact groups.
    if image_payload_paths.len() != image_disk_paths.len()
        || image_payload_paths.len() != image_info_paths.len()
        || image_payload_paths.len() != image_formats.len()
        || image_payload_paths.len() != image_uki_paths.len()
    {
        bail!(
            "--image-payload, --image-disk, --image-info, --image-format, and --image-uki must be specified in groups ({} payloads, {} disks, {} metadata files, {} formats, {} UKIs)",
            image_payload_paths.len(),
            image_disk_paths.len(),
            image_info_paths.len(),
            image_formats.len(),
            image_uki_paths.len()
        );
    }
    if config_module_path.is_some() != config_base_lib_path.is_some() {
        bail!("--config-module and --config-base-lib must be specified together");
    }
    if config_module_path.is_none() && !config_dependencies.is_empty() {
        bail!("--config-dependency requires --config-module");
    }
    if !image_payload_paths.is_empty() && !sysroot {
        bail!("image artifact options are valid only with --sysroot");
    }

    printer.step(1, 4, "Introspecting store path...");
    let info = introspect_store_path(store_path)?;
    validate_store_path_release_policy(&info)?;
    let source_info = if let Some(source_drv) = source_drv {
        Some(
            introspect_store_path(source_drv)
                .with_context(|| format!("introspecting source derivation {source_drv}"))?,
        )
    } else {
        introspect_deriver(&info.path)?
    };

    let (parsed_name, parsed_version) = parse_store_path(&info.path);
    let pkg_name = name_override.unwrap_or(&parsed_name);
    let pkg_version = version_override.unwrap_or(&parsed_version);
    validate_package_name(pkg_name)?;
    let platform = platform_override
        .map(|s| s.to_string())
        .unwrap_or_else(default_platform);
    validate_platform_name(&platform)?;
    let config_module_info = config_module_path
        .map(introspect_store_path)
        .transpose()
        .context("introspecting config-module store path")?;
    let config_base_lib_info = config_base_lib_path
        .map(introspect_store_path)
        .transpose()
        .context("introspecting config base-lib")?;
    let config_dependency_outputs = parse_config_dependency_outputs(config_dependencies, &info)?;
    let config_module_bundle = match (config_module_info.as_ref(), config_base_lib_info.as_ref()) {
        (Some(output), Some(base_lib)) => Some(read_publish_config_module(
            output,
            base_lib,
            pkg_name,
            &info.path,
            &config_dependency_outputs,
        )?),
        (None, None) => None,
        _ => bail!("--config-module and --config-base-lib must be specified together"),
    };
    let config_module = config_module_bundle.as_ref().map(|bundle| &bundle.metadata);
    // Bind the exact disk, canonical per-format metadata, and paired UKI
    // before catalog construction. Committed Secure Boot policy is enforced
    // below.
    let sb_db_cert = sb_db_cert_path(config, &name);
    let mut image_infos: Vec<PublishedImage> = Vec::new();
    for ((((payload_path, disk_path), info_path), img_fmt), uki_path) in image_payload_paths
        .iter()
        .zip(image_disk_paths.iter())
        .zip(image_info_paths.iter())
        .zip(image_formats.iter())
        .zip(image_uki_paths.iter())
    {
        let payload_info = introspect_store_path(payload_path)?;
        let disk_info = introspect_store_path(disk_path)?;
        let metadata_info = introspect_store_path(info_path)?;
        image_infos.push(inspect_published_image(
            img_fmt,
            payload_info,
            disk_info,
            metadata_info,
            Path::new(uki_path),
            pkg_name,
            pkg_version,
            &platform,
            sb_db_cert.as_deref(),
        )?);
    }
    let sb_catalog = sb_certs::load_sb_certs_toml(&dir)?;
    apply_publish_sb_policy(&mut image_infos, sb_catalog.as_ref(), sb_db_cert.is_some())?;
    let expose_manifest = expose_manifest_path
        .map(|path| read_publish_expose_manifest(path, pkg_name))
        .transpose()?;
    let expose_artifact_info = expose_manifest_path
        .map(infer_publish_expose_artifact)
        .transpose()?;
    let expose_manifest_digest = expose_manifest_path
        .map(|path| read_publish_manifest_digest(Path::new(path)))
        .transpose()?;
    let documentation = publish_package_documentation(
        pkg_name,
        pkg_version,
        &platform,
        description,
        homepage,
        license,
        &info,
        source_info.as_ref(),
        config_module,
        config_module_bundle.as_ref().map(|bundle| &bundle.authored),
        expose_manifest.as_ref(),
        expose_artifact_info.as_ref(),
        config_module_bundle
            .as_ref()
            .map(|bundle| bundle.declarations.as_slice())
            .unwrap_or_default(),
    )?;
    let provenance_signer = Some(resolve_package_provenance_signer(
        &dir,
        &name,
        signing_key.as_ref(),
        key_id,
    )?);

    let _publish_lock = RegistryPublishLock::acquire(&dir)?;

    printer.step(2, 4, "Writing package TOML...");
    let letter = first_letter(pkg_name);
    let pkg_dir = dir.join("packages").join(&letter);
    std::fs::create_dir_all(&pkg_dir)?;

    let toml_path = pkg_dir.join(format!("{pkg_name}.toml"));

    // Read existing TOML if it exists, or create a new one.
    let content = if toml_path.exists() {
        std::fs::read_to_string(&toml_path)?
    } else {
        String::new()
    };

    let config_attestation = config_module
        .map(|module| {
            publish_config_attestation_meta(
                pkg_name,
                pkg_version,
                &platform,
                &info,
                module,
                expose_manifest_digest.as_deref(),
            )
        })
        .transpose()?;
    let documentation_attestation = if config_module.is_none() && expose_manifest.is_none() {
        Some(publish_documentation_attestation_meta(
            pkg_name,
            pkg_version,
            &platform,
            &info,
        )?)
    } else {
        None
    };
    let new_content = build_package_toml_with_documentation(
        &content,
        pkg_name,
        pkg_version,
        &platform,
        &info,
        Some(description),
        homepage,
        Some(license),
        Some(maintainer),
        sysroot,
        previous,
        &image_infos,
        source_info.as_ref(),
        expose_manifest.as_ref(),
        expose_artifact_info.as_ref(),
        expose_manifest_digest.as_deref(),
        config_module,
        config_attestation.as_ref(),
        Some(&documentation.metadata),
        documentation_attestation.as_ref(),
    )?;
    let provenance_artifact =
        if let (Some(module), Some(attestation)) = (config_module, config_attestation.as_ref()) {
            Some(publish_config_provenance_artifact_with_documentation(
                &name,
                pkg_name,
                pkg_version,
                &platform,
                &info,
                source_info.as_ref(),
                module,
                expose_manifest_digest.as_deref(),
                attestation,
                &documentation.metadata,
                provenance_signer
                    .as_ref()
                    .context("provenance signer missing for config-module package")?,
            )?)
        } else {
            match (expose_manifest.as_ref(), expose_manifest_digest.as_deref()) {
                (Some(manifest), Some(manifest_digest)) => {
                    publish_provenance_artifact_with_documentation(
                        &name,
                        pkg_name,
                        pkg_version,
                        &platform,
                        &info,
                        source_info.as_ref(),
                        manifest,
                        manifest_digest,
                        &documentation.metadata,
                        provenance_signer
                            .as_ref()
                            .context("provenance signer missing for exposed package")?,
                    )?
                }
                _ => Some(publish_documentation_provenance_artifact(
                    &name,
                    pkg_name,
                    pkg_version,
                    &platform,
                    &info,
                    source_info.as_ref(),
                    &documentation.metadata,
                    documentation_attestation
                        .as_ref()
                        .context("documentation-only package is missing attestation metadata")?,
                    provenance_signer
                        .as_ref()
                        .context("provenance signer missing for documented package")?,
                )?),
            }
        };

    std::fs::write(&toml_path, &new_content)?;
    let provenance_path = if let Some(artifact) = &provenance_artifact {
        let path = dir.join(&artifact.path);
        let parent = path
            .parent()
            .with_context(|| format!("provenance path has no parent: {}", path.display()))?;
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating provenance directory {}", parent.display()))?;
        std::fs::write(&path, &artifact.jsonl)
            .with_context(|| format!("writing provenance artifact {}", path.display()))?;
        Some(path)
    } else {
        None
    };

    printer.step(3, 4, "Computing realisation graph...");
    let content_addressed = registry_content_addressed(&dir) && !no_ca;
    let store_report = write_store_files(&dir, &info.path, content_addressed, bless, printer)
        .with_context(|| format!("writing store/ realisation graph for {}", info.path))?;
    let mut image_store_reports = Vec::with_capacity(image_infos.len() * 3);
    for image in &image_infos {
        for artifact in [&image.payload, &image.store, &image.info_store] {
            image_store_reports.push(
                write_store_files(&dir, &artifact.path, content_addressed, bless, printer)
                    .with_context(|| {
                        format!("writing store/ realisation graph for {}", artifact.path)
                    })?,
            );
        }
    }
    let expose_store_report = if let Some(artifact) = &expose_artifact_info {
        Some(
            write_store_files(&dir, &artifact.path, content_addressed, bless, printer)
                .with_context(|| {
                    format!(
                        "writing store/ realisation graph for expose artifact {}",
                        artifact.path
                    )
                })?,
        )
    } else {
        None
    };
    let config_store_report = if let Some(output) = &config_module_info {
        Some(
            write_store_files(&dir, &output.path, content_addressed, bless, printer).with_context(
                || {
                    format!(
                        "writing store/ realisation graph for config module {}",
                        output.path
                    )
                },
            )?,
        )
    } else {
        None
    };
    let documentation_store_report = write_store_files(
        &dir,
        &documentation.info.path,
        content_addressed,
        bless,
        printer,
    )
    .with_context(|| {
        format!(
            "writing store/ realisation graph for documentation {}",
            documentation.info.path
        )
    })?;
    let transparency_log_path = if let Some(artifact) = &provenance_artifact {
        let provenance_file_path = provenance_path
            .as_ref()
            .context("provenance artifact path missing before transparency log append")?;
        Some(append_package_provenance_transparency_log(
            &dir,
            pkg_name,
            pkg_version,
            &platform,
            &info,
            source_info.as_ref(),
            artifact,
            provenance_file_path,
        )?)
    } else {
        None
    };

    printer.step(4, 4, "Done.");
    printer.kv("Package", pkg_name);
    printer.kv("Version", pkg_version);
    printer.kv("Platform", &platform);
    printer.kv("Store path", &info.path);
    printer.kv("NAR hash", &info.nar_hash);
    printer.kv("NAR size", &format_size(info.nar_size));
    printer.kv("Closure size", &format_size(info.closure_size));
    printer.kv("Store graph", &store_report.summary());
    for (index, report) in image_store_reports.iter().enumerate() {
        printer.kv(
            &format!("Image artifact graph {}", index + 1),
            &report.summary(),
        );
    }
    if let Some(artifact) = &expose_artifact_info {
        printer.kv("Expose artifact", &artifact.path);
    }
    if let Some(report) = &expose_store_report {
        printer.kv("Expose artifact graph", &report.summary());
    }
    if let Some(output) = &config_module_info {
        printer.kv("Config module", &output.path);
    }
    if let Some(report) = &config_store_report {
        printer.kv("Config module graph", &report.summary());
    }
    printer.kv("Documentation", &documentation.info.path);
    printer.kv("Documentation graph", &documentation_store_report.summary());
    if let Some(artifact) = &provenance_artifact {
        printer.kv("Provenance", &artifact.path);
    }
    if let Some(path) = &transparency_log_path {
        printer.kv(
            "Transparency log",
            &path
                .strip_prefix(&dir)
                .unwrap_or(path)
                .display()
                .to_string(),
        );
    }
    if let Some(source_info) = &source_info {
        printer.kv("Source drv", &source_info.path);
    }
    if sysroot {
        printer.kv("Sysroot", "true");
    }
    if let Some(prev) = previous {
        printer.kv("Previous", prev);
    }
    for image in &image_infos {
        printer.kv(&format!("Image ({})", image.format), &image.store.path);
        printer.kv("  File", &image.delivery.filename);
        printer.kv("  SHA-256", &image.delivery.sha256);
        if let Some(cert) = &image.sb.signer_cert_sha256 {
            printer.kv(&format!("  SB signer cert ({})", image.format), cert);
        }
    }

    let mut committed = false;
    let mut commit_message = None;
    if !no_commit {
        let default_msg = format!("publish {pkg_name} {pkg_version} ({platform})");
        let msg = message.unwrap_or(&default_msg);
        let mut staged_paths = vec![toml_path.clone(), dir.join(store::STORE_DIR)];
        if let Some(path) = &provenance_path {
            staged_paths.push(path.clone());
        }
        if let Some(path) = &transparency_log_path {
            staged_paths.push(path.clone());
        }
        commit_registry_paths(
            &dir,
            msg,
            &staged_paths,
            signing_key.as_ref().map(|k| k.path()),
        )?;
        refresh_registry_object_store(&dir)
            .context("refreshing dumb-HTTP object store after publish")?;
        committed = true;
        commit_message = Some(msg.to_string());
        printer.success(&format!("Committed: {msg}"));
    } else {
        printer.info("Skipped commit (--no-commit).");
    }

    if printer.mode() == OutputMode::Json {
        let source = source_info.as_ref().map(|source| {
            serde_json::json!({
                "store_path": source.path.as_str(),
                "nar_hash": source.nar_hash.as_str(),
                "nar_size": source.nar_size,
            })
        });
        let images = image_infos
            .iter()
            .map(|image| {
                serde_json::json!({
                    "format": image.format.as_str(),
                    "store_path": image.store.path.as_str(),
                    "nar_hash": image.store.nar_hash.as_str(),
                    "nar_size": image.store.nar_size,
                    "delivery": &image.delivery,
                    "sb_signer_cert_sha256": image.sb.signer_cert_sha256,
                    "sbat": image.sb.sbat.iter().map(|item| serde_json::json!({
                        "component": item.component,
                        "generation": item.generation,
                    })).collect::<Vec<_>>(),
                    "expected_pcr11": image.sb.expected_pcr11,
                    "ukis": image.sb.ukis,
                    "recovery_ukis": image.sb.recovery_ukis,
                    "recovery_bundle": image.sb.recovery_bundle,
                })
            })
            .collect::<Vec<_>>();
        printer.json(&serde_json::json!({
            "action": "publish",
            "registry": name,
            "package": pkg_name,
            "version": pkg_version,
            "platform": platform,
            "store_path": info.path,
            "nar_hash": info.nar_hash,
            "nar_size": info.nar_size,
            "closure_size": info.closure_size,
            "store_graph": {
                "created": store_report.created,
                "blessed": store_report.blessed,
                "unchanged": store_report.unchanged,
                "content_addressed": store_report.content_addressed,
            },
            "expose_artifact": expose_artifact_info.as_ref().map(|artifact| serde_json::json!({
                "store_path": artifact.path.as_str(),
                "nar_hash": artifact.nar_hash.as_str(),
                "nar_size": artifact.nar_size,
            })),
            "expose_artifact_graph": expose_store_report.as_ref().map(|report| serde_json::json!({
                "created": report.created,
                "blessed": report.blessed,
                "unchanged": report.unchanged,
                "content_addressed": report.content_addressed,
            })),
            "provenance": provenance_artifact.as_ref().map(|artifact| artifact.path.as_str()),
            "transparency_log": transparency_log_path.as_ref().map(|path| {
                path.strip_prefix(&dir)
                    .unwrap_or(path)
                    .display()
                    .to_string()
            }),
            "references": info.references,
            "source": source,
            "sysroot": sysroot,
            "previous": previous,
            "images": images,
            "package_file": toml_path
                .strip_prefix(&dir)
                .unwrap_or(&toml_path)
                .display()
                .to_string(),
            "committed": committed,
            "commit_message": commit_message,
            "current": current_git_branch(&dir)?,
            "head": current_git_head(&dir)?,
            "branches": git_branch_entries(&dir)?,
        }));
    }

    Ok(())
}

/// Returns required package distribution metadata after rejecting historical
/// placeholders that do not describe a package.
fn required_publish_metadata<'a>(
    value: Option<&'a str>,
    flag: &str,
    legacy_placeholder: &str,
) -> Result<&'a str> {
    let value = value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("{flag} is required and must not be empty"))?;
    if value.eq_ignore_ascii_case(legacy_placeholder) {
        bail!(
            "{flag} must describe the package, not use the legacy placeholder '{legacy_placeholder}'"
        );
    }
    Ok(value)
}

/// Validates metadata for the optional package attached to a release plan.
fn validate_release_publish_metadata(
    store_path: Option<&str>,
    description: Option<&str>,
    license: Option<&str>,
    maintainer: Option<&str>,
) -> Result<()> {
    if store_path.is_some() {
        required_publish_metadata(description, "--description", "No description")?;
        required_publish_metadata(license, "--license", "unknown")?;
        required_publish_metadata(maintainer, "--maintainer", "unknown")?;
    }
    Ok(())
}

/// Requires an authenticated roster identity for a package-bearing release.
fn validate_release_publish_signing_identity(
    store_path: Option<&str>,
    key_id: Option<&str>,
) -> Result<()> {
    if store_path.is_some() && key_id.is_none() {
        bail!(
            "releasing a store path requires --key-id so package provenance is tied to keys.toml"
        );
    }
    Ok(())
}

fn apply_publish_sb_policy(
    images: &mut [PublishedImage],
    catalog: Option<&SbCertsToml>,
    has_db_cert: bool,
) -> Result<()> {
    for image in images {
        let signers = image
            .sb
            .signer_cert_sha256
            .iter()
            .map(String::as_str)
            .chain(
                image
                    .sb
                    .ukis
                    .iter()
                    .filter_map(|uki| uki.sb_signer_cert_sha256.as_deref()),
            );
        let signers = signers.chain(
            image
                .sb
                .recovery_ukis
                .iter()
                .map(|uki| uki.sb_signer_cert_sha256.as_str()),
        );
        for signer in signers {
            if let Some(catalog) = catalog {
                if !catalog.accepts_signer(signer) {
                    bail!(
                        "image UKI signer {signer} is not active in the committed sb-certs.toml policy"
                    );
                }
                if !has_db_cert {
                    bail!(
                        "committed Secure Boot policy requires the matching registry db.pem for publish-time verification"
                    );
                }
            }
        }
        if image.sb.signer_cert_sha256.is_some() && catalog.is_some() {
            image.delivery.uki.verification = ImageVerificationState::PolicyVerified;
        }
    }
    Ok(())
}

/// Require `dir` to be a git authoring clone; consumer-extracted registry
/// trees (plain files synced by `apm update`) cannot host publish commits
/// and are rejected with remediation steps.
fn ensure_writable_registry_clone(name: &str, dir: &Path) -> Result<()> {
    if dir.join(".git").is_dir() {
        return Ok(());
    }

    bail!(
        "registry '{name}' has no writable local clone at {path}.\n\
         `{pkg} update --registry {name}` only syncs consumer metadata; it cannot create an \
         APR publishing worktree.\n\
         To publish, remove and re-add the registry without `--no-clone`, or author a new \
         local registry with `{reg} create {name}`.",
        path = dir.display(),
        reg = aos_core::invocation::package_registry_command(),
        pkg = aos_core::invocation::package_manager_command(),
    );
}

/// Build package TOML content, merging with existing content if present.
///
/// A fresh file is rendered through the TOML value serializer; an existing
/// file is parsed and the version/platform entry is upserted, preserving
/// unrelated versions and platforms. Panics if an existing `versions` array
/// entry is not a table.
#[allow(clippy::too_many_arguments)]
fn build_package_toml_with_documentation(
    existing: &str,
    name: &str,
    version: &str,
    platform: &str,
    info: &StorePathInfo,
    description: Option<&str>,
    homepage: Option<&str>,
    license: Option<&str>,
    maintainer: Option<&str>,
    sysroot: bool,
    previous: Option<&str>,
    image_infos: &[PublishedImage],
    source_info: Option<&StorePathInfo>,
    expose_manifest: Option<&PublishExposeManifest>,
    expose_artifact_info: Option<&StorePathInfo>,
    expose_manifest_digest: Option<&str>,
    config_module: Option<&ConfigModuleMeta>,
    config_attestation: Option<&AttestationMeta>,
    documentation: Option<&DocumentationArtifactMeta>,
    documentation_attestation: Option<&AttestationMeta>,
) -> Result<String> {
    let desc = description.context("package description is required")?;
    let lic = license.context("package license is required")?;
    let maint = maintainer.context("package maintainer is required")?;
    let source_drv = source_info
        .map(|source| source.path.as_str())
        .unwrap_or_default();
    let source_nar_hash = source_info
        .map(|source| source.nar_hash.as_str())
        .unwrap_or_default();
    let mut platform_table = package_platform_table(
        name,
        version,
        platform,
        info,
        image_infos,
        source_drv,
        source_nar_hash,
        expose_manifest,
        expose_artifact_info,
        expose_manifest_digest,
    )?;
    if let Some(documentation) = documentation {
        let table = platform_table
            .as_table_mut()
            .context("new package platform metadata is not a TOML table")?;
        record_documentation_platform_fields(table, documentation)?;
    }
    if let Some(module) = config_module {
        let table = platform_table
            .as_table_mut()
            .context("new package platform metadata is not a TOML table")?;
        record_config_module_platform_fields(table, name, module)?;
        record_attestation_platform_fields(
            table,
            config_attestation
                .context("config-module package is missing its publish provenance attestation")?,
        )?;
    } else if let Some(attestation) = documentation_attestation {
        let table = platform_table
            .as_table_mut()
            .context("new package platform metadata is not a TOML table")?;
        record_attestation_platform_fields(table, attestation)?;
    }

    if existing.is_empty() {
        let mut package = toml::map::Map::new();
        package.insert("name".into(), toml::Value::String(name.to_string()));
        package.insert("description".into(), toml::Value::String(desc.to_string()));
        if sysroot {
            package.insert("sysroot".into(), toml::Value::Boolean(true));
        }
        if let Some(hp) = homepage {
            package.insert("homepage".into(), toml::Value::String(hp.to_string()));
        }
        package.insert("license".into(), toml::Value::String(lic.to_string()));
        package.insert("maintainer".into(), toml::Value::String(maint.to_string()));

        let mut version_table = toml::map::Map::new();
        version_table.insert("version".into(), toml::Value::String(version.to_string()));
        if let Some(prev) = previous {
            version_table.insert("previous".into(), toml::Value::String(prev.to_string()));
        }
        let mut platforms = toml::map::Map::new();
        platforms.insert(platform.to_string(), platform_table);
        version_table.insert("platforms".into(), toml::Value::Table(platforms));

        let mut root = toml::map::Map::new();
        root.insert("package".into(), toml::Value::Table(package));
        root.insert(
            "versions".into(),
            toml::Value::Array(vec![toml::Value::Table(version_table)]),
        );
        Ok(toml::to_string_pretty(&toml::Value::Table(root))?)
    } else {
        // Parse existing, add/update the version+platform entry.
        let mut toml_val: toml::Value =
            toml::from_str(existing).context("parsing existing package TOML")?;

        // Metadata describes the package across versions. Explicit values on
        // a later publication replace stale catalog values as well as the
        // historical placeholders emitted by older clients.
        if let Some(pkg) = toml_val.get_mut("package").and_then(|v| v.as_table_mut()) {
            if let Some(description) = description {
                pkg.insert(
                    "description".into(),
                    toml::Value::String(description.to_string()),
                );
            }
            if let Some(homepage) = homepage {
                pkg.insert("homepage".into(), toml::Value::String(homepage.to_string()));
            }
            if let Some(license) = license {
                pkg.insert("license".into(), toml::Value::String(license.to_string()));
            }
            if let Some(maintainer) = maintainer {
                pkg.insert(
                    "maintainer".into(),
                    toml::Value::String(maintainer.to_string()),
                );
            }
            if sysroot {
                pkg.insert("sysroot".into(), toml::Value::Boolean(true));
            }
        }

        // Ensure versions array exists.
        let versions = toml_val.get_mut("versions").and_then(|v| v.as_array_mut());

        if let Some(versions) = versions {
            // Find existing version entry.
            let existing_idx = versions.iter().position(|v| {
                v.get("version")
                    .and_then(|ver| ver.as_str())
                    .map(|ver| ver == version)
                    .unwrap_or(false)
            });

            if let Some(idx) = existing_idx {
                // Update existing version entry.
                let ver_entry = &mut versions[idx];
                let ver_table = ver_entry
                    .as_table_mut()
                    .context("existing package versions entry is not a TOML table")?;
                if let Some(prev) = previous {
                    ver_table.insert("previous".into(), toml::Value::String(prev.to_string()));
                }
                let platforms = ver_table
                    .entry("platforms")
                    .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
                platforms
                    .as_table_mut()
                    .context("existing package platforms metadata is not a TOML table")?
                    .insert(platform.to_string(), platform_table);
            } else {
                // Add new version entry.
                let mut ver_table = toml::map::Map::new();
                ver_table.insert("version".into(), toml::Value::String(version.to_string()));
                if let Some(prev) = previous {
                    ver_table.insert("previous".into(), toml::Value::String(prev.to_string()));
                }
                let mut platforms = toml::map::Map::new();
                platforms.insert(platform.to_string(), platform_table);
                ver_table.insert("platforms".into(), toml::Value::Table(platforms));
                versions.push(toml::Value::Table(ver_table));
            }
        } else {
            // No versions array yet - add one.
            let mut ver_table = toml::map::Map::new();
            ver_table.insert("version".into(), toml::Value::String(version.to_string()));
            if let Some(prev) = previous {
                ver_table.insert("previous".into(), toml::Value::String(prev.to_string()));
            }
            let mut platforms = toml::map::Map::new();
            platforms.insert(platform.to_string(), platform_table);
            ver_table.insert("platforms".into(), toml::Value::Table(platforms));

            toml_val
                .as_table_mut()
                .context("existing package metadata root is not a TOML table")?
                .insert(
                    "versions".into(),
                    toml::Value::Array(vec![toml::Value::Table(ver_table)]),
                );
        }

        Ok(toml::to_string_pretty(&toml_val)?)
    }
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn build_package_toml(
    existing: &str,
    name: &str,
    version: &str,
    platform: &str,
    info: &StorePathInfo,
    description: Option<&str>,
    homepage: Option<&str>,
    license: Option<&str>,
    maintainer: Option<&str>,
    sysroot: bool,
    previous: Option<&str>,
    image_infos: &[PublishedImage],
    source_info: Option<&StorePathInfo>,
    expose_manifest: Option<&PublishExposeManifest>,
    expose_artifact_info: Option<&StorePathInfo>,
    expose_manifest_digest: Option<&str>,
    config_module: Option<&ConfigModuleMeta>,
    config_attestation: Option<&AttestationMeta>,
) -> Result<String> {
    build_package_toml_with_documentation(
        existing,
        name,
        version,
        platform,
        info,
        description,
        homepage,
        license,
        maintainer,
        sysroot,
        previous,
        image_infos,
        source_info,
        expose_manifest,
        expose_artifact_info,
        expose_manifest_digest,
        config_module,
        config_attestation,
        None,
        None,
    )
}

fn read_publish_expose_manifest(path: &str, package_name: &str) -> Result<PublishExposeManifest> {
    let content =
        fs::read_to_string(path).with_context(|| format!("reading expose manifest {path}"))?;
    let mut manifest: PublishExposeManifest = serde_json::from_str(&content)
        .with_context(|| format!("parsing expose manifest {path}"))?;

    validate_expose_meta_for_package(package_name, &manifest.expose)
        .with_context(|| format!("validating expose manifest for package '{package_name}'"))?;
    if manifest.permissions.confinement.is_none() {
        manifest.permissions.confinement = Some(manifest.permissions.computed_confinement());
    }
    validate_permissions_meta(package_name, &manifest.permissions)
        .with_context(|| format!("validating permissions manifest for package '{package_name}'"))?;
    if let Some(mac) = &manifest.mac {
        validate_publish_mac_profile_manifest(package_name, &manifest.permissions, mac)
            .with_context(|| {
                format!("validating MAC profile manifest for package '{package_name}'")
            })?;
        validate_publish_mac_profile_artifacts(Path::new(path), package_name, mac)?;
    }

    Ok(manifest)
}

fn read_publish_manifest_digest(path: &Path) -> Result<String> {
    let bytes =
        fs::read(path).with_context(|| format!("reading expose manifest {}", path.display()))?;
    Ok(crate::package_attestation::package_manifest_digest_bytes(
        &bytes,
    ))
}

/// Parses and authenticates the named outputs exposed to a config module.
fn parse_config_dependency_outputs(
    values: &[String],
    runtime_output: &StorePathInfo,
) -> Result<BTreeMap<String, String>> {
    let mut outputs = BTreeMap::new();
    for value in values {
        let (name, path) = value.split_once('=').with_context(|| {
            format!("invalid --config-dependency {value:?}; expected name=/nix/store/path")
        })?;
        validate_package_name(name)
            .with_context(|| format!("validating config dependency name {name:?}"))?;
        let dependency = introspect_store_path(path)
            .with_context(|| format!("introspecting config dependency {name:?}"))?;
        let dependency_hash = crate::registry::store_path_hash(&dependency.path);
        if !runtime_output
            .references
            .iter()
            .any(|hash| hash == dependency_hash)
        {
            bail!(
                "config dependency '{name}' output {} is not a direct runtime reference of {}",
                dependency.path,
                runtime_output.path
            );
        }
        if outputs.insert(name.to_string(), dependency.path).is_some() {
            bail!("config dependency '{name}' was supplied more than once");
        }
    }
    Ok(outputs)
}

fn read_publish_config_module(
    config_output: &StorePathInfo,
    base_lib: &StorePathInfo,
    package_name: &str,
    runtime_output: &str,
    dependency_outputs: &BTreeMap<String, String>,
) -> Result<PublishedConfigModule> {
    let root = Path::new(&config_output.path);
    let module_path = root.join("module.nix");
    let manifest_path = root.join("config-meta.json");
    for path in [&module_path, &manifest_path] {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("reading config-module artifact {}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!(
                "config-module artifact {} must be a regular file, not a symlink",
                path.display()
            );
        }
    }
    reject_config_derivation_references(&config_output.path)?;

    let manifest_bytes =
        fs::read(&manifest_path).with_context(|| format!("reading {}", manifest_path.display()))?;
    let authored: PublishConfigModuleManifest = serde_json::from_slice(&manifest_bytes)
        .with_context(|| format!("parsing {}", manifest_path.display()))?;
    if authored.schema != "aos.config-module-meta/v1" {
        bail!(
            "config-module artifact {} has unsupported metadata schema '{}'",
            config_output.path,
            authored.schema
        );
    }
    let mut dependency_names = dependency_outputs.keys().cloned().collect::<Vec<_>>();
    dependency_names.sort();
    let mut authored_dependencies = authored.dependencies.clone();
    authored_dependencies.sort();
    authored_dependencies.dedup();
    if dependency_names != authored_dependencies {
        bail!(
            "config-meta.json dependency claims do not match --config-dependency arguments: authored={authored_dependencies:?}, supplied={dependency_names:?}"
        );
    }

    let declarations = derive_config_option_declarations(
        &config_output.path,
        &base_lib.path,
        package_name,
        runtime_output,
        dependency_outputs,
        &authored,
    )?;
    let mut declares = declarations
        .iter()
        .map(|declaration| declaration.path_str.clone())
        .filter(|path| !path.starts_with("_module."))
        .collect::<Vec<_>>();
    declares.sort();
    declares.dedup();
    let mut declaration_schema = declarations
        .iter()
        .filter(|declaration| !declaration.path_str.starts_with("_module."))
        .map(|declaration| ConfigOptionDeclaration {
            path: declaration.path_str.clone(),
            type_signature: declaration.type_sig.clone(),
        })
        .collect::<Vec<_>>();
    declaration_schema.sort_by(|left, right| left.path.cmp(&right.path));

    let mut authored_declares = authored.declares.clone();
    authored_declares.sort();
    authored_declares.dedup();
    if declares != authored_declares {
        bail!(
            "config-meta.json declaration claims do not match options-only evaluation for package '{package_name}': authored={authored_declares:?}, derived={declares:?}"
        );
    }

    // Ownership is derived structurally: every declared non-private root is
    // owned by this module. The authored manifest supplies only the ABI number
    // for each mechanically discovered root.
    let mut owned_by_name = authored
        .owns_roots
        .iter()
        .map(|owned| (owned.root.as_str(), owned))
        .collect::<BTreeMap<_, _>>();
    let derived_owned_roots =
        derive_owned_root_names(&declares, package_name, &authored.owns_roots);
    let mut owns_roots = Vec::with_capacity(derived_owned_roots.len());
    for root in &derived_owned_roots {
        let authored_root = owned_by_name.remove(root.as_str()).with_context(|| {
            format!(
                "config-meta.json does not supply interface_abi for derived owned root '{root}'"
            )
        })?;
        let mut contributable = declarations
            .iter()
            .filter(|declaration| declaration.contributable)
            .filter_map(|declaration| {
                declaration
                    .path_str
                    .strip_prefix(&format!("{root}."))
                    .map(str::to_string)
            })
            .collect::<Vec<_>>();
        contributable.sort();
        contributable.dedup();
        let mut authored_contributable = authored_root.contributable.clone();
        authored_contributable.sort();
        authored_contributable.dedup();
        if contributable != authored_contributable {
            bail!(
                "config-meta.json contributable claims for root '{root}' do not match options-only evaluation: authored={authored_contributable:?}, derived={contributable:?}"
            );
        }
        owns_roots.push(OwnedRoot {
            root: root.clone(),
            interface_abi: authored_root.interface_abi,
            contributable,
        });
    }
    if !owned_by_name.is_empty() {
        let extras = owned_by_name.keys().copied().collect::<Vec<_>>();
        bail!("config-meta.json claims roots not owned by evaluated declarations: {extras:?}");
    }

    let (contributes, provides_capabilities, requires) = scan_config_module_interface(
        root,
        package_name,
        &derived_owned_roots,
        &authored.contributes,
    )?;
    let mut authored_contributes = authored.contributes.clone();
    normalize_contributions(&mut authored_contributes);
    if contributes != authored_contributes {
        bail!(
            "config-meta.json contribution claims do not match the conservative module scan: authored={authored_contributes:?}, derived={contributes:?}; publish scanning requires explicit config.<path> assignments for foreign contributions"
        );
    }
    let mut authored_capabilities = authored.provides_capabilities.clone();
    authored_capabilities.sort();
    authored_capabilities.dedup();
    if provides_capabilities != authored_capabilities {
        bail!(
            "config-meta.json capability claims do not match the conservative module scan: authored={authored_capabilities:?}, derived={provides_capabilities:?}; publish scanning requires explicit config.system.capabilities.<token> assignments"
        );
    }

    let module = ConfigModuleMeta {
        config_output: ConfigOutputMeta {
            store_path: config_output.path.clone(),
            nar_hash: config_output.nar_hash.clone(),
            nar_size: config_output.nar_size,
            references: config_output.references.clone(),
        },
        evaluation_base_lib: Some(ConfigOutputMeta {
            store_path: base_lib.path.clone(),
            nar_hash: base_lib.nar_hash.clone(),
            nar_size: base_lib.nar_size,
            references: base_lib.references.clone(),
        }),
        dependency_outputs: dependency_outputs.clone(),
        module_abi_compat: authored.module_abi_compat,
        declares,
        declaration_schema,
        requires,
        owns_roots,
        contributes,
        artifacts: authored.artifacts.clone(),
        provides_capabilities,
    };
    validate_config_output_meta(&module.config_output)?;
    validate_config_module_meta(package_name, &module)?;
    Ok(PublishedConfigModule {
        metadata: module,
        authored,
        declarations: declarations
            .into_iter()
            .filter(|declaration| !declaration.path_str.starts_with("_module."))
            .collect(),
    })
}

fn derive_owned_root_names(
    declares: &[String],
    package_name: &str,
    authored_roots: &[OwnedRoot],
) -> Vec<String> {
    let mut roots = declares
        .iter()
        .filter_map(|path| path.split('.').next())
        .filter(|root| {
            // Package-prefixed declarations are private by default, but an
            // explicit ownsRoots entry promotes that same-name root into a
            // versioned contributor interface. Publication must validate the
            // claim just like any differently named shared root.
            *root != package_name || authored_roots.iter().any(|owned| owned.root == *root)
        })
        .map(str::to_string)
        .collect::<Vec<_>>();
    roots.sort();
    roots.dedup();
    roots
}

fn reject_config_derivation_references(config_output: &str) -> Result<()> {
    let output = nix_command("nix-store")
        .args(["--query", "--references", config_output])
        .output()
        .with_context(|| format!("querying config-module references for {config_output}"))?;
    if !output.status.success() {
        bail!(
            "nix-store --query --references failed for config module {config_output}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    if let Some(reference) = String::from_utf8_lossy(&output.stdout)
        .lines()
        .find(|reference| !reference.trim().is_empty())
    {
        bail!(
            "config module {config_output} must have an empty reference set, but references {reference}"
        );
    }
    Ok(())
}

fn derive_config_option_declarations(
    config_output: &str,
    base_lib_path: &str,
    package_name: &str,
    runtime_output: &str,
    dependency_outputs: &BTreeMap<String, String>,
    authored: &PublishConfigModuleManifest,
) -> Result<Vec<DerivedOptionDeclaration>> {
    let owns = authored
        .owns_roots
        .iter()
        .map(|owned| nix_publish_string(&owned.root))
        .collect::<Vec<_>>()
        .join(" ");
    let contributes = authored
        .contributes
        .iter()
        .map(|contribution| {
            let paths = contribution
                .paths
                .iter()
                .map(|path| nix_publish_string(path))
                .collect::<Vec<_>>()
                .join(" ");
            format!("{} = [ {paths} ];", nix_publish_string(&contribution.root))
        })
        .collect::<Vec<_>>()
        .join(" ");
    let expression = format!(
        r#"let
  base = import <aos-publish-base-lib>;
  evaluated = base.lib.evalModules {{
    modules = [];
    packageModules = [ {{
      name = {};
      configRoot = <aos-publish-config-module>;
      module = <aos-publish-config-module/module.nix>;
      outputs = {{ self = {}; dependencies = {{ {} }}; }};
      authorization = {{ owns = [ {owns} ]; contributes = {{ {contributes} }}; }};
    }} ];
    inherit (base) lib;
  }};
in builtins.map (decl: {{
  inherit (decl)
    path pathStr typeSig type description default example visibility readOnly
    contributable owner;
}})
  (base.lib.optionSurface evaluated)"#,
        nix_publish_string(package_name),
        nix_publish_string(runtime_output),
        dependency_outputs
            .iter()
            .map(|(name, path)| {
                format!(
                    "{} = {};",
                    nix_publish_string(name),
                    nix_publish_string(path)
                )
            })
            .collect::<Vec<_>>()
            .join(" ")
    );
    let base_search_path = format!("aos-publish-base-lib={base_lib_path}");
    let module_search_path = format!("aos-publish-config-module={config_output}");
    let evaluator = std::env::var_os("PATH")
        .and_then(|path| {
            std::env::split_paths(&path)
                .map(|directory| directory.join("nix-instantiate"))
                .find(|candidate| candidate.is_file())
        })
        .context("cannot find nix-instantiate in the AOS command path")?;
    let mut command = Command::new(evaluator);
    command.env_clear();
    let output = command
        .args([
            "--store",
            "dummy://",
            "--eval",
            "--strict",
            "--json",
            "--option",
            "restrict-eval",
            "true",
            "--option",
            "allow-import-from-derivation",
            "false",
            "-I",
            &base_search_path,
            "-I",
            &module_search_path,
            "--expr",
            &expression,
        ])
        .output()
        .with_context(|| {
            format!("running options-only config-module eval for package '{package_name}'")
        })?;
    if !output.status.success() {
        bail!(
            "options-only config-module eval failed for package '{package_name}': {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    serde_json::from_slice(&output.stdout).with_context(|| {
        format!("parsing options-only config-module eval for package '{package_name}'")
    })
}

#[allow(clippy::too_many_arguments)]
fn publish_package_documentation(
    name: &str,
    version: &str,
    platform: &str,
    description: &str,
    homepage: Option<&str>,
    license: &str,
    runtime: &StorePathInfo,
    source: Option<&StorePathInfo>,
    config_module: Option<&ConfigModuleMeta>,
    config_manifest: Option<&PublishConfigModuleManifest>,
    expose_manifest: Option<&PublishExposeManifest>,
    expose_artifact: Option<&StorePathInfo>,
    declarations: &[DerivedOptionDeclaration],
) -> Result<PublishedDocumentation> {
    let authored = config_manifest
        .map(|manifest| &manifest.documentation)
        .cloned()
        .unwrap_or_default();
    if let Some(summary) = authored.summary.as_deref()
        && summary != description
    {
        bail!(
            "package '{name}' documentation summary must equal its catalog description so there is one summary authority"
        );
    }

    let declaration_paths = documented_option_declarations(declarations)
        .map(|declaration| declaration.path_str.as_str())
        .collect::<HashSet<_>>();
    if let Some(foreign) = authored
        .options
        .keys()
        .find(|path| !declaration_paths.contains(path.as_str()))
    {
        bail!("package '{name}' documentation enriches undeclared option '{foreign}'");
    }

    let sections = authored
        .sections
        .into_iter()
        .map(|(id, section)| Section {
            id,
            title: section.title,
            blocks: section.blocks,
        })
        .collect::<Vec<_>>();
    let options = documented_option_declarations(declarations)
        .map(|declaration| {
            let enrichment = authored.options.get(&declaration.path_str);
            let description = if declaration.description.trim().is_empty() {
                format!("Configuration option {}.", declaration.path_str)
            } else {
                declaration.description.clone()
            };
            let root = declaration
                .path
                .first()
                .cloned()
                .context("documentation option path is empty")?;
            let interface_abi = config_manifest.and_then(|manifest| {
                manifest
                    .owns_roots
                    .iter()
                    .find(|owned| owned.root == root)
                    .map(|owned| owned.interface_abi)
            });
            Ok(OptionDocument {
                path: declaration
                    .path
                    .iter()
                    .cloned()
                    .map(|value| PathSegment::Literal { value })
                    .collect(),
                display_path: declaration.path_str.clone(),
                option_type: declaration.option_type.clone(),
                type_signature: declaration.type_sig.clone(),
                description: vec![ProseBlock::Paragraph {
                    spans: vec![aos_doc_model::InlineSpan::Text { text: description }],
                }],
                default: declaration.default.clone(),
                example: declaration.example.clone(),
                visibility: declaration.visibility,
                read_only: declaration.read_only,
                deprecated: enrichment.and_then(|entry| entry.deprecated.clone()),
                replacement: enrichment.and_then(|entry| entry.replacement.clone()),
                owner: OptionOwner {
                    package: declaration.owner.clone(),
                    root,
                    interface_abi,
                },
                contributable: declaration.contributable,
                activation: enrichment.and_then(|entry| entry.activation.clone()),
                source: None,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let mut document = PackageDocumentation {
        schema: DOCUMENT_SCHEMA.to_string(),
        package: DocumentedPackage {
            name: name.to_string(),
            version: version.to_string(),
            platform: platform.to_string(),
            summary: description.to_string(),
            homepage: homepage.map(str::to_string),
            license: license.to_string(),
        },
        identity: DocumentationIdentity {
            semantic_schema_sha256: format!("sha256:{}", "0".repeat(64)),
            runtime_nar_hash: documentation_nar_identity(&runtime.nar_hash)?,
            config_module_nar_hash: config_module
                .map(|module| documentation_nar_identity(&module.config_output.nar_hash))
                .transpose()?,
            expose_artifact_nar_hash: expose_artifact
                .map(|artifact| documentation_nar_identity(&artifact.nar_hash))
                .transpose()?,
            source_nar_hash: documentation_nar_identity(
                source.map_or(runtime.nar_hash.as_str(), |source| source.nar_hash.as_str()),
            )?,
        },
        sections,
        options,
        runtime: documentation_runtime_surface(expose_manifest),
    };
    document.identity.semantic_schema_sha256 = document
        .computed_semantic_schema_sha256()
        .context("computing package documentation semantic schema digest")?;
    document
        .verify_semantic_schema_sha256()
        .context("verifying package documentation semantic schema digest")?;
    let bytes = document
        .canonical_json()
        .context("encoding canonical package documentation")?;
    let document_sha256 = format!("sha256:{}", sha256_hex(&bytes));

    let directory = tempfile::tempdir().context("creating documentation materialization input")?;
    let path = directory
        .path()
        .join(format!("{name}-{version}-aos-docs.json"));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .with_context(|| format!("creating documentation input {}", path.display()))?;
    file.write_all(&bytes)
        .with_context(|| format!("writing documentation input {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing documentation input {}", path.display()))?;
    drop(file);

    let output = nix_command("nix-store")
        .args(["--add-fixed", "sha256"])
        .arg(&path)
        .output()
        .context("adding canonical package documentation to the Nix store")?;
    if !output.status.success() {
        bail!(
            "nix-store --add-fixed failed for package documentation: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let store_path = String::from_utf8(output.stdout)
        .context("documentation store path is not UTF-8")?
        .trim()
        .to_string();
    let info = introspect_store_path(&store_path)
        .context("introspecting canonical package documentation store object")?;
    if !info.references.is_empty() {
        bail!("package documentation store object must have no references");
    }
    let stored = fs::metadata(&info.path)
        .with_context(|| format!("inspecting documentation object {}", info.path))?;
    if !stored.is_file() || stored.len() != bytes.len() as u64 {
        bail!("package documentation store object must be one exact regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if stored.permissions().mode() & 0o111 != 0 {
            bail!("package documentation store object must not be executable");
        }
    }

    let metadata = DocumentationArtifactMeta {
        format: DOCUMENT_FORMAT.to_string(),
        store_path: info.path.clone(),
        nar_hash: info.nar_hash.clone(),
        nar_size: info.nar_size,
        document_sha256,
        document_size: bytes.len() as u64,
        semantic_schema_sha256: document.identity.semantic_schema_sha256,
        references: Vec::new(),
    };
    validate_documentation_artifact_meta(&metadata)
        .context("validating published package documentation metadata")?;
    Ok(PublishedDocumentation { metadata, info })
}

/// Selects the declarations that form the user/tooling documentation surface.
///
/// Internal module-system plumbing remains part of the signed config-module
/// declaration schema and authorization checks, but it is not a package API
/// and may intentionally use reserved path segments such as
/// `_aosExposeConfigProjection`.
fn documented_option_declarations(
    declarations: &[DerivedOptionDeclaration],
) -> impl Iterator<Item = &DerivedOptionDeclaration> {
    declarations
        .iter()
        .filter(|declaration| declaration.visibility != Visibility::Internal)
}

fn documentation_runtime_surface(manifest: Option<&PublishExposeManifest>) -> RuntimeSurface {
    let Some(manifest) = manifest else {
        return RuntimeSurface::default();
    };
    let expose = &manifest.expose;
    let permissions = &manifest.permissions;
    let network = match permissions.network {
        Some(crate::types::NetworkPermission::PrivateOutbound) => "private-outbound",
        Some(crate::types::NetworkPermission::Host) => "host",
        Some(crate::types::NetworkPermission::Private) | None => "private",
    };
    let mut units = expose
        .units
        .iter()
        .map(|name| RuntimeUnit {
            name: name.clone(),
            kind: name
                .rsplit_once('.')
                .map_or("unit", |(_, kind)| kind)
                .to_string(),
            summary: String::new(),
            requires: Vec::new(),
        })
        .collect::<Vec<_>>();
    if !units.iter().any(|unit| unit.name == expose.target) {
        units.push(RuntimeUnit {
            name: expose.target.clone(),
            kind: "target".to_string(),
            summary: "Package activation target".to_string(),
            requires: Vec::new(),
        });
    }
    units.sort_by(|left, right| left.name.cmp(&right.name));

    let listeners = permissions
        .tcp_bind
        .iter()
        .copied()
        .map(|port| RuntimeListener {
            unit: expose.target.clone(),
            protocol: "tcp".to_string(),
            port: Some(port),
            network_mode: network.to_string(),
        })
        .collect();
    let mut managed_paths = permissions
        .host_paths
        .iter()
        .map(|path| aos_doc_model::ManagedPath {
            path: path.path.clone(),
            purpose: "host-path".to_string(),
            writable: path.mode == crate::types::HostPathMode::Rw,
        })
        .collect::<Vec<_>>();
    managed_paths.extend(expose.config.artifacts.iter().map(|artifact| {
        aos_doc_model::ManagedPath {
            path: artifact.path.clone(),
            purpose: "configuration".to_string(),
            writable: false,
        }
    }));
    managed_paths.sort_by(|left, right| left.path.cmp(&right.path));

    let config_artifacts = expose
        .config
        .artifacts
        .iter()
        .map(|artifact| {
            let kind = match artifact.reload {
                crate::types::ConfigReloadPolicy::Reload => ActivationKind::Reload,
                crate::types::ConfigReloadPolicy::Restart => ActivationKind::Restart,
                crate::types::ConfigReloadPolicy::None => ActivationKind::None,
            };
            let mut units = artifact.units.clone();
            units.sort();
            units.dedup();
            RuntimeConfigArtifact {
                name: artifact.name.clone(),
                destination: artifact.path.clone(),
                format: match artifact.format {
                    crate::types::ConfigArtifactFormat::Env => "env",
                    crate::types::ConfigArtifactFormat::Json => "json",
                    crate::types::ConfigArtifactFormat::Toml => "toml",
                }
                .to_string(),
                activation: Some(ActivationEffect { kind, units }),
            }
        })
        .collect();
    let credentials = expose
        .config
        .credentials
        .iter()
        .map(|credential| CredentialContract {
            name: credential.name.clone(),
            purpose: format!("Credential consumed by {}", credential.units.join(", ")),
            destination: format!("%d/{}", credential.name),
            accepted_kinds: if credential.encrypted {
                vec![
                    "tpm2-credential".to_string(),
                    "system-credential".to_string(),
                ]
            } else {
                vec!["system-credential".to_string()]
            },
            required: !credential.optional,
            mode: 0o600,
            activation: Some(ActivationEffect {
                kind: ActivationKind::Restart,
                units: {
                    let mut units = credential.units.clone();
                    units.sort();
                    units.dedup();
                    units
                },
            }),
        })
        .collect();
    let mut capabilities = expose
        .provides
        .iter()
        .map(|capability| RuntimeCapability {
            name: capability.name.clone(),
            direction: "provides".to_string(),
        })
        .chain(expose.uses.iter().map(|capability| RuntimeCapability {
            name: format!("{}/{}", capability.provider, capability.name),
            direction: "uses".to_string(),
        }))
        .collect::<Vec<_>>();
    capabilities
        .sort_by(|left, right| (&left.direction, &left.name).cmp(&(&right.direction, &right.name)));
    let computed = permissions.computed_confinement();
    let class = match computed.class {
        ConfinementClass::Sandboxed => "sandboxed",
        ConfinementClass::SandboxedWithHoles => "sandboxed-with-holes",
        ConfinementClass::Unconfined => "unconfined",
    };

    RuntimeSurface {
        units,
        listeners,
        managed_paths,
        config_artifacts,
        credentials,
        capabilities,
        confinement: Some(ConfinementSummary {
            class: class.to_string(),
            network: network.to_string(),
            private_root: computed.class != ConfinementClass::Unconfined,
        }),
    }
}

fn nix_publish_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn normalize_contributions(contributions: &mut Vec<RootContribution>) {
    for contribution in contributions.iter_mut() {
        contribution.paths.sort();
        contribution.paths.dedup();
    }
    contributions.sort_by(|left, right| left.root.cmp(&right.root));
}

fn scan_config_module_interface(
    root: &Path,
    package_name: &str,
    owned_roots: &[String],
    authored_contributions: &[RootContribution],
) -> Result<(Vec<RootContribution>, Vec<String>, Vec<String>)> {
    let access = Regex::new(r"(?:config|options)\.([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+)")?;
    let assignment = Regex::new(r"config\.([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+)\s*=")?;
    let mut requires = Vec::new();
    let mut writes = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("inspecting config-module source {}", path.display()))?;
        if metadata.file_type().is_symlink() {
            bail!(
                "config-module source must not contain symlink {}",
                path.display()
            );
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(&path)
                .with_context(|| format!("reading config-module directory {}", path.display()))?
            {
                pending.push(entry?.path());
            }
            continue;
        }
        let relative = path.strip_prefix(root).unwrap_or(&path);
        if relative == Path::new("config-meta.json")
            || relative == Path::new("expose-config.json")
            || relative == Path::new("generated/expose-config.json")
        {
            continue;
        }
        if path.extension().and_then(|extension| extension.to_str()) != Some("nix") {
            bail!(
                "config-module source contains non-Nix helper {}",
                path.display()
            );
        }
        let source = fs::read_to_string(&path)
            .with_context(|| format!("reading config-module source {}", path.display()))?;
        let code = strip_nix_comments_and_strings(&source);
        requires.extend(
            access
                .captures_iter(&code)
                .map(|capture| capture[1].to_string()),
        );
        writes.extend(
            assignment
                .captures_iter(&code)
                .map(|capture| capture[1].to_string()),
        );
    }
    requires.sort();
    requires.dedup();
    writes.sort();
    writes.dedup();

    let owned = owned_roots
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let write_set = writes.iter().map(String::as_str).collect::<HashSet<_>>();
    requires.retain(|path| {
        let root = path.split_once('.').map_or(path.as_str(), |(root, _)| root);
        root != package_name
            && root != "_module"
            && root != "assertions"
            && root != "warnings"
            && !owned.contains(root)
            && !write_set.contains(path.as_str())
    });
    let mut contribution_map = BTreeMap::<String, Vec<String>>::new();
    let mut provides_capabilities = Vec::new();
    for path in writes {
        if let Some(token) = path.strip_prefix("system.capabilities.") {
            provides_capabilities.push(format!("system.capabilities.{token}"));
            continue;
        }
        let Some((root, relative)) = path.split_once('.') else {
            continue;
        };
        if matches!(root, "_module" | "assertions" | "warnings") {
            continue;
        }
        if root != package_name && !owned.contains(root) {
            contribution_map
                .entry(root.to_string())
                .or_default()
                .push(relative.to_string());
        }
    }
    let contribution_abis = authored_contributions
        .iter()
        .map(|contribution| (contribution.root.as_str(), contribution.interface_abi))
        .collect::<BTreeMap<_, _>>();
    let mut contributes = contribution_map
        .into_iter()
        .map(|(root, paths)| {
            let interface_abi = contribution_abis.get(root.as_str()).copied().with_context(|| {
                format!(
                    "foreign contribution to root '{root}' has no authenticated interface_abi; set contributes[].interfaceAbi to the owner's current interface ABI and republish"
                )
            })?;
            Ok(RootContribution {
                root,
                interface_abi,
                paths,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    normalize_contributions(&mut contributes);
    provides_capabilities.sort();
    provides_capabilities.dedup();
    Ok((contributes, provides_capabilities, requires))
}

/// Blanks comments and string bodies while preserving byte positions/newlines.
///
/// Assignment discovery must not accept a claimed foreign write merely
/// because `config.foo =` appears in documentation or a string literal.
fn strip_nix_comments_and_strings(source: &str) -> String {
    #[derive(Clone, Copy)]
    enum State {
        Code,
        Comment,
        DoubleQuoted { escaped: bool },
        Indented,
    }

    let bytes = source.as_bytes();
    let mut output = String::with_capacity(source.len());
    let mut state = State::Code;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        match state {
            State::Code if byte == b'#' => {
                output.push(' ');
                state = State::Comment;
            }
            State::Code if byte == b'"' => {
                output.push(' ');
                state = State::DoubleQuoted { escaped: false };
            }
            State::Code if byte == b'\'' && bytes.get(index + 1).copied() == Some(b'\'') => {
                output.push_str("  ");
                index += 1;
                state = State::Indented;
            }
            State::Code => output.push(char::from(byte)),
            State::Comment if byte == b'\n' => {
                output.push('\n');
                state = State::Code;
            }
            State::Comment => output.push(' '),
            State::DoubleQuoted { escaped: false } if byte == b'"' => {
                output.push(' ');
                state = State::Code;
            }
            State::DoubleQuoted { escaped } => {
                output.push(if byte == b'\n' { '\n' } else { ' ' });
                state = State::DoubleQuoted {
                    escaped: !escaped && byte == b'\\',
                };
            }
            State::Indented if byte == b'\'' && bytes.get(index + 1).copied() == Some(b'\'') => {
                output.push_str("  ");
                index += 1;
                state = State::Code;
            }
            State::Indented => output.push(if byte == b'\n' { '\n' } else { ' ' }),
        }
        index += 1;
    }
    output
}

fn validate_publish_mac_profile_manifest(
    package_name: &str,
    permissions: &PermissionsMeta,
    mac: &PublishMacProfileManifest,
) -> Result<()> {
    let expected_label = permissions
        .security_label
        .clone()
        .unwrap_or_else(|| format!("aos-pkg-{package_name}"));
    let expected_default_deny = permissions
        .confinement
        .as_ref()
        .map(|confinement| confinement.class != ConfinementClass::Unconfined)
        .unwrap_or_else(|| {
            permissions.computed_confinement().class != ConfinementClass::Unconfined
        });
    let expected_profile_path =
        expected_default_deny.then(|| expected_publish_selinux_profile_path(&expected_label));

    if mac.version != 1 {
        bail!(
            "MAC profile manifest for package '{}' has unsupported version {}",
            package_name,
            mac.version
        );
    }
    if mac.package != package_name {
        bail!(
            "MAC profile manifest package mismatch: expected '{}', got '{}'",
            package_name,
            mac.package
        );
    }
    if mac.backend != "selinux" {
        bail!(
            "MAC profile manifest backend mismatch for package '{}'",
            package_name
        );
    }
    if mac.security_label != expected_label {
        bail!(
            "MAC profile manifest security label mismatch for package '{}'",
            package_name
        );
    }
    if mac.default_deny != expected_default_deny
        || mac.profile_path.as_deref() != expected_profile_path.as_deref()
    {
        bail!(
            "MAC profile manifest confinement mode mismatch for package '{}'",
            package_name
        );
    }
    Ok(())
}

fn validate_publish_mac_profile_artifacts(
    manifest_path: &Path,
    package_name: &str,
    mac: &PublishMacProfileManifest,
) -> Result<()> {
    let artifact_root = manifest_path.parent().with_context(|| {
        format!(
            "expose manifest path has no parent: {}",
            manifest_path.display()
        )
    })?;
    let mac_path = artifact_root.join("mac-profile.json");
    let artifact_mac: PublishMacProfileManifest = read_publish_mac_profile_file(&mac_path)
        .with_context(|| {
            format!(
                "validating MAC profile artifact for package '{}' at {}",
                package_name,
                mac_path.display()
            )
        })?;
    if &artifact_mac != mac {
        bail!(
            "MAC profile artifact for package '{}' does not match manifest.mac",
            package_name
        );
    }

    let Some(profile_path) = &mac.profile_path else {
        return Ok(());
    };
    let profile_bytes =
        read_artifact_regular_bytes_no_symlink(artifact_root, Path::new(profile_path))
            .with_context(|| format!("reading MAC profile file {}", profile_path))?;
    if profile_bytes.is_empty() {
        bail!(
            "MAC profile file for package '{}' is empty: {}",
            package_name,
            profile_path
        );
    }
    let module_name = publish_selinux_identifier_for_label(&mac.security_label);
    let module_path = format!("mac/selinux/{module_name}.mod");
    let module_bytes =
        read_artifact_regular_bytes_no_symlink(artifact_root, Path::new(&module_path))
            .with_context(|| format!("reading MAC module file {}", module_path))?;
    if module_bytes.is_empty() {
        bail!(
            "MAC module file for package '{}' is empty: {}",
            package_name,
            module_path
        );
    }
    let source_path = format!("mac/selinux/{module_name}.te");
    let source_text = read_artifact_regular_file_no_symlink(artifact_root, Path::new(&source_path))
        .with_context(|| format!("reading MAC source file {}", source_path))?;
    let expected_profile = expected_publish_selinux_profile(&mac.security_label);
    if source_text.trim_end() != expected_profile.trim_end() {
        bail!(
            "MAC source file for package '{}' does not match the expected default-deny scaffold",
            package_name
        );
    }
    validate_publish_compiled_selinux_profile(
        package_name,
        &source_text,
        &module_name,
        &module_path,
        &module_bytes,
        profile_path,
        &profile_bytes,
    )?;
    Ok(())
}

fn validate_publish_compiled_selinux_profile(
    package_name: &str,
    source_text: &str,
    module_name: &str,
    module_path: &str,
    module_bytes: &[u8],
    profile_path: &str,
    profile_bytes: &[u8],
) -> Result<()> {
    let expected = compile_publish_selinux_profile(source_text, module_name)
        .with_context(|| format!("rebuilding SELinux profile for package '{package_name}'"))?;
    if module_bytes != expected.module {
        bail!(
            "MAC module file for package '{}' does not match the validated SELinux source: {}",
            package_name,
            module_path
        );
    }
    if profile_bytes != expected.profile {
        bail!(
            "MAC profile file for package '{}' does not match the validated SELinux source: {}",
            package_name,
            profile_path
        );
    }
    Ok(())
}

#[cfg(test)]
fn compile_publish_selinux_profile(
    source_text: &str,
    _module_name: &str,
) -> Result<CompiledSelinuxProfile> {
    Ok(CompiledSelinuxProfile {
        module: format!("compiled-module\n{source_text}").into_bytes(),
        profile: format!("compiled-policy\n{source_text}").into_bytes(),
    })
}

#[cfg(not(test))]
fn compile_publish_selinux_profile(
    source_text: &str,
    module_name: &str,
) -> Result<CompiledSelinuxProfile> {
    let checkmodule = trusted_publish_checkmodule_path()?;
    let semodule_package = trusted_publish_semodule_package_path()?;
    let tmp = tempfile::TempDir::new().context("creating SELinux policy validation tempdir")?;
    let source_path = tmp.path().join(format!("{module_name}.te"));
    let module_path = tmp.path().join(format!("{module_name}.mod"));
    let profile_path = tmp.path().join(format!("{module_name}.pp"));
    fs::write(&source_path, source_text)
        .with_context(|| format!("writing {}", source_path.display()))?;
    run_selinux_policy_tool(
        &checkmodule,
        &[
            std::ffi::OsStr::new("-M"),
            std::ffi::OsStr::new("-m"),
            std::ffi::OsStr::new("-o"),
            module_path.as_os_str(),
            source_path.as_os_str(),
        ],
    )?;
    run_selinux_policy_tool(
        &semodule_package,
        &[
            std::ffi::OsStr::new("-o"),
            profile_path.as_os_str(),
            std::ffi::OsStr::new("-m"),
            module_path.as_os_str(),
        ],
    )?;
    Ok(CompiledSelinuxProfile {
        module: fs::read(&module_path)
            .with_context(|| format!("reading {}", module_path.display()))?,
        profile: fs::read(&profile_path)
            .with_context(|| format!("reading {}", profile_path.display()))?,
    })
}

#[cfg(not(test))]
fn run_selinux_policy_tool(program: &str, args: &[&std::ffi::OsStr]) -> Result<()> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("running {program}"))?;
    if !output.status.success() {
        bail!(
            "{} failed with status {}: {}{}",
            program,
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn read_publish_mac_profile_file(path: &Path) -> Result<PublishMacProfileManifest> {
    let content = read_regular_file_no_symlink(path)?;
    serde_json::from_str(&content).with_context(|| format!("parsing {}", path.display()))
}

fn read_artifact_regular_file_no_symlink(root: &Path, relative_path: &Path) -> Result<String> {
    let current = artifact_regular_file_no_symlink(root, relative_path)?;
    std::fs::read_to_string(&current).with_context(|| format!("reading {}", current.display()))
}

fn read_artifact_regular_bytes_no_symlink(root: &Path, relative_path: &Path) -> Result<Vec<u8>> {
    let current = artifact_regular_file_no_symlink(root, relative_path)?;
    std::fs::read(&current).with_context(|| format!("reading {}", current.display()))
}

fn artifact_regular_file_no_symlink(root: &Path, relative_path: &Path) -> Result<PathBuf> {
    let mut components = relative_path.components().peekable();
    if components.peek().is_none() {
        bail!("artifact-relative path is empty");
    }

    let mut current = root.to_path_buf();
    while let Some(component) = components.next() {
        let std::path::Component::Normal(component) = component else {
            bail!(
                "artifact-relative path contains unsupported component: {}",
                relative_path.display()
            );
        };
        current.push(component);
        let metadata = std::fs::symlink_metadata(&current)
            .with_context(|| format!("checking {}", current.display()))?;
        if components.peek().is_some() {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                bail!(
                    "artifact path component is not a non-symlink directory: {}",
                    current.display()
                );
            }
        } else if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            bail!(
                "artifact path is not a non-symlink regular file: {}",
                current.display()
            );
        }
    }

    Ok(current)
}

fn read_regular_file_no_symlink(path: &Path) -> Result<String> {
    let metadata =
        std::fs::symlink_metadata(path).with_context(|| format!("checking {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        bail!("path is not a regular file: {}", path.display());
    }
    std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
}

#[cfg(not(test))]
fn trusted_publish_checkmodule_path() -> Result<String> {
    if let Ok(path) = std::env::var(CHECKMODULE_ENV) {
        if path.is_empty() {
            bail!("{CHECKMODULE_ENV} must not be empty");
        }
        if !path.starts_with('/') || !path.ends_with("/bin/checkmodule") {
            bail!("{CHECKMODULE_ENV} must point to an absolute checkmodule binary");
        }
        return Ok(path);
    }

    bail!("{CHECKMODULE_ENV} is not configured for MAC policy validation");
}

#[cfg(not(test))]
fn trusted_publish_semodule_package_path() -> Result<String> {
    if let Ok(path) = std::env::var(SEMODULE_PACKAGE_ENV) {
        if path.is_empty() {
            bail!("{SEMODULE_PACKAGE_ENV} must not be empty");
        }
        if !path.starts_with('/') || !path.ends_with("/bin/semodule_package") {
            bail!("{SEMODULE_PACKAGE_ENV} must point to an absolute semodule_package binary");
        }
        return Ok(path);
    }

    bail!("{SEMODULE_PACKAGE_ENV} is not configured for MAC policy validation");
}

fn expected_publish_selinux_profile_path(label: &str) -> String {
    format!(
        "mac/selinux/{}.pp",
        publish_selinux_identifier_for_label(label)
    )
}

fn publish_selinux_identifier_for_label(label: &str) -> String {
    let mut normalized = String::with_capacity(label.len());
    for byte in label.bytes() {
        if byte.is_ascii_alphanumeric() {
            normalized.push(byte as char);
        } else {
            normalized.push_str(&format!("_x{byte:02x}"));
        }
    }
    if normalized
        .as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
    {
        normalized
    } else {
        format!("aos_pkg_{normalized}")
    }
}

fn publish_selinux_type_for_label(label: &str) -> String {
    format!("{}_t", publish_selinux_identifier_for_label(label))
}

fn expected_publish_selinux_profile(label: &str) -> String {
    let module_name = publish_selinux_identifier_for_label(label);
    let type_name = publish_selinux_type_for_label(label);
    format!(
        "# Generated by AOS package expose renderer.\n# RFC-0001 per-package SELinux default-deny module.\nmodule {module_name} 1.0;\n\nrequire {{\n  type init_t;\n  type kernel_t;\n  type root_t;\n  type tmp_t;\n  type tmpfs_t;\n  type unlabeled_t;\n  type var_lib_t;\n  type var_t;\n  attribute domain;\n  attribute file_type;\n  role system_r;\n  class dir {{ getattr open read search }};\n  class fd use;\n  class file {{ execute execute_no_trans execmod getattr map open read }};\n  class lnk_file {{ getattr read }};\n  class process {{ dyntransition execmem execstack execheap }};\n  class process2 {{ nnp_transition nosuid_transition }};\n}}\n\ntype {type_name};\ntypeattribute {type_name} domain;\nrole system_r types {type_name};\n\nallow {type_name} init_t:fd use;\nallow init_t {type_name}:process dyntransition;\nallow init_t {type_name}:process2 {{ nnp_transition nosuid_transition }};\nallow {type_name} kernel_t:fd use;\nallow kernel_t {type_name}:process dyntransition;\nallow kernel_t {type_name}:process2 {{ nnp_transition nosuid_transition }};\nallow {type_name} self:process {{ execmem execstack execheap }};\nallow {type_name} self:process2 {{ nnp_transition nosuid_transition }};\nallow {type_name} file_type:file execmod;\nallow {type_name} root_t:dir {{ getattr open read search }};\nallow {type_name} tmp_t:dir {{ getattr open read search }};\nallow {type_name} tmp_t:lnk_file {{ getattr read }};\nallow {type_name} tmpfs_t:dir {{ getattr open read search }};\nallow {type_name} tmpfs_t:lnk_file {{ getattr read }};\nallow {type_name} unlabeled_t:dir {{ getattr open read search }};\nallow {type_name} unlabeled_t:file {{ execute execute_no_trans execmod getattr map open read }};\nallow {type_name} unlabeled_t:lnk_file {{ getattr read }};\nallow {type_name} var_t:dir {{ getattr open read search }};\nallow {type_name} var_t:lnk_file {{ getattr read }};\nallow {type_name} var_lib_t:dir {{ getattr open read search }};\nallow {type_name} var_lib_t:lnk_file {{ getattr read }};\n"
    )
}

/// Infer the rendered expose artifact from a manifest produced by
/// `_expose-renderer.nix`.
fn infer_publish_expose_artifact(path: &str) -> Result<StorePathInfo> {
    let manifest_path = Path::new(path);
    let Some(parent) = manifest_path.parent() else {
        bail!("expose manifest path has no parent: {path}");
    };
    let Some(parent_str) = parent.to_str() else {
        bail!(
            "expose manifest parent path is not UTF-8: {}",
            parent.display()
        );
    };
    if manifest_path.file_name().and_then(|name| name.to_str()) != Some("manifest.json") {
        bail!("expose manifest must be named manifest.json: {path}");
    }
    if store_dir_from_store_path(parent_str).is_none() {
        bail!("expose manifest must live directly in a Nix store artifact: {path}");
    }
    if !parent.join("units").is_dir() {
        bail!(
            "expose artifact {} is missing required units/ directory",
            parent.display()
        );
    }

    let info = introspect_store_path(parent_str)
        .with_context(|| format!("introspecting expose artifact {parent_str}"))?;
    let artifact = ExposeArtifactMeta {
        store_path: info.path.clone(),
        nar_hash: info.nar_hash.clone(),
        nar_size: info.nar_size,
    };
    validate_expose_artifact_meta(&artifact)?;
    Ok(info)
}

/// Secure Boot facts extracted from a signed UKI at publish time.
///
/// Every field is derived from the real binary so the registry catalog
/// cannot disagree with what was actually signed (RFC-0006 phase 4,
/// `registry-catalog.md`). A field is `None`/empty when the corresponding
/// fact could not be derived (e.g. `systemd-measure` unavailable).
#[derive(Debug, Default, Clone)]
struct SbFacts {
    /// Lowercase hex SHA-256 of the signer leaf cert in the PE cert table.
    signer_cert_sha256: Option<String>,
    /// SBAT component/generation pairs from the PE `.sbat` section.
    sbat: Vec<SbatEntry>,
    /// `systemd-measure`-predicted PCR-11 over this UKI's measured sections at
    /// the `ready` boot phase (the stable value quoted during activation;
    /// see [`extract_expected_pcr11`]).
    expected_pcr11: Option<String>,
    /// Deterministically identified per-slot facts for an A/B image payload.
    ukis: Vec<SysrootUkiEntry>,
    /// Independently verified signed recovery copies for an A/B image payload.
    recovery_ukis: Vec<RecoveryUkiEntry>,
    /// Complete catalog-authenticated offline recovery bundle manifest.
    recovery_bundle: Option<RecoveryBundleManifest>,
}

/// A fully validated disk-image publication input.
///
/// Unlike the historical NAR-only tuple, this binds the exact disk file and
/// producer metadata that direct-download consumers receive.
struct PublishedImage {
    format: String,
    /// Canonical directory store output carrying the A/B update artifacts.
    payload: StorePathInfo,
    /// Canonical regular-file store output containing the disk encoding.
    store: StorePathInfo,
    /// Canonical regular-file store output containing `image-info.json`.
    info_store: StorePathInfo,
    sb: SbFacts,
    delivery: ImageDelivery,
    /// Pinned image-output directory that owns the disk and metadata names.
    directory: ValidatedImageDirectory,
    /// Exact validated disk store output retained through commit.
    disk: ValidatedImageFile,
    /// Exact validated metadata store output retained through commit.
    image_info: ValidatedImageFile,
    /// Original producer metadata retained to detect replacement before commit.
    producer_image_info: ValidatedImageFile,
    /// Exact UKI whose Secure Boot facts were recorded in the catalog.
    uki: ValidatedImageFile,
    /// Byte offset of the ESP in the canonical raw logical disk.
    esp_offset_bytes: u64,
    /// Byte interval of the canonical root filesystem payload.
    root_range: (u64, u64),
    /// Exact byte length of the reconstructed canonical raw disk.
    virtual_size_bytes: u64,
}

struct ValidatedImageDirectory {
    path: PathBuf,
    file: fs::File,
    identity: FileIdentity,
}

struct ValidatedImageFile {
    path: PathBuf,
    file: fs::File,
    identity: FileIdentity,
    path_bound: bool,
}

#[derive(Clone, PartialEq, Eq)]
struct FileIdentity {
    len: u64,
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    links: u64,
}

/// Delivery fields emitted by every system image derivation's
/// `image-info.json`.
///
/// The complete, versioned public producer manifest. Unknown top-level and
/// nested fields are rejected so private build-environment data can never be
/// uploaded accidentally.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProducerImageInfo {
    schema_version: u32,
    name: String,
    version: String,
    architecture: String,
    platform: String,
    format: String,
    filename: String,
    media_type: String,
    compression: ImageCompression,
    byte_size: u64,
    virtual_size_bytes: u64,
    sha256: String,
    logical_disk_sha256: String,
    rootfs_sha256: String,
    artifact_budgets_mi_b: ProducerArtifactBudgets,
    #[serde(default)]
    module_abi: Option<u32>,
    compatible_targets: Vec<ImageTarget>,
    uki: PortableUkiInfo,
    #[serde(default)]
    disk_size_mi_b: Option<u64>,
    #[serde(default)]
    esp_size_mi_b: Option<u64>,
    #[serde(default)]
    esp_budget: Option<ProducerEspBudget>,
    #[serde(default)]
    root_size_mi_b: Option<u64>,
    #[serde(default)]
    partition_table: Option<String>,
    #[serde(default)]
    kernel_params: Option<String>,
    #[serde(default)]
    partitions: Vec<ProducerPartitionInfo>,
    #[serde(default)]
    esp: Option<ProducerEspInfo>,
    #[serde(default)]
    recovery: Option<ProducerRecoveryInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PortableUkiInfo {
    filename: String,
    esp_path: String,
    byte_size: u64,
    sha256: String,
    signed: bool,
    measured: bool,
}

/// Maximum artifact sizes and storage geometry declared by an image producer.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProducerArtifactBudgets {
    root: u64,
    verity: u64,
    initrd: u64,
    uki: u64,
    esp: u64,
    runtime_closure: u64,
    download: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProducerRecoveryInfo {
    abi: u32,
    release: String,
    command_line: String,
    copies: ProducerRecoveryCopies,
    entries: ProducerRecoveryEntries,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProducerRecoveryCopies {
    #[serde(rename = "A")]
    a: ProducerRecoveryCopy,
    #[serde(rename = "B")]
    b: ProducerRecoveryCopy,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProducerRecoveryCopy {
    esp_path: String,
    byte_size: u64,
    sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProducerRecoveryEntries {
    #[serde(rename = "A")]
    a: String,
    #[serde(rename = "B")]
    b: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProducerPartitionInfo {
    number: u32,
    label: String,
    #[serde(rename = "type")]
    kind: String,
    filesystem: String,
    size_mi_b: u64,
    offset_bytes: u64,
    size_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProducerEspInfo {
    uki: String,
    sd_boot: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProducerEspBudget {
    installed_bytes: u64,
    transaction_bytes: u64,
    required_bytes: u64,
    partition_bytes: u64,
}

/// Verifies that declared budgets agree with observable image metadata.
fn validate_image_artifact_budgets(
    budgets: &ProducerArtifactBudgets,
    download_size: u64,
    uki_size: u64,
    partitions: &[ProducerPartitionInfo],
) -> Result<()> {
    let nonzero = [
        budgets.root,
        budgets.verity,
        budgets.initrd,
        budgets.uki,
        budgets.esp,
        budgets.runtime_closure,
        budgets.download,
    ]
    .into_iter()
    .all(|value| value > 0);
    let uki_fits = uki_size <= budgets.uki.saturating_mul(1024 * 1024);
    let download_fits = download_size <= budgets.download.saturating_mul(1024 * 1024);
    let esp_holds_two_ukis = budgets.esp >= budgets.uki.saturating_mul(2).saturating_add(32);
    let partition_contracts_match = partitions.iter().all(|partition| {
        let exact_size = partition.size_bytes == partition.size_mi_b.saturating_mul(1024 * 1024);
        let budget_matches = match partition.kind.as_str() {
            "esp" => partition.size_mi_b == budgets.esp,
            // Root partitions are fixed storage capacity, while the root
            // budget is an artifact growth ceiling. The image module permits
            // intentional update headroom but rejects undersized partitions.
            "root" => partition.size_mi_b >= budgets.root,
            "verity" => partition.size_mi_b == budgets.verity,
            _ => true,
        };
        exact_size && budget_matches
    });
    if !nonzero || !uki_fits || !download_fits || !esp_holds_two_ukis || !partition_contracts_match
    {
        bail!("image-info artifact budgets disagree with the image payload or partition layout");
    }
    Ok(())
}

const MAX_IMAGE_INFO_BYTES: u64 = 1024 * 1024;
const MAX_LOGICAL_DISK_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const CANONICAL_GPT_TAIL_BYTES: u64 = 1024 * 1024;
const MAX_ZSTD_WINDOW_LOG: u32 = 27;

/// Rejects decompression sizes that are unbounded or disagree with GPT geometry.
fn validate_logical_disk_geometry(
    virtual_size_bytes: u64,
    partition_ranges: &[(u64, u64)],
) -> Result<()> {
    let partition_end = partition_ranges
        .last()
        .map(|range| range.1)
        .context("image-info must declare at least one partition")?;
    let expected_virtual_size = partition_end
        .checked_add(CANONICAL_GPT_TAIL_BYTES)
        .context("image-info partition geometry overflows")?;
    if virtual_size_bytes != expected_virtual_size || virtual_size_bytes > MAX_LOGICAL_DISK_BYTES {
        bail!(
            "image-info virtualSizeBytes must equal the canonical GPT extent and may not exceed {} bytes",
            MAX_LOGICAL_DISK_BYTES
        );
    }
    Ok(())
}

/// Validates one image store output and constructs its signed delivery entry.
///
/// The payload directory supplies authenticated layout, update, and recovery
/// facts. The downloadable disk and metadata are separate regular-file store
/// outputs, so cache publication never discovers an artifact by enumeration.
fn inspect_published_image(
    format: &str,
    payload: StorePathInfo,
    disk_store: StorePathInfo,
    info_store: StorePathInfo,
    uki_path: &Path,
    name: &str,
    release: &str,
    platform: &str,
    db_cert: Option<&Path>,
) -> Result<PublishedImage> {
    if store_dir_from_store_path(&payload.path).is_none() {
        bail!("published image payload must be a canonical Nix store path");
    }
    let canonical_payload = fs::canonicalize(&payload.path)
        .with_context(|| format!("canonicalizing image payload {}", payload.path))?;
    if canonical_payload != Path::new(&payload.path) {
        bail!("published image payload must not traverse aliases or symlinks");
    }
    let Some(uki_store) = uki_path.parent() else {
        bail!("published UKI must live directly in a Nix store output");
    };
    let Some(uki_store_text) = uki_store.to_str() else {
        bail!("published UKI store path is not UTF-8");
    };
    if store_dir_from_store_path(uki_store_text).is_none()
        || fs::canonicalize(uki_store)? != uki_store
    {
        bail!("published UKI must live directly in a canonical Nix store output");
    }
    let image = inspect_published_image_with(
        format,
        payload,
        disk_store,
        info_store,
        uki_path,
        name,
        release,
        platform,
        db_cert,
        derive_sb_facts,
    )?;
    verify_embedded_uki(&image)?;
    Ok(image)
}

fn inspect_published_image_with<F>(
    format: &str,
    payload: StorePathInfo,
    disk_store: StorePathInfo,
    info_store: StorePathInfo,
    uki_path: &Path,
    name: &str,
    release: &str,
    platform: &str,
    db_cert: Option<&Path>,
    derive_secure_boot: F,
) -> Result<PublishedImage>
where
    F: FnOnce(&Path, Option<&Path>) -> Result<SbFacts>,
{
    let root_path = PathBuf::from(&payload.path);
    let root = root_path.as_path();
    let immutable_store_output = store_dir_from_store_path(&payload.path).is_some();
    let root_meta = fs::symlink_metadata(root)
        .with_context(|| format!("inspecting image output {}", root.display()))?;
    if root_meta.file_type().is_symlink() || !root_meta.is_dir() {
        bail!(
            "image output must be a real directory containing one disk file and image-info.json: {}",
            root.display()
        );
    }
    let root_handle = rustix::fs::open(
        root,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .with_context(|| format!("opening image output directory {}", root.display()))?;
    let root_file = fs::File::from(root_handle);
    let root_identity = file_identity(&root_file.metadata()?);
    if file_identity(&root_meta) != root_identity {
        bail!("image output directory identity changed while opening");
    }

    let info_path = root.join("image-info.json");
    let (mut info_file, info_identity) = open_stable_regular_file_at_with_links(
        &root_file,
        "image-info.json",
        &info_path,
        immutable_store_output,
    )?;
    if info_identity.len == 0 || info_identity.len > MAX_IMAGE_INFO_BYTES {
        bail!("image-info.json size must be between 1 and {MAX_IMAGE_INFO_BYTES} bytes");
    }
    let mut info_bytes = Vec::with_capacity(info_identity.len as usize);
    (&mut info_file)
        .take(MAX_IMAGE_INFO_BYTES + 1)
        .read_to_end(&mut info_bytes)
        .with_context(|| format!("reading image metadata {}", info_path.display()))?;
    if info_bytes.len() as u64 != info_identity.len {
        bail!("image-info.json length changed while it was being read");
    }
    verify_stable_regular_file(&info_path, &info_file, &info_identity)?;
    let producer: ProducerImageInfo = serde_json::from_slice(&info_bytes)
        .with_context(|| format!("parsing {}", info_path.display()))?;
    if producer.schema_version != 2 {
        bail!("image-info schemaVersion must be 2");
    }
    let public_text = std::str::from_utf8(&info_bytes).context("image-info.json is not UTF-8")?;
    if public_text.contains("/nix/store/")
        || public_text.contains("/aos/store/")
        || public_text.contains("file://")
    {
        bail!("image-info.json contains a private build or filesystem path");
    }
    validate_single_filename(&producer.filename, "image filename")?;
    validate_single_filename(&producer.uki.filename, "UKI filename")?;
    validate_portable_relative_path(&producer.uki.esp_path, "UKI ESP path")?;
    if producer.virtual_size_bytes == 0 {
        bail!("image-info virtualSizeBytes must be non-zero");
    }
    validate_lower_sha256(&producer.logical_disk_sha256, "logical disk")?;
    validate_lower_sha256(&producer.rootfs_sha256, "root filesystem")?;
    validate_package_name(&producer.name).context("validating image-info name")?;
    if producer.name != name {
        bail!("image-info name does not match the signed package name");
    }
    if producer.partition_table.as_deref() != Some("gpt")
        || producer.kernel_params.is_none()
        || producer.partitions.is_empty()
        || producer.esp.is_none()
    {
        bail!(
            "image-info must declare canonical GPT layout, kernel parameters, partitions, and ESP facts"
        );
    }
    let mut partition_numbers = HashSet::new();
    let mut partition_ranges = Vec::new();
    for partition in &producer.partitions {
        if !partition_numbers.insert(partition.number)
            || partition.label.is_empty()
            || partition.kind.is_empty()
            || partition.filesystem.is_empty()
            || partition.size_bytes == 0
            || partition.size_mi_b != partition.size_bytes / (1024 * 1024)
            || partition
                .offset_bytes
                .checked_add(partition.size_bytes)
                .is_none_or(|end| end > producer.virtual_size_bytes)
        {
            bail!("image-info contains an invalid partition layout");
        }
        partition_ranges.push((
            partition.offset_bytes,
            partition.offset_bytes + partition.size_bytes,
        ));
    }
    partition_ranges.sort_unstable();
    if partition_ranges
        .windows(2)
        .any(|ranges| ranges[0].1 > ranges[1].0)
    {
        bail!("image-info partition layout overlaps");
    }
    validate_logical_disk_geometry(producer.virtual_size_bytes, &partition_ranges)?;
    if producer
        .esp
        .as_ref()
        .is_some_and(|esp| esp.uki != producer.uki.esp_path)
    {
        bail!("image-info ESP UKI path disagrees with the signed UKI identity");
    }
    let esp_partition = producer
        .partitions
        .iter()
        .find(|partition| partition.kind == "esp" && partition.filesystem == "vfat")
        .context("image-info must identify exactly one vfat ESP partition")?;
    let esp_offset_bytes = esp_partition.offset_bytes;
    if producer
        .partitions
        .iter()
        .filter(|partition| partition.kind == "esp" && partition.filesystem == "vfat")
        .count()
        != 1
    {
        bail!("image-info must identify exactly one vfat ESP partition");
    }
    let roots = producer
        .partitions
        .iter()
        .filter(|partition| partition.kind == "root" && partition.label == "root-a")
        .collect::<Vec<_>>();
    if roots.len() != 1 {
        bail!("image-info must identify exactly one root-a filesystem partition");
    }
    let root_range = (roots[0].offset_bytes, roots[0].size_bytes);
    if let Some(esp) = &producer.esp {
        validate_portable_relative_path(&esp.sd_boot, "systemd-boot ESP path")?;
    }
    if producer
        .disk_size_mi_b
        .is_some_and(|size| size != producer.virtual_size_bytes / (1024 * 1024))
        || producer.esp_size_mi_b == Some(0)
        || producer.root_size_mi_b == Some(0)
    {
        bail!("image-info MiB summaries disagree with the exact logical layout");
    }
    validate_image_artifact_budgets(
        &producer.artifact_budgets_mi_b,
        producer.byte_size,
        producer.uki.byte_size,
        &producer.partitions,
    )?;
    if let Some(budget) = &producer.esp_budget {
        let calculated = budget
            .installed_bytes
            .checked_add(budget.transaction_bytes)
            .and_then(|bytes| bytes.checked_add(32 * 1024 * 1024))
            .context("image-info ESP budget overflows")?;
        if budget.installed_bytes == 0
            || budget.transaction_bytes == 0
            || budget.required_bytes != calculated
            || budget.partition_bytes != esp_partition.size_bytes
            || budget.required_bytes > budget.partition_bytes
        {
            bail!("image-info ESP budget disagrees with the exact partition layout");
        }
    } else if producer.recovery.is_some() {
        bail!("recovery image-info must include the ESP transaction budget");
    }

    let mut entry_count = 0_u8;
    let mut auxiliary_names = HashSet::new();
    for entry in fs::read_dir(root)
        .with_context(|| format!("enumerating image output {}", root.display()))?
    {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() || !file_type.is_file() {
            bail!(
                "image output contains a symlink, directory, or special entry: {}",
                entry.path().display()
            );
        }
        let name = entry.file_name();
        let is_primary = name == std::ffi::OsStr::new("image-info.json")
            || name == std::ffi::OsStr::new(producer.filename.as_str());
        let is_auxiliary = name.to_str().is_some_and(|name| {
            matches!(
                name,
                "root.img"
                    | "root.verity"
                    | "root.roothash"
                    | "root.roothash.p7s"
                    | "uki-a.efi"
                    | "uki-b.efi"
                    | "recovery-a.efi"
                    | "recovery-b.efi"
                    | "recovery-a.conf"
                    | "recovery-b.conf"
                    | "recovery-bundle.json"
                    | "recovery-bundle.json.sig"
            )
        });
        if !is_primary && !is_auxiliary {
            bail!(
                "image output contains an ambiguous unreferenced artifact: {}",
                entry.path().display()
            );
        }
        if is_auxiliary {
            auxiliary_names.insert(name);
        }
        entry_count = entry_count
            .checked_add(1)
            .context("image output contains too many entries")?;
    }
    if entry_count < 2 {
        bail!("image output must contain one disk file and image-info.json");
    }
    let has_uki_a = auxiliary_names.contains(std::ffi::OsStr::new("uki-a.efi"));
    let has_uki_b = auxiliary_names.contains(std::ffi::OsStr::new("uki-b.efi"));
    if has_uki_a != has_uki_b {
        bail!("A/B image output must carry both uki-a.efi and uki-b.efi");
    }
    let recovery_count = [
        "recovery-a.efi",
        "recovery-b.efi",
        "recovery-a.conf",
        "recovery-b.conf",
    ]
    .iter()
    .filter(|name| auxiliary_names.contains(std::ffi::OsStr::new(name)))
    .count();
    if recovery_count != 0 && recovery_count != 4 {
        bail!("recovery image output must carry both UKIs and both loader entries");
    }
    if !auxiliary_names.is_empty() && !auxiliary_names.contains(std::ffi::OsStr::new("root.img")) {
        bail!("runtime-update image output must carry root.img");
    }

    let payload_image_path = root.join(&producer.filename);
    let (mut payload_image_file, payload_image_identity) = open_stable_regular_file_at_with_links(
        &root_file,
        &producer.filename,
        &payload_image_path,
        immutable_store_output,
    )?;
    let payload_sha256 = sha256_open_file(&mut payload_image_file, &payload_image_path)?;
    verify_stable_regular_file(
        &payload_image_path,
        &payload_image_file,
        &payload_image_identity,
    )?;

    let (mut image_file, image_identity, image_path) =
        open_canonical_store_regular_file(&disk_store, "image disk")?;
    let actual_sha256 = sha256_open_file(&mut image_file, &image_path)?;
    verify_stable_regular_file(&image_path, &image_file, &image_identity)?;
    let actual_size = image_identity.len;
    if payload_image_identity.len != actual_size || payload_sha256 != actual_sha256 {
        bail!("image payload disk does not match the explicit disk store output");
    }
    if producer.format != format {
        bail!(
            "--image-format '{format}' does not match image-info format '{}'",
            producer.format
        );
    }
    if producer.version != release {
        bail!("image-info version does not match the signed package release");
    }
    if producer.platform != platform {
        bail!("image-info platform does not match the signed platform");
    }
    if producer.byte_size != actual_size {
        bail!("image-info byteSize does not match the disk file");
    }
    if producer.sha256 != actual_sha256 {
        bail!("image-info sha256 does not match the disk file");
    }
    if !producer.uki.filename.ends_with(".efi") {
        bail!("image-info UKI filename must end in .efi");
    }
    let immutable_uki_output = uki_path
        .parent()
        .and_then(Path::to_str)
        .is_some_and(|parent| store_dir_from_store_path(parent).is_some());
    let (mut uki_file, uki_identity) =
        open_stable_regular_file_with_links(uki_path, immutable_uki_output)?;
    let uki_sha256 = sha256_open_file(&mut uki_file, uki_path)?;
    verify_stable_regular_file(uki_path, &uki_file, &uki_identity)?;
    if producer.uki.byte_size != uki_identity.len || producer.uki.sha256 != uki_sha256 {
        bail!("image-info UKI size or SHA-256 does not match the associated UKI");
    }

    let logical_identity = serde_json::json!({
        "schemaVersion": producer.schema_version,
        "release": &producer.version,
        "platform": &producer.platform,
        "architecture": &producer.architecture,
        "virtualSizeBytes": producer.virtual_size_bytes,
        "logicalDiskSha256": &producer.logical_disk_sha256,
        "rootfsSha256": &producer.rootfs_sha256,
        "partitionTable": &producer.partition_table,
        "kernelParams": &producer.kernel_params,
        "partitions": &producer.partitions,
        "uki": &producer.uki,
        "recovery": &producer.recovery,
    });
    let logical_image_id = sha256_hex(&serde_json::to_vec(&logical_identity)?);
    let producer_uki_signed = producer.uki.signed;
    let producer_uki_measured = producer.uki.measured;

    // Derive every verification claim from the exact pinned UKI descriptor.
    // The outer production path additionally proves these bytes are embedded
    // at the signed ESP path before the catalog can be committed.
    let (_verification_file, verification_path) = inheritable_procfd(&uki_file, uki_path)?;
    let mut sb = derive_secure_boot(&verification_path, db_cert)
        .with_context(|| format!("deriving Secure Boot facts for {}", uki_path.display()))?;
    verify_stable_regular_file(uki_path, &uki_file, &uki_identity)?;
    if producer_uki_signed != sb.signer_cert_sha256.is_some() {
        bail!("image-info UKI signed state does not match its Authenticode signature");
    }
    if producer_uki_measured != sb.expected_pcr11.is_some() {
        bail!("image-info UKI measured state does not match its PCR-11 policy");
    }
    sb.ukis = derive_slot_uki_facts(root, db_cert)?;
    sb.recovery_ukis =
        derive_recovery_uki_facts(root, producer.recovery.as_ref(), &producer.version, db_cert)?;
    if let Some(slot_a) = sb.ukis.iter().find(|uki| uki.slot == UkiSlot::A)
        && (slot_a.sb_signer_cert_sha256 != sb.signer_cert_sha256
            || slot_a.sbat != sb.sbat
            || slot_a.expected_pcr11 != sb.expected_pcr11)
    {
        bail!("slot-A UKI facts disagree with the UKI embedded in the published disk");
    }

    sb.recovery_bundle = derive_recovery_bundle_manifest(
        root,
        producer.recovery.as_ref(),
        producer.module_abi,
        &producer.version,
        &producer.architecture,
        &producer.platform,
    )?;
    if let Some(expected_bundle) = &sb.recovery_bundle {
        let bundle_path = root.join("recovery-bundle.json");
        let signature_path = root.join("recovery-bundle.json.sig");
        let bundle_metadata = fs::symlink_metadata(&bundle_path)?;
        let signature_metadata = fs::symlink_metadata(&signature_path)?;
        if !bundle_metadata.file_type().is_file()
            || bundle_metadata.len() == 0
            || bundle_metadata.len() > 256 * 1024
            || !signature_metadata.file_type().is_file()
            || signature_metadata.len() == 0
            || signature_metadata.len() > 16 * 1024
        {
            bail!("recovery bundle manifest or signature is outside its size bound");
        }
        let published_bundle: RecoveryBundleManifest =
            serde_json::from_slice(&fs::read(&bundle_path)?)
                .context("parsing recovery-bundle.json")?;
        if &published_bundle != expected_bundle {
            bail!("recovery-bundle.json disagrees with the authenticated image components");
        }
        let db_cert =
            db_cert.context("publishing a recovery bundle requires the registry db certificate")?;
        verify_detached_db_signature(&bundle_path, &signature_path, db_cert)?;
    }
    let (mut canonical_info_file, canonical_info_identity, canonical_info_path) =
        open_canonical_store_regular_file(&info_store, "image metadata")?;
    let mut published_info_bytes = Vec::with_capacity(canonical_info_identity.len as usize);
    (&mut canonical_info_file)
        .take(MAX_IMAGE_INFO_BYTES + 1)
        .read_to_end(&mut published_info_bytes)
        .with_context(|| format!("reading image metadata {}", canonical_info_path.display()))?;
    verify_stable_regular_file(
        &canonical_info_path,
        &canonical_info_file,
        &canonical_info_identity,
    )?;
    if published_info_bytes != info_bytes {
        bail!("explicit image metadata output does not match the payload image-info.json");
    }
    let info_sha256 = sha256_hex(&published_info_bytes);
    canonical_info_file.seek(SeekFrom::Start(0))?;
    let delivery = ImageDelivery {
        schema_version: producer.schema_version,
        release: release.to_string(),
        platform: producer.platform,
        architecture: producer.architecture,
        logical_image_id,
        logical_disk_sha256: producer.logical_disk_sha256,
        rootfs_sha256: producer.rootfs_sha256,
        filename: producer.filename,
        object_key: String::new(),
        media_type: producer.media_type,
        compression: producer.compression,
        byte_size: producer.byte_size,
        sha256: producer.sha256,
        compatible_targets: producer.compatible_targets,
        uki: ImageUkiIdentity {
            filename: producer.uki.filename,
            esp_path: producer.uki.esp_path,
            byte_size: producer.uki.byte_size,
            sha256: producer.uki.sha256,
            verification: if producer_uki_signed {
                ImageVerificationState::SignedUnverified
            } else {
                ImageVerificationState::Unsigned
            },
            signer_cert_sha256: sb.signer_cert_sha256.clone(),
            sbat: sb.sbat.clone(),
            measured: producer_uki_measured,
            expected_pcr11: sb.expected_pcr11.clone(),
        },
        image_info: ImageInfoReference {
            filename: "image-info.json".to_string(),
            object_key: String::new(),
            store_path: info_store.path.clone(),
            nar_hash: info_store.nar_hash.clone(),
            nar_size: info_store.nar_size,
            media_type: "application/vnd.aos.image-info+json".to_string(),
            byte_size: published_info_bytes.len() as u64,
            sha256: info_sha256.clone(),
        },
        update_payload: Some(ImageStoreReference {
            store_path: payload.path.clone(),
            nar_hash: payload.nar_hash.clone(),
            nar_size: payload.nar_size,
        }),
    };
    delivery
        .validate(format, release, platform)
        .with_context(|| format!("validating direct delivery contract for {format}"))?;
    Ok(PublishedImage {
        format: format.to_string(),
        payload,
        store: disk_store,
        info_store,
        sb,
        delivery,
        directory: ValidatedImageDirectory {
            path: root_path,
            file: root_file,
            identity: root_identity,
        },
        disk: ValidatedImageFile {
            path: image_path,
            file: image_file,
            identity: image_identity,
            path_bound: true,
        },
        image_info: ValidatedImageFile {
            path: canonical_info_path,
            file: canonical_info_file,
            identity: canonical_info_identity,
            path_bound: true,
        },
        producer_image_info: ValidatedImageFile {
            path: info_path,
            file: info_file,
            identity: info_identity,
            path_bound: true,
        },
        uki: ValidatedImageFile {
            path: uki_path.to_path_buf(),
            file: uki_file,
            identity: uki_identity,
            path_bound: true,
        },
        esp_offset_bytes,
        root_range,
        virtual_size_bytes: producer.virtual_size_bytes,
    })
}

fn validate_lower_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} SHA-256 must be 64 lowercase hexadecimal characters");
    }
    Ok(())
}

fn open_canonical_store_regular_file(
    store: &StorePathInfo,
    label: &str,
) -> Result<(fs::File, FileIdentity, PathBuf)> {
    if store_dir_from_store_path(&store.path).is_none() {
        bail!("published {label} must be a canonical Nix store path");
    }
    let path = PathBuf::from(&store.path);
    let canonical = fs::canonicalize(&path)
        .with_context(|| format!("canonicalizing {label} {}", path.display()))?;
    if canonical != path {
        bail!("published {label} must not traverse aliases or symlinks");
    }
    let (file, identity) = open_stable_regular_file_with_links(&path, true)
        .with_context(|| format!("opening {label} {}", path.display()))?;
    Ok((file, identity, path))
}

/// Persists the deterministic transaction marker uploaded after image/catalog
/// immutables and before any release or channel pointer.
fn persist_image_publication_receipt(registry_dir: &Path) -> Result<()> {
    let repository = git2::Repository::open(registry_dir).context("opening image registry")?;
    let commit = repository
        .head()
        .context("reading image publication HEAD")?
        .peel_to_commit()
        .context("resolving image publication commit")?;
    let commit_id = commit.id().to_string();
    let tree = commit.tree().context("reading image publication tree")?;
    let objects = committed_image_receipt_objects(&repository, &tree)?;
    if objects.is_empty() {
        return Ok(());
    }
    let registry = committed_registry_identity(&repository, &tree)?;
    let catalog_digest = aos_registry_surface::manifest::image_catalog_digest(
        &registry,
        objects.values().map(|object| {
            (
                object.key.as_str(),
                object.role,
                object.byte_size,
                object.sha256.as_str(),
            )
        }),
    );
    let bytes = serde_json::to_vec(&ImagePublicationReceipt {
        schema_version: 1,
        commit: &commit_id,
        registry: &registry,
        catalog_digest: &catalog_digest,
        objects: objects.into_values().collect(),
    })?;
    let git_dir = objectstore::repo_git_dir(registry_dir)?;
    let destination = git_dir
        .join("aos-static-origin/publication-receipts")
        .join(format!("{commit_id}.json"));
    if let Some(existing) = fs::read(&destination)
        .ok()
        .filter(|existing| existing == &bytes)
    {
        let _ = existing;
        return Ok(());
    }
    if destination.exists() {
        bail!("image publication receipt for commit {commit_id} has conflicting bytes");
    }
    let parent = destination
        .parent()
        .context("publication receipt has no parent")?;
    fs::create_dir_all(parent)?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".aos-image-receipt-")
        .tempfile_in(parent)?;
    temporary.write_all(&bytes)?;
    temporary.as_file_mut().sync_all()?;
    temporary
        .persist_noclobber(&destination)
        .map_err(|error| error.error)
        .with_context(|| format!("persisting image publication receipt for {commit_id}"))?;
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ImagePublicationReceipt<'a> {
    schema_version: u32,
    commit: &'a str,
    registry: &'a str,
    catalog_digest: &'a str,
    objects: Vec<ImagePublicationReceiptObject>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ImagePublicationReceiptObject {
    key: String,
    role: &'static str,
    byte_size: u64,
    sha256: String,
}

fn committed_registry_identity(
    repository: &git2::Repository,
    root: &git2::Tree<'_>,
) -> Result<String> {
    let entry = root
        .get_name("registry.toml")
        .context("image publication commit has no registry.toml")?;
    let blob = entry
        .to_object(repository)
        .context("reading committed registry.toml")?
        .peel_to_blob()
        .context("committed registry.toml is not a file")?;
    let content =
        std::str::from_utf8(blob.content()).context("committed registry.toml is not UTF-8")?;
    let root: RegistryRootConfig =
        toml::from_str(content).context("parsing committed registry.toml")?;
    if root.registry.name.is_empty() {
        bail!("committed registry identity is empty");
    }
    Ok(root.registry.name)
}

/// Collects every image object identity from the exact committed package tree.
///
/// A receipt describes the full signed image catalog at that commit, rather
/// than only the formats added by the latest command. This makes a fresh
/// indexer able to validate the transaction marker without reconstructing
/// publication history.
fn committed_image_receipt_objects(
    repository: &git2::Repository,
    root: &git2::Tree<'_>,
) -> Result<BTreeMap<String, ImagePublicationReceiptObject>> {
    let Some(packages_entry) = root.get_name("packages") else {
        return Ok(BTreeMap::new());
    };
    let packages = packages_entry
        .to_object(repository)
        .context("reading committed packages tree")?
        .peel_to_tree()
        .context("committed packages path is not a tree")?;
    let mut objects = BTreeMap::new();
    for bucket_entry in &packages {
        let bucket = bucket_entry
            .to_object(repository)
            .context("reading committed package bucket")?
            .peel_to_tree()
            .context("committed package bucket is not a tree")?;
        for package_entry in &bucket {
            let name = package_entry
                .name()
                .context("committed package has no name")?;
            if !name.ends_with(".toml") {
                continue;
            }
            let blob = package_entry
                .to_object(repository)
                .with_context(|| format!("reading committed package '{name}'"))?
                .peel_to_blob()
                .with_context(|| format!("committed package '{name}' is not a file"))?;
            let content = std::str::from_utf8(blob.content())
                .with_context(|| format!("committed package '{name}' is not UTF-8"))?;
            let package = crate::registry::parse::parse_package_file(content)
                .with_context(|| format!("parsing committed package '{name}'"))?;
            if !package.package.sysroot {
                continue;
            }
            for version in package.versions {
                for (platform, artifact) in version.platforms {
                    for image in artifact.images {
                        image.validate_delivery(&version.version, &platform)?;
                        if image.delivery.is_store_backed() {
                            continue;
                        }
                        insert_image_receipt_object(
                            &mut objects,
                            ImagePublicationReceiptObject {
                                key: image.delivery.object_key,
                                role: "disk",
                                byte_size: image.delivery.byte_size,
                                sha256: image.delivery.sha256,
                            },
                        )?;
                        insert_image_receipt_object(
                            &mut objects,
                            ImagePublicationReceiptObject {
                                key: image.delivery.image_info.object_key,
                                role: "image-info",
                                byte_size: image.delivery.image_info.byte_size,
                                sha256: image.delivery.image_info.sha256,
                            },
                        )?;
                    }
                }
            }
        }
    }
    Ok(objects)
}

fn insert_image_receipt_object(
    objects: &mut BTreeMap<String, ImagePublicationReceiptObject>,
    object: ImagePublicationReceiptObject,
) -> Result<()> {
    match objects.entry(object.key.clone()) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(object);
        }
        std::collections::btree_map::Entry::Occupied(entry) if entry.get() == &object => {}
        std::collections::btree_map::Entry::Occupied(entry) => {
            bail!(
                "committed image object key '{}' has conflicting identities",
                entry.key()
            );
        }
    }
    Ok(())
}

/// Duplicates a pinned descriptor and exposes only that descriptor to a child.
#[cfg(target_os = "linux")]
fn inheritable_procfd(file: &fs::File, _fallback: &Path) -> Result<(fs::File, PathBuf)> {
    let duplicate = file
        .try_clone()
        .context("duplicating pinned image descriptor")?;
    rustix::io::fcntl_setfd(&duplicate, rustix::io::FdFlags::empty())
        .context("making pinned image descriptor inheritable")?;
    let path = PathBuf::from(format!("/proc/self/fd/{}", duplicate.as_raw_fd()));
    Ok((duplicate, path))
}

#[cfg(not(target_os = "linux"))]
fn inheritable_procfd(file: &fs::File, fallback: &Path) -> Result<(fs::File, PathBuf)> {
    Ok((
        file.try_clone()
            .context("duplicating pinned image descriptor")?,
        fallback.to_path_buf(),
    ))
}

/// Proves that the separately verified UKI is byte-identical to the UKI
/// embedded in the disk image at the signed ESP path.
#[cfg(target_os = "linux")]
fn decompress_raw_disk(
    source: impl std::io::Read,
    destination: &mut impl std::io::Write,
    expected_size: u64,
) -> Result<()> {
    let mut decoder =
        zstd::stream::read::Decoder::new(source).context("opening compressed raw disk")?;
    decoder
        .window_log_max(MAX_ZSTD_WINDOW_LOG)
        .context("bounding compressed raw disk decode window")?;
    let copied = std::io::copy(
        &mut decoder.take(expected_size.saturating_add(1)),
        destination,
    )
    .context("decompressing canonical raw disk")?;
    if copied != expected_size {
        bail!("compressed raw image expands to {copied} bytes, expected {expected_size}");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn decompress_pinned_raw_disk(
    source: &fs::File,
    destination: &mut impl std::io::Write,
    expected_size: u64,
) -> Result<()> {
    let mut disk = source
        .try_clone()
        .context("duplicating compressed raw disk")?;
    // File::try_clone shares the open-file-description offset on Unix. Image
    // hashing intentionally leaves that offset at EOF, so every independent
    // consumer must establish its own starting position before reading.
    disk.seek(SeekFrom::Start(0))?;
    decompress_raw_disk(disk, destination, expected_size)
}

#[cfg(target_os = "linux")]
fn verify_embedded_uki(image: &PublishedImage) -> Result<()> {
    let mut raw = tempfile::tempfile().context("creating pinned raw-image verification file")?;
    let raw_input;
    let raw_path = if image.format == "raw" {
        decompress_pinned_raw_disk(&image.disk.file, &mut raw, image.virtual_size_bytes)?;
        raw.seek(SeekFrom::Start(0))?;
        let (file, path) = inheritable_procfd(&raw, Path::new("<raw image>"))?;
        raw_input = Some(file);
        path
    } else {
        let (input_file, input_path) = inheritable_procfd(&image.disk.file, &image.disk.path)?;
        // qemu-img must write through the already-open descriptor so path
        // replacement cannot redirect verification. Pre-size the bounded raw
        // target and use -n to suppress target creation and overwrite prompts.
        raw.set_len(image.virtual_size_bytes)
            .context("sizing pinned raw-image verification file")?;
        let (output_file, output_path) = inheritable_procfd(&raw, Path::new("<raw image>"))?;
        let qemu_img = std::env::var_os("AOS_QEMU_IMG")
            .map(PathBuf::from)
            .context("AOS_QEMU_IMG is required to verify converted image contents")?;
        let input_format = if image.format == "vhd" {
            "vpc"
        } else {
            image.format.as_str()
        };
        let status = Command::new(qemu_img)
            .args(["convert", "-n", "-f", input_format, "-O", "raw"])
            .arg(&input_path)
            .arg(&output_path)
            .status()
            .context("running qemu-img against pinned image descriptors")?;
        drop(output_file);
        drop(input_file);
        if !status.success() {
            bail!("qemu-img failed while materializing the canonical disk for UKI verification");
        }
        raw.seek(SeekFrom::Start(0))?;
        let (file, path) = inheritable_procfd(&raw, Path::new("<raw image>"))?;
        raw_input = Some(file);
        path
    };

    let mut logical_disk = raw.try_clone().context("duplicating canonical raw disk")?;
    let logical_disk_sha256 = sha256_open_file(&mut logical_disk, Path::new("<logical disk>"))?;
    if logical_disk_sha256 != image.delivery.logical_disk_sha256 {
        bail!("image encoding does not materialize the signed canonical logical disk");
    }
    let rootfs_sha256 = sha256_file_range(
        &mut logical_disk,
        image.root_range.0,
        image.root_range.1,
        "root filesystem partition",
    )?;
    if rootfs_sha256 != image.delivery.rootfs_sha256 {
        bail!("disk root filesystem payload does not match signed logical image identity");
    }

    let mut extracted = tempfile::tempfile().context("creating pinned embedded-UKI file")?;
    let (extracted_child, extracted_path) =
        inheritable_procfd(&extracted, Path::new("<embedded UKI>"))?;
    let mcopy = std::env::var_os("AOS_MCOPY")
        .map(PathBuf::from)
        .context("AOS_MCOPY is required to verify embedded image contents")?;
    let image_spec = format!("{}@@{}", raw_path.display(), image.esp_offset_bytes);
    let source = format!("::/{}", image.delivery.uki.esp_path);
    let status = Command::new(mcopy)
        .env("MTOOLS_SKIP_CHECK", "1")
        // The pinned procfd is an existing Unix destination. `-n` prevents
        // mcopy from reading the maintainer's terminal for overwrite consent.
        .args(["-n", "-i"])
        .arg(image_spec)
        .arg(source)
        .arg(&extracted_path)
        .status()
        .context("extracting the embedded UKI through pinned descriptors")?;
    drop(extracted_child);
    drop(raw_input);
    if !status.success() {
        bail!("the declared UKI is not readable from the disk image ESP");
    }
    extracted.seek(SeekFrom::Start(0))?;
    let extracted_identity = file_identity(&extracted.metadata()?);
    let extracted_sha256 = sha256_open_file(&mut extracted, Path::new("<embedded UKI>"))?;
    if extracted_identity.len != image.delivery.uki.byte_size
        || extracted_sha256 != image.delivery.uki.sha256
    {
        bail!("the UKI embedded in the disk does not match the signed catalog UKI identity");
    }
    Ok(())
}

fn sha256_file_range(file: &mut fs::File, offset: u64, length: u64, label: &str) -> Result<String> {
    use sha2::{Digest as _, Sha256};

    file.seek(SeekFrom::Start(offset))
        .with_context(|| format!("seeking to {label}"))?;
    let mut remaining = length;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 128 * 1024];
    while remaining != 0 {
        let wanted = usize::try_from(remaining.min(buffer.len() as u64))?;
        let count = file
            .read(&mut buffer[..wanted])
            .with_context(|| format!("reading {label}"))?;
        if count == 0 {
            bail!("{label} ended before its signed byte length");
        }
        hasher.update(&buffer[..count]);
        remaining -= count as u64;
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(not(target_os = "linux"))]
fn verify_embedded_uki(_image: &PublishedImage) -> Result<()> {
    bail!("image publication requires Linux descriptor-backed verification")
}

fn file_identity(metadata: &fs::Metadata) -> FileIdentity {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt as _;

    FileIdentity {
        len: metadata.len(),
        modified: metadata.modified().ok(),
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
        #[cfg(unix)]
        links: metadata.nlink(),
    }
}

/// Opens a regular file while allowing store-optimizer links only for an
/// already-validated immutable Nix store output.
fn open_stable_regular_file_with_links(
    path: &Path,
    allow_immutable_store_links: bool,
) -> Result<(fs::File, FileIdentity)> {
    let path_metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspecting {}", path.display()))?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        bail!(
            "artifact must be a regular non-symlink file: {}",
            path.display()
        );
    }
    let handle = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .with_context(|| format!("opening {}", path.display()))?;
    let file = fs::File::from(handle);
    let opened_identity = file_identity(&file.metadata()?);
    #[cfg(unix)]
    if !allow_immutable_store_links && opened_identity.links != 1 {
        bail!(
            "artifact must have exactly one hard link: {}",
            path.display()
        );
    }
    if file_identity(&path_metadata) != opened_identity {
        bail!("artifact identity changed while opening {}", path.display());
    }
    Ok((file, opened_identity))
}

/// Opens a direct child while allowing store-optimizer links only for an
/// already-validated immutable Nix store output.
fn open_stable_regular_file_at_with_links(
    directory: &fs::File,
    name: &str,
    display_path: &Path,
    allow_immutable_store_links: bool,
) -> Result<(fs::File, FileIdentity)> {
    let handle = rustix::fs::openat(
        directory,
        name,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .with_context(|| format!("opening {}", display_path.display()))?;
    let file = fs::File::from(handle);
    let identity = file_identity(&file.metadata()?);
    #[cfg(unix)]
    if !allow_immutable_store_links && identity.links != 1 {
        bail!(
            "artifact must have exactly one hard link: {}",
            display_path.display()
        );
    }
    if !file.metadata()?.is_file() {
        bail!(
            "artifact must be a regular file: {}",
            display_path.display()
        );
    }
    Ok((file, identity))
}

impl ValidatedImageFile {
    fn recheck(&self) -> Result<()> {
        if self.path_bound {
            verify_stable_regular_file(&self.path, &self.file, &self.identity)
        } else if file_identity(&self.file.metadata()?) != self.identity {
            bail!("pinned canonical artifact changed before commit")
        } else {
            Ok(())
        }
    }
}

impl PublishedImage {
    fn recheck_for_commit(&self) -> Result<()> {
        let path_metadata = fs::symlink_metadata(&self.directory.path)?;
        if path_metadata.file_type().is_symlink()
            || !path_metadata.is_dir()
            || file_identity(&path_metadata) != self.directory.identity
            || file_identity(&self.directory.file.metadata()?) != self.directory.identity
        {
            bail!("image output directory identity changed before commit");
        }
        self.disk.recheck()?;
        self.image_info.recheck()?;
        self.producer_image_info.recheck()?;
        self.uki.recheck()?;
        Ok(())
    }
}

fn verify_stable_regular_file(path: &Path, file: &fs::File, expected: &FileIdentity) -> Result<()> {
    let descriptor_identity = file_identity(&file.metadata()?);
    let path_metadata =
        fs::symlink_metadata(path).with_context(|| format!("rechecking {}", path.display()))?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_file()
        || &descriptor_identity != expected
        || &file_identity(&path_metadata) != expected
    {
        bail!("artifact identity changed while reading {}", path.display());
    }
    Ok(())
}

fn validate_single_filename(filename: &str, label: &str) -> Result<()> {
    if filename.is_empty()
        || filename.len() > 128
        || !filename.is_ascii()
        || !filename
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
        || !filename
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || filename.contains("..")
    {
        bail!("{label} must be a portable ASCII basename");
    }
    Ok(())
}

fn validate_portable_relative_path(path: &str, label: &str) -> Result<()> {
    if path.is_empty() || path.len() > 256 || !path.is_ascii() || path.contains('\\') {
        bail!("{label} must be a non-empty portable relative path");
    }
    for component in path.split('/') {
        if component.is_empty()
            || component == "."
            || component == ".."
            || !component.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+')
            })
        {
            bail!("{label} must be a non-empty portable relative path");
        }
    }
    Ok(())
}

/// Returns the lowercase hexadecimal SHA-256 read from one retained file
/// descriptor without retaining the potentially large artifact in memory.
fn sha256_open_file(file: &mut fs::File, path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};

    file.seek(SeekFrom::Start(0))
        .with_context(|| format!("seeking image bytes {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("reading image bytes {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Builds a Secure Boot helper command resolved only through the wrapper's
/// hermetic AOS runtime `PATH`.
///
/// `pkgs.aos` includes AOS-built `sbsigntools` and `systemd` in
/// that path. Internal verification must never consult `AOS_HOST_PATH`.
fn sb_tool_command(program: &str) -> Command {
    Command::new(program)
}

/// Hash the signer leaf certificate of a UKI's Authenticode signature.
///
/// Confirms the binary is signed with `sbverify --list <uki>`, then reads
/// the PE security directory directly to recover the Authenticode PKCS#7
/// blob and returns the lowercase hex SHA-256 of its first (leaf)
/// certificate. Returns `Ok(None)` when the binary carries no Authenticode
/// signature (an unsigned image), so unsigned dev builds do not break
/// publishing.
///
/// # Errors
///
/// Returns an error if `sbverify` cannot be spawned, exits with a failure
/// other than "no signature", or the PE/PKCS#7 structure cannot be parsed
/// into a leaf certificate.
fn extract_sb_signer_cert_sha256(uki: &Path) -> Result<Option<String>> {
    let output = sb_tool_command("sbverify")
        .arg("--list")
        .arg(uki)
        .output()
        .with_context(|| format!("running sbverify --list {}", uki.display()))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        // sbverify reports an unsigned binary; treat that as "no facts"
        // rather than a publish failure.
        if stderr.contains("No signature")
            || stdout.contains("No signature")
            || stderr.contains("no signature")
        {
            return Ok(None);
        }
        bail!(
            "sbverify --list {} failed: {}",
            uki.display(),
            combine_output(&stdout, &stderr)
        );
    }

    let bytes = fs::read(uki).with_context(|| format!("reading {}", uki.display()))?;
    let leaf = leaf_cert_from_pe(&bytes)
        .with_context(|| format!("extracting signer cert from {}", uki.display()))?;
    Ok(leaf.map(sha256_hex))
}

/// Return the first (leaf) X.509 certificate DER bytes from a signed PE's
/// Authenticode certificate table.
///
/// Locates the PE security directory (the `WIN_CERTIFICATE` blob holding a
/// PKCS#7 `SignedData`), then walks the DER structure to the embedded
/// certificate set and returns the first certificate's complete DER
/// encoding.
///
/// # Errors
///
/// Returns an error when the PE headers, the security directory, or the
/// PKCS#7 certificate set cannot be parsed.
fn leaf_cert_from_pe(pe: &[u8]) -> Result<Option<&[u8]>> {
    let Some((cert_off, cert_len)) = pe_security_dir(pe)? else {
        return Ok(None);
    };
    let cert_table = pe
        .get(cert_off..cert_off + cert_len)
        .ok_or_else(|| anyhow::anyhow!("security directory extends past end of file"))?;
    // WIN_CERTIFICATE header: dwLength(4) + wRevision(2) + wCertificateType(2).
    let pkcs7 = cert_table
        .get(8..)
        .ok_or_else(|| anyhow::anyhow!("WIN_CERTIFICATE blob too short"))?;
    first_certificate_der(pkcs7).map(Some)
}

/// Parse the PE optional-header data directory entry for the
/// `IMAGE_DIRECTORY_ENTRY_SECURITY` (index 4) certificate table, returning
/// its `(file_offset, size)`.
///
/// # Errors
///
/// Returns an error when the DOS/PE signatures, the optional-header magic,
/// or the data directory cannot be read. An unsigned PE returns `None`.
fn pe_security_dir(pe: &[u8]) -> Result<Option<(usize, usize)>> {
    let read_u16 = |off: usize| -> Option<u16> {
        pe.get(off..off + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
    };
    let read_u32 = |off: usize| -> Option<u32> {
        pe.get(off..off + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };

    if read_u16(0) != Some(0x5a4d) {
        bail!("not a PE image (missing MZ signature)");
    }
    let pe_off = read_u32(0x3c).context("reading e_lfanew")? as usize;
    if read_u32(pe_off) != Some(0x0000_4550) {
        bail!("missing PE signature");
    }
    let coff_off = pe_off
        .checked_add(4)
        .context("PE header offset overflowed")?;
    let optional_size = read_u16(coff_off + 16).context("reading optional-header size")? as usize;
    // COFF header is 20 bytes; the optional header follows.
    let opt_off = coff_off
        .checked_add(20)
        .context("optional-header offset overflowed")?;
    let opt_end = opt_off
        .checked_add(optional_size)
        .context("optional-header size overflowed")?;
    if opt_end > pe.len() {
        bail!("optional header extends past end of PE image");
    }
    let magic = read_u16(opt_off).context("reading optional-header magic")?;
    // The data directory array starts after the windows-specific fields:
    // 96 bytes for PE32 (0x10b), 112 bytes for PE32+ (0x20b).
    let (dir_off, count_off) = match magic {
        0x10b => (opt_off + 96, opt_off + 92),
        0x20b => (opt_off + 112, opt_off + 108),
        other => bail!("unexpected optional-header magic {other:#x}"),
    };
    if count_off.checked_add(4).is_none_or(|end| end > opt_end) {
        bail!("data-directory count is outside the declared optional header");
    }
    let directory_count =
        read_u32(count_off).context("reading optional-header data-directory count")?;
    if directory_count <= 4 {
        return Ok(None);
    }
    // Security directory is entry index 4 (8 bytes each: RVA/offset + size).
    let entry = dir_off + 4 * 8;
    if entry.checked_add(8).is_none_or(|end| end > opt_end) {
        bail!("security directory is outside the declared optional header");
    }
    let offset = read_u32(entry).context("reading security dir offset")? as usize;
    let size = read_u32(entry + 4).context("reading security dir size")? as usize;
    if offset == 0 && size == 0 {
        return Ok(None);
    }
    if offset == 0 || size == 0 {
        bail!("PE security directory has an incomplete certificate table");
    }
    Ok(Some((offset, size)))
}

/// Walk a PKCS#7 `SignedData` DER blob and return the *signer* certificate's
/// complete DER encoding from the `[0] IMPLICIT certificates` field.
///
/// The signer is identified by matching the first `SignerInfo`'s
/// `issuerAndSerialNumber` against each embedded certificate's issuer name
/// and serial number. This correctly picks the leaf even when the embedded
/// cert set is unordered or carries intermediate CA certs.
///
/// # Fallback caveat
///
/// If the `SignerInfo` cannot be located (for example a CMS variant that
/// uses `subjectKeyIdentifier` instead of `issuerAndSerialNumber`, which
/// Authenticode does not use in practice), this falls back to the first
/// certificate in the set. Authenticode signers produced by `sbsign`/`ukify`
/// embed a single end-entity certificate identified by issuer+serial, so the
/// matched path is the one exercised in production; the fallback exists only
/// so an unusual blob degrades to the previous behavior rather than failing.
///
/// # Errors
///
/// Returns an error when the DER structure does not match the expected
/// PKCS#7 `ContentInfo` → `SignedData` → certificates layout, or the
/// certificates field is absent.
fn first_certificate_der(pkcs7: &[u8]) -> Result<&[u8]> {
    // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
    let content_info = der_expect_seq(pkcs7).context("PKCS#7 ContentInfo")?;
    let (_oid, rest) = der_take(content_info).context("ContentInfo.contentType")?;
    // content [0] EXPLICIT
    let (tag, explicit, _) = der_tlv(rest).context("ContentInfo.content")?;
    if tag != 0xA0 {
        bail!("PKCS#7 content is not context-tag [0]");
    }
    // SignedData ::= SEQUENCE { version, digestAlgorithms, contentInfo,
    //   certificates [0] IMPLICIT, ..., signerInfos SET }
    let signed_data = der_expect_seq(explicit).context("SignedData")?;

    let mut certificates: Option<&[u8]> = None;
    let mut signer_infos: Option<&[u8]> = None;
    let mut cursor = signed_data;
    while !cursor.is_empty() {
        let (tag, value, after) = der_tlv(cursor).context("scanning SignedData fields")?;
        match tag {
            // certificates [0] IMPLICIT SET OF Certificate.
            0xA0 => certificates = Some(value),
            // signerInfos SET OF SignerInfo (the final SET in SignedData).
            0x31 => signer_infos = Some(value),
            _ => {}
        }
        cursor = after;
    }

    let certificates = certificates
        .ok_or_else(|| anyhow::anyhow!("PKCS#7 SignedData has no certificates field"))?;

    // Try to pick the cert whose issuer+serial matches the first SignerInfo.
    if let Some(signer_infos) = signer_infos
        && let Some((issuer, serial)) = signer_issuer_and_serial(signer_infos)
        && let Some(cert) = certificate_matching(certificates, issuer, serial)?
    {
        return Ok(cert);
    }

    // Fallback: the first certificate in the set (see caveat).
    der_full_tlv(certificates).context("leaf certificate TLV")
}

/// Extract `(issuerName, serialNumber)` DER slices from the first
/// `SignerInfo`'s `issuerAndSerialNumber`, or `None` if not in that form.
///
/// `SignerInfo ::= SEQUENCE { version, sid IssuerAndSerialNumber, ... }` and
/// `IssuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber INTEGER }`.
fn signer_issuer_and_serial(signer_infos_set: &[u8]) -> Option<(&[u8], &[u8])> {
    // First SignerInfo in the SET.
    let (_tag, signer_info, _) = der_tlv(signer_infos_set).ok()?;
    if _tag != 0x30 {
        return None;
    }
    // version INTEGER, then sid IssuerAndSerialNumber SEQUENCE.
    let (vtag, _version, rest) = der_tlv(signer_info).ok()?;
    if vtag != 0x02 {
        return None;
    }
    let (stag, ias, _) = der_tlv(rest).ok()?;
    if stag != 0x30 {
        return None;
    }
    // issuer Name (full TLV), serialNumber INTEGER (full TLV).
    let issuer = der_full_tlv(ias).ok()?;
    let (_itag, _ivalue, after_issuer) = der_tlv(ias).ok()?;
    let serial = der_full_tlv(after_issuer).ok()?;
    Some((issuer, serial))
}

/// Find the certificate in `certificates_set` whose issuer Name and serial
/// number equal `issuer`/`serial`, returning its complete DER TLV.
///
/// `Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { ... }, ... }` and
/// `TBSCertificate ::= SEQUENCE { [0] version?, serialNumber INTEGER,
/// signature, issuer Name, ... }`.
///
/// # Errors
///
/// Returns an error if a certificate element is malformed DER.
fn certificate_matching<'a>(
    certificates_set: &'a [u8],
    issuer: &[u8],
    serial: &[u8],
) -> Result<Option<&'a [u8]>> {
    let mut cursor = certificates_set;
    while !cursor.is_empty() {
        let cert = der_full_tlv(cursor).context("certificate TLV")?;
        if cert_issuer_and_serial(cert).is_some_and(|(ci, cs)| ci == issuer && cs == serial) {
            return Ok(Some(cert));
        }
        let consumed = cert.len();
        cursor = &cursor[consumed..];
    }
    Ok(None)
}

/// Extract `(issuerName, serialNumber)` DER slices from a `Certificate`.
fn cert_issuer_and_serial(cert: &[u8]) -> Option<(&[u8], &[u8])> {
    let tbs_outer = der_expect_seq(cert).ok()?; // Certificate value
    let tbs = der_expect_seq(tbs_outer).ok()?; // TBSCertificate value
    // Optional [0] EXPLICIT version, then serialNumber INTEGER.
    let (tag, _v, rest) = der_tlv(tbs).ok()?;
    let (serial, after_serial) = if tag == 0xA0 {
        let (stag, _sv, after) = der_tlv(rest).ok()?;
        if stag != 0x02 {
            return None;
        }
        (der_full_tlv(rest).ok()?, after)
    } else if tag == 0x02 {
        (der_full_tlv(tbs).ok()?, rest)
    } else {
        return None;
    };
    // signature AlgorithmIdentifier SEQUENCE, then issuer Name SEQUENCE.
    let (_sigtag, _sig, after_sig) = der_tlv(after_serial).ok()?;
    let issuer = der_full_tlv(after_sig).ok()?;
    Some((issuer, serial))
}

/// Split a DER TLV at `data`, returning `(tag, value, remaining)`.
fn der_tlv(data: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    if data.len() < 2 {
        bail!("truncated DER element");
    }
    let tag = data[0];
    let (len, header_len) = der_len(&data[1..])?;
    let start = 1 + header_len;
    let end = start
        .checked_add(len)
        .filter(|&e| e <= data.len())
        .ok_or_else(|| anyhow::anyhow!("DER length {len} exceeds buffer"))?;
    Ok((tag, &data[start..end], &data[end..]))
}

/// Like [`der_tlv`] but returns the *complete* leading TLV (tag + length +
/// value) of the first element in `data`.
fn der_full_tlv(data: &[u8]) -> Result<&[u8]> {
    let total = der_element_len(data)?;
    Ok(&data[..total])
}

/// Return the total byte length of the leading DER element in `data`.
fn der_element_len(data: &[u8]) -> Result<usize> {
    if data.len() < 2 {
        bail!("truncated DER element");
    }
    let (len, header_len) = der_len(&data[1..])?;
    Ok(1 + header_len + len)
}

/// Expect a DER SEQUENCE (`0x30`) at `data` and return its value bytes.
fn der_expect_seq(data: &[u8]) -> Result<&[u8]> {
    let (tag, value, _) = der_tlv(data)?;
    if tag != 0x30 {
        bail!("expected DER SEQUENCE, found tag {tag:#x}");
    }
    Ok(value)
}

/// Take the first DER element from `data`, returning `(element, remaining)`.
fn der_take(data: &[u8]) -> Result<(&[u8], &[u8])> {
    let total = der_element_len(data)?;
    Ok((&data[..total], &data[total..]))
}

/// Decode a DER length field, returning `(length, header_byte_count)`.
fn der_len(data: &[u8]) -> Result<(usize, usize)> {
    let first = *data
        .first()
        .ok_or_else(|| anyhow::anyhow!("missing DER length"))?;
    if first < 0x80 {
        return Ok((first as usize, 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 || data.len() < 1 + n {
        bail!("unsupported DER length encoding");
    }
    let mut len = 0usize;
    for &byte in &data[1..1 + n] {
        len = (len << 8) | byte as usize;
    }
    Ok((len, 1 + n))
}

/// Return the lowercase hex SHA-256 of `bytes`.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Read the SBAT component/generation table from a UKI's `.sbat` PE section.
///
/// Reads the section from the PE section table and parses the CSV: each
/// non-empty, non-comment line is `component,generation`
/// (extra columns describing the upstream are ignored). Returns an empty
/// vector when the binary carries no `.sbat` section.
///
/// # Errors
///
/// Returns an error if the PE section table is malformed, the section is not
/// valid UTF-8, or a generation field is not a non-negative integer.
fn extract_sbat_entries(uki: &Path) -> Result<Vec<SbatEntry>> {
    let pe = fs::read(uki).with_context(|| format!("reading UKI {}", uki.display()))?;
    let Some(raw) = pe_section(&pe, ".sbat")? else {
        return Ok(Vec::new());
    };
    let text = std::str::from_utf8(raw).context("decoding .sbat section as UTF-8")?;
    parse_sbat_csv(text)
}

/// Parse the CSV body of a `.sbat` section into [`SbatEntry`] records.
///
/// # Errors
///
/// Returns an error if a data line's generation column is not a
/// non-negative integer.
fn parse_sbat_csv(text: &str) -> Result<Vec<SbatEntry>> {
    let mut entries = Vec::new();
    for line in text.lines() {
        let line = line.trim_end_matches('\0').trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split(',');
        let Some(component) = fields.next() else {
            continue;
        };
        let component = component.trim();
        // The first CSV row is the SBAT format header (`sbat,1,SBAT...`);
        // it is itself a versioned component and is recorded like any other.
        let Some(generation) = fields.next() else {
            continue;
        };
        let generation: u32 = generation.trim().parse().with_context(|| {
            format!("parsing SBAT generation for component '{component}' from '{line}'")
        })?;
        entries.push(SbatEntry {
            component: component.to_string(),
            generation,
        });
    }
    Ok(entries)
}

/// Returns a named PE section's exact on-disk bytes.
///
/// PE section names are fixed-width eight-byte fields. UKI section names fit
/// directly in that field, so string-table indirection is deliberately not
/// accepted. Empty sections are treated as absent.
///
/// # Errors
///
/// Returns an error if the PE/COFF headers, section table, or selected raw-data
/// range is malformed, or if the image contains duplicate selected sections.
pub(crate) fn pe_section<'a>(pe: &'a [u8], section: &str) -> Result<Option<&'a [u8]>> {
    if section.is_empty() || section.len() > 8 || !section.is_ascii() {
        bail!("PE section name must contain one to eight ASCII bytes");
    }
    let read_u16 = |off: usize| -> Option<u16> {
        pe.get(off..off + 2)
            .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
    };
    let read_u32 = |off: usize| -> Option<u32> {
        pe.get(off..off + 4)
            .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    };

    if read_u16(0) != Some(0x5a4d) {
        bail!("not a PE image (missing MZ signature)");
    }
    let pe_off = read_u32(0x3c).context("reading e_lfanew")? as usize;
    if read_u32(pe_off) != Some(0x0000_4550) {
        bail!("missing PE signature");
    }
    let coff_off = pe_off
        .checked_add(4)
        .context("PE header offset overflowed")?;
    let section_count = read_u16(coff_off + 2).context("reading PE section count")? as usize;
    let optional_size = read_u16(coff_off + 16).context("reading optional-header size")? as usize;
    let section_table = coff_off
        .checked_add(20)
        .and_then(|offset| offset.checked_add(optional_size))
        .context("PE section-table offset overflowed")?;
    let section_table_end = section_count
        .checked_mul(40)
        .and_then(|size| section_table.checked_add(size))
        .context("PE section-table size overflowed")?;
    if section_table_end > pe.len() {
        bail!("PE section table extends past end of image");
    }

    let mut matched = false;
    let mut selected = None;
    for index in 0..section_count {
        let header = section_table + index * 40;
        let raw_name = &pe[header..header + 8];
        let name_len = raw_name.iter().position(|byte| *byte == 0).unwrap_or(8);
        if &raw_name[..name_len] != section.as_bytes() {
            continue;
        }
        if matched {
            bail!("PE image contains duplicate {section} sections");
        }
        matched = true;
        let virtual_size =
            read_u32(header + 8).context("reading PE section virtual size")? as usize;
        let raw_size = read_u32(header + 16).context("reading PE section size")? as usize;
        let raw_offset = read_u32(header + 20).context("reading PE section offset")? as usize;
        // systemd-stub measures only bytes materialized in the PE file. Its
        // loader and ukify both define that range as the smaller of the
        // section's virtual and raw sizes.
        let section_size = virtual_size.min(raw_size);
        if section_size == 0 {
            continue;
        }
        let raw_end = raw_offset
            .checked_add(section_size)
            .context("PE section range overflowed")?;
        selected = Some(
            pe.get(raw_offset..raw_end)
                .with_context(|| format!("PE {section} section extends past end of image"))?,
        );
    }
    Ok(selected)
}

/// Copies a selected PE section to a temporary file for `systemd-measure`.
fn dump_pe_section(pe: &[u8], section: &str) -> Result<Option<tempfile::NamedTempFile>> {
    let Some(bytes) = pe_section(pe, section)? else {
        return Ok(None);
    };
    let mut tmp = tempfile::Builder::new()
        .prefix("aos-uki-section-")
        .tempfile()
        .with_context(|| format!("creating temp file for {section} dump"))?;
    tmp.as_file_mut()
        .write_all(bytes)
        .with_context(|| format!("writing temporary {section} section"))?;
    Ok(Some(tmp))
}

/// Predict the TPM PCR-11 contribution of a UKI via `systemd-measure`.
///
/// Runs `systemd-measure calculate` over the assembled UKI and returns the
/// predicted PCR-11 value as lowercase hex. Returns `Ok(None)` when
/// `systemd-measure` is not available, so a publish never fails merely
/// because the measurement tool is missing.
///
/// # What is measured
///
/// `systemd-measure` must be fed the UKI's individual PE *sections* — the
/// same inputs sd-stub hashes into PCR 11 — not the whole UKI as a kernel
/// image. This dumps each section sd-stub measures (`.linux`, `.osrel`,
/// `.cmdline`, `.initrd`, `.ucode`, `.splash`, `.dtb`, `.uname`, `.sbat`,
/// `.pcrpkey`), skipping any that are absent, and passes the present ones
/// to `systemd-measure calculate --bank=sha256`. The result is the PCR 11
/// value sd-stub + `systemd-pcrextend` reach for the measured sections, which
/// is also the value `ukify` signs into the `.pcrsig` policy — so a machine
/// that boots this UKI and seals against the signed policy is sealing
/// against this digest.
///
/// `systemd-measure calculate` emits one `11:sha256=` line per boot phase
/// (`enter-initrd` → `enter-initrd:leave-initrd:sysinit:ready`); this records
/// the **last** — the stable `ready` phase at which configuration activation takes
/// its generation quote. `aos-eval.service` is explicitly ordered after
/// `systemd-pcrphase.service`, and later operator-driven switches necessarily
/// run in this same phase.
/// TPM-sealed `/var` unlock remains valid because systemd consumes
/// the signed multi-phase `.pcrsig` policy at `enter-initrd`; it does not use
/// this catalog scalar as its unlock policy.
///
/// # Errors
///
/// Returns an error if the UKI section table is malformed, `systemd-measure`
/// exits non-zero, or its output cannot be parsed into a PCR-11 digest.
pub(crate) fn extract_expected_pcr11(uki: &Path) -> Result<Option<String>> {
    // Section name -> systemd-measure flag, in sd-stub measurement order.
    // (systemd-measure applies its own canonical order internally, so the
    // flag order here is not significant.)
    const SECTIONS: &[(&str, &str)] = &[
        (".linux", "--linux"),
        (".osrel", "--osrel"),
        (".cmdline", "--cmdline"),
        (".initrd", "--initrd"),
        (".ucode", "--ucode"),
        (".splash", "--splash"),
        (".dtb", "--dtb"),
        (".uname", "--uname"),
        (".sbat", "--sbat"),
        (".pcrpkey", "--pcrpkey"),
    ];

    let mut cmd = sb_tool_command("systemd-measure");
    cmd.arg("calculate").arg("--bank=sha256");
    // Hold the section temp files alive until systemd-measure has run.
    let mut held = Vec::new();
    let mut any = false;
    let pe = fs::read(uki).with_context(|| format!("reading UKI {}", uki.display()))?;
    for (section, flag) in SECTIONS {
        if let Some(tmp) = dump_pe_section(&pe, section)? {
            cmd.arg(format!("{flag}={}", tmp.path().display()));
            held.push(tmp);
            any = true;
        }
    }
    // No measurable sections (e.g. not actually a UKI) — nothing to record.
    if !any {
        return Ok(None);
    }

    let output = match cmd.output() {
        Ok(output) => output,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("running systemd-measure on {}", uki.display()));
        }
    };
    if !output.status.success() {
        bail!(
            "systemd-measure on {} failed: {}",
            uki.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_pcr11(&stdout))
}

/// Extract the PCR-11 digest from `systemd-measure calculate` output.
///
/// The tool prints lines such as `11:sha256=<hex>`; this returns the hex of
/// the last PCR-11/sha256 line (`ready`), or `None` when no line is present.
fn parse_pcr11(text: &str) -> Option<String> {
    let mut parsed = None;
    for line in text.lines() {
        let line = line.trim();
        // Accept `11:sha256=<hex>` and `11:<hex>` shapes.
        let Some(rest) = line.strip_prefix("11:") else {
            continue;
        };
        let value = rest.rsplit('=').next().unwrap_or(rest).trim();
        if !value.is_empty() && value.bytes().all(|b| b.is_ascii_hexdigit()) {
            parsed = Some(value.to_ascii_lowercase());
        }
    }
    parsed
}

/// Verify a UKI's embedded Authenticode signature against a db certificate.
///
/// Runs `sbverify --cert <db_cert_pem> <uki>`; the registry refuses to
/// catalog a component it cannot itself verify is signed by the declared
/// db cert (RFC-0006 phase 4).
///
/// # Errors
///
/// Returns an error if `sbverify` cannot be spawned or reports the
/// signature does not verify against `db_cert_pem`.
fn verify_uki_against_db_cert(uki: &Path, db_cert_pem: &Path) -> Result<()> {
    let output = sb_tool_command("sbverify")
        .arg("--cert")
        .arg(db_cert_pem)
        .arg(uki)
        .output()
        .with_context(|| format!("running sbverify --cert on {}", uki.display()))?;
    if !output.status.success() {
        bail!(
            "UKI {} does not verify against db cert {}: {}",
            uki.display(),
            db_cert_pem.display(),
            combine_output(
                &String::from_utf8_lossy(&output.stdout),
                &String::from_utf8_lossy(&output.stderr)
            )
        );
    }
    Ok(())
}

/// Join non-empty stdout/stderr fragments into one diagnostic string.
fn combine_output(stdout: &str, stderr: &str) -> String {
    match (stdout.trim().is_empty(), stderr.trim().is_empty()) {
        (true, true) => "(no output)".to_string(),
        (false, true) => stdout.trim().to_string(),
        (true, false) => stderr.trim().to_string(),
        (false, false) => format!("{}\n{}", stdout.trim(), stderr.trim()),
    }
}

/// Locate a db certificate PEM to verify published UKIs against, if one is
/// provisioned for `registry`.
///
/// Looks for `<registries-storage>/<registry>/sb-certs/db.pem` in the
/// authoring clone. Returns `None` when no db cert is provisioned, in which
/// case `apr publish` records SB facts without the publish-time signature
/// cross-check (the closure signature still covers the recorded facts).
fn sb_db_cert_path(config: &ApmConfig, registry: &str) -> Option<PathBuf> {
    let path = config
        .scope
        .registries_path()
        .join(registry)
        .join("sb-certs")
        .join("db.pem");
    path.exists().then_some(path)
}

/// Derives the independently measured identities of a deterministic A/B UKI pair.
fn derive_slot_uki_facts(
    image_store: &Path,
    db_cert: Option<&Path>,
) -> Result<Vec<SysrootUkiEntry>> {
    let slot_paths = [
        (UkiSlot::A, image_store.join("uki-a.efi")),
        (UkiSlot::B, image_store.join("uki-b.efi")),
    ];
    let present = slot_paths.iter().filter(|(_, path)| path.is_file()).count();
    if present == 0 {
        return Ok(Vec::new());
    }
    if present != slot_paths.len() {
        bail!(
            "A/B image output {} must carry both uki-a.efi and uki-b.efi",
            image_store.display()
        );
    }

    let verify_slot_cmdline = image_store.join("root.roothash").is_file();
    let mut entries = Vec::with_capacity(slot_paths.len());
    for (slot, path) in slot_paths {
        let facts = derive_sb_facts(&path, db_cert)
            .with_context(|| format!("deriving slot-specific facts for {}", path.display()))?;
        if verify_slot_cmdline {
            validate_uki_slot_cmdline(&path, slot)?;
        }
        entries.push(SysrootUkiEntry {
            slot,
            path: path
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .context("slot UKI filename is not UTF-8")?
                .to_string(),
            sb_signer_cert_sha256: facts.signer_cert_sha256,
            sbat: facts.sbat,
            expected_pcr11: facts.expected_pcr11,
        });
    }
    let signed = entries
        .iter()
        .filter(|entry| entry.sb_signer_cert_sha256.is_some())
        .count();
    if signed != 0 && signed != entries.len() {
        bail!("A/B image must not mix signed and unsigned UKIs");
    }
    Ok(entries)
}

fn derive_recovery_uki_facts(
    image_store: &Path,
    recovery: Option<&ProducerRecoveryInfo>,
    release: &str,
    db_cert: Option<&Path>,
) -> Result<Vec<RecoveryUkiEntry>> {
    let paths = [
        image_store.join("recovery-a.efi"),
        image_store.join("recovery-b.efi"),
        image_store.join("recovery-a.conf"),
        image_store.join("recovery-b.conf"),
    ];
    let present = paths.iter().filter(|path| path.is_file()).count();
    let Some(recovery) = recovery else {
        if present != 0 {
            bail!("recovery artifacts require recovery metadata in image-info.json");
        }
        return Ok(Vec::new());
    };
    if present != paths.len() {
        bail!("recovery image output must carry two UKIs and two loader entries");
    }
    if recovery.abi == 0 || recovery.release != release {
        bail!("recovery ABI or release identity disagrees with the image release");
    }
    aos_boot_identity::parse_recovery(&recovery.command_line)
        .context("recovery image-info command line is not canonical")?;

    let copies = [
        (
            UkiSlot::A,
            "A",
            "recovery-a.efi",
            "recovery-a.conf",
            "EFI/AOS/recovery-a.efi",
            "loader/entries/recovery-a.conf",
            &recovery.copies.a,
            recovery.entries.a.as_str(),
        ),
        (
            UkiSlot::B,
            "B",
            "recovery-b.efi",
            "recovery-b.conf",
            "EFI/AOS/recovery-b.efi",
            "loader/entries/recovery-b.conf",
            &recovery.copies.b,
            recovery.entries.b.as_str(),
        ),
    ];
    let mut entries = Vec::with_capacity(copies.len());
    for (copy, copy_name, uki_name, entry_name, esp_path, entry_path, metadata, recorded_entry) in
        copies
    {
        if metadata.esp_path != esp_path || recorded_entry != entry_path {
            bail!("recovery copy {copy_name} uses a noncanonical ESP path");
        }
        let uki = image_store.join(uki_name);
        let uki_metadata = fs::symlink_metadata(&uki)?;
        if !uki_metadata.file_type().is_file() || uki_metadata.len() == 0 {
            bail!(
                "recovery UKI {} is not a nonempty regular file",
                uki.display()
            );
        }
        let mut uki_file = fs::File::open(&uki)?;
        let digest = sha256_open_file(&mut uki_file, &uki)?;
        if metadata.byte_size != uki_metadata.len() || metadata.sha256 != digest {
            bail!("recovery copy {copy_name} size or digest disagrees with image-info.json");
        }

        let facts = derive_sb_facts(&uki, db_cert)?;
        let signer = facts
            .signer_cert_sha256
            .context("recovery UKIs must carry a db-verifiable Authenticode signature")?;
        let cmdline = read_bounded_pe_text(&uki, ".cmdline", 64 * 1024)?;
        if cmdline != recovery.command_line {
            bail!("recovery copy {copy_name} command line disagrees with image-info.json");
        }
        aos_boot_identity::parse_recovery(&cmdline)
            .with_context(|| format!("recovery copy {copy_name} command line is not canonical"))?;
        let uki_bytes = fs::read(&uki)?;
        if dump_pe_section(&uki_bytes, ".pcrsig")?.is_some_and(|file| {
            file.as_file()
                .metadata()
                .is_ok_and(|metadata| metadata.len() != 0)
        }) {
            bail!("recovery copy {copy_name} carries forbidden normal PCR authorization");
        }
        let os_release = read_bounded_pe_text(&uki, ".osrel", 64 * 1024)?;
        validate_recovery_os_release(&os_release, copy_name, &recovery.release, recovery.abi)?;

        let entry = image_store.join(entry_name);
        let entry_metadata = fs::symlink_metadata(&entry)?;
        if !entry_metadata.file_type().is_file() || entry_metadata.len() > 4096 {
            bail!("recovery loader entry {entry_name} is not a bounded regular file");
        }
        let expected_entry = format!(
            "title AOS Recovery {copy_name} ({})\nefi /{esp_path}\n",
            recovery.release
        );
        if fs::read_to_string(&entry)? != expected_entry {
            bail!("recovery loader entry {entry_name} is not canonical");
        }

        entries.push(RecoveryUkiEntry {
            copy,
            path: uki_name.to_string(),
            entry_path: entry_name.to_string(),
            byte_size: metadata.byte_size,
            sha256: digest,
            release: recovery.release.clone(),
            recovery_abi: recovery.abi,
            sb_signer_cert_sha256: signer,
            sbat: facts.sbat,
        });
    }
    Ok(entries)
}

fn read_bounded_pe_text(uki: &Path, section: &str, maximum: u64) -> Result<String> {
    let bytes = fs::read(uki).with_context(|| format!("reading UKI {}", uki.display()))?;
    let extracted = dump_pe_section(&bytes, section)?
        .with_context(|| format!("recovery UKI {} has no {section} section", uki.display()))?;
    let metadata = extracted.as_file().metadata()?;
    if metadata.len() == 0 || metadata.len() > maximum {
        bail!("recovery UKI {section} section is outside its size bound");
    }
    let bytes = fs::read(extracted.path())?;
    let text = String::from_utf8(bytes)
        .with_context(|| format!("recovery UKI {section} section is not UTF-8"))?;
    Ok(text.trim_end_matches('\0').to_string())
}

fn validate_recovery_os_release(
    os_release: &str,
    copy: &str,
    release: &str,
    recovery_abi: u32,
) -> Result<()> {
    let expected = [
        ("AOS_RELEASE_ID", release.to_string()),
        ("AOS_RECOVERY_ABI", recovery_abi.to_string()),
        ("AOS_RECOVERY_COPY", copy.to_string()),
    ];
    for (key, expected_value) in expected {
        let values = os_release
            .lines()
            .filter_map(|line| line.split_once('='))
            .filter_map(|(found, value)| (found == key).then_some(value.trim_matches('"')))
            .collect::<Vec<_>>();
        if values.as_slice() != [expected_value.as_str()] {
            bail!("recovery signed os-release has invalid {key}");
        }
    }
    Ok(())
}

fn derive_recovery_bundle_manifest(
    image_store: &Path,
    recovery: Option<&ProducerRecoveryInfo>,
    module_abi: Option<u32>,
    release: &str,
    architecture: &str,
    platform: &str,
) -> Result<Option<RecoveryBundleManifest>> {
    let Some(recovery) = recovery else {
        return Ok(None);
    };
    let module_abi = module_abi
        .filter(|abi| *abi != 0)
        .context("recovery image-info.json must carry a positive moduleAbi")?;
    let specifications = [
        (RecoveryBundleComponentId::RootImage, "root.img"),
        (RecoveryBundleComponentId::RootVerity, "root.verity"),
        (RecoveryBundleComponentId::RootHash, "root.roothash"),
        (RecoveryBundleComponentId::NormalUkiA, "uki-a.efi"),
        (RecoveryBundleComponentId::NormalUkiB, "uki-b.efi"),
        (RecoveryBundleComponentId::RecoveryUkiA, "recovery-a.efi"),
        (RecoveryBundleComponentId::RecoveryUkiB, "recovery-b.efi"),
        (RecoveryBundleComponentId::RecoveryEntryA, "recovery-a.conf"),
        (RecoveryBundleComponentId::RecoveryEntryB, "recovery-b.conf"),
        (RecoveryBundleComponentId::ImageMetadata, "image-info.json"),
    ];
    let mut components = Vec::with_capacity(specifications.len());
    for (id, path) in specifications {
        let artifact = image_store.join(path);
        let metadata = fs::symlink_metadata(&artifact)
            .with_context(|| format!("reading recovery bundle component {path}"))?;
        if !metadata.file_type().is_file() || metadata.len() == 0 {
            bail!("recovery bundle component {path} is not a nonempty regular file");
        }
        let mut file = fs::File::open(&artifact)?;
        let digest = sha256_open_file(&mut file, &artifact)?;
        components.push(RecoveryBundleComponent {
            id,
            path: path.to_string(),
            byte_size: metadata.len(),
            sha256: digest,
        });
    }
    Ok(Some(RecoveryBundleManifest {
        schema: "aos.recovery-bundle/v1".to_string(),
        release: release.to_string(),
        architecture: architecture.to_string(),
        platform: platform.to_string(),
        module_abi,
        recovery_abi: recovery.abi,
        components,
    }))
}

pub(crate) fn verify_detached_db_signature(
    manifest: &Path,
    signature: &Path,
    db_cert: &Path,
) -> Result<()> {
    let public_key =
        tempfile::NamedTempFile::new().context("creating temporary recovery bundle public key")?;
    let output = Command::new("openssl")
        .args(["x509", "-pubkey", "-noout", "-in"])
        .arg(db_cert)
        .output()
        .context("extracting the recovery bundle verification key")?;
    if !output.status.success() {
        bail!(
            "extracting recovery bundle verification key failed: {}",
            combine_output(
                &String::from_utf8_lossy(&output.stdout),
                &String::from_utf8_lossy(&output.stderr)
            )
        );
    }
    fs::write(public_key.path(), output.stdout)?;
    let output = Command::new("openssl")
        .args(["dgst", "-sha256", "-verify"])
        .arg(public_key.path())
        .arg("-signature")
        .arg(signature)
        .arg(manifest)
        .output()
        .context("verifying the recovery bundle manifest signature")?;
    if !output.status.success() {
        bail!(
            "recovery bundle manifest signature rejected: {}",
            combine_output(
                &String::from_utf8_lossy(&output.stdout),
                &String::from_utf8_lossy(&output.stderr)
            )
        );
    }
    Ok(())
}

#[cfg(test)]
fn find_ukis_in_store_path(store_path: &str) -> Result<Vec<(Option<UkiSlot>, PathBuf)>> {
    let root = Path::new(store_path);
    let a = root.join("uki-a.efi");
    let b = root.join("uki-b.efi");
    if a.is_file() || b.is_file() {
        if !(a.is_file() && b.is_file()) {
            bail!("A/B image artifact {store_path} must carry both uki-a.efi and uki-b.efi");
        }
        return Ok(vec![(Some(UkiSlot::A), a), (Some(UkiSlot::B), b)]);
    }
    let mut found = fs::read_dir(root)
        .with_context(|| format!("reading image artifact {}", root.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.is_file()
                && path
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("efi"))
        })
        .collect::<Vec<_>>();
    found.sort();
    match found.len() {
        0 => Ok(Vec::new()),
        1 => Ok(vec![(None, found.remove(0))]),
        count => bail!(
            "image artifact {store_path} carries {count} UKIs but no deterministic uki-a.efi/uki-b.efi pair"
        ),
    }
}

fn validate_uki_slot_cmdline(uki: &Path, slot: UkiSlot) -> Result<()> {
    let pe = fs::read(uki).with_context(|| format!("reading UKI {}", uki.display()))?;
    let section = pe_section(&pe, ".cmdline")?
        .with_context(|| format!("A/B UKI {} has no measured .cmdline section", uki.display()))?;
    let cmdline = std::str::from_utf8(section)
        .with_context(|| format!("UKI {} .cmdline is not UTF-8", uki.display()))?;
    let cmdline = cmdline.trim_end_matches('\0');
    let suffix = match slot {
        UkiSlot::A => "a",
        UkiSlot::B => "b",
    };
    let data = format!("systemd.verity_root_data=/dev/disk/by-partlabel/root-{suffix}");
    let hash = format!("systemd.verity_root_hash=/dev/disk/by-partlabel/root-{suffix}-hash");
    if !cmdline.split_ascii_whitespace().any(|word| word == data)
        || !cmdline.split_ascii_whitespace().any(|word| word == hash)
    {
        bail!(
            "A/B UKI {} slot {:?} does not select its matching root and verity partitions",
            uki.display(),
            slot
        );
    }
    Ok(())
}

/// Derives Secure Boot facts from the exact UKI named by `image-info.json`.
///
/// Extracts the signer cert digest and SBAT table without searching an
/// artifact tree. A predicted PCR-11 value is included only when the UKI
/// carries a signed `.pcrsig` policy; Secure Boot signing alone does not make
/// an image a measured-boot image. Optionally enforces the publish-time
/// rule that an image's embedded signature must verify against `db_cert`
/// before it can be cataloged.
///
/// Returns an empty [`SbFacts`] for an explicitly associated unsigned UKI,
/// preserving unsigned development images without losing byte identity.
///
/// # Errors
///
/// Returns an error when a signed UKI fact cannot be derived, or when
/// `db_cert` is given and the signature does not verify against it.
fn derive_sb_facts(uki: &Path, db_cert: Option<&Path>) -> Result<SbFacts> {
    let signer = extract_sb_signer_cert_sha256(uki)?;
    // An image with no embedded signature carries no SB facts to catalog.
    if signer.is_none() {
        return Ok(SbFacts::default());
    }

    if let Some(db_cert) = db_cert {
        verify_uki_against_db_cert(uki, db_cert).with_context(|| {
            "refusing to catalog a component whose signature does not verify \
             against the declared db cert"
                .to_string()
        })?;
    }

    let pe = fs::read(uki).with_context(|| format!("reading UKI {}", uki.display()))?;
    let expected_pcr11 = if pe_section(&pe, ".pcrsig")?.is_some() {
        extract_expected_pcr11(uki)?
    } else {
        None
    };

    Ok(SbFacts {
        signer_cert_sha256: signer,
        sbat: extract_sbat_entries(uki)?,
        expected_pcr11,
        ukis: Vec::new(),
        recovery_ukis: Vec::new(),
        recovery_bundle: None,
    })
}

fn publish_attestation_meta(
    name: &str,
    version: &str,
    platform: &str,
    info: &StorePathInfo,
    manifest: &PublishExposeManifest,
    expose_manifest_digest: Option<&str>,
) -> Result<Option<AttestationMeta>> {
    let image = manifest
        .expose
        .images
        .iter()
        .find(|image| image.root_hash.is_some() || image.root_hash_sig.is_some());
    let manifest_digest = expose_manifest_digest
        .context("package root attestation requires an expose manifest digest")?;
    let root_hash = image
        .map(|image| {
            image
                .root_hash
                .clone()
                .context("verity package root image is missing root_hash")
        })
        .transpose()?;
    let root_hash_sig = image
        .map(|image| {
            image
                .root_hash_sig
                .clone()
                .context("verity package root image is missing root_hash_sig")
        })
        .transpose()?;
    let root_digest = root_hash
        .clone()
        .unwrap_or_else(|| package_nar_root_digest(&info.nar_hash));
    let measurement = crate::package_attestation::package_measurement_digest(
        name,
        version,
        &root_digest,
        manifest_digest,
    );
    let provenance = Some(publish_provenance_ref(name, platform, &measurement)?);
    let meta = AttestationMeta {
        root_digest: Some(root_digest),
        root_hash,
        root_hash_sig,
        provenance,
        measurement: Some(measurement),
    };
    validate_attestation_meta(&meta)?;
    Ok(Some(meta))
}

fn publish_config_attestation_meta(
    name: &str,
    version: &str,
    platform: &str,
    info: &StorePathInfo,
    module: &ConfigModuleMeta,
    expose_manifest_digest: Option<&str>,
) -> Result<AttestationMeta> {
    let root_digest = package_nar_root_digest(&info.nar_hash);
    let binding_digest = config_publish_binding_digest(module, expose_manifest_digest)?;
    let measurement = crate::package_attestation::package_measurement_digest(
        name,
        version,
        &root_digest,
        &binding_digest,
    );
    let meta = AttestationMeta {
        root_digest: Some(root_digest),
        root_hash: None,
        root_hash_sig: None,
        provenance: Some(publish_provenance_ref(name, platform, &measurement)?),
        measurement: Some(measurement),
    };
    validate_attestation_meta(&meta)?;
    Ok(meta)
}

fn publish_documentation_attestation_meta(
    name: &str,
    version: &str,
    platform: &str,
    info: &StorePathInfo,
) -> Result<AttestationMeta> {
    let root_digest = package_nar_root_digest(&info.nar_hash);
    let binding_digest = format!("sha256:{}", sha256_hex(b"aos.package-runtime-binding/v1"));
    let measurement = crate::package_attestation::package_measurement_digest(
        name,
        version,
        &root_digest,
        &binding_digest,
    );
    let meta = AttestationMeta {
        root_digest: Some(root_digest),
        root_hash: None,
        root_hash_sig: None,
        provenance: Some(publish_provenance_ref(name, platform, &measurement)?),
        measurement: Some(measurement),
    };
    validate_attestation_meta(&meta)?;
    Ok(meta)
}

fn config_publish_binding_digest(
    module: &ConfigModuleMeta,
    expose_manifest_digest: Option<&str>,
) -> Result<String> {
    crate::package_attestation::config_module_binding_digest(module, expose_manifest_digest)
}

fn package_nar_root_digest(nar_hash: &str) -> String {
    if let Some(hex) = sha256_hex_payload(nar_hash) {
        format!("sha256:{hex}")
    } else {
        format!("sha256:{}", sha256_hex(nar_hash.as_bytes()))
    }
}

/// Returns the canonical hexadecimal identity of the NAR bytes themselves.
fn documentation_nar_identity(nar_hash: &str) -> Result<String> {
    Ok(format!(
        "sha256:{}",
        aos_registry_surface::store::canonical_digest_hex(nar_hash)?
    ))
}

const PACKAGE_PROVENANCE_TRANSPARENCY_LOG: &str = "transparency/package-provenance.jsonl";
const PACKAGE_PROVENANCE_TRANSPARENCY_SCHEMA: &str =
    "https://andyl.com/aos/transparency/package-provenance/v1";
const PACKAGE_PROVENANCE_STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
const PACKAGE_PROVENANCE_PREDICATE_TYPE: &str = "https://slsa.dev/provenance/v1";
const PACKAGE_PROVENANCE_BUILD_TYPE: &str = "https://andyl.com/aos/apr-publish/v1";

/// Exclusive on-disk lock (`.git/apr-publish.lock`) serializing publication
/// critical sections that update append-only registry state.
struct RegistryPublishLock {
    path: PathBuf,
    owned: bool,
}

impl RegistryPublishLock {
    fn acquire(dir: &Path) -> Result<Self> {
        Self::acquire_inner(dir, false)
    }

    fn acquire_or_join_current_process(dir: &Path) -> Result<Self> {
        Self::acquire_inner(dir, true)
    }

    fn acquire_inner(dir: &Path, join_current_process: bool) -> Result<Self> {
        let git_dir = objectstore::repo_git_dir(dir)?;
        let path = git_dir.join("apr-publish.lock");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .or_else(|err| {
                if join_current_process && err.kind() == std::io::ErrorKind::AlreadyExists {
                    let content = fs::read_to_string(&path)?;
                    if content
                        .lines()
                        .any(|line| line.trim() == format!("pid={}", std::process::id()))
                    {
                        return Ok(OpenOptions::new().read(true).open(&path)?);
                    }
                }
                Err(err)
            })
            .with_context(|| {
                format!(
                    "acquiring publish lock {}; another publisher may be running",
                    path.display()
                )
            })?;
        let owned = file
            .metadata()
            .map(|metadata| metadata.len() == 0)
            .unwrap_or(false);
        if !owned {
            return Ok(Self { path, owned });
        }
        writeln!(file, "pid={}", std::process::id())
            .with_context(|| format!("writing {}", path.display()))?;
        Ok(Self { path, owned })
    }
}

impl Drop for RegistryPublishLock {
    fn drop(&mut self) {
        if self.owned {
            let _ = fs::remove_file(&self.path);
        }
    }
}

struct PublishProvenanceArtifact {
    path: String,
    jsonl: String,
    attestation: AttestationMeta,
}

struct PackageProvenanceSigner {
    key_id: String,
    key_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageProvenanceTransparencyLogEntry {
    body: PackageProvenanceTransparencyLogBody,
    entry_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageProvenanceTransparencyLogBody {
    schema: String,
    sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_entry_hash: Option<String>,
    package: String,
    version: String,
    platform: String,
    store_path: String,
    nar_hash: String,
    nar_size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    root_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    root_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    root_hash_sig: Option<String>,
    provenance: String,
    measurement: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<PackageProvenanceTransparencySource>,
    statement: PackageProvenanceTransparencyStatement,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageProvenanceTransparencySource {
    store_path: String,
    nar_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageProvenanceTransparencyStatement {
    path: String,
    jsonl_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StagedPackageProvenanceMeta {
    path: String,
    package: String,
    version: String,
    platform: String,
    store_path: String,
    source_drv: String,
    source_nar_hash: String,
    root_digest: String,
    root_hash: Option<String>,
    root_hash_sig: Option<String>,
    provenance: String,
    measurement: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct PackageTomlPlatformKey {
    package: String,
    version: String,
    platform: String,
}

#[derive(Debug, Deserialize)]
struct StagedPackageRfc0001Meta {
    #[serde(default)]
    expose: Option<ExposeMeta>,
    #[serde(default)]
    expose_artifact: Option<ExposeArtifactMeta>,
    #[serde(default)]
    permissions: PermissionsMeta,
    #[serde(default, rename = "bpf_lsm")]
    bpf_lsm: Option<BpfLsmPolicyMeta>,
}

fn publish_provenance_artifact_inner(
    registry_name: &str,
    name: &str,
    version: &str,
    platform: &str,
    info: &StorePathInfo,
    source_info: Option<&StorePathInfo>,
    manifest: &PublishExposeManifest,
    manifest_digest: &str,
    documentation: Option<&DocumentationArtifactMeta>,
    signer: &PackageProvenanceSigner,
) -> Result<Option<PublishProvenanceArtifact>> {
    let Some(attestation) = publish_attestation_meta(
        name,
        version,
        platform,
        info,
        manifest,
        Some(manifest_digest),
    )?
    else {
        return Ok(None);
    };
    let provenance = attestation.provenance.as_deref().map(str::to_string);
    let Some(provenance) = provenance else {
        return Ok(None);
    };
    let mut statement = publish_provenance_statement(
        registry_name,
        name,
        version,
        platform,
        info,
        source_info,
        manifest_digest,
        &attestation,
        &signer.key_id,
    )?;
    if let Some(documentation) = documentation {
        append_documentation_provenance_subject(
            &mut statement,
            name,
            version,
            platform,
            documentation,
        )?;
    }
    let jsonl = sign_statement_dsse_jsonl(&statement, &signer.key_id, &signer.key_path)?;
    Ok(Some(PublishProvenanceArtifact {
        path: provenance,
        jsonl,
        attestation,
    }))
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn publish_provenance_artifact(
    registry_name: &str,
    name: &str,
    version: &str,
    platform: &str,
    info: &StorePathInfo,
    source_info: Option<&StorePathInfo>,
    manifest: &PublishExposeManifest,
    manifest_digest: &str,
    signer: &PackageProvenanceSigner,
) -> Result<Option<PublishProvenanceArtifact>> {
    publish_provenance_artifact_inner(
        registry_name,
        name,
        version,
        platform,
        info,
        source_info,
        manifest,
        manifest_digest,
        None,
        signer,
    )
}

#[allow(clippy::too_many_arguments)]
fn publish_provenance_artifact_with_documentation(
    registry_name: &str,
    name: &str,
    version: &str,
    platform: &str,
    info: &StorePathInfo,
    source_info: Option<&StorePathInfo>,
    manifest: &PublishExposeManifest,
    manifest_digest: &str,
    documentation: &DocumentationArtifactMeta,
    signer: &PackageProvenanceSigner,
) -> Result<Option<PublishProvenanceArtifact>> {
    publish_provenance_artifact_inner(
        registry_name,
        name,
        version,
        platform,
        info,
        source_info,
        manifest,
        manifest_digest,
        Some(documentation),
        signer,
    )
}

#[allow(clippy::too_many_arguments)]
fn publish_config_provenance_artifact_inner(
    registry_name: &str,
    name: &str,
    version: &str,
    platform: &str,
    info: &StorePathInfo,
    source_info: Option<&StorePathInfo>,
    module: &ConfigModuleMeta,
    expose_manifest_digest: Option<&str>,
    attestation: &AttestationMeta,
    documentation: Option<&DocumentationArtifactMeta>,
    signer: &PackageProvenanceSigner,
) -> Result<PublishProvenanceArtifact> {
    let provenance = attestation
        .provenance
        .clone()
        .context("config-module attestation is missing its provenance reference")?;
    let base_lib = module
        .evaluation_base_lib
        .as_ref()
        .context("published config module is missing its evaluation base-lib binding")?;
    let mut statement = publish_provenance_statement(
        registry_name,
        name,
        version,
        platform,
        info,
        source_info,
        &config_publish_binding_digest(module, expose_manifest_digest)?,
        attestation,
        &signer.key_id,
    )?;
    let subjects = statement
        .get_mut("subject")
        .and_then(Value::as_array_mut)
        .context("generated provenance statement has no subject array")?;
    if let Some(expose_digest) = expose_manifest_digest {
        subjects.push(serde_json::json!({
            "name": format!("aos:expose-manifest:{name}:{version}:{platform}"),
            "digest": provenance_digest_map(expose_digest),
        }));
    }
    subjects.push(serde_json::json!({
        "name": format!("aos:config-module:{name}:{version}:{platform}"),
        "digest": provenance_digest_map(&module.config_output.nar_hash),
    }));
    subjects.push(serde_json::json!({
        "name": format!("aos:config-base-lib:{name}:{version}:{platform}"),
        "digest": provenance_digest_map(&base_lib.nar_hash),
    }));
    let dependencies = statement
        .pointer_mut("/predicate/buildDefinition/resolvedDependencies")
        .and_then(Value::as_array_mut)
        .context("generated provenance statement has no resolvedDependencies array")?;
    dependencies.push(serde_json::json!({
        "uri": module.config_output.store_path,
        "digest": provenance_digest_map(&module.config_output.nar_hash),
    }));
    dependencies.push(serde_json::json!({
        "uri": base_lib.store_path,
        "digest": provenance_digest_map(&base_lib.nar_hash),
    }));
    if let Some(documentation) = documentation {
        append_documentation_provenance_subject(
            &mut statement,
            name,
            version,
            platform,
            documentation,
        )?;
    }
    let jsonl = sign_statement_dsse_jsonl(&statement, &signer.key_id, &signer.key_path)?;
    Ok(PublishProvenanceArtifact {
        path: provenance,
        jsonl,
        attestation: attestation.clone(),
    })
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn publish_config_provenance_artifact(
    registry_name: &str,
    name: &str,
    version: &str,
    platform: &str,
    info: &StorePathInfo,
    source_info: Option<&StorePathInfo>,
    module: &ConfigModuleMeta,
    expose_manifest_digest: Option<&str>,
    attestation: &AttestationMeta,
    signer: &PackageProvenanceSigner,
) -> Result<PublishProvenanceArtifact> {
    publish_config_provenance_artifact_inner(
        registry_name,
        name,
        version,
        platform,
        info,
        source_info,
        module,
        expose_manifest_digest,
        attestation,
        None,
        signer,
    )
}

#[allow(clippy::too_many_arguments)]
fn publish_config_provenance_artifact_with_documentation(
    registry_name: &str,
    name: &str,
    version: &str,
    platform: &str,
    info: &StorePathInfo,
    source_info: Option<&StorePathInfo>,
    module: &ConfigModuleMeta,
    expose_manifest_digest: Option<&str>,
    attestation: &AttestationMeta,
    documentation: &DocumentationArtifactMeta,
    signer: &PackageProvenanceSigner,
) -> Result<PublishProvenanceArtifact> {
    publish_config_provenance_artifact_inner(
        registry_name,
        name,
        version,
        platform,
        info,
        source_info,
        module,
        expose_manifest_digest,
        attestation,
        Some(documentation),
        signer,
    )
}

#[allow(clippy::too_many_arguments)]
fn publish_documentation_provenance_artifact(
    registry_name: &str,
    name: &str,
    version: &str,
    platform: &str,
    info: &StorePathInfo,
    source_info: Option<&StorePathInfo>,
    documentation: &DocumentationArtifactMeta,
    attestation: &AttestationMeta,
    signer: &PackageProvenanceSigner,
) -> Result<PublishProvenanceArtifact> {
    let provenance = attestation
        .provenance
        .clone()
        .context("documentation attestation is missing its provenance reference")?;
    let binding_digest = format!("sha256:{}", sha256_hex(b"aos.package-runtime-binding/v1"));
    let mut statement = publish_provenance_statement(
        registry_name,
        name,
        version,
        platform,
        info,
        source_info,
        &binding_digest,
        attestation,
        &signer.key_id,
    )?;
    append_documentation_provenance_subject(
        &mut statement,
        name,
        version,
        platform,
        documentation,
    )?;
    let jsonl = sign_statement_dsse_jsonl(&statement, &signer.key_id, &signer.key_path)?;
    Ok(PublishProvenanceArtifact {
        path: provenance,
        jsonl,
        attestation: attestation.clone(),
    })
}

fn append_documentation_provenance_subject(
    statement: &mut Value,
    name: &str,
    version: &str,
    platform: &str,
    documentation: &DocumentationArtifactMeta,
) -> Result<()> {
    let subjects = statement
        .get_mut("subject")
        .and_then(Value::as_array_mut)
        .context("generated provenance statement has no subject array")?;
    subjects.push(serde_json::json!({
        "name": format!("aos:package-documentation:{name}:{version}:{platform}"),
        "digest": provenance_digest_map(&documentation.nar_hash),
    }));
    subjects.push(serde_json::json!({
        "name": format!("aos:package-document:{name}:{version}:{platform}"),
        "digest": provenance_digest_map(&documentation.document_sha256),
    }));
    subjects.push(serde_json::json!({
        "name": format!("aos:package-schema:{name}:{version}:{platform}"),
        "digest": provenance_digest_map(&documentation.semantic_schema_sha256),
    }));
    let dependencies = statement
        .pointer_mut("/predicate/buildDefinition/resolvedDependencies")
        .and_then(Value::as_array_mut)
        .context("generated provenance statement has no resolvedDependencies array")?;
    dependencies.push(serde_json::json!({
        "uri": documentation.store_path,
        "digest": provenance_digest_map(&documentation.nar_hash),
    }));
    Ok(())
}

fn resolve_package_provenance_signer(
    dir: &Path,
    registry_name: &str,
    signing_key: Option<&ResolvedSigningKey>,
    key_id: Option<&str>,
) -> Result<PackageProvenanceSigner> {
    let key_id = key_id.context(
        "publishing privileged package provenance requires --key-id so the DSSE builder \
         identity is tied to keys.toml",
    )?;
    validate_roster_key_id(key_id)?;
    let signing_key = signing_key
        .context("publishing privileged package provenance requires a resolved signing key")?;
    let roster = load_committed_roster(dir)?;
    if keys::is_revoked(&roster, key_id) {
        bail!("provenance signing key id '{key_id}' is revoked in keys.toml");
    }
    let active = keys::active_key_by_id(&roster, key_id).ok_or_else(|| {
        anyhow::anyhow!("provenance signing key id '{key_id}' is not active in keys.toml")
    })?;
    let derived = derive_trust_key(registry_name, signing_key.path())?;
    if derived != active.key {
        bail!(
            "provenance signing key id '{key_id}' derives '{derived}', but keys.toml declares '{}'",
            active.key
        );
    }
    Ok(PackageProvenanceSigner {
        key_id: key_id.to_string(),
        key_path: PathBuf::from(signing_key.path()),
    })
}

fn package_provenance_trusted_keys(dir: &Path) -> Result<(String, Vec<TrustedProvenanceKey>)> {
    let registry_name = read_registry_toml(dir)?
        .map(|config| config.registry.name)
        .context("package provenance DSSE verification requires registry.toml [registry].name")?;
    let roster = load_committed_roster(dir)?;
    if roster.active.is_empty() {
        bail!("package provenance DSSE verification requires at least one active key in keys.toml");
    }
    let mut trusted = Vec::with_capacity(roster.active.len());
    for entry in &roster.active {
        if keys::is_revoked(&roster, &entry.id) {
            bail!(
                "package provenance DSSE key id '{}' is both active and revoked in keys.toml",
                entry.id
            );
        }
        let (entry_registry, _algorithm, _public_key) = parse_signing_key(&entry.key)
            .with_context(|| format!("invalid package provenance DSSE key id '{}'", entry.id))?;
        if entry_registry != registry_name {
            bail!(
                "package provenance DSSE key id '{}' belongs to registry '{}', expected '{}'",
                entry.id,
                entry_registry,
                registry_name
            );
        }
        trusted.push(TrustedProvenanceKey {
            key_id: entry.id.clone(),
            key: entry.key.clone(),
            retired_before_sequence: None,
        });
    }
    for entry in &roster.revoked {
        let Some(key) = entry.key.as_ref() else {
            continue;
        };
        let retired_before_sequence = entry.provenance_before_sequence.with_context(|| {
            format!(
                "revoked package provenance DSSE key id '{}' declares key material without provenance-before-sequence",
                entry.id
            )
        })?;
        let (entry_registry, _algorithm, _public_key) =
            parse_signing_key(key).with_context(|| {
                format!(
                    "invalid revoked package provenance DSSE key id '{}'",
                    entry.id
                )
            })?;
        if entry_registry != registry_name {
            bail!(
                "revoked package provenance DSSE key id '{}' belongs to registry '{}', expected '{}'",
                entry.id,
                entry_registry,
                registry_name
            );
        }
        trusted.push(TrustedProvenanceKey {
            key_id: entry.id.clone(),
            key: key.clone(),
            retired_before_sequence: Some(retired_before_sequence),
        });
    }
    Ok((registry_name, trusted))
}

fn append_package_provenance_transparency_log(
    dir: &Path,
    name: &str,
    version: &str,
    platform: &str,
    info: &StorePathInfo,
    source_info: Option<&StorePathInfo>,
    artifact: &PublishProvenanceArtifact,
    provenance_file_path: &Path,
) -> Result<PathBuf> {
    let path = dir.join(PACKAGE_PROVENANCE_TRANSPARENCY_LOG);
    ensure_package_provenance_transparency_log_extends_head(dir, &path)?;
    let (sequence, previous_entry_hash) = read_package_provenance_transparency_log_state(&path)?;
    let root_digest = artifact
        .attestation
        .root_digest
        .as_deref()
        .context("package transparency entry missing root_digest")?;
    let root_hash = artifact.attestation.root_hash.clone();
    let root_hash_sig = artifact.attestation.root_hash_sig.clone();
    if root_hash.is_some() != root_hash_sig.is_some() {
        bail!("package transparency entry root_hash and root_hash_sig must be declared together");
    }
    let provenance = artifact
        .attestation
        .provenance
        .as_deref()
        .context("package transparency entry missing provenance")?;
    if artifact.path != provenance {
        bail!(
            "package transparency entry provenance path mismatch: expected '{}', got '{}'",
            provenance,
            artifact.path
        );
    }
    let provenance_file_ref = registry_relative_path(dir, provenance_file_path)?;
    if provenance_file_ref != artifact.path {
        bail!(
            "package transparency entry provenance file mismatch: expected '{}', got '{}'",
            artifact.path,
            provenance_file_ref
        );
    }
    ensure_safe_package_provenance_statement_path(&provenance_file_ref)?;
    let provenance_file = fs::read(provenance_file_path).with_context(|| {
        format!(
            "reading provenance artifact {}",
            provenance_file_path.display()
        )
    })?;
    let measurement = artifact
        .attestation
        .measurement
        .as_deref()
        .context("package transparency entry missing measurement")?;
    let body = PackageProvenanceTransparencyLogBody {
        schema: PACKAGE_PROVENANCE_TRANSPARENCY_SCHEMA.to_string(),
        sequence,
        previous_entry_hash,
        package: name.to_string(),
        version: version.to_string(),
        platform: platform.to_string(),
        store_path: info.path.clone(),
        nar_hash: info.nar_hash.clone(),
        nar_size: info.nar_size,
        root_digest: Some(root_digest.to_string()),
        root_hash,
        root_hash_sig,
        provenance: provenance.to_string(),
        measurement: measurement.to_string(),
        source: source_info.map(|source| PackageProvenanceTransparencySource {
            store_path: source.path.clone(),
            nar_hash: source.nar_hash.clone(),
        }),
        statement: PackageProvenanceTransparencyStatement {
            path: artifact.path.clone(),
            jsonl_sha256: format!("sha256:{}", sha256_hex(&provenance_file)),
        },
    };
    let entry_hash = package_provenance_transparency_entry_hash(&body)?;
    let entry = PackageProvenanceTransparencyLogEntry { body, entry_hash };
    let parent = path
        .parent()
        .with_context(|| format!("transparency log path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    let line =
        serde_json::to_string(&entry).context("serializing package transparency log entry")?;
    writeln!(file, "{line}").with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

fn read_package_provenance_transparency_log_state(path: &Path) -> Result<(u64, Option<String>)> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok((0, None));
        }
        Err(err) => return Err(err).with_context(|| format!("reading {}", path.display())),
    };
    let (next_sequence, previous_entry_hash, _) =
        parse_package_provenance_transparency_log(&content, &path.display().to_string())?;
    Ok((next_sequence, previous_entry_hash))
}

fn parse_package_provenance_transparency_log(
    content: &str,
    source: &str,
) -> Result<(
    u64,
    Option<String>,
    Vec<PackageProvenanceTransparencyLogEntry>,
)> {
    let mut next_sequence = 0u64;
    let mut previous_entry_hash: Option<String> = None;
    let mut entries = Vec::new();
    for (line_index, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let entry: PackageProvenanceTransparencyLogEntry = serde_json::from_str(line)
            .with_context(|| {
                format!(
                    "deserializing package transparency log entry {} in {}",
                    line_index + 1,
                    source
                )
            })?;
        if entry.body.schema != PACKAGE_PROVENANCE_TRANSPARENCY_SCHEMA {
            bail!(
                "package transparency log entry {} has unsupported schema '{}'",
                line_index + 1,
                entry.body.schema
            );
        }
        if entry.body.sequence != next_sequence {
            bail!(
                "package transparency log entry {} sequence mismatch: expected {}, got {}",
                line_index + 1,
                next_sequence,
                entry.body.sequence
            );
        }
        if entry.body.previous_entry_hash != previous_entry_hash {
            bail!(
                "package transparency log entry {} previous hash mismatch",
                line_index + 1
            );
        }
        let expected_entry_hash = package_provenance_transparency_entry_hash(&entry.body)
            .with_context(|| {
                format!(
                    "hashing package transparency log entry {} in {}",
                    line_index + 1,
                    source
                )
            })?;
        if entry.entry_hash != expected_entry_hash {
            bail!(
                "package transparency log entry {} hash mismatch: expected '{}', got '{}'",
                line_index + 1,
                expected_entry_hash,
                entry.entry_hash
            );
        }
        previous_entry_hash = Some(entry.entry_hash.clone());
        next_sequence = next_sequence
            .checked_add(1)
            .context("package transparency log sequence overflow")?;
        entries.push(entry);
    }
    Ok((next_sequence, previous_entry_hash, entries))
}

fn ensure_package_provenance_transparency_log_extends_head(dir: &Path, path: &Path) -> Result<()> {
    let Some(head_log) = head_package_provenance_transparency_log(dir)? else {
        return Ok(());
    };
    let current = match fs::read(path) {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(err) => return Err(err).with_context(|| format!("reading {}", path.display())),
    };
    ensure_package_provenance_transparency_bytes_extend_head(
        dir,
        &current,
        &head_log,
        &path.display().to_string(),
    )
}

fn ensure_package_provenance_transparency_bytes_extend_head(
    dir: &Path,
    current: &[u8],
    head_log: &[u8],
    source: &str,
) -> Result<()> {
    if !current.starts_with(head_log) {
        bail!(
            "package transparency log {source} does not extend committed HEAD:{PACKAGE_PROVENANCE_TRANSPARENCY_LOG}; restore the committed prefix before publishing"
        );
    }
    let head_text = std::str::from_utf8(head_log)
        .with_context(|| format!("decoding HEAD:{PACKAGE_PROVENANCE_TRANSPARENCY_LOG} as UTF-8"))?;
    parse_package_provenance_transparency_log(
        head_text,
        &format!("HEAD:{PACKAGE_PROVENANCE_TRANSPARENCY_LOG}"),
    )
    .with_context(|| {
        format!(
            "validating HEAD:{PACKAGE_PROVENANCE_TRANSPARENCY_LOG} in {}",
            dir.display()
        )
    })?;
    Ok(())
}

fn head_package_provenance_transparency_log(dir: &Path) -> Result<Option<Vec<u8>>> {
    let (is_repo, _, _) = git_try(dir, &["rev-parse", "--is-inside-work-tree"])?;
    if !is_repo {
        return Ok(None);
    }
    let (has_head, _, _) = git_try(dir, &["rev-parse", "--verify", "HEAD"])?;
    if !has_head {
        return Ok(None);
    }
    git_tree_file_bytes(dir, "HEAD", PACKAGE_PROVENANCE_TRANSPARENCY_LOG)
}

fn git_index_file_bytes(dir: &Path, path: &str) -> Result<Option<Vec<u8>>> {
    ensure_safe_git_jsonl_index_path(path)?;
    git_index_safe_file_bytes(dir, path)
}

fn git_index_safe_file_bytes(dir: &Path, path: &str) -> Result<Option<Vec<u8>>> {
    ensure_safe_git_index_path(path)?;
    git_tree_file_bytes(dir, "", path)
}

fn git_tree_file_bytes(dir: &Path, treeish: &str, path: &str) -> Result<Option<Vec<u8>>> {
    let spec = if treeish.is_empty() {
        format!(":{path}")
    } else {
        format!("{treeish}:{path}")
    };
    let (exists, _, _) = git_try(dir, &["cat-file", "-e", &spec])?;
    if !exists {
        return Ok(None);
    }
    git_raw(dir, &["show", &spec]).map(Some)
}

fn staged_package_provenance_transparency_validation_needed(dir: &Path) -> Result<bool> {
    let changed = git(dir, &["diff", "--cached", "--name-only"])?;
    let log_changed = changed
        .lines()
        .any(|line| line.trim() == PACKAGE_PROVENANCE_TRANSPARENCY_LOG);
    if log_changed {
        return Ok(true);
    }
    if !staged_package_toml_provenance_entries(dir)?.is_empty() {
        return Ok(true);
    }
    let provenance_statement_changed = changed.lines().any(|line| {
        let path = line.trim();
        path.starts_with("provenance/") && path.ends_with(".intoto.jsonl")
    });
    if provenance_statement_changed {
        return Ok(true);
    }
    let store_record_changed = changed
        .lines()
        .any(|line| line.trim().starts_with("store/"));
    if store_record_changed && !indexed_package_toml_provenance_entries(dir)?.is_empty() {
        return Ok(true);
    }
    Ok(false)
}

fn validate_staged_package_provenance_transparency_log(dir: &Path) -> Result<()> {
    let log = git_index_file_bytes(dir, PACKAGE_PROVENANCE_TRANSPARENCY_LOG)?
        .context("staged package provenance transparency log is missing")?;
    if let Some(head_log) = head_package_provenance_transparency_log(dir)? {
        ensure_package_provenance_transparency_bytes_extend_head(
            dir,
            &log,
            &head_log,
            &format!("index:{PACKAGE_PROVENANCE_TRANSPARENCY_LOG}"),
        )?;
    }
    let log_text = std::str::from_utf8(&log)
        .context("decoding staged package provenance transparency log as UTF-8")?;
    let (_, _, entries) = parse_package_provenance_transparency_log(
        log_text,
        &format!("index:{PACKAGE_PROVENANCE_TRANSPARENCY_LOG}"),
    )?;
    validate_staged_package_toml_provenance_entries(dir, &entries)?;
    validate_staged_store_provenance_entries(dir, &entries)?;
    let (registry_name, trusted_keys) = package_provenance_trusted_keys(dir)?;
    for entry in &entries {
        ensure_safe_package_provenance_statement_path(&entry.body.statement.path)?;
        let statement_bytes =
            git_index_file_bytes(dir, &entry.body.statement.path)?.with_context(|| {
                format!(
                    "staged package provenance statement '{}' is missing",
                    entry.body.statement.path
                )
            })?;
        let actual = format!("sha256:{}", sha256_hex(&statement_bytes));
        if actual != entry.body.statement.jsonl_sha256 {
            bail!(
                "staged package provenance statement '{}' digest mismatch: expected '{}', got '{}'",
                entry.body.statement.path,
                entry.body.statement.jsonl_sha256,
                actual
            );
        }
        let statement_text = std::str::from_utf8(&statement_bytes).with_context(|| {
            format!(
                "decoding package provenance statement '{}' as UTF-8",
                entry.body.statement.path
            )
        })?;
        let (statement, key_id) =
            crate::provenance::verify_statement_dsse_jsonl(statement_text, &trusted_keys)
                .with_context(|| {
                    format!(
                        "verifying package provenance DSSE envelope '{}'",
                        entry.body.statement.path
                    )
                })?;
        crate::provenance::verify_key_allowed_for_transparency_sequence(
            &trusted_keys,
            &key_id,
            entry.body.sequence,
        )
        .with_context(|| {
            format!(
                "verifying package provenance key lifetime for '{}'",
                entry.body.statement.path
            )
        })?;
        validate_package_provenance_transparency_statement(
            entry,
            &statement,
            &registry_name,
            &key_id,
        )?;
    }
    Ok(())
}

fn validate_staged_package_toml_provenance_entries(
    dir: &Path,
    log_entries: &[PackageProvenanceTransparencyLogEntry],
) -> Result<()> {
    for meta in staged_package_toml_provenance_entries(dir)? {
        let entry = unique_staged_package_transparency_entry(log_entries, &meta)?;
        ensure_staged_package_matches_transparency_entry(&meta, entry)?;
    }
    Ok(())
}

fn validate_staged_package_toml_provenance_requirements(dir: &Path) -> Result<()> {
    for path in staged_changed_paths(dir)? {
        if !is_package_toml_path(&path) {
            continue;
        }
        let Some(bytes) = git_index_safe_file_bytes(dir, &path)? else {
            continue;
        };
        let text = std::str::from_utf8(&bytes)
            .with_context(|| format!("decoding staged package metadata {path} as UTF-8"))?;
        let value: toml::Value = toml::from_str(text)
            .with_context(|| format!("parsing staged package metadata {path}"))?;
        for (key, platform_entry) in package_toml_platform_entries(&path, &value, "staged")? {
            ensure_staged_package_rfc0001_provenance(&path, &key, platform_entry)?;
        }
    }
    Ok(())
}

fn staged_package_toml_provenance_entries(dir: &Path) -> Result<Vec<StagedPackageProvenanceMeta>> {
    package_toml_provenance_entries_from_paths(dir, staged_changed_paths(dir)?, true)
}

fn indexed_package_toml_provenance_entries(dir: &Path) -> Result<Vec<StagedPackageProvenanceMeta>> {
    package_toml_provenance_entries_from_paths(dir, git_ls_files(dir, "packages")?, false)
}

fn head_package_toml_provenance_entries(dir: &Path) -> Result<Vec<StagedPackageProvenanceMeta>> {
    let mut metas = Vec::new();
    for path in git_ls_tree_files(dir, "HEAD", "packages")? {
        if !is_package_toml_path(&path) {
            continue;
        }
        let Some(bytes) = git_tree_file_bytes(dir, "HEAD", &path)? else {
            continue;
        };
        let text = std::str::from_utf8(&bytes)
            .with_context(|| format!("decoding HEAD package metadata {path} as UTF-8"))?;
        let value: toml::Value = toml::from_str(text)
            .with_context(|| format!("parsing HEAD package metadata {path}"))?;
        for (key, platform_entry) in package_toml_platform_entries(&path, &value, "HEAD")? {
            let Some(provenance) = platform_entry
                .get("provenance")
                .and_then(toml::Value::as_str)
            else {
                continue;
            };
            metas.push(StagedPackageProvenanceMeta {
                path: path.clone(),
                package: key.package.clone(),
                version: key.version.clone(),
                platform: key.platform.clone(),
                store_path: staged_package_string_field(
                    &path,
                    &key.package,
                    &key.version,
                    &key.platform,
                    platform_entry,
                    "store_path",
                )?,
                source_drv: staged_package_string_field(
                    &path,
                    &key.package,
                    &key.version,
                    &key.platform,
                    platform_entry,
                    "source_drv",
                )?,
                source_nar_hash: staged_package_string_field(
                    &path,
                    &key.package,
                    &key.version,
                    &key.platform,
                    platform_entry,
                    "source_nar_hash",
                )?,
                root_digest: staged_package_string_field(
                    &path,
                    &key.package,
                    &key.version,
                    &key.platform,
                    platform_entry,
                    "root_digest",
                )?,
                root_hash: staged_package_optional_string_field(
                    &path,
                    &key.package,
                    &key.version,
                    &key.platform,
                    platform_entry,
                    "root_hash",
                )?,
                root_hash_sig: staged_package_optional_string_field(
                    &path,
                    &key.package,
                    &key.version,
                    &key.platform,
                    platform_entry,
                    "root_hash_sig",
                )?,
                provenance: provenance.to_string(),
                measurement: staged_package_string_field(
                    &path,
                    &key.package,
                    &key.version,
                    &key.platform,
                    platform_entry,
                    "measurement",
                )?,
            });
        }
    }
    Ok(metas)
}

fn package_toml_provenance_entries_from_paths(
    dir: &Path,
    paths: Vec<String>,
    check_downgrade: bool,
) -> Result<Vec<StagedPackageProvenanceMeta>> {
    let mut metas = Vec::new();
    for path in paths {
        if !is_package_toml_path(&path) {
            continue;
        }
        let Some(bytes) = git_index_safe_file_bytes(dir, &path)? else {
            continue;
        };
        let text = std::str::from_utf8(&bytes)
            .with_context(|| format!("decoding staged package metadata {path} as UTF-8"))?;
        let value: toml::Value = toml::from_str(text)
            .with_context(|| format!("parsing staged package metadata {path}"))?;
        let staged_entries = package_toml_platform_entries(&path, &value, "staged")?;
        if check_downgrade {
            ensure_staged_package_provenance_not_downgraded(dir, &path, &staged_entries)?;
        }
        for (key, platform_entry) in staged_entries {
            let Some(provenance) = platform_entry
                .get("provenance")
                .and_then(toml::Value::as_str)
            else {
                continue;
            };
            metas.push(StagedPackageProvenanceMeta {
                path: path.clone(),
                package: key.package.clone(),
                version: key.version.clone(),
                platform: key.platform.clone(),
                store_path: staged_package_string_field(
                    &path,
                    &key.package,
                    &key.version,
                    &key.platform,
                    platform_entry,
                    "store_path",
                )?,
                source_drv: staged_package_string_field(
                    &path,
                    &key.package,
                    &key.version,
                    &key.platform,
                    platform_entry,
                    "source_drv",
                )?,
                source_nar_hash: staged_package_string_field(
                    &path,
                    &key.package,
                    &key.version,
                    &key.platform,
                    platform_entry,
                    "source_nar_hash",
                )?,
                root_digest: staged_package_string_field(
                    &path,
                    &key.package,
                    &key.version,
                    &key.platform,
                    platform_entry,
                    "root_digest",
                )?,
                root_hash: staged_package_optional_string_field(
                    &path,
                    &key.package,
                    &key.version,
                    &key.platform,
                    platform_entry,
                    "root_hash",
                )?,
                root_hash_sig: staged_package_optional_string_field(
                    &path,
                    &key.package,
                    &key.version,
                    &key.platform,
                    platform_entry,
                    "root_hash_sig",
                )?,
                provenance: provenance.to_string(),
                measurement: staged_package_string_field(
                    &path,
                    &key.package,
                    &key.version,
                    &key.platform,
                    platform_entry,
                    "measurement",
                )?,
            });
        }
    }
    Ok(metas)
}

fn ensure_staged_package_rfc0001_provenance(
    path: &str,
    key: &PackageTomlPlatformKey,
    entry: &toml::Value,
) -> Result<()> {
    let meta: StagedPackageRfc0001Meta = entry.clone().try_into().with_context(|| {
        format!(
            "parsing staged package metadata {path} {} {} {} RFC-0001 fields",
            key.package, key.version, key.platform
        )
    })?;
    let requires_provenance = rfc0001_metadata_requires_provenance(
        meta.expose.as_ref(),
        meta.expose_artifact.as_ref(),
        &meta.permissions,
        meta.bpf_lsm.as_ref(),
    );
    if !requires_provenance {
        return Ok(());
    }
    match entry.get("provenance") {
        Some(provenance) if provenance.is_str() => Ok(()),
        Some(_) => bail!(
            "staged package metadata {path} {} {} {} provenance must be a string",
            key.package,
            key.version,
            key.platform
        ),
        None => bail!(
            "staged package metadata {path} {} {} {} uses RFC-0001 exposed or permission metadata without attestation provenance",
            key.package,
            key.version,
            key.platform
        ),
    }
}

fn ensure_staged_package_provenance_not_downgraded(
    dir: &Path,
    path: &str,
    staged_entries: &[(PackageTomlPlatformKey, &toml::Value)],
) -> Result<()> {
    let staged_by_key = staged_entries
        .iter()
        .map(|(key, entry)| (key.clone(), *entry))
        .collect::<BTreeMap<_, _>>();
    for (key, entry) in &staged_by_key {
        if let Some(provenance) = entry.get("provenance")
            && !provenance.is_str()
        {
            bail!(
                "staged package metadata {path} {} {} {} provenance must be a string",
                key.package,
                key.version,
                key.platform
            );
        }
    }
    let Some(head_bytes) = git_tree_file_bytes(dir, "HEAD", path)? else {
        return Ok(());
    };
    let head_text = std::str::from_utf8(&head_bytes)
        .with_context(|| format!("decoding HEAD package metadata {path} as UTF-8"))?;
    let head_value: toml::Value = toml::from_str(head_text)
        .with_context(|| format!("parsing HEAD package metadata {path}"))?;
    for (key, head_entry) in package_toml_platform_entries(path, &head_value, "HEAD")? {
        let Some(head_provenance) = head_entry.get("provenance").and_then(toml::Value::as_str)
        else {
            continue;
        };
        let Some(staged_entry) = staged_by_key.get(&key) else {
            continue;
        };
        if staged_entry
            .get("provenance")
            .and_then(toml::Value::as_str)
            .is_none()
        {
            bail!(
                "staged package metadata {path} {} {} {} removes committed provenance '{}'",
                key.package,
                key.version,
                key.platform,
                head_provenance
            );
        }
    }
    Ok(())
}

fn package_toml_platform_entries<'a>(
    path: &str,
    value: &'a toml::Value,
    source: &str,
) -> Result<Vec<(PackageTomlPlatformKey, &'a toml::Value)>> {
    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    let package = value
        .get("package")
        .and_then(|package| package.get("name"))
        .and_then(toml::Value::as_str)
        .with_context(|| format!("{source} package metadata {path} missing package.name"))?;
    let Some(versions_value) = value.get("versions") else {
        return Ok(entries);
    };
    let versions = versions_value
        .as_array()
        .with_context(|| format!("{source} package metadata {path} versions must be an array"))?;
    for version_entry in versions {
        let version = version_entry
            .get("version")
            .and_then(toml::Value::as_str)
            .with_context(|| {
                format!("{source} package metadata {path} has a version missing version")
            })?;
        let Some(platforms_value) = version_entry.get("platforms") else {
            continue;
        };
        let platforms = platforms_value.as_table().with_context(|| {
            format!("{source} package metadata {path} version {version} platforms must be a table")
        })?;
        for (platform, platform_entry) in platforms {
            let key = PackageTomlPlatformKey {
                package: package.to_string(),
                version: version.to_string(),
                platform: platform.to_string(),
            };
            if !seen.insert(key.clone()) {
                bail!(
                    "{source} package metadata {path} has duplicate {} {} {} platform entries",
                    key.package,
                    key.version,
                    key.platform
                );
            }
            entries.push((key, platform_entry));
        }
    }
    Ok(entries)
}

fn validate_staged_store_provenance_entries(
    dir: &Path,
    log_entries: &[PackageProvenanceTransparencyLogEntry],
) -> Result<()> {
    let changed_ias = staged_store_record_ia_hashes(dir)?;
    let package_metas = indexed_package_toml_provenance_entries(dir)?;
    for meta in &package_metas {
        validate_staged_store_record_for_package(dir, log_entries, meta)?;
    }

    if changed_ias.is_empty() {
        return Ok(());
    }

    let protected_roots = head_package_toml_provenance_entries(dir)?
        .into_iter()
        .map(|meta| extract_hash(&meta.store_path).to_string())
        .collect::<HashSet<_>>();
    for root_meta in &package_metas {
        let root_ia = extract_hash(&root_meta.store_path);
        if !protected_roots.contains(root_ia) {
            continue;
        }
        let reachable = staged_store_reachable_ias(dir, root_ia)?;
        for changed_ia in changed_ias.intersection(&reachable) {
            let mut bound = false;
            for meta in package_metas
                .iter()
                .filter(|meta| extract_hash(&meta.store_path) == changed_ia.as_str())
            {
                bound = true;
                validate_staged_store_record_for_package(dir, log_entries, meta)?;
            }
            if !bound {
                let record_path =
                    registry_relative_path(dir, &store::entry_path(dir, changed_ia)?)?;
                bail!(
                    "staged store record {record_path} changes a reachable dependency of provenanced package {} {} {} without its own package provenance transparency binding",
                    root_meta.package,
                    root_meta.version,
                    root_meta.platform
                );
            }
        }
    }
    Ok(())
}

fn validate_staged_store_record_for_package(
    dir: &Path,
    log_entries: &[PackageProvenanceTransparencyLogEntry],
    meta: &StagedPackageProvenanceMeta,
) -> Result<()> {
    let ia_hash = extract_hash(&meta.store_path);
    let entry = unique_staged_package_transparency_entry(log_entries, meta)?;
    ensure_staged_package_matches_transparency_entry(meta, entry)?;
    let record_path = registry_relative_path(dir, &store::entry_path(dir, ia_hash)?)?;
    let bytes = git_index_safe_file_bytes(dir, &record_path)?.with_context(|| {
        format!(
            "staged store record {record_path} for provenanced package {} {} {} is missing",
            meta.package, meta.version, meta.platform
        )
    })?;
    let text = std::str::from_utf8(&bytes)
        .with_context(|| format!("decoding staged store record {record_path} as UTF-8"))?;
    let store_entry = store::parse_entry(text)
        .with_context(|| format!("parsing staged store record {record_path}"))?;
    let expected_nar = NarBytes::from_hash(&entry.body.nar_hash, entry.body.nar_size)
        .with_context(|| {
            format!(
                "normalizing transparency log NAR hash for {} {} {}",
                meta.package, meta.version, meta.platform
            )
        })?;
    let mut matched = false;
    for nar in store_entry.blessed_nars() {
        if nar == expected_nar {
            matched = true;
            continue;
        }
        bail!(
            "staged store record {record_path} blesses NAR sha256:{}:{} for provenanced package {} {} {}, but transparency log entry {} covers '{}:{}'",
            nar.sha256_nix32,
            nar.size,
            meta.package,
            meta.version,
            meta.platform,
            entry.body.sequence,
            entry.body.nar_hash,
            entry.body.nar_size
        );
    }
    if !matched {
        bail!(
            "staged store record {record_path} for provenanced package {} {} {} is missing transparency-log NAR '{}:{}'",
            meta.package,
            meta.version,
            meta.platform,
            entry.body.nar_hash,
            entry.body.nar_size
        );
    }
    Ok(())
}

fn staged_store_reachable_ias(dir: &Path, root_ia: &str) -> Result<HashSet<String>> {
    let mut reachable = HashSet::new();
    let mut stack = vec![root_ia.to_string()];
    while let Some(ia_hash) = stack.pop() {
        if !reachable.insert(ia_hash.clone()) {
            continue;
        }
        let Some(entry) = staged_store_entry(dir, &ia_hash)? else {
            continue;
        };
        stack.extend(entry.dep_ias());
    }
    Ok(reachable)
}

fn staged_store_entry(dir: &Path, ia_hash: &str) -> Result<Option<store::StoreEntry>> {
    let path = registry_relative_path(dir, &store::entry_path(dir, ia_hash)?)?;
    let Some(bytes) = git_index_safe_file_bytes(dir, &path)? else {
        return Ok(None);
    };
    let text = std::str::from_utf8(&bytes)
        .with_context(|| format!("decoding staged store record {path} as UTF-8"))?;
    store::parse_entry(text)
        .map(Some)
        .with_context(|| format!("parsing staged store record {path}"))
}

fn staged_store_record_ia_hashes(dir: &Path) -> Result<HashSet<String>> {
    let mut hashes = HashSet::new();
    for path in staged_changed_paths(dir)? {
        let Some(ia_hash) = store_record_ia_hash_from_index_path(dir, &path)? else {
            continue;
        };
        hashes.insert(ia_hash);
    }
    Ok(hashes)
}

fn store_record_ia_hash_from_index_path(dir: &Path, path: &str) -> Result<Option<String>> {
    if !path.starts_with("store/") {
        return Ok(None);
    }
    ensure_safe_git_index_path(path)?;
    let parts = path.split('/').collect::<Vec<_>>();
    if parts.len() != 3 {
        bail!("staged store record path '{path}' must use store/<shard>/<hash>");
    }
    let ia_hash = parts[2];
    let expected = registry_relative_path(dir, &store::entry_path(dir, ia_hash)?)?;
    if path != expected {
        bail!("staged store record path '{path}' is misfiled; expected '{expected}'");
    }
    Ok(Some(ia_hash.to_string()))
}

fn unique_staged_package_transparency_entry<'a>(
    log_entries: &'a [PackageProvenanceTransparencyLogEntry],
    meta: &StagedPackageProvenanceMeta,
) -> Result<&'a PackageProvenanceTransparencyLogEntry> {
    let mut matches = log_entries
        .iter()
        .filter(|entry| entry.body.provenance == meta.provenance);
    let entry = matches.next().with_context(|| {
        format!(
            "staged package metadata {} declares provenance '{}' with no transparency log entry",
            meta.path, meta.provenance
        )
    })?;
    if matches.next().is_some() {
        bail!(
            "staged package metadata {} declares provenance '{}' with duplicate transparency log entries",
            meta.path,
            meta.provenance
        );
    }
    Ok(entry)
}

fn ensure_staged_package_matches_transparency_entry(
    meta: &StagedPackageProvenanceMeta,
    entry: &PackageProvenanceTransparencyLogEntry,
) -> Result<()> {
    ensure_staged_package_field(meta, "package", &entry.body.package, &meta.package)?;
    ensure_staged_package_field(meta, "version", &entry.body.version, &meta.version)?;
    ensure_staged_package_field(meta, "platform", &entry.body.platform, &meta.platform)?;
    ensure_staged_package_field(meta, "store_path", &entry.body.store_path, &meta.store_path)?;
    let entry_root_digest = entry
        .body
        .root_digest
        .as_deref()
        .or(entry.body.root_hash.as_deref())
        .context("package transparency entry missing root_digest")?;
    ensure_staged_package_field(meta, "root_digest", entry_root_digest, &meta.root_digest)?;
    ensure_staged_package_optional_field(
        meta,
        "root_hash",
        entry.body.root_hash.as_deref(),
        meta.root_hash.as_deref(),
    )?;
    ensure_staged_package_optional_field(
        meta,
        "root_hash_sig",
        entry.body.root_hash_sig.as_deref(),
        meta.root_hash_sig.as_deref(),
    )?;
    ensure_staged_package_field(
        meta,
        "measurement",
        &entry.body.measurement,
        &meta.measurement,
    )?;
    ensure_staged_package_source(meta, entry)
}

fn ensure_staged_package_source(
    meta: &StagedPackageProvenanceMeta,
    entry: &PackageProvenanceTransparencyLogEntry,
) -> Result<()> {
    if let Some(source) = &entry.body.source {
        ensure_staged_package_field(meta, "source_drv", &source.store_path, &meta.source_drv)?;
        ensure_staged_package_field(
            meta,
            "source_nar_hash",
            &source.nar_hash,
            &meta.source_nar_hash,
        )?;
        return Ok(());
    }
    if !meta.source_drv.is_empty() || !meta.source_nar_hash.is_empty() {
        bail!(
            "staged package metadata {} {} {} {} declares source metadata but transparency log entry has no source dependency",
            meta.path,
            meta.package,
            meta.version,
            meta.platform
        );
    }
    Ok(())
}

fn staged_changed_paths(dir: &Path) -> Result<Vec<String>> {
    Ok(git(dir, &["diff", "--cached", "--name-only"])?
        .lines()
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(ToString::to_string)
        .collect())
}

fn git_ls_files(dir: &Path, pathspec: &str) -> Result<Vec<String>> {
    Ok(git(dir, &["ls-files", "--", pathspec])?
        .lines()
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(ToString::to_string)
        .collect())
}

fn git_ls_tree_files(dir: &Path, treeish: &str, pathspec: &str) -> Result<Vec<String>> {
    let (ok, stdout, _) = git_try(
        dir,
        &["ls-tree", "-r", "--name-only", treeish, "--", pathspec],
    )?;
    if !ok {
        return Ok(Vec::new());
    }
    Ok(stdout
        .lines()
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(ToString::to_string)
        .collect())
}

fn is_package_toml_path(path: &str) -> bool {
    path.starts_with("packages/")
        && path.ends_with(".toml")
        && ensure_safe_git_index_path(path).is_ok()
}

fn staged_package_string_field(
    path: &str,
    package: &str,
    version: &str,
    platform: &str,
    entry: &toml::Value,
    field: &str,
) -> Result<String> {
    entry
        .get(field)
        .and_then(toml::Value::as_str)
        .map(ToString::to_string)
        .with_context(|| {
            format!("staged package metadata {path} {package} {version} {platform} missing {field}")
        })
}

fn staged_package_optional_string_field(
    path: &str,
    package: &str,
    version: &str,
    platform: &str,
    entry: &toml::Value,
    field: &str,
) -> Result<Option<String>> {
    match entry.get(field) {
        Some(value) => value
            .as_str()
            .map(|value| Some(value.to_string()))
            .with_context(|| {
                format!(
                    "staged package metadata {path} {package} {version} {platform} {field} must be a string"
                )
            }),
        None => Ok(None),
    }
}

fn ensure_staged_package_field(
    meta: &StagedPackageProvenanceMeta,
    field: &str,
    expected: &str,
    actual: &str,
) -> Result<()> {
    if expected != actual {
        bail!(
            "staged package metadata {} {} {} {} {field} mismatch: expected '{}', got '{}'",
            meta.path,
            meta.package,
            meta.version,
            meta.platform,
            expected,
            actual
        );
    }
    Ok(())
}

fn ensure_staged_package_optional_field(
    meta: &StagedPackageProvenanceMeta,
    field: &str,
    expected: Option<&str>,
    actual: Option<&str>,
) -> Result<()> {
    if expected != actual {
        bail!(
            "staged package metadata {} {} {} {} {field} mismatch: expected '{}', got '{}'",
            meta.path,
            meta.package,
            meta.version,
            meta.platform,
            expected.unwrap_or("<absent>"),
            actual.unwrap_or("<absent>")
        );
    }
    Ok(())
}

fn validate_package_provenance_transparency_statement(
    entry: &PackageProvenanceTransparencyLogEntry,
    statement: &Value,
    registry_name: &str,
    key_id: &str,
) -> Result<()> {
    if entry.body.statement.path != entry.body.provenance {
        bail!(
            "package transparency log entry {} statement path '{}' does not match provenance '{}'",
            entry.body.sequence,
            entry.body.statement.path,
            entry.body.provenance
        );
    }
    ensure_json_string(
        statement,
        "_type",
        PACKAGE_PROVENANCE_STATEMENT_TYPE,
        "statement _type",
    )?;
    ensure_json_string(
        statement,
        "predicateType",
        PACKAGE_PROVENANCE_PREDICATE_TYPE,
        "statement predicateType",
    )?;

    let predicate = json_object(&statement, "predicate")?;
    let build_definition = json_object(predicate, "buildDefinition")?;
    let run_details = json_object(predicate, "runDetails")?;
    let builder = json_object(run_details, "builder")?;
    ensure_json_string(
        builder,
        "id",
        &provenance_builder_id(registry_name, key_id),
        "runDetails.builder.id",
    )?;
    ensure_json_string(
        build_definition,
        "buildType",
        PACKAGE_PROVENANCE_BUILD_TYPE,
        "statement buildType",
    )?;
    let params = json_object(build_definition, "externalParameters")?;
    ensure_json_string(
        params,
        "package",
        &entry.body.package,
        "externalParameters.package",
    )?;
    ensure_json_string(
        params,
        "version",
        &entry.body.version,
        "externalParameters.version",
    )?;
    ensure_json_string(
        params,
        "platform",
        &entry.body.platform,
        "externalParameters.platform",
    )?;
    ensure_json_string(
        params,
        "store_path",
        &entry.body.store_path,
        "externalParameters.store_path",
    )?;
    ensure_json_string(
        params,
        "root_digest",
        entry
            .body
            .root_digest
            .as_deref()
            .or(entry.body.root_hash.as_deref())
            .context("package transparency entry missing root_digest")?,
        "externalParameters.root_digest",
    )?;
    ensure_json_optional_string(
        params,
        "root_hash",
        entry.body.root_hash.as_deref(),
        "externalParameters.root_hash",
    )?;
    ensure_json_optional_string(
        params,
        "root_hash_sig",
        entry.body.root_hash_sig.as_deref(),
        "externalParameters.root_hash_sig",
    )?;
    ensure_json_string(
        params,
        "provenance",
        &entry.body.provenance,
        "externalParameters.provenance",
    )?;

    let package_subject = provenance_statement_named_object(
        json_array(statement, "subject")?,
        &entry.body.store_path,
    )
    .with_context(|| {
        format!(
            "locating package subject '{}' for transparency log entry {}",
            entry.body.store_path, entry.body.sequence
        )
    })?;
    ensure_json_value(
        package_subject,
        "digest",
        &provenance_digest_map(&entry.body.nar_hash),
        "package subject digest",
    )?;

    let manifest_subject_name = format!(
        "aos:permissions-manifest:{}:{}:{}",
        entry.body.package, entry.body.version, entry.body.platform
    );
    let manifest_subject = provenance_statement_named_object(
        json_array(statement, "subject")?,
        &manifest_subject_name,
    )
    .with_context(|| {
        format!(
            "locating permissions manifest subject '{}' for transparency log entry {}",
            manifest_subject_name, entry.body.sequence
        )
    })?;
    let manifest_digest = sha256_digest_from_statement_digest(
        manifest_subject.get("digest").with_context(|| {
            format!("permissions manifest subject '{manifest_subject_name}' missing digest")
        })?,
        "permissions manifest subject digest",
    )?;
    let expected_measurement = crate::package_attestation::package_measurement_digest(
        &entry.body.package,
        &entry.body.version,
        entry
            .body
            .root_digest
            .as_deref()
            .or(entry.body.root_hash.as_deref())
            .context("package transparency entry missing root_digest")?,
        &manifest_digest,
    );
    if expected_measurement != entry.body.measurement {
        bail!(
            "package transparency log entry {} measurement does not match permissions manifest digest",
            entry.body.sequence
        );
    }

    let measurement_subject_name = format!(
        "aos:package-measurement:{}:{}:{}",
        entry.body.package, entry.body.version, entry.body.platform
    );
    let measurement_subject = provenance_statement_named_object(
        json_array(statement, "subject")?,
        &measurement_subject_name,
    )
    .with_context(|| {
        format!(
            "locating measurement subject '{}' for transparency log entry {}",
            measurement_subject_name, entry.body.sequence
        )
    })?;
    ensure_json_value(
        measurement_subject,
        "digest",
        &provenance_digest_map(&entry.body.measurement),
        "measurement subject digest",
    )?;

    if let Some(source) = &entry.body.source {
        let source_uri = format!("nix:{}", source.store_path);
        let dependencies = json_array(build_definition, "resolvedDependencies")?;
        let dependency =
            provenance_statement_named_uri(dependencies, &source_uri).with_context(|| {
                format!(
                    "locating source dependency '{}' for transparency log entry {}",
                    source_uri, entry.body.sequence
                )
            })?;
        ensure_json_value(
            dependency,
            "digest",
            &provenance_digest_map(&source.nar_hash),
            "source dependency digest",
        )?;
    }

    Ok(())
}

fn provenance_statement_named_object<'a>(objects: &'a [Value], name: &str) -> Result<&'a Value> {
    let mut matches = objects.iter().filter(|object| {
        object
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|actual| actual == name)
    });
    let value = matches
        .next()
        .with_context(|| format!("provenance statement missing object named '{name}'"))?;
    if matches.next().is_some() {
        bail!("provenance statement has duplicate object named '{name}'");
    }
    Ok(value)
}

fn provenance_statement_named_uri<'a>(objects: &'a [Value], uri: &str) -> Result<&'a Value> {
    let mut matches = objects.iter().filter(|object| {
        object
            .get("uri")
            .and_then(Value::as_str)
            .is_some_and(|actual| actual == uri)
    });
    let value = matches
        .next()
        .with_context(|| format!("provenance statement missing dependency uri '{uri}'"))?;
    if matches.next().is_some() {
        bail!("provenance statement has duplicate dependency uri '{uri}'");
    }
    Ok(value)
}

fn json_object<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    value
        .get(key)
        .filter(|value| value.is_object())
        .with_context(|| format!("provenance statement missing object field '{key}'"))
}

fn json_array<'a>(value: &'a Value, key: &str) -> Result<&'a [Value]> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .with_context(|| format!("provenance statement missing array field '{key}'"))
}

fn ensure_json_string(object: &Value, key: &str, expected: &str, label: &str) -> Result<()> {
    let actual = object
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("provenance statement missing string field '{label}'"))?;
    if actual != expected {
        bail!("provenance statement {label} mismatch: expected '{expected}', got '{actual}'");
    }
    Ok(())
}

fn ensure_json_optional_string(
    object: &Value,
    key: &str,
    expected: Option<&str>,
    label: &str,
) -> Result<()> {
    let actual = object.get(key).and_then(Value::as_str);
    if actual != expected {
        bail!(
            "provenance statement {label} mismatch: expected '{}', got '{}'",
            expected.unwrap_or("<absent>"),
            actual.unwrap_or("<absent>")
        );
    }
    Ok(())
}

fn ensure_json_value(object: &Value, key: &str, expected: &Value, label: &str) -> Result<()> {
    let actual = object
        .get(key)
        .with_context(|| format!("provenance statement missing field '{label}'"))?;
    if actual != expected {
        bail!("provenance statement {label} mismatch");
    }
    Ok(())
}

fn sha256_digest_from_statement_digest(digest: &Value, label: &str) -> Result<String> {
    let sha256 = digest
        .get("sha256")
        .and_then(Value::as_str)
        .with_context(|| format!("provenance statement {label} missing sha256"))?;
    if sha256.len() != 64 || !sha256.chars().all(|ch| ch.is_ascii_hexdigit()) {
        bail!("provenance statement {label} has invalid sha256 digest '{sha256}'");
    }
    Ok(format!("sha256:{}", sha256.to_ascii_lowercase()))
}

fn ensure_safe_package_provenance_statement_path(path: &str) -> Result<()> {
    ensure_safe_git_jsonl_index_path(path)?;
    if !path.starts_with("provenance/") || !path.ends_with(".intoto.jsonl") {
        bail!(
            "package provenance statement path '{path}' must use the generated provenance/*.intoto.jsonl layout"
        );
    }
    Ok(())
}

fn ensure_safe_git_jsonl_index_path(path: &str) -> Result<()> {
    ensure_safe_git_index_path(path)?;
    if !path.ends_with(".jsonl") {
        bail!("package provenance statement path '{path}' must be a relative *.jsonl path");
    }
    Ok(())
}

fn ensure_safe_git_index_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains(':')
        || path.bytes().any(|byte| byte.is_ascii_control())
    {
        bail!("git index path '{path}' must be relative and must not contain revspec punctuation");
    }
    for component in Path::new(path).components() {
        match component {
            std::path::Component::Normal(part) if !part.is_empty() => {}
            _ => {
                bail!(
                    "package provenance statement path '{path}' must not contain '.', '..', or prefixes"
                );
            }
        }
    }
    Ok(())
}

fn package_provenance_transparency_entry_hash(
    body: &PackageProvenanceTransparencyLogBody,
) -> Result<String> {
    let payload = serde_json::to_vec(body)
        .context("serializing package transparency log entry body for hashing")?;
    Ok(format!("sha256:{}", sha256_hex(&payload)))
}

fn publish_provenance_statement(
    registry_name: &str,
    name: &str,
    version: &str,
    platform: &str,
    info: &StorePathInfo,
    source_info: Option<&StorePathInfo>,
    manifest_digest: &str,
    attestation: &AttestationMeta,
    key_id: &str,
) -> Result<serde_json::Value> {
    let root_digest = attestation
        .root_digest
        .as_deref()
        .context("package attestation root_digest missing")?;
    let measurement = attestation
        .measurement
        .as_deref()
        .context("package attestation measurement missing")?;
    let provenance = attestation
        .provenance
        .as_deref()
        .context("package attestation provenance missing")?;
    if attestation.root_hash.is_some() != attestation.root_hash_sig.is_some() {
        bail!("package attestation root_hash and root_hash_sig must be declared together");
    }
    let resolved_dependencies = source_info
        .into_iter()
        .map(|source| {
            serde_json::json!({
                "uri": format!("nix:{}", source.path.as_str()),
                "digest": provenance_digest_map(&source.nar_hash),
            })
        })
        .collect::<Vec<_>>();
    let mut external_parameters = serde_json::Map::new();
    external_parameters.insert("package".to_string(), serde_json::json!(name));
    external_parameters.insert("version".to_string(), serde_json::json!(version));
    external_parameters.insert("platform".to_string(), serde_json::json!(platform));
    external_parameters.insert(
        "store_path".to_string(),
        serde_json::json!(info.path.as_str()),
    );
    external_parameters.insert("root_digest".to_string(), serde_json::json!(root_digest));
    if let Some(root_hash) = attestation.root_hash.as_deref() {
        external_parameters.insert("root_hash".to_string(), serde_json::json!(root_hash));
    }
    if let Some(root_hash_sig) = attestation.root_hash_sig.as_deref() {
        external_parameters.insert(
            "root_hash_sig".to_string(),
            serde_json::json!(root_hash_sig),
        );
    }
    external_parameters.insert("provenance".to_string(), serde_json::json!(provenance));

    Ok(serde_json::json!({
        "_type": PACKAGE_PROVENANCE_STATEMENT_TYPE,
        "subject": [
            {
                "name": info.path.as_str(),
                "digest": provenance_digest_map(&info.nar_hash),
            },
            {
                "name": format!("aos:permissions-manifest:{name}:{version}:{platform}"),
                "digest": provenance_digest_map(manifest_digest),
            },
            {
                "name": format!("aos:package-measurement:{name}:{version}:{platform}"),
                "digest": provenance_digest_map(measurement),
            },
        ],
        "predicateType": PACKAGE_PROVENANCE_PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": PACKAGE_PROVENANCE_BUILD_TYPE,
                "externalParameters": external_parameters,
                "internalParameters": {},
                "resolvedDependencies": resolved_dependencies,
            },
            "runDetails": {
                "builder": {
                    "id": provenance_builder_id(registry_name, key_id),
                },
                "metadata": {
                    "invocationId": format!("apr-publish:{name}:{version}:{platform}"),
                },
            },
        },
    }))
}

fn publish_provenance_ref(name: &str, platform: &str, measurement: &str) -> Result<String> {
    validate_package_name(name)?;
    validate_platform_name(platform)?;
    let measurement_hex = sha256_hex_payload(measurement).with_context(|| {
        format!("package measurement must be a sha256 digest with 64 hex characters: {measurement}")
    })?;
    Ok(format!(
        "provenance/{}/{name}/{platform}/{measurement_hex}.intoto.jsonl",
        package_name_bucket(name)
    ))
}

fn package_platform_table(
    name: &str,
    version: &str,
    platform: &str,
    info: &StorePathInfo,
    image_infos: &[PublishedImage],
    source_drv: &str,
    source_nar_hash: &str,
    expose_manifest: Option<&PublishExposeManifest>,
    expose_artifact_info: Option<&StorePathInfo>,
    expose_manifest_digest: Option<&str>,
) -> Result<toml::Value> {
    let mut table = toml::map::Map::new();
    table.insert("store_path".into(), toml::Value::String(info.path.clone()));
    // No nar_hash/nar_size/references here: the output's content binding and
    // dependency edges live in the store/ realisation graph (RFC-0005), the
    // single authority. Sources and images keep their hashes below - they sit
    // outside the runtime closure the graph covers.
    table.insert(
        "closure_size".into(),
        toml::Value::Integer(info.closure_size as i64),
    );
    table.insert(
        "source_drv".into(),
        toml::Value::String(source_drv.to_string()),
    );
    table.insert(
        "source_nar_hash".into(),
        toml::Value::String(source_nar_hash.to_string()),
    );

    if !image_infos.is_empty() {
        let mut formats = HashSet::new();
        let first = &image_infos[0];
        for image in image_infos {
            image.recheck_for_commit()?;
            if !formats.insert(image.format.as_str()) {
                bail!(
                    "duplicate '{}' image encoding in one platform publication",
                    image.format
                );
            }
            if image.delivery.logical_image_id != first.delivery.logical_image_id
                || image.delivery.uki != first.delivery.uki
                || image.sb.signer_cert_sha256 != first.sb.signer_cert_sha256
                || image.sb.sbat != first.sb.sbat
                || image.sb.expected_pcr11 != first.sb.expected_pcr11
            {
                bail!(
                    "all image encodings in one platform publication must share one logical disk and UKI identity"
                );
            }
        }
        let images = image_infos
            .iter()
            .map(|image| {
                let mut entry = toml::map::Map::new();
                entry.insert("format".into(), toml::Value::String(image.format.clone()));
                entry.insert(
                    "store_path".into(),
                    toml::Value::String(image.store.path.clone()),
                );
                entry.insert(
                    "nar_hash".into(),
                    toml::Value::String(image.store.nar_hash.clone()),
                );
                let nar_size = i64::try_from(image.store.nar_size)
                    .context("image NAR size exceeds signed TOML integer range")?;
                entry.insert("nar_size".into(), toml::Value::Integer(nar_size));
                let delivery = toml::Value::try_from(&image.delivery)
                    .context("serializing image delivery contract")?;
                entry.insert("delivery".into(), delivery);
                if let Some(cert) = &image.sb.signer_cert_sha256 {
                    entry.insert(
                        "sb_signer_cert_sha256".into(),
                        toml::Value::String(cert.clone()),
                    );
                }
                if !image.sb.sbat.is_empty() {
                    let sbat = image
                        .sb
                        .sbat
                        .iter()
                        .map(|item| {
                            let mut row = toml::map::Map::new();
                            row.insert(
                                "component".into(),
                                toml::Value::String(item.component.clone()),
                            );
                            row.insert(
                                "generation".into(),
                                toml::Value::Integer(i64::from(item.generation)),
                            );
                            toml::Value::Table(row)
                        })
                        .collect::<Vec<_>>();
                    entry.insert("sbat".into(), toml::Value::Array(sbat));
                }
                if let Some(pcr11) = &image.sb.expected_pcr11 {
                    entry.insert("expected_pcr11".into(), toml::Value::String(pcr11.clone()));
                }
                if !image.sb.ukis.is_empty() {
                    entry.insert(
                        "ukis".into(),
                        toml::Value::try_from(&image.sb.ukis)
                            .context("serializing slot-specific UKI facts")?,
                    );
                }
                if !image.sb.recovery_ukis.is_empty() {
                    entry.insert(
                        "recovery_ukis".into(),
                        toml::Value::try_from(&image.sb.recovery_ukis)
                            .context("serializing recovery UKI facts")?,
                    );
                }
                if let Some(bundle) = &image.sb.recovery_bundle {
                    entry.insert(
                        "recovery_bundle".into(),
                        toml::Value::try_from(bundle)
                            .context("serializing recovery bundle manifest")?,
                    );
                }
                let root_image = image.directory.path.join("root.img");
                let root_verity = image.directory.path.join("root.verity");
                let root_hash = image.directory.path.join("root.roothash");
                let root_hash_sig = image.directory.path.join("root.roothash.p7s");
                // Recovery UKIs are only valid with the complete A/B verity
                // payload, including when its distributable disk encoding is
                // `raw`. Ordinary raw disk images may contain unrelated files
                // with these names and must not acquire a verity contract.
                let catalogs_verity =
                    matches!(image.format.as_str(), "ext4-verity" | "erofs-verity")
                        || !image.sb.recovery_ukis.is_empty();
                if catalogs_verity {
                    let verity_count = [&root_image, &root_verity, &root_hash, &root_hash_sig]
                        .iter()
                        .filter(|path| path.is_file())
                        .count();
                    if verity_count != 4 {
                        bail!("published image has an incomplete dm-verity artifact set");
                    }

                    let hash = fs::read_to_string(&root_hash)?;
                    let hash = hash.trim();
                    if hash.len() != 64
                        || !hash
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    {
                        bail!("published image has a malformed root.roothash");
                    }
                    entry.insert("root_image".into(), toml::Value::String("root.img".into()));
                    entry.insert(
                        "root_verity".into(),
                        toml::Value::String("root.verity".into()),
                    );
                    entry.insert(
                        "root_hash".into(),
                        toml::Value::String(format!("sha256:{hash}")),
                    );
                    entry.insert(
                        "root_hash_sig".into(),
                        toml::Value::String("root.roothash.p7s".into()),
                    );
                }
                Ok(toml::Value::Table(entry))
            })
            .collect::<Result<Vec<_>>>()?;
        table.insert("images".into(), toml::Value::Array(images));
        if image_infos.iter().any(|image| !image.sb.ukis.is_empty()) {
            let feature = toml::Value::String(FEATURE_UKI_SLOTS_V1.to_string());
            let features = table
                .entry("requires-features")
                .or_insert_with(|| toml::Value::Array(Vec::new()))
                .as_array_mut()
                .context("platform requires-features metadata is not an array")?;
            if !features.contains(&feature) {
                features.push(feature);
            }
            table.insert(
                "min-format".into(),
                toml::Value::Integer(i64::from(PACKAGE_META_FORMAT)),
            );
        }
        if image_infos
            .iter()
            .any(|image| !image.sb.recovery_ukis.is_empty())
        {
            let feature = toml::Value::String(FEATURE_RECOVERY_UKIS_V1.to_string());
            let features = table
                .entry("requires-features")
                .or_insert_with(|| toml::Value::Array(Vec::new()))
                .as_array_mut()
                .context("platform requires-features metadata is not an array")?;
            if !features.contains(&feature) {
                features.push(feature);
            }
            table.insert(
                "min-format".into(),
                toml::Value::Integer(i64::from(PACKAGE_META_FORMAT)),
            );
        }
    }

    if let Some(manifest) = expose_manifest {
        let artifact = expose_artifact_info
            .context("expose manifest requires rendered expose artifact metadata")?;
        let attestation = publish_attestation_meta(
            name,
            version,
            platform,
            info,
            manifest,
            expose_manifest_digest,
        )
        .with_context(|| format!("deriving package attestation metadata for package '{name}'"))?;
        table.insert(
            "min-format".into(),
            toml::Value::Integer(i64::from(PACKAGE_META_FORMAT)),
        );
        let mut required_features = vec![
            toml::Value::String(FEATURE_EXPOSE_V1.to_string()),
            toml::Value::String(FEATURE_EXPOSE_ARTIFACT_V1.to_string()),
            toml::Value::String(FEATURE_PERMISSIONS_V1.to_string()),
            toml::Value::String(FEATURE_NETWORK_POLICY_V1.to_string()),
        ];
        if !manifest.expose.requires.is_empty() {
            required_features.push(toml::Value::String(FEATURE_REQUIRES_V1.to_string()));
        }
        if !manifest.expose.config.is_empty() {
            required_features.push(toml::Value::String(FEATURE_CONFIG_V1.to_string()));
        }
        if manifest.expose.config.has_optional_credentials() {
            required_features.push(toml::Value::String(
                FEATURE_OPTIONAL_CREDENTIALS_V1.to_string(),
            ));
        }
        if manifest.expose.config.has_unit_reconciliation() {
            required_features.push(toml::Value::String(FEATURE_RELOAD_V1.to_string()));
        }
        if !manifest.expose.provides.is_empty() || !manifest.expose.uses.is_empty() {
            required_features.push(toml::Value::String(
                FEATURE_CAPABILITY_ROUTES_V1.to_string(),
            ));
        }
        let ebpf_unit = format!("aos-pkg-{name}-ebpf.service");
        if manifest.expose.units.iter().any(|unit| unit == &ebpf_unit) {
            required_features.push(toml::Value::String(FEATURE_EBPF_NET_POLICY_V1.to_string()));
        }
        if manifest.mac.is_some() {
            required_features.push(toml::Value::String(FEATURE_MAC_PROFILE_V1.to_string()));
        }
        if attestation.is_some() {
            required_features.push(toml::Value::String(FEATURE_ATTESTATION_V1.to_string()));
        }
        table.insert(
            "requires-features".into(),
            toml::Value::Array(required_features.clone()),
        );
        let mut references = toml::map::Map::new();
        references.insert("hashes".into(), toml::Value::Array(Vec::new()));
        references.insert(
            "min-format".into(),
            toml::Value::Integer(i64::from(PACKAGE_META_FORMAT)),
        );
        references.insert(
            "requires-features".into(),
            toml::Value::Array(required_features.clone()),
        );
        table.insert("references".into(), toml::Value::Table(references));
        table.insert(
            "expose".into(),
            toml::Value::try_from(&manifest.expose)
                .context("serializing expose manifest metadata")?,
        );
        let artifact = ExposeArtifactMeta {
            store_path: artifact.path.clone(),
            nar_hash: artifact.nar_hash.clone(),
            nar_size: artifact.nar_size,
        };
        validate_expose_artifact_meta(&artifact)?;
        table.insert(
            "expose_artifact".into(),
            toml::Value::try_from(&artifact).context("serializing expose artifact metadata")?,
        );
        table.insert(
            "permissions".into(),
            toml::Value::try_from(&manifest.permissions)
                .context("serializing permissions manifest metadata")?,
        );
        if let Some(attestation) = attestation {
            if let Some(root_digest) = attestation.root_digest {
                table.insert("root_digest".into(), toml::Value::String(root_digest));
            }
            if let Some(root_hash) = attestation.root_hash {
                table.insert("root_hash".into(), toml::Value::String(root_hash));
            }
            if let Some(root_hash_sig) = attestation.root_hash_sig {
                table.insert("root_hash_sig".into(), toml::Value::String(root_hash_sig));
            }
            if let Some(provenance) = attestation.provenance {
                table.insert("provenance".into(), toml::Value::String(provenance));
            }
            table.insert(
                "measurement".into(),
                toml::Value::String(
                    attestation
                        .measurement
                        .context("package attestation measurement missing")?,
                ),
            );
        }
    }

    Ok(toml::Value::Table(table))
}

fn record_documentation_platform_fields(
    table: &mut toml::map::Map<String, toml::Value>,
    documentation: &DocumentationArtifactMeta,
) -> Result<()> {
    validate_documentation_artifact_meta(documentation)
        .context("validating package documentation metadata for publish")?;
    let feature = toml::Value::String(FEATURE_PACKAGE_DOCUMENTATION_V1.to_string());
    let features = table
        .entry("requires-features")
        .or_insert_with(|| toml::Value::Array(Vec::new()))
        .as_array_mut()
        .context("platform requires-features metadata is not an array")?;
    if !features.contains(&feature) {
        features.push(feature.clone());
    }
    table.insert(
        "min-format".into(),
        toml::Value::Integer(i64::from(PACKAGE_META_FORMAT)),
    );

    let references = table
        .entry("references")
        .or_insert_with(|| {
            let mut references = toml::map::Map::new();
            references.insert("hashes".into(), toml::Value::Array(Vec::new()));
            toml::Value::Table(references)
        })
        .as_table_mut()
        .context("platform references metadata is not a table")?;
    references.insert(
        "min-format".into(),
        toml::Value::Integer(i64::from(PACKAGE_META_FORMAT)),
    );
    let reference_features = references
        .entry("requires-features")
        .or_insert_with(|| toml::Value::Array(Vec::new()))
        .as_array_mut()
        .context("platform references requires-features metadata is not an array")?;
    if !reference_features.contains(&feature) {
        reference_features.push(feature);
    }
    table.insert(
        "documentation".into(),
        toml::Value::try_from(documentation)
            .context("serializing package documentation metadata")?,
    );
    Ok(())
}

/// Records a `config_module` block and its fail-closed format gates.
///
/// # Errors
///
/// Returns an error when the package name or `module` metadata is malformed,
/// including when a declaration escapes the package's private, owned, and
/// contributed roots, or when TOML serialization fails.
pub(crate) fn record_config_module_platform_fields(
    table: &mut toml::map::Map<String, toml::Value>,
    package_name: &str,
    module: &ConfigModuleMeta,
) -> Result<()> {
    validate_config_module_meta(package_name, module)
        .context("validating config-module metadata for publish")?;
    let feature = toml::Value::String(FEATURE_CONFIG_MODULE_V1.to_string());
    let required_features_value = table
        .entry("requires-features")
        .or_insert_with(|| toml::Value::Array(Vec::new()));
    let required_features = required_features_value
        .as_array_mut()
        .context("platform requires-features metadata is not an array")?;
    if !required_features.contains(&feature) {
        required_features.push(feature.clone());
    }
    table.insert(
        "min-format".into(),
        toml::Value::Integer(i64::from(PACKAGE_META_FORMAT)),
    );
    let references_value = table.entry("references").or_insert_with(|| {
        let mut references = toml::map::Map::new();
        references.insert("hashes".into(), toml::Value::Array(Vec::new()));
        toml::Value::Table(references)
    });
    let references = references_value
        .as_table_mut()
        .context("platform references metadata is not a table")?;
    references.insert(
        "min-format".into(),
        toml::Value::Integer(i64::from(PACKAGE_META_FORMAT)),
    );
    let reference_features_value = references
        .entry("requires-features")
        .or_insert_with(|| toml::Value::Array(Vec::new()));
    let reference_features = reference_features_value
        .as_array_mut()
        .context("platform references requires-features metadata is not an array")?;
    if !reference_features.contains(&feature) {
        reference_features.push(feature);
    }
    table.insert(
        "config_module".into(),
        toml::Value::try_from(module).context("serializing config-module metadata")?,
    );
    Ok(())
}

fn record_attestation_platform_fields(
    table: &mut toml::map::Map<String, toml::Value>,
    attestation: &AttestationMeta,
) -> Result<()> {
    validate_attestation_meta(attestation)?;
    let feature = toml::Value::String(FEATURE_ATTESTATION_V1.to_string());
    for key in ["requires-features"] {
        let features = table
            .entry(key)
            .or_insert_with(|| toml::Value::Array(Vec::new()))
            .as_array_mut()
            .with_context(|| format!("platform {key} metadata is not an array"))?;
        if !features.contains(&feature) {
            features.push(feature.clone());
        }
    }
    let references = table
        .get_mut("references")
        .and_then(toml::Value::as_table_mut)
        .context("config-module platform is missing structural references metadata")?;
    let reference_features = references
        .entry("requires-features")
        .or_insert_with(|| toml::Value::Array(Vec::new()))
        .as_array_mut()
        .context("platform references requires-features metadata is not an array")?;
    if !reference_features.contains(&feature) {
        reference_features.push(feature);
    }
    if let Some(root_digest) = &attestation.root_digest {
        table.insert(
            "root_digest".into(),
            toml::Value::String(root_digest.clone()),
        );
    }
    if let Some(root_hash) = &attestation.root_hash {
        table.insert("root_hash".into(), toml::Value::String(root_hash.clone()));
    }
    if let Some(root_hash_sig) = &attestation.root_hash_sig {
        table.insert(
            "root_hash_sig".into(),
            toml::Value::String(root_hash_sig.clone()),
        );
    }
    table.insert(
        "provenance".into(),
        toml::Value::String(
            attestation
                .provenance
                .clone()
                .context("config-module attestation is missing provenance")?,
        ),
    );
    table.insert(
        "measurement".into(),
        toml::Value::String(
            attestation
                .measurement
                .clone()
                .context("config-module attestation is missing measurement")?,
        ),
    );
    Ok(())
}

/// `apr unpublish <PACKAGE> [VERSION]` — removes package metadata from the
/// registry.
///
/// With neither a version nor `--platform`, the whole package file is
/// deleted. With a version (and optionally a platform) only the matching
/// entries are removed; specifying only `--platform` removes that platform
/// from every version. The file is deleted once no versions remain.
/// Unless `--no-commit` is set, the change is committed (SSH-signed when
/// `--key`/`--key-id` is given) and the dumb-HTTP object store is
/// refreshed. Closure files are left in place.
///
/// # Errors
///
/// Fails when the package name is not safe for registry package paths, when
/// the package, the requested version, or the requested platform does not
/// exist in the registry, or when a file write, the commit, or the
/// object-store refresh fails.
#[allow(clippy::too_many_arguments)]
pub async fn unpublish(
    config: &ApmConfig,
    package: &str,
    version: Option<&str>,
    platform: Option<&str>,
    no_commit: bool,
    message: Option<&str>,
    key: Option<&str>,
    key_id: Option<&str>,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    validate_package_name(package)?;
    let dir = registry_dir(config, registry)?;
    let registry_name = resolve_registry_name(config, registry)?;
    let signing_key = if key.is_some() || key_id.is_some() {
        Some(resolve_producer_signing_key(
            config,
            &dir,
            &registry_name,
            key,
            key_id,
        )?)
    } else {
        None
    };
    let _publish_lock = RegistryPublishLock::acquire(&dir)?;
    let letter = first_letter(package);
    let toml_path = dir
        .join("packages")
        .join(&letter)
        .join(format!("{package}.toml"));

    if !toml_path.exists() {
        bail!("package '{package}' not found in registry");
    }

    let mut package_file_removed = false;
    let mut status = "updated";
    if version.is_none() && platform.is_none() {
        // Remove the entire file.
        std::fs::remove_file(&toml_path)?;
        package_file_removed = true;
        status = "removed";
        printer.info(&format!("Removed package '{package}' entirely."));
    } else {
        // Parse and selectively remove.
        let content = std::fs::read_to_string(&toml_path)?;
        let mut toml_val: toml::Value = toml::from_str(&content)?;

        if let Some(versions) = toml_val.get_mut("versions").and_then(|v| v.as_array_mut()) {
            if let Some(ver) = version {
                let idx = versions
                    .iter()
                    .position(|v| v.get("version").and_then(|s| s.as_str()) == Some(ver))
                    .ok_or_else(|| {
                        anyhow::anyhow!("package '{package}' does not contain version '{ver}'")
                    })?;
                if let Some(plat) = platform {
                    // Remove specific platform from specific version.
                    let remove_version = {
                        let platforms = versions[idx]
                            .as_table_mut()
                            .and_then(|t| t.get_mut("platforms"))
                            .and_then(|p| p.as_table_mut())
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "package '{package}' version '{ver}' has no platform entries"
                                )
                            })?;
                        if !platforms.contains_key(plat) {
                            bail!(
                                "package '{package}' version '{ver}' does not contain platform '{plat}'"
                            );
                        }
                        platforms.remove(plat);
                        platforms.is_empty()
                    };
                    if remove_version {
                        versions.remove(idx);
                    }
                } else {
                    // Remove entire version.
                    versions.remove(idx);
                }
            } else if let Some(plat) = platform {
                // Remove platform from all versions.
                let mut removed = false;
                for ver in versions.iter_mut() {
                    if let Some(platforms) = ver
                        .as_table_mut()
                        .and_then(|t| t.get_mut("platforms"))
                        .and_then(|p| p.as_table_mut())
                    {
                        removed |= platforms.remove(plat).is_some();
                    }
                }
                if !removed {
                    bail!("package '{package}' does not contain platform '{plat}'");
                }
                // Remove empty versions.
                versions.retain(|v| {
                    v.get("platforms")
                        .and_then(|p| p.as_table())
                        .map(|t| !t.is_empty())
                        .unwrap_or(false)
                });
            }

            if versions.is_empty() {
                std::fs::remove_file(&toml_path)?;
                package_file_removed = true;
                status = "removed";
                printer.info(&format!(
                    "Removed package '{package}' (no versions remaining)."
                ));
            } else {
                std::fs::write(&toml_path, toml::to_string_pretty(&toml_val)?)?;
                printer.info(&format!("Updated package '{package}'."));
            }
        }
    }

    let mut committed = false;
    let mut commit_message = None;
    if !no_commit {
        let default_msg = format!("unpublish {package}");
        let msg = message.unwrap_or(&default_msg);
        commit_registry(&dir, msg, signing_key.as_ref().map(|k| k.path()))?;
        refresh_registry_object_store(&dir)
            .context("refreshing dumb-HTTP object store after unpublish")?;
        committed = true;
        commit_message = Some(msg.to_string());
        printer.success(&format!("Committed: {msg}"));
    }

    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "action": "unpublish",
            "registry": registry_name,
            "package": package,
            "version": version,
            "platform": platform,
            "status": status,
            "package_file": toml_path
                .strip_prefix(&dir)
                .unwrap_or(&toml_path)
                .display()
                .to_string(),
            "package_file_removed": package_file_removed,
            "committed": committed,
            "commit_message": commit_message,
            "current": current_git_branch(&dir)?,
            "head": current_git_head(&dir)?,
            "branches": git_branch_entries(&dir)?,
        }));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Registry Query
// ---------------------------------------------------------------------------

fn selected_package_versions(
    toml_val: &toml::Value,
    version: Option<&str>,
) -> Result<Vec<toml::Value>> {
    let versions = matching_package_versions(toml_val, None);
    let Some(version) = version else {
        return Ok(versions);
    };

    let selected = versions
        .into_iter()
        .filter(|entry| entry.get("version").and_then(|v| v.as_str()) == Some(version))
        .collect::<Vec<_>>();
    if selected.is_empty() {
        bail!("package does not contain version '{version}'");
    }
    Ok(selected)
}

fn matching_package_versions(toml_val: &toml::Value, platform: Option<&str>) -> Vec<toml::Value> {
    let Some(versions) = toml_val.get("versions").and_then(|v| v.as_array()) else {
        return Vec::new();
    };

    versions
        .iter()
        .filter(|entry| version_has_platform(entry, platform))
        .cloned()
        .collect()
}

fn version_has_platform(entry: &toml::Value, platform: Option<&str>) -> bool {
    let Some(platform) = platform else {
        return true;
    };
    entry
        .get("platforms")
        .and_then(|platforms| platforms.as_table())
        .map(|platforms| platforms.contains_key(platform))
        .unwrap_or(false)
}

fn latest_version_string(versions: &[toml::Value]) -> Option<String> {
    versions
        .iter()
        .filter_map(|entry| entry.get("version").and_then(|version| version.as_str()))
        .max_by(|left, right| compare_registry_versions(left, right))
        .map(ToString::to_string)
}

/// Order version strings semver-first: a parsable semver always beats a
/// non-semver string, and two non-semver strings fall back to lexicographic
/// comparison.
fn compare_registry_versions(left: &str, right: &str) -> std::cmp::Ordering {
    match (semver::Version::parse(left), semver::Version::parse(right)) {
        (Ok(left), Ok(right)) => left.cmp(&right),
        (Ok(_), Err(_)) => std::cmp::Ordering::Greater,
        (Err(_), Ok(_)) => std::cmp::Ordering::Less,
        (Err(_), Err(_)) => left.cmp(right),
    }
}

fn package_toml_with_versions(
    toml_val: &toml::Value,
    versions: &[toml::Value],
) -> Result<toml::Value> {
    let mut filtered = toml_val.clone();
    let Some(root) = filtered.as_table_mut() else {
        bail!("package TOML root is not a table");
    };
    root.insert(
        "versions".to_string(),
        toml::Value::Array(versions.to_vec()),
    );
    Ok(filtered)
}

/// `apr show <PACKAGE>` — prints a package's registry metadata.
///
/// Shows the `[package]` header fields plus each version's per-platform
/// store paths, NAR sizes, and image artifacts. A version argument filters
/// the output to that version; `--raw` prints the package TOML verbatim
/// instead of the formatted view.
///
/// # Errors
///
/// Fails when the package name is not safe for registry package paths, when
/// the package file does not exist in the registry, cannot be parsed, or
/// does not contain the requested version.
pub async fn show(
    config: &ApmConfig,
    package: &str,
    version: Option<&str>,
    raw: bool,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    validate_package_name(package)?;
    let dir = registry_dir(config, registry)?;
    let letter = first_letter(package);
    let toml_path = dir
        .join("packages")
        .join(&letter)
        .join(format!("{package}.toml"));

    if !toml_path.exists() {
        bail!("package '{package}' not found in registry");
    }

    let content = std::fs::read_to_string(&toml_path)?;
    let toml_val: toml::Value = toml::from_str(&content)?;
    let selected_versions = selected_package_versions(&toml_val, version)?;

    if printer.mode() == OutputMode::Json {
        let value = if version.is_some() {
            package_toml_with_versions(&toml_val, &selected_versions)?
        } else {
            toml_val.clone()
        };
        printer.json(&serde_json::to_value(&value)?);
        return Ok(());
    }

    if raw {
        if version.is_some() {
            let filtered = package_toml_with_versions(&toml_val, &selected_versions)?;
            printer.plain(&toml::to_string_pretty(&filtered)?);
        } else {
            printer.plain(&content);
        }
    } else {
        if let Some(pkg) = toml_val.get("package") {
            if let Some(name) = pkg.get("name").and_then(|v| v.as_str()) {
                printer.header(&format!("Package: {name}"));
            }
            if let Some(desc) = pkg.get("description").and_then(|v| v.as_str()) {
                printer.kv("Description", desc);
            }
            if pkg
                .get("sysroot")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                printer.kv("Sysroot", "yes");
            }
            if let Some(hp) = pkg.get("homepage").and_then(|v| v.as_str()) {
                printer.kv("Homepage", hp);
            }
            if let Some(lic) = pkg.get("license").and_then(|v| v.as_str()) {
                printer.kv("License", lic);
            }
            if let Some(maint) = pkg.get("maintainer").and_then(|v| v.as_str()) {
                printer.kv("Maintainer", maint);
            }
        }
        for ver in &selected_versions {
            if let Some(v) = ver.get("version").and_then(|v| v.as_str()) {
                printer.kv("Version", v);
            }
            if let Some(prev) = ver.get("previous").and_then(|v| v.as_str()) {
                printer.kv("Previous", prev);
            }
            if let Some(platforms) = ver.get("platforms").and_then(|v| v.as_table()) {
                for (plat, entry) in platforms {
                    printer.kv(&format!("  {plat}"), "");
                    if let Some(sp) = entry.get("store_path").and_then(|v| v.as_str()) {
                        printer.kv("    Store path", sp);
                    }
                    if let Some(ns) = entry.get("nar_size").and_then(|v| v.as_integer()) {
                        printer.kv("    NAR size", &format_size(ns as u64));
                    }
                    if let Some(images) = entry.get("images").and_then(|v| v.as_array()) {
                        for img in images {
                            if let Some(fmt) = img.get("format").and_then(|v| v.as_str()) {
                                let img_path = img
                                    .get("store_path")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("?");
                                let img_size = img
                                    .get("nar_size")
                                    .and_then(|v| v.as_integer())
                                    .unwrap_or(0);
                                printer.kv(
                                    &format!("    Image ({fmt})"),
                                    &format!("{img_path} ({})", format_size(img_size as u64)),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// `apr packages` — lists every package in the registry with its latest
/// version.
///
/// `--platform` restricts the version selection to versions published for
/// that platform; `--outdated` shows only packages that carry more than
/// one matching version (i.e. that have superseded entries).
///
/// # Errors
///
/// Fails when the registry cannot be resolved or a package metadata file
/// cannot be read or parsed.
pub async fn packages(
    config: &ApmConfig,
    platform: Option<&str>,
    outdated: bool,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let dir = registry_dir(config, registry)?;
    let packages_dir = dir.join("packages");

    if !packages_dir.is_dir() {
        if printer.mode() == OutputMode::Json {
            printer.json(&serde_json::json!([]));
            return Ok(());
        }
        printer.info("No packages found.");
        return Ok(());
    }

    let mut pkgs = Vec::new();
    for letter_entry in std::fs::read_dir(&packages_dir)?.flatten() {
        if !letter_entry.path().is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(letter_entry.path())?.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "toml").unwrap_or(false) {
                let content = std::fs::read_to_string(&path)?;
                let name = crate::registry::parse::validate_package_file_layout(&path, &content)
                    .with_context(|| format!("validating {}", path.display()))?;
                let toml_val: toml::Value = toml::from_str(&content)?;
                let versions = matching_package_versions(&toml_val, platform);
                if outdated && versions.len() < 2 {
                    continue;
                }
                let Some(version) = latest_version_string(&versions) else {
                    continue;
                };
                pkgs.push((name, version));
            }
        }
    }

    pkgs.sort();

    if printer.mode() == OutputMode::Json {
        let packages_json = pkgs
            .iter()
            .map(|(name, version)| {
                serde_json::json!({
                    "name": name,
                    "version": version,
                })
            })
            .collect::<Vec<_>>();
        printer.json(&serde_json::json!(packages_json));
        return Ok(());
    }

    if pkgs.is_empty() {
        printer.info("No packages found.");
    } else {
        printer.header(&format!("{} packages:", pkgs.len()));
        for (name, version) in &pkgs {
            printer.plain(&format!("  {name} {version}"));
        }
    }

    Ok(())
}

/// One published store path discovered while scanning package TOMLs for
/// `apr verify`.
#[derive(Debug, Clone)]
struct RegistryVerifyStoreEntry {
    store_hash: String,
    store_path: String,
    package_name: String,
}

/// `apr verify` — checks registry-internal metadata consistency.
///
/// Verifies that every package TOML parses and has a `[package]` section,
/// that every published store path has a closure file whose first line is
/// the root hash, that all direct references recorded in the package TOML
/// appear in the closure, and that the closure adjacency list is
/// internally closed (members only reference other members). With `--fix`,
/// closure files are regenerated from the local Nix store before checking,
/// which requires the published store paths to be present locally.
///
/// # Errors
///
/// Fails when a `--package` filter is not a safe package name or matches no
/// package, when `--fix` cannot recompute a closure, or when any
/// verification error was found.
pub async fn verify(
    config: &ApmConfig,
    package: Option<&str>,
    fix: bool,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let registry_name = resolve_registry_name(config, registry)?;
    let dir = config.scope.registries_path().join(&registry_name);
    let packages_dir = dir.join("packages");
    if let Some(package) = package {
        validate_package_name(package)?;
    }

    let mut errors = 0u32;
    let mut checked = 0u32;
    let mut repaired = 0u32;

    // Collect all store path hashes from package TOMLs.
    let mut all_store_entries: Vec<RegistryVerifyStoreEntry> = Vec::new();
    let mut matched_package_filter = package.is_none();

    // Verify package TOML files.
    if packages_dir.is_dir() {
        for letter_entry in std::fs::read_dir(&packages_dir)?.flatten() {
            if !letter_entry.path().is_dir() {
                continue;
            }
            for entry in std::fs::read_dir(letter_entry.path())?.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "toml").unwrap_or(false) {
                    let path_matches_filter = match package {
                        Some(filter) => {
                            path.file_stem().and_then(|stem| stem.to_str()) == Some(filter)
                        }
                        None => true,
                    };
                    if !path_matches_filter {
                        continue;
                    }
                    matched_package_filter = true;
                    checked += 1;
                    let content = std::fs::read_to_string(&path)?;
                    match toml::from_str::<toml::Value>(&content) {
                        Ok(val) => {
                            if val.get("package").is_none() {
                                printer.warning(&format!(
                                    "{}: missing [package] section",
                                    path.display()
                                ));
                                errors += 1;
                                continue;
                            }
                            let pkg_name =
                                match crate::registry::parse::validate_package_file_layout(
                                    &path, &content,
                                ) {
                                    Ok(name) => name,
                                    Err(e) => {
                                        printer.warning(&format!("{}: {e}", path.display()));
                                        errors += 1;
                                        continue;
                                    }
                                };
                            // Extract store hashes from all version/platform entries.
                            if let Some(versions) = val.get("versions").and_then(|v| v.as_array()) {
                                for ver in versions {
                                    if let Some(platforms) =
                                        ver.get("platforms").and_then(|p| p.as_table())
                                    {
                                        for (_plat, plat_val) in platforms {
                                            if let Some(sp) =
                                                plat_val.get("store_path").and_then(|s| s.as_str())
                                            {
                                                let hash = extract_hash(sp).to_string();
                                                all_store_entries.push(RegistryVerifyStoreEntry {
                                                    store_hash: hash.clone(),
                                                    store_path: sp.to_string(),
                                                    package_name: pkg_name.clone(),
                                                });
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            printer.error(&format!("{}: {e}", path.display()));
                            errors += 1;
                        }
                    }
                }
            }
        }
    }

    if let Some(filter) = package {
        if !matched_package_filter {
            bail!("package '{filter}' not found in registry");
        }
    }

    if fix {
        let content_addressed = registry_content_addressed(&dir);
        let mut seen = HashSet::new();
        for entry in &all_store_entries {
            if seen.insert(entry.store_hash.clone()) {
                write_store_files(&dir, &entry.store_path, content_addressed, false, printer)
                    .with_context(|| {
                        format!(
                            "regenerating store/ records for {} ({})",
                            entry.package_name, entry.store_path
                        )
                    })?;
                repaired += 1;
            }
        }
        if repaired > 0 {
            printer.success(&format!(
                "Regenerated store/ records for {repaired} package(s)."
            ));
        }
    }

    // The store/ realisation graph, for coverage checks below (RFC-0005). A
    // malformed graph is an error; an absent one downgrades to a warning
    // (legacy registry - consumers fall back to unauthenticated narinfo).
    let store_graph = match StoreMap::load(&dir) {
        Ok(map) => {
            if !map.is_present() {
                printer.warning(
                    "registry publishes no store/ realisation graph; consumer NAR \
                     verification falls back to unauthenticated narinfo hashes",
                );
            }
            map
        }
        Err(e) => {
            printer.error(&format!("store/ graph failed to load: {e:#}"));
            errors += 1;
            StoreMap::default()
        }
    };

    // Verify graph coverage: every package root and every member reachable
    // from it via dependency edges must have a record with a blessed NAR.
    let mut roots_checked = 0u32;
    if store_graph.is_present() {
        for entry in &all_store_entries {
            let pkg_name = &entry.package_name;
            roots_checked += 1;
            let mut seen = HashSet::new();
            let mut stack = vec![entry.store_hash.clone()];
            while let Some(hash) = stack.pop() {
                if !seen.insert(hash.clone()) {
                    continue;
                }
                match store_graph.get(&hash) {
                    None => {
                        printer.warning(&format!(
                            "{pkg_name}: closure member {hash} has no store/ record \
                             (run `apr store backfill` or `apr verify --fix`)"
                        ));
                        errors += 1;
                    }
                    Some(record) if record.blessed_nars().is_empty() => {
                        printer.warning(&format!(
                            "{pkg_name}: store/ record {hash} has no blessed NAR"
                        ));
                        errors += 1;
                    }
                    Some(_) => {
                        stack.extend(store_graph.direct_deps(&hash));
                    }
                }
            }
        }
    }

    if errors == 0 {
        if printer.mode() == OutputMode::Json {
            printer.json(&serde_json::json!({
                "action": "verify",
                "status": "ok",
                "registry": registry_name,
                "package": package,
                "fix": fix,
                "checked": checked,
                "roots": roots_checked,
                "repaired": repaired,
                "errors": 0,
            }));
        } else {
            printer.success(&format!(
                "Verified {checked} package(s), {roots_checked} closure root(s), no errors."
            ));
        }
    } else {
        printer.error(&format!(
            "Verified {checked} package(s), {roots_checked} closure root(s), {errors} error(s) found."
        ));
        bail!("registry verification failed with {errors} error(s)");
    }

    Ok(())
}

/// `apr diff` — shows pending changes in the registry clone.
///
/// By default diffs the working tree against the index and lists untracked
/// files, so newly-published package metadata appears in the maintainer's
/// changeset before it has been staged. With `--remote`, diffs the remote
/// tracking base (the configured upstream, then `origin/<current-branch>`,
/// then `origin/HEAD`) against `HEAD`, showing committed work that has not
/// been pushed. `--stat` prints a diffstat instead of the patch.
///
/// # Errors
///
/// Fails when `--remote` is given but no remote tracking ref can be
/// determined, or when git fails.
pub async fn diff(
    config: &ApmConfig,
    stat: bool,
    remote: bool,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let dir = registry_dir(config, registry)?;

    if remote {
        let base = remote_diff_base(&dir)?;
        let mut args = vec!["diff", &base, "HEAD"];
        if stat {
            args.push("--stat");
        }
        let output = git(&dir, &args)?;
        // `clean` must come from the name-status entries, not `output`: with
        // `--stat`, libgit2's diffstat emits a `0 files changed, ...` summary
        // line even when nothing changed, so `output.is_empty()` is never true
        // for a stat diff and would wrongly report a clean tree as dirty.
        let changed_files = diff_name_status_entries(&dir, Some((&base, "HEAD")))?;
        let clean = changed_files.is_empty();
        if printer.mode() == OutputMode::Json {
            printer.json(&serde_json::json!({
                "remote": true,
                "base": base,
                "stat": stat,
                "clean": clean,
                "changed_files": changed_files,
                "output": output,
            }));
            return Ok(());
        }
        if clean {
            printer.info("No pending changes.");
        } else {
            printer.plain(&output);
        }
    } else {
        let mut args = vec!["diff"];
        if stat {
            args.push("--stat");
        }
        let output = git(&dir, &args)?;
        let untracked = untracked_diff_entries(&dir)?;
        let clean = output.is_empty() && untracked.is_empty();
        let output = diff_output_with_untracked(output, &untracked);
        if printer.mode() == OutputMode::Json {
            printer.json(&serde_json::json!({
                "remote": false,
                "base": serde_json::Value::Null,
                "stat": stat,
                "clean": clean,
                "changed_files": diff_name_status_entries_with_untracked(&dir, &untracked)?,
                "output": output,
            }));
            return Ok(());
        }
        if output.is_empty() {
            printer.info("No pending changes.");
        } else {
            printer.plain(&output);
        }
    }

    Ok(())
}

/// Pick the remote ref `apr diff --remote` compares against: the
/// configured upstream first, then `origin/<current-branch>`, then
/// `origin/HEAD`.
fn remote_diff_base(dir: &Path) -> Result<String> {
    let (has_upstream, upstream, _) = git_try(
        dir,
        &[
            "rev-parse",
            "--abbrev-ref",
            "--symbolic-full-name",
            "@{upstream}",
        ],
    )?;
    if has_upstream && !upstream.is_empty() {
        return Ok(upstream);
    }

    let current_branch = git(dir, &["rev-parse", "--abbrev-ref", "HEAD"])?;
    if current_branch != "HEAD" {
        let remote_branch = format!("origin/{current_branch}");
        if git_ref_exists(dir, &remote_branch)? {
            return Ok(remote_branch);
        }
    }

    if git_ref_exists(dir, "origin/HEAD")? {
        return Ok("origin/HEAD".to_string());
    }

    bail!(
        "no remote tracking ref found for diff; push the current branch or set an upstream first"
    );
}

fn git_ref_exists(dir: &Path, reference: &str) -> Result<bool> {
    let (exists, _, _) = git_try(dir, &["rev-parse", "--verify", reference])?;
    Ok(exists)
}

fn untracked_diff_entries(dir: &Path) -> Result<Vec<String>> {
    let output = git(dir, &["ls-files", "--others", "--exclude-standard"])?;
    Ok(output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

fn diff_output_with_untracked(mut output: String, untracked: &[String]) -> String {
    if untracked.is_empty() {
        return output;
    }

    if !output.is_empty() {
        output.push('\n');
    }
    output.push_str("Untracked files:\n");
    for path in untracked {
        output.push_str("  A ");
        output.push_str(path);
        output.push('\n');
    }
    output.trim_end().to_string()
}

/// `apr validate` — checks that published artifacts are downloadable from
/// the registry's caches.
///
/// For every published store path and image artifact (optionally filtered
/// by `--package` and `--platform`), fetches the `.narinfo` from each
/// cache listed in `registry.toml`, cross-checks its store path and NAR
/// hash against the registry metadata, and probes the referenced NAR with
/// an HTTP `HEAD`. An entry counts as found when any cache passes all
/// checks. Requests run with up to `--jobs` in parallel. With `--fix`,
/// entries missing from every cache are pruned from the registry metadata
/// on disk (the prune is not committed).
///
/// # Errors
///
/// Fails when a `--package` filter is not a safe package name, when
/// `--jobs` is zero, when entries are missing and `--fix` was not given
/// (or pruned nothing), or when reading registry metadata or running the
/// validation tasks fails.
#[allow(clippy::too_many_arguments)]
pub async fn validate(
    config: &ApmConfig,
    package: Option<&str>,
    platform: Option<&str>,
    fix: bool,
    jobs: u32,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let dir = registry_dir(config, registry)?;
    let mirrors = resolve_mirrors(&dir);
    if let Some(package) = package {
        validate_package_name(package)?;
    }
    if jobs == 0 {
        bail!("--jobs must be greater than zero");
    }

    if mirrors.is_empty() {
        if printer.mode() == OutputMode::Json {
            printer.json(&serde_json::json!({
                "status": "no_caches",
                "package": package,
                "platform": platform,
                "fix": fix,
                "jobs": jobs,
                "caches": 0,
                "checked": 0,
                "found": 0,
                "missing": 0,
                "missing_entries": [],
                "removed": 0,
            }));
            return Ok(());
        }
        printer.warning("No caches configured in registry.toml. Cannot validate.");
        return Ok(());
    }

    let entries = collect_cache_validation_entries(&dir, package, platform)?;

    if entries.is_empty() {
        if printer.mode() == OutputMode::Json {
            printer.json(&serde_json::json!({
                "status": "no_entries",
                "package": package,
                "platform": platform,
                "fix": fix,
                "jobs": jobs,
                "caches": mirrors.len(),
                "checked": 0,
                "found": 0,
                "missing": 0,
                "missing_entries": [],
                "removed": 0,
            }));
            return Ok(());
        }
        printer.info("No entries to validate.");
        return Ok(());
    }

    printer.info(&format!(
        "Validating {} entries against {} cache(s) with {} parallel requests...",
        entries.len(),
        mirrors.len(),
        jobs,
    ));

    let client = reqwest::Client::new();
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(jobs as usize));
    let mut handles = Vec::new();

    for entry in entries {
        let client = client.clone();
        let mirrors = mirrors.clone();
        let permit = semaphore.clone().acquire_owned().await?;

        let handle = tokio::spawn(async move {
            let result = validate_cache_entry(&client, &mirrors, entry).await;
            drop(permit);
            result
        });
        handles.push(handle);
    }

    let mut missing = 0u32;
    let mut ok = 0u32;
    let mut missing_store_paths = HashSet::new();
    let mut results = Vec::new();
    for handle in handles {
        let result = handle.await?;
        if result.found {
            ok += 1;
        } else {
            missing += 1;
            missing_store_paths.insert(result.entry.store_path.clone());
            let detail = result
                .details
                .first()
                .map(|detail| format!(" ({detail})"))
                .unwrap_or_default();
            printer.warning(&format!(
                "{}: {} not found in any cache{}",
                result.entry.name, result.entry.store_path, detail
            ));
        }
        results.push(result);
    }

    if missing == 0 {
        if printer.mode() == OutputMode::Json {
            printer.json(&cache_validation_summary_json(
                "ok",
                package,
                platform,
                fix,
                jobs,
                mirrors.len(),
                ok,
                missing,
                0,
                &results,
            ));
            return Ok(());
        }
        printer.success(&format!("All {ok} entries found in caches."));
    } else if fix {
        let removed = remove_missing_cache_entries(&dir, &missing_store_paths)?;
        if removed == 0 {
            if printer.mode() == OutputMode::Json {
                bail!(
                    "{}; no matching registry entries removed.",
                    cache_validation_missing_error(ok, missing, &results)
                );
            }
            bail!("{ok} found, {missing} missing; no matching registry entries removed.");
        }
        if printer.mode() == OutputMode::Json {
            printer.json(&cache_validation_summary_json(
                "fixed",
                package,
                platform,
                fix,
                jobs,
                mirrors.len(),
                ok,
                missing,
                removed,
                &results,
            ));
            return Ok(());
        }
        let noun = if removed == 1 { "entry" } else { "entries" };
        printer.success(&format!(
            "Removed {removed} missing cache {noun} from registry metadata."
        ));
    } else {
        if printer.mode() == OutputMode::Json {
            bail!("{}", cache_validation_missing_error(ok, missing, &results));
        }
        bail!("{ok} found, {missing} missing.");
    }

    Ok(())
}

/// One (store path, NAR hash) pair that `apr validate` checks against the
/// caches.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CacheValidationEntry {
    name: String,
    platform: String,
    store_path: String,
    store_hash: String,
    /// Acceptable NAR hashes for this path. A legacy TOML entry has one;
    /// a `store/` record may have several blessed realisations, any
    /// of which a cache may legitimately serve (RFC-0005 §2.2).
    nar_hashes: Vec<String>,
}

/// Outcome of probing the caches for one entry; `details` collects the
/// per-cache failure reasons.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CacheValidationResult {
    entry: CacheValidationEntry,
    found: bool,
    details: Vec<String>,
}

#[allow(clippy::too_many_arguments)]
fn cache_validation_summary_json(
    status: &str,
    package: Option<&str>,
    platform: Option<&str>,
    fix: bool,
    jobs: u32,
    caches: usize,
    found: u32,
    missing: u32,
    removed: usize,
    results: &[CacheValidationResult],
) -> serde_json::Value {
    serde_json::json!({
        "status": status,
        "package": package,
        "platform": platform,
        "fix": fix,
        "jobs": jobs,
        "caches": caches,
        "checked": found + missing,
        "found": found,
        "missing": missing,
        "missing_entries": results
            .iter()
            .filter(|result| !result.found)
            .map(cache_validation_result_json)
            .collect::<Vec<_>>(),
        "removed": removed,
    })
}

fn cache_validation_result_json(result: &CacheValidationResult) -> serde_json::Value {
    serde_json::json!({
        "name": &result.entry.name,
        "platform": &result.entry.platform,
        "store_path": &result.entry.store_path,
        "store_hash": &result.entry.store_hash,
        "nar_hashes": &result.entry.nar_hashes,
        "details": &result.details,
    })
}

fn cache_validation_missing_error(
    found: u32,
    missing: u32,
    results: &[CacheValidationResult],
) -> String {
    let missing_entries = results
        .iter()
        .filter(|result| !result.found)
        .map(|result| {
            let detail = result
                .details
                .first()
                .map(|detail| format!(" ({detail})"))
                .unwrap_or_default();
            format!(
                "{}: {} not found in any cache{}",
                result.entry.name, result.entry.store_path, detail
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    if missing_entries.is_empty() {
        format!("{found} found, {missing} missing")
    } else {
        format!("{found} found, {missing} missing: {missing_entries}")
    }
}

/// Gather every published (store path, NAR hash) pair from the registry's
/// package TOMLs — including image artifacts — honoring optional package
/// and platform filters. The result is sorted and deduplicated.
fn collect_cache_validation_entries(
    dir: &Path,
    package_filter: Option<&str>,
    platform_filter: Option<&str>,
) -> Result<Vec<CacheValidationEntry>> {
    let packages_dir = dir.join("packages");
    let mut entries = Vec::new();

    if !packages_dir.is_dir() {
        return Ok(entries);
    }

    // Newer registries record output NAR hashes in the store/ graph rather
    // than the package TOML; load it once for the fallback. A malformed graph
    // is a hard error (matching Registry::load) - silently treating it as
    // absent would validate nothing on a post-RFC registry.
    let store_graph = StoreMap::load(dir).context("loading store/ graph for cache validation")?;

    for letter_entry in std::fs::read_dir(&packages_dir)
        .with_context(|| format!("reading {}", packages_dir.display()))?
    {
        let letter_entry = letter_entry?;
        if !letter_entry.path().is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(letter_entry.path())
            .with_context(|| format!("reading {}", letter_entry.path().display()))?
        {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            collect_cache_validation_entries_from_package(
                &path,
                package_filter,
                platform_filter,
                &store_graph,
                &mut entries,
            )?;
        }
    }

    entries.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then_with(|| a.platform.cmp(&b.platform))
            .then_with(|| a.store_path.cmp(&b.store_path))
    });
    entries.dedup();
    Ok(entries)
}

fn collect_cache_validation_entries_from_package(
    path: &Path,
    package_filter: Option<&str>,
    platform_filter: Option<&str>,
    store_graph: &StoreMap,
    entries: &mut Vec<CacheValidationEntry>,
) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading package metadata {}", path.display()))?;
    let toml_val: toml::Value =
        toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;
    let name = toml_val
        .get("package")
        .and_then(|p| p.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    if package_filter.is_some_and(|filter| filter != name) {
        return Ok(());
    }

    let Some(versions) = toml_val.get("versions").and_then(|v| v.as_array()) else {
        return Ok(());
    };
    for version in versions {
        let Some(platforms) = version.get("platforms").and_then(|v| v.as_table()) else {
            continue;
        };
        for (platform, entry) in platforms {
            if platform_filter.is_some_and(|filter| filter != platform) {
                continue;
            }
            let Some(store_path) = entry.get("store_path").and_then(|v| v.as_str()) else {
                continue;
            };
            // Acceptable hashes: the legacy TOML nar_hash, or ALL blessed
            // NARs from the store/ graph (a cache may legitimately serve any
            // of them - RFC-0005 §2.3).
            let mut nar_hashes: Vec<String> = entry
                .get("nar_hash")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .into_iter()
                .collect();
            if nar_hashes.is_empty() {
                nar_hashes.extend(
                    store_graph
                        .blessed_nars(extract_hash(store_path))
                        .iter()
                        .map(NarBytes::nar_hash),
                );
            }
            if nar_hashes.is_empty() {
                continue;
            }
            entries.push(CacheValidationEntry {
                name: name.to_string(),
                platform: platform.to_string(),
                store_path: store_path.to_string(),
                store_hash: extract_hash(store_path).to_string(),
                nar_hashes,
            });
            if let Some(images) = entry.get("images").and_then(|v| v.as_array()) {
                for image in images {
                    let Some(image_store_path) = image.get("store_path").and_then(|v| v.as_str())
                    else {
                        continue;
                    };
                    let Some(image_nar_hash) = image.get("nar_hash").and_then(|v| v.as_str())
                    else {
                        continue;
                    };
                    entries.push(CacheValidationEntry {
                        name: name.to_string(),
                        platform: platform.to_string(),
                        store_path: image_store_path.to_string(),
                        store_hash: extract_hash(image_store_path).to_string(),
                        nar_hashes: vec![image_nar_hash.to_string()],
                    });
                }
            }
        }
    }
    Ok(())
}

/// Prune registry metadata entries whose store paths are in
/// `missing_store_paths` (`apr validate --fix`).
///
/// Removes matching platform entries and image artifacts, then drops
/// versions left without platforms and deletes package files left without
/// versions. Returns the number of entries removed. Changes are written to
/// the working tree only — nothing is committed.
fn remove_missing_cache_entries(
    dir: &Path,
    missing_store_paths: &HashSet<String>,
) -> Result<usize> {
    if missing_store_paths.is_empty() {
        return Ok(0);
    }

    let packages_dir = dir.join("packages");
    let mut removed = 0usize;

    if !packages_dir.is_dir() {
        return Ok(removed);
    }

    for letter_entry in fs::read_dir(&packages_dir)
        .with_context(|| format!("reading {}", packages_dir.display()))?
    {
        let letter_entry = letter_entry?;
        if !letter_entry.path().is_dir() {
            continue;
        }

        for entry in fs::read_dir(letter_entry.path())
            .with_context(|| format!("reading {}", letter_entry.path().display()))?
        {
            let path = entry?.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("toml") {
                continue;
            }
            removed += remove_missing_cache_entries_from_package(&path, missing_store_paths)?;
        }
    }

    Ok(removed)
}

fn remove_missing_cache_entries_from_package(
    path: &Path,
    missing_store_paths: &HashSet<String>,
) -> Result<usize> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("reading package metadata {}", path.display()))?;
    let mut toml_val: toml::Value =
        toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;
    let mut removed = 0usize;
    let mut remove_package = false;

    if let Some(versions) = toml_val
        .get_mut("versions")
        .and_then(|value| value.as_array_mut())
    {
        for version in versions.iter_mut() {
            let Some(platforms) = version
                .as_table_mut()
                .and_then(|table| table.get_mut("platforms"))
                .and_then(|value| value.as_table_mut())
            else {
                continue;
            };

            let platform_names: Vec<String> = platforms
                .iter()
                .filter_map(|(platform, entry)| {
                    let store_path = entry.get("store_path").and_then(|value| value.as_str())?;
                    if missing_store_paths.contains(store_path) {
                        Some(platform.clone())
                    } else {
                        None
                    }
                })
                .collect();
            for platform in platform_names {
                if platforms.remove(&platform).is_some() {
                    removed += 1;
                }
            }

            for (_platform_name, platform) in platforms.iter_mut() {
                let Some(platform_table) = platform.as_table_mut() else {
                    continue;
                };
                let remove_images_key = if let Some(images) = platform_table
                    .get_mut("images")
                    .and_then(|value| value.as_array_mut())
                {
                    let before = images.len();
                    images.retain(|image| {
                        let remove = image
                            .get("store_path")
                            .and_then(|value| value.as_str())
                            .map(|store_path| missing_store_paths.contains(store_path))
                            .unwrap_or(false);
                        !remove
                    });
                    removed += before - images.len();
                    images.is_empty()
                } else {
                    false
                };
                if remove_images_key {
                    platform_table.remove("images");
                }
            }
        }

        versions.retain(|version| {
            version
                .get("platforms")
                .and_then(|platforms| platforms.as_table())
                .map(|platforms| !platforms.is_empty())
                .unwrap_or(false)
        });
        remove_package = versions.is_empty();
    }

    if removed > 0 {
        if remove_package {
            fs::remove_file(path).with_context(|| format!("removing {}", path.display()))?;
        } else {
            fs::write(path, toml::to_string_pretty(&toml_val)?)
                .with_context(|| format!("writing {}", path.display()))?;
        }
    }

    Ok(removed)
}

/// Probe each mirror for one entry: fetch the `.narinfo`, cross-check its
/// store path and NAR hash against the registry metadata, then `HEAD` the
/// NAR it references. The first cache that fully matches wins; every
/// per-cache failure is accumulated as a detail string for diagnostics.
async fn validate_cache_entry(
    client: &reqwest::Client,
    mirrors: &[CacheEntry],
    entry: CacheValidationEntry,
) -> CacheValidationResult {
    let mut details = Vec::new();
    for cache in mirrors {
        let base = cache.url.trim_end_matches('/');
        let narinfo_url =
            crate::download::join_cache_url(base, &format!("{}.narinfo", entry.store_hash));

        let narinfo = match client.get(&narinfo_url).send().await {
            Ok(response) if response.status().is_success() => match response.text().await {
                Ok(text) => match narinfo::parse(&text) {
                    Ok(narinfo) => narinfo,
                    Err(err) => {
                        details.push(format!("{narinfo_url}: invalid narinfo: {err}"));
                        continue;
                    }
                },
                Err(err) => {
                    details.push(format!("{narinfo_url}: failed reading narinfo body: {err}"));
                    continue;
                }
            },
            Ok(response) => {
                details.push(format!("{narinfo_url}: HTTP {}", response.status()));
                continue;
            }
            Err(err) => {
                details.push(format!("{narinfo_url}: {err}"));
                continue;
            }
        };

        if narinfo.store_path != entry.store_path {
            details.push(format!(
                "{narinfo_url}: narinfo store path {} did not match registry path {}",
                narinfo.store_path, entry.store_path
            ));
            continue;
        }
        // Registry hashes may be SRI (legacy TOML) or nixbase32 (store/ graph
        // map); narinfo hashes vary by emitter. Compare normalized, and
        // accept the cache if it serves ANY blessed realisation.
        let narinfo_norm = aos_core::nar::cache::normalize_sha256_nix32(&narinfo.nar_hash);
        if !entry
            .nar_hashes
            .iter()
            .any(|expected| aos_core::nar::cache::normalize_sha256_nix32(expected) == narinfo_norm)
        {
            details.push(format!(
                "{narinfo_url}: narinfo NarHash {} matched none of the registry NarHash(es) [{}]",
                narinfo.nar_hash,
                entry.nar_hashes.join(", ")
            ));
            continue;
        }

        let nar_url = crate::download::join_cache_url(base, &narinfo.url);
        match client.head(&nar_url).send().await {
            Ok(response) if response.status().is_success() => {
                return CacheValidationResult {
                    entry,
                    found: true,
                    details,
                };
            }
            Ok(response) => {
                details.push(format!("{nar_url}: HTTP {}", response.status()));
            }
            Err(err) => {
                details.push(format!("{nar_url}: {err}"));
            }
        }
    }

    CacheValidationResult {
        entry,
        found: false,
        details,
    }
}

// ---------------------------------------------------------------------------
// Git Workflow
// ---------------------------------------------------------------------------

/// `apr status` — prints `git status --short` for the registry clone,
/// including untracked files.
///
/// # Errors
///
/// Fails when the registry cannot be resolved or git fails.
pub async fn status(config: &ApmConfig, registry: Option<&str>, printer: &Printer) -> Result<()> {
    let dir = registry_dir(config, registry)?;
    let raw_output = git_raw(&dir, &["status", "--short", "--untracked-files=all"])?;
    let output = String::from_utf8_lossy(&raw_output);
    if printer.mode() == OutputMode::Json {
        let entries = parse_status_short(&output);
        printer.json(&serde_json::json!({
            "clean": entries.is_empty(),
            "entries": entries,
        }));
        return Ok(());
    }
    printer.plain(output.trim());
    Ok(())
}

/// `apr commit` stages explicit registry-relative paths and creates one commit
/// with AOS's in-process SSH signer.
///
/// The command refuses a pre-populated index so a caller cannot accidentally
/// include paths staged by an earlier operation. Registries with an active
/// trust roster require `--key` or `--key-id`; an unsigned commit is permitted
/// only while the roster is empty.
///
/// # Errors
///
/// Fails when a path is absolute or escapes the registry, the index already
/// contains staged changes, the signing key is missing or invalid, registry
/// validation fails, or the commit/object-store refresh fails.
pub async fn commit_changes(
    config: &ApmConfig,
    paths: &[PathBuf],
    message: &str,
    key: Option<&str>,
    key_id: Option<&str>,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    if message.trim().is_empty() {
        bail!("commit message must not be empty");
    }

    let registry_name = resolve_registry_name(config, registry)?;
    let dir = config.scope.registries_path().join(&registry_name);
    ensure_writable_registry_clone(&registry_name, &dir)?;

    let staged = git_raw(&dir, &["diff", "--cached", "--name-only"])?;
    if !staged.is_empty() {
        bail!(
            "registry '{registry_name}' already has staged changes; commit or unstage them before `apr commit`"
        );
    }

    let mut absolute_paths = Vec::with_capacity(paths.len());
    for path in paths {
        if path.as_os_str().is_empty()
            || path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            bail!(
                "commit path must be a non-empty registry-relative path without '.' or '..': {}",
                path.display()
            );
        }
        absolute_paths.push(dir.join(path));
    }

    let roster = load_committed_roster(&dir)?;
    let signing_key =
        resolve_roster_commit_key(config, &dir, &registry_name, &roster, key, key_id)?;
    commit_registry_paths(
        &dir,
        message,
        &absolute_paths,
        signing_key.as_ref().map(ResolvedSigningKey::path),
    )?;
    refresh_registry_object_store(&dir)
        .context("refreshing dumb-HTTP object store after explicit commit")?;

    let head = current_git_head(&dir)?;
    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "action": "commit",
            "registry": registry_name,
            "commit": head,
            "message": message,
            "paths": paths,
            "signed": signing_key.is_some(),
        }));
        return Ok(());
    }
    printer.success(&format!("Committed {head}: {message}"));
    Ok(())
}

/// `apr log` — prints the last `n` commits of the registry clone, one line
/// each, optionally restricted to the history of a single package's TOML
/// file.
///
/// # Errors
///
/// Fails when the registry cannot be resolved, the package filter is not a
/// safe package name, or git fails.
pub async fn log(
    config: &ApmConfig,
    package: Option<&str>,
    n: u32,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let dir = registry_dir(config, registry)?;

    let n_str = format!("-{n}");
    let mut args = vec!["log", "--oneline", &n_str];

    let path_filter;
    if let Some(pkg) = package {
        validate_package_name(pkg)?;
        let letter = first_letter(pkg);
        path_filter = format!("packages/{letter}/{pkg}.toml");
        args.push("--");
        args.push(&path_filter);
    }

    let output = git(&dir, &args)?;
    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "package": package,
            "limit": n,
            "commits": git_log_entries(&dir, package, n)?,
        }));
        return Ok(());
    }
    if output.is_empty() {
        printer.info("No commits found.");
    } else {
        printer.plain(&output);
    }

    Ok(())
}

/// Parse `git status --short` lines into structured entries (index and
/// worktree status characters plus the path).
fn parse_status_short(output: &str) -> Vec<serde_json::Value> {
    output
        .lines()
        .filter_map(|line| {
            if line.len() < 3 {
                return None;
            }
            let bytes = line.as_bytes();
            let index = bytes[0] as char;
            let worktree = bytes[1] as char;
            let path = line[3..].to_string();
            Some(serde_json::json!({
                "index": index.to_string(),
                "worktree": worktree.to_string(),
                "status": line[..2].to_string(),
                "path": path,
            }))
        })
        .collect()
}

fn diff_name_status_entries(
    dir: &Path,
    range: Option<(&str, &str)>,
) -> Result<Vec<serde_json::Value>> {
    let output = match range {
        Some((base, head)) => git(dir, &["diff", "--name-status", base, head])?,
        None => git(dir, &["diff", "--name-status"])?,
    };
    Ok(output
        .lines()
        .filter_map(|line| {
            let mut fields = line.split('\t');
            let status = fields.next()?;
            let path = fields.next()?;
            let new_path = fields.next();
            let mut entry = serde_json::json!({
                "status": status,
                "path": path,
            });
            if let Some(new_path) = new_path {
                entry["new_path"] = serde_json::json!(new_path);
            }
            Some(entry)
        })
        .collect())
}

fn diff_name_status_entries_with_untracked(
    dir: &Path,
    untracked: &[String],
) -> Result<Vec<serde_json::Value>> {
    let mut entries = diff_name_status_entries(dir, None)?;
    entries.extend(untracked.iter().map(|path| {
        serde_json::json!({
            "status": "A",
            "path": path,
            "untracked": true,
        })
    }));
    Ok(entries)
}

/// Collect structured commit records for JSON output, using ASCII
/// unit/record separators (`%x1f`/`%x1e`) so subjects containing newlines
/// or tabs cannot corrupt the framing.
fn git_log_entries(dir: &Path, package: Option<&str>, n: u32) -> Result<Vec<serde_json::Value>> {
    let n_str = format!("-{n}");
    let pretty = "%H%x1f%h%x1f%s%x1f%ct%x1e";
    let pretty_arg = format!("--pretty=format:{pretty}");
    let mut args = vec!["log", &n_str, &pretty_arg];

    let path_filter;
    if let Some(pkg) = package {
        validate_package_name(pkg)?;
        let letter = first_letter(pkg);
        path_filter = format!("packages/{letter}/{pkg}.toml");
        args.push("--");
        args.push(&path_filter);
    }

    let output = git_raw(dir, &args)?;
    let text = String::from_utf8_lossy(&output);
    Ok(text
        .split('\x1e')
        .filter_map(|record| {
            let record = record.trim_matches('\n');
            if record.is_empty() {
                return None;
            }
            let mut fields = record.split('\x1f');
            let hash = fields.next()?;
            let short_hash = fields.next()?;
            let subject = fields.next()?;
            let timestamp = fields
                .next()
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or_default();
            Some(serde_json::json!({
                "hash": hash,
                "short_hash": short_hash,
                "subject": subject,
                "timestamp": timestamp,
            }))
        })
        .collect())
}

/// `apr branch` subcommands: list, create, switch to, and delete branches
/// in the registry clone.
///
/// # Errors
///
/// Fails when the registry cannot be resolved, a branch name is not safe to
/// use as a Git ref, or when the underlying git command fails (e.g. deleting
/// an unmerged branch or switching with a dirty working tree).
pub async fn run_branch(
    config: &ApmConfig,
    command: &BranchCommand,
    printer: &Printer,
) -> Result<()> {
    match command {
        BranchCommand::List { registry } => {
            let dir = registry_dir(config, registry.as_deref())?;
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "branches": git_branch_entries(&dir)?,
                }));
                return Ok(());
            }
            let output = git(&dir, &["branch", "-a"])?;
            printer.plain(&output);
            Ok(())
        }
        BranchCommand::Create { name, registry } => {
            validate_branch_name(name)?;
            let dir = registry_dir(config, registry.as_deref())?;
            git(&dir, &["branch", "--", name])?;
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "action": "create",
                    "branch": name,
                    "current": current_git_branch(&dir)?,
                    "branches": git_branch_entries(&dir)?,
                }));
                return Ok(());
            }
            printer.success(&format!("Created branch '{name}'."));
            Ok(())
        }
        BranchCommand::Switch { name, registry } => {
            validate_branch_name(name)?;
            let dir = registry_dir(config, registry.as_deref())?;
            git(&dir, &["switch", "--", name])?;
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "action": "switch",
                    "branch": name,
                    "current": current_git_branch(&dir)?,
                    "branches": git_branch_entries(&dir)?,
                }));
                return Ok(());
            }
            printer.success(&format!("Switched to branch '{name}'."));
            Ok(())
        }
        BranchCommand::Delete { name, registry } => {
            validate_branch_name(name)?;
            let dir = registry_dir(config, registry.as_deref())?;
            git(&dir, &["branch", "-d", "--", name])?;
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "action": "delete",
                    "branch": name,
                    "current": current_git_branch(&dir)?,
                    "branches": git_branch_entries(&dir)?,
                }));
                return Ok(());
            }
            printer.success(&format!("Deleted branch '{name}'."));
            Ok(())
        }
    }
}

fn current_git_branch(dir: &Path) -> Result<String> {
    git(dir, &["rev-parse", "--abbrev-ref", "HEAD"])
}

/// Collect local and remote branch records (name, ref, commit, flags) for
/// JSON output.
fn git_branch_entries(dir: &Path) -> Result<Vec<serde_json::Value>> {
    let current = current_git_branch(dir)?;
    let output = git_raw(
        dir,
        &[
            "for-each-ref",
            "--format=%(refname)%00%(refname:short)%00%(objectname)%00",
            "refs/heads",
            "refs/remotes",
        ],
    )?;
    let text = String::from_utf8_lossy(&output);
    Ok(text
        .lines()
        .filter_map(|line| {
            let mut fields = line.split('\0');
            let refname = fields.next()?;
            let short = fields.next()?;
            let commit = fields.next()?;
            if refname.is_empty() || short.is_empty() {
                return None;
            }
            let remote = refname.starts_with("refs/remotes/");
            Some(serde_json::json!({
                "name": short,
                "ref": refname,
                "commit": commit,
                "remote": remote,
                "current": !remote && short == current,
            }))
        })
        .collect())
}

/// `apr channel` subcommands for staged rollouts.
///
/// `init` points all 256 partitions of a channel at one release;
/// `advance` moves a subset (`--count` for an ascending fill, or an
/// explicit `--partitions` list) to a newer release; `status` summarizes
/// per-version partition counts and the channel frontier. Partition
/// updates write signed tag payloads under `.git/channels/<channel>/` and
/// move the channel branch head to the frontier release.
///
/// # Errors
///
/// Fails when the semver argument does not parse, when the release tag
/// does not exist, when the signing key cannot be resolved, or when
/// partition payloads are missing or fail verification.
pub async fn run_channel(
    config: &ApmConfig,
    command: &ChannelCommand,
    printer: &Printer,
) -> Result<()> {
    match command {
        ChannelCommand::Init {
            channel,
            semver,
            key,
            key_id,
            registry,
        } => {
            let version = semver::Version::parse(semver)
                .with_context(|| format!("parsing release semver '{semver}'"))?;
            channel_init(
                config,
                channel,
                &version,
                key.as_deref(),
                key_id.as_deref(),
                registry.as_deref(),
                printer,
            )
            .await
        }
        ChannelCommand::Advance {
            channel,
            semver,
            count,
            partitions,
            key,
            key_id,
            registry,
        } => {
            let version = semver::Version::parse(semver)
                .with_context(|| format!("parsing release semver '{semver}'"))?;
            channel_advance(
                config,
                channel,
                &version,
                *count,
                partitions.as_deref(),
                key.as_deref(),
                key_id.as_deref(),
                registry.as_deref(),
                printer,
            )
            .await
        }
        ChannelCommand::Status { channel, registry } => {
            channel_status(config, channel, registry.as_deref(), printer).await
        }
    }
}

/// The remote ref namespace a hub writes git-backed config change requests to.
///
/// A change request lives at `refs/hub/changes/<id>` — a ref, not a branch, so
/// consumers (who follow only signed tags and partitions) never see it. `apr
/// change` fetches these into a local `refs/hub/changes/*` mirror.
const HUB_CHANGES_NS: &str = "refs/hub/changes/";

/// The `AOS-Change-Id` commit-message trailer a hub stamps on draft commits.
const CHANGE_ID_TRAILER: &str = "AOS-Change-Id";

/// Dispatch the `apr change` subcommands (RFC-0004 "Configuration management",
/// git-backed change requests).
///
/// A hub commits web edits to committed config as change requests under
/// `refs/hub/changes/<id>`, signed by a non-roster draft-signing key. These
/// subcommands let a maintainer review and **promote** them locally:
///
/// - `list` fetches the remote's `refs/hub/changes/*` and lists each draft.
/// - `show` fetches one draft and diffs it against the current branch HEAD.
/// - `merge` fetches one draft, verifies it is a fast-forward of HEAD, replays
///   its tree as a new commit re-signed with a roster key, and pushes — the
///   draft (hub-signed, non-roster) becomes roster-signed state consumers
///   accept. The hub's draft-signing key is **not** a roster key, so a draft
///   never verifies for consumers until this promotion.
///
/// # Errors
///
/// Returns an error on a missing registry/clone, a fetch/push failure, an
/// unknown change id, a non-fast-forwardable draft, a missing signing key, or
/// any underlying git failure.
pub async fn run_change(
    config: &ApmConfig,
    command: &ChangeCommand,
    printer: &Printer,
) -> Result<()> {
    match command {
        ChangeCommand::List { registry } => change_list(config, registry.as_deref(), printer).await,
        ChangeCommand::Show { id, stat, registry } => {
            change_show(config, id, *stat, registry.as_deref(), printer).await
        }
        ChangeCommand::Merge {
            id,
            key,
            key_id,
            registry,
        } => {
            change_merge(
                config,
                id,
                key.as_deref(),
                key_id.as_deref(),
                registry.as_deref(),
                printer,
            )
            .await
        }
    }
}

/// Fetch the remote's `refs/hub/changes/*` into the local clone, mirroring them
/// under the same namespace. Returns nothing; the refs are then readable
/// locally with `git for-each-ref`/`git log`.
fn fetch_change_refs(dir: &Path) -> Result<()> {
    let refspec = format!("+{HUB_CHANGES_NS}*:{HUB_CHANGES_NS}*");
    git_transport(dir, &["fetch", "origin", &refspec, "--force"])?;
    Ok(())
}

/// The local ref path for change request `id`.
fn change_ref(id: &str) -> String {
    format!("{HUB_CHANGES_NS}{id}")
}

/// One change request discovered in the local `refs/hub/changes/*` mirror.
struct DiscoveredChange {
    id: String,
    commit: String,
    summary: String,
    change_id_trailer: Option<String>,
}

/// List the change requests mirrored under `refs/hub/changes/*`.
fn discover_changes(dir: &Path) -> Result<Vec<DiscoveredChange>> {
    let listing = git(
        dir,
        &[
            "for-each-ref",
            "--format=%(refname)%09%(objectname)%09%(contents:subject)",
            HUB_CHANGES_NS,
        ],
    )?;
    let mut out = Vec::new();
    for line in listing.lines().filter(|l| !l.trim().is_empty()) {
        let mut parts = line.splitn(3, '\t');
        let (Some(refname), Some(commit)) = (parts.next(), parts.next()) else {
            continue;
        };
        let summary = parts.next().unwrap_or("").to_string();
        let id = refname
            .strip_prefix(HUB_CHANGES_NS)
            .unwrap_or(refname)
            .to_string();
        let body = git(dir, &["log", "-1", "--format=%B", commit]).unwrap_or_default();
        let change_id_trailer = body.lines().find_map(|l| {
            l.trim()
                .strip_prefix(&format!("{CHANGE_ID_TRAILER}:"))
                .map(|rest| rest.trim().to_string())
        });
        out.push(DiscoveredChange {
            id,
            commit: commit.to_string(),
            summary,
            change_id_trailer,
        });
    }
    Ok(out)
}

/// `apr change list` — fetch and list the registry's open change requests.
async fn change_list(config: &ApmConfig, registry: Option<&str>, printer: &Printer) -> Result<()> {
    let dir = registry_dir(config, registry)?;
    fetch_change_refs(&dir)?;
    let changes = discover_changes(&dir)?;

    if printer.mode() == OutputMode::Json {
        let rows: Vec<_> = changes
            .iter()
            .map(|c| {
                serde_json::json!({
                    "id": c.id,
                    "commit": c.commit,
                    "summary": c.summary,
                    "change_id": c.change_id_trailer,
                })
            })
            .collect();
        printer.json(&serde_json::json!({ "change_requests": rows }));
        return Ok(());
    }
    if changes.is_empty() {
        printer.info("No open change requests.");
        return Ok(());
    }
    for change in &changes {
        printer.plain(&format!(
            "{}  {}  {}",
            &change.commit[..change.commit.len().min(12)],
            change.id,
            change.summary
        ));
    }
    Ok(())
}

/// `apr change show <id>` — diff a change request vs the current branch HEAD.
async fn change_show(
    config: &ApmConfig,
    id: &str,
    stat: bool,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let dir = registry_dir(config, registry)?;
    fetch_change_refs(&dir)?;
    let reference = change_ref(id);
    if !git_ref_exists(&dir, &reference)? {
        bail!("no change request '{id}' (looked for {reference})");
    }
    let mut args = vec!["diff", "HEAD", reference.as_str()];
    if stat {
        args.push("--stat");
    }
    let output = git(&dir, &args)?;
    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "id": id,
            "ref": reference,
            "stat": stat,
            "clean": output.is_empty(),
            "output": output,
        }));
        return Ok(());
    }
    if output.is_empty() {
        printer.info("Change request matches the current branch (no diff).");
    } else {
        printer.plain(&output);
    }
    Ok(())
}

/// `apr change merge <id>` — promote a change request onto the tracked branch.
///
/// Fetches the draft, verifies it is a fast-forward of the current HEAD (so its
/// tree cleanly replaces the branch tip), replays its tree as a new commit
/// re-signed with the maintainer's roster key, refreshes the static object
/// store, and pushes. The promotion turns a non-roster, hub-signed draft into
/// roster-signed state consumers accept.
async fn change_merge(
    config: &ApmConfig,
    id: &str,
    key: Option<&str>,
    key_id: Option<&str>,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let registry_name = resolve_registry_name(config, registry)?;
    let dir = config.scope.registries_path().join(&registry_name);
    fetch_change_refs(&dir)?;
    let reference = change_ref(id);
    if !git_ref_exists(&dir, &reference)? {
        bail!("no change request '{id}' (looked for {reference})");
    }

    // The draft must be a fast-forward of HEAD: the current tip is an ancestor
    // of the draft, so replaying its tree is an unambiguous promotion (not a
    // merge). A stale draft (HEAD moved on past its base) is rejected.
    let (is_ancestor, _, _) = git_try(&dir, &["merge-base", "--is-ancestor", "HEAD", &reference])?;
    if !is_ancestor {
        bail!(
            "change request '{id}' is not a fast-forward of the current branch HEAD; \
             it was branched from an older commit — re-create the change against the \
             current tip before merging"
        );
    }

    // Show the diff so the maintainer reviews exactly what they are signing.
    let diff = git(&dir, &["diff", "HEAD", &reference])?;
    if !diff.is_empty() {
        printer.plain(&diff);
    }

    // Resolve the roster signing key (the same producer signing path the rest
    // of `apr` uses).
    let signing_key = resolve_producer_signing_key(config, &dir, &registry_name, key, key_id)?;

    // Replay the draft's tree onto the working tree + index, then commit it as a
    // fresh, roster-signed child of HEAD (a cherry-pick of the change).
    let change_commit = git(&dir, &["rev-parse", &reference])?;
    git(&dir, &["read-tree", "-u", "--reset", &change_commit])?;
    let subject = git(&dir, &["log", "-1", "--format=%s", &reference])?;
    let message = format!("{subject}\n\npromoted from change request {id}");
    commit_staged_registry(&dir, &message, Some(signing_key.path()))?;

    // Refresh the dumb-HTTP object store so the new commit is fetchable, then
    // push the branch.
    refresh_registry_object_store(&dir)?;
    let branch = current_git_branch(&dir)?;
    git_transport(&dir, &["push", "origin", &branch])?;

    let new_commit = git(&dir, &["rev-parse", "HEAD"])?;
    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "id": id,
            "branch": branch,
            "commit": new_commit,
            "promoted_from": change_commit,
        }));
        return Ok(());
    }
    printer.info(&format!(
        "Promoted change request {id} as {} on {branch} (pushed).",
        &new_commit[..new_commit.len().min(12)]
    ));
    Ok(())
}

/// `apr cache` subcommands for the static Nix binary cache.
///
/// `generate` renders the registry's published store paths into a static
/// cache directory (narinfos plus compressed NARs, signed with `--key`
/// when given), optionally uploads it to each `--upload-url` (falling back
/// to the `upload_urls` persisted by `apr origin config` when no flag is
/// given), and with `--cache-url` upserts the committed `[caches]` stack in
/// `registry.toml`, committing the pointer change unless `--no-commit` is
/// set.
///
/// # Errors
///
/// Fails when cache generation, an upload, the pointer commit, or the
/// object-store refresh fails.
/// `apr store` - maintains the registry's `store/` realisation graph
/// (RFC-0005).
///
/// The graph is append-mostly: `bless` adds a realisation computed from the
/// local Nix store, `revoke` removes one (a security event with the same
/// review weight as a key retirement), `verify` checks graph health and
/// coverage, and `backfill` records every published closure in one pass so an
/// existing registry becomes fully covered.
///
/// # Errors
///
/// Fails when the registry cannot be resolved, the referenced store paths
/// are not valid in the local Nix store, a record cannot be read or written,
/// a blessing conflicts without `--bless`, verification finds errors, or the
/// commit fails.
pub async fn run_store(
    config: &ApmConfig,
    command: &StoreCommand,
    printer: &Printer,
) -> Result<()> {
    match command {
        StoreCommand::Bless {
            store_path,
            no_commit,
            message,
            key,
            key_id,
            registry,
        } => {
            let registry_name = resolve_registry_name(config, registry.as_deref())?;
            let dir = config.scope.registries_path().join(&registry_name);
            ensure_writable_registry_clone(&registry_name, &dir)?;
            let signing_key =
                resolve_optional_signing_key(config, &dir, &registry_name, key, key_id)?;
            let content_addressed = registry_content_addressed(&dir);
            let _publish_lock = RegistryPublishLock::acquire(&dir)?;

            // Bless the whole closure of the path (records every member).
            let report = write_store_files(&dir, store_path, content_addressed, true, printer)
                .with_context(|| format!("writing store/ records for {store_path}"))?;

            printer.kv("Store graph", &report.summary());
            let changed = report.created + report.blessed > 0;
            let mut committed = false;
            if changed && !*no_commit {
                let default_msg = format!("store: bless {store_path}");
                let msg = message.as_deref().unwrap_or(&default_msg);
                commit_registry_paths(
                    &dir,
                    msg,
                    &[dir.join(store::STORE_DIR)],
                    signing_key.as_ref().map(|k| k.path()),
                )?;
                refresh_registry_object_store(&dir)
                    .context("refreshing dumb-HTTP object store after store bless")?;
                committed = true;
                printer.success(&format!("Committed: {msg}"));
            } else if !changed {
                printer.info("Graph already covers this content; nothing to commit.");
            }

            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "action": "store_bless",
                    "registry": registry_name,
                    "store_path": store_path,
                    "created": report.created,
                    "blessed": report.blessed,
                    "unchanged": report.unchanged,
                    "content_addressed": report.content_addressed,
                    "committed": committed,
                }));
            }
            Ok(())
        }

        StoreCommand::Revoke {
            store_path,
            realisation,
            no_commit,
            message,
            key,
            key_id,
            registry,
        } => {
            let registry_name = resolve_registry_name(config, registry.as_deref())?;
            let dir = config.scope.registries_path().join(&registry_name);
            ensure_writable_registry_clone(&registry_name, &dir)?;
            let signing_key =
                resolve_optional_signing_key(config, &dir, &registry_name, key, key_id)?;
            let _publish_lock = RegistryPublishLock::acquire(&dir)?;

            let ia_hash = extract_hash(store_path);
            if !store::remove_realisations(&dir, ia_hash, realisation.as_deref())? {
                bail!("no matching store/ realisation for {ia_hash}; nothing to revoke");
            }

            printer.success(&format!(
                "Revoked {} for {ia_hash}.",
                realisation.as_deref().unwrap_or("all realisations"),
            ));
            let mut committed = false;
            if !*no_commit {
                let default_msg = format!("store: revoke {ia_hash}");
                let msg = message.as_deref().unwrap_or(&default_msg);
                commit_registry_paths(
                    &dir,
                    msg,
                    &[dir.join(store::STORE_DIR)],
                    signing_key.as_ref().map(|k| k.path()),
                )?;
                refresh_registry_object_store(&dir)
                    .context("refreshing dumb-HTTP object store after store revoke")?;
                committed = true;
                printer.success(&format!("Committed: {msg}"));
            }

            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "action": "store_revoke",
                    "registry": registry_name,
                    "ia_hash": ia_hash,
                    "realisation": realisation,
                    "committed": committed,
                }));
            }
            Ok(())
        }

        StoreCommand::Verify { deep, registry } => {
            let registry_name = resolve_registry_name(config, registry.as_deref())?;
            let dir = config.scope.registries_path().join(&registry_name);
            store_verify(&dir, &registry_name, *deep, printer)
        }

        StoreCommand::Backfill {
            bless,
            no_commit,
            message,
            key,
            key_id,
            registry,
        } => {
            let registry_name = resolve_registry_name(config, registry.as_deref())?;
            let dir = config.scope.registries_path().join(&registry_name);
            ensure_writable_registry_clone(&registry_name, &dir)?;
            let signing_key =
                resolve_optional_signing_key(config, &dir, &registry_name, key, key_id)?;
            let content_addressed = registry_content_addressed(&dir);
            let _publish_lock = RegistryPublishLock::acquire(&dir)?;

            let roots = collect_package_store_paths(&dir)?;
            if roots.is_empty() {
                bail!("registry has no published store paths to backfill");
            }

            let mut report = StoreWriteReport::default();
            for root in &roots {
                printer.info(&format!("Recording closure of {root}"));
                report.merge(
                    write_store_files(&dir, root, content_addressed, *bless, printer)
                        .with_context(|| format!("writing store/ records for {root}"))?,
                );
            }
            printer.kv("Roots", &roots.len().to_string());
            printer.kv("Store graph", &report.summary());

            let changed = report.created + report.blessed > 0;
            let mut committed = false;
            if changed && !*no_commit {
                let default_msg = format!(
                    "store: backfill realisation graph ({} closures)",
                    roots.len(),
                );
                let msg = message.as_deref().unwrap_or(&default_msg);
                commit_registry_paths(
                    &dir,
                    msg,
                    &[dir.join(store::STORE_DIR)],
                    signing_key.as_ref().map(|k| k.path()),
                )?;
                refresh_registry_object_store(&dir)
                    .context("refreshing dumb-HTTP object store after store backfill")?;
                committed = true;
                printer.success(&format!("Committed: {msg}"));
            } else if !changed {
                printer.info("Graph already covers every published closure.");
            }

            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "action": "store_backfill",
                    "registry": registry_name,
                    "roots": roots.len(),
                    "created": report.created,
                    "blessed": report.blessed,
                    "unchanged": report.unchanged,
                    "content_addressed": report.content_addressed,
                    "committed": committed,
                }));
            }
            Ok(())
        }
    }
}

/// Resolve a producer signing key only when `--key`/`--key-id` was given
/// (the `apr publish` convention).
fn resolve_optional_signing_key(
    config: &ApmConfig,
    dir: &Path,
    registry_name: &str,
    key: &Option<String>,
    key_id: &Option<String>,
) -> Result<Option<ResolvedSigningKey>> {
    if key.is_some() || key_id.is_some() {
        Ok(Some(resolve_producer_signing_key(
            config,
            dir,
            registry_name,
            key.as_deref(),
            key_id.as_deref(),
        )?))
    } else {
        Ok(None)
    }
}

/// Resolves the signing key for a committed cache-pointer update.
///
/// A registry without a trust roster may retain the unsigned local-development
/// behavior. Once active roster keys exist, however, publishing an unsigned
/// head would make the registry unusable to verifying consumers. Explicit
/// options win; otherwise a sole locally configured active key is selected.
fn resolve_cache_pointer_signing_key(
    config: &ApmConfig,
    dir: &Path,
    registry_name: &str,
    key: Option<&str>,
    key_id: Option<&str>,
) -> Result<Option<ResolvedSigningKey>> {
    if key.is_some() || key_id.is_some() {
        return resolve_producer_signing_key(config, dir, registry_name, key, key_id).map(Some);
    }

    let roster = load_committed_roster(dir)?;
    if roster.active.is_empty() {
        return Ok(None);
    }
    let registry_config = registry_config_by_name(config, registry_name).ok_or_else(|| {
        anyhow::anyhow!(
            "registry '{registry_name}' has an active trust roster but no producer configuration"
        )
    })?;
    let candidates = roster
        .active
        .iter()
        .filter(|entry| registry_config.signing_keys.contains_key(&entry.id))
        .map(|entry| entry.id.as_str())
        .collect::<Vec<_>>();
    match candidates.as_slice() {
        [key_id] => {
            resolve_producer_signing_key(config, dir, registry_name, None, Some(key_id)).map(Some)
        }
        [] => bail!(
            "registry '{registry_name}' has active trust keys but none has local private key material; pass --registry-key or configure one under [registry.signing_keys]"
        ),
        _ => bail!(
            "registry '{registry_name}' has multiple locally configured active keys; select one with --registry-key-id"
        ),
    }
}

/// `apr store verify` - checks graph health: record parseability, coverage of
/// every published closure member (reachable via dependency edges), and (with
/// `deep`) agreement with the local Nix store's actual NAR hashes.
fn store_verify(dir: &Path, registry_name: &str, deep: bool, printer: &Printer) -> Result<()> {
    let graph = StoreMap::load(dir).context("loading store/ graph")?;
    if !graph.is_present() {
        bail!(
            "registry '{registry_name}' publishes no store/ realisation graph; \
             run `apr store backfill` to create one"
        );
    }

    let mut errors = 0u32;
    let mut members_checked = 0u32;

    // Coverage: every member reachable from every published package root has a
    // record with a blessed NAR.
    for root in collect_package_store_paths(dir)? {
        let mut seen = HashSet::new();
        let mut stack = vec![extract_hash(&root).to_string()];
        while let Some(hash) = stack.pop() {
            if !seen.insert(hash.clone()) {
                continue;
            }
            members_checked += 1;
            match graph.get(&hash) {
                None => {
                    printer.warning(&format!("closure member {hash} has no store/ record"));
                    errors += 1;
                }
                Some(record) if record.blessed_nars().is_empty() => {
                    printer.warning(&format!("store/ record {hash} has no blessed NAR"));
                    errors += 1;
                }
                Some(_) => stack.extend(graph.direct_deps(&hash)),
            }
        }
    }

    // Deep: recompute every locally-available closure member's NAR hash and
    // require it to match a blessed NAR in the record.
    let mut deep_checked = 0u32;
    if deep {
        for root in collect_package_store_paths(dir)? {
            let members = match introspect_closure_nars(&root) {
                Ok(members) => members,
                Err(err) => {
                    printer.warning(&format!(
                        "skipping deep check for {root} (not introspectable locally): {err:#}"
                    ));
                    continue;
                }
            };
            for member in members {
                deep_checked += 1;
                let ia_hash = extract_hash(&member.path);
                let blessed = graph.blessed_nars(ia_hash);
                if blessed.is_empty() {
                    printer.warning(&format!("{}: no store/ record for {ia_hash}", member.path));
                    errors += 1;
                    continue;
                }
                if !blessed
                    .iter()
                    .any(|nar| nar.matches(&member.nar_hash, member.nar_size))
                {
                    printer.error(&format!(
                        "{}: local store content is NOT blessed (local {} / {} bytes)",
                        member.path, member.nar_hash, member.nar_size,
                    ));
                    errors += 1;
                }
            }
        }
    }

    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "action": "store_verify",
            "registry": registry_name,
            "records": graph.len(),
            "members_checked": members_checked,
            "deep_checked": deep_checked,
            "errors": errors,
        }));
    }

    if errors > 0 {
        bail!("store/ graph verification failed with {errors} error(s)");
    }
    printer.success(&format!(
        "Graph OK: {} record(s), {members_checked} closure member(s) covered{}.",
        graph.len(),
        if deep {
            format!(", {deep_checked} deep-checked")
        } else {
            String::new()
        },
    ));
    Ok(())
}

pub async fn run_cache(
    config: &ApmConfig,
    command: &CacheCommand,
    dry_run: bool,
    printer: &Printer,
) -> Result<()> {
    match command {
        CacheCommand::Generate {
            output,
            key,
            registry_key,
            registry_key_id,
            cache_url,
            upload_urls,
            auth,
            priority,
            no_commit,
            registry,
            jobs,
            no_skip,
        } => {
            let registry_name = resolve_registry_name(config, registry.as_deref())?;
            let dir = config.scope.registries_path().join(&registry_name);
            let upload_urls = resolve_upload_urls(config, &registry_name, upload_urls);
            let output = output
                .clone()
                .unwrap_or_else(|| config.registry_cache_path(&registry_name));
            if dry_run {
                if printer.mode() == OutputMode::Json {
                    printer.json(&serde_json::json!({
                        "action": "cache_generate",
                        "dry_run": true,
                        "registry": registry_name,
                        "output_dir": output.to_string_lossy().to_string(),
                        "cache_url": cache_url.as_deref(),
                        "priority": priority,
                        "upload_urls": upload_urls,
                        "uploaded": false,
                        "cache_pointer_updated": false,
                        "committed": false,
                    }));
                } else {
                    printer.info(&format!(
                        "Would generate the static cache for {registry_name} in {}",
                        output.display(),
                    ));
                }
                return Ok(());
            }
            let upload_auth =
                auth.auth_options_with_config(registry_upload_auth_config(config, &registry_name));
            let membership = if upload_urls.is_empty() || *no_skip {
                None
            } else {
                Some(
                    HeadMembership::from_urls(&upload_urls, &upload_auth)
                        .await
                        .context("creating remote cache membership checker")?,
                )
            };
            let membership = membership
                .as_ref()
                .map(|membership| membership as &dyn CacheMembership);
            let report = nixcache::generate_static_cache(
                &dir,
                &output,
                key.as_deref(),
                *priority,
                *jobs,
                membership,
                *no_skip,
                printer,
            )
            .await?;

            printer.success(&format!(
                "Generated static cache: {} narinfos, {} NARs ({} reused) in {}",
                report.narinfos,
                report.nars,
                report.local_reused,
                report.output_dir.display(),
            ));

            if !upload_urls.is_empty() {
                nixcache::upload_static_cache_to_all(
                    &output,
                    &upload_urls,
                    &upload_auth,
                    &report.root_hashes,
                    *no_skip,
                    printer,
                )
                .await?;
            }

            let mut cache_pointer_updated = false;
            let mut committed = false;
            if let Some(cache_url) = cache_url {
                if nixcache::upsert_registry_cache(&dir, cache_url, *priority)? {
                    cache_pointer_updated = true;
                    printer.info(&format!("Updated registry.toml [caches] -> {cache_url}"));
                    if !*no_commit {
                        let signing_key = resolve_cache_pointer_signing_key(
                            config,
                            &dir,
                            &registry_name,
                            registry_key.as_deref(),
                            registry_key_id.as_deref(),
                        )?;
                        commit_registry(
                            &dir,
                            "registry: update static cache pointer",
                            signing_key.as_ref().map(ResolvedSigningKey::path),
                        )?;
                        refresh_registry_object_store(&dir)
                            .context("refreshing dumb-HTTP object store after cache update")?;
                        committed = true;
                    }
                }
            }

            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "action": "cache_generate",
                    "registry": registry_name,
                    "output_dir": report.output_dir.to_string_lossy().to_string(),
                    "paths": report.paths,
                    "narinfos": report.narinfos,
                    "nars": report.nars,
                    "local_reused": report.local_reused,
                    "remote_skipped": report.remote_skipped,
                    "root_hashes": report.root_hashes,
                    "cache_url": cache_url.as_deref(),
                    "priority": priority,
                    "upload_urls": upload_urls,
                    "uploaded": !upload_urls.is_empty(),
                    "cache_pointer_updated": cache_pointer_updated,
                    "committed": committed,
                }));
            }

            warn_on_cache_gc(
                &output,
                registry_cache_max_age_days(config, &registry_name),
                printer,
            );

            Ok(())
        }
        CacheCommand::Gc {
            registry,
            max_age,
            dry_run,
        } => {
            let registry_name = resolve_registry_name(config, registry.as_deref())?;
            let output = config.registry_cache_path(&registry_name);
            let max_age_days =
                max_age.unwrap_or_else(|| registry_cache_max_age_days(config, &registry_name));
            let report = nixcache::gc_static_cache(&output, max_age_days, *dry_run)?;
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "action": "cache_gc",
                    "registry": registry_name,
                    "cache_dir": output.to_string_lossy().to_string(),
                    "max_age_days": max_age_days,
                    "dry_run": dry_run,
                    "candidates": report.candidates,
                    "deleted_files": report.deleted_files,
                    "deleted_bytes": report.deleted_bytes,
                    "deleted_bytes_human": format_size(report.deleted_bytes),
                    "hashes": report.hashes,
                }));
            } else if *dry_run {
                printer.info(&format!(
                    "Would delete {} staged cache pair(s) older than {max_age_days} day(s) from {}.",
                    report.candidates,
                    output.display(),
                ));
            } else {
                printer.success(&format!(
                    "Deleted {} staged cache file(s) ({}) from {}.",
                    report.deleted_files,
                    format_size(report.deleted_bytes),
                    output.display(),
                ));
            }
            Ok(())
        }
    }
}

/// `apr web` subcommands for the static on-CDN web surface.
///
/// `generate` renders the committed registry tree into the no-JS web
/// surface — `index.html`, `web/config.json`, `web/index.json`, per-package
/// `web/packages/<name>.json` snapshots, and `browse/<name>.html` static
/// pages — into `--output` (defaulting to a `web` directory beside the
/// registry clone), then optionally uploads it to each `--upload-url`
/// (falling back to the `upload_urls` persisted by `apr origin config` when
/// no flag is given), reusing the same static-upload path as
/// `apr cache generate` / `apr origin upload`.
///
/// The SPA dist (the WASM app) is out of scope here: this command emits the
/// content-bearing no-JS floor that the SPA progressively enhances when it
/// is dropped in alongside.
///
/// # Errors
///
/// Fails when web-surface generation or an upload fails.
pub async fn run_web(config: &ApmConfig, command: &WebCommand, printer: &Printer) -> Result<()> {
    match command {
        WebCommand::Generate {
            output,
            name,
            hub_url,
            accent,
            spa_dist,
            upload_urls,
            auth,
            registry,
        } => {
            let registry_name = resolve_registry_name(config, registry.as_deref())?;
            let dir = config.scope.registries_path().join(&registry_name);
            let output_dir = output.clone().unwrap_or_else(|| dir.join("web"));
            let upload_urls = resolve_upload_urls(config, &registry_name, upload_urls);

            let web_config = WebConfig {
                name: name.clone().unwrap_or_default(),
                accent: accent.clone(),
                hub_url: hub_url.clone(),
                spa_dist: spa_dist.clone(),
            };
            let written = webgen::generate_web_surface(&dir, &output_dir, web_config)?;

            printer.success(&format!(
                "Generated web surface: {} file(s) in {}",
                written.len(),
                output_dir.display(),
            ));

            if !upload_urls.is_empty() {
                let auth = auth
                    .auth_options_with_config(registry_upload_auth_config(config, &registry_name));
                webgen::upload_web_surface_to_all(&output_dir, &upload_urls, &auth, printer)
                    .await?;
            }

            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "action": "web_generate",
                    "registry": registry_name,
                    "output_dir": output_dir.to_string_lossy().to_string(),
                    "files": written.len(),
                    "upload_urls": upload_urls,
                    "uploaded": !upload_urls.is_empty(),
                }));
            }

            Ok(())
        }
    }
}

/// `apr origin` subcommands for the static dumb-HTTP git origin.
///
/// `prepare-index-bundles` backfills the bounded index transport in an already
/// materialized surface. `upload` refreshes the static object store indexes and uploads the
/// registry's git origin files (objects, packs, refs, channel payloads)
/// to each destination — the `--upload-url` flags, or the persisted
/// `upload_urls` defaults when no flag is given — so consumers can sync
/// from a plain file server. `config` shows or persists those producer
/// upload defaults (destinations and backend auth) in the registry's
/// `[registry.upload_auth]` section.
///
/// # Errors
///
/// Fails when a bundle surface is incomplete, when `upload` has no destination (neither `--upload-url` flags
/// nor persisted defaults), when the object-store refresh or any upload
/// fails, when `config` both sets and unsets the same field, or when
/// `config` cannot read, parse, or rewrite the registry config file.
pub async fn run_origin(
    config: &ApmConfig,
    command: &OriginCommand,
    printer: &Printer,
) -> Result<()> {
    match command {
        OriginCommand::PrepareIndexBundles { surface_dir } => {
            objectstore::write_index_bundles_for_surface(surface_dir)?;
            printer.success(&format!(
                "Prepared 256 bounded index bundles in {}.",
                surface_dir.display()
            ));
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "action": "origin_prepare_index_bundles",
                    "surface_dir": surface_dir.to_string_lossy(),
                    "bundles": 256,
                }));
            }
            Ok(())
        }
        OriginCommand::Upload {
            upload_urls,
            cache_dir,
            auth,
            registry,
        } => {
            let registry_name = resolve_registry_name(config, registry.as_deref())?;
            let upload_urls = resolve_upload_urls(config, &registry_name, upload_urls);
            if upload_urls.is_empty() {
                bail!(
                    "no upload destination: pass --upload-url <url> or persist defaults with \
                     `{} origin config --upload-url <url>`",
                    aos_core::invocation::package_registry_command(),
                );
            }
            let dir = config.scope.registries_path().join(&registry_name);
            // Ref metadata and loose-object canonicalization form one
            // publication snapshot. Keep registry writers out until every
            // destination has consumed that snapshot.
            let _publish_lock = RegistryPublishLock::acquire(&dir)?;
            refresh_registry_object_store(&dir)
                .context("refreshing static git origin before upload")?;
            let auth =
                auth.auth_options_with_config(registry_upload_auth_config(config, &registry_name));
            // When a cache dir is given, upload its bytes before the git origin
            // (NARs/narinfos before the refs that point at them), reusing the
            // ordering `upload_static_cache_to_all` already owns. This command
            // derives no roots, so every narinfo is a member (root-last
            // collapses to narinfos-after-NARs, still producer-safe). `files`
            // and `bytes` below report the git-origin surface; the cache upload
            // prints its own per-destination success line.
            if let Some(cache_dir) = cache_dir.as_deref() {
                nixcache::upload_static_cache_to_all(
                    cache_dir,
                    &upload_urls,
                    &auth,
                    &[],
                    false,
                    printer,
                )
                .await?;
            }
            let report = static_upload::upload_static_origin_to_all(
                &dir,
                &upload_urls,
                &auth,
                false,
                printer,
            )
            .await?;

            printer.success(&format!(
                "Uploaded {} static origin file(s) ({}).",
                report.files,
                format_size(report.bytes),
            ));
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "action": "origin_upload",
                    "registry": registry_name,
                    "upload_urls": upload_urls,
                    "cache_dir": cache_dir.as_ref().map(|path| path.to_string_lossy().to_string()),
                    "files": report.files,
                    "bytes": report.bytes,
                    "bytes_human": format_size(report.bytes),
                }));
            }
            Ok(())
        }
        OriginCommand::Config {
            upload_urls,
            token,
            view,
            http_user,
            http_password,
            header,
            s3_region,
            s3_profile,
            s3_endpoint,
            ssh_key,
            ssh_password,
            ssh_ask_pass,
            unset,
            registry,
        } => {
            let updates = UploadConfigUpdates {
                upload_urls,
                token: token.as_deref(),
                view: view.as_deref(),
                http_user: http_user.as_deref(),
                http_password: http_password.as_deref(),
                headers: header,
                s3_region: s3_region.as_deref(),
                s3_profile: s3_profile.as_deref(),
                s3_endpoint: s3_endpoint.as_deref(),
                ssh_key: ssh_key.as_deref(),
                ssh_password: ssh_password.as_deref(),
                ssh_ask_pass: *ssh_ask_pass,
            };
            origin_config(config, &updates, unset, registry.as_deref(), printer)
        }
    }
}

/// The `apr origin config` setter flags, grouped so [`origin_config`] can
/// treat "no flag given" uniformly across scalar, list, and boolean fields.
struct UploadConfigUpdates<'a> {
    /// Replacement default destinations; empty means "not given".
    upload_urls: &'a [String],
    token: Option<&'a str>,
    view: Option<&'a str>,
    http_user: Option<&'a str>,
    http_password: Option<&'a str>,
    /// Replacement extra HTTP headers; empty means "not given".
    headers: &'a [String],
    s3_region: Option<&'a str>,
    s3_profile: Option<&'a str>,
    s3_endpoint: Option<&'a str>,
    ssh_key: Option<&'a str>,
    ssh_password: Option<&'a str>,
    /// `--ssh-ask-pass` was passed; `false` means "leave unchanged".
    ssh_ask_pass: bool,
}

impl UploadConfigUpdates<'_> {
    /// Whether any setter flag was given at all.
    fn is_empty(&self) -> bool {
        self.upload_urls.is_empty()
            && self.token.is_none()
            && self.view.is_none()
            && self.http_user.is_none()
            && self.http_password.is_none()
            && self.headers.is_empty()
            && self.s3_region.is_none()
            && self.s3_profile.is_none()
            && self.s3_endpoint.is_none()
            && self.ssh_key.is_none()
            && self.ssh_password.is_none()
            && !self.ssh_ask_pass
    }

    /// Whether the setter for `field` was given (used to refuse a
    /// simultaneous `--unset` of the same field).
    fn sets(&self, field: UploadConfigField) -> bool {
        match field {
            UploadConfigField::UploadUrls => !self.upload_urls.is_empty(),
            UploadConfigField::Token => self.token.is_some(),
            UploadConfigField::View => self.view.is_some(),
            UploadConfigField::HttpUser => self.http_user.is_some(),
            UploadConfigField::HttpPassword => self.http_password.is_some(),
            UploadConfigField::Headers => !self.headers.is_empty(),
            UploadConfigField::S3Region => self.s3_region.is_some(),
            UploadConfigField::S3Profile => self.s3_profile.is_some(),
            UploadConfigField::S3Endpoint => self.s3_endpoint.is_some(),
            UploadConfigField::SshKey => self.ssh_key.is_some(),
            UploadConfigField::SshPassword => self.ssh_password.is_some(),
            UploadConfigField::SshAskPass => self.ssh_ask_pass,
        }
    }

    /// Apply every given setter onto `upload`.
    fn apply(&self, upload: &mut RegistryUploadAuthConfig) {
        if !self.upload_urls.is_empty() {
            upload.upload_urls = self.upload_urls.to_vec();
        }
        if let Some(token) = self.token {
            upload.token = Some(token.to_string());
        }
        if let Some(view) = self.view {
            upload.view = Some(view.to_string());
        }
        if let Some(http_user) = self.http_user {
            upload.http_user = Some(http_user.to_string());
        }
        if let Some(http_password) = self.http_password {
            upload.http_password = Some(http_password.to_string());
        }
        if !self.headers.is_empty() {
            upload.headers = self.headers.to_vec();
        }
        if let Some(s3_region) = self.s3_region {
            upload.s3_region = Some(s3_region.to_string());
        }
        if let Some(s3_profile) = self.s3_profile {
            upload.s3_profile = Some(s3_profile.to_string());
        }
        if let Some(s3_endpoint) = self.s3_endpoint {
            upload.s3_endpoint = Some(s3_endpoint.to_string());
        }
        if let Some(ssh_key) = self.ssh_key {
            upload.ssh_key = Some(ssh_key.to_string());
        }
        if let Some(ssh_password) = self.ssh_password {
            upload.ssh_password = Some(ssh_password.to_string());
        }
        if self.ssh_ask_pass {
            upload.ssh_ask_pass = true;
        }
    }
}

/// Clear `field` on `upload` (the `--unset` half of `apr origin config`).
fn unset_upload_config_field(upload: &mut RegistryUploadAuthConfig, field: UploadConfigField) {
    match field {
        UploadConfigField::UploadUrls => upload.upload_urls.clear(),
        UploadConfigField::Token => upload.token = None,
        UploadConfigField::View => upload.view = None,
        UploadConfigField::HttpUser => upload.http_user = None,
        UploadConfigField::HttpPassword => upload.http_password = None,
        UploadConfigField::Headers => upload.headers.clear(),
        UploadConfigField::S3Region => upload.s3_region = None,
        UploadConfigField::S3Profile => upload.s3_profile = None,
        UploadConfigField::S3Endpoint => upload.s3_endpoint = None,
        UploadConfigField::SshKey => upload.ssh_key = None,
        UploadConfigField::SshPassword => upload.ssh_password = None,
        UploadConfigField::SshAskPass => upload.ssh_ask_pass = false,
    }
}

/// `apr origin config` — shows or persists the producer upload defaults in
/// the registry's `[registry.upload_auth]` section.
///
/// With no setter or `--unset` flag, prints the currently persisted
/// defaults. Otherwise each given setter replaces the stored value (lists
/// — `--upload-url`, `--header` — are replaced wholesale, not appended),
/// each `--unset FIELD` clears the stored value, and the section is
/// rewritten in place, preserving every other field of the config file.
/// Unsetting the last stored field removes the whole section.
///
/// Unlike the flags on `origin upload`/`cache generate`/`release`, the
/// setters here read nothing from the environment: only values given
/// explicitly on the command line are persisted.
///
/// # Errors
///
/// Fails when the same field is both set and `--unset` in one invocation;
/// when the registry has no `registries.d` config to record into (created
/// by `apr add`); or when the config file cannot be read, parsed, or
/// rewritten.
fn origin_config(
    config: &ApmConfig,
    updates: &UploadConfigUpdates<'_>,
    unset: &[UploadConfigField],
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let registry_name = resolve_registry_name(config, registry)?;
    let config_path = config.registry_config_path_for_update(&registry_name);
    if !config_path.exists() {
        bail!(
            "registry '{registry_name}' has no config at {}; register the registry first with \
             `{} add <url>`, then re-run this command",
            config_path.display(),
            aos_core::invocation::package_registry_command(),
        );
    }

    let content = std::fs::read_to_string(&config_path)
        .with_context(|| format!("reading {}", config_path.display()))?;
    let rf: RegistryFile =
        toml::from_str(&content).with_context(|| format!("parsing {}", config_path.display()))?;
    let mut upload = rf.registry.upload_auth.unwrap_or_default();

    if updates.is_empty() && unset.is_empty() {
        print_upload_config(&registry_name, &config_path, &upload, printer);
        return Ok(());
    }

    for field in unset {
        if updates.sets(*field) {
            bail!(
                "cannot both set and --unset '{}' in the same invocation",
                field.to_possible_value().map_or_else(
                    || format!("{field:?}"),
                    |value| value.get_name().to_string(),
                ),
            );
        }
        unset_upload_config_field(&mut upload, *field);
    }
    updates.apply(&mut upload);

    state::save_upload_auth(&config_path, &upload)?;
    printer.success(&format!(
        "Updated upload defaults for registry '{registry_name}'.",
    ));
    print_upload_config(&registry_name, &config_path, &upload, printer);
    Ok(())
}

/// Print the persisted upload defaults, as key/value lines or JSON.
fn print_upload_config(
    registry_name: &str,
    config_path: &Path,
    upload: &RegistryUploadAuthConfig,
    printer: &Printer,
) {
    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "action": "origin_config",
            "registry": registry_name,
            "config": config_path.display().to_string(),
            "upload_auth": upload,
        }));
        return;
    }

    printer.kv("Config", &config_path.display().to_string());
    if *upload == RegistryUploadAuthConfig::default() {
        printer.info("No upload defaults configured.");
        return;
    }
    if !upload.upload_urls.is_empty() {
        printer.kv("Upload URLs", &upload.upload_urls.join(", "));
    }
    let scalar_fields = [
        ("Token", &upload.token),
        ("View", &upload.view),
        ("HTTP user", &upload.http_user),
        ("HTTP password", &upload.http_password),
    ];
    for (label, value) in scalar_fields {
        if let Some(value) = value {
            printer.kv(label, value);
        }
    }
    if !upload.headers.is_empty() {
        printer.kv("Headers", &upload.headers.join(", "));
    }
    let scalar_fields = [
        ("S3 region", &upload.s3_region),
        ("S3 profile", &upload.s3_profile),
        ("S3 endpoint", &upload.s3_endpoint),
        ("SSH key", &upload.ssh_key),
        ("SSH password", &upload.ssh_password),
    ];
    for (label, value) in scalar_fields {
        if let Some(value) = value {
            printer.kv(label, value);
        }
    }
    if upload.ssh_ask_pass {
        printer.kv("SSH ask pass", "true");
    }
}

/// `apr trust` subcommands for the consumer-side pinned trust store.
///
/// `pin` stores a `registry:Ed25519:<base64>` public key for a registry
/// (`--replace` drops existing pins first), `list` shows the pinned keys
/// per registry, and `remove` deletes a registry's pins.
///
/// # Errors
///
/// Fails when the registry name is not safe for trusted-key path use, the key
/// line does not parse or names a different registry, or the trust store
/// cannot be read or written.
pub fn run_trust(config: &ApmConfig, command: &TrustCommand, printer: &Printer) -> Result<()> {
    let store = KeyStore::new(config.scope.trusted_keys_dirs());
    match command {
        TrustCommand::Pin {
            registry,
            key,
            replace,
        } => {
            validate_registry_name(registry)?;
            let trusted = trusted_key_from_line(registry, key)?;
            if *replace {
                let _ = store.remove(registry)?;
            }
            store.store(&trusted)?;
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "action": "trust_pin",
                    "status": if *replace { "replaced" } else { "pinned" },
                    "registry": registry,
                    "replace": *replace,
                    "key": key,
                    "algorithm": trusted.algorithm,
                    "fingerprint": trusted.fingerprint,
                    "source": format!("{:?}", trusted.source),
                }));
                return Ok(());
            }
            let action = if *replace { "Re-pinned" } else { "Pinned" };
            printer.success(&format!(
                "{action} trust key for registry '{}' ({})",
                registry, trusted.fingerprint
            ));
            Ok(())
        }
        TrustCommand::List { registry } => {
            let registries = match registry {
                Some(name) => {
                    validate_registry_name(name)?;
                    vec![name.clone()]
                }
                None => configured_registry_names(config),
            };
            if printer.mode() == OutputMode::Json {
                let entries = registries
                    .iter()
                    .map(|name| {
                        let keys = store
                            .lookup_all(name)
                            .iter()
                            .map(|key| {
                                serde_json::json!({
                                    "algorithm": &key.algorithm,
                                    "fingerprint": &key.fingerprint,
                                    "source": format!("{:?}", key.source),
                                })
                            })
                            .collect::<Vec<_>>();
                        serde_json::json!({
                            "registry": name,
                            "keys": keys,
                        })
                    })
                    .collect::<Vec<_>>();
                printer.json(&serde_json::json!(entries));
                return Ok(());
            }
            if registries.is_empty() {
                printer.info("No configured registries to inspect.");
                return Ok(());
            }
            for name in registries {
                let keys = store.lookup_all(&name);
                if keys.is_empty() {
                    printer.plain(&format!("{name}: no pinned keys"));
                    continue;
                }
                for key in keys {
                    printer.plain(&format!(
                        "{}: {} {} ({:?})",
                        name, key.algorithm, key.fingerprint, key.source
                    ));
                }
            }
            Ok(())
        }
        TrustCommand::Remove { registry } => {
            validate_registry_name(registry)?;
            let removed = store.remove(registry)?;
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "action": "trust_remove",
                    "status": if removed { "removed" } else { "current" },
                    "registry": registry,
                    "removed": removed,
                }));
                return Ok(());
            }
            if removed {
                printer.success(&format!(
                    "Removed pinned trust keys for registry '{registry}'"
                ));
            } else {
                printer.info(&format!(
                    "No pinned trust keys found for registry '{registry}'"
                ));
            }
            Ok(())
        }
    }
}

/// `apr keys` subcommands for the committed `keys.toml` signing roster.
///
/// `list` prints active and revoked keys with fingerprints; `generate`
/// creates a new maintainer keypair; `register` adopts an externally-held
/// key without persisting key material; `add` appends a public key to the
/// active roster; `retire` moves a key to the revoked list and re-signs
/// every release tag and channel partition the retired key still covered
/// (the vouching survivor signs by default; `--no-resign` prints the plan
/// instead of executing it).
///
/// Roster-changing commits must be signed by an active maintainer key
/// whenever the roster was already non-empty, because clients verify
/// head-commit signatures against the keys they currently trust.
///
/// # Errors
///
/// Fails when a key id is invalid, duplicated, or revoked; when a
/// retirement would leave no active survivor key; when the commit signing
/// key cannot be resolved; or when the roster write, commit, re-signing,
/// or object-store refresh fails.
pub fn run_keys(config: &ApmConfig, command: &KeysCommand, printer: &Printer) -> Result<()> {
    match command {
        KeysCommand::List { registry } => {
            let registry_name = resolve_registry_name(config, registry.as_deref())?;
            let dir = config.scope.registries_path().join(&registry_name);
            let roster = load_committed_roster(&dir)?;
            if printer.mode() == OutputMode::Json {
                let active = roster
                    .active
                    .iter()
                    .map(|entry| {
                        let (_registry, algorithm, public_key) = parse_signing_key(&entry.key)
                            .with_context(|| format!("invalid active key '{}'", entry.id))?;
                        Ok(serde_json::json!({
                            "id": &entry.id,
                            "algorithm": algorithm,
                            "fingerprint": key_fingerprint(&public_key),
                            "key": &entry.key,
                        }))
                    })
                    .collect::<Result<Vec<_>>>()?;
                let revoked = roster
                    .revoked
                    .iter()
                    .map(|entry| {
                        serde_json::json!({
                            "id": &entry.id,
                            "reason": &entry.reason,
                        })
                    })
                    .collect::<Vec<_>>();
                printer.json(&serde_json::json!({
                    "registry": registry_name,
                    "active": active,
                    "revoked": revoked,
                }));
                return Ok(());
            }
            if roster.active.is_empty() && roster.revoked.is_empty() {
                printer.info(&format!(
                    "Registry '{registry_name}' has no keys in keys.toml."
                ));
                return Ok(());
            }

            printer.header(&format!("keys.toml for registry '{registry_name}'"));
            if roster.active.is_empty() {
                printer.plain("active: none");
            } else {
                printer.plain("active:");
                for entry in &roster.active {
                    let (_registry, algorithm, public_key) = parse_signing_key(&entry.key)
                        .with_context(|| format!("invalid active key '{}'", entry.id))?;
                    printer.plain(&format!(
                        "  {}: {} {}",
                        entry.id,
                        algorithm,
                        key_fingerprint(&public_key),
                    ));
                }
            }

            if roster.revoked.is_empty() {
                printer.plain("revoked: none");
            } else {
                printer.plain("revoked:");
                for entry in &roster.revoked {
                    if let Some(reason) = &entry.reason {
                        printer.plain(&format!("  {}: {}", entry.id, reason));
                    } else {
                        printer.plain(&format!("  {}", entry.id));
                    }
                }
            }
            Ok(())
        }
        KeysCommand::Generate {
            id,
            add,
            no_commit,
            signing_key,
            signing_key_id,
            registry,
        } => generate_roster_key(
            config,
            id,
            *add,
            *no_commit,
            signing_key.as_deref(),
            signing_key_id.as_deref(),
            registry.as_deref(),
            printer,
        ),
        KeysCommand::Register {
            id,
            key,
            key_command,
            registry,
        } => register_roster_key(
            config,
            id,
            key.as_deref(),
            key_command.as_deref(),
            registry.as_deref(),
            printer,
        ),
        KeysCommand::Add {
            id,
            key,
            no_commit,
            signing_key,
            signing_key_id,
            registry,
        } => {
            let registry_name = resolve_registry_name(config, registry.as_deref())?;
            let dir = config.scope.registries_path().join(&registry_name);
            let mut roster = load_committed_roster(&dir)?;
            let commit_key = if *no_commit {
                None
            } else {
                resolve_roster_commit_key(
                    config,
                    &dir,
                    &registry_name,
                    &roster,
                    signing_key.as_deref(),
                    signing_key_id.as_deref(),
                )?
            };
            add_roster_key(&mut roster, &registry_name, id, key)?;
            persist_committed_roster(
                &dir,
                &roster,
                *no_commit,
                &format!("registry: add signing key {id}"),
                commit_key.as_ref().map(|k| k.path()),
            )?;
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "action": "keys_add",
                    "status": "added",
                    "registry": registry_name,
                    "id": id,
                    "key": key,
                    "committed": !*no_commit,
                }));
                return Ok(());
            }
            printer.success(&format!(
                "Added active signing key '{id}' to registry '{registry_name}'."
            ));
            Ok(())
        }
        KeysCommand::Retire {
            id,
            reason,
            vouched_by,
            no_commit,
            signing_key,
            signing_key_id,
            no_resign,
            registry,
        } => {
            let registry_name = resolve_registry_name(config, registry.as_deref())?;
            let dir = config.scope.registries_path().join(&registry_name);
            let mut roster = load_committed_roster(&dir)?;
            let roster_before = roster.clone();
            let provenance_before_sequence = read_package_provenance_transparency_log_state(
                &dir.join(PACKAGE_PROVENANCE_TRANSPARENCY_LOG),
            )?
            .0;
            let vouching_id = retire_roster_key(
                &mut roster,
                id,
                reason.as_deref(),
                vouched_by,
                provenance_before_sequence,
            )?;
            // The vouching survivor signs the retirement by default; the
            // key resolution runs against the pre-retire roster, where the
            // voucher is still active. Re-signing also needs this key, so
            // resolution failures abort before anything is modified.
            let signer = if *no_commit && *no_resign {
                None
            } else if signing_key.is_none() && signing_key_id.is_none() {
                Some(resolve_producer_signing_key(
                    config,
                    &dir,
                    &registry_name,
                    None,
                    Some(&vouching_id),
                )?)
            } else {
                resolve_roster_commit_key(
                    config,
                    &dir,
                    &registry_name,
                    &roster_before,
                    signing_key.as_deref(),
                    signing_key_id.as_deref(),
                )?
            };
            // Signatures by the retired key become invalid on clients, so
            // every tag a client still resolves must be re-signed by a
            // survivor. Plan against the post-retirement active set before
            // mutating anything.
            let survivors: Vec<String> = roster
                .active
                .iter()
                .map(|entry| entry.key.clone())
                .collect();
            let plan = plan_retirement_resign(&dir, &survivors)?;
            persist_committed_roster(
                &dir,
                &roster,
                *no_commit,
                &format!("registry: retire signing key {id}"),
                if *no_commit {
                    None
                } else {
                    signer.as_ref().map(|k| k.path())
                },
            )?;
            if *no_resign {
                print_resign_plan(&plan, printer);
            } else if let Some(vouch_key) = signer.as_ref().map(|k| k.path()) {
                execute_retirement_resign(&dir, &plan, vouch_key, printer)?;
            }
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "action": "keys_retire",
                    "status": "retired",
                    "registry": registry_name,
                    "id": id,
                    "reason": reason.as_deref(),
                    "vouched_by": vouching_id,
                    "committed": !*no_commit,
                    "resigned": !*no_resign,
                    "resign_plan": resign_plan_json(&plan),
                }));
                return Ok(());
            }
            printer.success(&format!(
                "Retired signing key '{id}' from registry '{registry_name}' (vouched by '{vouching_id}')."
            ));
            Ok(())
        }
    }
}

/// `apr sb-certs ...` — manage the committed Secure Boot validation catalog.
///
/// Mutates the `sb-certs.toml` roster in an authoring clone (RFC-0006 phase
/// 4): the active db-cert set, its revocations, and the per-component SBAT
/// revocation floor. Each mutation loads-or-creates the catalog, applies the
/// change, and writes it back via
/// [`crate::registry::sb_certs::write_sb_certs_toml`]. Unless `--no-commit`
/// is given the change is committed (optionally signed by an active
/// `keys.toml` maintainer key) the same way `keys.toml` changes are, so the
/// catalog stays covered by the registry's release signature and reaches
/// consumers on their next `apm update`.
///
/// # Errors
///
/// Returns an error when the registry name cannot be resolved, the clone is
/// not writable, the catalog fails validation, the commit-signing key cannot
/// be resolved, or the write/commit fails.
pub fn run_sb_certs(config: &ApmConfig, command: &SbCertsCommand, printer: &Printer) -> Result<()> {
    match command {
        SbCertsCommand::List { registry } => {
            let registry_name = resolve_registry_name(config, registry.as_deref())?;
            let dir = config.scope.registries_path().join(&registry_name);
            let catalog = load_committed_sb_certs(&dir)?;
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "registry": registry_name,
                    "active": catalog.active.iter().map(|c| serde_json::json!({
                        "id": c.id,
                        "cert_sha256": c.cert_sha256,
                    })).collect::<Vec<_>>(),
                    "revoked": catalog.revoked.iter().map(|r| serde_json::json!({
                        "id": r.id,
                        "reason": r.reason,
                    })).collect::<Vec<_>>(),
                    "sbat_floor": catalog.sbat_floor.iter().map(|f| serde_json::json!({
                        "component": f.component,
                        "generation": f.generation,
                    })).collect::<Vec<_>>(),
                }));
                return Ok(());
            }
            if catalog.active.is_empty()
                && catalog.revoked.is_empty()
                && catalog.sbat_floor.is_empty()
            {
                printer.info(&format!(
                    "Registry '{registry_name}' has no Secure Boot catalog (sb-certs.toml)."
                ));
                return Ok(());
            }
            printer.header(&format!("sb-certs.toml for registry '{registry_name}'"));
            if catalog.active.is_empty() {
                printer.plain("active: none");
            } else {
                printer.plain("active:");
                for cert in &catalog.active {
                    printer.plain(&format!("  {}: {}", cert.id, cert.cert_sha256));
                }
            }
            if catalog.revoked.is_empty() {
                printer.plain("revoked: none");
            } else {
                printer.plain("revoked:");
                for rev in &catalog.revoked {
                    match &rev.reason {
                        Some(reason) => printer.plain(&format!("  {}: {}", rev.id, reason)),
                        None => printer.plain(&format!("  {}", rev.id)),
                    }
                }
            }
            if catalog.sbat_floor.is_empty() {
                printer.plain("sbat_floor: none");
            } else {
                printer.plain("sbat_floor:");
                for entry in &catalog.sbat_floor {
                    printer.plain(&format!("  {}: {}", entry.component, entry.generation));
                }
            }
            Ok(())
        }
        SbCertsCommand::Add {
            id,
            cert_sha256,
            no_commit,
            signing_key,
            signing_key_id,
            registry,
        } => {
            let (registry_name, dir) = resolve_sb_certs_target(config, registry.as_deref())?;
            let mut catalog = load_committed_sb_certs(&dir)?;
            let commit_key = sb_certs_commit_key(
                config,
                &dir,
                &registry_name,
                *no_commit,
                signing_key.as_deref(),
                signing_key_id.as_deref(),
            )?;
            add_sb_cert(&mut catalog, id, cert_sha256)?;
            persist_committed_sb_certs(
                &dir,
                &catalog,
                *no_commit,
                &format!("registry: add Secure Boot db cert {id}"),
                commit_key.as_ref().map(|k| k.path()),
            )?;
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "action": "sb_certs_add",
                    "status": "added",
                    "registry": registry_name,
                    "id": id,
                    "cert_sha256": cert_sha256,
                    "committed": !*no_commit,
                }));
                return Ok(());
            }
            printer.success(&format!(
                "Added active Secure Boot db cert '{id}' to registry '{registry_name}'."
            ));
            Ok(())
        }
        SbCertsCommand::Retire {
            id,
            reason,
            no_commit,
            signing_key,
            signing_key_id,
            registry,
        } => {
            let (registry_name, dir) = resolve_sb_certs_target(config, registry.as_deref())?;
            let mut catalog = load_committed_sb_certs(&dir)?;
            let commit_key = sb_certs_commit_key(
                config,
                &dir,
                &registry_name,
                *no_commit,
                signing_key.as_deref(),
                signing_key_id.as_deref(),
            )?;
            retire_sb_cert(&mut catalog, id, reason.as_deref())?;
            persist_committed_sb_certs(
                &dir,
                &catalog,
                *no_commit,
                &format!("registry: retire Secure Boot db cert {id}"),
                commit_key.as_ref().map(|k| k.path()),
            )?;
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "action": "sb_certs_retire",
                    "status": "retired",
                    "registry": registry_name,
                    "id": id,
                    "reason": reason.as_deref(),
                    "committed": !*no_commit,
                }));
                return Ok(());
            }
            printer.success(&format!(
                "Retired Secure Boot db cert '{id}' from registry '{registry_name}'."
            ));
            Ok(())
        }
        SbCertsCommand::SetFloor {
            component,
            generation,
            no_commit,
            signing_key,
            signing_key_id,
            registry,
        } => {
            let (registry_name, dir) = resolve_sb_certs_target(config, registry.as_deref())?;
            let mut catalog = load_committed_sb_certs(&dir)?;
            let commit_key = sb_certs_commit_key(
                config,
                &dir,
                &registry_name,
                *no_commit,
                signing_key.as_deref(),
                signing_key_id.as_deref(),
            )?;
            set_sbat_floor(&mut catalog, component, *generation)?;
            persist_committed_sb_certs(
                &dir,
                &catalog,
                *no_commit,
                &format!("registry: set SBAT floor {component}={generation}"),
                commit_key.as_ref().map(|k| k.path()),
            )?;
            if printer.mode() == OutputMode::Json {
                printer.json(&serde_json::json!({
                    "action": "sb_certs_set_floor",
                    "status": "set",
                    "registry": registry_name,
                    "component": component,
                    "generation": generation,
                    "committed": !*no_commit,
                }));
                return Ok(());
            }
            printer.success(&format!(
                "Set SBAT revocation floor '{component}' = {generation} for registry '{registry_name}'."
            ));
            Ok(())
        }
    }
}

/// Resolve the registry name and require a writable authoring clone for an
/// `apr sb-certs` mutation.
fn resolve_sb_certs_target(
    config: &ApmConfig,
    registry: Option<&str>,
) -> Result<(String, PathBuf)> {
    let registry_name = resolve_registry_name(config, registry)?;
    let dir = config.scope.registries_path().join(&registry_name);
    ensure_writable_registry_clone(&registry_name, &dir)?;
    Ok((registry_name, dir))
}

/// Load the committed `sb-certs.toml` catalog, defaulting to an empty
/// catalog when the file does not exist yet.
///
/// # Errors
///
/// Returns an error when the registry directory is missing or the catalog
/// fails to load/validate.
fn load_committed_sb_certs(dir: &Path) -> Result<SbCertsToml> {
    if !dir.exists() {
        bail!("registry directory does not exist: {}", dir.display());
    }
    Ok(sb_certs::load_sb_certs_toml(dir)?.unwrap_or_default())
}

/// Write `sb-certs.toml` and, unless `no_commit`, commit and refresh the
/// dumb-HTTP object store — the same persistence path `keys.toml` uses.
///
/// # Errors
///
/// Returns an error when the catalog fails validation, the write fails, or
/// the commit/object-store refresh fails.
fn persist_committed_sb_certs(
    dir: &Path,
    catalog: &SbCertsToml,
    no_commit: bool,
    message: &str,
    signing_key: Option<&str>,
) -> Result<()> {
    sb_certs::write_sb_certs_toml(dir, catalog)?;
    if !no_commit {
        commit_registry(dir, message, signing_key)?;
        refresh_registry_object_store(dir)
            .context("refreshing dumb-HTTP object store after sb-certs.toml update")?;
    }
    Ok(())
}

/// Resolve the maintainer key that signs an `sb-certs.toml` commit.
///
/// The catalog is part of the signed tree, so its commits must be signed by
/// an active `keys.toml` maintainer key exactly like a roster change. This
/// reuses [`resolve_roster_commit_key`] against the committed `keys.toml`:
/// the only unsigned case is a registry whose key roster is still empty
/// (bootstrap). Returns `None` when `no_commit` is set.
///
/// # Errors
///
/// Returns an error when the key roster is non-empty but no signing key was
/// provided, or the requested key cannot be resolved.
fn sb_certs_commit_key(
    config: &ApmConfig,
    dir: &Path,
    registry_name: &str,
    no_commit: bool,
    signing_key: Option<&str>,
    signing_key_id: Option<&str>,
) -> Result<Option<ResolvedSigningKey>> {
    if no_commit {
        return Ok(None);
    }
    let roster = load_committed_roster(dir)?;
    resolve_roster_commit_key(
        config,
        dir,
        registry_name,
        &roster,
        signing_key,
        signing_key_id,
    )
}

/// Append an active db cert after validating the id is non-empty and unused
/// and the digest is a 64-char lowercase hex SHA-256.
///
/// # Errors
///
/// Returns an error when the id is empty or already present, the digest is
/// malformed, or the same digest is already enrolled under another id.
fn add_sb_cert(catalog: &mut SbCertsToml, id: &str, cert_sha256: &str) -> Result<()> {
    if id.is_empty() {
        bail!("Secure Boot db cert id is empty");
    }
    let digest = cert_sha256.to_ascii_lowercase();
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("--cert-sha256 must be a 64-character hex SHA-256 digest, got '{cert_sha256}'");
    }
    if catalog.active.iter().any(|c| c.id == id) {
        bail!("active db cert id '{id}' already exists in sb-certs.toml");
    }
    if catalog
        .active
        .iter()
        .any(|c| c.cert_sha256.eq_ignore_ascii_case(&digest))
    {
        bail!("db cert digest already enrolled in sb-certs.toml under another id");
    }
    catalog.active.push(SbCert {
        id: id.to_string(),
        cert_sha256: digest,
    });
    Ok(())
}

/// Move db cert `id` into the revoked set.
///
/// The id must name an active db cert; an already-revoked id is rejected.
/// The cert stays under `[[active]]` (as `validate_catalog` requires every
/// revocation to reference an active entry) and gains a `[[revoked]]` row.
///
/// # Errors
///
/// Returns an error when `id` is empty, is not active, or is already
/// revoked.
fn retire_sb_cert(catalog: &mut SbCertsToml, id: &str, reason: Option<&str>) -> Result<()> {
    if id.is_empty() {
        bail!("Secure Boot db cert id is empty");
    }
    if !catalog.active.iter().any(|c| c.id == id) {
        bail!("db cert id '{id}' is not active in sb-certs.toml");
    }
    if catalog.revoked.iter().any(|r| r.id == id) {
        bail!("db cert id '{id}' is already revoked in sb-certs.toml");
    }
    catalog.revoked.push(RevokedSbCert {
        id: id.to_string(),
        reason: reason.map(str::to_string),
    });
    Ok(())
}

/// Set or raise the SBAT revocation floor for `component`.
///
/// A floor may only be raised, never lowered: lowering would re-admit a
/// component the fleet already revoked. An absent component is inserted.
///
/// # Errors
///
/// Returns an error when `component` is empty or the requested generation is
/// below the existing floor.
fn set_sbat_floor(catalog: &mut SbCertsToml, component: &str, generation: u32) -> Result<()> {
    if component.is_empty() {
        bail!("SBAT floor component is empty");
    }
    if let Some(entry) = catalog
        .sbat_floor
        .iter_mut()
        .find(|entry| entry.component == component)
    {
        if generation < entry.generation {
            bail!(
                "refusing to lower the SBAT floor for '{component}' from {} to {generation}: \
                 a floor may only be raised",
                entry.generation,
            );
        }
        entry.generation = generation;
    } else {
        catalog.sbat_floor.push(SbatEntry {
            component: component.to_string(),
            generation,
        });
    }
    Ok(())
}

/// Tags whose signatures must be refreshed after a key retirement.
///
/// `affected_partitions` carries the release each partition payload must
/// be rewritten against, captured *before* release tags are force-retagged
/// (re-signing changes the tag-object id, which would otherwise orphan the
/// payload's reference).
struct ResignPlan {
    affected_releases: Vec<semver::Version>,
    affected_partitions: Vec<(String, u8, semver::Version)>,
}

impl ResignPlan {
    fn is_empty(&self) -> bool {
        self.affected_releases.is_empty() && self.affected_partitions.is_empty()
    }
}

/// Enumerate the tags clients resolve and check which no longer verify
/// against the surviving active keys.
///
/// Covers every channel partition payload under `.git/channels/` and each
/// release tag those partitions reference. A partition is also marked
/// affected when its release tag must be re-signed: the new release tag
/// object gets a different id, so the payload has to be regenerated even
/// when its own signature is fine.
fn plan_retirement_resign(dir: &Path, survivors: &[String]) -> Result<ResignPlan> {
    let release_tags = semver_tag_object_map(dir)?;
    let git_dir = objectstore::repo_git_dir(dir)?;
    let channels_dir = git_dir.join("channels");

    // (channel, bucket, version, payload signature fails against survivors)
    let mut partitions: Vec<(String, u8, semver::Version, bool)> = Vec::new();
    if channels_dir.exists() {
        let mut channel_names: Vec<String> = Vec::new();
        for entry in std::fs::read_dir(&channels_dir)
            .with_context(|| format!("reading {}", channels_dir.display()))?
        {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                channel_names.push(entry.file_name().to_string_lossy().into_owned());
            }
        }
        channel_names.sort();
        for channel_name in channel_names {
            let channel_dir = channels_dir.join(&channel_name);
            for bucket in 0..=u8::MAX {
                let path = channel_dir.join(channel::bucket_hex(bucket));
                if !path.exists() {
                    continue;
                }
                let payload =
                    std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
                let tag = parse_tag_object(&String::from_utf8_lossy(&payload))
                    .with_context(|| format!("parsing channel partition {}", path.display()))?;
                let version = release_tags.get(&tag.object).ok_or_else(|| {
                    anyhow::anyhow!(
                        "channel partition {} points at unknown release tag object {}",
                        path.display(),
                        tag.object,
                    )
                })?;
                let oid = hash_tag_object(dir, &payload)?;
                let verified = verify_tag_signature(dir, &oid, survivors)?;
                partitions.push((channel_name.clone(), bucket, version.clone(), !verified));
            }
        }
    }

    let mut release_versions: Vec<semver::Version> = release_tags.values().cloned().collect();
    release_versions.sort();
    release_versions.dedup();

    let mut affected_releases: Vec<semver::Version> = Vec::new();
    for version in release_versions {
        if !verify_tag_signature(dir, &version.to_string(), survivors)? {
            affected_releases.push(version);
        }
    }
    affected_releases.sort();

    let affected_partitions = partitions
        .into_iter()
        .filter(|(_, _, version, failing)| *failing || affected_releases.contains(version))
        .map(|(channel, bucket, version, _)| (channel, bucket, version))
        .collect();

    Ok(ResignPlan {
        affected_releases,
        affected_partitions,
    })
}

/// Re-sign every affected tag with the vouching survivor's private key.
///
/// Release tags are force-retagged against their original commit and
/// message; affected channel partitions are regenerated against the new
/// tag objects, and each touched channel's branch head and object store
/// are refreshed.
fn execute_retirement_resign(
    dir: &Path,
    plan: &ResignPlan,
    vouch_key: &str,
    printer: &Printer,
) -> Result<()> {
    if plan.is_empty() {
        return Ok(());
    }

    for version in &plan.affected_releases {
        let tag = version.to_string();
        let commit = release_commit(dir, version)?;
        let payload = git(dir, &["cat-file", "-p", &format!("{tag}^{{tag}}")])?;
        let message = tag_message_without_signature(&payload);
        sign_tag(dir, &tag, &commit, message.as_deref(), vouch_key, true)?;
        printer.info(&format!("Re-signed release tag {tag}."));
    }

    let mut touched_channels: Vec<&str> = Vec::new();
    for (channel_name, bucket, version) in &plan.affected_partitions {
        write_channel_partition_tag(dir, channel_name, *bucket, version, vouch_key)?;
        if !touched_channels.contains(&channel_name.as_str()) {
            touched_channels.push(channel_name);
        }
    }
    for channel_name in touched_channels {
        let map = read_channel_partition_map(dir, channel_name)?;
        update_channel_frontier(dir, channel_name, &map)?;
        printer.info(&format!("Re-signed channel '{channel_name}' partitions."));
    }

    refresh_registry_object_store(dir)
        .context("refreshing dumb-HTTP object store after key-retirement re-sign")?;
    Ok(())
}

/// Print the re-sign plan for manual handling (`--no-resign`).
fn print_resign_plan(plan: &ResignPlan, printer: &Printer) {
    if plan.is_empty() {
        printer.info("No tags need re-signing.");
        return;
    }
    printer.warning("Skipped re-signing (--no-resign). Affected tags:");
    for version in &plan.affected_releases {
        printer.plain(&format!("  release tag {version}"));
    }
    for (channel, bucket, version) in &plan.affected_partitions {
        printer.plain(&format!(
            "  channel {channel} partition {} -> {version}",
            channel::bucket_hex(*bucket),
        ));
    }
}

fn resign_plan_json(plan: &ResignPlan) -> serde_json::Value {
    let partitions = plan
        .affected_partitions
        .iter()
        .map(|(channel, bucket, version)| {
            serde_json::json!({
                "channel": channel,
                "bucket": *bucket,
                "bucket_hex": channel::bucket_hex(*bucket),
                "version": version.to_string(),
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "release_tags": plan
            .affected_releases
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        "channel_partitions": partitions,
    })
}

/// Extract a signed tag's original message, dropping the SSH signature
/// block git appends to the payload.
fn tag_message_without_signature(payload: &str) -> Option<String> {
    let (_, body) = payload.split_once("\n\n")?;
    let message = match body.find("-----BEGIN SSH SIGNATURE-----") {
        Some(position) => &body[..position],
        None => body,
    };
    Some(message.trim_end().to_string())
}

/// Write a tag object payload into the object database, returning its id.
fn hash_tag_object(dir: &Path, payload: &[u8]) -> Result<String> {
    let repo = git2::Repository::open(dir)
        .with_context(|| format!("opening git repository at {}", dir.display()))?;
    let odb = repo.odb().context("opening object database")?;
    let oid = odb
        .write(git2::ObjectType::Tag, payload)
        .context("writing tag object")?;
    Ok(oid.to_string())
}

/// Load the committed `keys.toml` roster, defaulting to an empty roster
/// when the file does not exist yet.
fn load_committed_roster(dir: &Path) -> Result<KeysToml> {
    if !dir.exists() {
        bail!("registry directory does not exist: {}", dir.display());
    }
    Ok(keys::load_keys_toml(dir)?.unwrap_or_default())
}

/// `apr keys generate <id>`
///
/// Generates an OpenSSH Ed25519 maintainer keypair: the private key is
/// written under the per-scope config directory (mode `0600`, never
/// overwriting an existing file), its path is recorded in
/// `[registry.signing_keys]` so `--key-id <id>` resolves, and the public
/// half is printed in `registry:Ed25519:<base64>` form. With `--add` the
/// public key is also appended to the committed `keys.toml` roster via a
/// signed commit.
#[allow(clippy::too_many_arguments)]
fn generate_roster_key(
    config: &ApmConfig,
    id: &str,
    add: bool,
    no_commit: bool,
    signing_key: Option<&str>,
    signing_key_id: Option<&str>,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    validate_roster_key_id(id)?;
    let registry_name = resolve_registry_name(config, registry)?;

    let keys_dir = config.scope.config_dir().join("keys");
    {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        builder
            .create(&keys_dir)
            .with_context(|| format!("creating key directory {}", keys_dir.display()))?;
    }

    let key_path = keys_dir.join(format!("{registry_name}-{id}.key"));
    let keypair = sshkey::Ed25519Keypair::generate();
    let pem = keypair.to_openssh_private_key(&format!("{registry_name}-{id}"));
    {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&key_path).with_context(|| {
            format!(
                "creating private key file {} (refusing to overwrite an existing key)",
                key_path.display(),
            )
        })?;
        std::io::Write::write_all(&mut file, pem.as_bytes())
            .with_context(|| format!("writing {}", key_path.display()))?;
    }

    let trust_key = keypair.trust_key_line(&registry_name);
    let key_path_str = key_path.display().to_string();

    // Record the private key path so `--key-id <id>` resolves (§2.6).
    let config_path = config.registry_config_path_for_update(&registry_name);
    let configured = config_path.exists();
    if configured {
        state::upsert_signing_key(
            &config_path,
            id,
            &SigningKeySource::Path(key_path_str.clone()),
        )?;
        printer.kv("Config", &config_path.display().to_string());
    } else {
        printer.warning(&format!(
            "registry '{registry_name}' has no config at {}; to use --key-id {id}, add:\n\
             [registry.signing_keys]\n\"{id}\" = \"{key_path_str}\"",
            config_path.display(),
        ));
    }

    printer.kv("Key id", id);
    printer.kv("Private key", &key_path_str);
    printer.kv("Public key", &trust_key);
    printer.kv(
        "Fingerprint",
        &key_fingerprint(&keypair.public_key_base64()),
    );

    let mut committed = false;
    if add {
        let dir = config.scope.registries_path().join(&registry_name);
        let mut roster = load_committed_roster(&dir)?;
        if roster.active.is_empty() {
            bail!(
                "registry '{registry_name}' has an empty trust roster; seed the first key with \
                 `apr create {registry_name} --trust-key {trust_key} --key {key_path_str}` instead \
                 of --add"
            );
        }
        let commit_key = if no_commit {
            None
        } else {
            resolve_roster_commit_key(
                config,
                &dir,
                &registry_name,
                &roster,
                signing_key,
                signing_key_id,
            )?
        };
        add_roster_key(&mut roster, &registry_name, id, &trust_key)?;
        persist_committed_roster(
            &dir,
            &roster,
            no_commit,
            &format!("registry: add signing key {id}"),
            commit_key.as_ref().map(|k| k.path()),
        )?;
        committed = !no_commit;
        printer.success(&format!(
            "Added active signing key '{id}' to registry '{registry_name}'."
        ));
    }

    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "action": "keys_generate",
            "status": "generated",
            "registry": registry_name,
            "id": id,
            "private_key": key_path_str,
            "public_key": trust_key,
            "fingerprint": key_fingerprint(&keypair.public_key_base64()),
            "configured": configured,
            "config": if configured {
                Some(config_path.to_string_lossy().to_string())
            } else {
                None
            },
            "added": add,
            "committed": committed,
        }));
    }

    Ok(())
}

/// `apr keys register <id>`
///
/// Adopt an externally-held maintainer key without generating or persisting
/// key material. The private key is obtained from a path (`--key`) or a
/// command (`--key-command`); its public half is derived with `ssh-keygen -y`
/// (the same tool git uses to sign); the source is recorded under
/// `[registry.signing_keys]` so `--key-id <id>` resolves it; and the
/// `registry:Ed25519:<base64>` trust line is printed for an existing
/// maintainer to add with `apr keys add`.
///
/// Unlike [`generate_roster_key`], nothing is generated and the private key
/// never lands in a tool-managed file: a command source is materialized only
/// transiently — long enough to derive the public key — and removed
/// immediately. Resolving the source here doubles as validation that the
/// configured path or command actually yields a usable key.
///
/// The registry must already have a `registries.d` config (created by
/// `apr registry add`): the recorded `[registry.signing_keys]` entry is the
/// whole point of this command, and the config file cannot be created here
/// because it requires the registry URL. A missing config is an error, and
/// it is checked up front so the key source (which may prompt, e.g. a
/// secrets-manager command) is never run for a registration that cannot be
/// recorded.
fn register_roster_key(
    config: &ApmConfig,
    id: &str,
    key: Option<&str>,
    key_command: Option<&str>,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    validate_roster_key_id(id)?;
    let registry_name = resolve_registry_name(config, registry)?;

    let config_path = config.registry_config_path_for_update(&registry_name);
    if !config_path.exists() {
        bail!(
            "registry '{registry_name}' has no config at {}; register the registry first with \
             `{} add <url>`, then re-run this command",
            config_path.display(),
            aos_core::invocation::package_registry_command(),
        );
    }

    let source = match (key, key_command) {
        (Some(_), Some(_)) => bail!("use only one of --key or --key-command"),
        (Some(path), None) => SigningKeySource::Path(path.to_string()),
        (None, Some(command)) => SigningKeySource::Spec(SigningKeySpec {
            path: None,
            command: Some(command.to_string()),
        }),
        (None, None) => bail!("provide the key with --key <path> or --key-command <command>"),
    };

    let resolved = resolve_signing_key_source(id, &source)?;
    let trust_key = derive_trust_key(&registry_name, resolved.path())?;
    let (_registry, _algorithm, public_key) = parse_signing_key(&trust_key)?;

    state::upsert_signing_key(&config_path, id, &source)?;
    printer.kv("Config", &config_path.display().to_string());

    printer.kv("Key id", id);
    match (source.path(), source.command()) {
        (Some(path), _) => printer.kv("Key path", path),
        (_, Some(command)) => printer.kv("Key command", command),
        _ => {}
    }
    printer.kv("Public key", &trust_key);
    printer.kv("Fingerprint", &key_fingerprint(&public_key));
    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "action": "keys_register",
            "status": "registered",
            "registry": registry_name,
            "id": id,
            "source": if source.path().is_some() { "path" } else { "command" },
            "configured": true,
            "config": config_path.to_string_lossy().to_string(),
            "public_key": trust_key,
            "fingerprint": key_fingerprint(&public_key),
        }));
        return Ok(());
    }
    printer.info(&format!(
        "Hand the public key to an active maintainer to add it:\n  {} keys add {id} {trust_key} --registry {registry_name}",
        aos_core::invocation::package_registry_command(),
    ));
    Ok(())
}

/// Derive the `registry:Ed25519:<base64>` trust line for the private key at
/// `key_path`.
///
/// The base64 field is the SSH wire-format public key the trust line carries,
/// read from the private key with the `ssh-key` crate (see
/// [`crate::security::public_ed25519_blob`]).
fn derive_trust_key(registry_name: &str, key_path: &str) -> Result<String> {
    let blob = crate::security::public_ed25519_blob(Path::new(key_path))
        .context("deriving the public key from the signing key")?;
    Ok(format!("{registry_name}:Ed25519:{blob}"))
}

/// Write `keys.toml` back and, unless `no_commit`, commit it and refresh
/// the dumb-HTTP object store.
fn persist_committed_roster(
    dir: &Path,
    roster: &KeysToml,
    no_commit: bool,
    message: &str,
    signing_key: Option<&str>,
) -> Result<()> {
    keys::write_keys_toml(dir, roster)?;
    if !no_commit {
        commit_registry(dir, message, signing_key)?;
        refresh_registry_object_store(dir)
            .context("refreshing dumb-HTTP object store after keys.toml update")?;
    }
    Ok(())
}

/// Resolve the signing key for a roster-changing commit.
///
/// Roster commits must be signed whenever the pre-change roster is
/// non-empty: clients verify head-commit signatures against the keys they
/// already trust, so an unsigned roster change would be rejected on sync.
/// Only the bootstrap case (adding the first key to an empty roster, which
/// no client can verify yet) may proceed unsigned without an explicit key.
fn resolve_roster_commit_key(
    config: &ApmConfig,
    dir: &Path,
    registry_name: &str,
    roster_before: &KeysToml,
    key: Option<&str>,
    key_id: Option<&str>,
) -> Result<Option<ResolvedSigningKey>> {
    if key.is_some() || key_id.is_some() {
        return resolve_producer_signing_key(config, dir, registry_name, key, key_id).map(Some);
    }
    if roster_before.active.is_empty() {
        return Ok(None);
    }
    bail!(
        "registry '{registry_name}' has a non-empty trust roster, so roster changes must be \
         signed commits: pass --key <path> or --key-id <id> with an active maintainer key"
    )
}

/// Append an active key to the roster after validating that the id is
/// well-formed and unused, the key is not already present or revoked, and
/// the key's registry binding matches.
fn add_roster_key(roster: &mut KeysToml, registry_name: &str, id: &str, key: &str) -> Result<()> {
    validate_roster_key_id(id)?;
    if roster.active.iter().any(|entry| entry.id == id) {
        bail!("active signing key id '{id}' already exists in keys.toml");
    }
    if roster.revoked.iter().any(|entry| entry.id == id) {
        bail!("signing key id '{id}' is already revoked in keys.toml");
    }
    if roster.active.iter().any(|entry| entry.key == key) {
        bail!("signing key already exists in keys.toml under another id");
    }

    let (key_registry, _algorithm, _public_key) = parse_signing_key(key)?;
    if key_registry != registry_name {
        bail!(
            "signing key belongs to registry '{}', expected '{}'",
            key_registry,
            registry_name,
        );
    }

    roster.active.push(RosterKey {
        id: id.to_string(),
        key: key.to_string(),
    });
    Ok(())
}

/// Move key `id` from the active to the revoked roster, returning the id
/// of the vouching survivor key.
///
/// At least one active key must remain. `--vouched-by` is required when
/// more than one survivor exists and defaults to the sole survivor
/// otherwise; the voucher must itself be a surviving active key.
fn retire_roster_key(
    roster: &mut KeysToml,
    id: &str,
    reason: Option<&str>,
    vouched_by: &Option<String>,
    provenance_before_sequence: u64,
) -> Result<String> {
    validate_roster_key_id(id)?;
    let Some(position) = roster.active.iter().position(|entry| entry.id == id) else {
        if roster.revoked.iter().any(|entry| entry.id == id) {
            bail!("signing key id '{id}' is already revoked in keys.toml");
        }
        bail!("active signing key id '{id}' does not exist in keys.toml");
    };

    let survivors = roster
        .active
        .iter()
        .filter(|entry| entry.id != id)
        .map(|entry| entry.id.clone())
        .collect::<Vec<_>>();
    if survivors.is_empty() {
        bail!("cannot retire signing key '{id}': keys.toml must keep an active survivor key");
    }

    let vouching_id = match vouched_by.as_deref() {
        Some(vouching_id) => {
            validate_roster_key_id(vouching_id)?;
            if vouching_id == id {
                bail!("--vouched-by must name a different active key");
            }
            if !survivors.iter().any(|survivor| survivor == vouching_id) {
                bail!("--vouched-by '{vouching_id}' is not an active survivor key");
            }
            vouching_id.to_string()
        }
        None if survivors.len() == 1 => survivors[0].to_string(),
        None => bail!(
            "--vouched-by is required when more than one active survivor key remains ({})",
            survivors.join(", "),
        ),
    };

    let retired_key = roster.active.remove(position).key;
    upsert_revoked_key(roster, id, retired_key, provenance_before_sequence, reason);
    Ok(vouching_id)
}

/// Record `id` in the revoked list, updating the reason if it is already
/// there.
fn upsert_revoked_key(
    roster: &mut KeysToml,
    id: &str,
    key: String,
    provenance_before_sequence: u64,
    reason: Option<&str>,
) {
    let reason = reason.map(str::to_string);
    if let Some(entry) = roster.revoked.iter_mut().find(|entry| entry.id == id) {
        entry.key = Some(key);
        entry.provenance_before_sequence = Some(provenance_before_sequence);
        entry.reason = reason;
    } else {
        roster.revoked.push(RevokedKey {
            id: id.to_string(),
            key: Some(key),
            provenance_before_sequence: Some(provenance_before_sequence),
            reason,
        });
    }
}

fn validate_roster_key_id(id: &str) -> Result<()> {
    if id.is_empty() {
        bail!("key id cannot be empty");
    }
    if id.trim() != id
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("key id '{id}' must contain only ASCII letters, digits, '.', '-', or '_'");
    }
    Ok(())
}

fn configured_registry_names(config: &ApmConfig) -> Vec<String> {
    config
        .registries
        .iter()
        .map(|(registry, _)| registry.name.clone())
        .collect()
}

fn registry_upload_auth_config<'a>(
    config: &'a ApmConfig,
    registry_name: &str,
) -> Option<&'a crate::types::RegistryUploadAuthConfig> {
    config
        .registries
        .iter()
        .find(|(registry, _state)| registry.name == registry_name)
        .and_then(|(registry, _state)| registry.upload_auth.as_ref())
}

fn registry_cache_max_age_days(config: &ApmConfig, registry_name: &str) -> u64 {
    config
        .registries
        .iter()
        .find(|(registry, _state)| registry.name == registry_name)
        .map(|(registry, _state)| registry.cache.max_age_days())
        .unwrap_or(crate::types::DEFAULT_REGISTRY_CACHE_MAX_AGE_DAYS)
}

fn warn_on_cache_gc(cache_dir: &Path, max_age_days: u64, printer: &Printer) {
    if let Err(err) = nixcache::gc_static_cache(cache_dir, max_age_days, false) {
        printer.warning(&format!(
            "Static cache GC failed for {}: {err:#}",
            cache_dir.display()
        ));
    }
}

/// Resolve upload destinations: `--upload-url` flags when given, otherwise
/// the `upload_urls` persisted in `[registry.upload_auth]` by
/// `apr origin config`.
fn resolve_upload_urls(
    config: &ApmConfig,
    registry_name: &str,
    flag_urls: &[String],
) -> Vec<String> {
    if !flag_urls.is_empty() {
        return flag_urls.to_vec();
    }
    registry_upload_auth_config(config, registry_name)
        .map(|upload| upload.upload_urls.clone())
        .unwrap_or_default()
}

fn resolve_effective_release_cache_url(
    explicit_cache_url: Option<&str>,
    upload_urls: &[String],
    has_store_roots: bool,
) -> Result<Option<String>> {
    if let Some(cache_url) = explicit_cache_url {
        return Ok(Some(cache_url.to_string()));
    }
    if upload_urls.is_empty() || !has_store_roots {
        return Ok(None);
    }

    let http_urls = upload_urls
        .iter()
        .filter(|url| {
            url::Url::parse(url)
                .map(|parsed| matches!(parsed.scheme(), "http" | "https"))
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    if upload_urls.len() == 1 && http_urls.len() == 1 {
        return Ok(Some(http_urls[0].to_string()));
    }

    bail!(
        "publishing a release with store paths requires --cache-url unless exactly one upload URL is http(s)"
    );
}

/// Parse a `registry:Algorithm:<base64>` line into a [`TrustedKey`] pinned
/// via TOFU, verifying it belongs to `expected_registry`.
fn trusted_key_from_line(expected_registry: &str, key: &str) -> Result<TrustedKey> {
    let (registry, algorithm, public_key) = parse_signing_key(key)?;
    if registry != expected_registry {
        bail!(
            "trust key belongs to registry '{}', expected '{}'",
            registry,
            expected_registry,
        );
    }
    let fingerprint = key_fingerprint(&public_key);
    Ok(TrustedKey {
        registry,
        algorithm,
        public_key,
        fingerprint,
        source: KeySource::Tofu,
    })
}

/// A producer signing key resolved to a filesystem path that git can open.
///
/// For path sources [`path`](Self::path) points at the user's key file
/// directly. For command sources the key material is materialized into a
/// private temporary file (mode `0600`, in a tmpfs-backed directory when one
/// is available) whose lifetime is bound to this value: the file is removed
/// when the `ResolvedSigningKey` is dropped.
///
/// Because `ResolvedSigningKey` owns a [`tempfile::NamedTempFile`], Rust drops
/// it — and thus deletes the materialized key — at the end of its enclosing
/// scope, not at last use. Callers therefore keep it in a local binding for
/// the whole signing operation: `ssh-keygen` opens the key path more than
/// once per signature, so the path cannot be a pipe and the file must outlive
/// every git invocation that reads it.
#[derive(Debug)]
struct ResolvedSigningKey {
    path: String,
    /// Present for command sources; dropping it removes the temporary file.
    _materialized: Option<tempfile::NamedTempFile>,
}

impl ResolvedSigningKey {
    /// Wrap an on-disk key path that the tool does not own or manage.
    fn from_path(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            _materialized: None,
        }
    }

    /// The path to hand to `git -c user.signingkey=<path>`.
    fn path(&self) -> &str {
        &self.path
    }
}

/// Candidate directories for short-lived materialized keys, most-preferred
/// first: a tmpfs-backed runtime directory when available (`$XDG_RUNTIME_DIR`,
/// then `/dev/shm`), falling back to the system temp directory. Keeping the
/// plaintext key in RAM-backed storage avoids it ever touching persistent
/// disk.
fn ephemeral_key_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        let path = PathBuf::from(dir);
        if path.is_dir() {
            dirs.push(path);
        }
    }
    let shm = PathBuf::from("/dev/shm");
    if shm.is_dir() {
        dirs.push(shm);
    }
    dirs.push(std::env::temp_dir());
    dirs
}

/// Create an empty private temporary file in the most-preferred writable
/// [`ephemeral_key_dirs`] candidate.
///
/// A preferred directory may exist yet be unwritable (e.g. a read-only
/// `$XDG_RUNTIME_DIR`), so each candidate is tried in turn and the first that
/// accepts the file wins.
fn create_ephemeral_key_file() -> Result<tempfile::NamedTempFile> {
    let mut last_err: Option<(PathBuf, std::io::Error)> = None;
    for dir in ephemeral_key_dirs() {
        match tempfile::Builder::new()
            .prefix(".apm-signing-key-")
            .tempfile_in(&dir)
        {
            Ok(file) => return Ok(file),
            Err(err) => last_err = Some((dir, err)),
        }
    }
    match last_err {
        Some((dir, err)) => Err(anyhow::Error::new(err))
            .with_context(|| format!("creating temporary key file in {}", dir.display())),
        // `ephemeral_key_dirs` always yields the system temp dir, so the loop
        // runs at least once and records an error on total failure.
        None => bail!("no candidate directory available for a temporary key file"),
    }
}

/// Run a signing-key command via `bash -c` and materialize its stdout into a
/// private temporary file that `git`/`ssh-keygen` can open.
///
/// The command must print the unencrypted OpenSSH private key to stdout. The
/// returned [`ResolvedSigningKey`] owns the temporary file; the key is removed
/// from disk as soon as it is dropped.
///
/// The `aos`/`apm`/`apr` wrapper scripts replace `PATH` with a minimal
/// hermetic tool set and stash the caller's original value in
/// `AOS_HOST_PATH`. A key command is user-supplied and expects the user's
/// own environment (secret managers like `op`, filters like `jq`), so when
/// `AOS_HOST_PATH` is present the command runs with the caller's `PATH`
/// restored verbatim.
fn materialize_signing_key_command(command: &str) -> Result<ResolvedSigningKey> {
    materialize_signing_key_command_with_path(command, std::env::var_os("AOS_HOST_PATH"))
}

/// [`materialize_signing_key_command`] with an explicit `PATH` override for
/// the spawned `bash -c` process; `None` inherits this process's `PATH`.
fn materialize_signing_key_command_with_path(
    command: &str,
    search_path: Option<std::ffi::OsString>,
) -> Result<ResolvedSigningKey> {
    let runtime_path = std::env::var_os("PATH");
    let shell_program = runtime_path
        .as_deref()
        .and_then(|path| executable_on_path("bash", path))
        .unwrap_or_else(|| PathBuf::from("bash"));
    let mut shell = std::process::Command::new(shell_program);
    shell
        .arg("-c")
        .arg(command)
        .stdin(std::process::Stdio::null());
    if let Some(search_path) = search_path {
        shell.env("PATH", search_path);
    }
    let output = shell
        .output()
        .with_context(|| format!("running signing key command `{command}`"))?;
    if !output.status.success() {
        bail!(
            "signing key command `{command}` failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }
    if output.stdout.iter().all(u8::is_ascii_whitespace) {
        bail!("signing key command `{command}` produced no key material on stdout");
    }

    // `tempfile` creates the file with mode 0600 and O_EXCL on Unix and
    // removes it when the handle drops.
    let mut file = create_ephemeral_key_file()?;
    std::io::Write::write_all(file.as_file_mut(), &output.stdout)
        .context("writing materialized signing key to a temporary file")?;
    file.as_file()
        .sync_all()
        .context("flushing materialized signing key")?;

    let path = file
        .path()
        .to_str()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "temporary key path is not valid UTF-8: {}",
                file.path().display()
            )
        })?
        .to_string();
    Ok(ResolvedSigningKey {
        path,
        _materialized: Some(file),
    })
}

/// Return the first regular executable candidate named `program` on `path`.
fn executable_on_path(program: &str, path: &std::ffi::OsStr) -> Option<PathBuf> {
    std::env::split_paths(path)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}

/// Resolve a configured [`SigningKeySource`] to a path git can open.
///
/// A path source is validated for existence and returned as-is; a command
/// source is run and its output materialized via
/// [`materialize_signing_key_command`].
fn resolve_signing_key_source(
    key_id: &str,
    source: &SigningKeySource,
) -> Result<ResolvedSigningKey> {
    match (source.path(), source.command()) {
        (Some(_), Some(_)) => {
            bail!("signing key id '{key_id}' configures both 'path' and 'command'; set exactly one")
        }
        (None, None) => {
            bail!("signing key id '{key_id}' configures neither 'path' nor 'command'")
        }
        (Some(path), None) => {
            let path = path.trim();
            if path.is_empty() {
                bail!("local private key path for signing key id '{key_id}' is empty");
            }
            let path_buf = PathBuf::from(path);
            if !path_buf.exists() {
                bail!(
                    "local private key path for signing key id '{key_id}' does not exist: {}",
                    path_buf.display(),
                );
            }
            Ok(ResolvedSigningKey::from_path(path))
        }
        (None, Some(command)) => {
            let command = command.trim();
            if command.is_empty() {
                bail!("signing key command for id '{key_id}' is empty");
            }
            materialize_signing_key_command(command)
                .with_context(|| format!("resolving signing key id '{key_id}' via command"))
        }
    }
}

/// Resolve the maintainer signing key for tag and commit signing.
///
/// `--key` names a private key file used as-is. `--key-id` is looked up in
/// the committed `keys.toml` roster — rejecting revoked ids and keys bound
/// to another registry — and resolved to local key material through the
/// registry config's `[registry.signing_keys]` table (a path or a
/// command). Exactly one of the two must be provided.
fn resolve_producer_signing_key(
    config: &ApmConfig,
    dir: &Path,
    registry_name: &str,
    key: Option<&str>,
    key_id: Option<&str>,
) -> Result<ResolvedSigningKey> {
    match (key, key_id) {
        (Some(_), Some(_)) => bail!("use only one of --key or --key-id"),
        (Some(key), None) => Ok(ResolvedSigningKey::from_path(key)),
        (None, Some(key_id)) => {
            validate_roster_key_id(key_id)?;
            let roster = load_committed_roster(dir)?;
            if keys::is_revoked(&roster, key_id) {
                bail!("signing key id '{key_id}' is revoked in keys.toml");
            }
            let active = keys::active_key_by_id(&roster, key_id).ok_or_else(|| {
                anyhow::anyhow!("active signing key id '{key_id}' does not exist in keys.toml")
            })?;
            let (entry_registry, _algorithm, _public_key) = parse_signing_key(&active.key)
                .with_context(|| format!("invalid active key '{key_id}'"))?;
            if entry_registry != registry_name {
                bail!(
                    "active signing key id '{key_id}' belongs to registry '{}', expected '{}'",
                    entry_registry,
                    registry_name,
                );
            }

            let registry_config =
                registry_config_by_name(config, registry_name).ok_or_else(|| {
                    anyhow::anyhow!(
                        "--key-id requires registry '{}' to be configured in registries.d",
                        registry_name,
                    )
                })?;
            let source = registry_config.signing_keys.get(key_id).ok_or_else(|| {
                anyhow::anyhow!(
                    "no local private key configured for signing key id '{key_id}'; add [registry.signing_keys] {key_id} = \"/path/to/private-key\" (or {{ command = \"...\" }}) to the registry config or pass --key"
                )
            })?;
            resolve_signing_key_source(key_id, source)
        }
        (None, None) => bail!(
            "--key or --key-id is required: registry release and channel tags must be signed tag objects"
        ),
    }
}

fn registry_config_by_name<'a>(
    config: &'a ApmConfig,
    registry_name: &str,
) -> Option<&'a RegistryConfig> {
    config
        .registries
        .iter()
        .find(|(registry, _state)| registry.name == registry_name)
        .map(|(registry, _state)| registry)
}

/// `apr channel init`: point all 256 partitions of a channel at one
/// release and set the channel branch to it.
async fn channel_init(
    config: &ApmConfig,
    channel_name: &str,
    version: &semver::Version,
    key: Option<&str>,
    key_id: Option<&str>,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    validate_channel_name(channel_name)?;
    let registry_name = resolve_registry_name(config, registry)?;
    let dir = config.scope.registries_path().join(&registry_name);
    let signing_key = resolve_producer_signing_key(config, &dir, &registry_name, key, key_id)?;
    assert_release_tag_exists(&dir, version)?;

    let mut map = PartitionMap::new();
    for bucket in 0..=u8::MAX {
        write_channel_partition_tag(&dir, channel_name, bucket, version, signing_key.path())?;
        map.set(bucket as usize, version.clone())?;
    }
    update_channel_frontier(&dir, channel_name, &map)?;

    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "action": "channel_init",
            "registry": registry_name,
            "channel": channel_name,
            "version": version.to_string(),
            "partitions": 256,
            "frontier": version.to_string(),
        }));
        return Ok(());
    }

    printer.success(&format!(
        "Initialized channel '{channel_name}' with 256/256 partitions on {version}."
    ));
    Ok(())
}

/// `apr channel advance`: re-sign the selected partitions of an existing
/// channel against a newer release and recompute the frontier.
async fn channel_advance(
    config: &ApmConfig,
    channel_name: &str,
    version: &semver::Version,
    count: Option<usize>,
    partitions: Option<&str>,
    key: Option<&str>,
    key_id: Option<&str>,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    validate_channel_name(channel_name)?;
    let registry_name = resolve_registry_name(config, registry)?;
    let dir = config.scope.registries_path().join(&registry_name);
    let signing_key = resolve_producer_signing_key(config, &dir, &registry_name, key, key_id)?;
    assert_release_tag_exists(&dir, version)?;

    let mut map = read_channel_partition_map(&dir, channel_name)?;
    channel::assert_full_partition_set(&map)?;
    let selected = select_partitions_for_advance(count, partitions, &map, version)?;
    ensure_channel_advance_fix_forward(&map, &selected, version)?;
    if selected.is_empty() {
        if printer.mode() == OutputMode::Json {
            let frontier = channel::compute_frontier(&map);
            printer.json(&serde_json::json!({
                "action": "channel_advance",
                "registry": registry_name,
                "channel": channel_name,
                "version": version.to_string(),
                "partitions": [],
                "partition_count": 0,
                "frontier": frontier.as_ref().map(ToString::to_string),
                "status": "current",
            }));
            return Ok(());
        }
        printer.info("No partitions selected for advancement.");
        return Ok(());
    }

    for bucket in &selected {
        write_channel_partition_tag(&dir, channel_name, *bucket, version, signing_key.path())?;
        map.set(*bucket as usize, version.clone())?;
    }
    update_channel_frontier(&dir, channel_name, &map)?;

    if printer.mode() == OutputMode::Json {
        let frontier = channel::compute_frontier(&map);
        let partition_count = selected.len();
        printer.json(&serde_json::json!({
            "action": "channel_advance",
            "registry": registry_name,
            "channel": channel_name,
            "version": version.to_string(),
            "partitions": &selected,
            "partition_count": partition_count,
            "frontier": frontier.as_ref().map(ToString::to_string),
            "status": "advanced",
        }));
        return Ok(());
    }

    printer.success(&format!(
        "Advanced channel '{channel_name}' {} partition(s) to {version}.",
        selected.len()
    ));
    Ok(())
}

/// `apr channel status`: summarize partition versions, missing partitions,
/// and the channel frontier.
async fn channel_status(
    config: &ApmConfig,
    channel_name: &str,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    validate_channel_name(channel_name)?;
    let dir = registry_dir(config, registry)?;
    let map = read_channel_partition_map(&dir, channel_name)?;
    let frontier = channel::compute_frontier(&map);
    let missing = map.iter().filter(|(_, target)| target.is_none()).count();
    let mut counts: BTreeMap<semver::Version, usize> = BTreeMap::new();
    for (_, target) in map.iter() {
        if let Some(version) = target {
            *counts.entry(version.clone()).or_default() += 1;
        }
    }

    if printer.mode() == OutputMode::Json {
        let versions = counts
            .iter()
            .rev()
            .map(|(version, count)| {
                serde_json::json!({
                    "version": version.to_string(),
                    "partitions": count,
                })
            })
            .collect::<Vec<_>>();
        printer.json(&serde_json::json!({
            "channel": channel_name,
            "frontier": frontier.as_ref().map(ToString::to_string),
            "missing_partitions": missing,
            "versions": versions,
        }));
        return Ok(());
    }

    printer.header(&format!("Channel: {channel_name}"));
    if let Some(frontier) = frontier {
        printer.kv("Frontier", &frontier.to_string());
    } else {
        printer.kv("Frontier", "none");
    }
    printer.kv("Missing partitions", &missing.to_string());
    for (version, count) in counts.iter().rev() {
        printer.kv(&version.to_string(), &format!("{count}/256"));
    }
    Ok(())
}

/// `apr push` — pushes the current (or named) branch of the registry clone
/// to `origin`.
///
/// Runs as a network transport, so the host git configuration (credential
/// helpers, proxies) stays visible. `--set-upstream` passes `-u origin`
/// with the selected branch, using the current branch when `--branch` is not
/// supplied; `--force` force-pushes.
///
/// # Errors
///
/// Fails when a supplied branch name is not safe to use as a Git ref, when
/// no remote or upstream is configured for the branch, or when the remote
/// rejects the push.
pub async fn push(
    config: &ApmConfig,
    branch: Option<&str>,
    set_upstream: bool,
    force: bool,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let dir = registry_dir(config, registry)?;
    let current = current_git_branch(&dir)?;
    if let Some(branch) = branch {
        validate_branch_name(branch)?;
    }
    let pushed_branch = branch
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| current.clone());

    let mut args = vec!["push"];
    if set_upstream {
        args.push("-u");
    }
    if force {
        args.push("--force");
    }
    if let Some(b) = branch {
        args.push("origin");
        args.push(b);
    } else if set_upstream {
        args.push("origin");
        args.push(&current);
    }

    let output = git_transport(&dir, &args)?;
    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "action": "push",
            "branch": pushed_branch,
            "set_upstream": set_upstream,
            "force": force,
            "current": current,
            "head": current_git_head(&dir)?,
            "branches": git_branch_entries(&dir)?,
            "output": output,
        }));
        return Ok(());
    }
    if !output.is_empty() {
        printer.plain(&output);
    }
    printer.success("Pushed.");

    Ok(())
}

/// `apr pull` — pulls the current branch of the registry clone from its
/// upstream, rebasing local commits instead of merging when `--rebase` is
/// given.
///
/// # Errors
///
/// Fails when no upstream is configured or the pull cannot complete
/// cleanly (e.g. merge conflicts).
pub async fn pull(
    config: &ApmConfig,
    rebase: bool,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let dir = registry_dir(config, registry)?;

    let mut args = vec!["pull"];
    if rebase {
        args.push("--rebase");
    }

    let output = git_transport(&dir, &args)?;
    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "action": "pull",
            "rebase": rebase,
            "current": current_git_branch(&dir)?,
            "head": current_git_head(&dir)?,
            "branches": git_branch_entries(&dir)?,
            "output": output,
        }));
        return Ok(());
    }
    printer.plain(&output);

    Ok(())
}

/// `apr merge <BRANCH>` — merges `branch` into the current branch of the
/// registry clone.
///
/// `--no-ff` always creates a merge commit; `--squash` stages the combined
/// changes without committing them.
///
/// # Errors
///
/// Fails when the branch name is not safe to use as a Git ref, when the
/// branch does not exist, or when the merge conflicts.
pub async fn merge(
    config: &ApmConfig,
    branch: &str,
    no_ff: bool,
    squash: bool,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let dir = registry_dir(config, registry)?;
    validate_branch_name(branch)?;

    let mut args = vec!["merge"];
    if no_ff {
        args.push("--no-ff");
    }
    if squash {
        args.push("--squash");
    }
    args.push("--");
    args.push(branch);

    let output = git(&dir, &args)?;
    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "action": "merge",
            "branch": branch,
            "no_ff": no_ff,
            "squash": squash,
            "current": current_git_branch(&dir)?,
            "head": current_git_head(&dir)?,
            "branches": git_branch_entries(&dir)?,
            "output": output,
        }));
        return Ok(());
    }
    printer.plain(&output);
    printer.success(&format!("Merged '{branch}'."));

    Ok(())
}

fn current_git_head(dir: &Path) -> Result<String> {
    git(dir, &["rev-parse", "HEAD"])
}

// ---------------------------------------------------------------------------
// Release
// ---------------------------------------------------------------------------

/// Options controlling [`release_registry_tree`].
///
/// Mirrors the flags of `apr release` once the optional `--store-path`
/// publish step has been handled by [`release`].
#[derive(Debug, Clone)]
pub struct ReleaseTreeOptions {
    /// Release version; doubles as the git tag name.
    pub version: semver::Version,
    /// Path to the OpenSSH Ed25519 private key used for tags and commits.
    pub signing_key: String,
    /// OpenSSH keys available for TUF role signatures.
    pub tuf_signing_keys: Vec<tuf::MetadataSigningKey>,
    /// Channel to initialize or advance after tagging, if any.
    pub channel: Option<String>,
    /// Initialize all 256 channel partitions instead of advancing a subset.
    pub init_channel: bool,
    /// Number of partitions to advance (ascending fill).
    pub count: Option<usize>,
    /// Explicit partition list to advance (decimal or hex buckets).
    pub partitions: Option<String>,
    /// Internal directory to stage static Nix cache files into.
    pub cache_dir: PathBuf,
    /// Nix cache signing key for the generated narinfos.
    pub cache_key: Option<PathBuf>,
    /// Effective public cache URL to upsert into the registry cache stack.
    pub cache_url: Option<String>,
    /// Whether `cache_url` came from an explicit `--cache-url`.
    pub cache_url_explicit: bool,
    /// Priority recorded for the cache pointer.
    pub cache_priority: u32,
    /// Whether `cache_priority` came from an explicit `--cache-priority`.
    pub cache_priority_explicit: bool,
    /// Whether the registry already has store roots or this release will
    /// publish one.
    pub has_store_roots: bool,
    /// Regenerate/reupload paths even if local or remote entries exist.
    pub no_skip: bool,
    /// Static-origin upload destinations.
    pub upload_urls: Vec<String>,
    /// Authentication used for cache and origin uploads.
    pub upload_auth: AuthOptions,
    /// Print the release plan without executing it.
    pub dry_run: bool,
    /// Reuse an existing tag and pack artifacts at HEAD instead of failing.
    pub resume: bool,
    /// Parallel compression jobs for the static cache (default: CPU count).
    pub jobs: Option<usize>,
    /// Optional package publish payload to run under the release lock.
    pub store_publish: Option<ReleaseStorePublish>,
    /// Staged cache retention after a successful release.
    pub cache_max_age_days: u64,
}

/// Optional `--store-path` publish payload carried into the locked release.
#[derive(Debug, Clone)]
pub struct ReleaseStorePublish {
    pub config: ApmConfig,
    pub store_path: String,
    pub name: Option<String>,
    pub version: Option<String>,
    pub platform: Option<String>,
    pub description: Option<String>,
    pub homepage: Option<String>,
    pub license: Option<String>,
    pub maintainer: Option<String>,
    pub sysroot: bool,
    pub previous: Option<String>,
    pub source_drv: Option<String>,
    pub image_payload_paths: Vec<String>,
    pub image_disk_paths: Vec<String>,
    pub image_info_paths: Vec<String>,
    pub image_formats: Vec<String>,
    pub image_uki_paths: Vec<String>,
    pub bless: bool,
    pub message: Option<String>,
    pub registry: String,
    /// Stable roster identity corresponding to the resolved release key.
    pub signing_key_id: Option<String>,
}

impl ReleaseStorePublish {
    fn publish_signing_args(&self) -> (Option<&str>, Option<&str>) {
        (None, self.signing_key_id.as_deref())
    }
}

impl ReleaseTreeOptions {
    fn publishing(&self) -> bool {
        !self.upload_urls.is_empty()
    }

    fn should_publish_cache(&self) -> bool {
        self.publishing() && self.has_store_roots
    }
}

/// Summary of the artifacts produced by [`release_registry_tree`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReleaseReport {
    /// Filename of the generated full pack, when the release kind needs one.
    pub full_pack: Option<String>,
    /// Filenames of the generated compressed thin-delta packs.
    pub deltas: Vec<String>,
    /// Static Nix cache generation report, when one was requested.
    pub cache: Option<nixcache::StaticCacheReport>,
    /// Whether the `registry.toml` cache pointer was updated and committed.
    pub cache_pointer_updated: bool,
    /// Number of channel partitions touched, when a channel was given.
    pub channel_partitions: Option<usize>,
    /// Files uploaded to the static origin, when uploads ran.
    pub uploaded_files: Option<usize>,
    /// Bytes uploaded to the static origin, when uploads ran.
    pub uploaded_bytes: Option<u64>,
}

/// Exclusive on-disk lock (`.git/apr-release.lock`) serializing release
/// publishers against one registry clone; the lock file records the
/// holder's pid and is removed on drop.
struct ReleaseLock {
    path: PathBuf,
}

impl ReleaseLock {
    fn acquire(dir: &Path) -> Result<Self> {
        let git_dir = objectstore::repo_git_dir(dir)?;
        let path = git_dir.join("apr-release.lock");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| {
                format!(
                    "acquiring release lock {}; another publisher may be running",
                    path.display()
                )
            })?;
        writeln!(file, "pid={}", std::process::id())
            .with_context(|| format!("writing {}", path.display()))?;
        Ok(Self { path })
    }
}

impl Drop for ReleaseLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// `apr release <SEMVER>` — runs the end-to-end registry release workflow.
///
/// When `--store-path` is given, first publishes that store path into the
/// release metadata under the release version (committed and SSH-signed),
/// including explicit `--source-drv` provenance when provided, then
/// delegates to [`release_registry_tree`] to create the signed
/// release tag, generate pack artifacts, and run the optional cache,
/// channel, and upload steps. `--dry-run` prints the plan without changing
/// anything.
///
/// # Errors
///
/// Fails when the semver does not parse, the registry directory is
/// missing, the signing key cannot be resolved, the working tree is dirty,
/// a policy-bearing internal component is supplied as the store-path root,
/// an aggregate root does not directly retain its required corresponding
/// source, the publish step fails, or any delegated release step fails (see
/// [`release_registry_tree`]).
#[allow(clippy::too_many_arguments)]
pub async fn release(
    config: &ApmConfig,
    semver: &str,
    store_path: Option<&str>,
    name: Option<&str>,
    version_override: Option<&str>,
    platform: Option<&str>,
    description: Option<&str>,
    homepage: Option<&str>,
    license: Option<&str>,
    maintainer: Option<&str>,
    sysroot: bool,
    previous: Option<&str>,
    source_drv: Option<&str>,
    image_payload_paths: &[String],
    image_disk_paths: &[String],
    image_info_paths: &[String],
    image_formats: &[String],
    image_uki_paths: &[String],
    bless: bool,
    message: Option<&str>,
    channel: Option<&str>,
    init_channel: bool,
    count: Option<usize>,
    partitions: Option<&str>,
    key: Option<&str>,
    key_id: Option<&str>,
    rotate_from: Option<&Path>,
    cache_key: Option<&Path>,
    cache_url: Option<&str>,
    cache_priority: Option<u32>,
    no_skip: bool,
    upload_urls: &[String],
    auth: &CacheUploadAuthArgs,
    dry_run: bool,
    resume: bool,
    registry: Option<&str>,
    jobs: Option<usize>,
    printer: &Printer,
) -> Result<()> {
    validate_release_publish_metadata(store_path, description, license, maintainer)?;
    validate_release_publish_signing_identity(store_path, key_id)?;

    let version = semver::Version::parse(semver)
        .with_context(|| format!("parsing release semver '{semver}'"))?;
    if let Some(store_path) = store_path {
        let info = introspect_store_path(store_path)?;
        validate_store_path_release_policy(&info)?;
    }
    let registry_name = resolve_registry_name(config, registry)?;
    let dir = config.scope.registries_path().join(&registry_name);
    if !dir.exists() {
        bail!("registry directory does not exist: {}", dir.display());
    }
    let signing_key = resolve_producer_signing_key(config, &dir, &registry_name, key, key_id)?;
    let (_tuf_key_owners, tuf_signing_keys) =
        resolve_tuf_metadata_signing_keys(config, &dir, &registry_name, &signing_key, rotate_from)?;

    let upload_auth =
        auth.auth_options_with_config(registry_upload_auth_config(config, &registry_name));
    let resolved_upload_urls = resolve_upload_urls(config, &registry_name, upload_urls);
    let has_store_roots = store_path.is_some() || nixcache::registry_has_store_roots(&dir)?;
    let cache_url_explicit = cache_url.is_some();
    let effective_cache_url =
        resolve_effective_release_cache_url(cache_url, &resolved_upload_urls, has_store_roots)?;
    let store_publish = store_path.map(|store_path| ReleaseStorePublish {
        config: config.clone(),
        store_path: store_path.to_string(),
        name: name.map(ToString::to_string),
        version: version_override.map(ToString::to_string),
        platform: platform.map(ToString::to_string),
        description: description.map(ToString::to_string),
        homepage: homepage.map(ToString::to_string),
        license: license.map(ToString::to_string),
        maintainer: maintainer.map(ToString::to_string),
        sysroot,
        previous: previous.map(ToString::to_string),
        source_drv: source_drv.map(ToString::to_string),
        image_payload_paths: image_payload_paths.to_vec(),
        image_disk_paths: image_disk_paths.to_vec(),
        image_info_paths: image_info_paths.to_vec(),
        image_formats: image_formats.to_vec(),
        image_uki_paths: image_uki_paths.to_vec(),
        bless,
        message: message.map(ToString::to_string),
        registry: registry_name.clone(),
        signing_key_id: key_id.map(ToString::to_string),
    });
    let options = ReleaseTreeOptions {
        version,
        signing_key: signing_key.path().to_string(),
        tuf_signing_keys,
        channel: channel.map(ToString::to_string),
        init_channel,
        count,
        partitions: partitions.map(ToString::to_string),
        cache_dir: config.registry_cache_path(&registry_name),
        cache_key: cache_key.map(Path::to_path_buf),
        cache_url: effective_cache_url,
        cache_url_explicit,
        cache_priority: cache_priority.unwrap_or(40),
        cache_priority_explicit: cache_priority.is_some(),
        has_store_roots,
        no_skip,
        upload_urls: resolved_upload_urls,
        upload_auth,
        dry_run,
        resume,
        jobs,
        store_publish,
        cache_max_age_days: registry_cache_max_age_days(config, &registry_name),
    };

    release_registry_tree(&dir, &registry_name, &options, printer).await?;
    Ok(())
}

/// Publish a release's `--store-path` into the registry tree.
///
/// The published package version is **not** the release tag. Like a plain
/// `apr publish`, it defaults to the store-path basename and can be overridden
/// explicitly, so a registry release tag and the package versions it snapshots
/// remain independent.
async fn publish_release_store_path(
    publish_opts: &ReleaseStorePublish,
    printer: &Printer,
) -> Result<()> {
    let (key, key_id) = publish_opts.publish_signing_args();
    publish(
        &publish_opts.config,
        &publish_opts.store_path,
        publish_opts.name.as_deref(),
        publish_opts.version.as_deref(),
        publish_opts.platform.as_deref(),
        publish_opts.description.as_deref(),
        publish_opts.homepage.as_deref(),
        publish_opts.license.as_deref(),
        publish_opts.maintainer.as_deref(),
        publish_opts.sysroot,
        publish_opts.previous.as_deref(),
        publish_opts.source_drv.as_deref(),
        &publish_opts.image_payload_paths,
        &publish_opts.image_disk_paths,
        &publish_opts.image_info_paths,
        &publish_opts.image_formats,
        &publish_opts.image_uki_paths,
        None,
        None,
        None,
        &[],
        publish_opts.bless,
        false,
        false,
        publish_opts.message.as_deref(),
        key,
        key_id,
        Some(&publish_opts.registry),
        printer,
    )
    .await
}

/// Executes the release workflow against a registry directory.
///
/// Under an exclusive release lock, this: rejects up front a release whose
/// tag already exists (unless `resume`), so a doomed release fails before any
/// mutating work; optionally publishes `--store-path` (whose package version
/// comes from the store path, independent of the release tag); optionally
/// commits a `registry.toml` cache pointer; creates the signed semver release
/// tag at HEAD (or reuses an existing tag there when `resume` is set);
/// generates the release pack artifacts under `.git/releases/<version>/` — a
/// full pack for major/minor releases plus zstd-compressed thin deltas from
/// the prior releases selected by the delta scheme; optionally generates the
/// static Nix cache; initializes or advances the rollout channel; and
/// uploads the static origin files. The dumb-HTTP object store is
/// refreshed after each ref-moving step. With `dry_run`, the plan is
/// printed and nothing is modified.
///
/// Returns a [`ReleaseReport`] describing the produced artifacts.
///
/// # Errors
///
/// Fails when the option combination is invalid (`--init-channel` or
/// partition selectors without `--channel`, cache flags without a publishing
/// destination or store roots); when another publisher holds the release
/// lock; when the working tree is dirty; when the tag or pack artifacts
/// already exist without `resume` (or the tag exists at a different commit);
/// or when pack generation, cache generation, channel updates, or uploads
/// fail.
pub async fn release_registry_tree(
    dir: &Path,
    registry_name: &str,
    options: &ReleaseTreeOptions,
    printer: &Printer,
) -> Result<ReleaseReport> {
    validate_release_options(options)?;
    if options.dry_run {
        if printer.mode() == OutputMode::Json {
            printer.json(&release_result_json(
                "planned",
                registry_name,
                dir,
                options,
                &ReleaseReport::default(),
            ));
        } else {
            print_release_plan(dir, registry_name, options, printer);
        }
        return Ok(ReleaseReport::default());
    }

    let _lock = ReleaseLock::acquire(dir)?;
    objectstore::assert_sha256(dir)?;
    ensure_release_worktree_clean(dir)?;
    ensure_release_tag_available(dir, &options.version, options.resume)?;

    if let Some(publish) = &options.store_publish {
        publish_release_store_path(publish, printer).await?;
    }

    // Publishing cache unit (§9): generate into the internal staging dir, push
    // the cache bytes, and only then commit the advertising pointer. A failed
    // upload aborts the release here with no tag and no `[caches]` change; a
    // committed pointer lands before the tag so it is part of the snapshot.
    let mut cache_report = None;
    let mut cache_pointer_updated = false;
    if options.should_publish_cache() {
        let membership = if options.no_skip {
            None
        } else {
            Some(
                HeadMembership::from_urls(&options.upload_urls, &options.upload_auth)
                    .await
                    .context("creating remote cache membership checker")?,
            )
        };
        let membership_ref = membership
            .as_ref()
            .map(|membership| membership as &dyn CacheMembership);
        let generated = nixcache::generate_static_cache(
            dir,
            &options.cache_dir,
            options.cache_key.as_deref(),
            options.cache_priority,
            options.jobs,
            membership_ref,
            options.no_skip,
            printer,
        )
        .await?;
        printer.success(&format!(
            "Generated static cache: {} narinfos, {} NARs ({} reused, {} remote-skipped) in {}",
            generated.narinfos,
            generated.nars,
            generated.local_reused,
            generated.remote_skipped,
            generated.output_dir.display(),
        ));

        // Cache bytes first (NARs, then member narinfos, then root narinfos).
        // On failure the `?` aborts before any tag or pointer exists.
        nixcache::upload_static_cache_to_all(
            &options.cache_dir,
            &options.upload_urls,
            &options.upload_auth,
            &generated.root_hashes,
            options.no_skip,
            printer,
        )
        .await?;

        // Advertise only when at least one narinfo is present on the
        // destinations — freshly uploaded (`narinfos`) or already there
        // (`remote_skipped`). Never advertise an empty or unpublished cache.
        if let Some(cache_url) = &options.cache_url
            && generated.narinfos + generated.remote_skipped > 0
            && nixcache::upsert_registry_cache(dir, cache_url, options.cache_priority)?
        {
            cache_pointer_updated = true;
            printer.info(&format!("Updated registry.toml [caches] -> {cache_url}"));
            commit_registry(
                dir,
                "registry: update static cache pointer",
                Some(&options.signing_key),
            )?;
        }
        cache_report = Some(generated);
    }

    let release_tag_exists = existing_release_tag_commit(dir, &options.version)?.is_some();
    if !release_tag_exists {
        let tuf_changed = write_tuf_release_metadata(dir, registry_name, options, printer)?;
        if tuf_changed {
            commit_registry_paths(
                dir,
                "registry: update TUF release metadata",
                &[dir.join(tuf::TUF_DIR)],
                Some(&options.signing_key),
            )?;
        }
    } else if options.resume {
        printer.info(&format!(
            "Release tag {} already exists; leaving committed TUF metadata unchanged.",
            options.version,
        ));
    }

    let head = git(dir, &["rev-parse", "HEAD"])?;
    let published_before = semver_tag_versions(dir)?
        .into_iter()
        .filter(|version| version != &options.version)
        .collect::<Vec<_>>();

    ensure_release_tag(dir, options, &head, printer)?;
    refresh_registry_object_store(dir).context("refreshing dumb-HTTP object store after tag")?;

    let artifacts = write_release_artifacts(dir, &published_before, options, printer).await?;
    refresh_registry_object_store(dir)
        .context("refreshing dumb-HTTP object store after release artifacts")?;

    let mut report = artifacts;
    report.cache_pointer_updated = cache_pointer_updated;
    report.cache = cache_report;

    if let Some(channel) = &options.channel {
        if options.init_channel {
            let partitions = channel_init_dir(
                dir,
                channel,
                &options.version,
                &options.signing_key,
                printer,
            )?;
            report.channel_partitions = Some(partitions);
        } else {
            let partitions = channel_advance_dir(
                dir,
                channel,
                &options.version,
                options.count,
                options.partitions.as_deref(),
                &options.signing_key,
                printer,
            )?;
            report.channel_partitions = Some(partitions);
        }
    }

    // Static git origin last: objects, refs, channel payloads, and the
    // committed cache pointer. Cache bytes, when any, were already uploaded
    // above, so this call carries the git surface only (`cache_dir = None`).
    if !options.upload_urls.is_empty() {
        let upload = static_upload::upload_static_origin_to_all(
            dir,
            &options.upload_urls,
            &options.upload_auth,
            options.no_skip,
            printer,
        )
        .await?;
        report.uploaded_files = Some(upload.files);
        report.uploaded_bytes = Some(upload.bytes);
        printer.success(&format!(
            "Uploaded {} static origin file(s) ({}).",
            upload.files,
            format_size(upload.bytes),
        ));
    }

    printer.success(&format!("Released {registry_name} {}.", options.version));
    if printer.mode() == OutputMode::Json {
        printer.json(&release_result_json(
            "released",
            registry_name,
            dir,
            options,
            &report,
        ));
    }
    if let Some(cache) = &report.cache {
        warn_on_cache_gc(&cache.output_dir, options.cache_max_age_days, printer);
    }
    Ok(report)
}

fn write_tuf_release_metadata(
    dir: &Path,
    registry_name: &str,
    options: &ReleaseTreeOptions,
    printer: &Printer,
) -> Result<bool> {
    let tuf_signing_keys = if options.tuf_signing_keys.is_empty() {
        let trust_key = derive_trust_key(registry_name, &options.signing_key)?;
        vec![tuf::MetadataSigningKey {
            key_id: tuf_signing_key_id(dir, &trust_key)?,
            key_path: PathBuf::from(&options.signing_key),
            key: trust_key,
            role_key: true,
        }]
    } else {
        options.tuf_signing_keys.clone()
    };
    let changed = tuf::write_release_metadata_worktree(
        dir,
        registry_name,
        &options.version,
        &tuf_signing_keys,
    )?;
    if changed {
        printer.success("Updated TUF release metadata.");
    }
    Ok(changed)
}

fn tuf_signing_key_id(dir: &Path, trust_key: &str) -> Result<String> {
    if let Some(roster) = keys::load_keys_toml(dir)? {
        if let Some(entry) = roster.active.iter().find(|entry| entry.key == trust_key) {
            return Ok(entry.id.clone());
        }
    }
    let (_registry, _algorithm, public_key) = parse_signing_key(trust_key)?;
    Ok(format!("key-{}", key_fingerprint(&public_key)))
}

fn resolve_tuf_metadata_signing_keys(
    config: &ApmConfig,
    dir: &Path,
    registry_name: &str,
    primary: &ResolvedSigningKey,
    rotate_from: Option<&Path>,
) -> Result<(Vec<ResolvedSigningKey>, Vec<tuf::MetadataSigningKey>)> {
    let primary_trust_key = derive_trust_key(registry_name, primary.path())?;
    let primary_key = tuf::MetadataSigningKey {
        key_id: tuf_signing_key_id(dir, &primary_trust_key)?,
        key_path: PathBuf::from(primary.path()),
        key: primary_trust_key.clone(),
        role_key: true,
    };
    let mut metadata_keys = vec![primary_key];
    let mut owners = Vec::new();

    // An operator rotating the root signing key supplies the previous root key
    // explicitly with `--rotate-from`; it co-signs the new root so the
    // previous-root-role authorization check accepts the transition. It is not
    // a member of the new root policy (role_key=false). Its id must be a key id
    // in the *current* (previous) root role, matched by public key — a freshly
    // derived id would not satisfy the previous-root authorization check.
    if let Some(rotate_from) = rotate_from {
        let rotate_from_str = rotate_from.to_str().ok_or_else(|| {
            anyhow::anyhow!(
                "--rotate-from path is not valid UTF-8: {}",
                rotate_from.display()
            )
        })?;
        let rotate_public = derive_trust_key(registry_name, rotate_from_str)?;
        if rotate_public == primary_trust_key {
            bail!(
                "--rotate-from key is the same as the release signing key; \
                 omit --rotate-from when not rotating the root key"
            );
        }
        let previous_key_id = tuf::worktree_root_role_keys(dir)?
            .into_iter()
            .find(|(_, public)| *public == rotate_public)
            .map(|(key_id, _)| key_id)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "--rotate-from key is not a current root-role key; \
                     pass the previous root key being rotated away from"
                )
            })?;
        metadata_keys.push(tuf::MetadataSigningKey {
            key_id: previous_key_id,
            key_path: rotate_from.to_path_buf(),
            key: rotate_public,
            role_key: false,
        });
    }

    let Some(roster) = keys::load_keys_toml(dir)? else {
        return Ok((owners, metadata_keys));
    };
    let Some(registry_config) = registry_config_by_name(config, registry_name) else {
        return Ok((owners, metadata_keys));
    };
    let active_key_ids = roster
        .active
        .iter()
        .map(|entry| entry.id.clone())
        .collect::<HashSet<_>>();
    for entry in &roster.active {
        if metadata_keys.iter().any(|key| key.key == entry.key) {
            continue;
        }
        let Some(source) = registry_config.signing_keys.get(&entry.id) else {
            continue;
        };
        let resolved = resolve_signing_key_source(&entry.id, source)?;
        let trust_key = derive_trust_key(registry_name, resolved.path())?;
        if trust_key != entry.key {
            bail!(
                "configured private key for signing key id '{}' derives '{}', but keys.toml declares '{}'",
                entry.id,
                trust_key,
                entry.key,
            );
        }
        metadata_keys.push(tuf::MetadataSigningKey {
            key_id: entry.id.clone(),
            key_path: PathBuf::from(resolved.path()),
            key: trust_key,
            role_key: true,
        });
        owners.push(resolved);
    }
    for key_id in tuf::worktree_root_role_key_ids(dir)? {
        if active_key_ids.contains(&key_id) || metadata_keys.iter().any(|key| key.key_id == key_id)
        {
            continue;
        }
        let Some(source) = registry_config.signing_keys.get(&key_id) else {
            continue;
        };
        let resolved = resolve_signing_key_source(&key_id, source)?;
        let trust_key = derive_trust_key(registry_name, resolved.path())?;
        if metadata_keys.iter().any(|key| key.key == trust_key) {
            owners.push(resolved);
            continue;
        }
        metadata_keys.push(tuf::MetadataSigningKey {
            key_id,
            key_path: PathBuf::from(resolved.path()),
            key: trust_key,
            role_key: false,
        });
        owners.push(resolved);
    }

    Ok((owners, metadata_keys))
}

/// Reject invalid `apr release` flag combinations before any work happens.
fn validate_release_options(options: &ReleaseTreeOptions) -> Result<()> {
    match (&options.channel, options.init_channel) {
        (None, true) => bail!("--init-channel requires --channel"),
        (None, false) => {
            if options.count.is_some() || options.partitions.is_some() {
                bail!("--count and --partitions require --channel");
            }
        }
        (Some(_), true) => {
            if options.count.is_some() || options.partitions.is_some() {
                bail!("--init-channel cannot be combined with --count or --partitions");
            }
        }
        (Some(_), false) => {
            select_partitions_for_advance(
                options.count,
                options.partitions.as_deref(),
                &PartitionMap::new(),
                &options.version,
            )
            .map(|_| ())?;
        }
    }

    if !options.publishing() {
        if options.cache_url_explicit {
            bail!("--cache-url requires an upload destination");
        }
        if options.cache_key.is_some() {
            bail!("--cache-key signs published narinfos; it requires an upload destination");
        }
        if options.cache_priority_explicit {
            bail!("--cache-priority requires an upload destination");
        }
        if options.no_skip {
            bail!("--no-skip requires an upload destination");
        }
    } else if !options.has_store_roots {
        if options.cache_url_explicit
            || options.cache_key.is_some()
            || options.cache_priority_explicit
            || options.no_skip
        {
            bail!("cache flags require registry store paths when publishing");
        }
    } else if options.cache_url.is_none() {
        bail!(
            "publishing a release with store paths requires --cache-url unless exactly one upload URL is http(s)"
        );
    }
    Ok(())
}

fn release_result_json(
    status: &str,
    registry_name: &str,
    dir: &Path,
    options: &ReleaseTreeOptions,
    report: &ReleaseReport,
) -> serde_json::Value {
    let channel = options.channel.as_ref().map(|channel| {
        serde_json::json!({
            "name": channel,
            "action": if options.init_channel { "init" } else { "advance" },
            "count": options.count,
            "partitions": options.partitions.as_deref(),
            "touched_partitions": report.channel_partitions,
        })
    });
    serde_json::json!({
        "action": "release",
        "status": status,
        "registry": registry_name,
        "directory": dir.to_string_lossy().to_string(),
        "version": options.version.to_string(),
        "dry_run": options.dry_run,
        "resume": options.resume,
        "cache_dir": options.cache_dir.to_string_lossy().to_string(),
        "cache_url": options.cache_url.as_deref(),
        "cache_url_explicit": options.cache_url_explicit,
        "cache_priority": options.cache_priority,
        "cache_priority_explicit": options.cache_priority_explicit,
        "has_store_roots": options.has_store_roots,
        "no_skip": options.no_skip,
        "cache": report.cache.as_ref().map(static_cache_report_json),
        "cache_pointer_updated": report.cache_pointer_updated,
        "upload_urls": &options.upload_urls,
        "uploaded_files": report.uploaded_files,
        "uploaded_bytes": report.uploaded_bytes,
        "uploaded_bytes_human": report.uploaded_bytes.map(format_size),
        "channel": channel,
        "full_pack": report.full_pack.as_deref(),
        "deltas": &report.deltas,
        "planned_steps": release_plan_steps_json(options),
    })
}

fn static_cache_report_json(report: &nixcache::StaticCacheReport) -> serde_json::Value {
    serde_json::json!({
        "paths": report.paths,
        "narinfos": report.narinfos,
        "nars": report.nars,
        "local_reused": report.local_reused,
        "remote_skipped": report.remote_skipped,
        "root_hashes": report.root_hashes,
        "output_dir": report.output_dir.to_string_lossy().to_string(),
    })
}

fn release_plan_steps_json(options: &ReleaseTreeOptions) -> Vec<&'static str> {
    let mut steps = vec!["ensure_clean_worktree"];
    if options.store_publish.is_some() {
        steps.push("publish_store_path");
    }
    // Cache bytes upload and pointer commit precede the tag so the pointer is
    // part of the released snapshot and a failed upload leaves no tag.
    if options.should_publish_cache() {
        steps.push("generate_static_cache");
        steps.push("upload_static_cache");
        steps.push("commit_cache_pointer");
    }
    steps.push("create_signed_release_tag");
    steps.push("generate_release_packs");
    if options.channel.is_some() {
        steps.push(if options.init_channel {
            "initialize_channel"
        } else {
            "publish_channel_pointer"
        });
    }
    if !options.upload_urls.is_empty() {
        steps.push("upload_static_origin");
    }
    steps
}

fn print_release_plan(
    dir: &Path,
    registry_name: &str,
    options: &ReleaseTreeOptions,
    printer: &Printer,
) {
    printer.header("Release plan");
    printer.kv("Registry", registry_name);
    printer.kv("Directory", &dir.display().to_string());
    printer.kv("Release", &options.version.to_string());
    printer.plain("- ensure registry working tree is clean");
    if options.store_publish.is_some() {
        printer.plain("- publish store path into release metadata");
    }
    if options.should_publish_cache() {
        printer.plain("- generate static Nix cache files");
        printer.plain("- upload cache NARs and narinfos to every destination");
        if let Some(cache_url) = &options.cache_url {
            printer.plain(&format!(
                "- commit registry.toml cache pointer {cache_url} once published"
            ));
        }
    }
    printer.plain("- create signed release tag if absent");
    printer.plain("- generate full pack and guaranteed compressed thin deltas");
    if let Some(channel) = &options.channel {
        let action = if options.init_channel {
            "initialize"
        } else {
            "advance"
        };
        printer.plain(&format!("- {action} channel {channel}"));
    }
    if !options.upload_urls.is_empty() {
        printer.plain("- upload static git origin (immutable objects first, refs last)");
    }
}

/// Require a clean working tree before releasing; bare repositories pass
/// trivially.
fn ensure_release_worktree_clean(dir: &Path) -> Result<()> {
    let is_bare = git(dir, &["rev-parse", "--is-bare-repository"])? == "true";
    if is_bare {
        return Ok(());
    }
    let status = git(dir, &["status", "--porcelain"])?;
    if !status.is_empty() {
        bail!("registry working tree has uncommitted changes; commit them or use --store-path");
    }
    Ok(())
}

/// Create the signed release tag at `head`, or accept an existing tag that
/// already points at `head` when resuming.
fn ensure_release_tag(
    dir: &Path,
    options: &ReleaseTreeOptions,
    head: &str,
    printer: &Printer,
) -> Result<()> {
    if let Some(existing_commit) = existing_release_tag_commit(dir, &options.version)? {
        if options.resume && existing_commit == head {
            printer.info(&format!(
                "Release tag {} already exists at HEAD; resuming.",
                options.version
            ));
            return Ok(());
        }
        if existing_commit == head {
            bail!(
                "release tag {} already exists at HEAD; pass --resume to reuse it",
                options.version,
            );
        }
        bail!(
            "release tag {} already exists at {}, but HEAD is {}",
            options.version,
            existing_commit,
            head,
        );
    }

    sign_tag(
        dir,
        &options.version.to_string(),
        head,
        Some("AOS registry release"),
        &options.signing_key,
        false,
    )?;
    printer.success(&format!("Created signed tag '{}'.", options.version));
    Ok(())
}

/// Return the commit an existing release tag points at, or `None` when no
/// tag exists; a non-tag ref carrying the release name is an error.
fn existing_release_tag_commit(dir: &Path, version: &semver::Version) -> Result<Option<String>> {
    let tag = version.to_string();
    let (tag_ok, _, tag_stderr) = git_try(dir, &["rev-parse", &format!("{tag}^{{tag}}")])?;
    if !tag_ok {
        let commit_probe = git_try(dir, &["rev-parse", &format!("{tag}^{{commit}}")])?;
        if commit_probe.0 {
            bail!("release name '{tag}' exists but is not an annotated tag object");
        }
        if !tag_stderr.is_empty() {
            return Ok(None);
        }
        return Ok(None);
    }
    let commit = release_commit(dir, version)?;
    Ok(Some(commit))
}

/// Reject a release whose tag already exists, before any mutating work.
///
/// This is a best-effort preflight, not a lock. It runs before the store-path
/// publish and the static-cache generation/upload so that the common mistake —
/// re-using a version that is already released — fails fast and leaves the
/// registry untouched, instead of bailing only at tag-creation time after a
/// publish commit and a cache upload have already landed.
///
/// It is deliberately *not* sufficient on its own: the authoritative collision
/// check still happens in [`ensure_release_tag`] under the release lock, since
/// a concurrent producer working from a different clone can create the same
/// tag after this check passes. That residual race resolves when the losing
/// producer pushes to the shared origin. Passing `resume` skips the preflight,
/// since resuming an interrupted release legitimately reuses an existing tag.
///
/// # Errors
///
/// Returns an error when `resume` is false and the release tag already exists,
/// or when probing the tag fails (for example, a non-annotated tag of the same
/// name).
fn ensure_release_tag_available(dir: &Path, version: &semver::Version, resume: bool) -> Result<()> {
    if resume {
        return Ok(());
    }
    if let Some(existing) = existing_release_tag_commit(dir, version)? {
        bail!(
            "release tag {version} already exists at {existing}; choose an unused version or pass --resume to resume that release"
        );
    }
    Ok(())
}

/// Generate the pack artifacts for a release under
/// `.git/releases/<version>/`.
///
/// Major and minor releases get a self-contained full pack, recorded in
/// `info/packs` for dumb-HTTP fetchers. Every release also gets a
/// zstd-compressed thin delta from each prior release selected by the
/// delta scheme, so consumers on a supported base version can fetch a
/// compact incremental pack instead of the full history.
async fn write_release_artifacts(
    dir: &Path,
    published_before: &[semver::Version],
    options: &ReleaseTreeOptions,
    printer: &Printer,
) -> Result<ReleaseReport> {
    let commit = release_commit(dir, &options.version)?;
    let release_objects = objectstore::repo_git_dir(dir)?
        .join("releases")
        .join(objectstore::release_object_dir(&options.version));
    let pack_dir = release_objects.join("pack");
    let info_dir = release_objects.join("info");
    fs::create_dir_all(&pack_dir).with_context(|| format!("creating {}", pack_dir.display()))?;
    fs::create_dir_all(&info_dir).with_context(|| format!("creating {}", info_dir.display()))?;

    let full_pack = match pack::release_kind(&options.version) {
        pack::ReleaseKind::Major | pack::ReleaseKind::Minor => {
            Some(write_full_pack_artifact(dir, &commit, &pack_dir, options.resume, printer).await?)
        }
        pack::ReleaseKind::Patch => None,
    };

    if let Some(full_pack) = &full_pack {
        fs::write(info_dir.join("packs"), format!("P {full_pack}\n"))
            .with_context(|| format!("writing {}", info_dir.join("packs").display()))?;
    }

    let mut deltas = Vec::new();
    for base in pack::scheme_deltas(&options.version, published_before) {
        let base_commit = release_commit(dir, &base)?;
        deltas.push(
            write_delta_artifact(
                dir,
                &base,
                &base_commit,
                &commit,
                &pack_dir,
                options.resume,
                printer,
            )
            .await?,
        );
    }

    Ok(ReleaseReport {
        full_pack,
        deltas,
        ..ReleaseReport::default()
    })
}

/// Generate (or, with `resume`, reuse) the full `pack-*.pack` for a
/// release commit, staging it in a tempdir before copying it and its
/// `.idx` into place.
async fn write_full_pack_artifact(
    dir: &Path,
    commit: &str,
    pack_dir: &Path,
    resume: bool,
    printer: &Printer,
) -> Result<String> {
    if let Some(existing) = existing_full_pack(pack_dir)? {
        if resume {
            let idx = pack_dir.join(existing.trim_end_matches(".pack").to_string() + ".idx");
            if !idx.exists() {
                bail!(
                    "full pack {existing} exists but its index {} is missing; rerun without --resume to regenerate it",
                    idx.display()
                );
            }
            printer.info(&format!("Full pack {existing} already exists; resuming."));
            return Ok(existing);
        }
        bail!("full pack {existing} already exists; pass --resume to reuse it");
    }

    let tmp = tempfile::Builder::new()
        .prefix(".tmp-full-pack-")
        .tempdir_in(pack_dir)
        .with_context(|| format!("creating full-pack tempdir in {}", pack_dir.display()))?;
    let pack_path = pack::full_pack(dir, commit, tmp.path()).await?;
    let pack_name = file_name_string(&pack_path)?;
    fs::copy(&pack_path, pack_dir.join(&pack_name))
        .with_context(|| format!("copying {}", pack_path.display()))?;
    let idx_path = pack_path.with_extension("idx");
    if !idx_path.exists() {
        bail!("full pack index was not generated: {}", idx_path.display());
    }
    let idx_name = file_name_string(&idx_path)?;
    fs::copy(&idx_path, pack_dir.join(idx_name))
        .with_context(|| format!("copying {}", idx_path.display()))?;
    printer.success(&format!("Generated full pack {pack_name}."));
    Ok(pack_name)
}

/// Generate (or, with `resume`, reuse) the `delta-<base>.pack.zst` thin
/// pack carrying the objects needed to go from `base_commit` to
/// `target_commit`.
async fn write_delta_artifact(
    dir: &Path,
    base: &semver::Version,
    base_commit: &str,
    target_commit: &str,
    pack_dir: &Path,
    resume: bool,
    printer: &Printer,
) -> Result<String> {
    let artifact_name = format!("delta-{base}.pack.zst");
    let dest = pack_dir.join(&artifact_name);
    if dest.exists() {
        if resume {
            printer.info(&format!(
                "Delta pack {artifact_name} already exists; resuming."
            ));
            return Ok(artifact_name);
        }
        bail!("delta pack {artifact_name} already exists; pass --resume to reuse it");
    }

    let tmp = tempfile::Builder::new()
        .prefix(".tmp-delta-pack-")
        .tempdir_in(pack_dir)
        .with_context(|| format!("creating delta-pack tempdir in {}", pack_dir.display()))?;
    let delta = pack::thin_delta(dir, base_commit, target_commit, base, tmp.path()).await?;
    let compressed = pack::zstd_compress(&delta, None).await?;
    fs::copy(&compressed, &dest).with_context(|| format!("copying {}", compressed.display()))?;
    printer.success(&format!("Generated delta pack {artifact_name}."));
    Ok(artifact_name)
}

/// Find an already-generated full pack in `pack_dir`; more than one is an
/// error because `info/packs` records exactly one.
fn existing_full_pack(pack_dir: &Path) -> Result<Option<String>> {
    if !pack_dir.exists() {
        return Ok(None);
    }
    let mut packs = Vec::new();
    for entry in
        fs::read_dir(pack_dir).with_context(|| format!("reading {}", pack_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.starts_with("pack-") && name.ends_with(".pack") {
            packs.push(name.to_string());
        }
    }
    packs.sort();
    if packs.len() > 1 {
        bail!(
            "multiple full packs already exist in {}: {}",
            pack_dir.display(),
            packs.join(", "),
        );
    }
    Ok(packs.into_iter().next())
}

fn file_name_string(path: &Path) -> Result<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(ToString::to_string)
        .ok_or_else(|| anyhow::anyhow!("path has no UTF-8 filename: {}", path.display()))
}

/// Point all 256 partitions of a channel at `version` and move the channel
/// branch to the new frontier. Returns the partition count (always 256).
fn channel_init_dir(
    dir: &Path,
    channel_name: &str,
    version: &semver::Version,
    signing_key: &str,
    printer: &Printer,
) -> Result<usize> {
    validate_channel_name(channel_name)?;
    assert_release_tag_exists(dir, version)?;
    let mut map = PartitionMap::new();
    for bucket in 0..=u8::MAX {
        write_channel_partition_tag(dir, channel_name, bucket, version, signing_key)?;
        map.set(bucket as usize, version.clone())?;
    }
    update_channel_frontier(dir, channel_name, &map)?;
    printer.success(&format!(
        "Initialized channel '{channel_name}' with 256/256 partitions on {version}."
    ));
    Ok(256)
}

/// Advance the selected partitions of an existing channel to `version` and
/// update the frontier. Returns how many partitions were touched.
fn channel_advance_dir(
    dir: &Path,
    channel_name: &str,
    version: &semver::Version,
    count: Option<usize>,
    partitions: Option<&str>,
    signing_key: &str,
    printer: &Printer,
) -> Result<usize> {
    validate_channel_name(channel_name)?;
    assert_release_tag_exists(dir, version)?;
    let mut map = read_channel_partition_map(dir, channel_name)?;
    channel::assert_full_partition_set(&map)?;
    let selected = select_partitions_for_advance(count, partitions, &map, version)?;
    ensure_channel_advance_fix_forward(&map, &selected, version)?;
    if selected.is_empty() {
        printer.info("No partitions selected for advancement.");
        return Ok(0);
    }
    for bucket in &selected {
        write_channel_partition_tag(dir, channel_name, *bucket, version, signing_key)?;
        map.set(*bucket as usize, version.clone())?;
    }
    update_channel_frontier(dir, channel_name, &map)?;
    printer.success(&format!(
        "Advanced channel '{channel_name}' {} partition(s) to {version}.",
        selected.len()
    ));
    Ok(selected.len())
}

/// `apr tag <NAME>` — creates an SSH-signed annotated tag at HEAD in the
/// registry clone and refreshes the dumb-HTTP object store.
///
/// The tag message defaults to `AOS registry release`.
///
/// # Errors
///
/// Fails when the tag name is not a safe Git refname, when the signing key
/// cannot be resolved, when the tag already exists, or when git tag signing
/// fails.
pub async fn tag(
    config: &ApmConfig,
    name: &str,
    message: Option<&str>,
    key: Option<&str>,
    key_id: Option<&str>,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    validate_git_ref_name(name)?;
    let registry_name = resolve_registry_name(config, registry)?;
    let dir = config.scope.registries_path().join(&registry_name);
    let signing_key = resolve_producer_signing_key(config, &dir, &registry_name, key, key_id)?;
    let tag_message = message.unwrap_or("AOS registry release");

    sign_tag(
        &dir,
        name,
        "HEAD",
        Some(tag_message),
        signing_key.path(),
        false,
    )?;
    refresh_registry_object_store(&dir).context("refreshing dumb-HTTP object store after tag")?;

    if printer.mode() == OutputMode::Json {
        let tag_object = git(&dir, &["rev-parse", &format!("{name}^{{tag}}")])
            .with_context(|| format!("resolving tag object for '{name}'"))?;
        let target = git(&dir, &["rev-parse", &format!("{name}^{{commit}}")])
            .with_context(|| format!("resolving tag target for '{name}'"))?;
        printer.json(&serde_json::json!({
            "action": "tag",
            "status": "tagged",
            "registry": registry_name,
            "tag": name,
            "message": tag_message,
            "target": target,
            "tag_object": tag_object,
        }));
        return Ok(());
    }

    printer.success(&format!("Created signed tag '{name}'."));
    Ok(())
}

/// `apr sign <TAG>` — re-signs an existing tag in place.
///
/// The tag is force-recreated against its current target commit with a
/// fresh SSH signature, and the dumb-HTTP object store is refreshed.
///
/// # Errors
///
/// Fails when no tag name is given, when the tag name is not a safe Git
/// refname, when the tag cannot be resolved, when the signing key cannot be
/// resolved, or when git tag signing fails.
pub async fn sign(
    config: &ApmConfig,
    tag: Option<&str>,
    key: Option<&str>,
    key_id: Option<&str>,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let registry_name = resolve_registry_name(config, registry)?;
    let dir = config.scope.registries_path().join(&registry_name);
    let tag_name = tag.ok_or_else(|| {
        anyhow::anyhow!("`apr sign` now signs tag objects; pass the existing tag name to re-sign")
    })?;
    validate_git_ref_name(tag_name)?;
    let signing_key = resolve_producer_signing_key(config, &dir, &registry_name, key, key_id)?;
    let previous_tag_object = git(&dir, &["rev-parse", &format!("{tag_name}^{{tag}}")])
        .with_context(|| format!("resolving existing tag object for '{tag_name}'"))?;
    let target = git(&dir, &["rev-list", "-n", "1", tag_name])
        .with_context(|| format!("resolving tag '{tag_name}' target commit"))?;

    sign_tag(
        &dir,
        tag_name,
        &target,
        Some("AOS registry release"),
        signing_key.path(),
        true,
    )?;
    refresh_registry_object_store(&dir).context("refreshing dumb-HTTP object store after sign")?;
    if printer.mode() == OutputMode::Json {
        let tag_object = git(&dir, &["rev-parse", &format!("{tag_name}^{{tag}}")])
            .with_context(|| format!("resolving re-signed tag object for '{tag_name}'"))?;
        printer.json(&serde_json::json!({
            "action": "sign",
            "status": "signed",
            "registry": registry_name,
            "tag": tag_name,
            "target": target,
            "previous_tag_object": previous_tag_object,
            "tag_object": tag_object,
        }));
        return Ok(());
    }
    printer.success(&format!("Re-signed tag '{tag_name}'."));

    Ok(())
}

/// Require the signed release tag for `version` to exist, returning the
/// tag object id.
fn assert_release_tag_exists(dir: &Path, version: &semver::Version) -> Result<String> {
    let tag = version.to_string();
    git(dir, &["rev-parse", &format!("{tag}^{{tag}}")])
        .with_context(|| format!("resolving signed release tag '{tag}'"))
}

/// Resolve the commit a release tag points at.
fn release_commit(dir: &Path, version: &semver::Version) -> Result<String> {
    let tag = version.to_string();
    git(dir, &["rev-parse", &format!("{tag}^{{commit}}")])
        .with_context(|| format!("resolving release tag '{tag}' commit"))
}

/// Resolve which partitions a channel advance should touch: `--count`
/// picks the lowest-numbered partitions not yet on the target version
/// (ascending fill), while `--partitions` names buckets explicitly.
/// Exactly one of the two must be given.
fn select_partitions_for_advance(
    count: Option<usize>,
    partitions: Option<&str>,
    map: &PartitionMap,
    version: &semver::Version,
) -> Result<Vec<u8>> {
    match (count, partitions) {
        (Some(_), Some(_)) => bail!("use only one of --count or --partitions"),
        (None, None) => bail!("one of --count or --partitions is required"),
        (Some(count), None) => {
            if count > channel::PARTITION_COUNT {
                bail!("--count must be <= {}", channel::PARTITION_COUNT);
            }
            Ok(channel::ascending_fill(count, map, version))
        }
        (None, Some(spec)) => parse_partition_list(spec),
    }
}

/// Refuse producer-side channel rewrites that would lower any selected
/// partition's semver target.
fn ensure_channel_advance_fix_forward(
    map: &PartitionMap,
    selected: &[u8],
    version: &semver::Version,
) -> Result<()> {
    for bucket in selected {
        let Some(current) = map.get(*bucket) else {
            continue;
        };
        if version < current {
            bail!(
                "channel advance would decrement partition {} from {} to {}; publish a newer fix-forward release instead",
                channel::bucket_hex(*bucket),
                current,
                version,
            );
        }
    }
    Ok(())
}

fn parse_partition_list(spec: &str) -> Result<Vec<u8>> {
    let mut buckets = Vec::new();
    for raw in spec.split(',') {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let bucket = parse_partition(raw)?;
        if !buckets.contains(&bucket) {
            buckets.push(bucket);
        }
    }
    if buckets.is_empty() {
        bail!("partition list is empty");
    }
    Ok(buckets)
}

/// Parse a single partition bucket: `0x`-prefixed or letter-containing
/// strings are hex, everything else is decimal.
fn parse_partition(raw: &str) -> Result<u8> {
    if let Some(hex) = raw.strip_prefix("0x") {
        return u8::from_str_radix(hex, 16)
            .with_context(|| format!("invalid hex partition '{raw}'"));
    }
    if raw.bytes().any(|b| matches!(b, b'a'..=b'f' | b'A'..=b'F')) {
        return u8::from_str_radix(raw, 16)
            .with_context(|| format!("invalid hex partition '{raw}'"));
    }
    raw.parse::<u8>()
        .with_context(|| format!("invalid decimal partition '{raw}'"))
}

/// Reconstruct a channel's partition map from the signed tag payloads
/// under `.git/channels/<name>/`, verifying each payload's channel-name
/// binding and resolving its target tag object to a release version.
fn read_channel_partition_map(dir: &Path, channel_name: &str) -> Result<PartitionMap> {
    let release_tags = semver_tag_object_map(dir)?;
    let git_dir = objectstore::repo_git_dir(dir)?;
    let channel_dir = git_dir.join("channels").join(channel_name);
    let mut map = PartitionMap::new();

    for bucket in 0..=u8::MAX {
        let path = channel_dir.join(channel::bucket_hex(bucket));
        if !path.exists() {
            continue;
        }
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let tag = parse_tag_object(&content)
            .with_context(|| format!("parsing channel partition {}", path.display()))?;
        verify_name_binding(&tag, channel_name)?;
        if tag.target_type != TagTarget::Tag {
            bail!(
                "channel partition {} targets {:?}, expected tag",
                path.display(),
                tag.target_type,
            );
        }
        let version = release_tags.get(&tag.object).ok_or_else(|| {
            anyhow::anyhow!(
                "channel partition {} points at unknown release tag object {}",
                path.display(),
                tag.object,
            )
        })?;
        map.set(bucket as usize, version.clone())?;
    }
    Ok(map)
}

/// Map each release tag's object id to its release version.
fn semver_tag_object_map(dir: &Path) -> Result<BTreeMap<String, semver::Version>> {
    let mut map = BTreeMap::new();
    for version in semver_tag_versions(dir)? {
        let oid = assert_release_tag_exists(dir, &version)?;
        map.insert(oid, version);
    }
    Ok(map)
}

/// Sign and store the payload for one channel partition.
///
/// Git can only sign tags through refs, so a temporary tag named after the
/// channel is force-created against the release tag object, its signed
/// payload is copied into `.git/channels/<channel>/<bucket>`, and the
/// temporary ref is deleted. The payload file is the durable artifact
/// consumers fetch and verify.
fn write_channel_partition_tag(
    dir: &Path,
    channel_name: &str,
    bucket: u8,
    version: &semver::Version,
    signing_key: &str,
) -> Result<()> {
    let target = format!("{version}^{{tag}}");
    let message = format!(
        "AOS channel {channel_name} partition {}",
        channel::bucket_hex(bucket)
    );
    sign_tag(
        dir,
        channel_name,
        &target,
        Some(&message),
        signing_key,
        true,
    )?;
    let tag_ref = format!("refs/tags/{channel_name}^{{tag}}");
    let oid = git(dir, &["rev-parse", &tag_ref])?;
    let payload = git_raw(dir, &["cat-file", "-p", &oid])?;

    let git_dir = objectstore::repo_git_dir(dir)?;
    let channel_dir = git_dir.join("channels").join(channel_name);
    std::fs::create_dir_all(&channel_dir)
        .with_context(|| format!("creating {}", channel_dir.display()))?;
    let partition = channel_dir.join(channel::bucket_hex(bucket));
    std::fs::write(&partition, payload)
        .with_context(|| format!("writing {}", partition.display()))?;

    git(dir, &["tag", "-d", channel_name])
        .with_context(|| format!("deleting temporary channel tag '{channel_name}'"))?;
    Ok(())
}

/// Recompute the channel frontier from the partition map, point
/// `refs/heads/<channel>` at the frontier release's commit, and refresh
/// the dumb-HTTP object store.
fn update_channel_frontier(dir: &Path, channel_name: &str, map: &PartitionMap) -> Result<()> {
    channel::assert_full_partition_set(map)?;
    let frontier = channel::compute_frontier(map)
        .ok_or_else(|| anyhow::anyhow!("channel '{channel_name}' has no frontier"))?;
    let commit = release_commit(dir, &frontier)?;
    git(
        dir,
        &["update-ref", &format!("refs/heads/{channel_name}"), &commit],
    )?;
    refresh_registry_object_store(dir)
        .context("refreshing dumb-HTTP object store after channel update")?;
    Ok(())
}

/// Create an SSH-signed annotated tag object.
///
/// Builds the tag object directly and appends the armored SSH signature after
/// the message — the same on-disk layout `git tag -s` produces and that
/// [`crate::security::verify_tag_signature`] verifies (the signed payload is
/// everything before the signature block).
fn sign_tag(
    dir: &Path,
    tag_name: &str,
    target: &str,
    message: Option<&str>,
    signing_key: &str,
    force: bool,
) -> Result<()> {
    validate_git_ref_name(tag_name)?;
    let message = message.unwrap_or("AOS registry release");
    ensure_commit_identity(dir)?;

    let repo = git2::Repository::open(dir)
        .with_context(|| format!("opening git repository at {}", dir.display()))?;
    let target_object = repo
        .revparse_single(target)
        .with_context(|| format!("resolving tag target {target}"))?;
    let target_type = match target_object.kind() {
        Some(git2::ObjectType::Commit) => "commit",
        Some(git2::ObjectType::Tag) => "tag",
        Some(git2::ObjectType::Tree) => "tree",
        Some(git2::ObjectType::Blob) => "blob",
        _ => bail!("cannot tag object {} of unknown type", target_object.id()),
    };
    let tagger = git2_identity(&repo)?;

    // Build the unsigned tag payload, then sign exactly those bytes.
    let mut payload = Vec::new();
    payload.extend_from_slice(format!("object {}\n", target_object.id()).as_bytes());
    payload.extend_from_slice(format!("type {target_type}\n").as_bytes());
    payload.extend_from_slice(format!("tag {tag_name}\n").as_bytes());
    payload.extend_from_slice(
        format!(
            "tagger {} <{}> {} {}\n",
            tagger.name().unwrap_or(""),
            tagger.email().unwrap_or(""),
            tagger.when().seconds(),
            format_git_tz(tagger.when()),
        )
        .as_bytes(),
    );
    payload.push(b'\n');
    payload.extend_from_slice(message.as_bytes());
    payload.push(b'\n');

    let armored = crate::security::sign_payload_signature(Path::new(signing_key), "git", &payload)?;
    payload.extend_from_slice(armored.as_bytes());

    let odb = repo.odb().context("opening object database")?;
    let oid = odb
        .write(git2::ObjectType::Tag, &payload)
        .context("writing tag object")?;
    let refname = format!("refs/tags/{tag_name}");
    repo.reference(&refname, oid, force, &format!("apr tag {tag_name}"))
        .with_context(|| format!("creating tag ref '{tag_name}'"))?;
    Ok(())
}

/// Format a git timezone offset (`+HHMM`/`-HHMM`) from a [`git2::Time`].
fn format_git_tz(when: git2::Time) -> String {
    let offset = when.offset_minutes();
    let sign = if offset < 0 { '-' } else { '+' };
    let abs = offset.abs();
    format!("{sign}{:02}{:02}", abs / 60, abs % 60)
}

// ---------------------------------------------------------------------------
// Helpers (format)
// ---------------------------------------------------------------------------

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let kib = bytes as f64 / 1024.0;
    if kib < 1024.0 {
        return format!("{kib:.1} KiB");
    }
    let mib = kib / 1024.0;
    if mib < 1024.0 {
        return format!("{mib:.1} MiB");
    }
    let gib = mib / 1024.0;
    format!("{gib:.1} GiB")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::verify_tag_signature;
    use crate::testutil;
    use crate::types::{
        ApmSettings, ConfigOutputMeta, ModuleAbiCompat, OwnedRoot, ProfileScope, RegistryConfig,
        RegistryUploadAuthConfig,
    };
    use std::fs;
    use tempfile::TempDir;

    fn documentation_declaration(path: &str, visibility: Visibility) -> DerivedOptionDeclaration {
        DerivedOptionDeclaration {
            path: path.split('.').map(str::to_string).collect(),
            path_str: path.to_string(),
            type_sig: "boolean".to_string(),
            option_type: OptionType::Bool,
            description: "Fixture option.".to_string(),
            default: None,
            example: None,
            visibility,
            read_only: false,
            contributable: false,
            owner: "nginx".to_string(),
        }
    }

    #[test]
    fn package_documentation_excludes_internal_module_plumbing() {
        let declarations = [
            documentation_declaration("nginx.enable", Visibility::Public),
            documentation_declaration("nginx._aosExposeConfigProjection", Visibility::Internal),
        ];

        let paths = documented_option_declarations(&declarations)
            .map(|declaration| declaration.path_str.as_str())
            .collect::<Vec<_>>();

        assert_eq!(paths, ["nginx.enable"]);
    }

    #[test]
    fn package_documentation_preserves_the_nar_byte_identity() {
        let expected = format!("sha256:{}", "0".repeat(64));
        assert_eq!(documentation_nar_identity(&expected).unwrap(), expected);

        let sri = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        assert_eq!(documentation_nar_identity(sri).unwrap(), expected);

        let nix_base32 = format!("sha256:{}", "0".repeat(52));
        assert_eq!(documentation_nar_identity(&nix_base32).unwrap(), expected);
    }

    #[test]
    fn portable_filename_accepts_sd_boot_counting_suffix() {
        validate_single_filename("aos-server-2026.08+3.efi", "UKI filename")
            .expect("sd-boot counting filename");
    }

    #[test]
    fn image_artifact_budgets_match_payload_and_partition_contracts() {
        let partitions = [
            ProducerPartitionInfo {
                number: 1,
                label: "ESP".into(),
                kind: "esp".into(),
                filesystem: "vfat".into(),
                size_mi_b: 384,
                offset_bytes: 0,
                size_bytes: 384 * 1024 * 1024,
            },
            ProducerPartitionInfo {
                number: 2,
                label: "root-a".into(),
                kind: "root".into(),
                filesystem: "erofs".into(),
                size_mi_b: 512,
                offset_bytes: 384 * 1024 * 1024,
                size_bytes: 512 * 1024 * 1024,
            },
            ProducerPartitionInfo {
                number: 3,
                label: "root-a-hash".into(),
                kind: "verity".into(),
                filesystem: "dm-verity".into(),
                size_mi_b: 16,
                offset_bytes: 896 * 1024 * 1024,
                size_bytes: 16 * 1024 * 1024,
            },
        ];
        let mut budgets = ProducerArtifactBudgets {
            root: 512,
            verity: 16,
            initrd: 128,
            uki: 160,
            esp: 384,
            runtime_closure: 768,
            download: 640,
        };

        assert!(
            validate_image_artifact_budgets(
                &budgets,
                590 * 1024 * 1024,
                108 * 1024 * 1024,
                &partitions,
            )
            .is_ok()
        );

        budgets.root = 511;
        assert!(
            validate_image_artifact_budgets(
                &budgets,
                590 * 1024 * 1024,
                108 * 1024 * 1024,
                &partitions,
            )
            .is_ok()
        );

        budgets.root = 513;
        assert!(
            validate_image_artifact_budgets(
                &budgets,
                590 * 1024 * 1024,
                108 * 1024 * 1024,
                &partitions,
            )
            .is_err()
        );

        budgets.root = 512;
        budgets.download = 589;
        assert!(
            validate_image_artifact_budgets(
                &budgets,
                590 * 1024 * 1024,
                108 * 1024 * 1024,
                &partitions,
            )
            .is_err()
        );
    }

    #[test]
    fn logical_disk_geometry_bounds_decompression_before_materialization() {
        let mib = 1024 * 1024;
        assert!(validate_logical_disk_geometry(36 * mib, &[(mib, 35 * mib)]).is_ok());
        assert!(validate_logical_disk_geometry(35 * mib, &[(mib, 35 * mib)]).is_err());
        assert!(
            validate_logical_disk_geometry(
                MAX_LOGICAL_DISK_BYTES + mib,
                &[(mib, MAX_LOGICAL_DISK_BYTES)]
            )
            .is_err()
        );
    }

    fn write_direct_image_output(
        container: &Path,
        format: &str,
        targets: serde_json::Value,
    ) -> StorePathInfo {
        let root = container.join("00000000000000000000000000000000-image-output");
        let uki_root = container.join("uki-output");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&uki_root).unwrap();
        let extension = if format == "raw" { "img.zst" } else { format };
        let filename = format!("aos-test.{extension}");
        let image_path = root.join(&filename);
        let logical_path = container.join("logical.raw");
        fs::write(&logical_path, b"exact disk image bytes").unwrap();
        OpenOptions::new()
            .write(true)
            .open(&logical_path)
            .unwrap()
            .set_len(36 * 1024 * 1024)
            .unwrap();
        let logical_size = fs::metadata(&logical_path).unwrap().len();
        let (mut logical_file, logical_identity) =
            open_stable_regular_file_with_links(&logical_path, false).unwrap();
        let logical_sha256 = sha256_open_file(&mut logical_file, &logical_path).unwrap();
        verify_stable_regular_file(&logical_path, &logical_file, &logical_identity).unwrap();
        if format == "raw" {
            logical_file.seek(SeekFrom::Start(0)).unwrap();
            let image_file = fs::File::create(&image_path).unwrap();
            zstd::stream::copy_encode(logical_file, image_file, 1).unwrap();
        } else {
            fs::copy(&logical_path, &image_path).unwrap();
        }
        let (mut image_file, image_identity) =
            open_stable_regular_file_with_links(&image_path, false).unwrap();
        let sha256 = sha256_open_file(&mut image_file, &image_path).unwrap();
        verify_stable_regular_file(&image_path, &image_file, &image_identity).unwrap();
        let uki_filename = "aos-test.efi";
        let uki_path = uki_root.join(uki_filename);
        fs::write(&uki_path, b"unsigned fake UKI bytes").unwrap();
        let (mut uki_file, uki_identity) =
            open_stable_regular_file_with_links(&uki_path, false).unwrap();
        let uki_sha256 = sha256_open_file(&mut uki_file, &uki_path).unwrap();
        verify_stable_regular_file(&uki_path, &uki_file, &uki_identity).unwrap();
        let media_type = match format {
            "raw" => "application/vnd.aos.disk-image.raw+zstd",
            "qcow2" => "application/vnd.aos.disk-image.qcow2",
            "vmdk" => "application/x-vmdk",
            "vhd" => "application/vnd.aos.disk-image.vhd",
            other => panic!("unsupported fixture format {other}"),
        };
        let info = serde_json::json!({
            "schemaVersion": 2,
            "name": "test",
            "version": "2026.08",
            "architecture": "x86_64",
            "platform": "x86_64-linux",
            "format": format,
            "filename": filename,
            "mediaType": media_type,
            "compression": if format == "raw" { "zstd" } else { "none" },
            "byteSize": fs::metadata(&image_path).unwrap().len(),
            "virtualSizeBytes": logical_size,
            "sha256": &sha256,
            "logicalDiskSha256": &logical_sha256,
            "rootfsSha256": "2".repeat(64),
            "artifactBudgetsMiB": {
                "root": 1,
                "verity": 1,
                "initrd": 1,
                "uki": 1,
                "esp": 34,
                "runtimeClosure": 1,
                "download": 64,
            },
            "compatibleTargets": targets,
            "partitionTable": "gpt",
            "kernelParams": "",
            "partitions": [{
                "number": 1,
                "label": "ESP",
                "type": "esp",
                "filesystem": "vfat",
                "sizeMiB": 34,
                "offsetBytes": 0,
                "sizeBytes": 34 * 1024 * 1024,
            }, {
                "number": 2,
                "label": "root-a",
                "type": "root",
                "filesystem": "fake",
                "sizeMiB": 1,
                "offsetBytes": 34 * 1024 * 1024,
                "sizeBytes": 1024 * 1024,
            }],
            "esp": {"uki": "EFI/Linux/aos-test.efi", "sdBoot": "EFI/systemd/systemd-bootx64.efi"},
            "uki": {
                "filename": uki_filename,
                "espPath": "EFI/Linux/aos-test.efi",
                "byteSize": uki_identity.len,
                "sha256": uki_sha256,
                "signed": false,
                "measured": false,
            },
        });
        fs::write(
            root.join("image-info.json"),
            serde_json::to_vec(&info).unwrap(),
        )
        .unwrap();
        StorePathInfo {
            path: root.display().to_string(),
            nar_hash: "sha256:0000000000000000000000000000000000000000000000000000".to_string(),
            nar_size: 128,
            references: Vec::new(),
            closure_size: 128,
        }
    }

    fn write_test_image_projections(
        payload: &StorePathInfo,
    ) -> Result<(StorePathInfo, StorePathInfo)> {
        let payload_path = Path::new(&payload.path);
        let container = payload_path.parent().unwrap();
        let producer: serde_json::Value =
            serde_json::from_slice(&fs::read(payload_path.join("image-info.json"))?)?;
        let filename = producer["filename"].as_str().unwrap();
        let disk_path = container.join("11111111111111111111111111111111-image-disk");
        let info_path = container.join("22222222222222222222222222222222-image-info");
        fs::copy(payload_path.join(filename), &disk_path)?;
        fs::copy(payload_path.join("image-info.json"), &info_path)?;
        let artifact = |path: &Path, marker: char| StorePathInfo {
            path: path.display().to_string(),
            nar_hash: format!("sha256:{}", marker.to_string().repeat(52)),
            nar_size: 256,
            references: Vec::new(),
            closure_size: 256,
        };
        let disk_store = artifact(&disk_path, '1');
        let info_store = artifact(&info_path, '2');
        Ok((disk_store, info_store))
    }

    fn inspect_test_image(
        format: &str,
        payload: StorePathInfo,
        release: &str,
        platform: &str,
    ) -> Result<PublishedImage> {
        let (disk_store, info_store) = write_test_image_projections(&payload)?;
        let payload_path = Path::new(&payload.path);
        let uki_path = payload_path
            .parent()
            .unwrap()
            .join("uki-output/aos-test.efi");
        inspect_published_image_with(
            format,
            payload,
            disk_store,
            info_store,
            &uki_path,
            "test",
            release,
            platform,
            None,
            |_uki, _db_cert| Ok(SbFacts::default()),
        )
    }

    fn rewrite_test_image_parent(store: &StorePathInfo, release: &str, platform: &str) {
        let path = Path::new(&store.path).join("image-info.json");
        let mut info: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        info["version"] = serde_json::json!(release);
        info["platform"] = serde_json::json!(platform);
        info["architecture"] = serde_json::json!(platform.split('-').next().unwrap_or_default());
        fs::write(path, serde_json::to_vec(&info).unwrap()).unwrap();
    }

    #[test]
    fn image_publisher_binds_exact_disk_and_metadata_bytes() {
        let temp = TempDir::new().unwrap();
        let store = write_direct_image_output(
            temp.path(),
            "qcow2",
            serde_json::json!(["qemu-kvm", "openstack"]),
        );
        let image = inspect_test_image("qcow2", store, "2026.08", "x86_64-linux").unwrap();
        assert_eq!(image.delivery.byte_size, 36 * 1024 * 1024);
        assert_eq!(image.delivery.filename, "aos-test.qcow2");
        assert_eq!(image.delivery.image_info.filename, "image-info.json");
        assert_eq!(image.delivery.schema_version, 2);
        assert!(image.delivery.object_key.is_empty());
        assert_eq!(image.delivery.image_info.store_path, image.info_store.path);
        let update_payload = image.delivery.update_payload.as_ref().unwrap();
        assert_eq!(update_payload.store_path, image.payload.path);
        assert_eq!(update_payload.nar_hash, image.payload.nar_hash);
        assert_eq!(update_payload.nar_size, image.payload.nar_size);
        assert_eq!(image.disk.identity.len, image.delivery.byte_size);
        assert_eq!(
            image.uki.path.extension().and_then(|value| value.to_str()),
            Some("efi")
        );
        assert_eq!(image.uki.identity.len, 23);
        assert_eq!(image.delivery.uki.sha256.len(), 64);
        let mut public_info_file = image.image_info.file.try_clone().unwrap();
        public_info_file.seek(SeekFrom::Start(0)).unwrap();
        let mut public_info = String::new();
        public_info_file.read_to_string(&mut public_info).unwrap();
        assert!(!public_info.contains("ukiStorePath"));
        assert_eq!(image.image_info.identity.len, public_info.len() as u64);
    }

    #[test]
    fn image_publisher_rejects_tamper_ambiguity_and_wrong_targets() {
        let tamper = TempDir::new().unwrap();
        let store =
            write_direct_image_output(tamper.path(), "raw", serde_json::json!(["bare-metal"]));
        fs::write(
            Path::new(&store.path).join("aos-test.img.zst"),
            b"changed bytes",
        )
        .unwrap();
        assert!(inspect_test_image("raw", store, "2026.08", "x86_64-linux").is_err());

        let ambiguous = TempDir::new().unwrap();
        let store =
            write_direct_image_output(ambiguous.path(), "raw", serde_json::json!(["bare-metal"]));
        fs::write(Path::new(&store.path).join("another.img"), b"ambiguous").unwrap();
        assert!(inspect_test_image("raw", store, "2026.08", "x86_64-linux").is_err());

        let wrong_target = TempDir::new().unwrap();
        let store = write_direct_image_output(
            wrong_target.path(),
            "qcow2",
            serde_json::json!(["bare-metal"]),
        );
        assert!(inspect_test_image("qcow2", store, "2026.08", "x86_64-linux").is_err());
    }

    #[test]
    fn image_publisher_rejects_path_traversal_and_parent_drift() {
        let traversal = TempDir::new().unwrap();
        let store =
            write_direct_image_output(traversal.path(), "raw", serde_json::json!(["bare-metal"]));
        let info_path = Path::new(&store.path).join("image-info.json");
        let mut info: serde_json::Value =
            serde_json::from_slice(&fs::read(&info_path).unwrap()).unwrap();
        info["filename"] = serde_json::json!("../disk.img");
        fs::write(&info_path, serde_json::to_vec(&info).unwrap()).unwrap();
        assert!(inspect_test_image("raw", store, "2026.08", "x86_64-linux").is_err());

        let drift = TempDir::new().unwrap();
        let store =
            write_direct_image_output(drift.path(), "raw", serde_json::json!(["bare-metal"]));
        assert!(inspect_test_image("raw", store, "2026.09", "x86_64-linux").is_err());
        let store = StorePathInfo {
            path: drift
                .path()
                .join("00000000000000000000000000000000-image-output")
                .display()
                .to_string(),
            nar_hash: "sha256:0000000000000000000000000000000000000000000000000000".to_string(),
            nar_size: 128,
            references: Vec::new(),
            closure_size: 128,
        };
        assert!(inspect_test_image("raw", store, "2026.08", "aarch64-linux").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn image_publisher_rejects_symlinked_artifacts() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let store =
            write_direct_image_output(temp.path(), "raw", serde_json::json!(["bare-metal"]));
        let target = TempDir::new().unwrap();
        let external = target.path().join("real.img");
        let image_path = Path::new(&store.path).join("aos-test.img.zst");
        fs::rename(&image_path, &external).unwrap();
        symlink(&external, &image_path).unwrap();
        assert!(inspect_test_image("raw", store, "2026.08", "x86_64-linux").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn image_publisher_rejects_hardlinked_artifacts() {
        let temp = TempDir::new().unwrap();
        let mut store =
            write_direct_image_output(temp.path(), "raw", serde_json::json!(["bare-metal"]));
        let ordinary_output = temp.path().join("image-output");
        fs::rename(&store.path, &ordinary_output).unwrap();
        store.path = ordinary_output.display().to_string();
        fs::hard_link(
            Path::new(&store.path).join("aos-test.img.zst"),
            temp.path().join("disk-alias.img"),
        )
        .unwrap();
        assert!(inspect_test_image("raw", store, "2026.08", "x86_64-linux").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn stable_file_open_allows_store_optimizer_links_after_store_validation() {
        let temp = TempDir::new().unwrap();
        let artifact = temp.path().join("artifact");
        fs::write(&artifact, b"immutable store bytes").unwrap();
        fs::hard_link(&artifact, temp.path().join("store-optimizer-link")).unwrap();

        assert!(open_stable_regular_file_with_links(&artifact, false).is_err());
        assert!(open_stable_regular_file_with_links(&artifact, true).is_ok());
    }

    #[test]
    fn pinned_image_recheck_detects_namespace_replacement() {
        let temp = TempDir::new().unwrap();
        let store =
            write_direct_image_output(temp.path(), "raw", serde_json::json!(["bare-metal"]));
        let image_path = Path::new(&store.path).join("aos-test.img.zst");
        let image = inspect_test_image("raw", store, "2026.08", "x86_64-linux").unwrap();
        fs::rename(&image_path, temp.path().join("original.img")).unwrap();
        fs::write(&image_path, b"replacement bytes").unwrap();
        assert!(image.recheck_for_commit().is_err());
    }

    #[test]
    fn image_publisher_distinguishes_transfer_and_logical_disk_identity() {
        let temp = TempDir::new().unwrap();
        let store =
            write_direct_image_output(temp.path(), "raw", serde_json::json!(["bare-metal"]));
        let image = inspect_test_image("raw", store, "2026.08", "x86_64-linux").unwrap();
        assert!(image.delivery.byte_size < image.virtual_size_bytes);
        assert_ne!(image.delivery.sha256, image.delivery.logical_disk_sha256);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn compressed_raw_materialization_enforces_exact_logical_size() {
        let logical = b"canonical raw disk bytes";
        let compressed = zstd::stream::encode_all(&logical[..], 1).unwrap();

        let mut output = Vec::new();
        decompress_raw_disk(&compressed[..], &mut output, logical.len() as u64).unwrap();
        assert_eq!(output, logical);

        assert!(
            decompress_raw_disk(&compressed[..], &mut Vec::new(), logical.len() as u64 - 1)
                .is_err()
        );
        assert!(
            decompress_raw_disk(&compressed[..], &mut Vec::new(), logical.len() as u64 + 1)
                .is_err()
        );
        assert!(
            decompress_raw_disk(
                &compressed[..compressed.len() - 1],
                &mut Vec::new(),
                logical.len() as u64,
            )
            .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pinned_raw_materialization_rewinds_after_hashing() {
        let logical = b"canonical raw disk bytes";
        let compressed = zstd::stream::encode_all(&logical[..], 1).unwrap();
        let mut pinned = tempfile::tempfile().unwrap();
        pinned.write_all(&compressed).unwrap();
        pinned.seek(SeekFrom::Start(0)).unwrap();
        sha256_open_file(&mut pinned, Path::new("<compressed test image>")).unwrap();

        let mut output = Vec::new();
        decompress_pinned_raw_disk(&pinned, &mut output, logical.len() as u64).unwrap();

        assert_eq!(output, logical);
    }

    #[test]
    fn image_publisher_rejects_unknown_or_private_metadata() {
        for (field, value) in [
            ("publisherToken", serde_json::json!("secret")),
            ("buildPath", serde_json::json!("/nix/store/secret-input")),
        ] {
            let temp = TempDir::new().unwrap();
            let store =
                write_direct_image_output(temp.path(), "raw", serde_json::json!(["bare-metal"]));
            let info_path = Path::new(&store.path).join("image-info.json");
            let mut info: serde_json::Value =
                serde_json::from_slice(&fs::read(&info_path).unwrap()).unwrap();
            info[field] = value;
            fs::write(&info_path, serde_json::to_vec(&info).unwrap()).unwrap();
            assert!(inspect_test_image("raw", store, "2026.08", "x86_64-linux").is_err());
        }
    }

    #[test]
    fn secure_boot_publish_policy_distinguishes_unverified_active_and_revoked() {
        let temp = TempDir::new().unwrap();
        let store =
            write_direct_image_output(temp.path(), "raw", serde_json::json!(["bare-metal"]));
        let mut image = inspect_test_image("raw", store, "2026.08", "x86_64-linux").unwrap();
        let signer = "e".repeat(64);
        image.sb.signer_cert_sha256 = Some(signer.clone());
        image.delivery.uki.verification = ImageVerificationState::SignedUnverified;

        apply_publish_sb_policy(std::slice::from_mut(&mut image), None, false).unwrap();
        assert_eq!(
            image.delivery.uki.verification,
            ImageVerificationState::SignedUnverified
        );

        let active = SbCertsToml {
            active: vec![SbCert {
                id: "current".into(),
                cert_sha256: signer.clone(),
            }],
            ..SbCertsToml::default()
        };
        assert!(
            apply_publish_sb_policy(std::slice::from_mut(&mut image), Some(&active), false)
                .is_err()
        );
        apply_publish_sb_policy(std::slice::from_mut(&mut image), Some(&active), true).unwrap();
        assert_eq!(
            image.delivery.uki.verification,
            ImageVerificationState::PolicyVerified
        );

        let revoked = SbCertsToml {
            active: active.active,
            revoked: vec![RevokedSbCert {
                id: "current".into(),
                reason: Some("rotated".into()),
            }],
            ..SbCertsToml::default()
        };
        assert!(
            apply_publish_sb_policy(std::slice::from_mut(&mut image), Some(&revoked), true)
                .is_err()
        );
    }

    #[test]
    fn image_publisher_rejects_uki_input_or_signature_state_drift() {
        let input_drift = TempDir::new().unwrap();
        let store =
            write_direct_image_output(input_drift.path(), "raw", serde_json::json!(["bare-metal"]));
        let wrong_uki = input_drift.path().join("uki-output/other.efi");
        fs::write(&wrong_uki, b"other").unwrap();
        let (disk_store, info_store) = write_test_image_projections(&store).unwrap();
        let result = inspect_published_image_with(
            "raw",
            store,
            disk_store,
            info_store,
            &wrong_uki,
            "test",
            "2026.08",
            "x86_64-linux",
            None,
            |_uki, _db_cert| Ok(SbFacts::default()),
        );
        assert!(result.is_err());

        let signature_drift = TempDir::new().unwrap();
        let store = write_direct_image_output(
            signature_drift.path(),
            "raw",
            serde_json::json!(["bare-metal"]),
        );
        let uki_path = signature_drift.path().join("uki-output/aos-test.efi");
        let (disk_store, info_store) = write_test_image_projections(&store).unwrap();
        let result = inspect_published_image_with(
            "raw",
            store,
            disk_store,
            info_store,
            &uki_path,
            "test",
            "2026.08",
            "x86_64-linux",
            None,
            |_uki, _db_cert| {
                Ok(SbFacts {
                    signer_cert_sha256: Some("c".repeat(64)),
                    ..SbFacts::default()
                })
            },
        );
        assert!(result.is_err());
    }

    fn config_module_fixture() -> ConfigModuleMeta {
        ConfigModuleMeta {
            config_output: ConfigOutputMeta {
                store_path: "/nix/store/0000000000000000000000000000000a-firewall-config"
                    .to_string(),
                nar_hash: "sha256:cc".to_string(),
                nar_size: 2048,
                references: vec![],
            },
            evaluation_base_lib: None,
            dependency_outputs: BTreeMap::new(),
            module_abi_compat: ModuleAbiCompat { min: 1, max: 2 },
            declares: vec!["firewall.allowedTCPPorts".to_string()],
            declaration_schema: vec![],
            requires: vec![],
            owns_roots: vec![OwnedRoot {
                root: "firewall".to_string(),
                interface_abi: 1,
                contributable: vec!["allowedTCPPorts".to_string()],
            }],
            contributes: vec![],
            artifacts: Default::default(),
            provides_capabilities: vec!["system.capabilities.dns-resolver".to_string()],
        }
    }

    #[test]
    fn publication_validates_explicit_same_name_owned_root() {
        let declarations = vec!["nginx.enable".to_string(), "nginx.virtualHosts".to_string()];
        let owned = vec![OwnedRoot {
            root: "nginx".to_string(),
            interface_abi: 1,
            contributable: vec!["virtualHosts".to_string()],
        }];

        assert_eq!(
            derive_owned_root_names(&declarations, "nginx", &owned),
            vec!["nginx".to_string()]
        );
        assert!(derive_owned_root_names(&declarations, "nginx", &[]).is_empty());
    }

    #[test]
    fn record_config_module_emits_table_and_feature() {
        let mut table = toml::map::Map::new();
        record_config_module_platform_fields(&mut table, "firewall", &config_module_fixture())
            .expect("records config module");
        assert!(table.contains_key("config_module"));
        let features = table
            .get("requires-features")
            .and_then(toml::Value::as_array)
            .expect("feature array");
        assert!(features.contains(&toml::Value::String(FEATURE_CONFIG_MODULE_V1.to_string())));
        // Idempotent feature append.
        record_config_module_platform_fields(&mut table, "firewall", &config_module_fixture())
            .expect("re-records");
        let features = table
            .get("requires-features")
            .and_then(toml::Value::as_array)
            .expect("feature array");
        assert_eq!(
            features
                .iter()
                .filter(|f| **f == toml::Value::String(FEATURE_CONFIG_MODULE_V1.to_string()))
                .count(),
            1
        );
    }

    #[test]
    fn config_interface_scan_excludes_own_write_from_requires() {
        let tmp = TempDir::new().expect("temporary config module");
        fs::write(
            tmp.path().join("module.nix"),
            "{ config, ... }: { config.web.enable = true; }\n",
        )
        .expect("write module");

        let (contributes, capabilities, requires) =
            scan_config_module_interface(tmp.path(), "web", &[], &[]).expect("scan module");

        assert!(contributes.is_empty());
        assert!(capabilities.is_empty());
        assert!(requires.is_empty());
    }

    #[test]
    fn config_interface_scan_excludes_module_system_metadata() {
        let tmp = TempDir::new().expect("temporary config module");
        fs::write(
            tmp.path().join("module.nix"),
            "{ config, ... }: {\n  config._module.strict = true;\n  config.web.port = config._module.args.port;\n}\n",
        )
        .expect("write module");

        let (contributes, capabilities, requires) =
            scan_config_module_interface(tmp.path(), "web", &[], &[]).expect("scan module");

        assert!(contributes.is_empty());
        assert!(capabilities.is_empty());
        assert!(requires.is_empty());
    }

    #[test]
    fn config_interface_scan_separates_foreign_reads_writes_and_capabilities() {
        let tmp = TempDir::new().expect("temporary config module");
        fs::write(
            tmp.path().join("module.nix"),
            "{ config, ... }: {\n  config.nginx.virtualHosts = {};\n  config.system.capabilities.dns = true;\n  config.web.port = config.redis.port;\n}\n",
        )
        .expect("write module");

        let authored = vec![RootContribution {
            root: "nginx".to_string(),
            interface_abi: 1,
            paths: vec!["virtualHosts".to_string()],
        }];
        let (contributes, capabilities, requires) =
            scan_config_module_interface(tmp.path(), "web", &[], &authored).expect("scan module");

        assert_eq!(
            contributes,
            vec![RootContribution {
                root: "nginx".to_string(),
                interface_abi: 1,
                paths: vec!["virtualHosts".to_string()],
            }]
        );
        assert_eq!(capabilities, vec!["system.capabilities.dns"]);
        assert_eq!(requires, vec!["redis.port"]);
    }

    #[test]
    fn config_interface_scan_does_not_trust_assignment_text_in_comments_or_strings() {
        let tmp = TempDir::new().expect("temporary config module");
        fs::write(
            tmp.path().join("module.nix"),
            "{ ... }: {\n  # config.nginx.enable = true;\n  config.web.note = \"config.redis.enable = true\";\n}\n",
        )
        .expect("write module");

        let (contributes, capabilities, _requires) =
            scan_config_module_interface(tmp.path(), "web", &[], &[]).expect("scan module");

        assert!(contributes.is_empty());
        assert!(capabilities.is_empty());
    }

    #[test]
    fn config_interface_scan_accepts_only_generated_expose_metadata() {
        let tmp = TempDir::new().expect("temporary config module");
        fs::create_dir(tmp.path().join("generated")).expect("create generated directory");
        fs::write(tmp.path().join("module.nix"), "{ ... }: {}\n").expect("write module");
        fs::write(
            tmp.path().join("generated/expose-config.json"),
            "{\"schema\":\"aos.expose-config/v1\"}\n",
        )
        .expect("write generated exposure metadata");

        scan_config_module_interface(tmp.path(), "web", &[], &[])
            .expect("scan generated exposure metadata");

        fs::write(tmp.path().join("authored.json"), "{}\n").expect("write unauthorized helper");
        let error = scan_config_module_interface(tmp.path(), "web", &[], &[])
            .expect_err("reject unauthorized non-Nix helper");
        assert!(error.to_string().contains("non-Nix helper"), "{error:#}");
    }

    #[test]
    fn config_attestation_binds_config_base_lib_and_expose_independently() {
        let payload = StorePathInfo {
            path: "/nix/store/0000000000000000000000000000000a-web-1".to_string(),
            nar_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            nar_size: 1,
            references: vec![],
            closure_size: 1,
        };
        let mut module = config_module_fixture();
        module.config_output.nar_hash =
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string();
        module.evaluation_base_lib = Some(ConfigOutputMeta {
            store_path: "/nix/store/0000000000000000000000000000000c-base-lib".to_string(),
            nar_hash: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                .to_string(),
            nar_size: 1,
            references: vec![],
        });
        let original = publish_config_attestation_meta(
            "web",
            "1",
            "x86_64-linux",
            &payload,
            &module,
            Some("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
        )
        .expect("derive combined attestation");
        let signer = test_provenance_signer();
        let artifact = publish_config_provenance_artifact(
            TEST_PROVENANCE_REGISTRY,
            "web",
            "1",
            "x86_64-linux",
            &payload,
            None,
            &module,
            Some("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
            &original,
            &signer.signer,
        )
        .expect("sign combined config provenance");
        let statement = signed_provenance_statement(&artifact);
        let subjects = statement["subject"].as_array().expect("subjects");
        for (name, digest) in [
            (
                "aos:expose-manifest:web:1:x86_64-linux",
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            ),
            (
                "aos:config-module:web:1:x86_64-linux",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
            (
                "aos:config-base-lib:web:1:x86_64-linux",
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            ),
        ] {
            let subject = subjects
                .iter()
                .find(|subject| subject["name"].as_str() == Some(name))
                .unwrap_or_else(|| panic!("missing signed subject {name}"));
            assert_eq!(subject["digest"]["sha256"].as_str(), Some(digest));
        }

        module.config_output.nar_hash =
            "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string();
        let changed_config = publish_config_attestation_meta(
            "web",
            "1",
            "x86_64-linux",
            &payload,
            &module,
            Some("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
        )
        .expect("derive config-tampered attestation");
        assert_ne!(original.measurement, changed_config.measurement);

        module.config_output.nar_hash =
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string();
        module
            .evaluation_base_lib
            .as_mut()
            .expect("base lib")
            .nar_hash =
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();
        let changed_base = publish_config_attestation_meta(
            "web",
            "1",
            "x86_64-linux",
            &payload,
            &module,
            Some("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
        )
        .expect("derive base-tampered attestation");
        assert_ne!(original.measurement, changed_base.measurement);

        let changed_expose = publish_config_attestation_meta(
            "web",
            "1",
            "x86_64-linux",
            &payload,
            &config_module_fixture_with_base(),
            Some("sha256:1111111111111111111111111111111111111111111111111111111111111111"),
        )
        .expect("derive expose-tampered attestation");
        assert_ne!(original.measurement, changed_expose.measurement);
    }

    fn config_module_fixture_with_base() -> ConfigModuleMeta {
        let mut module = config_module_fixture();
        module.config_output.nar_hash =
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string();
        module.evaluation_base_lib = Some(ConfigOutputMeta {
            store_path: "/nix/store/0000000000000000000000000000000c-base-lib".to_string(),
            nar_hash: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                .to_string(),
            nar_size: 1,
            references: vec![],
        });
        module
    }

    #[test]
    fn build_package_toml_round_trips_config_output_hash_and_base_lib_binding() {
        let info = StorePathInfo {
            path: "/nix/store/0000000000000000000000000000000d-firewall-1".to_string(),
            nar_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            nar_size: 1024,
            references: vec![],
            closure_size: 1024,
        };
        let module = config_module_fixture_with_base();
        let attestation =
            publish_config_attestation_meta("firewall", "1", "x86_64-linux", &info, &module, None)
                .expect("config attestation");
        let content = build_package_toml(
            "",
            "firewall",
            "1",
            "x86_64-linux",
            &info,
            Some("Firewall configuration"),
            None,
            Some("Apache-2.0"),
            Some("Andyl, Inc."),
            false,
            None,
            &[],
            None,
            None,
            None,
            None,
            Some(&module),
            Some(&attestation),
        )
        .expect("render config-module package metadata");

        let parsed = crate::registry::parse::parse_package_toml(&content, "x86_64-linux")
            .expect("parse package metadata")
            .expect("matching platform");
        let parsed_module = parsed.config_module.expect("config module metadata");
        assert_eq!(
            parsed_module.config_output.nar_hash,
            module.config_output.nar_hash
        );
        assert_eq!(
            parsed_module
                .evaluation_base_lib
                .expect("base-lib binding")
                .nar_hash,
            module
                .evaluation_base_lib
                .expect("fixture base-lib binding")
                .nar_hash
        );
        assert!(
            parsed
                .requires_features
                .iter()
                .any(|feature| { feature == FEATURE_CONFIG_MODULE_V1 })
        );
        assert_eq!(parsed.attestation.provenance, attestation.provenance);
    }

    #[test]
    fn build_package_toml_binds_documentation_as_a_signed_platform_artifact() {
        let info = StorePathInfo {
            path: "/nix/store/0000000000000000000000000000000d-firewall-1".to_string(),
            nar_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            nar_size: 1024,
            references: vec![],
            closure_size: 1024,
        };
        let documentation = DocumentationArtifactMeta {
            format: aos_doc_model::DOCUMENT_FORMAT.to_string(),
            store_path: "/nix/store/0000000000000000000000000000000e-firewall-docs.json"
                .to_string(),
            nar_hash: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_string(),
            nar_size: 512,
            document_sha256:
                "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                    .to_string(),
            document_size: 384,
            semantic_schema_sha256:
                "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                    .to_string(),
            references: vec![],
        };
        let attestation = AttestationMeta {
            root_digest: Some(info.nar_hash.clone()),
            provenance: Some("provenance/firewall/1/x86_64-linux.jsonl".to_string()),
            measurement: Some(
                "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                    .to_string(),
            ),
            ..AttestationMeta::default()
        };

        let content = build_package_toml_with_documentation(
            "",
            "firewall",
            "1",
            "x86_64-linux",
            &info,
            Some("Firewall configuration"),
            None,
            Some("Apache-2.0"),
            Some("Andyl, Inc."),
            false,
            None,
            &[],
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&documentation),
            Some(&attestation),
        )
        .expect("render documentation-bearing package metadata");

        let parsed = crate::registry::parse::parse_package_toml(&content, "x86_64-linux")
            .expect("parse package metadata")
            .expect("matching platform");
        assert_eq!(parsed.documentation, Some(documentation));
        assert!(
            parsed
                .requires_features
                .iter()
                .any(|feature| feature == FEATURE_PACKAGE_DOCUMENTATION_V1)
        );
        assert_eq!(parsed.attestation.provenance, attestation.provenance);
    }

    fn test_release_options(tmp: &TempDir) -> ReleaseTreeOptions {
        ReleaseTreeOptions {
            version: semver::Version::parse("1.0.0").unwrap(),
            signing_key: tmp
                .path()
                .join("signing.key")
                .to_string_lossy()
                .into_owned(),
            tuf_signing_keys: Vec::new(),
            channel: None,
            init_channel: false,
            count: None,
            partitions: None,
            cache_dir: tmp.path().join("cache"),
            cache_key: None,
            cache_url: None,
            cache_url_explicit: false,
            cache_priority: 40,
            cache_priority_explicit: false,
            has_store_roots: false,
            no_skip: false,
            upload_urls: Vec::new(),
            upload_auth: AuthOptions::default(),
            dry_run: false,
            resume: false,
            jobs: None,
            store_publish: None,
            cache_max_age_days: 30,
        }
    }

    fn release_policy_info(path: &Path, references: Vec<String>) -> StorePathInfo {
        StorePathInfo {
            path: path.to_string_lossy().into_owned(),
            nar_hash: String::new(),
            nar_size: 0,
            references,
            closure_size: 0,
        }
    }

    fn write_internal_release_policy(path: &Path, identity: &str) {
        fs::create_dir_all(path.join("nix-support")).unwrap();
        fs::write(
            path.join(RELEASE_POLICY_RELATIVE_PATH),
            format!(
                "policy_version=1\nartifact_role=internal-component\nstandalone_release=false\nrelease_via=crucible\ncorresponding_source_required=true\ncorresponding_source_identity={identity}\n"
            ),
        )
        .unwrap();
    }

    #[test]
    fn raw_internal_component_publication_is_rejected() {
        let tmp = TempDir::new().unwrap();
        let qemu = tmp
            .path()
            .join("0000000000000000000000000000000a-qemu-crucible");
        write_internal_release_policy(&qemu, "build-1");

        let error = validate_store_path_release_policy_in_closure(
            &release_policy_info(&qemu, vec![]),
            &[qemu.to_string_lossy().into_owned()],
        )
        .unwrap_err();
        let rendered = format!("{error:#}");
        assert!(rendered.contains("is not an aggregate release root"));
    }

    #[test]
    fn unmarked_wrapper_around_internal_component_is_rejected() {
        let tmp = TempDir::new().unwrap();
        let wrapper = tmp.path().join("0000000000000000000000000000000a-wrapper");
        let qemu = tmp.path().join("0000000000000000000000000000000b-qemu");
        fs::create_dir_all(&wrapper).unwrap();
        write_internal_release_policy(&qemu, "build-1");
        let error = validate_store_path_release_policy_in_closure(
            &release_policy_info(
                &wrapper,
                vec![extract_hash(qemu.to_str().unwrap()).to_owned()],
            ),
            &[
                wrapper.to_string_lossy().into_owned(),
                qemu.to_string_lossy().into_owned(),
            ],
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("has no aggregate release policy"));
    }

    #[test]
    fn plugin_shaped_wrapper_around_internal_component_is_rejected() {
        let tmp = TempDir::new().unwrap();
        let plugin = tmp
            .path()
            .join("0000000000000000000000000000000a-crucible-qemu-plugin");
        let qemu = tmp.path().join("0000000000000000000000000000000b-qemu");
        fs::create_dir_all(&plugin).unwrap();
        write_internal_release_policy(&qemu, "build-1");
        let error = validate_store_path_release_policy_in_closure(
            &release_policy_info(
                &plugin,
                vec![extract_hash(qemu.to_str().unwrap()).to_owned()],
            ),
            &[
                plugin.to_string_lossy().into_owned(),
                qemu.to_string_lossy().into_owned(),
            ],
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("has no aggregate release policy"));
    }

    #[test]
    fn complete_aggregate_publication_retains_matching_source() {
        let tmp = TempDir::new().unwrap();
        let suite = tmp.path().join("0000000000000000000000000000000a-crucible");
        let qemu = tmp
            .path()
            .join("0000000000000000000000000000000b-qemu-crucible");
        let source = tmp
            .path()
            .join("0000000000000000000000000000000c-qemu-crucible-source");
        fs::create_dir_all(suite.join("nix-support")).unwrap();
        write_internal_release_policy(&qemu, "build-1");
        fs::create_dir_all(source.join("nix-support")).unwrap();
        fs::write(
            source.join("nix-support/qemu-crucible-source-build-info"),
            "qemu_build_id=build-1\n",
        )
        .unwrap();
        fs::write(
            suite.join(RELEASE_POLICY_RELATIVE_PATH),
            format!(
                "policy_version=1\nartifact_role=aggregate-release-root\nstandalone_release=true\npair_count=1\npair_1_component_path={}\npair_1_corresponding_source_path={}\npair_1_identity=build-1\n",
                qemu.display(),
                source.display()
            ),
        )
        .unwrap();
        let paired = release_policy_info(
            &suite,
            vec![
                extract_hash(qemu.to_str().unwrap()).to_string(),
                extract_hash(source.to_str().unwrap()).to_string(),
            ],
        );
        validate_store_path_release_policy_in_closure(
            &paired,
            &[
                suite.to_string_lossy().into_owned(),
                qemu.to_string_lossy().into_owned(),
                source.to_string_lossy().into_owned(),
            ],
        )
        .unwrap();
    }

    #[test]
    fn generic_unmarked_qemu_publication_remains_allowed() {
        let tmp = TempDir::new().unwrap();
        let qemu = tmp.path().join("0000000000000000000000000000000a-qemu");
        fs::create_dir_all(&qemu).unwrap();
        validate_store_path_release_policy_in_closure(
            &release_policy_info(&qemu, vec![]),
            &[qemu.to_string_lossy().into_owned()],
        )
        .unwrap();
    }

    fn write_publish_selinux_artifacts(root: &Path, label: &str) {
        let module_name = publish_selinux_identifier_for_label(label);
        let source_text = expected_publish_selinux_profile(label);
        let compiled = compile_publish_selinux_profile(&source_text, &module_name).unwrap();
        let profile_path = root.join(format!("mac/selinux/{module_name}.pp"));
        fs::create_dir_all(profile_path.parent().unwrap()).unwrap();
        fs::write(&profile_path, compiled.profile).unwrap();
        fs::write(
            root.join(format!("mac/selinux/{module_name}.mod")),
            compiled.module,
        )
        .unwrap();
        fs::write(
            root.join(format!("mac/selinux/{module_name}.te")),
            source_text,
        )
        .unwrap();
    }

    fn verity_expose_manifest(root_hash: &str) -> PublishExposeManifest {
        PublishExposeManifest {
            expose: ExposeMeta {
                target: "aos-pkg-webapp.target".into(),
                units: vec!["webapp.service".into()],
                images: vec![crate::types::SysrootImageEntry {
                    format: "ext4-verity".into(),
                    store_path: "/nix/store/imagehash111-webapp-root".into(),
                    nar_hash: "sha256:image".into(),
                    nar_size: 4096,
                    delivery: crate::types::test_image_delivery("raw"),
                    sb_signer_cert_sha256: None,
                    sbat: Vec::new(),
                    expected_pcr11: None,
                    ukis: Vec::new(),
                    recovery_ukis: Vec::new(),
                    recovery_bundle: None,
                    root_image: Some("root.img".into()),
                    root_verity: Some("root.verity".into()),
                    root_hash: Some(root_hash.into()),
                    root_hash_sig: Some("root.roothash.p7s".into()),
                }],
                requires: Vec::new(),
                config: Default::default(),
                provides: Vec::new(),
                uses: Vec::new(),
            },
            permissions: PermissionsMeta::default(),
            mac: None,
            _kernel: None,
            _firewall: None,
            _confinement: None,
        }
    }

    #[test]
    fn parse_sbat_csv_reads_component_generations() {
        let csv = "sbat,1,SBAT Version,sbat,1,https://x\naos,2,AOS,aos,2,https://aos\n# comment\n\nsystemd,1,systemd,systemd,1,https://systemd\n";
        let entries = parse_sbat_csv(csv).unwrap();
        assert_eq!(
            entries,
            vec![
                SbatEntry {
                    component: "sbat".into(),
                    generation: 1
                },
                SbatEntry {
                    component: "aos".into(),
                    generation: 2
                },
                SbatEntry {
                    component: "systemd".into(),
                    generation: 1
                },
            ]
        );
    }

    #[test]
    fn parse_sbat_csv_rejects_non_numeric_generation() {
        assert!(parse_sbat_csv("aos,notanumber,AOS\n").is_err());
    }

    fn synthetic_pe_section(name: &[u8], virtual_size: u32, raw: &[u8]) -> Vec<u8> {
        assert!(name.len() <= 8);
        let pe_offset = 0x40_usize;
        let optional_size = 112_usize;
        let section_table = pe_offset + 4 + 20 + optional_size;
        let raw_offset = section_table + 40;
        let mut pe = vec![0_u8; raw_offset + raw.len()];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());
        pe[pe_offset..pe_offset + 4].copy_from_slice(&0x0000_4550_u32.to_le_bytes());
        let coff = pe_offset + 4;
        pe[coff + 2..coff + 4].copy_from_slice(&1_u16.to_le_bytes());
        pe[coff + 16..coff + 18].copy_from_slice(&(optional_size as u16).to_le_bytes());
        pe[coff + 20..coff + 22].copy_from_slice(&0x020b_u16.to_le_bytes());
        pe[section_table..section_table + name.len()].copy_from_slice(name);
        pe[section_table + 8..section_table + 12].copy_from_slice(&virtual_size.to_le_bytes());
        pe[section_table + 16..section_table + 20]
            .copy_from_slice(&(raw.len() as u32).to_le_bytes());
        pe[section_table + 20..section_table + 24]
            .copy_from_slice(&(raw_offset as u32).to_le_bytes());
        pe[raw_offset..].copy_from_slice(raw);
        pe
    }

    #[test]
    fn pe_section_returns_virtual_bytes_without_file_padding() {
        let pe = synthetic_pe_section(b".cmdline", 5, b"root\0padding");
        assert_eq!(pe_section(&pe, ".cmdline").unwrap(), Some(&b"root\0"[..]));
        assert!(pe_section(&pe, ".sbat").unwrap().is_none());

        let zero_virtual = synthetic_pe_section(b".cmdline", 0, b"ignored");
        assert!(pe_section(&zero_virtual, ".cmdline").unwrap().is_none());

        let larger_virtual = synthetic_pe_section(b".cmdline", 32, b"materialized");
        assert_eq!(
            pe_section(&larger_virtual, ".cmdline").unwrap(),
            Some(&b"materialized"[..])
        );
    }

    #[test]
    fn pe_section_rejects_malformed_and_duplicate_ranges() {
        let mut malformed = synthetic_pe_section(b".sbat", 5, b"short");
        let pe_offset = 0x40_usize;
        let coff = pe_offset + 4;
        let section_table = coff + 20 + 112;
        malformed[section_table + 20..section_table + 24].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(pe_section(&malformed, ".sbat").is_err());

        let mut duplicate_pe = synthetic_pe_section(b".sbat", 5, b"short");
        duplicate_pe[coff + 2..coff + 4].copy_from_slice(&2_u16.to_le_bytes());
        let duplicate = duplicate_pe[section_table..section_table + 40].to_vec();
        duplicate_pe.splice(section_table + 40..section_table + 40, duplicate);
        assert!(pe_section(&duplicate_pe, ".sbat").is_err());
    }

    #[test]
    fn parse_pcr11_extracts_sha256_digest() {
        let out = "11:sha256=abcdef0123\n12:sha256=ffff\n";
        assert_eq!(parse_pcr11(out).as_deref(), Some("abcdef0123"));
        assert_eq!(parse_pcr11("no pcr lines here"), None);
    }

    #[test]
    fn parse_pcr11_takes_ready_phase_line() {
        // `systemd-measure calculate` prints one 11: line per boot phase
        // (enter-initrd first and ready last). Runtime activation happens after
        // the ready barrier, so the catalog pins the final line.
        let out = "# PCR[11] Phase <enter-initrd>\n\
                   # PCR[11] Phase <enter-initrd:leave-initrd>\n\
                   11:sha256=aaaa\n\
                   11:sha256=bbbb\n";
        assert_eq!(parse_pcr11(out).as_deref(), Some("bbbb"));
    }

    #[test]
    fn uki_discovery_uses_explicit_ab_slot_names() {
        let temp = tempfile::TempDir::new().unwrap();
        std::fs::write(temp.path().join("uki-b.efi"), b"b").unwrap();
        std::fs::write(temp.path().join("uki-a.efi"), b"a").unwrap();
        std::fs::write(temp.path().join("other.txt"), b"not a UKI").unwrap();

        let found = find_ukis_in_store_path(temp.path().to_str().unwrap()).unwrap();
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].0, Some(UkiSlot::A));
        assert_eq!(found[0].1.file_name().unwrap(), "uki-a.efi");
        assert_eq!(found[1].0, Some(UkiSlot::B));
        assert_eq!(found[1].1.file_name().unwrap(), "uki-b.efi");
    }

    #[test]
    fn uki_discovery_rejects_ambiguous_or_partial_payloads() {
        let partial = tempfile::TempDir::new().unwrap();
        std::fs::write(partial.path().join("uki-a.efi"), b"a").unwrap();
        let error = find_ukis_in_store_path(partial.path().to_str().unwrap()).unwrap_err();
        assert!(error.to_string().contains("both uki-a.efi and uki-b.efi"));

        let ambiguous = tempfile::TempDir::new().unwrap();
        std::fs::write(ambiguous.path().join("one.efi"), b"one").unwrap();
        std::fs::write(ambiguous.path().join("two.efi"), b"two").unwrap();
        let error = find_ukis_in_store_path(ambiguous.path().to_str().unwrap()).unwrap_err();
        assert!(error.to_string().contains("deterministic"));
    }

    #[test]
    fn der_len_handles_short_and_long_forms() {
        assert_eq!(der_len(&[0x05]).unwrap(), (5, 1));
        // 0x82 => two length octets follow: 0x01 0x00 = 256.
        assert_eq!(der_len(&[0x82, 0x01, 0x00]).unwrap(), (256, 3));
    }

    #[test]
    fn leaf_cert_from_pe_extracts_first_certificate() {
        // Build a tiny synthetic PE32+ with a security directory whose
        // WIN_CERTIFICATE blob holds a PKCS#7 ContentInfo wrapping a
        // SignedData with two certificates; assert we return the first.
        let leaf: &[u8] = &[0x30, 0x03, 0x01, 0x02, 0x03]; // SEQUENCE len 3
        let second: &[u8] = &[0x30, 0x02, 0x09, 0x08]; // SEQUENCE len 2
        let mut certs_value = Vec::new();
        certs_value.extend_from_slice(leaf);
        certs_value.extend_from_slice(second);
        // certificates [0] IMPLICIT (tag 0xA0).
        let mut certs_field = vec![0xA0, certs_value.len() as u8];
        certs_field.extend_from_slice(&certs_value);
        // SignedData SEQUENCE wrapping the certificates field.
        let mut signed_data = vec![0x30, certs_field.len() as u8];
        signed_data.extend_from_slice(&certs_field);
        // content [0] EXPLICIT wrapping SignedData.
        let mut content = vec![0xA0, signed_data.len() as u8];
        content.extend_from_slice(&signed_data);
        // ContentInfo SEQUENCE { OID, content [0] }.
        let oid: &[u8] = &[0x06, 0x01, 0x2A]; // OBJECT IDENTIFIER len 1
        let mut ci_value = Vec::new();
        ci_value.extend_from_slice(oid);
        ci_value.extend_from_slice(&content);
        let mut pkcs7 = vec![0x30, ci_value.len() as u8];
        pkcs7.extend_from_slice(&ci_value);

        let extracted = first_certificate_der(&pkcs7).unwrap();
        assert_eq!(extracted, leaf);

        // Wrap the PKCS#7 in a WIN_CERTIFICATE blob and a minimal PE32+ so
        // leaf_cert_from_pe finds it via the security directory.
        let mut win_cert = vec![0u8; 8]; // dwLength/wRevision/wCertificateType
        win_cert.extend_from_slice(&pkcs7);

        // Assemble: DOS header (e_lfanew at 0x3c), PE sig, COFF, optional
        // header (PE32+ magic), data directories with security entry.
        let mut pe = vec![0u8; 0x40];
        pe[0] = b'M';
        pe[1] = b'Z';
        let pe_off: u32 = 0x40;
        pe[0x3c..0x40].copy_from_slice(&pe_off.to_le_bytes());
        // PE signature + COFF header (20 bytes) + optional header.
        let mut tail = Vec::new();
        tail.extend_from_slice(&0x0000_4550u32.to_le_bytes()); // "PE\0\0"
        tail.extend_from_slice(&[0u8; 20]); // COFF header
        tail[20..22].copy_from_slice(&(112_u16 + 16 * 8).to_le_bytes());
        let opt_start = pe.len() + tail.len();
        tail.extend_from_slice(&0x020bu16.to_le_bytes()); // PE32+ magic
        // Pad optional header up to the data directory (112 bytes from magic).
        tail.resize(tail.len() + (112 - 2), 0);
        let count_in_tail = (opt_start - pe.len()) + 108;
        tail[count_in_tail..count_in_tail + 4].copy_from_slice(&16_u32.to_le_bytes());
        let dir_start = opt_start + 112;
        // Security dir is entry index 4 (each entry 8 bytes).
        let cert_off = dir_start + 16 * 8; // place blob after all 16 entries
        tail.resize(tail.len() + 16 * 8, 0);
        // Write security entry (index 4): offset + size.
        let entry_in_tail = (dir_start - pe.len()) + 4 * 8;
        tail[entry_in_tail..entry_in_tail + 4].copy_from_slice(&(cert_off as u32).to_le_bytes());
        tail[entry_in_tail + 4..entry_in_tail + 8]
            .copy_from_slice(&(win_cert.len() as u32).to_le_bytes());
        pe.extend_from_slice(&tail);
        assert_eq!(pe.len(), cert_off);
        pe.extend_from_slice(&win_cert);

        let from_pe = leaf_cert_from_pe(&pe).unwrap().unwrap();
        assert_eq!(from_pe, leaf);

        let mut unsigned = pe;
        let entry_in_pe = 0x40 + entry_in_tail;
        unsigned[entry_in_pe..entry_in_pe + 8].fill(0);
        assert!(leaf_cert_from_pe(&unsigned).unwrap().is_none());

        let mut malformed = unsigned;
        malformed[entry_in_pe..entry_in_pe + 4].copy_from_slice(&(cert_off as u32).to_le_bytes());
        assert!(leaf_cert_from_pe(&malformed).is_err());

        let mut truncated_optional_header = malformed;
        let coff_optional_size = 0x40 + 4 + 16;
        truncated_optional_header[coff_optional_size..coff_optional_size + 2]
            .copy_from_slice(&64_u16.to_le_bytes());
        assert!(leaf_cert_from_pe(&truncated_optional_header).is_err());
    }

    /// Wrap a DER value in a SEQUENCE/SET/context tag with a short length.
    fn der_wrap(tag: u8, value: &[u8]) -> Vec<u8> {
        assert!(value.len() < 0x80, "test helper only handles short form");
        let mut out = vec![tag, value.len() as u8];
        out.extend_from_slice(value);
        out
    }

    /// M3: with a real SignerInfo present, the signer cert is selected by
    /// issuer+serial even when it is NOT first in the certificate SET. A
    /// naive "take element [0]" would return the intermediate and fail.
    #[test]
    fn first_certificate_der_selects_signer_by_issuer_and_serial() {
        // Build a minimal Certificate: SEQUENCE { TBSCertificate SEQUENCE {
        //   serialNumber INTEGER, signature SEQUENCE{}, issuer Name SEQUENCE
        // } }. We omit signatureAlgorithm/signatureValue siblings — only the
        // TBS prefix is parsed by cert_issuer_and_serial.
        fn make_cert(serial: u8, issuer_byte: u8) -> Vec<u8> {
            let serial_int = vec![0x02, 0x01, serial]; // INTEGER serial
            let sig_alg = der_wrap(0x30, &[]); // empty AlgorithmIdentifier
            let issuer = der_wrap(0x30, &[0x05, 0x01, issuer_byte]); // Name
            let mut tbs_value = Vec::new();
            tbs_value.extend_from_slice(&serial_int);
            tbs_value.extend_from_slice(&sig_alg);
            tbs_value.extend_from_slice(&issuer);
            let tbs = der_wrap(0x30, &tbs_value);
            der_wrap(0x30, &tbs) // Certificate wraps the TBS
        }

        // Intermediate (serial 1, issuer 0xAA) and signer (serial 9, issuer
        // 0xBB). Place the signer second.
        let intermediate = make_cert(1, 0xAA);
        let signer = make_cert(9, 0xBB);
        let mut certs_value = Vec::new();
        certs_value.extend_from_slice(&intermediate);
        certs_value.extend_from_slice(&signer);
        let certs_field = der_wrap(0xA0, &certs_value);

        // SignerInfo SEQUENCE { version INTEGER 1, IssuerAndSerialNumber
        //   SEQUENCE { issuer Name(0xBB), serialNumber INTEGER 9 } }.
        let issuer_bb = der_wrap(0x30, &[0x05, 0x01, 0xBB]);
        let serial_9 = vec![0x02, 0x01, 0x09];
        let mut ias_value = Vec::new();
        ias_value.extend_from_slice(&issuer_bb);
        ias_value.extend_from_slice(&serial_9);
        let ias = der_wrap(0x30, &ias_value);
        let mut signer_info_value = vec![0x02, 0x01, 0x01]; // version 1
        signer_info_value.extend_from_slice(&ias);
        let signer_info = der_wrap(0x30, &signer_info_value);
        let signer_infos = der_wrap(0x31, &signer_info); // SET OF SignerInfo

        // SignedData SEQUENCE { certificates [0], signerInfos SET }.
        let mut signed_data_value = Vec::new();
        signed_data_value.extend_from_slice(&certs_field);
        signed_data_value.extend_from_slice(&signer_infos);
        let signed_data = der_wrap(0x30, &signed_data_value);
        let content = der_wrap(0xA0, &signed_data); // content [0] EXPLICIT
        let mut ci_value = vec![0x06, 0x01, 0x2A]; // contentType OID
        ci_value.extend_from_slice(&content);
        let pkcs7 = der_wrap(0x30, &ci_value);

        let extracted = first_certificate_der(&pkcs7).unwrap();
        assert_eq!(
            extracted,
            signer.as_slice(),
            "signer cert (issuer 0xBB / serial 9) must be selected, not the first cert"
        );

        // Sanity: the SHA-256 of the selected cert is the signer's digest.
        assert_eq!(sha256_hex(extracted), sha256_hex(&signer));
    }

    const SBCERT_A: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    const SBCERT_B: &str = "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752";

    #[test]
    fn add_sb_cert_enrolls_and_rejects_dupes() {
        let mut catalog = SbCertsToml::default();
        add_sb_cert(&mut catalog, "db-2026", SBCERT_A).unwrap();
        assert_eq!(catalog.active.len(), 1);
        assert_eq!(catalog.active[0].cert_sha256, SBCERT_A);
        // Uppercase digest is normalized to lowercase.
        let mut c2 = SbCertsToml::default();
        add_sb_cert(&mut c2, "db", &SBCERT_A.to_ascii_uppercase()).unwrap();
        assert_eq!(c2.active[0].cert_sha256, SBCERT_A);
        // Duplicate id and duplicate digest both rejected.
        assert!(add_sb_cert(&mut catalog, "db-2026", SBCERT_B).is_err());
        assert!(add_sb_cert(&mut catalog, "other", SBCERT_A).is_err());
        // Bad digest rejected.
        assert!(add_sb_cert(&mut catalog, "bad", "nothex").is_err());
    }

    #[test]
    fn retire_sb_cert_moves_active_to_revoked() {
        let mut catalog = SbCertsToml::default();
        add_sb_cert(&mut catalog, "db", SBCERT_A).unwrap();
        retire_sb_cert(&mut catalog, "db", Some("compromised")).unwrap();
        assert_eq!(catalog.revoked.len(), 1);
        // Still active-listed (validate_catalog requires it) but revoked.
        assert!(catalog.active.iter().any(|c| c.id == "db"));
        assert!(!catalog.accepts_signer(SBCERT_A));
        // Already revoked / unknown id rejected.
        assert!(retire_sb_cert(&mut catalog, "db", None).is_err());
        assert!(retire_sb_cert(&mut catalog, "ghost", None).is_err());
    }

    #[test]
    fn set_sbat_floor_raises_only() {
        let mut catalog = SbCertsToml::default();
        set_sbat_floor(&mut catalog, "aos", 1).unwrap();
        set_sbat_floor(&mut catalog, "aos", 3).unwrap();
        assert_eq!(catalog.sbat_floor[0].generation, 3);
        // Lowering is refused.
        assert!(set_sbat_floor(&mut catalog, "aos", 2).is_err());
        // Equal is allowed (idempotent re-set).
        set_sbat_floor(&mut catalog, "aos", 3).unwrap();
        // New component inserted.
        set_sbat_floor(&mut catalog, "systemd", 1).unwrap();
        assert_eq!(catalog.sbat_floor.len(), 2);
        assert!(set_sbat_floor(&mut catalog, "", 1).is_err());
    }

    struct TestSigningFixture {
        trusted_key: String,
        private_key: PathBuf,
    }

    #[test]
    fn parse_store_path_standard() {
        let (name, version) =
            parse_store_path("/nix/store/k7j3m8abc123def456ghijklmnopqrst-curl-8.5.0");
        assert_eq!(name, "curl");
        assert_eq!(version, "8.5.0");
    }

    #[test]
    fn parse_store_path_multi_dash_name() {
        let (name, version) =
            parse_store_path("/nix/store/k7j3m8abc123def456ghijklmnopqrst-my-cool-package-1.2.3");
        assert_eq!(name, "my-cool-package");
        assert_eq!(version, "1.2.3");
    }

    #[test]
    fn parse_store_path_no_version() {
        let (name, version) =
            parse_store_path("/nix/store/k7j3m8abc123def456ghijklmnopqrst-just-name");
        assert_eq!(name, "just-name");
        assert_eq!(version, "0.0.0");
    }

    #[test]
    fn first_letter_basic() {
        assert_eq!(first_letter("curl"), "c");
        assert_eq!(first_letter("Zlib"), "z");
    }

    #[test]
    fn semver_tag_list_filters_and_sorts_registry_releases() {
        let versions =
            semver_versions_from_tag_list("not-a-release\n1.2.0\nv1.3.0\n1.1.9\n1.2.0\n");
        assert_eq!(
            versions,
            vec![
                semver::Version::parse("1.1.9").unwrap(),
                semver::Version::parse("1.2.0").unwrap(),
            ],
        );
    }

    #[test]
    fn initial_keys_roster_defaults_to_empty_schema_one_roster() {
        let roster = initial_keys_roster("aos-core", None, None).unwrap();
        assert_eq!(roster.schema, keys::KEYS_TOML_SCHEMA);
        assert!(roster.active.is_empty());
        assert!(roster.revoked.is_empty());
    }

    #[test]
    fn initial_keys_roster_accepts_matching_registry_key() {
        let roster =
            initial_keys_roster("aos-core", Some("aos-core:Ed25519:YWJjZA=="), Some("2026a"))
                .unwrap();
        assert_eq!(roster.active.len(), 1);
        assert_eq!(roster.active[0].id, "2026a");
        assert_eq!(roster.active[0].key, "aos-core:Ed25519:YWJjZA==");
    }

    #[test]
    fn initial_keys_roster_defaults_key_id_when_key_is_supplied() {
        let roster =
            initial_keys_roster("aos-core", Some("aos-core:Ed25519:YWJjZA=="), None).unwrap();
        assert_eq!(roster.active[0].id, "initial");
    }

    #[test]
    fn initial_keys_roster_rejects_key_id_without_key() {
        let err = initial_keys_roster("aos-core", None, Some("2026a")).unwrap_err();
        assert!(format!("{err:#}").contains("--trust-key-id requires --trust-key"));
    }

    #[test]
    fn initial_keys_roster_rejects_invalid_key_id() {
        let err = initial_keys_roster(
            "aos-core",
            Some("aos-core:Ed25519:YWJjZA=="),
            Some("bad/id"),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("key id"));
    }

    #[test]
    fn initial_keys_roster_rejects_foreign_registry_key() {
        let err = initial_keys_roster("aos-core", Some("other:Ed25519:YWJjZA=="), Some("2026a"))
            .unwrap_err();
        assert!(format!("{err:#}").contains("expected 'aos-core'"));
    }

    #[test]
    fn resolve_upload_urls_prefers_flags_over_persisted_defaults() {
        let upload_auth = RegistryUploadAuthConfig {
            upload_urls: vec!["s3://persisted/".to_string()],
            ..RegistryUploadAuthConfig::default()
        };
        let config = ApmConfig {
            settings: ApmSettings::default(),
            registries: vec![(test_registry_config("aos-core", Some(upload_auth)), None)],
            scope: ProfileScope::User,
        };

        let flags = vec!["s3://flag/".to_string()];
        assert_eq!(resolve_upload_urls(&config, "aos-core", &flags), flags);
        assert_eq!(
            resolve_upload_urls(&config, "aos-core", &[]),
            vec!["s3://persisted/".to_string()],
        );
        // A registry with no persisted defaults resolves to no destinations.
        assert!(resolve_upload_urls(&config, "other", &[]).is_empty());
    }

    #[test]
    fn release_validation_rejects_cache_flags_without_publishing() {
        let tmp = TempDir::new().unwrap();

        let mut options = test_release_options(&tmp);
        options.cache_url = Some("https://cache.example".to_string());
        options.cache_url_explicit = true;
        assert!(
            format!("{:#}", validate_release_options(&options).unwrap_err())
                .contains("--cache-url requires an upload destination")
        );

        let mut options = test_release_options(&tmp);
        options.cache_key = Some(tmp.path().join("narinfo.key"));
        assert!(
            format!("{:#}", validate_release_options(&options).unwrap_err())
                .contains("--cache-key signs published narinfos")
        );

        let mut options = test_release_options(&tmp);
        options.cache_priority_explicit = true;
        assert!(
            format!("{:#}", validate_release_options(&options).unwrap_err())
                .contains("--cache-priority requires an upload destination")
        );

        let mut options = test_release_options(&tmp);
        options.no_skip = true;
        assert!(
            format!("{:#}", validate_release_options(&options).unwrap_err())
                .contains("--no-skip requires an upload destination")
        );
    }

    #[test]
    fn release_validation_rejects_cache_flags_when_publishing_without_roots() {
        let tmp = TempDir::new().unwrap();
        let mut options = test_release_options(&tmp);
        options.upload_urls = vec!["file:///tmp/origin".to_string()];
        options.cache_url = Some("https://cache.example".to_string());
        options.cache_url_explicit = true;

        assert!(
            format!("{:#}", validate_release_options(&options).unwrap_err())
                .contains("cache flags require registry store paths")
        );
    }

    #[test]
    fn release_tag_preflight_rejects_existing_tag_unless_resume() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        git(
            tmp.path(),
            &[
                "init",
                "--object-format=sha256",
                "--initial-branch=main",
                repo.to_str().unwrap(),
            ],
        )
        .unwrap();
        git(&repo, &["config", "user.name", "AOS Registry"]).unwrap();
        git(&repo, &["config", "user.email", "registry@example.com"]).unwrap();
        git(&repo, &["config", "commit.gpgsign", "false"]).unwrap();
        fs::write(
            repo.join("registry.toml"),
            "[registry]\nname = \"aos-core\"\n",
        )
        .unwrap();
        git(&repo, &["add", "."]).unwrap();
        git(&repo, &["commit", "-m", "init"]).unwrap();
        // Create the annotated release tag the way production does, via
        // `sign_tag` (libgit2). The `git()` porcelain dispatcher only supports
        // `tag --list` / `tag -d`, so `git tag -a` is an unsupported invocation.
        let signing = write_test_signing_key(tmp.path(), "aos-core");
        sign_tag(
            &repo,
            "1.0.0",
            "HEAD",
            Some("release 1.0.0"),
            signing.private_key.to_str().unwrap(),
            false,
        )
        .unwrap();

        let taken = semver::Version::parse("1.0.0").unwrap();
        let unused = semver::Version::parse("2.0.0").unwrap();

        // A version already released is rejected before any mutating work.
        let err = ensure_release_tag_available(&repo, &taken, false).unwrap_err();
        assert!(
            format!("{err:#}").contains("already exists"),
            "unexpected error: {err:#}"
        );

        // An unused version passes the preflight.
        ensure_release_tag_available(&repo, &unused, false).unwrap();

        // `resume` legitimately reuses an existing tag, so the preflight is skipped.
        ensure_release_tag_available(&repo, &taken, true).unwrap();
    }

    #[test]
    fn release_cache_url_derives_from_single_http_upload_only() {
        assert_eq!(
            resolve_effective_release_cache_url(
                None,
                &["https://cache.example/root".to_string()],
                true,
            )
            .unwrap()
            .as_deref(),
            Some("https://cache.example/root"),
        );
        // Write-only single destinations cannot be advertised as a read URL.
        for write_only in [
            "file:///tmp/origin",
            "s3://bucket/prefix",
            "sftp://host/srv/cache",
        ] {
            assert!(
                resolve_effective_release_cache_url(None, &[write_only.to_string()], true).is_err(),
                "{write_only} should require an explicit --cache-url",
            );
        }
        assert!(
            resolve_effective_release_cache_url(
                None,
                &[
                    "https://cache.example/a".to_string(),
                    "https://cache.example/b".to_string(),
                ],
                true,
            )
            .is_err()
        );
        // An explicit --cache-url is always honored, even for write-only uploads.
        assert_eq!(
            resolve_effective_release_cache_url(
                Some("https://cdn.example/cache"),
                &["s3://bucket/prefix".to_string()],
                true,
            )
            .unwrap()
            .as_deref(),
            Some("https://cdn.example/cache"),
        );
    }

    #[test]
    fn producer_signing_key_direct_path_bypasses_key_id_lookup() {
        let config = ApmConfig {
            settings: ApmSettings::default(),
            registries: Vec::new(),
            scope: ProfileScope::User,
        };
        let resolved = resolve_producer_signing_key(
            &config,
            Path::new("/missing"),
            "aos-core",
            Some("/tmp/key"),
            None,
        )
        .unwrap();

        assert_eq!(resolved.path(), "/tmp/key");
    }

    #[test]
    fn producer_signing_key_rejects_ambiguous_key_sources() {
        let config = ApmConfig {
            settings: ApmSettings::default(),
            registries: Vec::new(),
            scope: ProfileScope::User,
        };
        let err = resolve_producer_signing_key(
            &config,
            Path::new("/missing"),
            "aos-core",
            Some("/tmp/key"),
            Some("initial"),
        )
        .unwrap_err();

        assert!(format!("{err:#}").contains("use only one of --key or --key-id"));
    }

    #[test]
    fn producer_signing_key_id_resolves_configured_private_key() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        let signing = write_test_signing_key(tmp.path(), "aos-core");
        write_test_roster(&repo, "initial", &signing.trusted_key, &[]).unwrap();
        let config = test_config_with_signing_key("aos-core", "initial", &signing.private_key);

        let resolved =
            resolve_producer_signing_key(&config, &repo, "aos-core", None, Some("initial"))
                .unwrap();

        assert_eq!(PathBuf::from(resolved.path()), signing.private_key);
    }

    #[test]
    fn producer_signing_key_id_rejects_missing_local_mapping() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        let signing = write_test_signing_key(tmp.path(), "aos-core");
        write_test_roster(&repo, "initial", &signing.trusted_key, &[]).unwrap();
        let config = ApmConfig {
            settings: ApmSettings::default(),
            registries: vec![(test_registry_config("aos-core", None), None)],
            scope: ProfileScope::User,
        };

        let err = resolve_producer_signing_key(&config, &repo, "aos-core", None, Some("initial"))
            .unwrap_err();

        assert!(format!("{err:#}").contains("no local private key configured"));
    }

    #[test]
    fn producer_signing_key_id_rejects_revoked_key() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        let signing = write_test_signing_key(tmp.path(), "aos-core");
        write_test_roster(&repo, "initial", &signing.trusted_key, &["initial"]).unwrap();
        let config = test_config_with_signing_key("aos-core", "initial", &signing.private_key);

        let err = resolve_producer_signing_key(&config, &repo, "aos-core", None, Some("initial"))
            .unwrap_err();

        assert!(format!("{err:#}").contains("revoked"));
    }

    #[test]
    fn producer_signing_key_id_signs_verifiable_release_tag() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        git(
            tmp.path(),
            &[
                "init",
                "--object-format=sha256",
                "--initial-branch=main",
                repo.to_str().unwrap(),
            ],
        )
        .unwrap();
        git(&repo, &["config", "user.name", "AOS Registry"]).unwrap();
        git(&repo, &["config", "user.email", "registry@example.com"]).unwrap();
        git(&repo, &["config", "commit.gpgsign", "false"]).unwrap();
        fs::write(
            repo.join("registry.toml"),
            "[registry]\nname = \"aos-core\"\n",
        )
        .unwrap();

        let signing = write_test_signing_key(tmp.path(), "aos-core");
        write_test_roster(&repo, "initial", &signing.trusted_key, &[]).unwrap();
        git(&repo, &["add", "."]).unwrap();
        git(&repo, &["commit", "-m", "init"]).unwrap();

        let config = test_config_with_signing_key("aos-core", "initial", &signing.private_key);
        let resolved =
            resolve_producer_signing_key(&config, &repo, "aos-core", None, Some("initial"))
                .unwrap();
        sign_tag(
            &repo,
            "1.0.0",
            "HEAD",
            Some("AOS registry release"),
            resolved.path(),
            false,
        )
        .unwrap();

        assert!(
            verify_tag_signature(&repo, "1.0.0", std::slice::from_ref(&signing.trusted_key))
                .unwrap()
        );
    }

    #[test]
    fn producer_signing_key_command_source_signs_verifiable_release_tag() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        git(
            tmp.path(),
            &[
                "init",
                "--object-format=sha256",
                "--initial-branch=main",
                repo.to_str().unwrap(),
            ],
        )
        .unwrap();
        git(&repo, &["config", "user.name", "AOS Registry"]).unwrap();
        git(&repo, &["config", "user.email", "registry@example.com"]).unwrap();
        git(&repo, &["config", "commit.gpgsign", "false"]).unwrap();
        fs::write(
            repo.join("registry.toml"),
            "[registry]\nname = \"aos-core\"\n",
        )
        .unwrap();

        let signing = write_test_signing_key(tmp.path(), "aos-core");
        write_test_roster(&repo, "initial", &signing.trusted_key, &[]).unwrap();
        git(&repo, &["add", "."]).unwrap();
        git(&repo, &["commit", "-m", "init"]).unwrap();

        // A command source: `cat` the key file just-in-time. This exercises
        // the materialize-to-tempfile path that `ssh-keygen`'s double-open
        // requires (a pipe would fail here).
        let mut registry_config = test_registry_config("aos-core", None);
        registry_config.signing_keys.insert(
            "initial".to_string(),
            SigningKeySource::Spec(SigningKeySpec {
                path: None,
                command: Some(format!("cat {}", signing.private_key.display())),
            }),
        );
        let config = ApmConfig {
            settings: ApmSettings::default(),
            registries: vec![(registry_config, None)],
            scope: ProfileScope::User,
        };

        let resolved =
            resolve_producer_signing_key(&config, &repo, "aos-core", None, Some("initial"))
                .unwrap();
        // The key was materialized into a fresh temp file, not the original.
        assert_ne!(resolved.path(), signing.private_key.to_str().unwrap());
        let materialized = PathBuf::from(resolved.path());
        assert!(materialized.exists());

        sign_tag(
            &repo,
            "1.0.0",
            "HEAD",
            Some("AOS registry release"),
            resolved.path(),
            false,
        )
        .unwrap();
        assert!(
            verify_tag_signature(&repo, "1.0.0", std::slice::from_ref(&signing.trusted_key))
                .unwrap()
        );

        // Dropping the resolved key removes the materialized temp file.
        drop(resolved);
        assert!(!materialized.exists());
    }

    #[test]
    fn producer_signing_key_command_failure_is_reported() {
        let source = SigningKeySource::Spec(SigningKeySpec {
            path: None,
            command: Some("exit 3".to_string()),
        });
        let err = resolve_signing_key_source("initial", &source).unwrap_err();
        assert!(format!("{err:#}").contains("signing key command"));
    }

    #[test]
    fn signing_key_command_runs_with_search_path_override() {
        // Passing the current PATH through the override exercises the same
        // code path the wrappers trigger via AOS_HOST_PATH.
        let resolved = materialize_signing_key_command_with_path(
            "printf 'key material'",
            std::env::var_os("PATH"),
        )
        .unwrap();
        assert_eq!(fs::read_to_string(resolved.path()).unwrap(), "key material");
    }

    #[test]
    fn signing_key_command_finds_host_path_helpers() {
        let tmp = TempDir::new().unwrap();
        let helper = tmp.path().join("emit-signing-key");
        let runtime_path = std::env::var_os("PATH").unwrap();
        let bash = executable_on_path("bash", &runtime_path).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(bash, &helper).unwrap();
        }
        #[cfg(not(unix))]
        {
            fs::copy(bash, &helper).unwrap();
        }

        let resolved = materialize_signing_key_command_with_path(
            "emit-signing-key -c \"printf 'host key material'\"",
            Some(tmp.path().as_os_str().to_os_string()),
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(resolved.path()).unwrap(),
            "host key material"
        );
    }

    #[test]
    fn signing_key_command_shell_resolution_survives_path_override() {
        // The shell itself is resolved from the runtime PATH before the
        // user command sees the override, so shell builtins still work.
        let tmp = TempDir::new().unwrap();
        let resolved = materialize_signing_key_command_with_path(
            "printf 'key material'",
            Some(tmp.path().as_os_str().to_os_string()),
        )
        .unwrap();
        assert_eq!(fs::read_to_string(resolved.path()).unwrap(), "key material");
    }

    #[test]
    fn signing_key_command_search_path_override_replaces_command_path() {
        let tmp = TempDir::new().unwrap();
        let err = materialize_signing_key_command_with_path(
            "cat /definitely/missing",
            Some(tmp.path().as_os_str().to_os_string()),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("signing key command"));
    }

    #[test]
    fn signing_key_source_rejects_both_path_and_command() {
        let source = SigningKeySource::Spec(SigningKeySpec {
            path: Some("/tmp/key".to_string()),
            command: Some("cat /tmp/key".to_string()),
        });
        let err = resolve_signing_key_source("initial", &source).unwrap_err();
        assert!(format!("{err:#}").contains("both 'path' and 'command'"));
    }

    #[test]
    fn remote_diff_base_uses_pushed_current_branch_without_origin_head() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        let origin = tmp.path().join("origin.git");
        git(
            tmp.path(),
            &[
                "init",
                "--object-format=sha256",
                "--initial-branch=main",
                repo.to_str().unwrap(),
            ],
        )
        .unwrap();
        git(&repo, &["config", "user.name", "AOS Registry"]).unwrap();
        git(&repo, &["config", "user.email", "registry@example.com"]).unwrap();
        git(&repo, &["config", "commit.gpgsign", "false"]).unwrap();
        fs::write(
            repo.join("registry.toml"),
            "[registry]\nname = \"aos-core\"\n",
        )
        .unwrap();
        git(&repo, &["add", "."]).unwrap();
        git(&repo, &["commit", "-m", "init"]).unwrap();
        git(
            tmp.path(),
            &[
                "init",
                "--bare",
                "--object-format=sha256",
                origin.to_str().unwrap(),
            ],
        )
        .unwrap();
        git(
            &repo,
            &["remote", "add", "origin", origin.to_str().unwrap()],
        )
        .unwrap();
        git(&repo, &["push", "origin", "main"]).unwrap();

        assert!(!git_ref_exists(&repo, "origin/HEAD").unwrap());
        assert_eq!(remote_diff_base(&repo).unwrap(), "origin/main");
    }

    #[test]
    fn registry_upload_auth_config_selects_requested_registry() {
        let config_auth = RegistryUploadAuthConfig {
            token: Some("core-token".into()),
            view: Some("prod".into()),
            ..RegistryUploadAuthConfig::default()
        };
        let config = ApmConfig {
            settings: ApmSettings::default(),
            registries: vec![
                (test_registry_config("other", None), None),
                (
                    test_registry_config("core", Some(config_auth.clone())),
                    None,
                ),
            ],
            scope: ProfileScope::User,
        };

        let selected = registry_upload_auth_config(&config, "core").expect("core auth config");
        assert_eq!(selected, &config_auth);
        assert!(registry_upload_auth_config(&config, "missing").is_none());
    }

    fn test_registry_config(
        name: &str,
        upload_auth: Option<RegistryUploadAuthConfig>,
    ) -> RegistryConfig {
        RegistryConfig {
            name: name.into(),
            url: format!("https://registry.example.com/{name}"),
            priority: 500,
            enabled: true,
            commit: None,
            branch: None,
            channel: None,
            tag: None,
            version: None,
            pin: None,
            max_staleness_seconds: None,
            caches: Vec::new(),
            cache: Default::default(),
            upload_auth,
            signing_keys: Default::default(),
            signing: None,
        }
    }

    fn test_config_with_signing_key(registry: &str, key_id: &str, private_key: &Path) -> ApmConfig {
        let mut registry_config = test_registry_config(registry, None);
        registry_config.signing_keys.insert(
            key_id.to_string(),
            SigningKeySource::Path(private_key.to_str().unwrap().to_string()),
        );
        ApmConfig {
            settings: ApmSettings::default(),
            registries: vec![(registry_config, None)],
            scope: ProfileScope::User,
        }
    }

    struct TestProvenanceSigner {
        _tmp: TempDir,
        signer: PackageProvenanceSigner,
        trusted_key: String,
    }

    const TEST_PROVENANCE_REGISTRY: &str = "test";
    const TEST_PROVENANCE_KEY_ID: &str = "builder";

    fn test_provenance_signer() -> TestProvenanceSigner {
        let tmp = TempDir::new().unwrap();
        let key = write_seeded_signing_key(
            tmp.path(),
            TEST_PROVENANCE_REGISTRY,
            [42_u8; 32],
            TEST_PROVENANCE_KEY_ID,
        );
        TestProvenanceSigner {
            signer: PackageProvenanceSigner {
                key_id: TEST_PROVENANCE_KEY_ID.to_string(),
                key_path: key.private_key.clone(),
            },
            trusted_key: key.trusted_key,
            _tmp: tmp,
        }
    }

    fn signed_provenance_statement(artifact: &PublishProvenanceArtifact) -> serde_json::Value {
        let trusted = vec![TrustedProvenanceKey {
            key_id: TEST_PROVENANCE_KEY_ID.to_string(),
            key: test_provenance_signer().trusted_key,
            retired_before_sequence: None,
        }];
        let (statement, key_id) =
            crate::provenance::verify_statement_dsse_jsonl(&artifact.jsonl, &trusted).unwrap();
        assert_eq!(key_id, TEST_PROVENANCE_KEY_ID);
        statement
    }

    fn sign_test_provenance_statement(statement: &Value) -> String {
        let signer = test_provenance_signer();
        sign_statement_dsse_jsonl(
            statement,
            TEST_PROVENANCE_KEY_ID,
            signer.signer.key_path.as_path(),
        )
        .unwrap()
    }

    fn write_test_roster(
        dir: &Path,
        key_id: &str,
        trusted_key: &str,
        revoked: &[&str],
    ) -> Result<()> {
        let roster = KeysToml {
            active: vec![RosterKey {
                id: key_id.to_string(),
                key: trusted_key.to_string(),
            }],
            revoked: revoked
                .iter()
                .map(|id| RevokedKey {
                    id: (*id).to_string(),
                    key: None,
                    provenance_before_sequence: None,
                    reason: Some("test".into()),
                })
                .collect(),
            ..KeysToml::default()
        };
        keys::write_keys_toml(dir, &roster)
    }

    fn write_test_signing_key(root: &Path, registry: &str) -> TestSigningFixture {
        write_seeded_signing_key(root, registry, [9u8; 32], "registry_ed25519")
    }

    fn write_seeded_signing_key(
        root: &Path,
        registry: &str,
        seed: [u8; 32],
        name: &str,
    ) -> TestSigningFixture {
        let signing_dir = root.join("signing");
        fs::create_dir_all(&signing_dir).unwrap();

        let keypair = crate::sshkey::Ed25519Keypair::from_seed(seed);
        let private_key = signing_dir.join(name);

        fs::write(&private_key, keypair.to_openssh_private_key(registry)).unwrap();
        restrict_private_key_permissions(&private_key).unwrap();

        TestSigningFixture {
            trusted_key: keypair.trust_key_line(registry),
            private_key,
        }
    }

    #[test]
    fn cache_pointer_commit_selects_the_only_configured_active_key() {
        let tmp = TempDir::new().unwrap();
        let key = write_seeded_signing_key(tmp.path(), "maintenance", [31_u8; 32], "maintainer");
        write_test_roster(tmp.path(), "maintainer", &key.trusted_key, &[]).unwrap();
        let config = test_config_with_signing_key("maintenance", "maintainer", &key.private_key);

        let resolved =
            resolve_cache_pointer_signing_key(&config, tmp.path(), "maintenance", None, None)
                .unwrap()
                .unwrap();

        assert_eq!(resolved.path(), key.private_key.to_str().unwrap());
    }

    #[test]
    fn cache_pointer_commit_fails_closed_without_active_private_material() {
        let tmp = TempDir::new().unwrap();
        let key = write_seeded_signing_key(tmp.path(), "maintenance", [32_u8; 32], "maintainer");
        write_test_roster(tmp.path(), "maintainer", &key.trusted_key, &[]).unwrap();
        let config = ApmConfig {
            settings: ApmSettings::default(),
            registries: vec![(test_registry_config("maintenance", None), None)],
            scope: ProfileScope::User,
        };

        let error =
            resolve_cache_pointer_signing_key(&config, tmp.path(), "maintenance", None, None)
                .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("none has local private key material")
        );
    }

    #[test]
    fn retire_roster_key_preserves_provenance_key_cutoff() {
        let mut roster = KeysToml {
            active: vec![
                RosterKey {
                    id: "old".to_string(),
                    key: "aos-core:Ed25519:YWJjZA==".to_string(),
                },
                RosterKey {
                    id: "new".to_string(),
                    key: "aos-core:Ed25519:ZWZnaA==".to_string(),
                },
            ],
            ..KeysToml::default()
        };

        let vouching_id =
            retire_roster_key(&mut roster, "old", Some("planned"), &None, 4).expect("retire key");

        assert_eq!(vouching_id, "new");
        assert!(roster.active.iter().all(|entry| entry.id != "old"));
        assert_eq!(roster.revoked.len(), 1);
        assert_eq!(roster.revoked[0].id, "old");
        assert_eq!(
            roster.revoked[0].key.as_deref(),
            Some("aos-core:Ed25519:YWJjZA==")
        );
        assert_eq!(roster.revoked[0].provenance_before_sequence, Some(4));
    }

    #[test]
    fn retirement_resign_rotates_release_and_partition_signatures() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        git(
            tmp.path(),
            &[
                "init",
                "--object-format=sha256",
                "--initial-branch=stable",
                repo.to_str().unwrap(),
            ],
        )
        .unwrap();
        git(&repo, &["config", "user.name", "AOS Registry"]).unwrap();
        git(&repo, &["config", "user.email", "registry@example.com"]).unwrap();
        git(&repo, &["config", "commit.gpgsign", "false"]).unwrap();
        fs::write(
            repo.join("registry.toml"),
            "[registry]\nname = \"aos-core\"\n",
        )
        .unwrap();

        // Maintainer A signs everything and then retires; B survives.
        let key_a = write_seeded_signing_key(tmp.path(), "aos-core", [9u8; 32], "key_a");
        let key_b = write_seeded_signing_key(tmp.path(), "aos-core", [10u8; 32], "key_b");
        git(&repo, &["add", "."]).unwrap();
        git(&repo, &["commit", "-m", "init"]).unwrap();

        let version = semver::Version::new(1, 0, 0);
        let key_a_path = key_a.private_key.to_str().unwrap();
        sign_tag(
            &repo,
            "1.0.0",
            "HEAD",
            Some("release 1.0.0"),
            key_a_path,
            false,
        )
        .unwrap();
        let printer = Printer::new(0, true, false);
        channel_init_dir(&repo, "prod", &version, key_a_path, &printer).unwrap();

        // Nothing is affected while A is still a survivor.
        let survivors_both = vec![key_a.trusted_key.clone(), key_b.trusted_key.clone()];
        let plan = plan_retirement_resign(&repo, &survivors_both).unwrap();
        assert!(plan.is_empty());

        // Retiring A: the release tag and every partition need re-signing.
        let survivors = vec![key_b.trusted_key.clone()];
        let plan = plan_retirement_resign(&repo, &survivors).unwrap();
        assert_eq!(plan.affected_releases, vec![version.clone()]);
        assert_eq!(plan.affected_partitions.len(), 256);

        execute_retirement_resign(&repo, &plan, key_b.private_key.to_str().unwrap(), &printer)
            .unwrap();

        // The release tag now verifies only against the survivor.
        assert!(
            verify_tag_signature(&repo, "1.0.0", std::slice::from_ref(&key_b.trusted_key)).unwrap()
        );
        assert!(
            !verify_tag_signature(&repo, "1.0.0", std::slice::from_ref(&key_a.trusted_key))
                .unwrap()
        );

        // Partition payloads were regenerated against the new tag object
        // and verify against the survivor.
        let payload = fs::read(repo.join(".git/channels/prod/00")).unwrap();
        let oid = hash_tag_object(&repo, &payload).unwrap();
        assert!(
            verify_tag_signature(&repo, &oid, std::slice::from_ref(&key_b.trusted_key)).unwrap()
        );
        let map = read_channel_partition_map(&repo, "prod").unwrap();
        assert_eq!(channel::compute_frontier(&map), Some(version));

        // Re-planning against the survivor finds nothing left to re-sign.
        let plan = plan_retirement_resign(&repo, &survivors).unwrap();
        assert!(plan.is_empty());
    }

    #[test]
    fn retirement_resign_includes_release_tags_without_channels() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        git(
            tmp.path(),
            &[
                "init",
                "--object-format=sha256",
                "--initial-branch=stable",
                repo.to_str().unwrap(),
            ],
        )
        .unwrap();
        git(&repo, &["config", "user.name", "AOS Registry"]).unwrap();
        git(&repo, &["config", "user.email", "registry@example.com"]).unwrap();
        git(&repo, &["config", "commit.gpgsign", "false"]).unwrap();
        fs::write(
            repo.join("registry.toml"),
            "[registry]\nname = \"aos-core\"\n",
        )
        .unwrap();

        let key_a = write_seeded_signing_key(tmp.path(), "aos-core", [11u8; 32], "key_a");
        let key_b = write_seeded_signing_key(tmp.path(), "aos-core", [12u8; 32], "key_b");
        git(&repo, &["add", "."]).unwrap();
        git(&repo, &["commit", "-m", "init"]).unwrap();

        let version = semver::Version::new(1, 0, 0);
        sign_tag(
            &repo,
            "1.0.0",
            "HEAD",
            Some("release 1.0.0"),
            key_a.private_key.to_str().unwrap(),
            false,
        )
        .unwrap();

        let survivors = vec![key_b.trusted_key.clone()];
        let plan = plan_retirement_resign(&repo, &survivors).unwrap();

        assert_eq!(plan.affected_releases, vec![version]);
        assert!(plan.affected_partitions.is_empty());
    }

    #[cfg(unix)]
    fn restrict_private_key_permissions(path: &Path) -> Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("setting permissions on {}", path.display()))
    }

    #[cfg(not(unix))]
    fn restrict_private_key_permissions(_path: &Path) -> Result<()> {
        Ok(())
    }

    #[test]
    fn partition_list_accepts_decimal_and_hex() {
        assert_eq!(
            parse_partition_list("0,1,0a,0xff,1").unwrap(),
            vec![0, 1, 10, 255],
        );
        assert!(parse_partition_list("").is_err());
        assert!(parse_partition_list("256").is_err());
    }

    #[test]
    fn channel_advance_selector_requires_one_mode() {
        let map = PartitionMap::all(semver::Version::parse("1.0.0").unwrap());
        let target = semver::Version::parse("1.1.0").unwrap();

        assert!(select_partitions_for_advance(None, None, &map, &target).is_err());
        assert!(select_partitions_for_advance(Some(1), Some("0"), &map, &target).is_err());
        assert_eq!(
            select_partitions_for_advance(Some(3), None, &map, &target).unwrap(),
            vec![0, 1, 2],
        );
    }

    #[test]
    fn channel_advance_rejects_selected_partition_decrement() {
        let mut map = PartitionMap::all(semver::Version::parse("1.1.0").unwrap());
        map.set(2, semver::Version::parse("1.0.0").unwrap())
            .unwrap();
        let older = semver::Version::parse("1.0.0").unwrap();
        let same = semver::Version::parse("1.1.0").unwrap();
        let newer = semver::Version::parse("1.2.0").unwrap();

        let err = ensure_channel_advance_fix_forward(&map, &[0], &older).unwrap_err();
        assert!(format!("{err:#}").contains("decrement partition 00 from 1.1.0 to 1.0.0"));
        ensure_channel_advance_fix_forward(&map, &[0], &same).unwrap();
        ensure_channel_advance_fix_forward(&map, &[0, 2], &newer).unwrap();
    }

    #[test]
    fn store_dir_from_store_path_accepts_alternate_stores() {
        assert_eq!(
            store_dir_from_store_path("/nix/store/0123456789abcdfghijklmnpqrsvwxyz-curl-8.5.0"),
            Some("/nix/store"),
        );
        assert_eq!(
            store_dir_from_store_path(
                "/build/aos-root/store/0123456789abcdfghijklmnpqrsvwxyz-curl-8.5.0.drv",
            ),
            Some("/build/aos-root/store"),
        );
        assert_eq!(store_dir_from_store_path("unknown-deriver"), None);
        assert_eq!(
            store_dir_from_store_path("/nix/store/not-a-store-path"),
            None
        );
    }

    #[test]
    fn build_package_toml_new() {
        let info = StorePathInfo {
            path: "/nix/store/abc123-curl-8.5.0".into(),
            nar_hash: "sha256:deadbeef".into(),
            nar_size: 1048576,
            references: vec!["ref1".into(), "ref2".into()],
            closure_size: 5242880,
        };
        let content = build_package_toml(
            "",
            "curl",
            "8.5.0",
            "x86_64-linux",
            &info,
            Some("URL transfer tool"),
            Some("https://curl.se"),
            Some("MIT"),
            Some("aos-team"),
            false,
            None,
            &[],
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert!(content.contains("name = \"curl\""));
        assert!(content.contains("version = \"8.5.0\""));
        assert!(content.contains("x86_64-linux"));
        // Output content bindings live in the store/ graph, not the TOML
        // (RFC-0005).
        assert!(!content.contains("nar_hash = \"sha256:deadbeef\""));
        assert!(!content.contains("nar_size"));
        assert!(content.contains("source_drv = \"\""));
        assert!(content.contains("source_nar_hash = \"\""));
    }

    #[test]
    fn publish_distribution_metadata_rejects_missing_empty_and_legacy_values() {
        assert!(required_publish_metadata(None, "--description", "No description").is_err());
        assert!(required_publish_metadata(Some("  "), "--license", "unknown").is_err());
        assert!(required_publish_metadata(Some("UNKNOWN"), "--maintainer", "unknown").is_err());
        assert_eq!(
            required_publish_metadata(Some("  Andyl, Inc.  "), "--maintainer", "unknown").unwrap(),
            "Andyl, Inc."
        );
    }

    #[test]
    fn release_store_path_metadata_is_validated_for_dry_run_plans() {
        assert!(validate_release_publish_metadata(None, None, None, None).is_ok());
        assert!(
            validate_release_publish_metadata(Some("/nix/store/example"), None, None, None)
                .is_err()
        );
        assert!(
            validate_release_publish_metadata(
                Some("/nix/store/example"),
                Some("Example package"),
                Some("MIT"),
                Some("Andyl, Inc."),
            )
            .is_ok()
        );
    }

    #[test]
    fn release_store_path_requires_and_preserves_roster_identity() {
        assert!(validate_release_publish_signing_identity(None, None).is_ok());
        let error =
            validate_release_publish_signing_identity(Some("/nix/store/example-package"), None)
                .unwrap_err();
        assert!(format!("{error:#}").contains("requires --key-id"));
        assert!(
            validate_release_publish_signing_identity(
                Some("/nix/store/example-package"),
                Some("initial"),
            )
            .is_ok()
        );

        let publish = ReleaseStorePublish {
            config: ApmConfig {
                settings: ApmSettings::default(),
                registries: Vec::new(),
                scope: ProfileScope::User,
            },
            store_path: "/nix/store/example-package".into(),
            name: None,
            version: None,
            platform: None,
            description: Some("Example package".into()),
            homepage: None,
            license: Some("MIT".into()),
            maintainer: Some("Andyl, Inc.".into()),
            sysroot: false,
            previous: None,
            source_drv: None,
            image_payload_paths: Vec::new(),
            image_disk_paths: Vec::new(),
            image_info_paths: Vec::new(),
            image_formats: Vec::new(),
            image_uki_paths: Vec::new(),
            bless: false,
            message: None,
            registry: "production".into(),
            signing_key_id: Some("initial".into()),
        };
        assert_eq!(publish.signing_key_id.as_deref(), Some("initial"));
        assert_eq!(publish.publish_signing_args(), (None, Some("initial")));
    }

    #[test]
    fn build_package_toml_refreshes_package_metadata() {
        let info = StorePathInfo {
            path: "/nix/store/abc123-curl-8.5.0".into(),
            nar_hash: "sha256:deadbeef".into(),
            nar_size: 1048576,
            references: vec![],
            closure_size: 5242880,
        };
        let existing = r#"
[package]
name = "curl"
description = "No description"
license = "unknown"
maintainer = "unknown"

[[versions]]
version = "8.5.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/old-curl-8.5.0"
source_drv = ""
source_nar_hash = ""
"#;

        let content = build_package_toml(
            existing,
            "curl",
            "8.5.0",
            "x86_64-linux",
            &info,
            Some("Command line tool and library for transferring data with URLs"),
            Some("https://curl.se"),
            Some("curl"),
            Some("Andyl, Inc."),
            false,
            None,
            &[],
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        assert!(content.contains(
            "description = \"Command line tool and library for transferring data with URLs\""
        ));
        assert!(content.contains("homepage = \"https://curl.se\""));
        assert!(content.contains("license = \"curl\""));
        assert!(content.contains("maintainer = \"Andyl, Inc.\""));
        assert!(!content.contains("No description"));
        assert!(!content.contains("unknown"));
    }

    #[test]
    fn build_package_toml_records_source_deriver() {
        let info = StorePathInfo {
            path: "/nix/store/abc123-curl-8.5.0".into(),
            nar_hash: "sha256:deadbeef".into(),
            nar_size: 1048576,
            references: vec![],
            closure_size: 5242880,
        };
        let source_info = StorePathInfo {
            path: "/nix/store/drv123-curl-8.5.0.drv".into(),
            nar_hash: "sha256:source".into(),
            nar_size: 4096,
            references: vec![],
            closure_size: 4096,
        };
        let content = build_package_toml(
            "",
            "curl",
            "8.5.0",
            "x86_64-linux",
            &info,
            Some("URL transfer tool"),
            None,
            Some("MIT"),
            Some("aos-team"),
            false,
            None,
            &[],
            Some(&source_info),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert!(content.contains("source_drv = \"/nix/store/drv123-curl-8.5.0.drv\""));
        assert!(content.contains("source_nar_hash = \"sha256:source\""));
    }

    #[test]
    fn read_publish_expose_manifest_accepts_renderer_mac_manifest() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("manifest.json");
        let mac = serde_json::json!({
            "version": 1,
            "package": "webapp",
            "backend": "selinux",
            "securityLabel": "aos-pkg-webapp",
            "defaultDeny": true,
            "profilePath": "mac/selinux/aos_x2dpkg_x2dwebapp.pp",
        });
        let manifest = serde_json::json!({
            "expose": {
                "target": "aos-pkg-webapp.target",
                "units": ["webapp.service"],
            },
            "kernel": {
                "modules": [],
            },
            "firewall": {
                "enabled": false,
            },
            "mac": mac,
            "confinement": {
                "class": "sandboxed",
                "label": "sandboxed",
                "holes": [],
            },
            "permissions": {
                "security-label": "aos-pkg-webapp",
                "confinement": {
                    "class": "sandboxed",
                    "label": "sandboxed",
                    "holes": [],
                },
            },
        });
        fs::write(&path, serde_json::to_string(&manifest).unwrap()).unwrap();
        fs::write(
            tmp.path().join("mac-profile.json"),
            serde_json::to_string(&manifest["mac"]).unwrap(),
        )
        .unwrap();
        write_publish_selinux_artifacts(tmp.path(), "aos-pkg-webapp");

        let parsed = read_publish_expose_manifest(path.to_str().unwrap(), "webapp").unwrap();
        let mac = parsed.mac.as_ref().unwrap();

        assert_eq!(mac.backend, "selinux");
        assert_eq!(mac.security_label, "aos-pkg-webapp");
        assert_eq!(
            mac.profile_path.as_deref(),
            Some("mac/selinux/aos_x2dpkg_x2dwebapp.pp")
        );
    }

    #[test]
    fn read_publish_expose_manifest_rejects_target_bound_to_other_package() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("manifest.json");
        let manifest = serde_json::json!({
            "expose": {
                "target": "aos-pkg-other.target",
                "units": ["webapp.service"],
            },
            "permissions": {},
        });
        fs::write(&path, serde_json::to_string(&manifest).unwrap()).unwrap();

        let err = read_publish_expose_manifest(path.to_str().unwrap(), "webapp").unwrap_err();

        assert!(
            format!("{err:#}").contains("must equal aos-pkg-webapp.target"),
            "{err:#}"
        );
    }

    #[test]
    fn read_publish_manifest_digest_tracks_manifest_bytes() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("manifest.json");
        fs::write(&path, br#"{"permissions":{"network":"private"}}"#).unwrap();
        let first = read_publish_manifest_digest(&path).unwrap();

        fs::write(&path, br#"{"permissions":{"network":"host"}}"#).unwrap();
        let second = read_publish_manifest_digest(&path).unwrap();

        assert_eq!(
            first,
            crate::package_attestation::package_manifest_digest_bytes(
                br#"{"permissions":{"network":"private"}}"#
            )
        );
        assert_ne!(first, second);
    }

    #[test]
    fn publish_selinux_identifiers_escape_label_punctuation_without_collisions() {
        let labels = ["a.b", "a-b", "a_b", "a+b", "a=b"];
        let identifiers = labels
            .iter()
            .map(|label| publish_selinux_identifier_for_label(label))
            .collect::<std::collections::BTreeSet<_>>();

        assert_eq!(identifiers.len(), labels.len());
        assert_eq!(
            publish_selinux_identifier_for_label("aos-pkg-webapp"),
            "aos_x2dpkg_x2dwebapp"
        );
        assert_eq!(
            publish_selinux_identifier_for_label("1webapp"),
            "aos_pkg_1webapp"
        );
    }

    #[test]
    fn read_publish_expose_manifest_rejects_mac_profile_payload_mismatch() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("manifest.json");
        let mac = serde_json::json!({
            "version": 1,
            "package": "webapp",
            "backend": "selinux",
            "securityLabel": "aos-pkg-webapp",
            "defaultDeny": true,
            "profilePath": "mac/selinux/aos_x2dpkg_x2dwebapp.pp",
        });
        let manifest = serde_json::json!({
            "expose": {
                "target": "aos-pkg-webapp.target",
                "units": ["webapp.service"],
            },
            "mac": mac,
            "permissions": {
                "security-label": "aos-pkg-webapp",
                "confinement": {
                    "class": "sandboxed",
                    "label": "sandboxed",
                    "holes": [],
                },
            },
        });
        fs::write(&path, serde_json::to_string(&manifest).unwrap()).unwrap();
        fs::write(
            tmp.path().join("mac-profile.json"),
            serde_json::to_string(&manifest["mac"]).unwrap(),
        )
        .unwrap();
        write_publish_selinux_artifacts(tmp.path(), "aos-pkg-webapp");
        fs::write(
            tmp.path().join("mac/selinux/aos_x2dpkg_x2dwebapp.pp"),
            b"permissive compiled policy",
        )
        .unwrap();

        let err = read_publish_expose_manifest(path.to_str().unwrap(), "webapp").unwrap_err();

        assert!(
            format!("{err:#}").contains("does not match the validated SELinux source"),
            "{err:?}"
        );
    }

    #[test]
    fn read_publish_expose_manifest_rejects_missing_mac_artifact() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("manifest.json");
        let manifest = serde_json::json!({
            "expose": {
                "target": "aos-pkg-webapp.target",
                "units": ["webapp.service"],
            },
            "mac": {
                "version": 1,
                "package": "webapp",
                "backend": "selinux",
                "securityLabel": "aos-pkg-webapp",
                "defaultDeny": true,
                "profilePath": "mac/selinux/aos_x2dpkg_x2dwebapp.pp",
            },
            "permissions": {
                "security-label": "aos-pkg-webapp",
                "confinement": {
                    "class": "sandboxed",
                    "label": "sandboxed",
                    "holes": [],
                },
            },
        });
        fs::write(&path, serde_json::to_string(&manifest).unwrap()).unwrap();

        let err = read_publish_expose_manifest(path.to_str().unwrap(), "webapp").unwrap_err();

        assert!(
            format!("{err:#}").contains("validating MAC profile artifact for package 'webapp'")
        );
    }

    #[cfg(unix)]
    #[test]
    fn read_publish_expose_manifest_rejects_mac_profile_parent_symlink() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("manifest.json");
        let mac = serde_json::json!({
            "version": 1,
            "package": "webapp",
            "backend": "selinux",
            "securityLabel": "aos-pkg-webapp",
            "defaultDeny": true,
            "profilePath": "mac/selinux/aos_x2dpkg_x2dwebapp.pp",
        });
        let manifest = serde_json::json!({
            "expose": {
                "target": "aos-pkg-webapp.target",
                "units": ["webapp.service"],
            },
            "mac": mac,
            "permissions": {
                "security-label": "aos-pkg-webapp",
                "confinement": {
                    "class": "sandboxed",
                    "label": "sandboxed",
                    "holes": [],
                },
            },
        });
        fs::write(&path, serde_json::to_string(&manifest).unwrap()).unwrap();
        fs::write(
            tmp.path().join("mac-profile.json"),
            serde_json::to_string(&manifest["mac"]).unwrap(),
        )
        .unwrap();
        let external_mac = tmp.path().join("external-mac");
        let external_profile = external_mac.join("selinux/aos_x2dpkg_x2dwebapp.pp");
        fs::create_dir_all(external_profile.parent().unwrap()).unwrap();
        fs::write(&external_profile, b"compiled-policy").unwrap();
        std::os::unix::fs::symlink(&external_mac, tmp.path().join("mac")).unwrap();

        let err = read_publish_expose_manifest(path.to_str().unwrap(), "webapp").unwrap_err();

        assert!(
            format!("{err:#}").contains("not a non-symlink directory"),
            "{err:?}"
        );
    }

    #[test]
    fn build_package_toml_records_expose_manifest_metadata() {
        let info = StorePathInfo {
            path: "/nix/store/abc123-webapp-1.0.0".into(),
            nar_hash: "sha256:deadbeef".into(),
            nar_size: 1048576,
            references: vec![],
            closure_size: 5242880,
        };
        let artifact = StorePathInfo {
            path: "/nix/store/artifacthash111-expose-webapp".into(),
            nar_hash: "sha256:artifact".into(),
            nar_size: 2048,
            references: vec![],
            closure_size: 2048,
        };
        let mut permissions = PermissionsMeta {
            network: Some(crate::types::NetworkPermission::PrivateOutbound),
            tcp_bind: vec![8080],
            tcp_connect: vec![443],
            capabilities: vec!["CAP_NET_BIND_SERVICE".into()],
            ..PermissionsMeta::default()
        };
        permissions.confinement = Some(permissions.computed_confinement());
        let manifest = PublishExposeManifest {
            expose: ExposeMeta {
                target: "aos-pkg-webapp.target".into(),
                units: vec![
                    "webapp.service".into(),
                    "aos-pkg-webapp.slice".into(),
                    "aos-pkg-webapp-mac.service".into(),
                    "aos-pkg-webapp-ebpf.service".into(),
                ],
                images: Vec::new(),
                requires: vec!["zlib".into()],
                config: crate::types::ExposeConfigMeta {
                    artifacts: vec![crate::types::ConfigArtifactMeta {
                        name: "env".into(),
                        path: "/etc/aos/packages/webapp/config.env".into(),
                        format: crate::types::ConfigArtifactFormat::Env,
                        required: vec!["TOKEN".into()],
                        optional: Vec::new(),
                        units: vec!["webapp.service".into()],
                        reload: crate::types::ConfigReloadPolicy::Reload,
                    }],
                    credentials: Vec::new(),
                },
                provides: vec![crate::types::ProvidedCapabilityMeta {
                    name: "data".into(),
                    kind: crate::types::CapabilityKind::Directory,
                    path: Some("/var/lib/webapp/data".into()),
                    unit: None,
                }],
                uses: vec![crate::types::RequiredCapabilityMeta {
                    provider: "zlib".into(),
                    name: "headers".into(),
                    kind: crate::types::CapabilityKind::Directory,
                    unit: "webapp.service".into(),
                }],
            },
            permissions,
            mac: Some(PublishMacProfileManifest {
                version: 1,
                package: "webapp".into(),
                backend: "selinux".into(),
                security_label: "aos-pkg-webapp".into(),
                default_deny: true,
                profile_path: Some("mac/selinux/aos_x2dpkg_x2dwebapp.pp".into()),
            }),
            _kernel: None,
            _firewall: None,
            _confinement: None,
        };
        let manifest_digest = crate::package_attestation::package_manifest_digest_bytes(
            br#"{"expose":{"target":"aos-pkg-webapp.target","units":["webapp.service"]},"permissions":{}}"#,
        );
        let expected_root_digest = package_nar_root_digest(&info.nar_hash);
        let expected_measurement = crate::package_attestation::package_measurement_digest(
            "webapp",
            "1.0.0",
            &expected_root_digest,
            &manifest_digest,
        );

        let content = build_package_toml(
            "",
            "webapp",
            "1.0.0",
            "x86_64-linux",
            &info,
            Some("Web application"),
            None,
            Some("MIT"),
            Some("aos-team"),
            false,
            None,
            &[],
            None,
            Some(&manifest),
            Some(&artifact),
            Some(&manifest_digest),
            None,
            None,
        )
        .unwrap();

        let rendered: toml::Value = toml::from_str(&content).unwrap();
        let platform = rendered
            .get("versions")
            .and_then(|versions| versions.as_array())
            .and_then(|versions| versions.first())
            .and_then(|version| version.get("platforms"))
            .and_then(|platforms| platforms.get("x86_64-linux"))
            .unwrap();
        assert_eq!(
            platform.get("min-format").and_then(toml::Value::as_integer),
            Some(i64::from(PACKAGE_META_FORMAT))
        );
        assert_eq!(
            platform
                .get("requires-features")
                .and_then(toml::Value::as_array)
                .map(|features| {
                    features
                        .iter()
                        .filter_map(toml::Value::as_str)
                        .collect::<Vec<_>>()
                })
                .unwrap(),
            vec![
                FEATURE_EXPOSE_V1,
                FEATURE_EXPOSE_ARTIFACT_V1,
                FEATURE_PERMISSIONS_V1,
                FEATURE_NETWORK_POLICY_V1,
                FEATURE_REQUIRES_V1,
                FEATURE_CONFIG_V1,
                FEATURE_RELOAD_V1,
                FEATURE_CAPABILITY_ROUTES_V1,
                FEATURE_EBPF_NET_POLICY_V1,
                FEATURE_MAC_PROFILE_V1,
                FEATURE_ATTESTATION_V1,
            ]
        );
        assert_eq!(
            platform.get("root_digest").and_then(toml::Value::as_str),
            Some(expected_root_digest.as_str())
        );
        assert_eq!(
            platform.get("measurement").and_then(toml::Value::as_str),
            Some(expected_measurement.as_str())
        );
        assert_eq!(
            platform
                .get("references")
                .and_then(|references| references.get("min-format"))
                .and_then(toml::Value::as_integer),
            Some(i64::from(PACKAGE_META_FORMAT))
        );
        assert_eq!(
            platform
                .get("expose")
                .and_then(|expose| expose.get("target"))
                .and_then(toml::Value::as_str),
            Some("aos-pkg-webapp.target")
        );
        assert_eq!(
            platform
                .get("expose_artifact")
                .and_then(|artifact| artifact.get("store_path"))
                .and_then(toml::Value::as_str),
            Some("/nix/store/artifacthash111-expose-webapp")
        );
        assert_eq!(
            platform
                .get("permissions")
                .and_then(|permissions| permissions.get("network"))
                .and_then(toml::Value::as_str),
            Some("private-outbound")
        );
        assert_eq!(
            platform
                .get("permissions")
                .and_then(|permissions| permissions.get("tcp-bind"))
                .and_then(toml::Value::as_array)
                .map(|ports| {
                    ports
                        .iter()
                        .filter_map(toml::Value::as_integer)
                        .collect::<Vec<_>>()
                }),
            Some(vec![8080])
        );
        assert_eq!(
            platform
                .get("permissions")
                .and_then(|permissions| permissions.get("tcp-connect"))
                .and_then(toml::Value::as_array)
                .map(|ports| {
                    ports
                        .iter()
                        .filter_map(toml::Value::as_integer)
                        .collect::<Vec<_>>()
                }),
            Some(vec![443])
        );
        assert_eq!(
            platform
                .get("permissions")
                .and_then(|permissions| permissions.get("confinement"))
                .and_then(|confinement| confinement.get("label"))
                .and_then(toml::Value::as_str),
            Some(
                "sandboxed-with-holes (network:private-outbound, tcp-bind:8080, tcp-connect:443, capability:CAP_NET_BIND_SERVICE)",
            )
        );

        let parsed = crate::registry::parse::parse_package_toml(&content, "x86_64-linux")
            .unwrap()
            .unwrap();
        assert_eq!(
            parsed.expose.as_ref().map(|expose| expose.target.as_str()),
            Some("aos-pkg-webapp.target")
        );
        assert_eq!(
            parsed
                .expose_artifact
                .as_ref()
                .map(|artifact| artifact.store_path.as_str()),
            Some("/nix/store/artifacthash111-expose-webapp")
        );
        assert_eq!(
            parsed.permissions.network,
            Some(crate::types::NetworkPermission::PrivateOutbound)
        );
        assert_eq!(parsed.permissions.tcp_bind, vec![8080]);
        assert_eq!(parsed.permissions.tcp_connect, vec![443]);
    }

    #[test]
    fn build_package_toml_detects_ebpf_feature_from_package_name() {
        let info = StorePathInfo {
            path: "/nix/store/abc123-webapp-1.0.0".into(),
            nar_hash: "sha256:deadbeef".into(),
            nar_size: 1048576,
            references: vec![],
            closure_size: 5242880,
        };
        let artifact = StorePathInfo {
            path: "/nix/store/artifacthash111-expose-webapp".into(),
            nar_hash: "sha256:artifact".into(),
            nar_size: 2048,
            references: vec![],
            closure_size: 2048,
        };
        let manifest = PublishExposeManifest {
            expose: ExposeMeta {
                target: "aos-pkg-webapp.target".into(),
                units: vec![
                    "webapp.service".into(),
                    "aos-pkg-webapp.slice".into(),
                    "aos-pkg-webapp-ebpf.service".into(),
                ],
                images: Vec::new(),
                requires: Vec::new(),
                config: Default::default(),
                provides: Vec::new(),
                uses: Vec::new(),
            },
            permissions: PermissionsMeta::default(),
            mac: None,
            _kernel: None,
            _firewall: None,
            _confinement: None,
        };
        let manifest_digest = crate::package_attestation::package_manifest_digest_bytes(
            br#"{"expose":{"target":"aos-pkg-webapp.target","units":["webapp.service"]},"permissions":{}}"#,
        );

        let content = build_package_toml(
            "",
            "webapp",
            "1.0.0",
            "x86_64-linux",
            &info,
            Some("Web application"),
            None,
            Some("MIT"),
            Some("aos-team"),
            false,
            None,
            &[],
            None,
            Some(&manifest),
            Some(&artifact),
            Some(&manifest_digest),
            None,
            None,
        )
        .unwrap();

        let rendered: toml::Value = toml::from_str(&content).unwrap();
        let features = rendered
            .get("versions")
            .and_then(|versions| versions.as_array())
            .and_then(|versions| versions.first())
            .and_then(|version| version.get("platforms"))
            .and_then(|platforms| platforms.get("x86_64-linux"))
            .and_then(|platform| platform.get("requires-features"))
            .and_then(toml::Value::as_array)
            .map(|features| {
                features
                    .iter()
                    .filter_map(toml::Value::as_str)
                    .collect::<Vec<_>>()
            })
            .unwrap();
        assert!(features.contains(&FEATURE_EBPF_NET_POLICY_V1));
    }

    #[test]
    fn build_package_toml_rejects_expose_manifest_without_artifact() {
        let info = StorePathInfo {
            path: "/nix/store/abc123-webapp-1.0.0".into(),
            nar_hash: "sha256:deadbeef".into(),
            nar_size: 1048576,
            references: vec![],
            closure_size: 5242880,
        };
        let manifest = PublishExposeManifest {
            expose: ExposeMeta {
                target: "aos-pkg-webapp.target".into(),
                units: vec!["webapp.service".into()],
                images: Vec::new(),
                requires: Vec::new(),
                config: Default::default(),
                provides: Vec::new(),
                uses: Vec::new(),
            },
            permissions: PermissionsMeta::default(),
            mac: None,
            _kernel: None,
            _firewall: None,
            _confinement: None,
        };

        let err = build_package_toml(
            "",
            "webapp",
            "1.0.0",
            "x86_64-linux",
            &info,
            Some("Web application"),
            None,
            Some("MIT"),
            Some("aos-team"),
            false,
            None,
            &[],
            None,
            Some(&manifest),
            None,
            None,
            None,
            None,
        )
        .unwrap_err();

        assert!(format!("{err:#}").contains("requires rendered expose artifact"));
    }

    #[test]
    fn build_package_toml_records_expose_artifact_metadata() {
        let info = StorePathInfo {
            path: "/nix/store/abc123-webapp-1.0.0".into(),
            nar_hash: "sha256:deadbeef".into(),
            nar_size: 1048576,
            references: vec![],
            closure_size: 5242880,
        };
        let artifact = StorePathInfo {
            path: "/nix/store/artifacthash111-expose-webapp".into(),
            nar_hash: "sha256:artifact".into(),
            nar_size: 2048,
            references: vec![],
            closure_size: 2048,
        };
        let manifest = PublishExposeManifest {
            expose: ExposeMeta {
                target: "aos-pkg-webapp.target".into(),
                units: vec!["webapp.service".into()],
                images: Vec::new(),
                requires: Vec::new(),
                config: Default::default(),
                provides: Vec::new(),
                uses: Vec::new(),
            },
            permissions: PermissionsMeta::default(),
            mac: None,
            _kernel: None,
            _firewall: None,
            _confinement: None,
        };
        let manifest_digest = crate::package_attestation::package_manifest_digest_bytes(
            br#"{"expose":{"target":"aos-pkg-webapp.target","units":["webapp.service"]},"permissions":{}}"#,
        );
        let expected_root_digest = package_nar_root_digest(&info.nar_hash);
        let expected_measurement = crate::package_attestation::package_measurement_digest(
            "webapp",
            "1.0.0",
            &expected_root_digest,
            &manifest_digest,
        );

        let content = build_package_toml(
            "",
            "webapp",
            "1.0.0",
            "x86_64-linux",
            &info,
            Some("Web application"),
            None,
            Some("MIT"),
            Some("aos-team"),
            false,
            None,
            &[],
            None,
            Some(&manifest),
            Some(&artifact),
            Some(&manifest_digest),
            None,
            None,
        )
        .unwrap();

        let rendered: toml::Value = toml::from_str(&content).unwrap();
        let platform = rendered
            .get("versions")
            .and_then(|versions| versions.as_array())
            .and_then(|versions| versions.first())
            .and_then(|version| version.get("platforms"))
            .and_then(|platforms| platforms.get("x86_64-linux"))
            .unwrap();
        let features = platform
            .get("requires-features")
            .and_then(toml::Value::as_array)
            .map(|features| {
                features
                    .iter()
                    .filter_map(toml::Value::as_str)
                    .collect::<Vec<_>>()
            })
            .unwrap();
        assert!(features.contains(&FEATURE_EXPOSE_ARTIFACT_V1));
        assert!(features.contains(&FEATURE_NETWORK_POLICY_V1));
        assert!(features.contains(&FEATURE_ATTESTATION_V1));
        assert_eq!(
            platform
                .get("expose_artifact")
                .and_then(|artifact| artifact.get("store_path"))
                .and_then(toml::Value::as_str),
            Some("/nix/store/artifacthash111-expose-webapp")
        );
        assert_eq!(
            platform.get("root_digest").and_then(toml::Value::as_str),
            Some(expected_root_digest.as_str())
        );
        assert_eq!(platform.get("root_hash"), None);
        assert_eq!(platform.get("root_hash_sig"), None);
        let expected_provenance =
            publish_provenance_ref("webapp", "x86_64-linux", &expected_measurement).unwrap();
        assert_eq!(
            platform.get("provenance").and_then(toml::Value::as_str),
            Some(expected_provenance.as_str())
        );
        assert_eq!(
            platform.get("measurement").and_then(toml::Value::as_str),
            Some(expected_measurement.as_str())
        );

        let parsed = crate::registry::parse::parse_package_toml(&content, "x86_64-linux")
            .unwrap()
            .unwrap();
        assert_eq!(
            parsed
                .expose_artifact
                .as_ref()
                .map(|artifact| artifact.store_path.as_str()),
            Some("/nix/store/artifacthash111-expose-webapp")
        );
        assert_eq!(
            parsed.attestation.root_digest.as_deref(),
            Some(expected_root_digest.as_str())
        );
        assert_eq!(
            parsed.attestation.provenance.as_deref(),
            Some(expected_provenance.as_str())
        );
        assert_eq!(
            parsed.attestation.measurement.as_deref(),
            Some(expected_measurement.as_str())
        );
    }

    #[test]
    fn build_package_toml_records_package_attestation_measurement() {
        let info = StorePathInfo {
            path: "/nix/store/abc123-webapp-1.0.0".into(),
            nar_hash: "sha256:deadbeef".into(),
            nar_size: 1048576,
            references: vec![],
            closure_size: 5242880,
        };
        let artifact = StorePathInfo {
            path: "/nix/store/artifacthash111-expose-webapp".into(),
            nar_hash: "sha256:artifact".into(),
            nar_size: 2048,
            references: vec![],
            closure_size: 2048,
        };
        let root_hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let manifest = verity_expose_manifest(root_hash);
        let manifest_digest = crate::package_attestation::package_manifest_digest_bytes(
            br#"{"expose":{"target":"aos-pkg-webapp.target"},"permissions":{}}"#,
        );
        let expected_measurement = crate::package_attestation::package_measurement_digest(
            "webapp",
            "1.0.0",
            root_hash,
            &manifest_digest,
        );

        let content = build_package_toml(
            "",
            "webapp",
            "1.0.0",
            "x86_64-linux",
            &info,
            Some("Web application"),
            None,
            Some("MIT"),
            Some("aos-team"),
            false,
            None,
            &[],
            None,
            Some(&manifest),
            Some(&artifact),
            Some(&manifest_digest),
            None,
            None,
        )
        .unwrap();

        let rendered: toml::Value = toml::from_str(&content).unwrap();
        let platform = rendered
            .get("versions")
            .and_then(|versions| versions.as_array())
            .and_then(|versions| versions.first())
            .and_then(|version| version.get("platforms"))
            .and_then(|platforms| platforms.get("x86_64-linux"))
            .unwrap();
        let features = platform
            .get("requires-features")
            .and_then(toml::Value::as_array)
            .map(|features| {
                features
                    .iter()
                    .filter_map(toml::Value::as_str)
                    .collect::<Vec<_>>()
            })
            .unwrap();
        assert!(features.contains(&FEATURE_ATTESTATION_V1));
        assert_eq!(
            platform.get("root_digest").and_then(toml::Value::as_str),
            Some(root_hash)
        );
        assert_eq!(
            platform.get("root_hash").and_then(toml::Value::as_str),
            Some(root_hash)
        );
        assert_eq!(
            platform.get("root_hash_sig").and_then(toml::Value::as_str),
            Some("root.roothash.p7s")
        );
        let expected_provenance =
            publish_provenance_ref("webapp", "x86_64-linux", &expected_measurement).unwrap();
        assert_eq!(
            platform.get("provenance").and_then(toml::Value::as_str),
            Some(expected_provenance.as_str())
        );
        assert_eq!(
            platform.get("measurement").and_then(toml::Value::as_str),
            Some(expected_measurement.as_str())
        );

        let parsed = crate::registry::parse::parse_package_toml(&content, "x86_64-linux")
            .unwrap()
            .unwrap();
        assert_eq!(parsed.attestation.root_digest.as_deref(), Some(root_hash));
        assert_eq!(parsed.attestation.root_hash.as_deref(), Some(root_hash));
        assert_eq!(
            parsed.attestation.root_hash_sig.as_deref(),
            Some("root.roothash.p7s")
        );
        assert_eq!(
            parsed.attestation.provenance.as_deref(),
            Some(expected_provenance.as_str())
        );
        assert_eq!(
            parsed.attestation.measurement.as_deref(),
            Some(expected_measurement.as_str())
        );
    }

    #[test]
    fn publish_provenance_artifact_binds_nar_manifest_measurement_and_source() {
        let info = StorePathInfo {
            path: "/nix/store/abc123-webapp-1.0.0".into(),
            nar_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            nar_size: 1048576,
            references: vec![],
            closure_size: 5242880,
        };
        let source = StorePathInfo {
            path: "/nix/store/srcdrv-webapp-1.0.0.drv".into(),
            nar_hash: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .into(),
            nar_size: 4096,
            references: vec![],
            closure_size: 4096,
        };
        let root_hash = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let manifest = verity_expose_manifest(root_hash);
        let manifest_digest =
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let measurement = crate::package_attestation::package_measurement_digest(
            "webapp",
            "1.0.0",
            root_hash,
            manifest_digest,
        );
        let expected_provenance =
            publish_provenance_ref("webapp", "x86_64-linux", &measurement).unwrap();

        let signer = test_provenance_signer();
        let artifact = publish_provenance_artifact(
            TEST_PROVENANCE_REGISTRY,
            "webapp",
            "1.0.0",
            "x86_64-linux",
            &info,
            Some(&source),
            &manifest,
            manifest_digest,
            &signer.signer,
        )
        .unwrap()
        .expect("provenance artifact");

        assert_eq!(artifact.path, expected_provenance);
        assert!(artifact.path.contains("/x86_64-linux/"));
        let statement = signed_provenance_statement(&artifact);
        assert_eq!(statement["_type"], "https://in-toto.io/Statement/v1");
        assert_eq!(statement["predicateType"], "https://slsa.dev/provenance/v1");
        assert_eq!(
            statement["subject"][0]["name"].as_str(),
            Some(info.path.as_str())
        );
        assert_eq!(
            statement["subject"][0]["digest"]["sha256"],
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(
            statement["subject"][1]["digest"]["sha256"],
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        );
        assert_eq!(
            statement["subject"][2]["digest"]["sha256"],
            measurement.trim_start_matches("sha256:")
        );
        assert_eq!(
            statement["predicate"]["buildDefinition"]["externalParameters"]["root_digest"].as_str(),
            Some(root_hash)
        );
        assert_eq!(
            statement["predicate"]["buildDefinition"]["externalParameters"]["root_hash"].as_str(),
            Some(root_hash)
        );
        assert_eq!(
            statement["predicate"]["buildDefinition"]["externalParameters"]["provenance"].as_str(),
            Some(expected_provenance.as_str())
        );
        let expected_source_uri = format!("nix:{}", source.path);
        assert_eq!(
            statement["predicate"]["buildDefinition"]["resolvedDependencies"][0]["uri"].as_str(),
            Some(expected_source_uri.as_str())
        );
        assert_eq!(
            statement["predicate"]["buildDefinition"]["resolvedDependencies"][0]["digest"]
                ["sha256"]
                .as_str(),
            Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        );
    }

    #[test]
    fn publish_provenance_artifact_binds_non_verity_root_digest() {
        let info = StorePathInfo {
            path: "/nix/store/abc123-webapp-1.0.0".into(),
            nar_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            nar_size: 1048576,
            references: vec![],
            closure_size: 5242880,
        };
        let manifest = PublishExposeManifest {
            expose: ExposeMeta {
                target: "aos-pkg-webapp.target".into(),
                units: vec!["webapp.service".into()],
                images: Vec::new(),
                requires: Vec::new(),
                config: Default::default(),
                provides: Vec::new(),
                uses: Vec::new(),
            },
            permissions: PermissionsMeta::default(),
            mac: None,
            _kernel: None,
            _firewall: None,
            _confinement: None,
        };
        let manifest_digest =
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let expected_root_digest = package_nar_root_digest(&info.nar_hash);
        let measurement = crate::package_attestation::package_measurement_digest(
            "webapp",
            "1.0.0",
            &expected_root_digest,
            manifest_digest,
        );

        let signer = test_provenance_signer();
        let artifact = publish_provenance_artifact(
            TEST_PROVENANCE_REGISTRY,
            "webapp",
            "1.0.0",
            "x86_64-linux",
            &info,
            None,
            &manifest,
            manifest_digest,
            &signer.signer,
        )
        .unwrap()
        .expect("provenance artifact");

        assert_eq!(artifact.attestation.root_hash, None);
        assert_eq!(artifact.attestation.root_hash_sig, None);
        assert_eq!(
            artifact.attestation.root_digest.as_deref(),
            Some(expected_root_digest.as_str())
        );
        assert_eq!(
            artifact.attestation.measurement.as_deref(),
            Some(measurement.as_str())
        );
        let statement = signed_provenance_statement(&artifact);
        let params = &statement["predicate"]["buildDefinition"]["externalParameters"];
        assert_eq!(
            params["root_digest"].as_str(),
            Some(expected_root_digest.as_str())
        );
        assert!(params.get("root_hash").is_none());
        assert!(params.get("root_hash_sig").is_none());
    }

    #[test]
    fn publish_provenance_paths_are_platform_scoped() {
        let measurement = crate::package_attestation::package_measurement_digest(
            "webapp",
            "1.0.0",
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        );

        let x86 = publish_provenance_ref("webapp", "x86_64-linux", &measurement).unwrap();
        let arm = publish_provenance_ref("webapp", "aarch64-linux", &measurement).unwrap();

        assert_ne!(x86, arm);
        assert!(x86.contains("/x86_64-linux/"));
        assert!(arm.contains("/aarch64-linux/"));
    }

    #[test]
    fn publish_provenance_ref_rejects_malformed_measurements() {
        assert!(publish_provenance_ref("webapp", "x86_64-linux", "not-a-digest").is_err());
        assert!(publish_provenance_ref("webapp", "x86_64-linux", "sha256:abcd").is_err());
        assert!(
            publish_provenance_ref(
                "webapp",
                "x86_64-linux",
                "sha256:gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"
            )
            .is_err()
        );
    }

    #[test]
    fn publish_provenance_artifact_preserves_sri_nar_hashes_as_nix_digests() {
        let package_nar_hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let source_nar_hash = "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";
        let info = StorePathInfo {
            path: "/nix/store/abc123-webapp-1.0.0".into(),
            nar_hash: package_nar_hash.into(),
            nar_size: 1048576,
            references: vec![],
            closure_size: 5242880,
        };
        let source = StorePathInfo {
            path: "/nix/store/srcdrv-webapp-1.0.0.drv".into(),
            nar_hash: source_nar_hash.into(),
            nar_size: 4096,
            references: vec![],
            closure_size: 4096,
        };
        let root_hash = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let manifest = verity_expose_manifest(root_hash);
        let manifest_digest =
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

        let signer = test_provenance_signer();
        let artifact = publish_provenance_artifact(
            TEST_PROVENANCE_REGISTRY,
            "webapp",
            "1.0.0",
            "x86_64-linux",
            &info,
            Some(&source),
            &manifest,
            manifest_digest,
            &signer.signer,
        )
        .unwrap()
        .expect("provenance artifact");

        let statement = signed_provenance_statement(&artifact);
        assert_eq!(
            statement["subject"][0]["digest"]["nix:narHash"].as_str(),
            Some(package_nar_hash)
        );
        assert!(statement["subject"][0]["digest"].get("sha256").is_none());
        assert_eq!(
            statement["predicate"]["buildDefinition"]["resolvedDependencies"][0]["digest"]
                ["nix:narHash"]
                .as_str(),
            Some(source_nar_hash)
        );
        assert!(
            statement["predicate"]["buildDefinition"]["resolvedDependencies"][0]["digest"]
                .get("sha256")
                .is_none()
        );
    }

    #[test]
    fn append_package_provenance_transparency_log_records_hash_chain() {
        let tmp = TempDir::new().unwrap();
        let (info, source, artifact) = sample_transparency_provenance();
        let provenance_path = write_sample_provenance_artifact(tmp.path(), &artifact);

        let log_path = append_package_provenance_transparency_log(
            tmp.path(),
            "webapp",
            "1.0.0",
            "x86_64-linux",
            &info,
            Some(&source),
            &artifact,
            &provenance_path,
        )
        .unwrap();
        append_package_provenance_transparency_log(
            tmp.path(),
            "webapp",
            "1.0.0",
            "x86_64-linux",
            &info,
            Some(&source),
            &artifact,
            &provenance_path,
        )
        .unwrap();

        assert_eq!(
            log_path,
            tmp.path().join(PACKAGE_PROVENANCE_TRANSPARENCY_LOG)
        );
        let content = fs::read_to_string(&log_path).unwrap();
        let entries = content
            .lines()
            .map(|line| serde_json::from_str::<PackageProvenanceTransparencyLogEntry>(line))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].body.sequence, 0);
        assert_eq!(entries[0].body.previous_entry_hash, None);
        assert_eq!(entries[0].body.package, "webapp");
        assert_eq!(entries[0].body.version, "1.0.0");
        assert_eq!(entries[0].body.platform, "x86_64-linux");
        assert_eq!(entries[0].body.store_path, info.path);
        assert_eq!(
            entries[0].body.root_digest.as_deref(),
            artifact.attestation.root_digest.as_deref()
        );
        assert_eq!(
            entries[0].body.root_hash.as_deref(),
            artifact.attestation.root_hash.as_deref()
        );
        assert_eq!(
            entries[0].body.statement.jsonl_sha256,
            format!("sha256:{}", sha256_hex(artifact.jsonl.as_bytes()))
        );
        assert_eq!(
            entries[0].entry_hash,
            package_provenance_transparency_entry_hash(&entries[0].body).unwrap()
        );
        assert_eq!(entries[1].body.sequence, 1);
        assert_eq!(
            entries[1].body.previous_entry_hash.as_deref(),
            Some(entries[0].entry_hash.as_str())
        );
        assert_eq!(
            read_package_provenance_transparency_log_state(&log_path).unwrap(),
            (2, Some(entries[1].entry_hash.clone()))
        );
    }

    #[test]
    fn append_package_provenance_transparency_log_rejects_corrupt_history() {
        let tmp = TempDir::new().unwrap();
        let (info, source, artifact) = sample_transparency_provenance();
        let provenance_path = write_sample_provenance_artifact(tmp.path(), &artifact);
        let log_path = append_package_provenance_transparency_log(
            tmp.path(),
            "webapp",
            "1.0.0",
            "x86_64-linux",
            &info,
            Some(&source),
            &artifact,
            &provenance_path,
        )
        .unwrap();
        let content = fs::read_to_string(&log_path).unwrap();
        let mut entry: PackageProvenanceTransparencyLogEntry =
            serde_json::from_str(content.trim()).unwrap();
        entry.entry_hash = format!("sha256:{}", "0".repeat(64));
        fs::write(
            &log_path,
            format!("{}\n", serde_json::to_string(&entry).unwrap()),
        )
        .unwrap();

        let err = append_package_provenance_transparency_log(
            tmp.path(),
            "webapp",
            "1.0.0",
            "x86_64-linux",
            &info,
            Some(&source),
            &artifact,
            &provenance_path,
        )
        .unwrap_err();

        assert!(format!("{err:#}").contains("hash mismatch"));
    }

    #[test]
    fn append_package_provenance_transparency_log_rejects_broken_previous_link() {
        let tmp = TempDir::new().unwrap();
        let (info, source, artifact) = sample_transparency_provenance();
        let provenance_path = write_sample_provenance_artifact(tmp.path(), &artifact);
        let log_path = append_package_provenance_transparency_log(
            tmp.path(),
            "webapp",
            "1.0.0",
            "x86_64-linux",
            &info,
            Some(&source),
            &artifact,
            &provenance_path,
        )
        .unwrap();
        append_package_provenance_transparency_log(
            tmp.path(),
            "webapp",
            "1.0.0",
            "x86_64-linux",
            &info,
            Some(&source),
            &artifact,
            &provenance_path,
        )
        .unwrap();
        let content = fs::read_to_string(&log_path).unwrap();
        let mut entries = content
            .lines()
            .map(|line| serde_json::from_str::<PackageProvenanceTransparencyLogEntry>(line))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        entries[1].body.previous_entry_hash = Some(format!("sha256:{}", "1".repeat(64)));
        entries[1].entry_hash =
            package_provenance_transparency_entry_hash(&entries[1].body).unwrap();
        let rewritten = entries
            .iter()
            .map(serde_json::to_string)
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .join("\n");
        fs::write(&log_path, format!("{rewritten}\n")).unwrap();

        let err = read_package_provenance_transparency_log_state(&log_path).unwrap_err();

        assert!(format!("{err:#}").contains("previous hash mismatch"));
    }

    #[test]
    fn append_package_provenance_transparency_log_rejects_head_rewrite() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        init_test_transparency_repo(&repo);
        let (info, source, artifact) = sample_transparency_provenance();
        let provenance_path = write_sample_provenance_artifact(&repo, &artifact);
        let log_path = append_package_provenance_transparency_log(
            &repo,
            "webapp",
            "1.0.0",
            "x86_64-linux",
            &info,
            Some(&source),
            &artifact,
            &provenance_path,
        )
        .unwrap();
        git(
            &repo,
            &[
                "add",
                PACKAGE_PROVENANCE_TRANSPARENCY_LOG,
                artifact.path.as_str(),
            ],
        )
        .unwrap();
        git(&repo, &["commit", "-m", "publish webapp"]).unwrap();
        fs::write(&log_path, "").unwrap();

        let err = append_package_provenance_transparency_log(
            &repo,
            "webapp",
            "1.0.0",
            "x86_64-linux",
            &info,
            Some(&source),
            &artifact,
            &provenance_path,
        )
        .unwrap_err();

        assert!(format!("{err:#}").contains("does not extend committed HEAD"));
    }

    #[test]
    fn validate_staged_package_provenance_transparency_log_rejects_statement_digest_mismatch() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        init_test_transparency_repo(&repo);
        let (info, source, artifact) = sample_transparency_provenance();
        let provenance_path = write_sample_provenance_artifact(&repo, &artifact);
        append_package_provenance_transparency_log(
            &repo,
            "webapp",
            "1.0.0",
            "x86_64-linux",
            &info,
            Some(&source),
            &artifact,
            &provenance_path,
        )
        .unwrap();
        fs::write(&provenance_path, "{}\n").unwrap();
        git(
            &repo,
            &[
                "add",
                PACKAGE_PROVENANCE_TRANSPARENCY_LOG,
                artifact.path.as_str(),
            ],
        )
        .unwrap();

        let err = validate_staged_package_provenance_transparency_log(&repo).unwrap_err();

        assert!(format!("{err:#}").contains("digest mismatch"));
    }

    #[test]
    fn commit_registry_paths_rejects_prestaged_bad_transparency_log() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        init_test_transparency_repo(&repo);
        let (info, source, artifact) = sample_transparency_provenance();
        let provenance_path = write_sample_provenance_artifact(&repo, &artifact);
        let log_path = append_package_provenance_transparency_log(
            &repo,
            "webapp",
            "1.0.0",
            "x86_64-linux",
            &info,
            Some(&source),
            &artifact,
            &provenance_path,
        )
        .unwrap();
        git(
            &repo,
            &[
                "add",
                PACKAGE_PROVENANCE_TRANSPARENCY_LOG,
                artifact.path.as_str(),
            ],
        )
        .unwrap();
        git(&repo, &["commit", "-m", "publish webapp"]).unwrap();

        let content = fs::read_to_string(&log_path).unwrap();
        let mut entry: PackageProvenanceTransparencyLogEntry =
            serde_json::from_str(content.trim()).unwrap();
        entry.entry_hash = format!("sha256:{}", "0".repeat(64));
        fs::write(
            &log_path,
            format!("{}\n", serde_json::to_string(&entry).unwrap()),
        )
        .unwrap();
        git(&repo, &["add", PACKAGE_PROVENANCE_TRANSPARENCY_LOG]).unwrap();
        let registry_toml = repo.join("registry.toml");
        fs::write(&registry_toml, "[registry]\nname = \"test\"\n").unwrap();

        let err =
            commit_registry_paths(&repo, "metadata change", &[registry_toml], None).unwrap_err();

        assert!(format!("{err:#}").contains("does not extend committed HEAD"));
    }

    #[test]
    fn commit_registry_paths_rejects_prestaged_statement_change_without_log_change() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        init_test_transparency_repo(&repo);
        let (info, source, artifact) = sample_transparency_provenance();
        let provenance_path = write_sample_provenance_artifact(&repo, &artifact);
        append_package_provenance_transparency_log(
            &repo,
            "webapp",
            "1.0.0",
            "x86_64-linux",
            &info,
            Some(&source),
            &artifact,
            &provenance_path,
        )
        .unwrap();
        git(
            &repo,
            &[
                "add",
                PACKAGE_PROVENANCE_TRANSPARENCY_LOG,
                artifact.path.as_str(),
            ],
        )
        .unwrap();
        git(&repo, &["commit", "-m", "publish webapp"]).unwrap();

        fs::write(&provenance_path, "{}\n").unwrap();
        git(&repo, &["add", artifact.path.as_str()]).unwrap();
        let registry_toml = repo.join("registry.toml");
        fs::write(&registry_toml, "[registry]\nname = \"test\"\n").unwrap();

        let err =
            commit_registry_paths(&repo, "metadata change", &[registry_toml], None).unwrap_err();

        assert!(format!("{err:#}").contains("digest mismatch"));
    }

    #[test]
    fn commit_registry_paths_rejects_first_provenance_statement_without_log() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        init_test_transparency_repo(&repo);
        let (_, _, artifact) = sample_transparency_provenance();
        write_sample_provenance_artifact(&repo, &artifact);
        git(&repo, &["add", artifact.path.as_str()]).unwrap();
        let registry_toml = repo.join("registry.toml");
        fs::write(&registry_toml, "[registry]\nname = \"test\"\n").unwrap();

        let err =
            commit_registry_paths(&repo, "metadata change", &[registry_toml], None).unwrap_err();

        assert!(format!("{err:#}").contains("transparency log is missing"));
    }

    #[test]
    fn commit_registry_paths_rejects_rfc0001_package_without_provenance() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        init_test_transparency_repo(&repo);
        let package_toml = repo.join("packages").join("w").join("webapp.toml");
        fs::create_dir_all(package_toml.parent().unwrap()).unwrap();
        fs::write(
            &package_toml,
            "[package]\n\
             name = \"webapp\"\n\
             description = \"\"\n\
             \n\
             [[versions]]\n\
             version = \"1.0.0\"\n\
             \n\
             [versions.platforms.x86_64-linux]\n\
             store_path = \"/nix/store/abc123-webapp-1.0.0\"\n\
             closure_size = 1\n\
             source_drv = \"\"\n\
             source_nar_hash = \"\"\n\
             \n\
             [versions.platforms.x86_64-linux.expose]\n\
             target = \"aos-pkg-webapp.target\"\n",
        )
        .unwrap();

        let err =
            commit_registry_paths(&repo, "publish webapp", &[package_toml], None).unwrap_err();

        assert!(format!("{err:#}").contains("without attestation provenance"));
    }

    #[test]
    fn commit_registry_paths_allows_package_toml_without_versions() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        init_test_transparency_repo(&repo);
        let package_toml = repo.join("packages").join("s").join("stub.toml");
        fs::create_dir_all(package_toml.parent().unwrap()).unwrap();
        fs::write(
            &package_toml,
            "[package]\n\
             name = \"stub\"\n\
             description = \"\"\n\
             license = \"MIT\"\n\
             maintainer = \"aos-team\"\n",
        )
        .unwrap();

        commit_registry_paths(&repo, "publish stub", &[package_toml], None).unwrap();

        assert!(current_git_head(&repo).is_ok());
    }

    #[test]
    fn commit_registry_paths_allows_semantically_empty_rfc0001_tables_without_provenance() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        init_test_transparency_repo(&repo);
        let package_toml = repo.join("packages").join("w").join("webapp.toml");
        fs::create_dir_all(package_toml.parent().unwrap()).unwrap();
        fs::write(
            &package_toml,
            "[package]\n\
             name = \"webapp\"\n\
             description = \"\"\n\
             license = \"MIT\"\n\
             maintainer = \"aos-team\"\n\
             \n\
             [[versions]]\n\
             version = \"1.0.0\"\n\
             \n\
             [versions.platforms.x86_64-linux]\n\
             store_path = \"/nix/store/abc123-webapp-1.0.0\"\n\
             closure_size = 1\n\
             source_drv = \"\"\n\
             source_nar_hash = \"\"\n\
             \n\
             [versions.platforms.x86_64-linux.permissions]\n\
             capabilities = []\n\
             cgroup-delegate = false\n\
             \n\
             [versions.platforms.x86_64-linux.bpf_lsm]\n\
             policies = []\n",
        )
        .unwrap();

        commit_registry_paths(&repo, "publish webapp", &[package_toml], None).unwrap();

        assert!(current_git_head(&repo).is_ok());
    }

    #[test]
    fn commit_registry_paths_joins_current_process_publish_lock() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        init_test_transparency_repo(&repo);
        let _publish_lock = RegistryPublishLock::acquire(&repo).unwrap();
        let registry_toml = repo.join("registry.toml");
        fs::write(&registry_toml, "[registry]\nname = \"test\"\n").unwrap();

        commit_registry_paths(&repo, "metadata change", &[registry_toml], None).unwrap();

        assert!(current_git_head(&repo).is_ok());
    }

    #[test]
    fn commit_registry_paths_fails_before_staging_when_publish_lock_is_foreign() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        init_test_transparency_repo(&repo);
        fs::write(repo.join(".git").join("apr-publish.lock"), "pid=999999\n").unwrap();
        let registry_toml = repo.join("registry.toml");
        fs::write(&registry_toml, "[registry]\nname = \"test\"\n").unwrap();

        let err =
            commit_registry_paths(&repo, "metadata change", &[registry_toml], None).unwrap_err();

        assert!(format!("{err:#}").contains("another publisher may be running"));
        assert_eq!(
            git(&repo, &["diff", "--cached", "--name-only"]).unwrap(),
            ""
        );
    }

    #[test]
    fn validate_staged_package_provenance_transparency_log_rejects_statement_body_mismatch() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        init_test_transparency_repo(&repo);
        let (info, source, artifact) = sample_transparency_provenance();
        let provenance_path = write_sample_provenance_artifact(&repo, &artifact);
        let log_path = append_package_provenance_transparency_log(
            &repo,
            "webapp",
            "1.0.0",
            "x86_64-linux",
            &info,
            Some(&source),
            &artifact,
            &provenance_path,
        )
        .unwrap();
        let content = fs::read_to_string(&log_path).unwrap();
        let mut entry: PackageProvenanceTransparencyLogEntry =
            serde_json::from_str(content.trim()).unwrap();
        entry.body.package = "other".to_string();
        entry.entry_hash = package_provenance_transparency_entry_hash(&entry.body).unwrap();
        fs::write(
            &log_path,
            format!("{}\n", serde_json::to_string(&entry).unwrap()),
        )
        .unwrap();
        git(
            &repo,
            &[
                "add",
                PACKAGE_PROVENANCE_TRANSPARENCY_LOG,
                artifact.path.as_str(),
            ],
        )
        .unwrap();

        let err = validate_staged_package_provenance_transparency_log(&repo).unwrap_err();

        assert!(format!("{err:#}").contains("externalParameters.package mismatch"));
    }

    #[test]
    fn validate_staged_package_provenance_transparency_log_rejects_manifest_measurement_mismatch() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        init_test_transparency_repo(&repo);
        let (info, source, artifact) = sample_transparency_provenance();
        let provenance_path = write_sample_provenance_artifact(&repo, &artifact);
        let log_path = append_package_provenance_transparency_log(
            &repo,
            "webapp",
            "1.0.0",
            "x86_64-linux",
            &info,
            Some(&source),
            &artifact,
            &provenance_path,
        )
        .unwrap();
        let mut statement = signed_provenance_statement(&artifact);
        let subjects = statement
            .get_mut("subject")
            .and_then(Value::as_array_mut)
            .unwrap();
        let manifest_subject = subjects
            .iter_mut()
            .find(|subject| {
                subject.get("name").and_then(Value::as_str)
                    == Some("aos:permissions-manifest:webapp:1.0.0:x86_64-linux")
            })
            .unwrap();
        manifest_subject["digest"]["sha256"] = Value::String("e".repeat(64));
        let statement_jsonl = sign_test_provenance_statement(&statement);
        fs::write(&provenance_path, &statement_jsonl).unwrap();

        let content = fs::read_to_string(&log_path).unwrap();
        let mut entry: PackageProvenanceTransparencyLogEntry =
            serde_json::from_str(content.trim()).unwrap();
        entry.body.statement.jsonl_sha256 =
            format!("sha256:{}", sha256_hex(statement_jsonl.as_bytes()));
        entry.entry_hash = package_provenance_transparency_entry_hash(&entry.body).unwrap();
        fs::write(
            &log_path,
            format!("{}\n", serde_json::to_string(&entry).unwrap()),
        )
        .unwrap();
        git(
            &repo,
            &[
                "add",
                PACKAGE_PROVENANCE_TRANSPARENCY_LOG,
                artifact.path.as_str(),
            ],
        )
        .unwrap();

        let err = validate_staged_package_provenance_transparency_log(&repo).unwrap_err();

        assert!(format!("{err:#}").contains("measurement does not match permissions manifest"));
    }

    #[test]
    fn validate_staged_package_provenance_transparency_log_accepts_matching_package_toml() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        init_test_transparency_repo(&repo);
        let (info, source, artifact) = sample_transparency_provenance();
        let provenance_path = write_sample_provenance_artifact(&repo, &artifact);
        append_package_provenance_transparency_log(
            &repo,
            "webapp",
            "1.0.0",
            "x86_64-linux",
            &info,
            Some(&source),
            &artifact,
            &provenance_path,
        )
        .unwrap();
        let package_toml = write_sample_package_toml(&repo, &info, &source, &artifact, None);
        let store_record = write_sample_store_record(&repo, &info, None);
        git(
            &repo,
            &[
                "add",
                PACKAGE_PROVENANCE_TRANSPARENCY_LOG,
                artifact.path.as_str(),
                package_toml.strip_prefix(&repo).unwrap().to_str().unwrap(),
                store_record.strip_prefix(&repo).unwrap().to_str().unwrap(),
            ],
        )
        .unwrap();

        validate_staged_package_provenance_transparency_log(&repo).unwrap();
    }

    #[test]
    fn validate_staged_package_provenance_transparency_log_rejects_package_toml_mismatch() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        init_test_transparency_repo(&repo);
        let (info, source, artifact) = sample_transparency_provenance();
        let provenance_path = write_sample_provenance_artifact(&repo, &artifact);
        append_package_provenance_transparency_log(
            &repo,
            "webapp",
            "1.0.0",
            "x86_64-linux",
            &info,
            Some(&source),
            &artifact,
            &provenance_path,
        )
        .unwrap();
        let bad_measurement = format!("sha256:{}", "f".repeat(64));
        let package_toml =
            write_sample_package_toml(&repo, &info, &source, &artifact, Some(&bad_measurement));
        git(
            &repo,
            &[
                "add",
                PACKAGE_PROVENANCE_TRANSPARENCY_LOG,
                artifact.path.as_str(),
                package_toml.strip_prefix(&repo).unwrap().to_str().unwrap(),
            ],
        )
        .unwrap();

        let err = validate_staged_package_provenance_transparency_log(&repo).unwrap_err();

        assert!(format!("{err:#}").contains("measurement mismatch"));
    }

    #[test]
    fn commit_registry_paths_rejects_package_toml_provenance_removal() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        init_test_transparency_repo(&repo);
        let (info, source, artifact) = sample_transparency_provenance();
        let provenance_path = write_sample_provenance_artifact(&repo, &artifact);
        append_package_provenance_transparency_log(
            &repo,
            "webapp",
            "1.0.0",
            "x86_64-linux",
            &info,
            Some(&source),
            &artifact,
            &provenance_path,
        )
        .unwrap();
        let package_toml = write_sample_package_toml(&repo, &info, &source, &artifact, None);
        git(
            &repo,
            &[
                "add",
                PACKAGE_PROVENANCE_TRANSPARENCY_LOG,
                artifact.path.as_str(),
                package_toml.strip_prefix(&repo).unwrap().to_str().unwrap(),
            ],
        )
        .unwrap();
        git(&repo, &["commit", "-m", "publish webapp"]).unwrap();

        let content = fs::read_to_string(&package_toml).unwrap();
        let without_provenance = content
            .lines()
            .filter(|line| !line.trim_start().starts_with("provenance = "))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&package_toml, format!("{without_provenance}\n")).unwrap();
        git(
            &repo,
            &[
                "add",
                package_toml.strip_prefix(&repo).unwrap().to_str().unwrap(),
            ],
        )
        .unwrap();
        let registry_toml = repo.join("registry.toml");
        fs::write(&registry_toml, "[registry]\nname = \"test\"\n").unwrap();

        let err =
            commit_registry_paths(&repo, "metadata change", &[registry_toml], None).unwrap_err();

        assert!(format!("{err:#}").contains("removes committed provenance"));
    }

    #[test]
    fn commit_registry_paths_rejects_package_toml_provenance_type_change() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        init_test_transparency_repo(&repo);
        let (info, source, artifact) = sample_transparency_provenance();
        let provenance_path = write_sample_provenance_artifact(&repo, &artifact);
        append_package_provenance_transparency_log(
            &repo,
            "webapp",
            "1.0.0",
            "x86_64-linux",
            &info,
            Some(&source),
            &artifact,
            &provenance_path,
        )
        .unwrap();
        let package_toml = write_sample_package_toml(&repo, &info, &source, &artifact, None);
        git(
            &repo,
            &[
                "add",
                PACKAGE_PROVENANCE_TRANSPARENCY_LOG,
                artifact.path.as_str(),
                package_toml.strip_prefix(&repo).unwrap().to_str().unwrap(),
            ],
        )
        .unwrap();
        git(&repo, &["commit", "-m", "publish webapp"]).unwrap();

        let provenance = artifact.attestation.provenance.as_deref().unwrap();
        let content = fs::read_to_string(&package_toml).unwrap();
        fs::write(
            &package_toml,
            content.replace(&format!("provenance = \"{provenance}\""), "provenance = []"),
        )
        .unwrap();
        git(
            &repo,
            &[
                "add",
                package_toml.strip_prefix(&repo).unwrap().to_str().unwrap(),
            ],
        )
        .unwrap();
        let registry_toml = repo.join("registry.toml");
        fs::write(&registry_toml, "[registry]\nname = \"test\"\n").unwrap();

        let err =
            commit_registry_paths(&repo, "metadata change", &[registry_toml], None).unwrap_err();

        assert!(format!("{err:#}").contains("provenance must be a string"));
    }

    #[test]
    fn commit_registry_paths_rejects_package_toml_source_nar_hash_mismatch() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        init_test_transparency_repo(&repo);
        let (info, source, artifact) = sample_transparency_provenance();
        let provenance_path = write_sample_provenance_artifact(&repo, &artifact);
        append_package_provenance_transparency_log(
            &repo,
            "webapp",
            "1.0.0",
            "x86_64-linux",
            &info,
            Some(&source),
            &artifact,
            &provenance_path,
        )
        .unwrap();
        let package_toml = write_sample_package_toml(&repo, &info, &source, &artifact, None);
        git(
            &repo,
            &[
                "add",
                PACKAGE_PROVENANCE_TRANSPARENCY_LOG,
                artifact.path.as_str(),
                package_toml.strip_prefix(&repo).unwrap().to_str().unwrap(),
            ],
        )
        .unwrap();
        git(&repo, &["commit", "-m", "publish webapp"]).unwrap();

        let content = fs::read_to_string(&package_toml).unwrap();
        fs::write(
            &package_toml,
            content.replace(
                &format!("source_nar_hash = \"{}\"", source.nar_hash),
                &format!("source_nar_hash = \"sha256:{}\"", "f".repeat(64)),
            ),
        )
        .unwrap();
        git(
            &repo,
            &[
                "add",
                package_toml.strip_prefix(&repo).unwrap().to_str().unwrap(),
            ],
        )
        .unwrap();
        let registry_toml = repo.join("registry.toml");
        fs::write(&registry_toml, "[registry]\nname = \"test\"\n").unwrap();

        let err =
            commit_registry_paths(&repo, "metadata change", &[registry_toml], None).unwrap_err();

        assert!(format!("{err:#}").contains("source_nar_hash mismatch"));
    }

    #[test]
    fn commit_registry_paths_rejects_unlogged_provenanced_store_bytes() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        init_test_transparency_repo(&repo);
        let (info, source, artifact) = sample_transparency_provenance();
        let provenance_path = write_sample_provenance_artifact(&repo, &artifact);
        append_package_provenance_transparency_log(
            &repo,
            "webapp",
            "1.0.0",
            "x86_64-linux",
            &info,
            Some(&source),
            &artifact,
            &provenance_path,
        )
        .unwrap();
        let package_toml = write_sample_package_toml(&repo, &info, &source, &artifact, None);
        let store_record = write_sample_store_record(&repo, &info, None);
        git(
            &repo,
            &[
                "add",
                PACKAGE_PROVENANCE_TRANSPARENCY_LOG,
                artifact.path.as_str(),
                package_toml.strip_prefix(&repo).unwrap().to_str().unwrap(),
                store_record.strip_prefix(&repo).unwrap().to_str().unwrap(),
            ],
        )
        .unwrap();
        git(&repo, &["commit", "-m", "publish webapp"]).unwrap();

        let bad_nar_hash = format!("sha256:{}", "e".repeat(64));
        write_sample_store_record(&repo, &info, Some(&bad_nar_hash));
        git(
            &repo,
            &[
                "add",
                store_record.strip_prefix(&repo).unwrap().to_str().unwrap(),
            ],
        )
        .unwrap();
        let registry_toml = repo.join("registry.toml");
        fs::write(&registry_toml, "[registry]\nname = \"test\"\n").unwrap();

        let err =
            commit_registry_paths(&repo, "metadata change", &[registry_toml], None).unwrap_err();

        assert!(format!("{err:#}").contains("blesses NAR"));
    }

    #[test]
    fn commit_registry_paths_rejects_new_provenanced_root_unlogged_store_bytes() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        init_test_transparency_repo(&repo);
        let (info, source, artifact) = sample_transparency_provenance();
        let provenance_path = write_sample_provenance_artifact(&repo, &artifact);
        append_package_provenance_transparency_log(
            &repo,
            "webapp",
            "1.0.0",
            "x86_64-linux",
            &info,
            Some(&source),
            &artifact,
            &provenance_path,
        )
        .unwrap();
        let package_toml = write_sample_package_toml(&repo, &info, &source, &artifact, None);
        let bad_nar_hash = format!("sha256:{}", "e".repeat(64));
        let store_record = write_sample_store_record(&repo, &info, Some(&bad_nar_hash));
        git(
            &repo,
            &[
                "add",
                PACKAGE_PROVENANCE_TRANSPARENCY_LOG,
                artifact.path.as_str(),
                package_toml.strip_prefix(&repo).unwrap().to_str().unwrap(),
                store_record.strip_prefix(&repo).unwrap().to_str().unwrap(),
            ],
        )
        .unwrap();
        let registry_toml = repo.join("registry.toml");
        fs::write(&registry_toml, "[registry]\nname = \"test\"\n").unwrap();

        let err =
            commit_registry_paths(&repo, "metadata change", &[registry_toml], None).unwrap_err();

        assert!(format!("{err:#}").contains("blesses NAR"));
    }

    #[test]
    fn commit_registry_paths_rejects_new_provenanced_root_without_store_record() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        init_test_transparency_repo(&repo);
        let (info, source, artifact) = sample_transparency_provenance();
        let provenance_path = write_sample_provenance_artifact(&repo, &artifact);
        append_package_provenance_transparency_log(
            &repo,
            "webapp",
            "1.0.0",
            "x86_64-linux",
            &info,
            Some(&source),
            &artifact,
            &provenance_path,
        )
        .unwrap();
        let package_toml = write_sample_package_toml(&repo, &info, &source, &artifact, None);
        git(
            &repo,
            &[
                "add",
                PACKAGE_PROVENANCE_TRANSPARENCY_LOG,
                artifact.path.as_str(),
                package_toml.strip_prefix(&repo).unwrap().to_str().unwrap(),
            ],
        )
        .unwrap();
        let registry_toml = repo.join("registry.toml");
        fs::write(&registry_toml, "[registry]\nname = \"test\"\n").unwrap();

        let err =
            commit_registry_paths(&repo, "metadata change", &[registry_toml], None).unwrap_err();

        assert!(format!("{err:#}").contains("store record"));
    }

    #[test]
    fn validate_staged_package_provenance_transparency_log_rejects_duplicate_package_platform() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        init_test_transparency_repo(&repo);
        let (info, source, artifact) = sample_transparency_provenance();
        let provenance_path = write_sample_provenance_artifact(&repo, &artifact);
        append_package_provenance_transparency_log(
            &repo,
            "webapp",
            "1.0.0",
            "x86_64-linux",
            &info,
            Some(&source),
            &artifact,
            &provenance_path,
        )
        .unwrap();
        let package_toml = write_sample_package_toml(&repo, &info, &source, &artifact, None);
        fs::OpenOptions::new()
            .append(true)
            .open(&package_toml)
            .unwrap()
            .write_all(
                b"\n[[versions]]\n\
                  version = \"1.0.0\"\n\
                  \n\
                  [versions.platforms.x86_64-linux]\n\
                  store_path = \"/nix/store/abc123-webapp-1.0.0\"\n\
                  closure_size = 1\n\
                  source_drv = \"\"\n\
                  source_nar_hash = \"\"\n",
            )
            .unwrap();
        git(
            &repo,
            &[
                "add",
                PACKAGE_PROVENANCE_TRANSPARENCY_LOG,
                artifact.path.as_str(),
                package_toml.strip_prefix(&repo).unwrap().to_str().unwrap(),
            ],
        )
        .unwrap();

        let err = validate_staged_package_provenance_transparency_log(&repo).unwrap_err();

        assert!(format!("{err:#}").contains("duplicate webapp 1.0.0 x86_64-linux"));
    }

    #[test]
    fn commit_registry_paths_rejects_provenanced_store_nar_size_mismatch() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        init_test_transparency_repo(&repo);
        let (info, source, artifact) = sample_transparency_provenance();
        let provenance_path = write_sample_provenance_artifact(&repo, &artifact);
        append_package_provenance_transparency_log(
            &repo,
            "webapp",
            "1.0.0",
            "x86_64-linux",
            &info,
            Some(&source),
            &artifact,
            &provenance_path,
        )
        .unwrap();
        let package_toml = write_sample_package_toml(&repo, &info, &source, &artifact, None);
        let store_record = write_sample_store_record(&repo, &info, None);
        git(
            &repo,
            &[
                "add",
                PACKAGE_PROVENANCE_TRANSPARENCY_LOG,
                artifact.path.as_str(),
                package_toml.strip_prefix(&repo).unwrap().to_str().unwrap(),
                store_record.strip_prefix(&repo).unwrap().to_str().unwrap(),
            ],
        )
        .unwrap();
        git(&repo, &["commit", "-m", "publish webapp"]).unwrap();

        write_sample_store_record(&repo, &info, Some(&info.nar_hash));
        git(
            &repo,
            &[
                "add",
                store_record.strip_prefix(&repo).unwrap().to_str().unwrap(),
            ],
        )
        .unwrap();
        let registry_toml = repo.join("registry.toml");
        fs::write(&registry_toml, "[registry]\nname = \"test\"\n").unwrap();

        let err =
            commit_registry_paths(&repo, "metadata change", &[registry_toml], None).unwrap_err();

        assert!(format!("{err:#}").contains("blesses NAR"));
    }

    #[test]
    fn commit_registry_paths_rejects_reachable_dependency_store_change() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        init_test_transparency_repo(&repo);
        let (info, source, artifact) = sample_transparency_provenance();
        let dep = StorePathInfo {
            path: "/nix/store/lib123-runtime-1.0".into(),
            nar_hash: format!("sha256:{}", "1".repeat(64)),
            nar_size: 4096,
            references: vec![],
            closure_size: 4096,
        };
        let provenance_path = write_sample_provenance_artifact(&repo, &artifact);
        append_package_provenance_transparency_log(
            &repo,
            "webapp",
            "1.0.0",
            "x86_64-linux",
            &info,
            Some(&source),
            &artifact,
            &provenance_path,
        )
        .unwrap();
        let package_toml = write_sample_package_toml(&repo, &info, &source, &artifact, None);
        let root_record = write_sample_store_record_with_deps(&repo, &info, &[&dep.path], None);
        let dep_record = write_sample_store_record(&repo, &dep, None);
        git(
            &repo,
            &[
                "add",
                PACKAGE_PROVENANCE_TRANSPARENCY_LOG,
                artifact.path.as_str(),
                package_toml.strip_prefix(&repo).unwrap().to_str().unwrap(),
                root_record.strip_prefix(&repo).unwrap().to_str().unwrap(),
                dep_record.strip_prefix(&repo).unwrap().to_str().unwrap(),
            ],
        )
        .unwrap();
        git(&repo, &["commit", "-m", "publish webapp"]).unwrap();

        let bad_nar_hash = format!("sha256:{}", "2".repeat(64));
        write_sample_store_record(&repo, &dep, Some(&bad_nar_hash));
        git(
            &repo,
            &[
                "add",
                dep_record.strip_prefix(&repo).unwrap().to_str().unwrap(),
            ],
        )
        .unwrap();
        let registry_toml = repo.join("registry.toml");
        fs::write(&registry_toml, "[registry]\nname = \"test\"\n").unwrap();

        let err =
            commit_registry_paths(&repo, "metadata change", &[registry_toml], None).unwrap_err();

        assert!(format!("{err:#}").contains("reachable dependency"));
    }

    #[test]
    fn package_provenance_statement_path_rejects_git_revspec_punctuation() {
        assert!(ensure_safe_package_provenance_statement_path("0:foo.intoto.jsonl").is_err());
        assert!(
            ensure_safe_package_provenance_statement_path(
                "provenance/w/web/x86_64-linux/bad:path.intoto.jsonl"
            )
            .is_err()
        );
        assert!(
            ensure_safe_package_provenance_statement_path(
                "provenance/w/web/x86_64-linux/good.intoto.jsonl"
            )
            .is_ok()
        );
    }

    fn sample_transparency_provenance() -> (StorePathInfo, StorePathInfo, PublishProvenanceArtifact)
    {
        let info = StorePathInfo {
            path: "/nix/store/abc123-webapp-1.0.0".into(),
            nar_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            nar_size: 1048576,
            references: vec![],
            closure_size: 5242880,
        };
        let source = StorePathInfo {
            path: "/nix/store/srcdrv-webapp-1.0.0.drv".into(),
            nar_hash: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .into(),
            nar_size: 4096,
            references: vec![],
            closure_size: 4096,
        };
        let root_hash = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let manifest = verity_expose_manifest(root_hash);
        let manifest_digest =
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let signer = test_provenance_signer();
        let artifact = publish_provenance_artifact(
            TEST_PROVENANCE_REGISTRY,
            "webapp",
            "1.0.0",
            "x86_64-linux",
            &info,
            Some(&source),
            &manifest,
            manifest_digest,
            &signer.signer,
        )
        .unwrap()
        .unwrap();
        (info, source, artifact)
    }

    fn write_sample_provenance_artifact(
        root: &Path,
        artifact: &PublishProvenanceArtifact,
    ) -> PathBuf {
        let path = root.join(&artifact.path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, &artifact.jsonl).unwrap();
        path
    }

    fn write_sample_store_record(
        root: &Path,
        info: &StorePathInfo,
        extra_nar_hash: Option<&str>,
    ) -> PathBuf {
        write_sample_store_record_with_deps(root, info, &[], extra_nar_hash)
    }

    fn write_sample_store_record_with_deps(
        root: &Path,
        info: &StorePathInfo,
        deps: &[&str],
        extra_nar_hash: Option<&str>,
    ) -> PathBuf {
        let ia_hash = extract_hash(&info.path);
        let path = store::entry_path(root, ia_hash).unwrap();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let dep_edges = deps
            .iter()
            .map(|dep| DepEdge {
                dep_ia: extract_hash(dep).to_string(),
                dep_ca: None,
            })
            .collect::<Vec<_>>();
        let mut entry = store::StoreEntry {
            realisations: vec![Realisation {
                nar: NarBytes::from_hash(&info.nar_hash, info.nar_size).unwrap(),
                ca: None,
                deps: dep_edges,
            }],
        };
        if let Some(nar_hash) = extra_nar_hash {
            entry.realisations.push(Realisation {
                nar: NarBytes::from_hash(nar_hash, info.nar_size + 1).unwrap(),
                ca: Some(store::normalize_digest(nar_hash).unwrap()),
                deps: Vec::new(),
            });
        }
        fs::write(&path, store::serialize_entry(&entry)).unwrap();
        path
    }

    fn write_sample_package_toml(
        root: &Path,
        info: &StorePathInfo,
        source: &StorePathInfo,
        artifact: &PublishProvenanceArtifact,
        measurement_override: Option<&str>,
    ) -> PathBuf {
        let path = root.join("packages").join("w").join("webapp.toml");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let root_digest = artifact.attestation.root_digest.as_deref().unwrap();
        let root_hash = artifact.attestation.root_hash.as_deref().unwrap();
        let root_hash_sig = artifact.attestation.root_hash_sig.as_deref().unwrap();
        let provenance = artifact.attestation.provenance.as_deref().unwrap();
        let measurement = measurement_override
            .or(artifact.attestation.measurement.as_deref())
            .unwrap();
        fs::write(
            &path,
            format!(
                "[package]\n\
                 name = \"webapp\"\n\
                 description = \"\"\n\
                 \n\
                 [[versions]]\n\
                 version = \"1.0.0\"\n\
                 \n\
                 [versions.platforms.x86_64-linux]\n\
                 store_path = \"{}\"\n\
                 closure_size = 1\n\
                 source_drv = \"{}\"\n\
                 source_nar_hash = \"{}\"\n\
                 root_digest = \"{}\"\n\
                 root_hash = \"{}\"\n\
                 root_hash_sig = \"{}\"\n\
                 provenance = \"{}\"\n\
                 measurement = \"{}\"\n",
                info.path,
                source.path,
                source.nar_hash,
                root_digest,
                root_hash,
                root_hash_sig,
                provenance,
                measurement
            ),
        )
        .unwrap();
        path
    }

    fn init_test_transparency_repo(repo: &Path) {
        git(
            repo,
            &["init", "--object-format=sha256", "--initial-branch=main"],
        )
        .unwrap();
        git(repo, &["config", "user.name", "AOS Registry"]).unwrap();
        git(repo, &["config", "user.email", "registry@example.com"]).unwrap();
        git(repo, &["config", "commit.gpgsign", "false"]).unwrap();
        fs::write(
            repo.join("registry.toml"),
            format!("[registry]\nname = \"{TEST_PROVENANCE_REGISTRY}\"\n"),
        )
        .unwrap();
        let keypair = crate::sshkey::Ed25519Keypair::from_seed([42_u8; 32]);
        keys::write_keys_toml(
            repo,
            &KeysToml {
                active: vec![RosterKey {
                    id: TEST_PROVENANCE_KEY_ID.to_string(),
                    key: keypair.trust_key_line(TEST_PROVENANCE_REGISTRY),
                }],
                ..KeysToml::default()
            },
        )
        .unwrap();
    }

    #[test]
    fn package_attestation_measurement_changes_when_manifest_digest_changes() {
        let root_hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let first = crate::package_attestation::package_measurement_digest(
            "webapp",
            "1.0.0",
            root_hash,
            &crate::package_attestation::package_manifest_digest_bytes(br#"{"network":"private"}"#),
        );
        let second = crate::package_attestation::package_measurement_digest(
            "webapp",
            "1.0.0",
            root_hash,
            &crate::package_attestation::package_manifest_digest_bytes(br#"{"network":"host"}"#),
        );

        assert_ne!(first, second);
    }

    #[test]
    fn build_package_toml_update_existing() {
        let existing = r#"[package]
name = "curl"
description = "URL transfer tool"
license = "MIT"
maintainer = "aos-team"

[[versions]]
version = "8.5.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/old-curl-8.5.0"
nar_hash = "sha256:old"
nar_size = 100
closure_size = 500
source_drv = ""
source_nar_hash = ""
references = []
"#;
        let info = StorePathInfo {
            path: "/nix/store/new-curl-8.5.0".into(),
            nar_hash: "sha256:new".into(),
            nar_size: 200,
            references: vec![],
            closure_size: 600,
        };
        let content = build_package_toml(
            existing,
            "curl",
            "8.5.0",
            "aarch64-linux",
            &info,
            Some("URL transfer tool"),
            None,
            Some("MIT"),
            Some("aos-team"),
            false,
            None,
            &[],
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        // Should contain both platforms.
        assert!(content.contains("x86_64-linux"));
        assert!(content.contains("aarch64-linux"));
        assert!(content.contains("/nix/store/new-curl-8.5.0"));
        // The pre-existing platform's legacy fields survive untouched; the
        // new platform entry carries no nar_hash (RFC-0005).
        assert!(content.contains("sha256:old"));
        assert!(!content.contains("sha256:new"));
    }

    #[test]
    fn build_package_toml_with_sysroot() {
        let image_fixture = TempDir::new().unwrap();
        let info = StorePathInfo {
            path: "/nix/store/abc123-server-2026.04".into(),
            nar_hash: "sha256:aabb".into(),
            nar_size: 12345678,
            references: vec!["ref1".into()],
            closure_size: 52428800,
        };
        let img_info = write_direct_image_output(
            image_fixture.path(),
            "raw",
            serde_json::json!(["bare-metal"]),
        );
        rewrite_test_image_parent(&img_info, "2026.04", "x86_64-linux");
        let image = inspect_test_image("raw", img_info, "2026.04", "x86_64-linux").unwrap();
        let content = build_package_toml(
            "",
            "server",
            "2026.04",
            "x86_64-linux",
            &info,
            Some("AOS server"),
            None,
            Some("MIT"),
            Some("aos-team"),
            true,
            Some("2026.03"),
            &[image],
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert!(content.contains("sysroot = true"));
        assert!(content.contains("previous = \"2026.03\""));
        assert!(content.contains("format = \"raw\""));
        assert!(content.contains("sha256:1111111111111111111111111111111111111111111111111111"));
        assert!(content.contains("sha256:2222222222222222222222222222222222222222222222222222"));
        let parsed = crate::registry::parse::parse_package_file(&content).unwrap();
        let image = &parsed.versions[0].platforms["x86_64-linux"].images[0];
        assert_eq!(image.delivery.schema_version, 2);
        assert!(image.delivery.object_key.is_empty());
    }

    #[test]
    fn build_package_toml_keeps_disk_image_verity_sidecars_out_of_catalog() {
        let image_fixture = TempDir::new().unwrap();
        let info = StorePathInfo {
            path: "/nix/store/abc123-server-2026.04".into(),
            nar_hash: "sha256:aabb".into(),
            nar_size: 12345678,
            references: vec!["ref1".into()],
            closure_size: 52428800,
        };
        let img_info = write_direct_image_output(
            image_fixture.path(),
            "raw",
            serde_json::json!(["bare-metal"]),
        );
        let image_root = Path::new(&img_info.path);
        fs::write(image_root.join("root.img"), b"root").unwrap();
        fs::write(image_root.join("root.verity"), b"verity").unwrap();
        fs::write(image_root.join("root.roothash"), "a".repeat(64)).unwrap();
        fs::write(image_root.join("root.roothash.p7s"), b"signature").unwrap();
        rewrite_test_image_parent(&img_info, "2026.04", "x86_64-linux");
        let image = inspect_test_image("raw", img_info, "2026.04", "x86_64-linux").unwrap();

        let content = build_package_toml(
            "",
            "server",
            "2026.04",
            "x86_64-linux",
            &info,
            Some("AOS server"),
            None,
            Some("MIT"),
            Some("aos-team"),
            true,
            None,
            &[image],
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        let parsed = crate::registry::parse::parse_package_file(&content).unwrap();
        let image = &parsed.versions[0].platforms["x86_64-linux"].images[0];
        assert_eq!(image.format, "raw");
        assert!(image.root_image.is_none());
        assert!(image.root_verity.is_none());
        assert!(image.root_hash.is_none());
        assert!(image.root_hash_sig.is_none());
    }

    #[test]
    fn build_package_toml_catalogs_verity_for_raw_recovery_image() {
        let image_fixture = TempDir::new().unwrap();
        let info = StorePathInfo {
            path: "/nix/store/abc123-server-2026.04".into(),
            nar_hash: "sha256:aabb".into(),
            nar_size: 12345678,
            references: vec!["ref1".into()],
            closure_size: 52428800,
        };
        let img_info = write_direct_image_output(
            image_fixture.path(),
            "raw",
            serde_json::json!(["bare-metal"]),
        );
        let image_root = Path::new(&img_info.path);
        fs::write(image_root.join("root.img"), b"root").unwrap();
        fs::write(image_root.join("root.verity"), b"verity").unwrap();
        fs::write(image_root.join("root.roothash"), "a".repeat(64)).unwrap();
        fs::write(image_root.join("root.roothash.p7s"), b"signature").unwrap();
        rewrite_test_image_parent(&img_info, "2026.04", "x86_64-linux");
        let mut image = inspect_test_image("raw", img_info, "2026.04", "x86_64-linux").unwrap();
        image.sb.recovery_ukis.push(RecoveryUkiEntry {
            copy: UkiSlot::A,
            path: "recovery-a.efi".into(),
            entry_path: "recovery-a.conf".into(),
            byte_size: 1,
            sha256: "b".repeat(64),
            release: "2026.04".into(),
            recovery_abi: 1,
            sb_signer_cert_sha256: "c".repeat(64),
            sbat: vec![SbatEntry {
                component: "aos".into(),
                generation: 1,
            }],
        });

        let content = build_package_toml(
            "",
            "server",
            "2026.04",
            "x86_64-linux",
            &info,
            Some("AOS server"),
            None,
            Some("MIT"),
            Some("aos-team"),
            true,
            None,
            &[image],
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        assert!(content.contains("root_image = \"root.img\""));
        assert!(content.contains("root_verity = \"root.verity\""));
        assert!(content.contains(&format!("root_hash = \"sha256:{}\"", "a".repeat(64))));
        assert!(content.contains("root_hash_sig = \"root.roothash.p7s\""));
    }

    #[test]
    fn build_package_toml_escapes_maintainer_metadata() {
        let image_fixture = TempDir::new().unwrap();
        let info = StorePathInfo {
            path: "/nix/store/abc123-tool-1.0.0".into(),
            nar_hash: "sha256:aabb".into(),
            nar_size: 42,
            references: vec!["ref\"one".into()],
            closure_size: 84,
        };
        let img_info = write_direct_image_output(
            image_fixture.path(),
            "raw",
            serde_json::json!(["bare-metal"]),
        );
        rewrite_test_image_parent(&img_info, "1.0.0", "x86_64-linux");
        let image = inspect_test_image("raw", img_info, "1.0.0", "x86_64-linux").unwrap();

        let content = build_package_toml(
            "",
            "tool",
            "1.0.0",
            "x86_64-linux",
            &info,
            Some("Tool with \"quoted\" metadata\nand a second line"),
            Some("https://example.invalid/tool?feature=\"quotes\""),
            Some("MIT OR Apache-2.0"),
            Some("AOS Team <aos@example.invalid>"),
            false,
            Some("0.9.0+build\"meta"),
            &[image],
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        let rendered: toml::Value = toml::from_str(&content).unwrap();
        assert_eq!(
            rendered
                .get("package")
                .and_then(|package| package.get("description"))
                .and_then(|description| description.as_str()),
            Some("Tool with \"quoted\" metadata\nand a second line")
        );
        assert_eq!(
            rendered
                .get("versions")
                .and_then(|versions| versions.as_array())
                .and_then(|versions| versions.first())
                .and_then(|version| version.get("previous"))
                .and_then(|previous| previous.as_str()),
            Some("0.9.0+build\"meta")
        );
        assert_eq!(
            rendered
                .get("versions")
                .and_then(|versions| versions.as_array())
                .and_then(|versions| versions.first())
                .and_then(|version| version.get("platforms"))
                .and_then(|platforms| platforms.get("x86_64-linux"))
                .and_then(|platform| platform.get("images"))
                .and_then(|images| images.as_array())
                .and_then(|images| images.first())
                .and_then(|image| image.get("format"))
                .and_then(|format| format.as_str()),
            Some("raw")
        );
    }

    #[test]
    fn selected_package_versions_filters_exact_version() {
        let toml_val: toml::Value = toml::from_str(
            r#"[package]
name = "tool"
description = "test"
license = "MIT"
maintainer = "test"

[[versions]]
version = "1.0.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/aaa111-tool-1.0.0"
nar_hash = "sha256:v1"
nar_size = 1
closure_size = 1
source_drv = ""
source_nar_hash = ""
references = []

[[versions]]
version = "2.0.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/bbb222-tool-2.0.0"
nar_hash = "sha256:v2"
nar_size = 2
closure_size = 2
source_drv = ""
source_nar_hash = ""
references = []
"#,
        )
        .unwrap();

        let selected = selected_package_versions(&toml_val, Some("1.0.0")).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(
            selected[0]
                .get("version")
                .and_then(|version| version.as_str()),
            Some("1.0.0")
        );
        assert!(selected_package_versions(&toml_val, Some("9.9.9")).is_err());

        let raw = package_toml_with_versions(&toml_val, &selected).unwrap();
        let rendered = toml::to_string_pretty(&raw).unwrap();
        assert!(rendered.contains("1.0.0"));
        assert!(!rendered.contains("2.0.0"));
    }

    #[test]
    fn latest_version_string_uses_semver_and_platform_filter() {
        let toml_val: toml::Value = toml::from_str(
            r#"[package]
name = "tool"
description = "test"
license = "MIT"
maintainer = "test"

[[versions]]
version = "1.9.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/aaa111-tool-1.9.0"
nar_hash = "sha256:v1"
nar_size = 1
closure_size = 1
source_drv = ""
source_nar_hash = ""
references = []

[[versions]]
version = "1.10.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/bbb222-tool-1.10.0"
nar_hash = "sha256:v2"
nar_size = 2
closure_size = 2
source_drv = ""
source_nar_hash = ""
references = []

[[versions]]
version = "3.0.0"

[versions.platforms.aarch64-linux]
store_path = "/nix/store/ccc333-tool-3.0.0"
nar_hash = "sha256:v3"
nar_size = 3
closure_size = 3
source_drv = ""
source_nar_hash = ""
references = []
"#,
        )
        .unwrap();

        assert_eq!(
            latest_version_string(&matching_package_versions(&toml_val, Some("x86_64-linux"))),
            Some("1.10.0".to_string())
        );
        assert_eq!(
            latest_version_string(&matching_package_versions(&toml_val, Some("aarch64-linux"))),
            Some("3.0.0".to_string())
        );
        assert!(matching_package_versions(&toml_val, Some("riscv64-linux")).is_empty());
    }

    #[test]
    fn cache_validation_entries_honor_package_and_platform_filters() {
        let tmp = TempDir::new().unwrap();
        let pkg_dir = tmp.path().join("packages").join("t");
        fs::create_dir_all(&pkg_dir).unwrap();
        fs::write(
            pkg_dir.join("tool.toml"),
            r#"[package]
name = "tool"
description = "test"
license = "MIT"
maintainer = "test"

[[versions]]
version = "1.0.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/aaa111-tool-1.0.0"
nar_hash = "sha256:x86"
nar_size = 1
closure_size = 1
references = []

[versions.platforms.aarch64-linux]
store_path = "/nix/store/bbb222-tool-1.0.0"
nar_hash = "sha256:arm"
nar_size = 1
closure_size = 1
references = []

[[versions.platforms.aarch64-linux.images]]
format = "raw"
store_path = "/nix/store/ccc333-tool-image-1.0.0"
nar_hash = "sha256:image"
nar_size = 1
"#,
        )
        .unwrap();

        let entries =
            collect_cache_validation_entries(tmp.path(), Some("tool"), Some("aarch64-linux"))
                .unwrap();
        assert_eq!(
            entries,
            vec![
                CacheValidationEntry {
                    name: "tool".into(),
                    platform: "aarch64-linux".into(),
                    store_path: "/nix/store/bbb222-tool-1.0.0".into(),
                    store_hash: "bbb222".into(),
                    nar_hashes: vec!["sha256:arm".into()],
                },
                CacheValidationEntry {
                    name: "tool".into(),
                    platform: "aarch64-linux".into(),
                    store_path: "/nix/store/ccc333-tool-image-1.0.0".into(),
                    store_hash: "ccc333".into(),
                    nar_hashes: vec!["sha256:image".into()],
                },
            ]
        );
        assert!(
            collect_cache_validation_entries(tmp.path(), Some("missing"), None)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn remove_missing_cache_entries_prunes_platforms_and_images() {
        let tmp = TempDir::new().unwrap();
        let pkg_dir = tmp.path().join("packages/t");
        fs::create_dir_all(&pkg_dir).unwrap();
        let toml_path = pkg_dir.join("tool.toml");
        fs::write(
            &toml_path,
            r#"[package]
name = "tool"
description = "test"
license = "MIT"
maintainer = "test"

[[versions]]
version = "1.0.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/aaa111-tool-1.0.0"
nar_hash = "sha256:x86"
nar_size = 1
closure_size = 1
references = []

[versions.platforms.aarch64-linux]
store_path = "/nix/store/bbb222-tool-1.0.0"
nar_hash = "sha256:arm"
nar_size = 1
closure_size = 1
references = []

[[versions.platforms.aarch64-linux.images]]
format = "raw"
store_path = "/nix/store/ccc333-tool-image-1.0.0"
nar_hash = "sha256:image"
nar_size = 1
"#,
        )
        .unwrap();

        let mut missing = std::collections::HashSet::new();
        missing.insert("/nix/store/ccc333-tool-image-1.0.0".to_string());
        assert_eq!(
            remove_missing_cache_entries(tmp.path(), &missing).unwrap(),
            1
        );
        let toml_val: toml::Value =
            toml::from_str(&fs::read_to_string(&toml_path).unwrap()).unwrap();
        let aarch64 = toml_val
            .get("versions")
            .and_then(|versions| versions.as_array())
            .and_then(|versions| versions.first())
            .and_then(|version| version.get("platforms"))
            .and_then(|platforms| platforms.get("aarch64-linux"))
            .unwrap();
        assert!(aarch64.get("images").is_none());

        missing.clear();
        missing.insert("/nix/store/bbb222-tool-1.0.0".to_string());
        assert_eq!(
            remove_missing_cache_entries(tmp.path(), &missing).unwrap(),
            1
        );
        let toml_val: toml::Value =
            toml::from_str(&fs::read_to_string(&toml_path).unwrap()).unwrap();
        let platforms = toml_val
            .get("versions")
            .and_then(|versions| versions.as_array())
            .and_then(|versions| versions.first())
            .and_then(|version| version.get("platforms"))
            .and_then(|platforms| platforms.as_table())
            .unwrap();
        assert!(platforms.contains_key("x86_64-linux"));
        assert!(!platforms.contains_key("aarch64-linux"));

        missing.clear();
        missing.insert("/nix/store/aaa111-tool-1.0.0".to_string());
        assert_eq!(
            remove_missing_cache_entries(tmp.path(), &missing).unwrap(),
            1
        );
        assert!(!toml_path.exists());
    }

    #[tokio::test]
    async fn cache_validation_entry_follows_narinfo_url() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 2048];
                let n = stream.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]);
                let narinfo = concat!(
                    "StorePath: /nix/store/abc123-tool-1.0.0\n",
                    "URL: nar/abc123-sha256-test.nar.zst\n",
                    "Compression: zstd\n",
                    "NarHash: sha256:test\n",
                    "NarSize: 1\n",
                );
                let response = if req.starts_with("GET /abc123.narinfo ") {
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        narinfo.len(),
                        narinfo,
                    )
                } else if req.starts_with("HEAD /nar/abc123-sha256-test.nar.zst ") {
                    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
                } else {
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_string()
                };
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let result = validate_cache_entry(
            &reqwest::Client::new(),
            &[CacheEntry {
                url: format!("http://{addr}"),
                priority: 100,
            }],
            CacheValidationEntry {
                name: "tool".into(),
                platform: "x86_64-linux".into(),
                store_path: "/nix/store/abc123-tool-1.0.0".into(),
                store_hash: "abc123".into(),
                nar_hashes: vec!["sha256:test".into()],
            },
        )
        .await;

        assert!(result.found, "{result:?}");
        server.await.unwrap();
    }

    #[test]
    fn format_size_values() {
        assert_eq!(format_size(500), "500 B");
        assert_eq!(format_size(2048), "2.0 KiB");
        assert_eq!(format_size(3_300_000), "3.1 MiB");
        assert_eq!(format_size(2_147_483_648), "2.0 GiB");
    }

    /// Initialize a git repository with one commit at `dir`.
    fn init_authoring_clone(dir: &Path) {
        fs::create_dir_all(dir).unwrap();
        testutil::git(dir, &["init"]);
        fs::write(dir.join("registry.toml"), "[registry]\n").unwrap();
        testutil::git(dir, &["add", "."]);
        testutil::git(dir, &["commit", "-m", "init"]);
    }

    #[test]
    fn local_registries_skips_configured_names() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("configured-reg")).unwrap();
        fs::create_dir_all(tmp.path().join("authored-reg/packages/t")).unwrap();
        fs::write(
            tmp.path().join("authored-reg/packages/t/tool-1.0.0.toml"),
            "",
        )
        .unwrap();

        let local = local_registries(tmp.path(), &["configured-reg"]);
        assert_eq!(local.len(), 1);
        assert_eq!(local[0].name, "authored-reg");
        assert_eq!(local[0].packages, 1);
        assert_eq!(local[0].origin, None);
    }

    #[test]
    fn local_registries_reports_origin() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("authored-reg");
        init_authoring_clone(&dir);
        testutil::git(
            &dir,
            &["remote", "add", "origin", "https://cdn.example.com/reg"],
        );

        let local = local_registries(tmp.path(), &[]);
        assert_eq!(local.len(), 1);
        assert_eq!(
            local[0].origin.as_deref(),
            Some("https://cdn.example.com/reg")
        );
    }

    #[test]
    fn local_registries_missing_dir_is_empty() {
        let tmp = TempDir::new().unwrap();
        assert!(local_registries(&tmp.path().join("absent"), &[]).is_empty());
    }

    #[test]
    fn authoring_clone_precious_ignores_plain_dirs() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("consumer-reg");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("registry.toml"), "[registry]\n").unwrap();

        assert!(authoring_clone_precious(&dir).unwrap().is_none());
        assert!(
            authoring_clone_precious(&tmp.path().join("absent"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn authoring_clone_precious_without_remote() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("authored-reg");
        init_authoring_clone(&dir);

        let reason = authoring_clone_precious(&dir).unwrap();
        assert!(
            reason.as_deref().is_some_and(|r| r.contains("no remote")),
            "got: {reason:?}"
        );
    }

    #[test]
    fn authoring_clone_precious_uncommitted_changes() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("authored-reg");
        init_authoring_clone(&dir);
        fs::write(dir.join("registry.toml"), "[registry]\nname = \"x\"\n").unwrap();

        let reason = authoring_clone_precious(&dir).unwrap();
        assert_eq!(reason.as_deref(), Some("uncommitted changes"));
    }

    #[test]
    fn authoring_clone_precious_unpushed_and_pushed() {
        let tmp = TempDir::new().unwrap();
        let origin = tmp.path().join("origin.git");
        fs::create_dir_all(&origin).unwrap();
        testutil::git(&origin, &["init", "--bare"]);

        let dir = tmp.path().join("authored-reg");
        init_authoring_clone(&dir);
        testutil::git(&dir, &["remote", "add", "origin", origin.to_str().unwrap()]);

        let reason = authoring_clone_precious(&dir).unwrap();
        assert!(
            reason
                .as_deref()
                .is_some_and(|r| r.contains("not pushed to any remote")),
            "got: {reason:?}"
        );

        let branch = testutil::git(&dir, &["branch", "--show-current"]);
        testutil::git(&dir, &["push", "origin", &branch]);
        assert!(authoring_clone_precious(&dir).unwrap().is_none());
    }
}
