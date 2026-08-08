//! The configuration manifest materializer for on-host configuration
//! evaluation.
//!
//! [`super::stock`] and [`super::run_fixpoint`] *produce* an
//! `aos.config-manifest/v1` document (`/run/aos/manifest.json`); this module
//! *applies* it, rendering the manifest's `/etc` tree into a per-generation
//! lower directory so a generation's `/etc` reflects the operator `host.nix`.
//! The manifest is the sole source of a generation's per-host `/etc`.
//!
//! # The manifest (`aos.config-manifest/v1`)
//!
//! The subset this materializer consumes — the `/etc` tree and the job scripts
//! its unit bodies reference:
//!
//! ```json
//! {
//!   "schema": "aos.config-manifest/v1",
//!   "etc": {
//!     "apm/registries.d/andyl.toml": { "kind": "text", "mode": "0644", "text": "…" },
//!     "localtime": { "kind": "store-symlink", "target": "/nix/store/…/UTC" },
//!     "systemd/system/getty.target.wants/getty@tty1.service":
//!         { "kind": "symlink", "target": "../getty@tty1.service" }
//!   },
//!   "jobScripts": {
//!     "aos-attest.service:ExecStart.0": { "mode": "0755", "name": "…", "text": "#!/…/bash\n…" }
//!   }
//! }
//! ```
//!
//! Each `etc` entry is written under a caller-supplied root:
//! - `text`  — a regular file with the given octal `mode`. Any
//!   `#aos-jobscript:<key>#` placeholder in the body (from the F2-A job-script
//!   inversion) is rewritten to the job script's materialized absolute path.
//! - `symlink` / `store-symlink` — a symlink to `target` (relative install
//!   symlinks and absolute `/nix/store` links respectively; both are created
//!   verbatim with `symlink(2)`).
//!
//! Every job script is written under `<root>/aos-job-scripts/<key>` (mode
//! `0755`), and the placeholder rewrite points unit `Exec*=` lines at
//! `<job_scripts_runtime_dir>/<key>` — the path that directory has once the
//! lower is mounted as `/etc`.
//!
//! `users`, `presets`, and `units` are carried by the manifest too, but the
//! `/etc` materialization here consumes only `etc` + `jobScripts`; the others
//! are applied by their own reconcilers (users via the passwd path, presets are
//! already `etc` entries under `systemd/system-preset/`).

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use rustix::fd::OwnedFd;
use rustix::fs::{AtFlags, Mode, OFlags, fchmod, mkdirat, openat, symlinkat, unlinkat};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::runtime::{RuntimePackageOrigin, RuntimePackagePin};
use crate::types::ModuleAbiCompat;

/// The runtime directory a materialized job script resolves to once the
/// per-generation lower is mounted at `/etc`. Unit `Exec*=` placeholders are
/// rewritten to `<this>/<key>`.
pub const DEFAULT_JOB_SCRIPTS_RUNTIME_DIR: &str = "/etc/aos-job-scripts";

/// The subdirectory (relative to the materialization root) that job scripts are
/// written into. Kept in lockstep with [`DEFAULT_JOB_SCRIPTS_RUNTIME_DIR`]'s
/// final path component.
const JOB_SCRIPTS_SUBDIR: &str = "aos-job-scripts";

/// The directory atomically published inside a configuration generation.
pub const GENERATION_LOWER_DIR: &str = "config-lower";

/// The EROFS image mounted as the configuration layer of `/etc`.
pub const GENERATION_LOWER_IMAGE: &str = "etc.erofs";

const GENERATION_LOWER_TREE: &str = "etc-tree";
const GENERATION_LOWER_META: &str = "metadata.json";
const GENERATION_LOWER_SCHEMA: &str = "aos.config-lower/v1";
const CONFIG_EROFS_UUID: &str = "bdfb6fc9-0011-4000-8000-000000000001";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerationLowerMetadata {
    schema: String,
    #[serde(rename = "manifestHash")]
    manifest_hash: String,
    #[serde(rename = "imageSha256")]
    image_sha256: String,
    #[serde(rename = "treeSha256")]
    tree_sha256: String,
}

/// The complete `aos.config-manifest/v1` shared Rust/Nix data contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigManifest {
    /// The schema tag; must be [`Self::SCHEMA`].
    pub schema: String,
    /// The `/etc` tree keyed by target path (relative to `/etc`).
    pub etc: BTreeMap<String, EtcEntry>,
    /// Per-unit activation actions.
    pub units: BTreeMap<String, UnitAction>,
    /// Job-script bodies keyed by `<unit>:<slot>.<index>`.
    #[serde(rename = "jobScripts", default)]
    pub job_scripts: BTreeMap<String, JobScript>,
    /// Users the generation ensures exist.
    #[serde(default)]
    pub users: Vec<ManifestUser>,
    /// systemd preset decisions.
    #[serde(default)]
    pub presets: Vec<PresetEntry>,
    /// Sorted store closures pinned by the generation.
    #[serde(rename = "storePaths")]
    pub store_paths: Vec<String>,
    /// Shared module ABI used for evaluation.
    pub module_abi: u32,
    /// The five deterministic evaluator inputs.
    pub inputs: ManifestInputs,
    /// Sorted package names in the converged fixpoint.
    pub packages: Vec<String>,
    /// Exact authenticated runtime output and closure pins by package.
    #[serde(rename = "packageOutputs")]
    pub package_outputs: BTreeMap<String, RuntimePackagePin>,
    /// Package dependency graph used by activation planning.
    pub graph: ManifestGraph,
    /// Per-package projected non-secret configuration.
    pub config: BTreeMap<String, serde_json::Value>,
    /// Per-package credential handles, never secret values.
    pub credentials: BTreeMap<String, serde_json::Value>,
    /// Eval-produced exact config bytes and unit actions for migrated expose
    /// companions. Legacy packages are intentionally absent and render from
    /// signed flat metadata at staging time.
    #[serde(
        rename = "configProjections",
        default,
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub config_projections: BTreeMap<String, ProjectedPackageConfig>,
    /// Ownership index used for fail-closed degraded projection.
    pub ownership: ManifestOwnership,
}

impl ConfigManifest {
    /// The only schema tag this materializer understands.
    pub const SCHEMA: &'static str = "aos.config-manifest/v1";

    /// Validates invariants that Serde's structural checks cannot express.
    ///
    /// # Errors
    ///
    /// Returns an error for a wrong schema, malformed paths or modes, duplicate
    /// ordered records, inconsistent ABI/input data, or an invalid graph.
    pub fn validate(&self) -> Result<()> {
        if self.schema != Self::SCHEMA {
            bail!(
                "unsupported config-manifest schema {:?} (expected {:?})",
                self.schema,
                Self::SCHEMA
            );
        }
        if self.module_abi != self.inputs.base_lib.module_abi {
            bail!("manifest module_abi does not match inputs.base_lib.module_abi");
        }
        for hash in [
            &self.inputs.base_lib.abi_hash,
            &self.inputs.config_modules.closure_hash,
            &self.inputs.host_nix.content_hash,
            &self.inputs.instance_facts.facts_hash,
        ] {
            validate_content_sha256(hash)?;
        }
        validate_store_identity_hash(&self.inputs.evaluator.store_hash)?;
        if self.inputs.config_modules.count != self.inputs.config_modules.store_paths.len() {
            bail!("config_modules count does not match store_paths");
        }
        if self.inputs.config_modules.count != self.inputs.config_modules.nar_hashes.len() {
            bail!("config_modules count does not match nar_hashes");
        }
        if self.inputs.config_modules.count != self.inputs.config_modules.package_names.len() {
            bail!("config_modules count does not match package_names");
        }
        if !self.inputs.config_modules.origins.is_empty()
            && self.inputs.config_modules.count != self.inputs.config_modules.origins.len()
        {
            bail!("config_modules count does not match origins");
        }
        if self
            .inputs
            .config_modules
            .origins
            .iter()
            .any(|origin| origin != "registry" && origin != "image")
        {
            bail!("config_modules contains an unsupported trust origin");
        }
        // Manifests written before origin tracking had neither an origin list
        // nor signed-release identity. Preserve their read/migration path, but
        // require complete identity for every newly explicit registry origin.
        let has_registry_modules = self
            .inputs
            .config_modules
            .origins
            .iter()
            .any(|origin| origin == "registry");
        let release_identity = [
            self.inputs.config_modules.registry.as_ref(),
            self.inputs.config_modules.release_tag.as_ref(),
            self.inputs.config_modules.tag_signer_key.as_ref(),
            self.inputs.config_modules.realization.as_ref(),
        ];
        if has_registry_modules && release_identity.iter().any(|field| field.is_none()) {
            bail!("registry config modules require complete signed-release identity");
        }
        if !self.inputs.config_modules.origins.is_empty()
            && !has_registry_modules
            && release_identity.iter().any(|field| field.is_some())
        {
            bail!("image-only config modules must not claim signed-release identity");
        }
        if self.inputs.config_modules.count != self.inputs.config_modules.module_abi_compat.len() {
            bail!("config_modules count does not match module_abi_compat");
        }
        if !self.inputs.config_modules.authorizations.is_empty()
            && self.inputs.config_modules.count != self.inputs.config_modules.authorizations.len()
        {
            bail!("config_modules count does not match authorizations");
        }
        for compat in &self.inputs.config_modules.module_abi_compat {
            if compat.min > compat.max {
                bail!("config_modules contains an inverted module ABI range");
            }
        }
        let mut seen_config_modules = BTreeSet::new();
        if self
            .inputs
            .config_modules
            .store_paths
            .iter()
            .any(|path| !seen_config_modules.insert(path))
        {
            bail!("config_modules.store_paths contains a duplicate path");
        }
        if self
            .inputs
            .config_modules
            .store_paths
            .iter()
            .any(|path| validate_canonical_store_path(path).is_err())
        {
            bail!("config_modules.store_paths contains a noncanonical store path");
        }
        for package in &self.inputs.config_modules.package_names {
            crate::types::validate_package_name(package)
                .context("config_modules.package_names contains an invalid package")?;
        }
        let mut closure_members = self
            .inputs
            .config_modules
            .store_paths
            .iter()
            .zip(&self.inputs.config_modules.nar_hashes)
            .map(|(path, nar_hash)| {
                let canonical = crate::registry::store::NarBytes::from_hash(nar_hash, 0)
                    .context("config_modules.nar_hashes contains an invalid NAR hash")?
                    .nar_hash();
                if canonical != *nar_hash {
                    bail!("config_modules.nar_hashes contains a noncanonical NAR hash");
                }
                Ok(serde_json::json!([path, nar_hash]))
            })
            .collect::<Result<Vec<_>>>()?;
        closure_members.sort_by(|left, right| {
            left[0]
                .as_str()
                .unwrap_or_default()
                .cmp(right[0].as_str().unwrap_or_default())
        });
        let expected_closure =
            crate::graph_compile::reproject::hash_cjson(&serde_json::Value::Array(closure_members));
        if self.inputs.config_modules.closure_hash != expected_closure {
            bail!("config_modules closure_hash does not match store path/NAR hash set");
        }
        for (field, path) in [
            ("host_nix.store_path", &self.inputs.host_nix.store_path),
            ("base_lib.store_path", &self.inputs.base_lib.store_path),
            ("evaluator.store_path", &self.inputs.evaluator.store_path),
            (
                "instance_facts.store_path",
                &self.inputs.instance_facts.store_path,
            ),
        ] {
            validate_canonical_store_path(path)
                .with_context(|| format!("manifest inputs.{field} is not canonical"))?;
        }
        let mut prior = None;
        for path in &self.store_paths {
            validate_canonical_store_path(path)?;
            if prior.is_some_and(|previous: &String| previous >= path) {
                bail!("manifest storePaths must be sorted and deduplicated");
            }
            prior = Some(path);
        }
        for (path, entry) in &self.etc {
            validate_relative_path(path, "etc")?;
            if path == JOB_SCRIPTS_SUBDIR || path.starts_with("aos-job-scripts/") {
                bail!("manifest etc path {path:?} uses the reserved job-script subtree");
            }
            match entry {
                EtcEntry::Text { mode, .. } => validate_mode(mode)?,
                EtcEntry::Symlink { target } => validate_etc_symlink(path, target)?,
                EtcEntry::StoreSymlink { target } => {
                    let root = store_path_root(target).ok_or_else(|| {
                        anyhow::anyhow!("invalid store symlink target {target:?}")
                    })?;
                    if !self.store_paths.iter().any(|path| path == root) {
                        bail!("store symlink target {target:?} is not pinned by storePaths");
                    }
                }
                EtcEntry::CertificateBundle { mode, parts } => {
                    validate_mode(mode)?;
                    if parts.is_empty() {
                        bail!("manifest certificate bundle {path:?} has no inputs");
                    }
                    for (index, part) in parts.iter().enumerate() {
                        match part {
                            CertificateBundlePart::Text { text } => {
                                validate_certificate_pem(text.as_bytes()).with_context(|| {
                                    format!(
                                        "validating inline certificate bundle input etc.{path}.parts[{index}]"
                                    )
                                })?;
                            }
                            CertificateBundlePart::StoreFile { path: source } => {
                                let root = store_path_root(source).ok_or_else(|| {
                                    anyhow::anyhow!(
                                        "invalid certificate bundle store file {source:?}"
                                    )
                                })?;
                                if !self.store_paths.iter().any(|path| path == root) {
                                    bail!(
                                        "certificate bundle store file {source:?} is not pinned by storePaths"
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        let pinned_store_paths: BTreeSet<&str> =
            self.store_paths.iter().map(String::as_str).collect();
        for (path, entry) in &self.etc {
            let artifact_owner = self.ownership.etc.get(path).map(String::as_str);
            match entry {
                EtcEntry::Text { text, .. } => validate_emitted_store_paths(
                    text,
                    &pinned_store_paths,
                    &self.ownership.store_paths,
                    artifact_owner,
                    &self.graph,
                    &format!("etc.{path}.text"),
                )?,
                EtcEntry::StoreSymlink { target } => validate_emitted_store_paths(
                    target,
                    &pinned_store_paths,
                    &self.ownership.store_paths,
                    artifact_owner,
                    &self.graph,
                    &format!("etc.{path}.target"),
                )?,
                EtcEntry::CertificateBundle { parts, .. } => {
                    for (index, part) in parts.iter().enumerate() {
                        match part {
                            CertificateBundlePart::Text { text } => validate_emitted_store_paths(
                                text,
                                &pinned_store_paths,
                                &self.ownership.store_paths,
                                artifact_owner,
                                &self.graph,
                                &format!("etc.{path}.parts[{index}].text"),
                            )?,
                            CertificateBundlePart::StoreFile { path: source } => {
                                validate_emitted_store_paths(
                                    source,
                                    &pinned_store_paths,
                                    &self.ownership.store_paths,
                                    artifact_owner,
                                    &self.graph,
                                    &format!("etc.{path}.parts[{index}].path"),
                                )?;
                            }
                        }
                    }
                }
                EtcEntry::Symlink { .. } => {}
            }
        }
        for (key, script) in &self.job_scripts {
            validate_job_script_key(key)?;
            validate_mode(&script.mode)?;
            validate_emitted_store_paths(
                &script.text,
                &pinned_store_paths,
                &self.ownership.store_paths,
                self.ownership.job_scripts.get(key).map(String::as_str),
                &self.graph,
                &format!("jobScripts.{key}.text"),
            )?;
        }
        for user in &self.users {
            validate_emitted_store_paths(
                &user.home,
                &pinned_store_paths,
                &self.ownership.store_paths,
                self.ownership.users.get(&user.name).map(String::as_str),
                &self.graph,
                &format!("users.{}.home", user.name),
            )?;
            validate_emitted_store_paths(
                &user.shell,
                &pinned_store_paths,
                &self.ownership.store_paths,
                self.ownership.users.get(&user.name).map(String::as_str),
                &self.graph,
                &format!("users.{}.shell", user.name),
            )?;
        }
        for (package, config) in &self.config {
            validate_json_store_paths(
                config,
                &pinned_store_paths,
                &self.ownership.store_paths,
                Some(package),
                &self.graph,
                &format!("config.{package}"),
            )?;
        }
        for (package, credentials) in &self.credentials {
            validate_secret_refs(package, credentials, self.package_outputs.get(package))?;
            validate_json_store_paths(
                credentials,
                &pinned_store_paths,
                &self.ownership.store_paths,
                Some(package),
                &self.graph,
                &format!("credentials.{package}"),
            )?;
        }
        self.validate_config_projections()?;
        for path in self.etc.keys() {
            let mut ancestor = path.as_str();
            while let Some((parent, _)) = ancestor.rsplit_once('/') {
                if self.etc.contains_key(parent) {
                    bail!("manifest etc paths conflict: {parent:?} is an ancestor of {path:?}");
                }
                ancestor = parent;
            }
        }
        let mut users = std::collections::BTreeSet::new();
        for user in &self.users {
            if !users.insert(&user.name) {
                bail!("duplicate manifest user {:?}", user.name);
            }
        }
        validate_sorted_unique(&self.packages, "packages")?;
        let package_set: std::collections::BTreeSet<&str> =
            self.packages.iter().map(String::as_str).collect();
        if let Some(package) = self
            .config
            .keys()
            .chain(self.credentials.keys())
            .find(|package| !package_set.contains(package.as_str()))
        {
            bail!("manifest package-owned state names absent package {package:?}");
        }
        let pinned_packages: BTreeSet<&str> =
            self.package_outputs.keys().map(String::as_str).collect();
        if pinned_packages != package_set {
            bail!("manifest packageOutputs must exactly cover packages");
        }
        for (package, pin) in &self.package_outputs {
            if !self.store_paths.contains(&pin.store_path) {
                bail!("packageOutputs.{package}.store_path is absent from manifest storePaths");
            }
            if !matches!(
                self.ownership.store_paths.get(&pin.store_path),
                Some(owner)
                    if owner == package
                        || (owner == "@base"
                            && pin.origin == RuntimePackageOrigin::Image)
            ) {
                bail!("packageOutputs.{package}.store_path is not owned by that package");
            }
            validate_runtime_pin(package, pin)?;
            if let Some(artifact) = &pin.expose_artifact {
                if !self.store_paths.contains(&artifact.store_path) {
                    bail!(
                        "packageOutputs.{package}.expose_artifact.store_path is absent from manifest storePaths"
                    );
                }
                if !matches!(
                    self.ownership.store_paths.get(&artifact.store_path),
                    Some(owner) if owner == package || owner == "@base"
                ) {
                    bail!(
                        "packageOutputs.{package}.expose_artifact.store_path has invalid ownership"
                    );
                }
            }
        }
        for (package, deps) in &self.graph.edges {
            if !package_set.contains(package.as_str()) {
                bail!("graph node {package:?} is absent from packages");
            }
            validate_sorted_unique(deps, "graph dependency list")?;
            if deps.iter().any(|dep| !package_set.contains(dep.as_str())) {
                bail!("graph edge from {package:?} names an absent package");
            }
        }
        validate_owner_keys(self.etc.keys(), &self.ownership.etc, "etc", &package_set)?;
        validate_owner_keys(
            self.units.keys(),
            &self.ownership.units,
            "units",
            &package_set,
        )?;
        validate_owner_keys(
            self.job_scripts.keys(),
            &self.ownership.job_scripts,
            "jobScripts",
            &package_set,
        )?;
        let user_names: BTreeSet<String> =
            self.users.iter().map(|user| user.name.clone()).collect();
        validate_owner_keys(
            user_names.iter(),
            &self.ownership.users,
            "users",
            &package_set,
        )?;
        let preset_keys: BTreeSet<String> = self
            .presets
            .iter()
            .map(|preset| format!("{}:{}", preset.unit, preset.source))
            .collect();
        if preset_keys.len() != self.presets.len() {
            bail!("duplicate manifest preset unit/source identity");
        }
        validate_owner_keys(
            preset_keys.iter(),
            &self.ownership.presets,
            "presets",
            &package_set,
        )?;
        validate_owner_keys(
            self.store_paths.iter(),
            &self.ownership.store_paths,
            "storePaths",
            &package_set,
        )?;
        Ok(())
    }

    fn validate_config_projections(&self) -> Result<()> {
        let expected = self
            .package_outputs
            .iter()
            .filter_map(|(package, pin)| pin.config_projection.as_ref().map(|_| package.as_str()))
            .collect::<BTreeSet<_>>();
        let actual = self
            .config_projections
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if expected != actual {
            bail!("manifest configProjections must exactly cover migrated expose packages");
        }
        for (package, projection) in &self.config_projections {
            let pin = self.package_outputs[package]
                .config_projection
                .as_ref()
                .context("migrated expose package lost its authenticated projection pin")?;
            let module_index = self
                .inputs
                .config_modules
                .package_names
                .iter()
                .position(|name| name == package)
                .with_context(|| {
                    format!("config projection for {package:?} has no evaluated config module")
                })?;
            if self.inputs.config_modules.store_paths[module_index] != pin.config_output
                || self.inputs.config_modules.nar_hashes[module_index] != pin.config_nar_hash
            {
                bail!(
                    "config projection for {package:?} disagrees with authenticated config-module input"
                );
            }
            let expected_schema_hash = expose_config_schema_hash(&pin.config)?;
            if projection.schema != ProjectedPackageConfig::SCHEMA
                || projection.schema_hash != expected_schema_hash
            {
                bail!("config projection for {package:?} has a missing or tampered schema binding");
            }
            if projection.artifacts.len() != pin.config.artifacts.len() {
                bail!("config projection for {package:?} does not cover every signed artifact");
            }
            let desired =
                desired_package_from_json(self.config.get(package).with_context(|| {
                    format!("config projection for {package:?} has no desired config")
                })?)?;
            let expected_render =
                crate::render_package_config(package, &pin.config.artifacts, Some(&desired))
                    .with_context(|| format!("re-rendering config projection for {package:?}"))?;
            for (rendered, (signed, expected_bytes)) in
                projection.artifacts.iter().zip(expected_render)
            {
                if rendered.path != signed.path || rendered.mode != "0644" {
                    bail!("config projection artifact metadata disagrees for {package:?}");
                }
                if rendered.text.as_bytes() != expected_bytes.as_slice() {
                    bail!(
                        "config projection artifact bytes disagree with desired config for {package:?}"
                    );
                }
                let expected_hash = format!(
                    "sha256:{}",
                    hex::encode(Sha256::digest(rendered.text.as_bytes()))
                );
                if rendered.sha256 != expected_hash {
                    bail!("config projection artifact bytes are tampered for {package:?}");
                }
            }
            let expected_actions = projected_unit_actions(&pin.config.artifacts);
            if projection.units != expected_actions {
                bail!("config projection unit actions disagree with signed policy for {package:?}");
            }
        }
        Ok(())
    }
}

/// Validates that evaluated credentials contain references, never plaintext.
fn validate_secret_refs(
    package: &str,
    value: &serde_json::Value,
    package_pin: Option<&RuntimePackagePin>,
) -> Result<()> {
    let handles = value
        .as_object()
        .with_context(|| format!("credentials.{package} must be an object"))?;
    for (name, value) in handles {
        let reference: crate::secret_ref::SecretRef = serde_json::from_value(value.clone())
            .with_context(|| {
                format!(
                    "credentials.{package}.{name} must contain only name, source, encrypted, units, ref, and package-authored ciphertext"
                )
            })?;
        crate::types::validate_credential_name(name)
            .with_context(|| format!("invalid credential handle credentials.{package}.{name}"))?;
        if reference.name != *name {
            bail!("credentials.{package}.{name} changes its credential name");
        }
        reference.validate_reference().with_context(|| {
            format!("invalid credential reference credentials.{package}.{name}")
        })?;
        if let Some(ciphertext) = reference.ciphertext.as_deref() {
            let signed = package_pin
                .and_then(|pin| {
                    pin.config_projection
                        .as_ref()
                        .map(|projection| &projection.config)
                        .or(pin.legacy_config.as_ref())
                })
                .and_then(|config| {
                    config
                        .credentials
                        .iter()
                        .find(|credential| credential.name == *name)
                })
                .and_then(|credential| credential.ciphertext.as_deref());
            if signed != Some(ciphertext) {
                bail!(
                    "credentials.{package}.{name} contains ciphertext that was not package-authored"
                );
            }
        }
    }
    Ok(())
}

/// Converts one package's JSON desired-config block into the flat renderer's
/// TOML value shape, rejecting structural mismatches and JSON nulls.
fn desired_package_from_json(
    value: &serde_json::Value,
) -> Result<BTreeMap<String, BTreeMap<String, toml::Value>>> {
    let artifacts = value
        .as_object()
        .context("desired package config must be an object")?;
    artifacts
        .iter()
        .map(|(artifact, fields)| {
            let fields = fields.as_object().with_context(|| {
                format!("desired config artifact {artifact:?} must be an object")
            })?;
            let fields = fields
                .iter()
                .map(|(field, value)| {
                    let value = serde_json::from_value::<toml::Value>(value.clone())
                        .with_context(|| format!("converting desired config field {field:?}"))?;
                    Ok((field.clone(), value))
                })
                .collect::<Result<BTreeMap<_, _>>>()?;
            Ok((artifact.clone(), fields))
        })
        .collect()
}

/// Exact eval-produced config projection consumed by `render-one`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectedPackageConfig {
    /// Projection schema discriminator.
    pub schema: String,
    /// Canonical hash of the authenticated signed config schema.
    pub schema_hash: String,
    /// Exact rendered UTF-8 artifact bytes.
    pub artifacts: Vec<ProjectedConfigArtifact>,
    /// Signed reload/restart actions, with restart dominating reload.
    pub units: BTreeMap<String, UnitReconcileAction>,
}

impl ProjectedPackageConfig {
    /// Current projection schema.
    pub const SCHEMA: &'static str = "aos.package-config-projection/v1";
}

/// One exact rendered artifact in a migrated package projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectedConfigArtifact {
    /// Final absolute path beneath `/etc`.
    pub path: String,
    /// Exact UTF-8 bytes represented as a JSON string.
    pub text: String,
    /// Final octal file mode.
    pub mode: String,
    /// SHA-256 binding of `text` bytes.
    pub sha256: String,
}

/// Derives deterministic unit actions from signed artifact policies.
pub(crate) fn projected_unit_actions(
    artifacts: &[crate::types::ConfigArtifactMeta],
) -> BTreeMap<String, UnitReconcileAction> {
    use crate::types::ConfigReloadPolicy;

    let mut units = BTreeMap::new();
    for artifact in artifacts {
        let action = match artifact.reload {
            ConfigReloadPolicy::Restart => UnitReconcileAction::Restart,
            ConfigReloadPolicy::Reload => UnitReconcileAction::Reload,
            ConfigReloadPolicy::None => UnitReconcileAction::None,
        };
        for unit in &artifact.units {
            units
                .entry(unit.clone())
                .and_modify(|current| {
                    if matches!(action, UnitReconcileAction::Restart)
                        || matches!(current, UnitReconcileAction::None)
                    {
                        *current = action;
                    }
                })
                .or_insert(action);
        }
    }
    units
}

/// Hashes the fully normalized schema bytes emitted by the Nix expose
/// renderer. Unlike ordinary Serde output, this retains explicit empty/default
/// fields because those bytes are part of the generated companion binding.
pub(crate) fn expose_config_schema_hash(config: &crate::types::ExposeConfigMeta) -> Result<String> {
    let artifacts = config
        .artifacts
        .iter()
        .map(|artifact| {
            serde_json::json!({
                "name": artifact.name,
                "path": artifact.path,
                "format": artifact.format,
                "required": artifact.required,
                "optional": artifact.optional,
                "units": artifact.units,
                "reload": artifact.reload,
            })
        })
        .collect::<Vec<_>>();
    let credentials = config
        .credentials
        .iter()
        .map(|credential| -> Result<serde_json::Value> {
            let mut value = serde_json::json!({
                "name": credential.name,
                "units": credential.units,
                "encrypted": credential.encrypted,
            });
            let object = value
                .as_object_mut()
                .context("normalized credential schema is not an object")?;
            if let Some(source) = &credential.source {
                object.insert("source".into(), serde_json::Value::String(source.clone()));
            }
            if let Some(ciphertext) = &credential.ciphertext {
                object.insert(
                    "ciphertext".into(),
                    serde_json::Value::String(ciphertext.clone()),
                );
            }
            Ok(value)
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(crate::graph_compile::reproject::hash_cjson(
        &serde_json::json!({
            "artifacts": artifacts,
            "credentials": credentials,
        }),
    ))
}

fn validate_runtime_pin(package: &str, pin: &RuntimePackagePin) -> Result<()> {
    match (&pin.expose, &pin.expose_artifact) {
        (Some(expose), Some(artifact)) => {
            crate::types::validate_expose_meta_for_package(package, expose)
                .with_context(|| format!("validating packageOutputs.{package}.expose"))?;
            crate::types::validate_expose_artifact_meta(artifact)
                .with_context(|| format!("validating packageOutputs.{package}.expose_artifact"))?;
        }
        (None, None) => {}
        _ => bail!("packageOutputs.{package} must carry expose metadata and its artifact together"),
    }
    if pin.config_projection.is_some() && pin.legacy_config.is_some() {
        bail!("packageOutputs.{package} must not carry both migrated and legacy config schemas");
    }
    if let Some(projection) = &pin.config_projection {
        validate_canonical_store_path(&projection.config_output).with_context(|| {
            format!("validating packageOutputs.{package}.config_projection.config_output")
        })?;
        let canonical = crate::registry::store::NarBytes::from_hash(&projection.config_nar_hash, 0)
            .with_context(|| {
                format!("validating packageOutputs.{package}.config_projection.config_nar_hash")
            })?
            .nar_hash();
        if canonical != projection.config_nar_hash {
            bail!("packageOutputs.{package}.config_projection.config_nar_hash is not canonical");
        }
        crate::types::validate_expose_config_meta(&projection.config).with_context(|| {
            format!("validating packageOutputs.{package}.config_projection.config")
        })?;
    }
    if let Some(legacy) = &pin.legacy_config {
        crate::types::validate_expose_config_meta(legacy)
            .with_context(|| format!("validating packageOutputs.{package}.legacy_config"))?;
    }
    let root_hash = pin
        .store_path
        .strip_prefix("/nix/store/")
        .and_then(|suffix| suffix.split_once('-').map(|(hash, _)| hash))
        .filter(|hash| !hash.is_empty())
        .with_context(|| {
            format!("packageOutputs.{package}.store_path is not a named Nix store path")
        })?;
    if pin.closure.is_empty() {
        bail!("packageOutputs.{package}.closure must not be empty");
    }
    let mut previous = None;
    let mut includes_root = false;
    for member in &pin.closure {
        if previous.is_some_and(|prior: &String| prior >= &member.store_path_hash) {
            bail!(
                "packageOutputs.{package}.closure must be sorted and deduplicated by store_path_hash"
            );
        }
        previous = Some(&member.store_path_hash);
        includes_root |= member.store_path_hash == root_hash;
        if let Some(path) = member.store_path.as_deref() {
            let member_hash = path
                .strip_prefix("/nix/store/")
                .and_then(|suffix| suffix.split_once('-').map(|(hash, _)| hash))
                .filter(|hash| !hash.is_empty())
                .with_context(|| {
                    format!(
                        "packageOutputs.{package}.closure member path is not a named Nix store path"
                    )
                })?;
            if member_hash != member.store_path_hash {
                bail!(
                    "packageOutputs.{package}.closure member path disagrees with store_path_hash"
                );
            }
        }
        if member.realisations.is_empty() {
            bail!("packageOutputs.{package}.closure member has no authenticated realisation");
        }
        if member
            .realisations
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            bail!("packageOutputs.{package}.closure realisations must be sorted and deduplicated");
        }
        for realisation in &member.realisations {
            if !realisation.nar_hash.starts_with("sha256:") || realisation.nar_size == 0 {
                bail!("packageOutputs.{package}.closure contains an invalid NAR realisation");
            }
        }
    }
    if !includes_root {
        bail!("packageOutputs.{package}.closure omits its runtime output root");
    }
    if let Some(artifact) = &pin.expose_artifact {
        let artifact_hash = crate::registry::store_path_hash(&artifact.store_path);
        let Some(member) = pin
            .closure
            .iter()
            .find(|member| member.store_path_hash == artifact_hash)
        else {
            bail!("packageOutputs.{package}.closure omits its expose artifact root");
        };
        if member.store_path.as_deref() != Some(artifact.store_path.as_str()) {
            bail!(
                "packageOutputs.{package}.expose artifact root is not a named fetchable closure member"
            );
        }
        let expected =
            crate::registry::store::NarBytes::from_hash(&artifact.nar_hash, artifact.nar_size)
                .with_context(|| {
                    format!("validating packageOutputs.{package}.expose_artifact NAR identity")
                })?;
        if !member.realisations.iter().any(|realisation| {
            realisation.nar_hash == expected.nar_hash() && realisation.nar_size == expected.size
        }) {
            bail!(
                "packageOutputs.{package}.expose artifact disagrees with its authenticated closure"
            );
        }
    }
    Ok(())
}

/// One `/etc` entry, discriminated by its `kind` tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "kebab-case")]
pub enum EtcEntry {
    /// Inline file content written with an explicit octal mode.
    Text {
        /// The file body. `#aos-jobscript:<key>#` placeholders are rewritten.
        text: String,
        /// The octal mode string, e.g. `"0644"`.
        mode: String,
    },
    /// A symlink whose `target` is a relative install-symlink path
    /// (e.g. `../getty@tty1.service`).
    Symlink {
        /// The verbatim symlink target.
        target: String,
    },
    /// A symlink whose `target` is an absolute `/nix/store` path.
    StoreSymlink {
        /// The verbatim symlink target.
        target: String,
    },
    /// A certificate-only PEM stream assembled from ordered pure-data and
    /// authenticated store-file inputs at generation materialization time.
    CertificateBundle {
        /// Ordered inputs concatenated byte-for-byte.
        parts: Vec<CertificateBundlePart>,
        /// The octal mode string, e.g. `"0644"`.
        mode: String,
    },
}

/// One ordered input to a runtime-materialized certificate bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "kebab-case")]
pub enum CertificateBundlePart {
    /// Certificate-only PEM bytes carried directly in the manifest.
    Text {
        /// Exact bytes represented as UTF-8 text.
        text: String,
    },
    /// Certificate-only PEM bytes read from an authenticated, pinned store
    /// path when the generation is materialized.
    StoreFile {
        /// Absolute file path beneath a pinned `/nix/store` root.
        path: String,
    },
}

/// A job-script body written to `<root>/aos-job-scripts/<key>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobScript {
    /// The script body (including its `#!` interpreter line).
    pub text: String,
    /// The octal mode string, e.g. `"0755"`.
    pub mode: String,
    /// Optional diagnostic name emitted by the Nix job-script renderer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// One unit's post-swap reconcile policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitAction {
    /// Reconcile verb.
    pub action: UnitReconcileAction,
    /// Credential handles consumed by this unit.
    #[serde(default)]
    pub credentials: Vec<String>,
    /// Whether the unit is enabled by operator policy.
    #[serde(default)]
    pub enable: bool,
}

/// Reconcile verb for a changed unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnitReconcileAction {
    /// Restart the unit.
    Restart,
    /// Reload the unit, falling back to restart.
    Reload,
    /// Materialize without touching the running unit.
    None,
}

/// A user declared by the evaluated generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestUser {
    /// Account name.
    pub name: String,
    /// Fixed UID, or `None` for allocation.
    pub uid: Option<u32>,
    /// Primary group name.
    pub group: String,
    /// Fixed primary GID, or `None` for allocation.
    pub gid: Option<u32>,
    /// Home directory.
    pub home: String,
    /// Login shell.
    pub shell: String,
    /// Whether this is a system account.
    pub system: bool,
    /// Human-readable account description.
    #[serde(default)]
    pub description: String,
    /// Supplementary group names.
    #[serde(rename = "supplementaryGroups", default)]
    pub supplementary_groups: Vec<String>,
}

/// One systemd preset decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresetEntry {
    /// Unit name.
    pub unit: String,
    /// Enable/disable policy.
    pub policy: PresetPolicy,
    /// Package or operator provenance.
    pub source: String,
}

/// A systemd preset policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PresetPolicy {
    /// Enable the unit.
    Enable,
    /// Disable the unit.
    Disable,
}

/// The five inputs that fully determine the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestInputs {
    /// ABI-pinned base library.
    pub base_lib: BaseLibInput,
    /// Evaluator executable.
    pub evaluator: EvaluatorInput,
    /// Config-only module closure.
    pub config_modules: ConfigModulesInput,
    /// Exact authorized host module.
    pub host_nix: HostNixInput,
    /// Canonical metadata facts.
    pub instance_facts: InstanceFactsInput,
}

/// Base library input identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaseLibInput {
    /// Store path.
    pub store_path: String,
    /// Shared option schema hash.
    pub abi_hash: String,
    /// Module ABI integer.
    pub module_abi: u32,
}

/// Evaluator input identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluatorInput {
    /// Evaluator store path.
    pub store_path: String,
    /// Evaluator content hash.
    pub store_hash: String,
}

/// Config module closure identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigModulesInput {
    /// Registry whose signed release authenticated the module set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,
    /// Name-bound semver release tag for the authenticated tree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_tag: Option<String>,
    /// Fingerprint of the roster key that signed the release tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag_signer_key: Option<String>,
    /// Hash of the consumed authenticated `store/` graph subset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realization: Option<String>,
    /// Set-hash of the authenticated config-output store paths and NAR hashes.
    pub closure_hash: String,
    /// Number of config outputs.
    pub count: usize,
    /// Exact evaluator order of config-output store paths retained for rollback.
    pub store_paths: Vec<String>,
    /// Canonical authenticated NAR hash corresponding to each store path.
    pub nar_hashes: Vec<String>,
    /// Authenticated package identity corresponding to each ordered module.
    pub package_names: Vec<String>,
    /// Trust origin aligned with each config output (`registry` or `image`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub origins: Vec<String>,
    /// ABI compatibility band corresponding to each ordered module path.
    pub module_abi_compat: Vec<ModuleAbiCompat>,
    /// Exact authenticated write authorization corresponding to each module.
    #[serde(default)]
    pub authorizations: Vec<super::PackageAuthorization>,
}

/// Authorized host module identity and trust evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostNixInput {
    /// Hash of exact host module bytes.
    pub content_hash: String,
    /// `platform` or `signed`.
    pub trust_mode: String,
    /// Metadata platform identifier.
    pub platform: String,
    /// Trusted signing-key fingerprint in signed mode.
    pub signer_key: Option<String>,
    /// Content-addressed store copy retained for rollback.
    pub store_path: String,
}

/// Canonical instance-facts identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceFactsInput {
    /// Hash of the normalized facts tree.
    pub facts_hash: String,
    /// Metadata platform identifier.
    pub platform: String,
    /// Store path containing the exact facts JSON bytes consumed by eval.
    pub store_path: String,
}

/// Deterministic dependency graph embedded in the manifest.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestGraph {
    /// Sorted dependencies keyed by package name.
    pub edges: BTreeMap<String, Vec<String>>,
}

/// Artifact ownership required for deterministic degraded projection.
///
/// Owners are package names or the reserved `@base` and `@host` roots. Every
/// aggregate artifact has exactly one entry; omission is rejected fail closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestOwnership {
    /// Owners keyed by `/etc` relative path.
    pub etc: BTreeMap<String, String>,
    /// Owners keyed by unit name.
    pub units: BTreeMap<String, String>,
    /// Owners keyed by job-script key.
    #[serde(rename = "jobScripts")]
    pub job_scripts: BTreeMap<String, String>,
    /// Owners keyed by user name.
    pub users: BTreeMap<String, String>,
    /// Owners keyed by `<unit>:<source>`.
    pub presets: BTreeMap<String, String>,
    /// Owners keyed by absolute store path.
    #[serde(rename = "storePaths")]
    pub store_paths: BTreeMap<String, String>,
}

fn validate_owner_keys<'a, I>(
    expected: I,
    owners: &BTreeMap<String, String>,
    field: &str,
    packages: &BTreeSet<&str>,
) -> Result<()>
where
    I: Iterator<Item = &'a String>,
{
    let expected: BTreeSet<&str> = expected.map(String::as_str).collect();
    let actual: BTreeSet<&str> = owners.keys().map(String::as_str).collect();
    if expected != actual {
        bail!("manifest ownership.{field} does not exactly cover its artifacts");
    }
    for owner in owners.values() {
        if owner != "@base" && owner != "@host" && !packages.contains(owner.as_str()) {
            bail!("manifest ownership.{field} names unknown owner {owner:?}");
        }
    }
    Ok(())
}

pub(super) fn validate_content_sha256(hash: &str) -> Result<()> {
    let digest = hash
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow::anyhow!("manifest hash lacks sha256: prefix: {hash:?}"))?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("manifest hash is not 64 lowercase hexadecimal digits: {hash:?}");
    }
    Ok(())
}

fn validate_store_identity_hash(hash: &str) -> Result<()> {
    let digest = hash
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow::anyhow!("manifest hash lacks sha256: prefix: {hash:?}"))?;
    if digest.len() != 40
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("manifest evaluator store hash is not 40 lowercase hexadecimal digits: {hash:?}");
    }
    Ok(())
}

fn validate_mode(mode: &str) -> Result<()> {
    if mode.len() != 4
        || !mode.starts_with('0')
        || !mode.bytes().all(|byte| (b'0'..=b'7').contains(&byte))
    {
        bail!("manifest mode must match 0[0-7]{{3}}: {mode:?}");
    }
    Ok(())
}

/// Validates a certificate-only PEM stream without accepting private keys,
/// arbitrary prose, or other PEM object types.
fn validate_certificate_pem(bytes: &[u8]) -> Result<()> {
    const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
    const END: &[u8] = b"-----END CERTIFICATE-----";

    let mut rest = trim_ascii_whitespace(bytes);
    let mut count = 0usize;
    while !rest.is_empty() {
        let encoded = rest
            .strip_prefix(BEGIN)
            .context("certificate PEM input contains non-certificate data")?;
        let end = find_bytes(encoded, END).context("certificate PEM input has no end marker")?;
        let body = &encoded[..end];
        let body = body
            .iter()
            .copied()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect::<Vec<_>>();
        if body.is_empty()
            || !body
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        {
            bail!("certificate PEM input has invalid base64 data");
        }
        let der = base64::engine::general_purpose::STANDARD
            .decode(body)
            .context("decoding certificate PEM input")?;
        validate_der_certificate(&der)?;
        count = count.saturating_add(1);
        rest = trim_ascii_whitespace(&encoded[end + END.len()..]);
    }
    if count == 0 {
        bail!("certificate PEM input has no certificates");
    }
    Ok(())
}

fn trim_ascii_whitespace(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|candidate| candidate == needle)
}

/// Checks the outer X.509 DER shape: `SEQUENCE { SEQUENCE, SEQUENCE,
/// BIT STRING }`. Signature verification is deliberately left to TLS clients;
/// this boundary only ensures the public certificate channel cannot carry an
/// unrelated plaintext or private-key payload.
fn validate_der_certificate(der: &[u8]) -> Result<()> {
    let (tag, certificate, rest) = der_tlv(der)?;
    if tag != 0x30 || !rest.is_empty() {
        bail!("certificate PEM input is not one DER certificate");
    }
    let (tbs_tag, _, certificate) = der_tlv(certificate)?;
    let (algorithm_tag, _, certificate) = der_tlv(certificate)?;
    let (signature_tag, signature, certificate) = der_tlv(certificate)?;
    if tbs_tag != 0x30
        || algorithm_tag != 0x30
        || signature_tag != 0x03
        || signature.is_empty()
        || signature[0] > 7
        || !certificate.is_empty()
    {
        bail!("certificate PEM input has an invalid X.509 DER shape");
    }
    Ok(())
}

fn der_tlv(input: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    let (&tag, after_tag) = input
        .split_first()
        .context("certificate DER is truncated before its tag")?;
    let (&first_length, after_length) = after_tag
        .split_first()
        .context("certificate DER is truncated before its length")?;
    let (length, body) = if first_length & 0x80 == 0 {
        (usize::from(first_length), after_length)
    } else {
        let width = usize::from(first_length & 0x7f);
        if width == 0 || width > std::mem::size_of::<usize>() || after_length.len() < width {
            bail!("certificate DER has an invalid length");
        }
        let mut length = 0usize;
        for byte in &after_length[..width] {
            length = length
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*byte)))
                .context("certificate DER length overflows")?;
        }
        (length, &after_length[width..])
    };
    if body.len() < length {
        bail!("certificate DER body is truncated");
    }
    Ok((tag, &body[..length], &body[length..]))
}

fn validate_relative_path(path: &str, field: &str) -> Result<()> {
    if path.is_empty()
        || path.starts_with('/')
        || path
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        bail!("invalid {field} relative path {path:?}");
    }
    Ok(())
}

fn validate_job_script_key(key: &str) -> Result<()> {
    if key.is_empty()
        || key.len() > 255
        || !key.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'@')
        })
    {
        bail!("invalid jobScripts key {key:?}");
    }
    Ok(())
}

fn validate_etc_symlink(link_path: &str, target: &str) -> Result<()> {
    if target == "/dev/null" {
        return Ok(());
    }
    let (mut stack, relative): (Vec<&str>, &str) =
        if let Some(relative) = target.strip_prefix("/etc/") {
            (Vec::new(), relative)
        } else if target.starts_with('/') {
            bail!("symlink target is outside /etc: {target:?}");
        } else {
            (
                link_path
                    .rsplit_once('/')
                    .map_or(Vec::new(), |(parent, _)| parent.split('/').collect()),
                target,
            )
        };
    for component in relative.split('/') {
        match component {
            "" | "." => bail!("invalid symlink target component in {target:?}"),
            ".." => {
                if stack.pop().is_none() {
                    bail!("symlink target escapes /etc: {target:?}");
                }
            }
            component => stack.push(component),
        }
    }
    Ok(())
}

fn store_path_root(target: &str) -> Option<&str> {
    let suffix = target.strip_prefix("/nix/store/")?;
    let first = suffix.split('/').next()?;
    if first.is_empty() {
        return None;
    }
    Some(&target[.."/nix/store/".len() + first.len()])
}

pub(super) fn validate_canonical_store_path(path: &str) -> Result<()> {
    let suffix = path
        .strip_prefix("/nix/store/")
        .ok_or_else(|| anyhow::anyhow!("manifest store path is outside /nix/store: {path:?}"))?;
    if suffix.contains('/') {
        bail!("manifest storePaths entry is not a store root: {path:?}");
    }
    let Some((hash, name)) = suffix.split_once('-') else {
        bail!("manifest storePaths entry is not a named store path: {path:?}");
    };
    const NIX_BASE32: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";
    if hash.len() != 32 || !hash.bytes().all(|byte| NIX_BASE32.contains(&byte)) {
        bail!("manifest storePaths entry has an invalid Nix store hash: {path:?}");
    }
    if name.is_empty()
        || !name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.' | b'_' | b'?' | b'=')
        })
    {
        bail!("manifest storePaths entry has an invalid store name: {path:?}");
    }
    Ok(())
}

/// Rejects an authenticated module's attempt to emit a store path that the
/// manifest does not independently pin and assign ownership to.
fn validate_emitted_store_paths(
    value: &str,
    pinned: &BTreeSet<&str>,
    store_owners: &BTreeMap<String, String>,
    artifact_owner: Option<&str>,
    graph: &ManifestGraph,
    field: &str,
) -> Result<()> {
    let artifact_owner = artifact_owner
        .ok_or_else(|| anyhow::anyhow!("manifest {field} has no authenticated artifact owner"))?;
    for (offset, _) in value.match_indices("/nix/store/") {
        let suffix = &value[offset + "/nix/store/".len()..];
        let bytes = suffix.as_bytes();
        if bytes.len() < 34
            || !bytes[..32]
                .iter()
                .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(byte))
            || bytes[32] != b'-'
        {
            bail!("manifest {field} contains a malformed Nix store-path prefix");
        }
        let name_len = bytes[33..]
            .iter()
            .take_while(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'+' | b'-' | b'.' | b'_' | b'?' | b'=')
            })
            .count();
        if name_len == 0 {
            bail!("manifest {field} contains a malformed Nix store-path prefix");
        }
        let root = format!("/nix/store/{}", &suffix[..33 + name_len]);
        if !pinned.contains(root.as_str()) {
            bail!("manifest {field} emits unpinned store path {root:?}");
        }
        let store_owner = store_owners.get(&root).ok_or_else(|| {
            anyhow::anyhow!("manifest {field} emits store path {root:?} without an owner")
        })?;
        let authorized = owner_can_reference_store(artifact_owner, store_owner, &graph.edges);
        if !authorized {
            bail!(
                "manifest {field} owner {artifact_owner:?} emits store path {root:?} owned by {store_owner:?}"
            );
        }
    }
    Ok(())
}

/// Returns whether an artifact owner may reference a store owner under the
/// authenticated package dependency graph.
pub(crate) fn owner_can_reference_store(
    artifact_owner: &str,
    store_owner: &str,
    edges: &BTreeMap<String, Vec<String>>,
) -> bool {
    match artifact_owner {
        "@host" => true,
        "@base" => store_owner == "@base",
        package => {
            store_owner == package
                || store_owner == "@base"
                || graph_dependency_closure_contains(edges, package, store_owner)
        }
    }
}

/// Returns whether `dependency` is reachable from `package` in authenticated
/// package dependency edges.
fn graph_dependency_closure_contains(
    edges: &BTreeMap<String, Vec<String>>,
    package: &str,
    dependency: &str,
) -> bool {
    let mut pending = vec![package];
    let mut visited = BTreeSet::new();
    while let Some(current) = pending.pop() {
        if !visited.insert(current) {
            continue;
        }
        let Some(dependencies) = edges.get(current) else {
            continue;
        };
        if dependencies.iter().any(|candidate| candidate == dependency) {
            return true;
        }
        pending.extend(dependencies.iter().map(String::as_str));
    }
    false
}

fn validate_json_store_paths(
    value: &serde_json::Value,
    pinned: &BTreeSet<&str>,
    store_owners: &BTreeMap<String, String>,
    artifact_owner: Option<&str>,
    graph: &ManifestGraph,
    field: &str,
) -> Result<()> {
    match value {
        serde_json::Value::String(value) => {
            validate_emitted_store_paths(value, pinned, store_owners, artifact_owner, graph, field)
        }
        serde_json::Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                validate_json_store_paths(
                    value,
                    pinned,
                    store_owners,
                    artifact_owner,
                    graph,
                    &format!("{field}[{index}]"),
                )?;
            }
            Ok(())
        }
        serde_json::Value::Object(values) => {
            for (key, value) in values {
                validate_emitted_store_paths(
                    key,
                    pinned,
                    store_owners,
                    artifact_owner,
                    graph,
                    &format!("{field} object key"),
                )?;
                validate_json_store_paths(
                    value,
                    pinned,
                    store_owners,
                    artifact_owner,
                    graph,
                    &format!("{field}.{key}"),
                )?;
            }
            Ok(())
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
            Ok(())
        }
    }
}

fn validate_sorted_unique(values: &[String], field: &str) -> Result<()> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        bail!("manifest {field} must be sorted and deduplicated");
    }
    Ok(())
}

/// Reads the manifest at `manifest_path` and applies its `/etc` tree under
/// `etc_root`, writing job scripts under `<etc_root>/aos-job-scripts/` and
/// rewriting unit-body placeholders to `<job_scripts_runtime_dir>/<key>`.
///
/// This is idempotent: existing files at target paths are overwritten and
/// existing symlinks are replaced, so re-materializing the same manifest is a
/// no-op in effect.
///
/// # Errors
///
/// Returns an error if the manifest cannot be read or parsed, if its `schema`
/// tag is not [`ConfigManifest::SCHEMA`], or if any filesystem write fails.
pub fn materialize_manifest(
    manifest_path: &Path,
    etc_root: &Path,
    job_scripts_runtime_dir: &str,
) -> Result<()> {
    let raw = std::fs::read_to_string(manifest_path)
        .with_context(|| format!("reading manifest {}", manifest_path.display()))?;
    let manifest: ConfigManifest = serde_json::from_str(&raw)
        .with_context(|| format!("parsing manifest {}", manifest_path.display()))?;
    apply(&manifest, etc_root, job_scripts_runtime_dir)
}

/// Materializes and atomically publishes a configuration generation's EROFS
/// lower.
///
/// The final artifact is `<generation_dir>/config-lower/`. It contains the
/// rendered `etc-tree`, a deterministic `etc.erofs` image, and metadata that
/// binds both to the canonical manifest hash. Existing artifacts are never
/// overwritten: a byte-identical retry validates and reuses them, while any
/// mismatch fails closed before activation can mount or swap `/etc`.
///
/// `mkfs_erofs` and `fsck_erofs` must be absolute paths to the AOS-built
/// erofs-utils binaries carried by the running image. The commands run with an
/// empty environment, so no host `PATH` or ambient tool can participate.
///
/// # Errors
///
/// Returns an error if the manifest or generation directory is invalid, an
/// existing artifact fails validation, rendering fails, either EROFS tool
/// fails, or the durable staging rename cannot be completed.
pub fn materialize_generation_lower(
    manifest_path: &Path,
    generation_dir: &Path,
    job_scripts_runtime_dir: &str,
    mkfs_erofs: &Path,
    fsck_erofs: &Path,
) -> Result<PathBuf> {
    if !is_aos_store_tool(mkfs_erofs) || !is_aos_store_tool(fsck_erofs) {
        bail!("EROFS materializer tools must be explicit AOS /nix/store paths");
    }
    let generation_metadata = std::fs::symlink_metadata(generation_dir).with_context(|| {
        format!(
            "inspecting generation directory {}",
            generation_dir.display()
        )
    })?;
    if !generation_metadata.is_dir() || generation_metadata.file_type().is_symlink() {
        bail!(
            "configuration generation root {} is not a real directory",
            generation_dir.display()
        );
    }

    let raw = std::fs::read(manifest_path)
        .with_context(|| format!("reading manifest {}", manifest_path.display()))?;
    let manifest: ConfigManifest = serde_json::from_slice(&raw)
        .with_context(|| format!("parsing manifest {}", manifest_path.display()))?;
    manifest
        .validate()
        .with_context(|| format!("validating manifest {}", manifest_path.display()))?;
    let manifest_value = serde_json::to_value(&manifest)?;
    let manifest_hash = crate::graph_compile::reproject::hash_cjson(&manifest_value);
    let final_dir = generation_dir.join(GENERATION_LOWER_DIR);
    if final_dir.exists() {
        validate_generation_lower(&final_dir, &manifest_hash, fsck_erofs)?;
        return Ok(final_dir.join(GENERATION_LOWER_IMAGE));
    }

    let stage = generation_dir.join(format!(
        ".{GENERATION_LOWER_DIR}.stage.{}",
        std::process::id()
    ));
    remove_stage_if_present(&stage)?;
    std::fs::create_dir(&stage)
        .with_context(|| format!("creating configuration lower stage {}", stage.display()))?;
    let tree = stage.join(GENERATION_LOWER_TREE);
    std::fs::create_dir(&tree)
        .with_context(|| format!("creating configuration lower tree {}", tree.display()))?;

    let result = (|| {
        apply(&manifest, &tree, job_scripts_runtime_dir)?;
        normalize_tree_directory_modes(&tree)?;
        sync_tree(&tree)?;

        let image = stage.join(GENERATION_LOWER_IMAGE);
        let status = Command::new(mkfs_erofs)
            .env_clear()
            .args([
                OsStr::new("--all-root"),
                OsStr::new("-T0"),
                OsStr::new("-U"),
                OsStr::new(CONFIG_EROFS_UUID),
                OsStr::new("-L"),
                OsStr::new("aos-config"),
            ])
            .arg(&image)
            .arg(&tree)
            .status()
            .with_context(|| format!("running AOS mkfs.erofs {}", mkfs_erofs.display()))?;
        if !status.success() {
            bail!("AOS mkfs.erofs failed with status {status}");
        }
        sync_file(&image)?;
        run_fsck(fsck_erofs, &image)?;

        let metadata = GenerationLowerMetadata {
            schema: GENERATION_LOWER_SCHEMA.to_string(),
            manifest_hash,
            image_sha256: sha256_file(&image)?,
            tree_sha256: hash_tree(&tree)?,
        };
        let metadata_path = stage.join(GENERATION_LOWER_META);
        let encoded = serde_json::to_vec_pretty(&metadata)?;
        write_durable(&metadata_path, &encoded)?;
        sync_directory(&stage)?;
        std::fs::rename(&stage, &final_dir)
            .with_context(|| format!("publishing configuration lower {}", final_dir.display()))?;
        sync_directory(generation_dir)?;
        validate_generation_lower(&final_dir, &metadata.manifest_hash, fsck_erofs)?;
        Ok(final_dir.join(GENERATION_LOWER_IMAGE))
    })();
    if result.is_err() {
        let _ = remove_stage_if_present(&stage);
    }
    result
}

fn is_aos_store_tool(path: &Path) -> bool {
    let Some(path) = path.to_str() else {
        return false;
    };
    let Some(root) = store_path_root(path) else {
        return false;
    };
    path.starts_with(&format!("{root}/")) && validate_canonical_store_path(root).is_ok()
}

fn validate_generation_lower(
    lower_dir: &Path,
    expected_manifest_hash: &str,
    fsck_erofs: &Path,
) -> Result<()> {
    let lower_metadata = std::fs::symlink_metadata(lower_dir)
        .with_context(|| format!("inspecting retained lower {}", lower_dir.display()))?;
    if !lower_metadata.is_dir() || lower_metadata.file_type().is_symlink() {
        bail!("retained configuration lower is not a real directory");
    }
    let metadata_path = lower_dir.join(GENERATION_LOWER_META);
    let metadata: GenerationLowerMetadata = serde_json::from_slice(
        &std::fs::read(&metadata_path)
            .with_context(|| format!("reading {}", metadata_path.display()))?,
    )
    .with_context(|| format!("parsing {}", metadata_path.display()))?;
    if metadata.schema != GENERATION_LOWER_SCHEMA {
        bail!(
            "unsupported retained configuration lower schema {:?}",
            metadata.schema
        );
    }
    if metadata.manifest_hash != expected_manifest_hash {
        bail!("retained configuration lower belongs to a different manifest");
    }
    let tree = lower_dir.join(GENERATION_LOWER_TREE);
    let actual_tree = hash_tree(&tree)?;
    if actual_tree != metadata.tree_sha256 {
        bail!("retained configuration lower tree checksum mismatch");
    }
    let image = lower_dir.join(GENERATION_LOWER_IMAGE);
    let actual_image = sha256_file(&image)?;
    if actual_image != metadata.image_sha256 {
        bail!("retained configuration lower image checksum mismatch");
    }
    run_fsck(fsck_erofs, &image)
}

fn run_fsck(fsck_erofs: &Path, image: &Path) -> Result<()> {
    let status = Command::new(fsck_erofs)
        .env_clear()
        .arg(image)
        .status()
        .with_context(|| format!("running AOS fsck.erofs {}", fsck_erofs.display()))?;
    if !status.success() {
        bail!(
            "AOS fsck.erofs rejected {} with status {status}",
            image.display()
        );
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("opening {} for hashing", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .with_context(|| format!("hashing {}", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn hash_tree(root: &Path) -> Result<String> {
    let metadata = std::fs::symlink_metadata(root)
        .with_context(|| format!("inspecting configuration tree {}", root.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("configuration lower tree is not a real directory");
    }
    let mut records = Vec::new();
    collect_tree_records(root, root, &mut records)?;
    Ok(crate::graph_compile::reproject::hash_cjson(
        &serde_json::Value::Array(records),
    ))
}

fn collect_tree_records(
    root: &Path,
    directory: &Path,
    records: &mut Vec<serde_json::Value>,
) -> Result<()> {
    let mut entries = std::fs::read_dir(directory)
        .with_context(|| format!("reading configuration tree {}", directory.display()))?
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .context("configuration tree entry escaped its root")?;
        let relative = String::from_utf8(relative.as_os_str().as_bytes().to_vec())
            .context("configuration tree contains a non-UTF-8 path")?;
        let metadata = std::fs::symlink_metadata(&path)
            .with_context(|| format!("inspecting configuration tree entry {relative:?}"))?;
        let mode = metadata.permissions().mode() & 0o7777;
        if metadata.file_type().is_symlink() {
            let target = std::fs::read_link(&path)
                .with_context(|| format!("reading configuration symlink {relative:?}"))?;
            let target = String::from_utf8(target.as_os_str().as_bytes().to_vec())
                .context("configuration tree contains a non-UTF-8 symlink target")?;
            records.push(serde_json::json!([relative, "symlink", target]));
        } else if metadata.is_dir() {
            records.push(serde_json::json!([
                relative,
                "directory",
                format!("{mode:04o}")
            ]));
            collect_tree_records(root, &path, records)?;
        } else if metadata.is_file() {
            records.push(serde_json::json!([
                relative,
                "file",
                format!("{mode:04o}"),
                sha256_file(&path)?
            ]));
        } else {
            bail!("configuration tree contains unsupported entry {relative:?}");
        }
    }
    Ok(())
}

fn sync_tree(root: &Path) -> Result<()> {
    let mut directories = vec![root.to_path_buf()];
    let mut cursor = 0;
    while cursor < directories.len() {
        let directory = directories[cursor].clone();
        cursor += 1;
        for entry in std::fs::read_dir(&directory)
            .with_context(|| format!("reading {} for durable sync", directory.display()))?
        {
            let path = entry?.path();
            let metadata = std::fs::symlink_metadata(&path)?;
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                directories.push(path);
            } else if metadata.is_file() {
                sync_file(&path)?;
            }
        }
    }
    for directory in directories.iter().rev() {
        sync_directory(directory)?;
    }
    Ok(())
}

fn normalize_tree_directory_modes(root: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(root)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("configuration lower tree is not a real directory");
    }
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(root, permissions)?;
    for entry in std::fs::read_dir(root)? {
        let path = entry?.path();
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            normalize_tree_directory_modes(&path)?;
        }
    }
    Ok(())
}

fn sync_file(path: &Path) -> Result<()> {
    std::fs::File::open(path)
        .with_context(|| format!("opening {} for sync", path.display()))?
        .sync_all()
        .with_context(|| format!("syncing {}", path.display()))
}

fn sync_directory(path: &Path) -> Result<()> {
    std::fs::File::open(path)
        .with_context(|| format!("opening directory {} for sync", path.display()))?
        .sync_all()
        .with_context(|| format!("syncing directory {}", path.display()))
}

fn write_durable(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing {}", path.display()))
}

fn remove_stage_if_present(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            std::fs::remove_file(path)
                .with_context(|| format!("removing stale lower stage {}", path.display()))
        }
        Ok(_) => std::fs::remove_dir_all(path)
            .with_context(|| format!("removing stale lower stage {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("inspecting stale lower stage {}", path.display()))
        }
    }
}

/// Applies an already-parsed [`ConfigManifest`] under `etc_root`.
///
/// Split from [`materialize_manifest`] so the pure rendering logic is unit
/// testable without touching a real manifest file.
///
/// # Errors
///
/// Returns an error if the schema tag is wrong or any filesystem write fails.
pub fn apply(
    manifest: &ConfigManifest,
    etc_root: &Path,
    job_scripts_runtime_dir: &str,
) -> Result<()> {
    manifest.validate()?;
    std::fs::create_dir_all(etc_root)
        .with_context(|| format!("creating materialization root {}", etc_root.display()))?;
    let root = openat(
        rustix::fs::CWD,
        etc_root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening materialization root {}", etc_root.display()))?;

    // 1. Job scripts first: their materialized paths are what the unit-body
    //    placeholder rewrite below points at.
    let mut placeholders: Vec<(String, String)> = Vec::with_capacity(manifest.job_scripts.len());
    for (key, script) in &manifest.job_scripts {
        if manifest.ownership.job_scripts.get(key).map(String::as_str) == Some("@base") {
            continue;
        }
        let relative = format!("{JOB_SCRIPTS_SUBDIR}/{key}");
        write_file_beneath(&root, &relative, script.text.as_bytes(), &script.mode)
            .with_context(|| format!("writing job script {key}"))?;
        placeholders.push((
            format!("#aos-jobscript:{key}#"),
            format!("{}/{key}", job_scripts_runtime_dir.trim_end_matches('/')),
        ));
    }

    // 2. The /etc tree.
    for (target, entry) in &manifest.etc {
        if manifest.ownership.etc.get(target).map(String::as_str) == Some("@base") {
            continue;
        }
        match entry {
            EtcEntry::Text { text, mode } => {
                let rendered = substitute_placeholders(text, &placeholders);
                write_file_beneath(&root, target, rendered.as_bytes(), mode)
                    .with_context(|| format!("writing /etc/{target}"))?;
            }
            EtcEntry::Symlink { target: link } | EtcEntry::StoreSymlink { target: link } => {
                write_symlink_beneath(&root, target, link)
                    .with_context(|| format!("linking /etc/{target} -> {link}"))?;
            }
            EtcEntry::CertificateBundle { parts, mode } => {
                let mut bundle = Vec::new();
                for (index, part) in parts.iter().enumerate() {
                    let bytes = match part {
                        CertificateBundlePart::Text { text } => text.as_bytes().to_vec(),
                        CertificateBundlePart::StoreFile { path } => {
                            let metadata = std::fs::symlink_metadata(path).with_context(|| {
                                format!(
                                    "inspecting certificate bundle input {index} for /etc/{target}"
                                )
                            })?;
                            if !metadata.is_file() || metadata.file_type().is_symlink() {
                                bail!(
                                    "certificate bundle input {index} for /etc/{target} is not a regular store file"
                                );
                            }
                            std::fs::read(path).with_context(|| {
                                format!(
                                    "reading certificate bundle input {index} for /etc/{target}"
                                )
                            })?
                        }
                    };
                    validate_certificate_pem(&bytes).with_context(|| {
                        format!("validating certificate bundle input {index} for /etc/{target}")
                    })?;
                    bundle.extend_from_slice(&bytes);
                }
                write_file_beneath(&root, target, &bundle, mode)
                    .with_context(|| format!("writing /etc/{target}"))?;
            }
        }
    }

    Ok(())
}

/// Rewrites every `#aos-jobscript:<key>#` placeholder in `body` to its
/// materialized job-script path. `replacements` pairs are
/// `(placeholder, absolute_path)`.
fn substitute_placeholders(body: &str, replacements: &[(String, String)]) -> String {
    let mut out = body.to_string();
    for (placeholder, path) in replacements {
        if out.contains(placeholder.as_str()) {
            out = out.replace(placeholder.as_str(), path);
        }
    }
    out
}

/// Writes `contents` to `dest` with octal `mode`, creating parent directories.
/// Overwrites any existing file (idempotent re-materialization).
///
/// # Errors
///
/// Returns an error if `mode` is not a valid octal string or any filesystem
/// operation fails.
fn write_file_beneath(root: &OwnedFd, path: &str, contents: &[u8], mode: &str) -> Result<()> {
    let perm = parse_octal_mode(mode)?;
    let (parent, name) = open_parent_beneath(root, path)?;
    unlink_file_if_present(&parent, &name)?;
    let fd = openat(
        &parent,
        &name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(perm as _),
    )
    .with_context(|| format!("creating {path:?} beneath materialization root"))?;
    let mut file = std::fs::File::from(fd);
    file.write_all(contents)
        .with_context(|| format!("writing {path:?} beneath materialization root"))?;
    fchmod(&file, Mode::from_raw_mode(perm as _))
        .with_context(|| format!("chmod {perm:o} {path:?}"))?;
    Ok(())
}

/// Writes one relative file beneath a filesystem root without following any
/// symlink in the path.
///
/// This is the shared boundary used by transaction staging as well as the
/// final `/etc` materializer. The caller supplies an already-created root;
/// parent directories below it are created with mode `0755`.
///
/// # Errors
///
/// Returns an error for an unsafe relative path, invalid mode, symlinked path
/// component, or filesystem failure.
pub(crate) fn write_bytes_beneath(
    root_path: &Path,
    path: &str,
    contents: &[u8],
    mode: &str,
) -> Result<()> {
    validate_relative_path(path, "staged file")?;
    std::fs::create_dir_all(root_path)
        .with_context(|| format!("creating staging root {}", root_path.display()))?;
    let root = openat(
        rustix::fs::CWD,
        root_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening staging root {}", root_path.display()))?;
    write_file_beneath(&root, path, contents, mode)
}

/// Reads one regular file beneath a filesystem root without following any
/// symlink in the path.
///
/// # Errors
///
/// Returns an error for an unsafe relative path, a symlink/non-directory path
/// component, a non-regular final entry, or an I/O failure.
pub(crate) fn read_bytes_beneath(root_path: &Path, path: &str) -> Result<Vec<u8>> {
    validate_relative_path(path, "staged file")?;
    let root = openat(
        rustix::fs::CWD,
        root_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening staging root {}", root_path.display()))?;
    let (parent, name) = open_parent_beneath(&root, path)?;
    let fd = openat(
        &parent,
        &name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening {path:?} beneath {}", root_path.display()))?;
    let mut file = std::fs::File::from(fd);
    if !file
        .metadata()
        .with_context(|| format!("inspecting {path:?} beneath {}", root_path.display()))?
        .is_file()
    {
        bail!("staged path {path:?} is not a regular file");
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .with_context(|| format!("reading {path:?} beneath {}", root_path.display()))?;
    Ok(bytes)
}

/// Creates a symlink at `dest` pointing at `target`, creating parent
/// directories and replacing any existing entry (idempotent).
///
/// # Errors
///
/// Returns an error if any filesystem operation fails.
fn write_symlink_beneath(root: &OwnedFd, path: &str, target: &str) -> Result<()> {
    let (parent, name) = open_parent_beneath(root, path)?;
    unlink_file_if_present(&parent, &name)?;
    symlinkat(target, &parent, &name)
        .with_context(|| format!("symlink {path:?} -> {target:?} beneath materialization root"))?;
    Ok(())
}

fn open_parent_beneath(root: &OwnedFd, path: &str) -> Result<(OwnedFd, String)> {
    let mut components = path.split('/').collect::<Vec<_>>();
    let name = components
        .pop()
        .context("materialization path has no final component")?
        .to_string();
    let mut directory = openat(
        root,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    for component in components {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        match openat(&directory, component, flags, Mode::empty()) {
            Ok(next) => directory = next,
            Err(error) if error == rustix::io::Errno::NOENT => {
                match mkdirat(&directory, component, Mode::from_raw_mode(0o755)) {
                    Ok(()) => {}
                    Err(error) if error == rustix::io::Errno::EXIST => {}
                    Err(error) => return Err(error.into()),
                }
                directory = openat(&directory, component, flags, Mode::empty())
                    .with_context(|| format!("opening materialization directory {component:?}"))?;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("refusing non-directory or symlink component {component:?}")
                });
            }
        }
    }
    Ok((directory, name))
}

fn unlink_file_if_present(parent: &OwnedFd, name: &str) -> Result<()> {
    match unlinkat(parent, name, AtFlags::empty()) {
        Ok(()) => Ok(()),
        Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Parses a 3- or 4-digit octal mode string (e.g. `"0644"`) into a `u32`.
///
/// # Errors
///
/// Returns an error if `mode` is not valid octal.
fn parse_octal_mode(mode: &str) -> Result<u32> {
    u32::from_str_radix(mode, 8).with_context(|| format!("invalid octal mode {mode:?}"))
}

/// Emits the set of unit-body placeholders a manifest declares. Exposed for
/// callers that want to inspect the job-script wiring without materializing.
///
/// The returned paths use [`DEFAULT_JOB_SCRIPTS_RUNTIME_DIR`].
pub fn job_script_placeholders(manifest: &ConfigManifest) -> Vec<(String, PathBuf)> {
    manifest
        .job_scripts
        .keys()
        .filter(|key| manifest.ownership.job_scripts.get(*key).map(String::as_str) != Some("@base"))
        .map(|key| {
            (
                format!("#aos-jobscript:{key}#"),
                PathBuf::from(DEFAULT_JOB_SCRIPTS_RUNTIME_DIR).join(key),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_from(json: &str) -> ConfigManifest {
        let mut value: serde_json::Value = serde_json::from_str(json).expect("valid json");
        let object = value.as_object_mut().expect("manifest object");
        object.insert("units".into(), serde_json::json!({}));
        object.insert("users".into(), serde_json::json!([]));
        object.insert("presets".into(), serde_json::json!([]));
        let mut stores = BTreeMap::new();
        if let Some(etc) = object.get("etc").and_then(serde_json::Value::as_object) {
            for entry in etc.values() {
                if entry.get("kind").and_then(serde_json::Value::as_str) == Some("store-symlink") {
                    if let Some(root) = entry
                        .get("target")
                        .and_then(serde_json::Value::as_str)
                        .and_then(store_path_root)
                    {
                        stores.insert(root.to_string(), "@base");
                    }
                }
                if entry.get("kind").and_then(serde_json::Value::as_str)
                    == Some("certificate-bundle")
                {
                    for part in entry
                        .get("parts")
                        .and_then(serde_json::Value::as_array)
                        .into_iter()
                        .flatten()
                    {
                        if let Some(root) = part
                            .get("path")
                            .and_then(serde_json::Value::as_str)
                            .and_then(store_path_root)
                        {
                            stores.insert(root.to_string(), "@base");
                        }
                    }
                }
            }
        }
        if let Some(scripts) = object
            .get("jobScripts")
            .and_then(serde_json::Value::as_object)
        {
            for script in scripts.values() {
                let Some(text) = script.get("text").and_then(serde_json::Value::as_str) else {
                    continue;
                };
                for (offset, _) in text.match_indices("/nix/store/") {
                    if let Some(root) = store_path_root(&text[offset..]) {
                        stores.insert(root.to_string(), "@base");
                    }
                }
            }
        }
        object.insert(
            "storePaths".into(),
            serde_json::to_value(stores.keys().collect::<Vec<_>>()).expect("stores"),
        );
        object.insert("module_abi".into(), serde_json::json!(1));
        object.insert("packages".into(), serde_json::json!([]));
        object.insert("packageOutputs".into(), serde_json::json!({}));
        object.insert("graph".into(), serde_json::json!({"edges": {}}));
        object.insert("config".into(), serde_json::json!({}));
        object.insert("credentials".into(), serde_json::json!({}));
        let hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let store_hash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        object.insert(
            "inputs".into(),
            serde_json::json!({
                "base_lib": {"store_path":"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-base", "abi_hash":hash, "module_abi":1},
                "evaluator": {"store_path":"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-evaluator", "store_hash":store_hash},
                "config_modules": {"closure_hash":"sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945", "count":0, "store_paths":[], "nar_hashes":[], "package_names":[], "module_abi_compat":[]},
                "host_nix": {"content_hash":hash, "trust_mode":"platform", "platform":"test", "signer_key":null, "store_path":"/nix/store/cccccccccccccccccccccccccccccccc-host-nix"},
                "instance_facts": {"facts_hash":hash, "platform":"test", "store_path":"/nix/store/dddddddddddddddddddddddddddddddd-facts"}
            }),
        );
        let etc_owners = object
            .get("etc")
            .and_then(serde_json::Value::as_object)
            .into_iter()
            .flatten()
            .map(|(key, _)| (key.clone(), "@host"))
            .collect::<BTreeMap<_, _>>();
        let script_owners = object
            .get("jobScripts")
            .and_then(serde_json::Value::as_object)
            .into_iter()
            .flatten()
            .map(|(key, _)| (key.clone(), "@host"))
            .collect::<BTreeMap<_, _>>();
        object.insert(
            "ownership".into(),
            serde_json::json!({
                "etc": etc_owners, "units": {}, "jobScripts": script_owners,
                "users": {}, "presets": {}, "storePaths": stores
            }),
        );
        serde_json::from_value(value).expect("valid manifest json")
    }

    #[test]
    fn rejects_unknown_schema() {
        let m = manifest_from(r#"{ "schema": "wrong/v9", "etc": {}, "jobScripts": {} }"#);
        let dir = tempdir();
        let err = apply(&m, &dir, DEFAULT_JOB_SCRIPTS_RUNTIME_DIR).unwrap_err();
        assert!(
            err.to_string()
                .contains("unsupported config-manifest schema"),
            "{err}"
        );
    }

    #[test]
    fn rejects_missing_mandatory_top_level_field() {
        let manifest =
            manifest_from(r#"{ "schema": "aos.config-manifest/v1", "etc": {}, "jobScripts": {} }"#);
        let mut value = serde_json::to_value(manifest).expect("serialize manifest");
        value
            .as_object_mut()
            .expect("manifest object")
            .remove("config");
        let error = serde_json::from_value::<ConfigManifest>(value)
            .expect_err("config is a mandatory manifest field");
        assert!(error.to_string().contains("missing field `config`"));
    }

    #[test]
    fn writes_text_entry_with_mode() {
        let m = manifest_from(
            r#"{ "schema": "aos.config-manifest/v1",
                 "etc": { "apm/registries.d/x.toml": { "kind": "text", "mode": "0640", "text": "hello\n" } },
                 "jobScripts": {} }"#,
        );
        let root = tempdir();
        apply(&m, &root, DEFAULT_JOB_SCRIPTS_RUNTIME_DIR).unwrap();
        let f = root.join("apm/registries.d/x.toml");
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "hello\n");
        let mode = std::fs::metadata(&f).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "mode {mode:o}");
    }

    #[test]
    fn materializes_certificate_only_inline_bundle() {
        let certificate =
            "-----BEGIN CERTIFICATE-----\nMAgwADAAAwIAAA==\n-----END CERTIFICATE-----\n";
        let manifest = manifest_from(
            &serde_json::json!({
                "schema": "aos.config-manifest/v1",
                "etc": {
                    "ssl/certs/ca-certificates.crt": {
                        "kind": "certificate-bundle",
                        "mode": "0644",
                        "parts": [
                            {"kind": "text", "text": certificate},
                            {"kind": "text", "text": certificate}
                        ]
                    }
                },
                "jobScripts": {}
            })
            .to_string(),
        );
        let root = tempdir();
        apply(&manifest, &root, DEFAULT_JOB_SCRIPTS_RUNTIME_DIR).unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join("ssl/certs/ca-certificates.crt")).unwrap(),
            format!("{certificate}{certificate}")
        );
    }

    #[test]
    fn rejects_non_certificate_inline_bundle_data() {
        let manifest = manifest_from(
            r#"{
                "schema": "aos.config-manifest/v1",
                "etc": {
                    "ssl/certs/ca-certificates.crt": {
                        "kind": "certificate-bundle",
                        "mode": "0644",
                        "parts": [{"kind": "text", "text": "password=hunter2\n"}]
                    }
                },
                "jobScripts": {}
            }"#,
        );
        let error = manifest.validate().expect_err("plaintext must be rejected");
        assert!(
            error
                .to_string()
                .contains("inline certificate bundle input"),
            "{error:#}"
        );
    }

    #[test]
    fn creates_relative_and_store_symlinks() {
        let m = manifest_from(
            r#"{ "schema": "aos.config-manifest/v1",
                 "etc": {
                   "systemd/system/getty.target.wants/getty@tty1.service":
                     { "kind": "symlink", "target": "../getty@tty1.service" },
                   "localtime": { "kind": "store-symlink", "target": "/nix/store/ffffffffffffffffffffffffffffffff-tzdata/UTC" }
                 },
                 "jobScripts": {} }"#,
        );
        let root = tempdir();
        apply(&m, &root, DEFAULT_JOB_SCRIPTS_RUNTIME_DIR).unwrap();
        let wants = root.join("systemd/system/getty.target.wants/getty@tty1.service");
        assert_eq!(
            std::fs::read_link(&wants).unwrap().to_str().unwrap(),
            "../getty@tty1.service"
        );
        let lt = root.join("localtime");
        assert_eq!(
            std::fs::read_link(&lt).unwrap().to_str().unwrap(),
            "/nix/store/ffffffffffffffffffffffffffffffff-tzdata/UTC"
        );
    }

    #[test]
    fn materializes_job_script_and_rewrites_placeholder() {
        let m = manifest_from(
            r##"{ "schema": "aos.config-manifest/v1",
                 "etc": {
                   "systemd/system/svc.service":
                     { "kind": "text", "mode": "0644",
                       "text": "[Service]\nExecStart=#aos-jobscript:svc.service:ExecStart.0# --flag\n" }
                 },
                 "jobScripts": {
                   "svc.service:ExecStart.0": { "mode": "0755", "name": "svc-start", "text": "#!/nix/store/hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh-bash/bin/bash\necho hi\n" }
                 } }"##,
        );
        let root = tempdir();
        apply(&m, &root, "/etc/aos-job-scripts").unwrap();

        // The job script is written under aos-job-scripts/<key> mode 0755.
        let js = root.join("aos-job-scripts/svc.service:ExecStart.0");
        assert_eq!(
            std::fs::read_to_string(&js).unwrap(),
            "#!/nix/store/hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh-bash/bin/bash\necho hi\n"
        );
        assert_eq!(
            std::fs::metadata(&js).unwrap().permissions().mode() & 0o777,
            0o755
        );

        // The unit body's placeholder is rewritten to the materialized path.
        let unit = std::fs::read_to_string(root.join("systemd/system/svc.service")).unwrap();
        assert!(
            unit.contains("ExecStart=/etc/aos-job-scripts/svc.service:ExecStart.0 --flag"),
            "unit body not rewritten: {unit}"
        );
        assert!(
            !unit.contains("#aos-jobscript:"),
            "placeholder left behind: {unit}"
        );
    }

    #[test]
    fn materializer_omits_image_owned_base_artifacts() {
        let mut manifest = manifest_from(
            r#"{ "schema": "aos.config-manifest/v1",
                 "etc": {
                   "os-release": { "kind": "text", "mode": "0644", "text": "old image\n" },
                   "host.conf": { "kind": "text", "mode": "0644", "text": "retained host\n" }
                 },
                 "jobScripts": {} }"#,
        );
        manifest
            .ownership
            .etc
            .insert("os-release".into(), "@base".into());
        let root = tempdir();
        apply(&manifest, &root, DEFAULT_JOB_SCRIPTS_RUNTIME_DIR).unwrap();

        assert!(!root.join("os-release").exists());
        assert_eq!(
            std::fs::read_to_string(root.join("host.conf")).unwrap(),
            "retained host\n"
        );
    }

    #[test]
    fn is_idempotent_over_reruns() {
        let m = manifest_from(
            r#"{ "schema": "aos.config-manifest/v1",
                 "etc": { "hostname": { "kind": "text", "mode": "0644", "text": "host-a\n" } },
                 "jobScripts": {} }"#,
        );
        let root = tempdir();
        apply(&m, &root, DEFAULT_JOB_SCRIPTS_RUNTIME_DIR).unwrap();
        apply(&m, &root, DEFAULT_JOB_SCRIPTS_RUNTIME_DIR).unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join("hostname")).unwrap(),
            "host-a\n"
        );
    }

    #[test]
    fn text_entry_replaces_an_existing_symlink() {
        // A path that was a symlink in a prior generation and is a text file now
        // must be replaced, not have the write follow the dangling link.
        let root = tempdir();
        std::fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink("/nonexistent", root.join("hostname")).unwrap();
        let m = manifest_from(
            r#"{ "schema": "aos.config-manifest/v1",
                 "etc": { "hostname": { "kind": "text", "mode": "0644", "text": "host-b\n" } },
                 "jobScripts": {} }"#,
        );
        apply(&m, &root, DEFAULT_JOB_SCRIPTS_RUNTIME_DIR).unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join("hostname")).unwrap(),
            "host-b\n"
        );
    }

    #[test]
    fn rejects_job_script_path_traversal() {
        let m = manifest_from(
            r##"{ "schema": "aos.config-manifest/v1", "etc": {},
                  "jobScripts": {
                    "../escape": { "mode": "0755", "name": "escape", "text": "echo escape\n" }
                  } }"##,
        );
        let root = tempdir();
        let error = apply(&m, &root, DEFAULT_JOB_SCRIPTS_RUNTIME_DIR).unwrap_err();
        assert!(error.to_string().contains("invalid jobScripts key"));
        assert!(!root.parent().unwrap().join("escape").exists());
    }

    #[test]
    fn rejects_ancestor_descendant_etc_conflicts() {
        let m = manifest_from(
            r#"{ "schema": "aos.config-manifest/v1",
                 "etc": {
                   "systemd": { "kind": "symlink", "target": "elsewhere" },
                   "systemd/system/x.service": { "kind": "text", "mode": "0644", "text": "x" }
                 },
                 "jobScripts": {} }"#,
        );
        let root = tempdir();
        let error = apply(&m, &root, DEFAULT_JOB_SCRIPTS_RUNTIME_DIR).unwrap_err();
        assert!(error.to_string().contains("is an ancestor"));
    }

    #[test]
    fn rejects_non_adjacent_ancestor_descendant_etc_conflicts() {
        let m = manifest_from(
            r#"{ "schema": "aos.config-manifest/v1",
                 "etc": {
                   "a": { "kind": "symlink", "target": "elsewhere" },
                   "a-escape": { "kind": "text", "mode": "0644", "text": "x" },
                   "a/child": { "kind": "text", "mode": "0644", "text": "x" }
                 },
                 "jobScripts": {} }"#,
        );
        let root = tempdir();
        let error = apply(&m, &root, DEFAULT_JOB_SCRIPTS_RUNTIME_DIR).unwrap_err();
        assert!(error.to_string().contains("is an ancestor"));
    }

    #[test]
    fn refuses_existing_symlink_in_parent_path() {
        let root = tempdir();
        let outside = root.with_extension("outside");
        let _ = std::fs::remove_dir_all(&outside);
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("systemd")).unwrap();
        let m = manifest_from(
            r#"{ "schema": "aos.config-manifest/v1",
                 "etc": {
                   "systemd/system/x.service": { "kind": "text", "mode": "0644", "text": "x" }
                 },
                 "jobScripts": {} }"#,
        );
        let error = apply(&m, &root, DEFAULT_JOB_SCRIPTS_RUNTIME_DIR).unwrap_err();
        assert!(format!("{error:#}").contains("symlink component"));
        assert!(!outside.join("system/x.service").exists());
    }

    #[test]
    fn generation_materializer_rejects_ambient_tool_names() {
        let root = tempdir();
        let manifest_path = root.join("manifest.json");
        std::fs::write(&manifest_path, b"{}").unwrap();
        let error = materialize_generation_lower(
            &manifest_path,
            &root,
            DEFAULT_JOB_SCRIPTS_RUNTIME_DIR,
            Path::new("mkfs.erofs"),
            Path::new("fsck.erofs"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("explicit AOS /nix/store paths"));
    }

    #[test]
    fn generation_materializer_rejects_absolute_host_tools() {
        let root = tempdir();
        let manifest_path = root.join("manifest.json");
        std::fs::write(&manifest_path, b"{}").unwrap();
        let error = materialize_generation_lower(
            &manifest_path,
            &root,
            DEFAULT_JOB_SCRIPTS_RUNTIME_DIR,
            Path::new("/opt/host-tools/mkfs.erofs"),
            Path::new("/opt/host-tools/fsck.erofs"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("explicit AOS /nix/store paths"));
    }

    #[test]
    fn retained_tree_hash_detects_file_mode_and_symlink_tampering() {
        let root = tempdir();
        std::fs::create_dir_all(root.join("systemd/system")).unwrap();
        let unit = root.join("systemd/system/example.service");
        std::fs::write(
            &unit,
            b"[Service]\nExecStart=/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-coreutils/bin/false\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(
            "../example.service",
            root.join("systemd/system/example.target.wants"),
        )
        .unwrap();
        let original = hash_tree(&root).unwrap();

        let mut permissions = std::fs::metadata(&unit).unwrap().permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(&unit, permissions).unwrap();
        assert_ne!(hash_tree(&root).unwrap(), original);

        std::fs::remove_file(root.join("systemd/system/example.target.wants")).unwrap();
        std::os::unix::fs::symlink(
            "../different.service",
            root.join("systemd/system/example.target.wants"),
        )
        .unwrap();
        assert_ne!(hash_tree(&root).unwrap(), original);
    }

    #[test]
    fn stale_stage_symlink_is_removed_without_following_it() {
        let root = tempdir();
        let outside = root.with_extension("stage-target");
        let _ = std::fs::remove_dir_all(&outside);
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("preserved"), b"yes").unwrap();
        let stage = root.join(".config-lower.stage.1");
        std::os::unix::fs::symlink(&outside, &stage).unwrap();

        remove_stage_if_present(&stage).unwrap();

        assert!(!stage.exists());
        assert_eq!(std::fs::read(outside.join("preserved")).unwrap(), b"yes");
    }

    /// Creates a unique temp dir under the process temp root. Avoids a
    /// dev-dependency; the path includes the test thread id for isolation.
    fn tempdir() -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "aos-materialize-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        base
    }
}
