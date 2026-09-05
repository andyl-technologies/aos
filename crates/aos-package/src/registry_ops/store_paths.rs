//! Nix store introspection, release-policy checks, and realisation graph publication.

use crate::platform::native_platform;
use crate::registry::store;
use crate::registry::store::{DepEdge, NarBytes, Realisation, UpsertOutcome};
use crate::types::{package_name_bucket, validate_platform_name};
use anyhow::{Context, Result, bail};
use aos_core::nix::aos_nix_env;
use aos_core::output::Printer;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::process::Command;

/// Build a `nix`/`nix-store` command with the AOS Nix environment applied.
pub(in crate::registry_ops) fn nix_command(program: &str) -> Command {
    let mut command = Command::new(program);
    command.envs(aos_nix_env());
    command
}

/// Parse a Nix store path into (name, version).
///
/// Format: `/nix/store/{hash}-{name}-{version}`
pub(in crate::registry_ops) fn parse_store_path(store_path: &str) -> (String, String) {
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
pub(in crate::registry_ops) fn first_letter(name: &str) -> String {
    package_name_bucket(name)
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
pub(in crate::registry_ops) fn introspect_store_path(store_path: &str) -> Result<StorePathInfo> {
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
pub(in crate::registry_ops) fn introspect_deriver(
    store_path: &str,
) -> Result<Option<StorePathInfo>> {
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
pub(in crate::registry_ops) fn store_dir_from_store_path(path: &str) -> Option<&str> {
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
pub(in crate::registry_ops) struct StorePathInfo {
    pub(in crate::registry_ops) path: String,
    pub(in crate::registry_ops) nar_hash: String,
    pub(in crate::registry_ops) nar_size: u64,
    pub(in crate::registry_ops) references: Vec<String>,
    pub(in crate::registry_ops) closure_size: u64,
}

pub(in crate::registry_ops) const RELEASE_POLICY_RELATIVE_PATH: &str =
    "nix-support/aos-release-policy";

pub(in crate::registry_ops) const TARGET_PLATFORM_RELATIVE_PATH: &str =
    "nix-support/aos-target-platform";

/// Resolves the platform a store output is published for.
///
/// New AOS derivations stamp their canonical target platform in
/// `nix-support/aos-target-platform`. An explicit producer override must agree
/// with that stamp, preventing a Linux-hosted Darwin cross build from being
/// mislabeled in registry metadata. Outputs created before the stamp existed
/// retain the native-platform default.
pub(in crate::registry_ops) fn resolve_publish_platform(
    store_path: &str,
    platform_override: Option<&str>,
) -> Result<String> {
    let marker = Path::new(store_path).join(TARGET_PLATFORM_RELATIVE_PATH);
    let marker_exists = marker
        .try_exists()
        .with_context(|| format!("checking target platform marker {}", marker.display()))?;
    let stamped = if marker_exists {
        let platform = fs::read_to_string(&marker)
            .with_context(|| format!("reading target platform marker {}", marker.display()))?
            .trim()
            .to_string();
        validate_platform_name(&platform)
            .with_context(|| format!("invalid target platform marker {}", marker.display()))?;
        Some(platform)
    } else {
        None
    };

    if let Some(platform_override) = platform_override {
        validate_platform_name(platform_override)?;
        if let Some(stamped) = stamped.as_deref()
            && stamped != platform_override
        {
            bail!(
                "--platform '{platform_override}' disagrees with target platform marker '{stamped}' in {}",
                marker.display()
            );
        }
        return Ok(platform_override.to_string());
    }

    Ok(stamped.unwrap_or_else(native_platform))
}

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

pub(in crate::registry_ops) fn validate_store_path_release_policy(
    info: &StorePathInfo,
) -> Result<()> {
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
pub(in crate::registry_ops) fn extract_hash(store_path: &str) -> &str {
    let basename = store_path.rsplit('/').next().unwrap_or(store_path);
    basename.split('-').next().unwrap_or(basename)
}

/// Per-member NAR metadata for a runtime closure.
pub(in crate::registry_ops) struct ClosureMemberNar {
    pub(in crate::registry_ops) path: String,
    pub(in crate::registry_ops) nar_hash: String,
    pub(in crate::registry_ops) nar_size: u64,
}

/// Introspects every member of a store path's runtime closure.
pub(in crate::registry_ops) fn introspect_closure_nars(
    store_path: &str,
) -> Result<Vec<ClosureMemberNar>> {
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
pub(in crate::registry_ops) struct StoreWriteReport {
    /// Paths that gained their first record.
    pub(in crate::registry_ops) created: usize,
    /// Paths that gained an additional realisation.
    pub(in crate::registry_ops) blessed: usize,
    /// Paths whose realisation was already present, unchanged.
    pub(in crate::registry_ops) unchanged: usize,
    /// Whether content addresses were filled.
    pub(in crate::registry_ops) content_addressed: bool,
}

impl StoreWriteReport {
    pub(in crate::registry_ops) fn merge(&mut self, other: StoreWriteReport) {
        self.created += other.created;
        self.blessed += other.blessed;
        self.unchanged += other.unchanged;
        self.content_addressed |= other.content_addressed;
    }

    pub(in crate::registry_ops) fn summary(&self) -> String {
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
pub(in crate::registry_ops) fn write_store_files(
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
pub(in crate::registry_ops) fn collect_package_store_paths(dir: &Path) -> Result<Vec<String>> {
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

#[cfg(test)]
mod tests;
