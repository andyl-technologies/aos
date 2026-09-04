//! Nix evaluation and read-only repository binding for maintenance inventory.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read as _;
use std::path::{Component, Path};
use std::process::{Command, Output};

use anyhow::{Context as _, Result, bail};
use aos_contract::{Sha256Digest, canonical};
use aos_core::nix::NixRunner;
use aos_maintain::MAINTENANCE_INVENTORY_ENVELOPE_V1;
use aos_maintain::envelope::{
    ControllerIdentity, GitObjectFormat, GitObjectId, InventoryEnvelopeV1, RepositoryContent,
    TargetEvaluation,
};
use aos_maintain::inventory::MaintenanceInventoryV1;
use aos_maintain::inventory::{Classification, UpdateUnit};
use sha2::{Digest as _, Sha256};
use url::Url;

const MAX_DIRTY_CONTENT_BYTES: usize = 64 * 1024 * 1024;

/// Evaluates and binds one target-specific maintenance inventory.
///
/// # Errors
///
/// Returns an error when Nix evaluation, strict inventory decoding, Git
/// inspection, dirty-content capture, executable hashing, or envelope
/// validation fails.
pub(super) fn evaluate(nix: &NixRunner, target: Option<&str>) -> Result<InventoryEnvelopeV1> {
    let value = nix.eval_json_for_target("maintenanceInventory", target)?;
    let target = match target {
        Some(target) => target.to_string(),
        None => nix
            .eval_expr_json("builtins.currentSystem")?
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| anyhow::anyhow!("builtins.currentSystem did not evaluate to text"))?,
    };
    bind_evaluated(nix.root(), value, target)
}

/// Binds already-confined Nix inventory output to exact repository state.
///
/// # Errors
///
/// Returns an error when strict inventory decoding, Git inspection,
/// dirty-content capture, controller hashing, or envelope validation fails.
pub(super) fn bind_evaluated(
    root: &Path,
    value: serde_json::Value,
    target: String,
) -> Result<InventoryEnvelopeV1> {
    let bytes = canonical::canonical_json(&value)?;
    let inventory = MaintenanceInventoryV1::from_slice(&bytes)?;
    let inventory_digest =
        Sha256Digest::of_canonical(aos_maintain::MAINTENANCE_INVENTORY_V1, &inventory)?;

    let coordinates = repository_coordinates(root)?;
    let repository_root = coordinates.root;
    let common_dir = coordinates.common_dir;
    let remote = coordinates.canonical_remote;

    let object_format =
        match git_text(&repository_root, &["rev-parse", "--show-object-format"])?.as_str() {
            "sha1" => GitObjectFormat::Sha1,
            "sha256" => GitObjectFormat::Sha256,
            other => bail!("unsupported Git object format: {other}"),
        };
    let head = git_object(
        object_format,
        git_text(
            &repository_root,
            &["rev-parse", "--verify", "HEAD^{commit}"],
        )?
        .as_str(),
    )?;
    let status = git(&repository_root, &["status", "--porcelain=v2", "-z"])?;
    if !status.status.success() {
        bail!("Git failed while inspecting working-tree state");
    }
    let content = if status.stdout.is_empty() {
        RepositoryContent::Clean {
            commit: head,
            tree: git_object(
                object_format,
                &git_text(&repository_root, &["rev-parse", "--verify", "HEAD^{tree}"])?,
            )?,
        }
    } else {
        RepositoryContent::Dirty {
            head,
            content_digest: dirty_content_digest(&repository_root, &status.stdout)?,
        }
    };

    let controller = controller_identity()?;
    let envelope = InventoryEnvelopeV1 {
        schema: MAINTENANCE_INVENTORY_ENVELOPE_V1.to_string(),
        canonical_remote: remote,
        repository_root: path_text(&repository_root, "repository root")?,
        git_common_dir: path_text(&common_dir, "Git common directory")?,
        content,
        target_evaluations: vec![TargetEvaluation {
            target,
            inventory_digest,
        }],
        inventory_digest,
        inventory,
        controller,
    };
    envelope.validate()?;
    Ok(envelope)
}

/// Resolves the exact executable and policy identity of this controller.
///
/// # Errors
///
/// Returns an error when the running executable cannot be read or hashed.
pub(super) fn controller_identity() -> Result<ControllerIdentity> {
    Ok(ControllerIdentity {
        version: env!("CARGO_PKG_VERSION").to_string(),
        executable_digest: executable_digest()?,
        policy_digest: Sha256Digest::separated(
            "aos.maintain.controller-policy/v1",
            format!(
                "{}:{}",
                env!("CARGO_PKG_VERSION"),
                aos_maintain::MAINTENANCE_INVENTORY_V1
            ),
        ),
    })
}

/// Audits every schedulable member's direct fixed-output derivation inputs.
///
/// # Errors
///
/// Returns an error when package derivations cannot be evaluated or inspected,
/// or when a reachable direct fixed-output input lacks exactly one declared
/// source/artifact association.
pub(super) fn audit_fixed_outputs(
    nix: &NixRunner,
    envelope: &InventoryEnvelopeV1,
    target: Option<&str>,
) -> Result<usize> {
    let schedulable = envelope
        .inventory
        .units
        .iter()
        .filter(|unit| {
            matches!(
                unit.classification,
                Classification::Automatic | Classification::Assisted
            )
        })
        .collect::<Vec<_>>();
    let members = schedulable
        .iter()
        .flat_map(|unit| unit.members.iter().map(ToString::to_string))
        .collect::<BTreeSet<_>>();
    let member_drvs = members
        .iter()
        .map(|member| {
            let attribute = format!("pkgs.{member}");
            let path = if let Some(target) = target {
                nix.instantiate_for_target(&attribute, target)?
            } else {
                nix.instantiate(&attribute)?
            };
            let path = path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("package derivation path is not UTF-8"))?
                .to_string();
            Ok((member.clone(), path))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;

    let roots = derivation_documents(member_drvs.values())?;
    let mut direct_inputs = BTreeSet::new();
    for member in &members {
        let drv = member_drvs
            .get(member)
            .ok_or_else(|| anyhow::anyhow!("package derivation evaluation omitted {member}"))?;
        direct_inputs.extend(direct_derivation_inputs(&roots, drv)?);
    }
    let inputs = derivation_documents(direct_inputs.iter())?;

    let mut audited = 0_usize;
    for unit in schedulable {
        let declared = declared_fixed_outputs(unit);
        for member in &unit.members {
            let drv = member_drvs
                .get(member.as_str())
                .ok_or_else(|| anyhow::anyhow!("package derivation evaluation omitted {member}"))?;
            let reachable = direct_derivation_inputs(&roots, drv)?
                .into_iter()
                .filter(|input| is_fixed_output(&inputs, input))
                .collect::<BTreeSet<_>>();
            if reachable != declared {
                let undeclared = reachable.difference(&declared).cloned().collect::<Vec<_>>();
                let unreachable = declared.difference(&reachable).cloned().collect::<Vec<_>>();
                bail!(
                    "unit {} member {member} fixed-output audit failed; undeclared={undeclared:?}, declared-but-unreachable={unreachable:?}",
                    unit.unit_id
                );
            }
            audited = audited.saturating_add(reachable.len());
        }
    }
    Ok(audited)
}

fn declared_fixed_outputs(unit: &UpdateUnit) -> BTreeSet<String> {
    let mut declared = unit
        .components
        .values()
        .flat_map(|component| component.sources.values())
        .map(|source| source.derivation.clone())
        .collect::<BTreeSet<_>>();
    declared.extend(
        unit.artifacts
            .values()
            .map(|artifact| artifact.derivation.clone()),
    );
    declared
}

fn derivation_documents<'a>(
    paths: impl IntoIterator<Item = &'a String>,
) -> Result<serde_json::Value> {
    let paths = paths.into_iter().collect::<Vec<_>>();
    if paths.is_empty() {
        return Ok(serde_json::json!({"derivations": {}}));
    }
    let output = Command::new("nix")
        .args(["derivation", "show"])
        .args(paths)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .context("inspecting package derivation inputs")?;
    if !output.status.success() {
        bail!(
            "Nix could not inspect package derivations: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    serde_json::from_slice(&output.stdout).context("decoding Nix derivation inspection")
}

fn derivation<'a>(documents: &'a serde_json::Value, path: &str) -> Result<&'a serde_json::Value> {
    let key = Path::new(path)
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow::anyhow!("derivation identity is not a valid store path"))?;
    let modern = documents
        .get("derivations")
        .and_then(|value| value.get(key));
    let legacy = documents.get(path);
    modern.or(legacy).ok_or_else(|| {
        let available = documents
            .get("derivations")
            .and_then(serde_json::Value::as_object)
            .or_else(|| documents.as_object())
            .map(|derivations| derivations.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        anyhow::anyhow!(
            "Nix omitted inspected derivation {path}; returned derivations={available:?}"
        )
    })
}

fn direct_derivation_inputs(documents: &serde_json::Value, path: &str) -> Result<BTreeSet<String>> {
    let value = derivation(documents, path)?;
    let modern = value
        .pointer("/inputs/drvs")
        .and_then(serde_json::Value::as_object);
    let legacy = value
        .get("inputDrvs")
        .and_then(serde_json::Value::as_object);
    let drvs = modern
        .or(legacy)
        .ok_or_else(|| anyhow::anyhow!("Nix derivation has no typed direct-input map"))?;
    Ok(drvs
        .keys()
        .map(|key| {
            if key.starts_with('/') {
                key.clone()
            } else {
                format!("/nix/store/{key}")
            }
        })
        .collect())
}

fn is_fixed_output(documents: &serde_json::Value, path: &str) -> bool {
    derivation(documents, path)
        .ok()
        .and_then(|value| value.pointer("/env/outputHash"))
        .and_then(serde_json::Value::as_str)
        .is_some_and(|hash| !hash.is_empty())
}

/// Canonical paths and remote identity used to bind local maintenance state.
pub(super) struct RepositoryCoordinates {
    pub(super) root: std::path::PathBuf,
    pub(super) common_dir: std::path::PathBuf,
    pub(super) canonical_remote: String,
}

/// Resolves the repository identity required by read-only cached views.
pub(super) fn repository_coordinates(root: &Path) -> Result<RepositoryCoordinates> {
    let directory = fs::canonicalize(root)
        .with_context(|| format!("resolving repository root {}", root.display()))?;
    let root = fs::canonicalize(git_text(&directory, &["rev-parse", "--show-toplevel"])?)
        .context("resolving Git worktree root")?;
    let common_dir = git_text(
        &root,
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
    )?;
    let common_dir = fs::canonicalize(&common_dir)
        .with_context(|| format!("resolving Git common directory {common_dir}"))?;
    let canonical_remote = canonical_remote(&git_text(&root, &["remote", "get-url", "origin"])?)?;
    Ok(RepositoryCoordinates {
        root,
        common_dir,
        canonical_remote,
    })
}

fn git_object(algorithm: GitObjectFormat, value: &str) -> Result<GitObjectId> {
    let object = GitObjectId {
        algorithm,
        value: value.to_string(),
    };
    object.validate()?;
    Ok(object)
}

fn canonical_remote(value: &str) -> Result<String> {
    if let Some(path) = value.strip_prefix("git@github.com:") {
        return github_remote(path);
    }

    let mut remote = Url::parse(value).context("parsing canonical Git remote")?;
    if remote.scheme() == "ssh" && remote.host_str() == Some("github.com") {
        return github_remote(remote.path().trim_start_matches('/'));
    }
    if remote.scheme() != "https" || !remote.username().is_empty() || remote.password().is_some() {
        bail!("origin must be an uncredentialed HTTPS or GitHub SSH remote");
    }
    remote.set_fragment(None);
    remote.set_query(None);
    if remote.host_str() == Some("github.com") {
        return github_remote(remote.path().trim_start_matches('/'));
    }
    Ok(remote.to_string())
}

fn github_remote(path: &str) -> Result<String> {
    if path.is_empty()
        || path.starts_with('/')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        bail!("GitHub origin has an invalid repository path");
    }
    Ok(format!(
        "https://github.com/{}",
        path.strip_suffix(".git").unwrap_or(path)
    ))
}

fn dirty_content_digest(root: &Path, status: &[u8]) -> Result<Sha256Digest> {
    let diff = git(root, &["diff", "--binary", "--full-index", "HEAD", "--"])?;
    if !diff.status.success() {
        bail!("Git failed while capturing tracked dirty content");
    }
    let untracked = git(root, &["ls-files", "--others", "--exclude-standard", "-z"])?;
    if !untracked.status.success() {
        bail!("Git failed while enumerating untracked content");
    }

    let mut bytes = Vec::new();
    append_bounded(&mut bytes, b"status\0", status)?;
    append_bounded(&mut bytes, b"diff\0", &diff.stdout)?;
    for encoded in untracked.stdout.split(|byte| *byte == 0) {
        if encoded.is_empty() {
            continue;
        }
        let relative = std::str::from_utf8(encoded).context("untracked path is not UTF-8")?;
        let path = safe_repository_path(root, relative)?;
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("inspecting untracked path {relative}"))?;
        append_bounded(&mut bytes, b"path\0", encoded)?;
        if metadata.file_type().is_symlink() {
            let target = fs::read_link(&path)
                .with_context(|| format!("reading untracked symlink {relative}"))?;
            let target = target
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("untracked symlink target is not UTF-8"))?;
            append_bounded(&mut bytes, b"symlink\0", target.as_bytes())?;
        } else if metadata.is_file() {
            let content =
                fs::read(&path).with_context(|| format!("reading untracked file {relative}"))?;
            append_bounded(&mut bytes, b"file\0", &content)?;
        } else {
            bail!("untracked path has unsupported file type: {relative}");
        }
    }
    Ok(Sha256Digest::separated(
        "aos.maintain.dirty-content/v1",
        bytes,
    ))
}

fn append_bounded(output: &mut Vec<u8>, label: &[u8], value: &[u8]) -> Result<()> {
    let required = label
        .len()
        .checked_add(8)
        .and_then(|size| size.checked_add(value.len()))
        .ok_or_else(|| anyhow::anyhow!("dirty content size overflow"))?;
    if output.len().saturating_add(required) > MAX_DIRTY_CONTENT_BYTES {
        bail!("dirty content exceeds {MAX_DIRTY_CONTENT_BYTES} bytes");
    }
    output.extend_from_slice(label);
    output.extend_from_slice(
        &u64::try_from(value.len())
            .map_err(|error| anyhow::anyhow!("dirty content length overflow: {error}"))?
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
    Ok(())
}

fn safe_repository_path(root: &Path, relative: &str) -> Result<std::path::PathBuf> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::CurDir | Component::RootDir
            )
        })
    {
        bail!("Git returned an unsafe repository-relative path");
    }
    Ok(root.join(path))
}

fn executable_digest() -> Result<Sha256Digest> {
    let path = std::env::current_exe().context("resolving current AOS executable")?;
    let mut file = File::open(&path)
        .with_context(|| format!("opening current AOS executable {}", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(Sha256Digest::from_bytes(digest.finalize().into()))
}

fn path_text(path: &Path, label: &str) -> Result<String> {
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("{label} is not UTF-8"))
}

fn git_text(root: &Path, arguments: &[&str]) -> Result<String> {
    let output = git(root, arguments)?;
    if !output.status.success() {
        bail!("Git command failed: git {}", arguments.join(" "));
    }
    String::from_utf8(output.stdout)
        .context("Git output is not UTF-8")
        .map(|text| text.trim_end().to_string())
}

fn git(root: &Path, arguments: &[&str]) -> Result<Output> {
    Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .with_context(|| format!("running git {}", arguments.join(" ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_supported_github_remotes() {
        assert_eq!(
            canonical_remote("git@github.com:andyl-technologies/aos.git")
                .expect("SCP-style GitHub remote should be supported"),
            "https://github.com/andyl-technologies/aos"
        );
        assert_eq!(
            canonical_remote("ssh://git@github.com/andyl-technologies/aos")
                .expect("SSH GitHub remote should be supported"),
            "https://github.com/andyl-technologies/aos"
        );
        assert_eq!(
            canonical_remote("https://github.com/andyl-technologies/aos.git?ignored=yes#fragment")
                .expect("uncredentialed HTTPS remote should be supported"),
            "https://github.com/andyl-technologies/aos"
        );
    }

    #[test]
    fn rejects_credentialed_or_unsafe_remotes() {
        assert!(canonical_remote("https://token@github.com/example/repo.git").is_err());
        assert!(canonical_remote("git@github.com:example/../repo.git").is_err());
    }

    #[test]
    fn rejects_paths_that_can_escape_the_repository() {
        let root = Path::new("/workspace");
        assert!(safe_repository_path(root, "../secret").is_err());
        assert!(safe_repository_path(root, "/absolute").is_err());
        assert_eq!(
            safe_repository_path(root, "pkgs/zlib.nix")
                .expect("normal repository path should be accepted"),
            root.join("pkgs/zlib.nix")
        );
    }

    #[test]
    fn parses_structured_nix_derivation_inputs_and_fixed_output_identity() -> Result<()> {
        let documents = serde_json::json!({
            "derivations": {
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-package.drv": {
                    "inputs": {"drvs": {
                        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-source.drv": {
                            "dynamicOutputs": {}, "outputs": ["out"]
                        }
                    }},
                    "env": {}
                },
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-source.drv": {
                    "inputs": {"drvs": {}},
                    "env": {"outputHash": "sha256-value", "outputHashMode": "flat"}
                }
            }
        });
        let package = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-package.drv";
        let source = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-source.drv";
        assert_eq!(
            direct_derivation_inputs(&documents, package)?,
            BTreeSet::from([source.to_string()])
        );
        assert!(is_fixed_output(&documents, source));
        assert!(!is_fixed_output(&documents, package));
        Ok(())
    }

    #[test]
    fn parses_legacy_nix_derivation_inputs_and_fixed_output_identity() -> Result<()> {
        let package = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-package.drv";
        let source = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-source.drv";
        let documents = serde_json::json!({
            (package): {
                "inputDrvs": {
                    (source): {"dynamicOutputs": {}, "outputs": ["out"]}
                },
                "env": {}
            },
            (source): {
                "inputDrvs": {},
                "env": {"outputHash": "sha256-value", "outputHashMode": "flat"}
            }
        });
        assert_eq!(
            direct_derivation_inputs(&documents, package)?,
            BTreeSet::from([source.to_string()])
        );
        assert!(is_fixed_output(&documents, source));
        assert!(!is_fixed_output(&documents, package));
        Ok(())
    }
}
