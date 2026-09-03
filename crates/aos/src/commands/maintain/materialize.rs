//! Bounded source hashing and deterministic attempt-zero mutation.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;

use anyhow::{Context as _, Result, bail};
use aos_contract::Sha256Digest;
use aos_core::nix::NixRunner;
use aos_maintain::PACKAGE_UPDATE_MATERIALIZATION_V1;
use aos_maintain::identity::ArtifactSlotId;
use aos_maintain::plan::{
    ArtifactIntent, PackageUpdatePlanV1, PackageUpdateUnitPlan, SemanticMutation, SourceIntent,
};
use aos_maintain::run::{
    MaterializationRecordV1, MaterializedArtifact, MaterializedSource, PackageUpdateRunV1,
    SourceAssuranceOutcome,
};
use aos_maintain::workflow::{ActorClass, RunState};
use base64::Engine as _;
use futures_util::StreamExt as _;
use sha2::{Digest as _, Sha256};
use url::Url;

use super::state::{self, StateStore};
use super::{inventory, mutation};

const MAX_SOURCE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_PATCH_BYTES: usize = 32 * 1024 * 1024;
const MAX_MATERIALIZER_LOG_BYTES: usize = 8 * 1024 * 1024;
const FAKE_HASH: &str = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

/// Advances a worktree-ready run through deterministic materialization.
///
/// # Errors
///
/// Returns an error for ambiguous interrupted state, unsafe redirects, source
/// transfer failure, semantic compare-and-swap failure, out-of-scope diff, or
/// post-mutation inventory mismatch.
pub(super) async fn execute(
    store: &StateStore,
    plan: &PackageUpdatePlanV1,
    run: &mut PackageUpdateRunV1,
    verbose: u8,
    quiet: bool,
) -> Result<MaterializationRecordV1> {
    if matches!(run.state, RunState::PolicyValid | RunState::QuickGated) {
        return verified_record(store, run);
    }
    if !matches!(run.state, RunState::WorktreeReady | RunState::Materializing) {
        bail!("run is not at a deterministic materialization boundary");
    }
    let root = std::path::PathBuf::from(&run.worktree);
    if let Some(record) = store.read_materialization(run.run_id.as_str())? {
        verify_recorded_patch(&root, &record)?;
        if run.state == RunState::Materializing {
            store.transition(
                run,
                RunState::PolicyValid,
                ActorClass::Controller,
                state::now_unix()?,
            )?;
        }
        return Ok(record);
    }
    ensure_clean_base(&root, plan, &run.branch)?;
    if run.state == RunState::WorktreeReady {
        store.transition(
            run,
            RunState::Materializing,
            ActorClass::Controller,
            state::now_unix()?,
        )?;
    }

    let mut sources = Vec::new();
    let mut unit_mutations = Vec::with_capacity(plan.units.len());
    for unit in &plan.units {
        let resolved = resolve_sources(store, unit).await?;
        let mut mutations = unit.semantic_mutations.clone();
        for source in &resolved {
            let intent = unit
                .sources
                .iter()
                .find(|intent| intent.component == source.component && intent.slot == source.slot)
                .ok_or_else(|| anyhow::anyhow!("resolved source was not authorized by the plan"))?;
            mutations.push(SemanticMutation {
                owner: mutation_owner(unit)?.to_string(),
                field_path: vec![
                    "components".to_string(),
                    source.component.to_string(),
                    "sources".to_string(),
                    source.slot.to_string(),
                    "hash".to_string(),
                ],
                expected: intent.expected_hash.clone(),
                replacement: source.hash.clone(),
            });
        }
        sources.extend(resolved);
        unit_mutations.push((unit, mutations));
    }
    let mutations = unit_mutations
        .iter()
        .flat_map(|(_, mutations)| mutations.iter().cloned())
        .collect::<Vec<_>>();
    let originals = capture_owner_files(&root, &mutations)?;
    let materialized = (|| {
        for (unit, mutations) in &unit_mutations {
            apply_mutations(&root, unit.unit_id.as_str(), mutations)?;
        }
        let mut artifacts = Vec::new();
        for unit in &plan.units {
            artifacts.extend(resolve_artifacts(&root, unit, verbose, quiet)?);
        }
        verify_post_inventory(&root, plan, verbose, quiet)?;
        verify_post_artifacts(&root, plan, &artifacts, verbose, quiet)?;
        Ok::<_, anyhow::Error>(artifacts)
    })();
    let artifacts = match materialized {
        Ok(artifacts) => artifacts,
        Err(error) => {
            restore_owner_files(&originals)?;
            return Err(error);
        }
    };
    let (patch, changed_paths) = checked_patch(&root, plan)?;
    let record = MaterializationRecordV1 {
        schema: PACKAGE_UPDATE_MATERIALIZATION_V1.to_string(),
        run_id: run.run_id.clone(),
        plan_id: plan.plan_id.clone(),
        attempt: 0,
        sources,
        artifacts,
        patch_digest: Sha256Digest::separated("aos.package-update-patch/v1", &patch),
        changed_paths,
        completed_at_unix: state::now_unix()?,
    };
    record.validate()?;
    store.write_materialization(&record, &patch)?;
    store.transition(
        run,
        RunState::PolicyValid,
        ActorClass::Controller,
        state::now_unix()?,
    )?;
    Ok(record)
}

fn resolve_artifacts(
    root: &Path,
    unit: &PackageUpdateUnitPlan,
    verbose: u8,
    quiet: bool,
) -> Result<Vec<MaterializedArtifact>> {
    let mut output = Vec::with_capacity(unit.artifacts.len());
    for intent in &unit.artifacts {
        if !intent.outputs.is_empty() {
            bail!(
                "artifact {} declares repository outputs unsupported by this controller",
                intent.slot
            );
        }
        apply_artifact_hash(root, unit, intent, &intent.expected_hash, FAKE_HASH)?;
        let derivation = evaluated_artifact_derivation(root, unit, &intent.slot, verbose, quiet)?;
        if derivation == intent.expected_derivation {
            bail!(
                "artifact {} did not bind the updated source graph",
                intent.slot
            );
        }
        let hash = realize_artifact(&derivation)?;
        apply_artifact_hash(root, unit, intent, FAKE_HASH, &hash)?;
        output.push(MaterializedArtifact {
            unit_id: unit.unit_id.clone(),
            slot: intent.slot.clone(),
            derivation,
            expected_hash: intent.expected_hash.clone(),
            hash,
        });
    }
    Ok(output)
}

fn apply_artifact_hash(
    root: &Path,
    unit: &PackageUpdateUnitPlan,
    intent: &ArtifactIntent,
    expected: &str,
    replacement: &str,
) -> Result<()> {
    apply_mutations(
        root,
        unit.unit_id.as_str(),
        &[SemanticMutation {
            owner: mutation_owner(unit)?.to_string(),
            field_path: vec![
                "artifacts".to_string(),
                intent.slot.to_string(),
                "hash".to_string(),
            ],
            expected: expected.to_string(),
            replacement: replacement.to_string(),
        }],
    )
}

fn evaluated_artifact_derivation(
    root: &Path,
    unit_plan: &PackageUpdateUnitPlan,
    slot: &ArtifactSlotId,
    verbose: u8,
    quiet: bool,
) -> Result<String> {
    let runner = NixRunner::for_root(root, verbose, quiet)?;
    let envelope = inventory::evaluate(&runner, None)?;
    let unit = envelope
        .inventory
        .units
        .iter()
        .find(|unit| unit.unit_id == unit_plan.unit_id)
        .ok_or_else(|| anyhow::anyhow!("updated unit disappeared from inventory"))?;
    let member = unit
        .members
        .first()
        .ok_or_else(|| anyhow::anyhow!("updated unit has no package member"))?;
    instantiate_member(root, member.as_str())?;
    unit.artifacts
        .get(slot)
        .map(|artifact| artifact.derivation.clone())
        .ok_or_else(|| anyhow::anyhow!("updated artifact {slot} disappeared from inventory"))
}

fn instantiate_member(root: &Path, member: &str) -> Result<()> {
    let mut command = Command::new("nix-instantiate");
    command
        .arg(root.join("default.nix"))
        .args(["-A", &format!("pkgs.{member}")])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let (status, _stdout, stderr, truncated) = bounded_output(command)?;
    if truncated || !status.success() {
        let detail = String::from_utf8_lossy(&stderr);
        bail!(
            "Nix could not instantiate artifact owner {member}: {}",
            detail.trim()
        );
    }
    Ok(())
}

fn realize_artifact(derivation: &str) -> Result<String> {
    let mut command = Command::new("nix-store");
    command
        .args(["--realise", derivation])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let (status, _stdout, stderr, truncated) = bounded_output(command)?;
    if truncated {
        bail!("artifact materializer diagnostics exceeded the bounded log limit");
    }
    if status.success() {
        bail!("artifact materializer unexpectedly accepted the controller fake hash");
    }
    parse_hash_mismatch(&stderr)
}

fn parse_hash_mismatch(stderr: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(stderr)
        .context("artifact materializer emitted non-UTF-8 diagnostics")?;
    let hashes = text
        .lines()
        .filter_map(|line| line.trim().strip_prefix("got:"))
        .map(str::trim)
        .filter(|value| value.starts_with("sha256-") && value.len() <= 128)
        .collect::<BTreeSet<_>>();
    if hashes.len() != 1 {
        bail!("artifact materializer failed without one unambiguous SRI SHA-256 mismatch");
    }
    hashes
        .first()
        .map(|value| (*value).to_string())
        .ok_or_else(|| anyhow::anyhow!("artifact materializer hash disappeared"))
}

fn bounded_output(
    mut command: Command,
) -> Result<(std::process::ExitStatus, Vec<u8>, Vec<u8>, bool)> {
    let mut child = command.spawn().context("spawning artifact materializer")?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("artifact stdout was not captured"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("artifact stderr was not captured"))?;
    let stdout_reader = std::thread::spawn(move || bounded_read(stdout));
    let stderr_reader = std::thread::spawn(move || bounded_read(stderr));
    let status = child.wait().context("waiting for artifact materializer")?;
    let (stdout, stdout_truncated) = stdout_reader
        .join()
        .map_err(|_| anyhow::anyhow!("artifact stdout reader panicked"))??;
    let (stderr, stderr_truncated) = stderr_reader
        .join()
        .map_err(|_| anyhow::anyhow!("artifact stderr reader panicked"))??;
    Ok((status, stdout, stderr, stdout_truncated || stderr_truncated))
}

fn bounded_read(mut reader: impl std::io::Read) -> Result<(Vec<u8>, bool)> {
    let mut retained = Vec::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut truncated = false;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let remaining = MAX_MATERIALIZER_LOG_BYTES.saturating_sub(retained.len());
        let accepted = remaining.min(count);
        retained.extend_from_slice(&buffer[..accepted]);
        truncated |= accepted < count;
    }
    Ok((retained, truncated))
}

fn mutation_owner(unit: &PackageUpdateUnitPlan) -> Result<&str> {
    let owners = unit
        .semantic_mutations
        .iter()
        .map(|mutation| mutation.owner.as_str())
        .collect::<BTreeSet<_>>();
    if owners.len() != 1 {
        bail!("generated artifacts require exactly one package-contract owner");
    }
    owners
        .first()
        .copied()
        .ok_or_else(|| anyhow::anyhow!("plan has no package-contract owner"))
}

fn capture_owner_files(
    root: &Path,
    mutations: &[SemanticMutation],
) -> Result<Vec<(std::path::PathBuf, u32, Vec<u8>)>> {
    let mut output = Vec::new();
    for owner in mutations
        .iter()
        .map(|mutation| mutation.owner.as_str())
        .collect::<BTreeSet<_>>()
    {
        let path = root.join(owner);
        let metadata = path
            .symlink_metadata()
            .with_context(|| format!("inspecting package owner {owner}"))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            bail!("package owner {owner} is not a regular non-symlink file");
        }
        output.push((path.clone(), metadata.permissions().mode(), fs::read(path)?));
    }
    Ok(output)
}

fn restore_owner_files(originals: &[(std::path::PathBuf, u32, Vec<u8>)]) -> Result<()> {
    for (path, mode, contents) in originals {
        replace_file(path, *mode, contents)
            .with_context(|| format!("restoring package owner {}", path.display()))?;
    }
    Ok(())
}

async fn resolve_sources(
    store: &StateStore,
    unit: &PackageUpdateUnitPlan,
) -> Result<Vec<MaterializedSource>> {
    let mut output = Vec::with_capacity(unit.sources.len());
    for source in &unit.sources {
        let materialized = resolve_source(&unit.unit_id, source).await?;
        let identity = format!(
            "{}\0{}\0{}\0{}",
            unit.unit_id, source.component, source.slot, source.upstream_id
        );
        store.record_source_identity(&identity, &materialized.hash)?;
        output.push(materialized);
    }
    Ok(output)
}

async fn resolve_source(
    unit_id: &aos_maintain::identity::UnitId,
    intent: &SourceIntent,
) -> Result<MaterializedSource> {
    let mut last_error = None;
    for requested in &intent.urls {
        match hash_url(requested, &intent.allowed_redirect_hosts).await {
            Ok((hash, bytes, final_url)) => {
                return Ok(MaterializedSource {
                    unit_id: unit_id.clone(),
                    component: intent.component.clone(),
                    slot: intent.slot.clone(),
                    upstream_id: intent.upstream_id.clone(),
                    requested_url: requested.clone(),
                    final_url,
                    hash,
                    bytes,
                    assurance: SourceAssuranceOutcome::OriginIntegrity,
                });
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("source intent has no usable URL")))
}

async fn hash_url(url: &str, redirect_hosts: &[String]) -> Result<(String, u64, String)> {
    let parsed = Url::parse(url).context("parsing planned source URL")?;
    let initial_host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("planned source URL has no host"))?
        .to_ascii_lowercase();
    let mut hosts = redirect_hosts.iter().cloned().collect::<BTreeSet<_>>();
    hosts.insert(initial_host);
    let hosts = Arc::new(hosts);
    let policy_hosts = Arc::clone(&hosts);
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::custom(move |attempt| {
            let target = attempt.url();
            if attempt.previous().len() >= 10 {
                return attempt.error("source redirect limit exceeded");
            }
            let safe = target.scheme() == "https"
                && target.username().is_empty()
                && target.password().is_none()
                && target
                    .host_str()
                    .is_some_and(|host| policy_hosts.contains(&host.to_ascii_lowercase()));
            if safe {
                attempt.follow()
            } else {
                attempt.error("source redirect escaped its planned HTTPS host allowlist")
            }
        }))
        .user_agent("aos-maintain/0.1 (+https://github.com/andyl-technologies/aos/issues)")
        .build()?;
    let response = client.get(parsed).send().await?.error_for_status()?;
    if response
        .content_length()
        .is_some_and(|size| size > MAX_SOURCE_BYTES)
    {
        bail!("source response exceeds the materialization byte limit");
    }
    let final_url = response.url().to_string();
    let mut stream = response.bytes_stream();
    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        bytes = bytes
            .checked_add(u64::try_from(chunk.len()).context("source chunk length overflow")?)
            .ok_or_else(|| anyhow::anyhow!("source response length overflow"))?;
        if bytes > MAX_SOURCE_BYTES {
            bail!("source response exceeds the materialization byte limit");
        }
        hasher.update(&chunk);
    }
    let digest = base64::engine::general_purpose::STANDARD.encode(hasher.finalize());
    Ok((format!("sha256-{digest}"), bytes, final_url))
}

fn apply_mutations(root: &Path, unit_id: &str, mutations: &[SemanticMutation]) -> Result<()> {
    if mutations.is_empty() {
        bail!("materialization has no semantic mutations");
    }

    let mut by_owner = BTreeMap::<&str, Vec<SemanticMutation>>::new();
    for mutation in mutations {
        by_owner
            .entry(mutation.owner.as_str())
            .or_default()
            .push(mutation.clone());
    }

    // Compute and format every replacement before changing the worktree. This
    // makes compare-and-swap and parse failures atomic across multi-file units.
    let mut staged = Vec::with_capacity(by_owner.len());
    for (owner, owner_mutations) in by_owner {
        let path = root.join(owner);
        let metadata = path
            .symlink_metadata()
            .with_context(|| format!("inspecting package owner {owner}"))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            bail!("package owner {owner} is not a regular non-symlink file");
        }
        let original =
            fs::read_to_string(&path).with_context(|| format!("reading package owner {owner}"))?;
        let updated = mutation::apply(&original, unit_id, &owner_mutations)?;
        let (status, formatted) = alejandra::format::in_memory(owner.to_string(), updated);
        if let alejandra::format::Status::Error(error) = status {
            bail!("formatting package owner {owner} failed: {error}")
        }
        staged.push((path, metadata.permissions().mode(), original, formatted));
    }

    let mut replaced = 0_usize;
    for (path, mode, _, formatted) in &staged {
        if let Err(error) = replace_file(path, *mode, formatted.as_bytes()) {
            for (rollback_path, rollback_mode, original, _) in staged[..replaced].iter().rev() {
                replace_file(rollback_path, *rollback_mode, original.as_bytes()).with_context(
                    || format!("rolling back package owner {}", rollback_path.display()),
                )?;
            }
            return Err(error)
                .with_context(|| format!("replacing package owner {}", path.display()));
        }
        replaced += 1;
    }
    Ok(())
}

fn replace_file(path: &Path, mode: u32, contents: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("package owner has no parent"))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary
        .as_file_mut()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    temporary.write_all(contents)?;
    temporary.as_file_mut().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    sync_directory(parent)
}

fn sync_directory(path: &Path) -> Result<()> {
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

pub(super) fn verify_post_inventory(
    root: &Path,
    plan: &PackageUpdatePlanV1,
    verbose: u8,
    quiet: bool,
) -> Result<()> {
    let runner = NixRunner::for_root(root, verbose, quiet)?;
    let envelope = inventory::evaluate(&runner, None)?;
    for unit_plan in &plan.units {
        let unit = envelope
            .inventory
            .units
            .iter()
            .find(|unit| unit.unit_id == unit_plan.unit_id)
            .ok_or_else(|| {
                anyhow::anyhow!("updated unit disappeared from maintenance inventory")
            })?;
        let package = unit
            .package
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("updated package projection disappeared"))?;
        if package.current_version != unit_plan.target_package_version {
            bail!("updated package version does not match the planned projection");
        }
        for (component_id, target) in &unit_plan.component_targets {
            let component = unit
                .components
                .get(component_id)
                .ok_or_else(|| anyhow::anyhow!("updated component disappeared"))?;
            if &component.current != target {
                bail!("updated component vector does not match the plan");
            }
        }
    }
    Ok(())
}

fn verify_post_artifacts(
    root: &Path,
    plan: &PackageUpdatePlanV1,
    materialized: &[MaterializedArtifact],
    verbose: u8,
    quiet: bool,
) -> Result<()> {
    let runner = NixRunner::for_root(root, verbose, quiet)?;
    let envelope = inventory::evaluate(&runner, None)?;
    let expected = plan
        .units
        .iter()
        .map(|unit| unit.artifacts.len())
        .sum::<usize>();
    if materialized.len() != expected {
        bail!("materialized artifact set is incomplete");
    }
    for resolved in materialized {
        let unit = envelope
            .inventory
            .units
            .iter()
            .find(|unit| unit.unit_id == resolved.unit_id)
            .ok_or_else(|| {
                anyhow::anyhow!("updated unit disappeared from maintenance inventory")
            })?;
        let artifact = unit
            .artifacts
            .get(&resolved.slot)
            .ok_or_else(|| anyhow::anyhow!("updated artifact {} disappeared", resolved.slot))?;
        if artifact.hash != resolved.hash {
            bail!(
                "updated artifact {} hash does not match materialization evidence",
                resolved.slot
            );
        }
    }
    Ok(())
}

fn checked_patch(root: &Path, plan: &PackageUpdatePlanV1) -> Result<(Vec<u8>, Vec<String>)> {
    let names = git(root, &["diff", "--name-only", "-z", "--"])?;
    if !names.status.success() {
        bail!("Git could not enumerate the materialized diff");
    }
    let changed_paths = names
        .stdout
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| String::from_utf8(entry.to_vec()).context("changed path is not UTF-8"))
        .collect::<Result<Vec<_>>>()?;
    let owners = plan
        .units
        .iter()
        .flat_map(|unit| unit.semantic_mutations.iter())
        .map(|mutation| mutation.owner.clone())
        .collect::<BTreeSet<_>>();
    if changed_paths.iter().cloned().collect::<BTreeSet<_>>() != owners {
        bail!("deterministic materialization changed a path outside the plan");
    }
    let summary = git(root, &["diff", "--summary", "--"])?;
    if !summary.status.success() || !summary.stdout.is_empty() {
        bail!("deterministic materialization changed a file mode, kind, or path identity");
    }
    let numstat = git(root, &["diff", "--numstat", "--"])?;
    if !numstat.status.success() || numstat.stdout.windows(2).any(|pair| pair == b"-\t") {
        bail!("binary materialization diffs are forbidden");
    }
    let patch = git(root, &["diff", "--no-ext-diff", "--full-index", "--"])?;
    if !patch.status.success() || patch.stdout.len() > MAX_PATCH_BYTES {
        bail!("materialization patch is unavailable or oversized");
    }
    Ok((patch.stdout, changed_paths))
}

fn ensure_clean_base(root: &Path, plan: &PackageUpdatePlanV1, branch: &str) -> Result<()> {
    let status = git(root, &["status", "--porcelain=v2", "-z"])?;
    let head = git_text(root, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    let current_branch = git_text(root, &["branch", "--show-current"])?;
    if !status.status.success()
        || !status.stdout.is_empty()
        || head != plan.base_commit.value
        || current_branch != branch
    {
        bail!("worktree contains unrecorded changes or no longer matches the plan base");
    }
    Ok(())
}

fn verified_record(
    store: &StateStore,
    run: &PackageUpdateRunV1,
) -> Result<MaterializationRecordV1> {
    let record = store
        .read_materialization(run.run_id.as_str())?
        .ok_or_else(|| anyhow::anyhow!("run state has no matching materialization evidence"))?;
    verify_recorded_patch(Path::new(&run.worktree), &record)?;
    Ok(record)
}

fn verify_recorded_patch(root: &Path, record: &MaterializationRecordV1) -> Result<()> {
    let patch = git(root, &["diff", "--no-ext-diff", "--full-index", "--"])?;
    if !patch.status.success()
        || Sha256Digest::separated("aos.package-update-patch/v1", &patch.stdout)
            != record.patch_digest
    {
        bail!("worktree diff no longer matches the recorded deterministic attempt");
    }
    Ok(())
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

fn git(root: &Path, arguments: &[&str]) -> Result<std::process::Output> {
    std::process::Command::new("git")
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
    use anyhow::Result;

    use super::{FAKE_HASH, parse_hash_mismatch};

    #[test]
    fn redirect_allowlist_rejects_invalid_host_shapes() {
        let invalid = [".example.org", "example.org.", "EXAMPLE.org", "example/org"];
        for host in invalid {
            assert!(
                !host.bytes().all(|byte| byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b'.'))
                    || host.starts_with('.')
                    || host.ends_with('.')
            );
        }
    }

    #[test]
    fn hash_mismatch_parser_requires_one_strict_sri_result() -> Result<()> {
        let expected = "sha256-0123456789012345678901234567890123456789012=";
        let diagnostic = format!(
            "error: hash mismatch in fixed-output derivation\n  specified: {FAKE_HASH}\n  got:    {expected}\n"
        );
        assert_eq!(parse_hash_mismatch(diagnostic.as_bytes())?, expected);
        assert!(parse_hash_mismatch(b"error: builder failed\n").is_err());
        assert!(
            parse_hash_mismatch(
                format!(
                    "got: {expected}\ngot: sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
                )
                .as_bytes()
            )
            .is_err()
        );
        Ok(())
    }
}
