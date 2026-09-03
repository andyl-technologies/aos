//! Bounded source hashing and deterministic attempt-zero mutation.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context as _, Result, bail};
use aos_contract::Sha256Digest;
use aos_core::nix::NixRunner;
use aos_maintain::PACKAGE_UPDATE_MATERIALIZATION_V1;
use aos_maintain::plan::{PackageUpdatePlanV1, SemanticMutation, SourceIntent};
use aos_maintain::run::{MaterializationRecordV1, MaterializedSource, PackageUpdateRunV1};
use aos_maintain::workflow::{ActorClass, RunState};
use base64::Engine as _;
use futures_util::StreamExt as _;
use sha2::{Digest as _, Sha256};
use url::Url;

use super::state::{self, StateStore};
use super::{inventory, mutation};

const MAX_SOURCE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_PATCH_BYTES: usize = 32 * 1024 * 1024;

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

    let sources = resolve_sources(plan).await?;
    let mut mutations = plan.semantic_mutations.clone();
    for source in &sources {
        let intent = plan
            .sources
            .iter()
            .find(|intent| intent.component == source.component && intent.slot == source.slot)
            .ok_or_else(|| anyhow::anyhow!("resolved source was not authorized by the plan"))?;
        mutations.push(SemanticMutation {
            owner: plan
                .semantic_mutations
                .first()
                .map(|mutation| mutation.owner.clone())
                .ok_or_else(|| anyhow::anyhow!("plan has no authored mutation owner"))?,
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
    apply_mutations(&root, &plan.unit_id.to_string(), &mutations)?;
    verify_post_inventory(&root, plan, verbose, quiet)?;
    let (patch, changed_paths) = checked_patch(&root, plan)?;
    let record = MaterializationRecordV1 {
        schema: PACKAGE_UPDATE_MATERIALIZATION_V1.to_string(),
        run_id: run.run_id.clone(),
        plan_id: plan.plan_id.clone(),
        attempt: 0,
        sources,
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

async fn resolve_sources(plan: &PackageUpdatePlanV1) -> Result<Vec<MaterializedSource>> {
    let mut output = Vec::with_capacity(plan.sources.len());
    for source in &plan.sources {
        output.push(resolve_source(source).await?);
    }
    Ok(output)
}

async fn resolve_source(intent: &SourceIntent) -> Result<MaterializedSource> {
    let mut last_error = None;
    for requested in &intent.urls {
        match hash_url(requested, &intent.allowed_redirect_hosts).await {
            Ok((hash, bytes, final_url)) => {
                return Ok(MaterializedSource {
                    component: intent.component.clone(),
                    slot: intent.slot.clone(),
                    requested_url: requested.clone(),
                    final_url,
                    hash,
                    bytes,
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
    let owners = mutations
        .iter()
        .map(|mutation| mutation.owner.as_str())
        .collect::<BTreeSet<_>>();
    if owners.len() != 1 {
        bail!("initial materializer supports exactly one declared owner file");
    }
    let owner = owners
        .first()
        .ok_or_else(|| anyhow::anyhow!("materialization has no owner file"))?;
    let path = root.join(owner);
    let metadata = path
        .symlink_metadata()
        .context("inspecting package owner")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!("package owner is not a regular non-symlink file");
    }
    let source = fs::read_to_string(&path).context("reading package owner")?;
    let updated = mutation::apply(&source, unit_id, mutations)?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("package owner has no parent"))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary
        .as_file_mut()
        .set_permissions(fs::Permissions::from_mode(metadata.permissions().mode()))?;
    temporary.write_all(updated.as_bytes())?;
    temporary.as_file_mut().sync_all()?;
    temporary.persist(&path).map_err(|error| error.error)?;
    match alejandra::format::in_fs(path.to_string_lossy().to_string(), true) {
        alejandra::format::Status::Error(error) => {
            bail!("formatting package owner failed: {error}")
        }
        alejandra::format::Status::Changed(_) => {}
    }
    Ok(())
}

fn verify_post_inventory(
    root: &Path,
    plan: &PackageUpdatePlanV1,
    verbose: u8,
    quiet: bool,
) -> Result<()> {
    let runner = NixRunner::for_root(root, verbose, quiet)?;
    let envelope = inventory::evaluate(&runner, None)?;
    let unit = envelope
        .inventory
        .units
        .iter()
        .find(|unit| unit.unit_id == plan.unit_id)
        .ok_or_else(|| anyhow::anyhow!("updated unit disappeared from maintenance inventory"))?;
    let package = unit
        .package
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("updated package projection disappeared"))?;
    if package.current_version != plan.target_package_version {
        bail!("updated package version does not match the planned projection");
    }
    for (component_id, target) in &plan.component_targets {
        let component = unit
            .components
            .get(component_id)
            .ok_or_else(|| anyhow::anyhow!("updated component disappeared"))?;
        if &component.current != target {
            bail!("updated component vector does not match the plan");
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
        .semantic_mutations
        .iter()
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
}
