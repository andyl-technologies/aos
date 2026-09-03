//! Confined provider-neutral repair adapter and human-confirmed patch gateway.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use aos_contract::{Sha256Digest, canonical};
use aos_maintain::agent::{
    AgentBudget, AgentContextFile, AgentOperation, AgentResultV1, AgentTaskV1, RepairFailure,
    RepairFailureKind,
};
use aos_maintain::envelope::GitObjectId;
use aos_maintain::inventory::RiskLevel;
use aos_maintain::plan::{GateKind, PackageUpdatePlanV1};
use aos_maintain::run::{AttemptOrigin, PackageUpdateRunV1, RepairAttemptV1};
use aos_maintain::workflow::{ActorClass, GateOutcome, RunState};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::confinement::{Backend, ResourceLimits};
use super::materialize;
use super::state::{self, StateStore};

const MAX_CONTEXT_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ADAPTER_STDERR_BYTES: usize = 64 * 1024;
const MAX_CANDIDATE_PATCH_BYTES: usize = 32 * 1024 * 1024;

/// One retained proposal ready for maintainer inspection or confirmation.
pub(super) struct Proposal {
    pub(super) task: AgentTaskV1,
    pub(super) result: AgentResultV1,
    pub(super) proposal_digest: Option<Sha256Digest>,
}

/// Invokes one confined adapter against a freshly constructed disposable view.
///
/// # Errors
///
/// Returns an error unless an eligible gate failure, valid adapter, verified
/// confinement backend, bounded response, and closed result are available.
pub(super) async fn propose(
    store: &StateStore,
    plan: &PackageUpdatePlanV1,
    run: &PackageUpdateRunV1,
    adapter: &Path,
) -> Result<Proposal> {
    if !matches!(run.state, RunState::PolicyValid | RunState::Repairing) {
        bail!("repair requires a policy-valid candidate with a failed quick gate");
    }
    if let Some((task, result)) = store.read_agent_proposal(run)? {
        return Ok(proposal(task, result));
    }

    let scratch = store.scratch_directory(
        run.run_id.as_str(),
        &format!("agent-{}", run.attempt.saturating_add(1)),
    )?;
    let view_parent = scratch.join("view");
    secure_directory(&view_parent)?;
    let view = tempfile::Builder::new()
        .prefix("context-")
        .tempdir_in(&view_parent)?;
    let task = build_task(store, plan, run, view.path())?;
    let result = invoke_adapter(&task, adapter, view.path(), &scratch).await?;
    result.validate_for(&task)?;
    store.write_agent_proposal(&task, &result)?;
    Ok(proposal(task, result))
}

/// Returns a previously retained proposal without invoking an adapter.
///
/// # Errors
///
/// Returns an error when retained state is malformed or belongs to another run
/// generation.
pub(super) fn pending(store: &StateStore, run: &PackageUpdateRunV1) -> Result<Option<Proposal>> {
    Ok(store
        .read_agent_proposal(run)?
        .map(|(task, result)| proposal(task, result)))
}

/// Applies one exact confirmed proposal and records a new cumulative attempt.
///
/// # Errors
///
/// Returns an error for a digest mismatch, unsafe patch shape, out-of-scope or
/// forbidden edit, apply failure, invalid inventory, or changed candidate race.
pub(super) fn accept(
    store: &StateStore,
    plan: &PackageUpdatePlanV1,
    run: &mut PackageUpdateRunV1,
    proposal: &Proposal,
    confirmation: &str,
    verbose: u8,
    quiet: bool,
) -> Result<RepairAttemptV1> {
    let patch = proposal
        .result
        .patch
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("retained agent result contains no patch proposal"))?;
    let proposal_digest = proposal
        .proposal_digest
        .ok_or_else(|| anyhow::anyhow!("retained agent result is not a patch proposal"))?;
    if confirmation != proposal_digest.to_string() {
        bail!("repair confirmation does not match the exact proposal digest");
    }
    if proposal.task.attempt != run.attempt.saturating_add(1) {
        bail!("repair proposal no longer targets the current attempt");
    }
    let root = Path::new(&run.worktree);
    let before_patch = cumulative_patch(root)?;
    let before_digest = Sha256Digest::separated("aos.package-update-patch/v1", &before_patch);
    let retained = store
        .read_patch(run.run_id.as_str())?
        .ok_or_else(|| anyhow::anyhow!("current candidate patch is unavailable"))?;
    if before_digest != Sha256Digest::separated("aos.package-update-patch/v1", &retained)
        || before_digest != proposal.task.tree_digest
    {
        bail!("candidate changed after the repair task was created");
    }

    let allowed = proposal
        .task
        .writable_paths
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    validate_proposal_patch(patch, &allowed)?;
    let scratch = store.scratch_directory(run.run_id.as_str(), "apply-repair")?;
    let original = apply_in_disposable_view(root, &scratch, patch, &allowed)?;
    let owner = allowed
        .first()
        .ok_or_else(|| anyhow::anyhow!("repair proposal has no writable owner"))?;
    let candidate_path = scratch.join("apply-view").join(owner);
    let candidate = fs::read(&candidate_path).context("reading gateway candidate output")?;
    let real_path = root.join(owner);
    if let Err(error) = atomic_replace(&real_path, &candidate)
        .and_then(|()| materialize::verify_post_inventory(root, plan, verbose, quiet))
        .and_then(|()| validate_cumulative_diff(root, &allowed))
    {
        atomic_replace(&real_path, &original).context("restoring rejected repair candidate")?;
        bail!("repair proposal failed the mutation gateway: {error:#}");
    }

    let cumulative = cumulative_patch(root)?;
    let changed_paths = changed_paths(root)?;
    let task_digest =
        Sha256Digest::of_canonical(aos_maintain::PACKAGE_UPDATE_AGENT_TASK_V1, &proposal.task)?;
    let result_digest = Sha256Digest::of_canonical(
        aos_maintain::PACKAGE_UPDATE_AGENT_RESULT_V1,
        &proposal.result,
    )?;
    let record = RepairAttemptV1 {
        schema: aos_maintain::PACKAGE_UPDATE_REPAIR_ATTEMPT_V1.to_string(),
        run_id: run.run_id.clone(),
        plan_id: run.plan_id.clone(),
        attempt: proposal.task.attempt,
        parent_attempt: run.attempt,
        origin: AttemptOrigin::Agent,
        task_digest: Some(task_digest),
        result_digest: Some(result_digest),
        proposal_digest,
        candidate_digest: Sha256Digest::separated("aos.package-update-patch/v1", &cumulative),
        changed_paths,
        completed_at_unix: state::now_unix()?,
    };
    record.validate()?;
    store.write_repair_attempt(run, &record, &cumulative)?;
    run.attempt = record.attempt;
    run.accepted_candidate = None;
    run.candidate_commit = None;
    run.evidence_digest = None;
    run.updated_at_unix = state::now_unix()?;
    store.write_run(run)?;
    if run.state == RunState::Repairing {
        store.transition(
            run,
            RunState::PolicyValid,
            ActorClass::Maintainer,
            state::now_unix()?,
        )?;
    }
    Ok(record)
}

fn proposal(task: AgentTaskV1, result: AgentResultV1) -> Proposal {
    let proposal_digest = result.patch.as_ref().map(|patch| {
        Sha256Digest::separated("aos.package-update-agent-proposal/v1", patch.as_bytes())
    });
    Proposal {
        task,
        result,
        proposal_digest,
    }
}

fn build_task(
    store: &StateStore,
    plan: &PackageUpdatePlanV1,
    run: &PackageUpdateRunV1,
    view: &Path,
) -> Result<AgentTaskV1> {
    let unit_plan = plan.single_unit()?;
    let inventory = store
        .read_inventory()?
        .ok_or_else(|| anyhow::anyhow!("repair inventory is unavailable"))?;
    let unit = inventory
        .inventory
        .units
        .iter()
        .find(|unit| unit.unit_id == unit_plan.unit_id)
        .ok_or_else(|| anyhow::anyhow!("repair unit disappeared from inventory"))?;
    let gates = store
        .read_gate_results(run.run_id.as_str(), "quick")?
        .ok_or_else(|| anyhow::anyhow!("repair requires retained failed quick-gate evidence"))?;
    let failed = gates
        .results
        .iter()
        .find(|result| result.outcome == GateOutcome::Failure)
        .ok_or_else(|| anyhow::anyhow!("repair requires an eligible failed quick gate"))?;
    let gate = plan
        .quick_gates
        .iter()
        .find(|gate| gate.id == failed.gate_id)
        .ok_or_else(|| anyhow::anyhow!("failed gate is absent from the immutable plan"))?;
    let kind = match gate.kind {
        GateKind::PackageBuild => RepairFailureKind::PackageBuild,
        GateKind::RepositoryTest => RepairFailureKind::PackageTest,
        _ => bail!("the selected gate failure is not eligible for agent repair"),
    };
    let log = store.read_gate_log(run.run_id.as_str(), "quick", &failed.gate_id)?;
    let owner = plan
        .single_unit()?
        .semantic_mutations
        .first()
        .map(|mutation| mutation.owner.clone())
        .ok_or_else(|| anyhow::anyhow!("repair plan has no package owner"))?;
    let source_path = Path::new(&run.worktree).join(&owner);
    let source = read_context_file(&source_path)?;
    let destination = view.join(&owner);
    let parent = destination
        .parent()
        .ok_or_else(|| anyhow::anyhow!("repair context path has no parent"))?;
    fs::create_dir_all(parent)?;
    fs::write(&destination, &source)?;
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o600))?;
    let max_attempts = match plan.risk {
        RiskLevel::Low => 3,
        RiskLevel::Normal => 2,
        RiskLevel::High | RiskLevel::Critical => 1,
    };
    let attempt = run
        .attempt
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("repair attempt counter overflow"))?;
    if attempt > max_attempts {
        bail!("repair attempt budget is exhausted for this risk class");
    }
    let head = git_text(
        Path::new(&run.worktree),
        &["rev-parse", "--verify", "HEAD^{commit}"],
    )?;
    let task = AgentTaskV1 {
        schema: aos_maintain::PACKAGE_UPDATE_AGENT_TASK_V1.to_string(),
        run_id: run.run_id.clone(),
        plan_id: run.plan_id.clone(),
        attempt,
        base_commit: plan.base_commit.clone(),
        head_commit: GitObjectId {
            algorithm: plan.base_commit.algorithm,
            value: head,
        },
        tree_digest: Sha256Digest::separated(
            "aos.package-update-patch/v1",
            cumulative_patch(Path::new(&run.worktree))?,
        ),
        unit_id: unit_plan.unit_id.clone(),
        family: unit.family.clone(),
        stream: unit.stream.clone(),
        members: unit.members.clone(),
        classification: unit.classification,
        lifecycle: unit.policy.lifecycle,
        component_targets: unit_plan.component_targets.clone(),
        target_version: unit_plan.target_package_version.clone(),
        risk: plan.risk,
        failure: RepairFailure {
            kind,
            gate_id: Some(failed.gate_id.clone()),
            log_digest: failed.log_digest,
            excerpt: sanitize_log(&log),
        },
        context: vec![AgentContextFile {
            path: owner.clone(),
            digest: Sha256Digest::of_bytes(&source),
            bytes: u64::try_from(source.len()).context("context length overflow")?,
            writable: true,
        }],
        allowed_operations: vec![
            AgentOperation::ReadContext,
            AgentOperation::SearchContext,
            AgentOperation::ProposePatch,
            AgentOperation::RequestQuickGate,
            AgentOperation::RequestScope,
            AgentOperation::AskMaintainer,
        ],
        writable_paths: vec![owner],
        required_gate_ids: plan
            .quick_gates
            .iter()
            .map(|gate| gate.id.clone())
            .collect(),
        budget: AgentBudget {
            remaining_attempts: max_attempts - attempt + 1,
            wall_seconds: 45 * 60,
            output_bytes: 8 * 1024 * 1024,
            patch_bytes: aos_maintain::agent::MAX_AGENT_PATCH_BYTES as u64,
            token_limit: Some(250_000),
        },
        untrusted_data: true,
    };
    task.validate()?;
    Ok(task)
}

async fn invoke_adapter(
    task: &AgentTaskV1,
    adapter: &Path,
    view: &Path,
    scratch: &Path,
) -> Result<AgentResultV1> {
    let backend = Backend::detect().context("verifying repair-agent confinement")?;
    let runtime_paths = [
        scratch.join("home"),
        scratch.join("tmp"),
        scratch.join("cache"),
    ];
    let (command, _) = backend.command(
        adapter,
        std::iter::empty::<&str>(),
        &[view.to_path_buf()],
        &runtime_paths,
        false,
        ResourceLimits::agent(),
    )?;
    let mut command = tokio::process::Command::from(command);
    command
        .current_dir(view)
        .env("HOME", &runtime_paths[0])
        .env("TMPDIR", &runtime_paths[1])
        .env("XDG_CACHE_HOME", &runtime_paths[2])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .context("spawning confined repair adapter")?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("repair adapter stdin was not captured"))?;
    let input = canonical::to_vec(task)?;
    stdin.write_all(&input).await?;
    stdin.write_all(b"\n").await?;
    stdin.shutdown().await?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("repair adapter stdout was not captured"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("repair adapter stderr was not captured"))?;
    let stdout_limit = usize::try_from(task.budget.output_bytes)
        .context("repair output budget does not fit this platform")?;
    let stdout_reader = tokio::spawn(bounded_read(stdout, stdout_limit));
    let stderr_reader = tokio::spawn(bounded_read(stderr, MAX_ADAPTER_STDERR_BYTES));
    let status =
        match tokio::time::timeout(Duration::from_secs(task.budget.wall_seconds), child.wait())
            .await
        {
            Ok(status) => status.context("waiting for repair adapter")?,
            Err(_) => {
                child
                    .start_kill()
                    .context("terminating timed-out repair adapter")?;
                let _ = child.wait().await;
                bail!("repair adapter exceeded its wall-time budget");
            }
        };
    let (stdout, stdout_truncated) = stdout_reader.await??;
    let (stderr, stderr_truncated) = stderr_reader.await??;
    if stdout_truncated {
        bail!("repair adapter exceeded its output byte budget");
    }
    if !status.success() {
        let message = String::from_utf8_lossy(&stderr);
        let suffix = if stderr_truncated { " [truncated]" } else { "" };
        bail!("repair adapter failed: {}{suffix}", message.trim());
    }
    let result: AgentResultV1 = serde_json::from_slice(&stdout)
        .context("repair adapter did not return one closed JSON result")?;
    result.validate_for(task)?;
    Ok(result)
}

async fn bounded_read(
    mut reader: impl tokio::io::AsyncRead + Unpin,
    maximum: usize,
) -> Result<(Vec<u8>, bool)> {
    let mut retained = Vec::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut truncated = false;
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        let accepted = maximum.saturating_sub(retained.len()).min(count);
        retained.extend_from_slice(&buffer[..accepted]);
        truncated |= accepted < count;
    }
    Ok((retained, truncated))
}

fn validate_proposal_patch(patch: &str, allowed: &BTreeSet<String>) -> Result<()> {
    if patch.is_empty()
        || patch.len() > aos_maintain::agent::MAX_AGENT_PATCH_BYTES
        || patch.bytes().any(|byte| byte == 0)
        || patch.contains("GIT binary patch")
        || patch.contains("Binary files ")
        || patch.lines().any(|line| {
            line.starts_with("new file mode ")
                || line.starts_with("deleted file mode ")
                || line.starts_with("old mode ")
                || line.starts_with("new mode ")
                || line.starts_with("rename from ")
                || line.starts_with("rename to ")
                || line.starts_with("similarity index ")
        })
    {
        bail!("repair proposal is empty, oversized, binary, or changes path identity");
    }
    let mut paths = BTreeSet::new();
    for line in patch.lines().filter(|line| line.starts_with("diff --git ")) {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 4
            || !fields[2].starts_with("a/")
            || !fields[3].starts_with("b/")
            || fields[2][2..] != fields[3][2..]
        {
            bail!("repair proposal has an invalid diff header");
        }
        paths.insert(fields[2][2..].to_string());
    }
    if paths.is_empty() || paths != *allowed {
        bail!("repair proposal changes a path outside its exact writable scope");
    }
    for line in patch.lines().filter_map(|line| line.strip_prefix('+')) {
        let lower = line.to_ascii_lowercase();
        if lower.contains("nixpkgs")
            || lower.contains("/usr/bin/env")
            || lower.contains("/bin/bash")
            || lower.contains("/bin/sh")
            || lower.contains("doCheck = false")
            || lower.contains("networking = true")
        {
            bail!("repair proposal introduces a forbidden build or test pattern");
        }
    }
    Ok(())
}

fn apply_in_disposable_view(
    root: &Path,
    scratch: &Path,
    patch: &str,
    allowed: &BTreeSet<String>,
) -> Result<Vec<u8>> {
    if allowed.len() != 1 {
        bail!("the initial repair gateway supports exactly one owner path");
    }
    let view = scratch.join("apply-view");
    secure_directory(&view)?;
    let owner = allowed
        .first()
        .ok_or_else(|| anyhow::anyhow!("repair writable scope is empty"))?;
    let source = read_context_file(&root.join(owner))?;
    let destination = view.join(owner);
    fs::create_dir_all(
        destination
            .parent()
            .ok_or_else(|| anyhow::anyhow!("repair owner has no parent"))?,
    )?;
    fs::write(&destination, &source)?;
    run_git_apply(&view, patch, true)?;
    run_git_apply(&view, patch, false)?;
    let updated = read_context_file(&destination)?;
    let text = std::str::from_utf8(&updated).context("repair output is not UTF-8")?;
    if !rnix::parse(text).errors().is_empty() {
        bail!("repair output is not valid Nix syntax");
    }
    Ok(source)
}

fn run_git_apply(view: &Path, patch: &str, check: bool) -> Result<()> {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(view)
        .args(["apply", "--whitespace=error-all"]);
    if check {
        command.arg("--check");
    }
    command.arg("-").stdin(Stdio::piped());
    let mut child = command.spawn().context("spawning repair patch validator")?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("Git apply stdin was not captured"))?
        .write_all(patch.as_bytes())?;
    if !child.wait()?.success() {
        bail!("repair proposal does not apply exactly to its disposable view");
    }
    Ok(())
}

fn validate_cumulative_diff(root: &Path, allowed: &BTreeSet<String>) -> Result<()> {
    let changed = changed_paths(root)?.into_iter().collect::<BTreeSet<_>>();
    if changed != *allowed {
        bail!("repair changed a path outside the approved owner scope");
    }
    let summary = git(root, &["diff", "--summary", "--"])?;
    let numstat = git(root, &["diff", "--numstat", "--"])?;
    if !summary.status.success()
        || !summary.stdout.is_empty()
        || !numstat.status.success()
        || numstat.stdout.windows(2).any(|pair| pair == b"-\t")
    {
        bail!("repair changed a file mode, kind, identity, or binary content");
    }
    Ok(())
}

fn changed_paths(root: &Path) -> Result<Vec<String>> {
    let output = git(root, &["diff", "--name-only", "-z", "--"])?;
    if !output.status.success() {
        bail!("Git could not enumerate the repaired candidate");
    }
    output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8(part.to_vec()).context("changed path is not UTF-8"))
        .collect()
}

fn cumulative_patch(root: &Path) -> Result<Vec<u8>> {
    let output = git(root, &["diff", "--no-ext-diff", "--full-index", "--"])?;
    if !output.status.success() || output.stdout.len() > MAX_CANDIDATE_PATCH_BYTES {
        bail!("cumulative candidate patch is unavailable or oversized");
    }
    Ok(output.stdout)
}

fn read_context_file(path: &Path) -> Result<Vec<u8>> {
    let metadata = path
        .symlink_metadata()
        .with_context(|| format!("inspecting repair context {}", path.display()))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_CONTEXT_FILE_BYTES
    {
        bail!("repair context file is unsafe or oversized");
    }
    fs::read(path).context("reading repair context")
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let metadata = path.symlink_metadata()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!("repair destination is not a regular non-symlink file");
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("repair destination has no parent"))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary
        .as_file_mut()
        .set_permissions(fs::Permissions::from_mode(metadata.permissions().mode()))?;
    temporary.write_all(bytes)?;
    temporary.as_file_mut().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn sanitize_log(bytes: &[u8]) -> String {
    let start = bytes.len().saturating_sub(48 * 1024);
    String::from_utf8_lossy(&bytes[start..])
        .lines()
        .map(|line| {
            let lower = line.to_ascii_lowercase();
            if [
                "authorization:",
                "access_token",
                "api_key",
                "password=",
                "secret=",
                "aws_secret_access_key",
            ]
            .iter()
            .any(|marker| lower.contains(marker))
            {
                "[redacted line]".to_string()
            } else {
                aos_maintain::presentation::escape_terminal(line, 4096)
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn secure_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    let metadata = path.symlink_metadata()?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("repair scratch path is not a real directory");
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
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
    fn patch_gateway_rejects_scope_escape_and_forbidden_builds() {
        let allowed = BTreeSet::from(["pkgs/test.nix".to_string()]);
        let escaped = "diff --git a/pkgs/test.nix b/pkgs/other.nix\n";
        assert!(validate_proposal_patch(escaped, &allowed).is_err());
        let forbidden = "diff --git a/pkgs/test.nix b/pkgs/test.nix\n--- a/pkgs/test.nix\n+++ b/pkgs/test.nix\n@@ -1 +1 @@\n-old\n+import <nixpkgs> {}\n";
        assert!(validate_proposal_patch(forbidden, &allowed).is_err());
    }

    #[test]
    fn log_sanitizer_redacts_secret_lines_and_terminal_controls() {
        let output = sanitize_log(b"ok\nAuthorization: bearer secret\ncolor=\x1b[31mred");
        assert!(output.contains("[redacted line]"));
        assert!(!output.contains("bearer secret"));
        assert!(!output.contains('\x1b'));
    }

    #[test]
    fn disposable_gateway_applies_without_git_metadata() -> Result<()> {
        let repository = tempfile::tempdir()?;
        let scratch = tempfile::tempdir()?;
        let owner = "pkgs/test.nix";
        let path = repository.path().join(owner);
        fs::create_dir_all(
            path.parent()
                .ok_or_else(|| anyhow::anyhow!("fixture owner has no parent"))?,
        )?;
        fs::write(&path, b"{ value = \"old\"; }\n")?;
        let patch = "diff --git a/pkgs/test.nix b/pkgs/test.nix\nindex 0000000..1111111 100644\n--- a/pkgs/test.nix\n+++ b/pkgs/test.nix\n@@ -1 +1 @@\n-{ value = \"old\"; }\n+{ value = \"new\"; }\n";
        let allowed = BTreeSet::from([owner.to_string()]);

        let original =
            apply_in_disposable_view(repository.path(), scratch.path(), patch, &allowed)?;

        assert_eq!(original, b"{ value = \"old\"; }\n");
        assert_eq!(
            fs::read(scratch.path().join("apply-view").join(owner))?,
            b"{ value = \"new\"; }\n"
        );
        assert!(!scratch.path().join("apply-view/.git").exists());
        Ok(())
    }
}
