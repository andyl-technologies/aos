//! Candidate patch reconciliation and maintainer-authored Git commits.

use std::path::Path;
use std::process::{Command, Output};

use anyhow::{Context as _, Result, bail};
use aos_contract::Sha256Digest;
use aos_maintain::envelope::GitObjectId;
use aos_maintain::plan::PackageUpdatePlanV1;
use aos_maintain::run::PackageUpdateRunV1;
use aos_maintain::workflow::{ActorClass, RunState};

use super::state::{self, StateStore};

/// Verifies and returns the exact retained candidate patch identity.
///
/// # Errors
///
/// Returns an error when materialization evidence is absent or the current
/// worktree diff differs from the retained candidate.
pub(super) fn candidate_digest(
    store: &StateStore,
    run: &PackageUpdateRunV1,
) -> Result<Sha256Digest> {
    let retained = store
        .read_patch(run.run_id.as_str())?
        .ok_or_else(|| anyhow::anyhow!("run has no retained candidate"))?;
    let retained_digest = Sha256Digest::separated("aos.package-update-patch/v1", &retained);
    let diff = git(
        Path::new(&run.worktree),
        &["diff", "--no-ext-diff", "--full-index", "--"],
    )?;
    if !diff.status.success()
        || Sha256Digest::separated("aos.package-update-patch/v1", &diff.stdout) != retained_digest
    {
        bail!("worktree differs from the retained candidate patch");
    }
    Ok(retained_digest)
}

/// Creates or reconciles the exact accepted candidate commit.
///
/// Git uses the maintainer's configured identity and signing policy while
/// repository hooks are disabled for this automation-owned effect.
///
/// # Errors
///
/// Returns an error unless acceptance, patch, branch, base, commit message,
/// resulting commit, and clean-worktree postconditions all match.
pub(super) fn commit_candidate(
    store: &StateStore,
    plan: &PackageUpdatePlanV1,
    run: &mut PackageUpdateRunV1,
) -> Result<GitObjectId> {
    if run.state == RunState::Committed {
        return verified_commit(plan, run);
    }
    if run.state != RunState::CandidateAccepted {
        bail!("run has not been accepted for commit");
    }
    let accepted = run
        .accepted_candidate
        .ok_or_else(|| anyhow::anyhow!("accepted run has no candidate digest"))?;
    let root = Path::new(&run.worktree);
    let head = git_text(root, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    if head != plan.base_commit.value {
        let commit = reconcile_created_commit(plan, run, accepted)?;
        finish_commit(store, run, commit.clone())?;
        return Ok(commit);
    }
    if candidate_digest(store, run)? != accepted {
        bail!("accepted candidate no longer matches the worktree");
    }
    if plan
        .semantic_mutations
        .iter()
        .any(|mutation| mutation.owner.starts_with("pkgs/emulation/qemu"))
    {
        bail!("QEMU-side changes require a human-created legal-name DCO commit");
    }
    let owners = plan
        .semantic_mutations
        .iter()
        .map(|mutation| mutation.owner.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let mut add = Command::new("git");
    add.arg("-C")
        .arg(root)
        .args(["add", "--"])
        .args(&owners)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0");
    if !add
        .status()
        .context("staging accepted candidate")?
        .success()
    {
        bail!("Git could not stage the accepted candidate");
    }
    let message = format!(
        "pkg: update {} to {}",
        plan.unit_id, plan.target_package_version
    );
    let status = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["-c", "core.hooksPath=/dev/null", "commit", "-m"])
        .arg(&message)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .status()
        .context("committing accepted candidate")?;
    if !status.success() {
        bail!("Git could not commit the accepted candidate");
    }
    let commit = reconcile_created_commit(plan, run, accepted)?;
    finish_commit(store, run, commit.clone())?;
    Ok(commit)
}

fn reconcile_created_commit(
    plan: &PackageUpdatePlanV1,
    run: &PackageUpdateRunV1,
    accepted: Sha256Digest,
) -> Result<GitObjectId> {
    let root = Path::new(&run.worktree);
    let branch = git_text(root, &["branch", "--show-current"])?;
    let status = git(root, &["status", "--porcelain=v2", "-z"])?;
    let head = git_text(root, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    let diff = git(
        root,
        &[
            "diff",
            "--no-ext-diff",
            "--full-index",
            &plan.base_commit.value,
            &head,
            "--",
        ],
    )?;
    if branch != run.branch
        || !status.status.success()
        || !status.stdout.is_empty()
        || !diff.status.success()
        || Sha256Digest::separated("aos.package-update-patch/v1", &diff.stdout) != accepted
    {
        bail!("candidate commit postconditions do not match the accepted patch");
    }
    let commit = GitObjectId {
        algorithm: plan.base_commit.algorithm,
        value: head,
    };
    commit.validate()?;
    Ok(commit)
}

fn finish_commit(
    store: &StateStore,
    run: &mut PackageUpdateRunV1,
    commit: GitObjectId,
) -> Result<()> {
    run.candidate_commit = Some(commit);
    run.updated_at_unix = state::now_unix()?;
    store.write_run(run)?;
    store.transition(
        run,
        RunState::Committed,
        ActorClass::Maintainer,
        state::now_unix()?,
    )
}

fn verified_commit(plan: &PackageUpdatePlanV1, run: &PackageUpdateRunV1) -> Result<GitObjectId> {
    let expected = run
        .candidate_commit
        .clone()
        .ok_or_else(|| anyhow::anyhow!("committed run has no commit identity"))?;
    let head = git_text(
        Path::new(&run.worktree),
        &["rev-parse", "--verify", "HEAD^{commit}"],
    )?;
    if head != expected.value || expected.algorithm != plan.base_commit.algorithm {
        bail!("worktree HEAD differs from the recorded candidate commit");
    }
    Ok(expected)
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
