//! Exact-base managed Git worktree creation and reconciliation.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use anyhow::{Context as _, Result, bail};
use aos_contract::Sha256Digest;
use aos_maintain::PACKAGE_UPDATE_RUN_V1;
use aos_maintain::identity::RunId;
use aos_maintain::plan::PackageUpdatePlanV1;
use aos_maintain::run::PackageUpdateRunV1;
use aos_maintain::workflow::{ActorClass, RunState};

use super::state::{self, StateStore};

/// Creates or safely resumes the exact managed worktree for a plan.
///
/// # Errors
///
/// Returns an error when the base object is unavailable, an existing branch or
/// worktree is ambiguous, Git reports unexpected state, or durable state
/// cannot be committed.
pub(super) fn ensure(
    store: &StateStore,
    repository_root: &Path,
    plan: &PackageUpdatePlanV1,
    requested_worktree: Option<&Path>,
) -> Result<PackageUpdateRunV1> {
    plan.validate()?;
    let plan_digest = Sha256Digest::of_canonical(aos_maintain::PACKAGE_UPDATE_PLAN_V1, plan)?;
    let run_id = RunId::parse(format!("run-{}", &plan_digest.hex()[..24]))?;
    if let Some(run) = store.read_run(run_id.as_str())? {
        if run.plan_digest != plan_digest {
            bail!("run identity collides with a different immutable plan");
        }
        if requested_worktree.is_some_and(|path| path != Path::new(&run.worktree)) {
            bail!("existing run is bound to a different worktree");
        }
        return reconcile(store, repository_root, plan, run);
    }

    verify_base(repository_root, plan)?;
    let worktree = requested_worktree
        .map(Path::to_path_buf)
        .unwrap_or(store.worktree_path(run_id.as_str())?);
    validate_destination(&worktree)?;
    let branch = available_branch(repository_root, plan, plan_digest)?;
    let now = state::now_unix()?;
    let mut run = PackageUpdateRunV1 {
        schema: PACKAGE_UPDATE_RUN_V1.to_string(),
        run_id,
        plan_id: plan.plan_id.clone(),
        plan_digest,
        state: RunState::Observed,
        branch,
        worktree: worktree
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("worktree path is not UTF-8"))?
            .to_string(),
        worktree_cleaned: false,
        base_commit: plan.base_commit.clone(),
        attempt: 0,
        created_at_unix: now,
        updated_at_unix: now,
    };
    store.initialize_run(&run, plan)?;
    store.transition(&mut run, RunState::Selected, ActorClass::Controller, now)?;
    store.transition(&mut run, RunState::Planned, ActorClass::Controller, now)?;
    reconcile(store, repository_root, plan, run)
}

fn reconcile(
    store: &StateStore,
    repository_root: &Path,
    plan: &PackageUpdatePlanV1,
    mut run: PackageUpdateRunV1,
) -> Result<PackageUpdateRunV1> {
    if run.state != RunState::Planned && run.state != RunState::WorktreeReady {
        return Ok(run);
    }
    let worktree = Path::new(&run.worktree);
    if worktree.exists() {
        verify_worktree(worktree, plan, &run.branch)?;
        if run.state == RunState::Planned {
            store.transition(
                &mut run,
                RunState::WorktreeReady,
                ActorClass::Controller,
                state::now_unix()?,
            )?;
        }
        return Ok(run);
    }
    if run.state == RunState::WorktreeReady {
        bail!("recorded worktree is missing; inspect the run before continuing");
    }
    if branch_exists(repository_root, &run.branch)? {
        bail!(
            "planned branch exists without its recorded worktree; manual reconciliation required"
        );
    }
    verify_base(repository_root, plan)?;
    create(
        repository_root,
        worktree,
        &run.branch,
        &plan.base_commit.value,
    )?;
    verify_worktree(worktree, plan, &run.branch)?;
    store.transition(
        &mut run,
        RunState::WorktreeReady,
        ActorClass::Controller,
        state::now_unix()?,
    )?;
    Ok(run)
}

fn create(root: &Path, destination: &Path, branch: &str, commit: &str) -> Result<()> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).context("creating managed worktree parent")?;
    }
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["worktree", "add", "-b", branch])
        .arg(destination)
        .arg(commit)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .context("creating isolated maintenance worktree")?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        bail!(
            "Git could not create the isolated maintenance worktree: {}",
            detail.trim().chars().take(2048).collect::<String>()
        );
    }
    Ok(())
}

fn verify_base(root: &Path, plan: &PackageUpdatePlanV1) -> Result<()> {
    let commit = git_text(
        root,
        &[
            "rev-parse",
            "--verify",
            &format!("{}^{{commit}}", plan.base_commit.value),
        ],
    )?;
    if commit != plan.base_commit.value {
        bail!("planned base commit is unavailable");
    }
    let tree = git_text(
        root,
        &[
            "rev-parse",
            "--verify",
            &format!("{}^{{tree}}", plan.base_commit.value),
        ],
    )?;
    if tree != plan.base_tree.value {
        bail!("planned base tree no longer matches its commit");
    }
    Ok(())
}

fn verify_worktree(root: &Path, plan: &PackageUpdatePlanV1, branch: &str) -> Result<()> {
    let head = git_text(root, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    let tree = git_text(root, &["rev-parse", "--verify", "HEAD^{tree}"])?;
    let current_branch = git_text(root, &["branch", "--show-current"])?;
    let status = git(root, &["status", "--porcelain=v2", "-z"])?;
    if head != plan.base_commit.value
        || tree != plan.base_tree.value
        || current_branch != branch
        || !status.status.success()
        || !status.stdout.is_empty()
    {
        bail!("managed worktree does not match its exact clean planned base");
    }
    Ok(())
}

fn validate_destination(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("maintenance worktree path must be absolute");
    }
    match path.symlink_metadata() {
        Ok(metadata) if metadata.is_dir() && fs::read_dir(path)?.next().is_none() => Ok(()),
        Ok(_) => bail!("maintenance worktree destination must be an empty real directory"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("inspecting maintenance worktree destination"),
    }
}

fn available_branch(
    root: &Path,
    plan: &PackageUpdatePlanV1,
    digest: Sha256Digest,
) -> Result<String> {
    let unit = slug(plan.unit_id.as_str(), 48);
    let target = slug(&plan.target_package_version, 48);
    let preferred = format!("dplecki/upgrade-{unit}-{target}");
    if !branch_exists(root, &preferred)? {
        return Ok(preferred);
    }
    let fallback = format!("{preferred}-{}", &digest.hex()[..8]);
    if branch_exists(root, &fallback)? {
        bail!("all deterministic maintenance branch names are already in use");
    }
    Ok(fallback)
}

fn slug(value: &str, maximum: usize) -> String {
    let mut output = String::new();
    let mut separator = false;
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            if separator && !output.is_empty() {
                output.push('-');
            }
            output.push(character.to_ascii_lowercase());
            separator = false;
        } else {
            separator = true;
        }
        if output.len() >= maximum {
            break;
        }
    }
    output.trim_end_matches('-').to_string()
}

fn branch_exists(root: &Path, branch: &str) -> Result<bool> {
    let output = git(
        root,
        &[
            "show-ref",
            "--verify",
            "--quiet",
            &format!("refs/heads/{branch}"),
        ],
    )?;
    match output.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => bail!("Git could not inspect the proposed maintenance branch"),
    }
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
    fn branch_slugs_are_bounded_lowercase_and_stable() {
        assert_eq!(slug("Bazel 8/nightly", 48), "bazel-8-nightly");
        assert_eq!(slug("--ZLIB--", 48), "zlib");
        assert!(slug(&"X".repeat(100), 48).len() <= 48);
    }
}
