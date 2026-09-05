//! Registry status, changes, branches, commits, and remote synchronization.

use crate::config::ApmConfig;
use crate::registry_ops::channels::{CHANGE_ID_TRAILER, HUB_CHANGES_NS};
use crate::registry_ops::config::{registry_dir, resolve_registry_name};
use crate::registry_ops::git::{
    commit_registry_paths, commit_staged_registry, current_git_head, git, git_raw, git_transport,
    git_try, refresh_registry_object_store,
};
use crate::registry_ops::publish::ensure_writable_registry_clone;
use crate::registry_ops::signing::{ResolvedSigningKey, resolve_producer_signing_key};
use crate::registry_ops::store_paths::first_letter;
use crate::registry_ops::trust::{load_committed_roster, resolve_roster_commit_key};
use crate::types::{validate_branch_name, validate_package_name};
use crate::{BranchCommand, ChangeCommand};
use anyhow::{Context, Result, bail};
use aos_core::output::{OutputMode, Printer};
use std::path::{Path, PathBuf};

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

pub(in crate::registry_ops) fn current_git_branch(dir: &Path) -> Result<String> {
    git(dir, &["rev-parse", "--abbrev-ref", "HEAD"])
}

/// Collect local and remote branch records (name, ref, commit, flags) for
/// JSON output.
pub(in crate::registry_ops) fn git_branch_entries(dir: &Path) -> Result<Vec<serde_json::Value>> {
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

#[cfg(test)]
mod tests;
