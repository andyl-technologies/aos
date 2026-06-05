use anyhow::Result;
use git2::{Repository, StatusOptions};

use aos_core::nix::NixRunner;
use aos_core::output::Printer;

/// `aos describe` — show repository information.
pub fn run(nix: &NixRunner, printer: &Printer) -> Result<()> {
    let repo = Repository::discover(nix.root()).ok();
    let git_commit = repo
        .as_ref()
        .and_then(git_rev)
        .unwrap_or_else(|| "unknown".to_string());
    let git_branch = repo
        .as_ref()
        .and_then(git_branch)
        .unwrap_or_else(|| "unknown".to_string());
    let git_dirty = repo.as_ref().map(git_dirty).unwrap_or(false);

    // Try to count packages by evaluating the package set attribute names.
    let pkg_count = nix
        .eval_json("pkgs")
        .ok()
        .and_then(|v| v.as_object().map(|o| o.len()))
        .map(|n| n.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Try to read version from the Nix expression.
    let version = nix
        .eval_str("version")
        .ok()
        .unwrap_or_else(|| "0.1.0".to_string());

    if printer.json_if_active(&serde_json::json!({
        "version": version,
        "git_commit": git_commit,
        "git_branch": git_branch,
        "git_dirty": git_dirty,
        "package_count": pkg_count,
        "root": nix.root().to_string_lossy(),
    })) {
        return Ok(());
    }

    printer.header("AOS Repository");
    printer.kv("Version", &version);
    printer.kv("Root", &nix.root().to_string_lossy());
    printer.kv("Git commit", &git_commit);
    printer.kv("Git branch", &git_branch);
    if git_dirty {
        printer.kv("Git status", "dirty (uncommitted changes)");
    }
    printer.kv("Packages", &pkg_count);

    Ok(())
}

fn git_rev(repo: &Repository) -> Option<String> {
    let oid = repo.head().ok()?.target()?;
    let oid = oid.to_string();
    Some(oid[..12.min(oid.len())].to_string())
}

fn git_branch(repo: &Repository) -> Option<String> {
    repo.head().ok()?.shorthand().ok().map(ToString::to_string)
}

fn git_dirty(repo: &Repository) -> bool {
    let mut options = StatusOptions::new();
    options.include_untracked(false);
    repo.statuses(Some(&mut options))
        .map(|statuses| !statuses.is_empty())
        .unwrap_or(false)
}
