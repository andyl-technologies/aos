//! `aos describe` — show repository information.
//!
//! Prints a summary of the working tree: the repo version (from the Nix
//! `version` attribute), root path, git commit/branch/dirty state, and
//! the number of packages in the `pkgs` set. Every probe is best-effort;
//! values that cannot be determined are reported as `unknown` rather
//! than failing the command.

use anyhow::Result;

use aos_core::nix::NixRunner;
use aos_core::output::Printer;

/// `aos describe` — show repository information.
///
/// # Errors
///
/// Currently infallible in practice — all probes (git, Nix evaluation)
/// degrade to `unknown` on failure; the `Result` only propagates output
/// plumbing errors.
pub fn run(nix: &NixRunner, printer: &Printer) -> Result<()> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| nix.root().to_path_buf());
    let (commit, branch, git_dirty) = aos_package::local_git_info(&cwd);
    let git_commit = commit.unwrap_or_else(|| "unknown".to_string());
    let git_branch = branch.unwrap_or_else(|| "unknown".to_string());

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
