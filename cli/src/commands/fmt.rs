use anyhow::{Context, Result};

use crate::nix::NixRunner;
use crate::output::Printer;

pub fn run(
    nix: &NixRunner,
    printer: &Printer,
    check: bool,
    files: &[String],
) -> Result<()> {
    // Determine which files to format
    let nix_files: Vec<String> = if files.is_empty() {
        // Find all .nix files under the project root
        let pattern = format!("{}/**/*.nix", nix.root().display());
        glob::glob(&pattern)
            .context("failed to glob for .nix files")?
            .filter_map(|entry| entry.ok())
            .map(|path| path.to_string_lossy().to_string())
            .collect()
    } else {
        files.to_vec()
    };

    if nix_files.is_empty() {
        printer.info("No .nix files found");
        return Ok(());
    }

    printer.info(&format!(
        "{} {} .nix file{}",
        if check { "Checking" } else { "Formatting" },
        nix_files.len(),
        if nix_files.len() == 1 { "" } else { "s" },
    ));

    // Try to find nixfmt binary
    let nixfmt = find_nixfmt()?;

    let mut cmd = std::process::Command::new(&nixfmt);
    if check {
        cmd.arg("--check");
    }
    cmd.args(&nix_files);
    cmd.current_dir(nix.root());

    let status = cmd.status().with_context(|| format!("failed to run {nixfmt}"))?;

    if !status.success() {
        if check {
            anyhow::bail!("formatting check failed — run 'aos fmt' to fix");
        } else {
            anyhow::bail!("nixfmt exited with status {status}");
        }
    }

    if !check {
        printer.success(&format!("Formatted {} file{}", nix_files.len(), if nix_files.len() == 1 { "" } else { "s" }));
    }

    Ok(())
}

fn find_nixfmt() -> Result<String> {
    // Check PATH for nixfmt variants
    for name in &["nixfmt", "nixfmt-rfc-style"] {
        if which(name).is_ok() {
            return Ok(name.to_string());
        }
    }

    anyhow::bail!(
        "nixfmt not found in PATH. Install it with: nix profile install nixpkgs#nixfmt-rfc-style"
    )
}

fn which(binary: &str) -> Result<std::path::PathBuf, ()> {
    let path_var = std::env::var_os("PATH").ok_or(())?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(binary);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(())
}
