use anyhow::{Context, Result};
use ignore::WalkBuilder;

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
        // Walk project tree respecting .gitignore (skips symlinks into /nix/store)
        let mut found = Vec::new();
        for entry in WalkBuilder::new(nix.root())
            .hidden(false)         // include dotfiles like .envrc
            .git_ignore(true)      // respect .gitignore
            .git_global(false)
            .git_exclude(true)
            .follow_links(false)   // never follow symlinks
            .build()
        {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "nix") && path.is_file() {
                found.push(path.to_string_lossy().to_string());
            }
        }
        found.sort();
        found
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

    // Try to find a Nix formatter binary
    let formatter = find_formatter()?;

    // Run formatter in batches to avoid "argument list too long"
    let batch_size = 200;
    for chunk in nix_files.chunks(batch_size) {
        let mut cmd = std::process::Command::new(&formatter);
        if check {
            cmd.arg("--check");
        }
        cmd.args(chunk);
        cmd.current_dir(nix.root());

        let status = cmd.status().with_context(|| format!("failed to run {formatter}"))?;

        if !status.success() {
            if check {
                anyhow::bail!("formatting check failed — run 'aos fmt' to fix");
            } else {
                anyhow::bail!("{formatter} exited with status {status}");
            }
        }
    }

    if !check {
        printer.success(&format!(
            "Formatted {} file{}",
            nix_files.len(),
            if nix_files.len() == 1 { "" } else { "s" }
        ));
    }

    Ok(())
}

fn find_formatter() -> Result<String> {
    // Prefer alejandra, fall back to nixfmt
    for name in &["alejandra", "nixfmt", "nixfmt-rfc-style"] {
        if which(name).is_ok() {
            return Ok(name.to_string());
        }
    }

    anyhow::bail!(
        "No Nix formatter found in PATH. Install alejandra or nixfmt."
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
