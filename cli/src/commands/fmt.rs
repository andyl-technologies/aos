use anyhow::{bail, Result};
use ignore::WalkBuilder;

use aos::nix::NixRunner;
use aos::output::Printer;

pub fn run(
    nix: &NixRunner,
    printer: &Printer,
    check: bool,
    files: &[String],
) -> Result<()> {
    let nix_files: Vec<String> = if files.is_empty() {
        // Walk project tree respecting .gitignore (skips symlinks into /nix/store)
        let mut found = Vec::new();
        for entry in WalkBuilder::new(nix.root())
            .hidden(false)
            .git_ignore(true)
            .git_global(false)
            .git_exclude(true)
            .follow_links(false)
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

    let mut had_changes = false;
    let mut errors = Vec::new();

    for path in &nix_files {
        // in_fs formats in-place when in_place=true, just checks when false
        let status = alejandra::format::in_fs(path.clone(), !check);
        match status {
            alejandra::format::Status::Changed(changed) => {
                if changed {
                    had_changes = true;
                }
            }
            alejandra::format::Status::Error(err) => {
                errors.push(format!("{path}: {err}"));
            }
        }
    }

    if !errors.is_empty() {
        bail!(
            "Formatting errors:\n{}",
            errors.join("\n")
        );
    }

    if check && had_changes {
        bail!("formatting check failed — run 'aos fmt' to fix");
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
