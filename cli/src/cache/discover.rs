use std::path::Path;

use anyhow::{Context, Result};

use crate::nix_cli::{self, FixedOutputDrv, NixCli};

/// Discover all fixed-output derivations in the closure of a .drv file.
///
/// 1. Enumerate all .drv files in the closure via `nix-store -qR`.
/// 2. Parse each .drv and check for `outputHash` in the env section.
/// 3. Return the FODs found.
pub fn discover_fods(nix: &NixCli, drv_path: &str) -> Result<Vec<FixedOutputDrv>> {
    // Get all derivations in the closure.
    let closure = nix
        .closure(drv_path)
        .with_context(|| format!("enumerating closure of {drv_path}"))?;

    let drv_paths: Vec<&str> = closure
        .iter()
        .map(String::as_str)
        .filter(|p| p.ends_with(".drv"))
        .collect();

    let mut fods = Vec::new();

    for drv in drv_paths {
        match nix_cli::parse_drv_for_fod(drv) {
            Ok(Some(fod)) => fods.push(fod),
            Ok(None) => {} // Not a FOD, skip.
            Err(e) => {
                // Log but don't fail — some .drv files may be malformed.
                eprintln!("warning: failed to parse {drv}: {e}");
            }
        }
    }

    Ok(fods)
}

/// Resolve an installable to a .drv path for FOD discovery.
///
/// For prefetch, we need the .drv (not the built output) so we can
/// examine its closure for FODs.
pub fn resolve_to_drv(
    nix: &NixCli,
    file: Option<&Path>,
    attr: Option<&str>,
    expr: Option<&str>,
    installable: Option<&str>,
) -> Result<String> {
    if let Some(expr) = expr {
        let drv = nix.instantiate_expr(expr)?;
        return Ok(drv.to_string_lossy().to_string());
    }

    if let Some(attr) = attr {
        let file = file.unwrap_or_else(|| Path::new("./default.nix"));
        let drv = nix.instantiate(file, attr)?;
        return Ok(drv.to_string_lossy().to_string());
    }

    if let Some(installable) = installable {
        // If it's already a .drv store path, use directly.
        if installable.starts_with("/nix/store/") && installable.ends_with(".drv") {
            return Ok(installable.to_string());
        }

        // Bare name -> pkgs.<name> (AOS convention)
        let attr = format!("pkgs.{installable}");
        let file = file.unwrap_or_else(|| Path::new("./default.nix"));
        let drv = nix.instantiate(file, &attr)?;
        return Ok(drv.to_string_lossy().to_string());
    }

    anyhow::bail!("no installable specified for prefetch")
}
