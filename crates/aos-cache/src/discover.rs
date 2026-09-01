//! Fixed-output derivation (FOD) discovery for prefetch.
//!
//! Prefetch wants the *sources* of a build, not its outputs: every
//! `fetchurl`-style derivation in the closure of a top-level `.drv`. This
//! module resolves an installable down to a `.drv` path and walks its
//! closure looking for derivations with an `outputHash` (the marker of a
//! fixed-output derivation).

use std::path::Path;

use anyhow::{Context, Result};

use aos_core::nix::NixCli;
use aos_core::nix::drv::{self, FixedOutputDrv};

/// Discovers all fixed-output derivations in the closure of a `.drv` file.
///
/// 1. Enumerate all `.drv` files in the closure via `nix-store -qR`.
/// 2. Parse each `.drv` and check for `outputHash` in the env section.
/// 3. Return the FODs found.
///
/// Individual `.drv` files that fail to parse are skipped with a warning
/// on stderr rather than failing the whole discovery — a closure may
/// contain the odd malformed derivation without invalidating the rest.
///
/// # Errors
///
/// Returns an error if the closure of `drv_path` cannot be enumerated
/// (e.g. the path does not exist or `nix-store` fails).
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

    for d in drv_paths {
        match drv::parse_drv_for_fod(d) {
            Ok(Some(fod)) => fods.push(fod),
            Ok(None) => {} // Not a FOD, skip.
            Err(e) => {
                // Log but don't fail — some .drv files may be malformed.
                eprintln!("warning: failed to parse {d}: {e}");
            }
        }
    }

    Ok(fods)
}

/// Resolves an installable to a `.drv` path for FOD discovery.
///
/// For prefetch, we need the `.drv` (not the built output) so we can
/// examine its closure for FODs without realising anything.
///
/// The selectors are tried in priority order:
///
/// 1. `expr` — instantiated as a raw Nix expression.
/// 2. `attr` — instantiated from `file` (default `./default.nix`).
/// 3. `installable` — used directly if it is already a `.drv` store path,
///    otherwise treated as a bare package name and instantiated as
///    `pkgs.<name>` (the AOS convention) from `file`.
///
/// When `target` is present, file/attribute instantiation receives it as the
/// top-level `crossSystem` string argument. Raw expressions cannot be paired
/// with `target` because the expression owns its import arguments.
///
/// # Errors
///
/// Returns an error if instantiation fails, or if none of `expr`, `attr`,
/// or `installable` is provided.
pub fn resolve_to_drv(
    nix: &NixCli,
    file: Option<&Path>,
    attr: Option<&str>,
    expr: Option<&str>,
    installable: Option<&str>,
    target: Option<&str>,
) -> Result<String> {
    if let Some(expr) = expr {
        if target.is_some() {
            anyhow::bail!(
                "--target cannot be combined with --expr; pass crossSystem in the expression"
            );
        }
        let drv = nix.instantiate_expr(expr)?;
        return Ok(drv.to_string_lossy().to_string());
    }

    if let Some(attr) = attr {
        let file = file.unwrap_or_else(|| Path::new("./default.nix"));
        let drv = match target {
            Some(target) => nix.instantiate_for_target(file, attr, target)?,
            None => nix.instantiate(file, attr)?,
        };
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
        let drv = match target {
            Some(target) => nix.instantiate_for_target(file, &attr, target)?,
            None => nix.instantiate(file, &attr)?,
        };
        return Ok(drv.to_string_lossy().to_string());
    }

    anyhow::bail!("no installable specified for prefetch")
}
