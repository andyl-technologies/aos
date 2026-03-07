use std::path::Path;

use anyhow::Result;

use aos_core::nix::NixCli;

/// Resolve installable arguments to store paths.
pub fn resolve_installables(
    nix: &NixCli,
    installables: &[String],
    file: Option<&str>,
    attr: Option<&str>,
    expr: Option<&str>,
) -> Result<Vec<String>> {
    // Raw expression.
    if let Some(expr) = expr {
        let drv = nix.instantiate_expr(expr)?;
        let path = nix.realise(&drv.to_string_lossy())?;
        return Ok(vec![path]);
    }

    // Explicit -A attr.
    if let Some(attr) = attr {
        let file_path = Path::new(file.unwrap_or("./default.nix"));
        let path = nix.build(file_path, attr)?;
        return Ok(vec![path.to_string_lossy().to_string()]);
    }

    let mut paths = Vec::new();
    let file_path = Path::new(file.unwrap_or("./default.nix"));

    for installable in installables {
        // Direct store paths.
        if installable.starts_with("/nix/store/") {
            paths.push(installable.clone());
            continue;
        }

        // Bare name -> pkgs.<name> (AOS convention).
        let attr = format!("pkgs.{installable}");
        let path = nix.build(file_path, &attr)?;
        paths.push(path.to_string_lossy().to_string());
    }

    if paths.is_empty() {
        anyhow::bail!("no installables specified");
    }

    Ok(paths)
}
