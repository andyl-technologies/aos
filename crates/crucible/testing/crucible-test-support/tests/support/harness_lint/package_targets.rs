//! Identifies Cargo library targets for package-wide error policy.
//!
//! Explicit `[lib]` targets remain libraries even when automatic discovery is
//! disabled. Binary source exemptions are a separate, unchanged policy.

use std::error::Error;
use std::fs;
use std::io;
use std::path::Path;

/// Reports whether Cargo discovers an explicit or implicit library target.
///
/// # Errors
/// Returns malformed manifest/target settings or an inaccessible implicit root.
/// Invalid settings never grant the binary-only package exemption.
pub(super) fn manifest_has_library_target(
    package_dir: &Path,
    manifest: &str,
) -> Result<bool, Box<dyn Error>> {
    let manifest: toml::Value = manifest.parse()?;
    let package = manifest
        .get("package")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| invalid_target("package must be a table"))?;
    let autolib = match package.get("autolib") {
        Some(value) => value
            .as_bool()
            .ok_or_else(|| invalid_target("package.autolib must be a boolean"))?,
        None => true,
    };

    if let Some(library) = manifest.get("lib") {
        let library = library
            .as_table()
            .ok_or_else(|| invalid_target("lib must be a table"))?;
        if let Some(path) = library.get("path")
            && path.as_str().is_none_or(str::is_empty)
        {
            return Err(invalid_target("lib.path must be a nonempty string").into());
        }

        return Ok(true);
    }

    if !autolib {
        return Ok(false);
    }

    match fs::metadata(package_dir.join("src/lib.rs")) {
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => Err(invalid_target("implicit library root must be a file").into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn invalid_target(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_logging::{
        error_logging_failures, manifest_error_dependency_failures, typed_error_policy_failures,
    };

    #[test]
    fn implicit_and_mixed_libraries_keep_package_error_policy() -> Result<(), Box<dyn Error>> {
        let package = tempfile::tempdir()?;
        fs::create_dir(package.path().join("src"))?;
        fs::write(package.path().join("src/lib.rs"), "")?;

        for binary in ["", "\n[[bin]]\nname = 'tool'\npath = 'src/main.rs'\n"] {
            if !binary.is_empty() {
                fs::write(package.path().join("src/main.rs"), "fn main() {}")?;
            }
            let manifest =
                format!("[package]\nname = 'mixed'\n[dependencies]\nanyhow = '1'\n{binary}");
            let is_library = manifest_has_library_target(package.path(), &manifest)?;

            assert!(is_library);
            assert!(!manifest_error_dependency_failures("mixed", &manifest, is_library).is_empty());
            assert!(!typed_error_policy_failures("mixed", &manifest, &[], is_library).is_empty());
        }

        Ok(())
    }

    #[test]
    fn explicit_custom_library_survives_disabled_discovery() -> Result<(), Box<dyn Error>> {
        let package = tempfile::tempdir()?;
        fs::create_dir(package.path().join("code"))?;
        fs::write(package.path().join("code/library.rs"), "")?;
        let manifest =
            "[package]\nname = 'custom'\nautolib = false\n[lib]\npath = 'code/library.rs'\n";

        assert!(manifest_has_library_target(package.path(), manifest)?);

        fs::create_dir(package.path().join("src"))?;
        fs::write(package.path().join("src/lib.rs"), "")?;
        assert!(manifest_has_library_target(
            package.path(),
            "[package]\nname = 'explicit'\n[lib]\n"
        )?);

        Ok(())
    }

    #[test]
    fn autolib_false_disables_only_implicit_library() -> Result<(), Box<dyn Error>> {
        let package = tempfile::tempdir()?;
        fs::create_dir(package.path().join("src"))?;
        fs::write(package.path().join("src/lib.rs"), "")?;

        assert!(!manifest_has_library_target(
            package.path(),
            "[package]\nname = 'explicit-only'\nautolib = false\n"
        )?);
        assert!(manifest_has_library_target(
            package.path(),
            "[package]\nname = 'explicit-only'\nautolib = false\n[lib]\n"
        )?);

        Ok(())
    }

    #[test]
    fn binary_only_package_does_not_relax_source_error_policy() -> Result<(), Box<dyn Error>> {
        let package = tempfile::tempdir()?;
        fs::create_dir(package.path().join("src"))?;
        fs::write(package.path().join("src/main.rs"), "fn main() {}")?;

        for manifest in [
            "[package]\nname = 'worker'\nautobins = false\n[[bin]]\nname = 'worker'\npath = 'src/main.rs'\n[dependencies]\nanyhow = '1'\n",
            "[package]\nname = 'worker'\n[dependencies]\nanyhow = '1'\n",
        ] {
            let is_library = manifest_has_library_target(package.path(), manifest)?;

            assert!(!is_library);
            assert!(manifest_error_dependency_failures("worker", manifest, is_library).is_empty());
            assert!(typed_error_policy_failures("worker", manifest, &[], is_library).is_empty());
        }

        assert!(
            !error_logging_failures(
                Path::new("worker/src/main.rs"),
                "fn main() -> anyhow::Result<()> { println!(\"still checked\"); Ok(()) }",
                false,
            )
            .is_empty()
        );

        Ok(())
    }

    #[test]
    fn malformed_library_settings_do_not_grant_an_exemption() -> Result<(), Box<dyn Error>> {
        let package = tempfile::tempdir()?;

        for manifest in [
            "[package",
            "package = []",
            "[package]\nname = 'bad'\nautolib = 'false'\n",
            "[package]\nname = 'bad'\n[lib]\npath = 42\n",
            "[package]\nname = 'bad'\n[lib]\npath = ''\n",
            "lib = []\n[package]\nname = 'bad'\n",
        ] {
            assert!(manifest_has_library_target(package.path(), manifest).is_err());
        }

        fs::create_dir_all(package.path().join("src/lib.rs"))?;
        assert!(
            manifest_has_library_target(package.path(), "[package]\nname = 'bad-root'\n").is_err()
        );

        Ok(())
    }
}
