//! Runtime requirements and AOS target identity validation.
//!
//! Portable package and registry operations deliberately work on non-AOS
//! hosts. Commands that select the system profile or manipulate live runtime
//! state must first establish the target they are authorized to interpret as
//! AOS. An explicit `AOS_ROOT` selects an offline root; otherwise the running
//! root must expose the immutable AOS identity at
//! `/aos-toplevel/os-release`.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// Describes the host assumptions a package command is allowed to make.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeRequirement {
    /// Runs without assuming that the host operating system is AOS.
    Portable,
    /// Reads or mutates a validated live or explicitly selected AOS root.
    AosRoot,
    /// Runs only as part of the live AOS service and activation machinery.
    LiveAos,
}

impl RuntimeRequirement {
    /// Validates the process environment before the command performs I/O.
    ///
    /// # Errors
    ///
    /// Returns an error when an AOS-root command has no valid AOS identity,
    /// when `AOS_ROOT` is empty or relative, or when a live-runtime command is
    /// redirected to an offline root.
    pub fn validate(self) -> Result<()> {
        match self {
            Self::Portable => Ok(()),
            Self::AosRoot => validate_aos_root(&selected_root()?, false),
            Self::LiveAos => {
                if env::var_os("AOS_ROOT").is_some() {
                    bail!("live AOS runtime commands do not accept AOS_ROOT");
                }
                validate_aos_root(Path::new("/"), true)
            }
        }
    }
}

/// Resolves the command's AOS root without silently accepting bad overrides.
fn selected_root() -> Result<PathBuf> {
    let Some(value) = env::var_os("AOS_ROOT") else {
        return Ok(PathBuf::from("/"));
    };
    if value.is_empty() {
        bail!("AOS_ROOT must not be empty");
    }

    let root = PathBuf::from(value);
    if !root.is_absolute() {
        bail!("AOS_ROOT must be an absolute path: {}", root.display());
    }
    Ok(root)
}

/// Validates the immutable identity of an AOS root.
fn validate_aos_root(root: &Path, live_only: bool) -> Result<()> {
    let immutable = root.join("aos-toplevel/os-release");
    let identity = if let Some(identity) = immutable_identity(root)? {
        identity
    } else if !live_only {
        let installed = root.join("etc/os-release");
        if installed.is_file() {
            installed
        } else {
            bail!(
                "{} is not an AOS root: neither {} nor {} exists",
                root.display(),
                immutable.display(),
                installed.display()
            );
        }
    } else {
        bail!(
            "the running system is not AOS: {} is missing",
            immutable.display()
        );
    };

    let values = parse_os_release(&identity)?;
    if values.get("ID").map(String::as_str) != Some("aos") {
        bail!("{} does not identify ID=aos", identity.display());
    }
    let module_abi = values
        .get("AOS_MODULE_ABI")
        .with_context(|| format!("{} has no AOS_MODULE_ABI", identity.display()))?;
    module_abi.parse::<u32>().with_context(|| {
        format!(
            "{} has invalid AOS_MODULE_ABI={module_abi}",
            identity.display()
        )
    })?;
    Ok(())
}

/// Resolves the immutable identity inside the selected root's mount namespace.
///
/// Installed roots use an absolute `/aos-toplevel` symlink. When an initrd
/// selects that root through `AOS_ROOT=/sysroot`, ordinary host path traversal
/// would follow the link through the initrd's `/nix/store` instead of the
/// mounted system's `/sysroot/nix/store`.
fn immutable_identity(root: &Path) -> Result<Option<PathBuf>> {
    let identity = root.join("aos-toplevel/os-release");
    if root == Path::new("/") {
        return Ok(identity.is_file().then_some(identity));
    }

    let link = root.join("aos-toplevel");
    let Ok(metadata) = fs::symlink_metadata(&link) else {
        return Ok(None);
    };
    if !metadata.file_type().is_symlink() {
        return Ok(identity.is_file().then_some(identity));
    }

    let target = fs::read_link(&link)
        .with_context(|| format!("reading immutable AOS identity link {}", link.display()))?;
    let Some(toplevel) = path_in_selected_root(root, &target)? else {
        return Ok(None);
    };

    let identity = toplevel.join("os-release");
    let Ok(metadata) = fs::symlink_metadata(&identity) else {
        return Ok(None);
    };
    if !metadata.file_type().is_symlink() {
        return Ok(metadata.is_file().then_some(identity));
    }

    let target = fs::read_link(&identity)
        .with_context(|| format!("reading immutable AOS identity link {}", identity.display()))?;
    let Some(identity) = path_in_selected_root(root, &target)? else {
        return Ok(None);
    };
    Ok(identity.is_file().then_some(identity))
}

/// Maps an absolute path from the selected root's namespace onto the host path.
fn path_in_selected_root(root: &Path, target: &Path) -> Result<Option<PathBuf>> {
    let Ok(relative) = target.strip_prefix("/") else {
        return Ok(None);
    };
    if relative
        .components()
        .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        bail!(
            "immutable AOS identity link escapes the selected root: {}",
            target.display()
        );
    }
    Ok(Some(root.join(relative)))
}

/// Reads the fields required from an os-release identity document.
fn parse_os_release(path: &Path) -> Result<BTreeMap<String, String>> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("reading AOS identity {}", path.display()))?;
    let mut values = BTreeMap::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        values.insert(key.to_string(), value.trim_matches(['\'', '"']).to_string());
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;

    use tempfile::tempdir;

    use super::validate_aos_root;

    #[test]
    fn accepts_an_identified_offline_aos_root() {
        let root = tempdir().unwrap();
        fs::create_dir_all(root.path().join("etc")).unwrap();
        fs::write(
            root.path().join("etc/os-release"),
            "NAME=AOS\nID=aos\nAOS_MODULE_ABI=7\n",
        )
        .unwrap();

        validate_aos_root(root.path(), false).unwrap();
    }

    #[test]
    fn accepts_an_absolute_toplevel_link_inside_an_offline_root() {
        let root = tempdir().unwrap();
        let toplevel = "/nix/store/00000000000000000000000000000000-aos-system";
        let identity = "/nix/store/11111111111111111111111111111111-etc-os-release/os-release";
        fs::create_dir_all(root.path().join(&toplevel[1..])).unwrap();
        fs::create_dir_all(root.path().join(&identity[1..]).parent().unwrap()).unwrap();
        fs::write(
            root.path().join(&identity[1..]),
            "NAME=AOS\nID=aos\nAOS_MODULE_ABI=7\n",
        )
        .unwrap();
        symlink(
            identity,
            root.path().join(&toplevel[1..]).join("os-release"),
        )
        .unwrap();
        symlink(toplevel, root.path().join("aos-toplevel")).unwrap();

        validate_aos_root(root.path(), false).unwrap();
    }

    #[test]
    fn rejects_an_absolute_toplevel_link_that_escapes_the_offline_root() {
        let root = tempdir().unwrap();
        symlink("/../etc", root.path().join("aos-toplevel")).unwrap();

        let error = validate_aos_root(root.path(), false).unwrap_err();
        assert!(format!("{error:#}").contains("escapes the selected root"));
    }

    #[test]
    fn rejects_a_non_aos_or_incomplete_root() {
        let root = tempdir().unwrap();
        fs::create_dir_all(root.path().join("etc")).unwrap();
        fs::write(root.path().join("etc/os-release"), "ID=linux\n").unwrap();
        assert!(validate_aos_root(root.path(), false).is_err());

        fs::write(root.path().join("etc/os-release"), "ID=aos\n").unwrap();
        assert!(validate_aos_root(root.path(), false).is_err());
    }

    #[test]
    fn live_runtime_requires_the_immutable_identity() {
        let root = tempdir().unwrap();
        fs::create_dir_all(root.path().join("etc")).unwrap();
        fs::write(
            root.path().join("etc/os-release"),
            "ID=aos\nAOS_MODULE_ABI=1\n",
        )
        .unwrap();

        assert!(validate_aos_root(root.path(), true).is_err());
    }
}
