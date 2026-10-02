//! Runtime requirements and AOS target identity validation.
//!
//! Portable package and registry operations deliberately work on non-AOS
//! hosts. Commands that select the system profile or manipulate live runtime
//! state must first establish the target they are authorized to interpret as
//! AOS. An explicit `AOS_ROOT` selects an offline root; otherwise the running
//! root must expose the immutable AOS identity at
//! `/usr/lib/aos/toplevel/os-release`.

use std::collections::{BTreeMap, VecDeque};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Component, Path, PathBuf};

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

/// Reads the selected host release for runtime compatibility evaluation.
///
/// Portable scopes may lack an AOS identity; constrained packages fail closed
/// later when no release is available.
///
/// # Errors
/// Returns an error for an invalid root override, unreadable identity, malformed
/// release entries, or paths that cannot be resolved inside the selected root.
pub(crate) fn os_release() -> Result<Option<aos_doc_model::runtime::OsRelease>> {
    os_release_in(&selected_root()?, env::var_os("AOS_ROOT").is_some())
}

fn os_release_in(
    root: &Path,
    allow_installed_identity: bool,
) -> Result<Option<aos_doc_model::runtime::OsRelease>> {
    let identities = ["/usr/lib/aos/toplevel/os-release", "/etc/os-release"];
    for logical in identities
        .into_iter()
        .take(if allow_installed_identity { 2 } else { 1 })
    {
        let identity = rooted_path(root, Path::new(logical))?;
        if !identity.is_file() {
            continue;
        }
        let values = parse_os_release(&identity)?;
        if values.get("ID").map(String::as_str) != Some("aos") {
            return Ok(None);
        }
        let Some(version) = values.get("VERSION_ID") else {
            return Ok(None);
        };
        return Ok(Some(aos_doc_model::runtime::OsRelease {
            name: values.get("NAME").cloned().unwrap_or_else(|| "aos".into()),
            version: version.clone(),
        }));
    }
    Ok(None)
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
    let immutable = rooted_path(root, Path::new("/usr/lib/aos/toplevel/os-release"))?;
    let identity = if immutable.is_file() {
        immutable.clone()
    } else if !live_only {
        let installed = rooted_path(root, Path::new("/etc/os-release"))?;
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
    let library = values
        .get("AOS_PACKAGE_MODULE_LIBRARY")
        .with_context(|| format!("{} has no AOS_PACKAGE_MODULE_LIBRARY", identity.display()))?;
    // Native modules bind compatibility to the retained source library rather
    // than the retired shared-option-schema ABI integer. Source admission owns
    // artifact availability and custody; this gate checks the declared identity.
    crate::deployment::nix::store_root_and_suffix(Path::new(library)).with_context(|| {
        format!(
            "{} has invalid AOS_PACKAGE_MODULE_LIBRARY={library}",
            identity.display()
        )
    })?;
    Ok(())
}

/// Resolves a logical absolute path inside an AOS root.
///
/// Absolute symlink targets are interpreted relative to `root`, matching
/// chroot semantics. This matters during initrd operation, where immutable AOS
/// identities point into `/nix/store` while the target filesystem is mounted
/// below `/sysroot`.
fn rooted_path(root: &Path, logical: &Path) -> Result<PathBuf> {
    const MAX_SYMLINKS: usize = 40;

    let mut pending = logical_components(logical)?;
    let mut resolved = PathBuf::new();
    let mut followed = 0;

    while let Some(component) = pending.pop_front() {
        resolved.push(&component);
        let candidate = root.join(&resolved);
        let metadata = match fs::symlink_metadata(&candidate) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                resolved.extend(pending);
                return Ok(root.join(resolved));
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("checking rooted AOS path {}", candidate.display()));
            }
        };
        if !metadata.file_type().is_symlink() {
            continue;
        }

        followed += 1;
        if followed > MAX_SYMLINKS {
            bail!("too many symlinks while resolving {}", logical.display());
        }
        resolved.pop();
        let target = fs::read_link(&candidate)
            .with_context(|| format!("reading rooted AOS symlink {}", candidate.display()))?;
        let target = if target.is_absolute() {
            target
        } else {
            resolved.join(target)
        };
        resolved.clear();
        let mut target_components = logical_components(&target)?;
        target_components.append(&mut pending);
        pending = target_components;
    }

    Ok(root.join(resolved))
}

fn logical_components(path: &Path) -> Result<VecDeque<OsString>> {
    let mut components = VecDeque::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) => bail!("unsupported rooted path prefix: {}", path.display()),
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                if components.pop_back().is_none() {
                    bail!("rooted path escapes its AOS root: {}", path.display());
                }
            }
            Component::Normal(value) => components.push_back(value.to_os_string()),
        }
    }
    Ok(components)
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

    use super::{os_release_in, validate_aos_root};

    #[test]
    fn accepts_an_identified_offline_aos_root() {
        let root = tempdir().unwrap();
        fs::create_dir_all(root.path().join("etc")).unwrap();
        fs::write(
            root.path().join("etc/os-release"),
            "NAME=AOS\nID=aos\nAOS_PACKAGE_MODULE_LIBRARY=/nix/store/00000000000000000000000000000000-aos-module-library\n",
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
            "NAME=AOS\nID=aos\nAOS_PACKAGE_MODULE_LIBRARY=/nix/store/00000000000000000000000000000000-aos-module-library\n",
        )
        .unwrap();
        symlink(
            identity,
            root.path().join(&toplevel[1..]).join("os-release"),
        )
        .unwrap();
        fs::create_dir_all(root.path().join("usr/lib/aos")).unwrap();
        symlink(toplevel, root.path().join("usr/lib/aos/toplevel")).unwrap();

        validate_aos_root(root.path(), false).unwrap();
    }

    #[test]
    fn rejects_an_absolute_toplevel_link_that_escapes_the_offline_root() {
        let root = tempdir().unwrap();
        fs::create_dir_all(root.path().join("usr/lib/aos")).unwrap();
        symlink("/../etc", root.path().join("usr/lib/aos/toplevel")).unwrap();

        let error = validate_aos_root(root.path(), false).unwrap_err();
        assert!(format!("{error:#}").contains("rooted path escapes its AOS root"));
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
    fn rejects_retired_or_invalid_module_library_identities() {
        let root = tempdir().unwrap();
        fs::create_dir_all(root.path().join("etc")).unwrap();
        let identity = root.path().join("etc/os-release");
        fs::write(&identity, "ID=aos\nAOS_MODULE_ABI=7\n").unwrap();

        let error = validate_aos_root(root.path(), false).unwrap_err();
        assert!(format!("{error:#}").contains("has no AOS_PACKAGE_MODULE_LIBRARY"));

        for library in [
            "/tmp/aos-module-library",
            "/nix/store/not-a-store-object",
            "/nix/store/00000000000000000000000000000000-aos-module-library/../foreign",
        ] {
            fs::write(
                &identity,
                format!("ID=aos\nAOS_PACKAGE_MODULE_LIBRARY={library}\n"),
            )
            .unwrap();

            let error = validate_aos_root(root.path(), false).unwrap_err();
            assert!(format!("{error:#}").contains("has invalid AOS_PACKAGE_MODULE_LIBRARY"));
        }
    }

    #[test]
    fn live_runtime_requires_the_immutable_identity() {
        let root = tempdir().unwrap();
        fs::create_dir_all(root.path().join("etc")).unwrap();
        fs::write(
            root.path().join("etc/os-release"),
            "ID=aos\nAOS_PACKAGE_MODULE_LIBRARY=/nix/store/00000000000000000000000000000000-aos-module-library\n",
        )
        .unwrap();

        assert!(validate_aos_root(root.path(), true).is_err());
    }

    #[test]
    fn accepts_store_symlinks_rooted_below_an_initrd_mount() {
        let root = tempdir().unwrap();
        fs::create_dir_all(root.path().join("nix/store/aos-system")).unwrap();
        fs::write(
            root.path().join("nix/store/os-release"),
            "ID=aos\nAOS_PACKAGE_MODULE_LIBRARY=/nix/store/00000000000000000000000000000000-aos-module-library\n",
        )
        .unwrap();
        fs::create_dir_all(root.path().join("usr/lib/aos")).unwrap();
        symlink(
            "/nix/store/aos-system",
            root.path().join("usr/lib/aos/toplevel"),
        )
        .unwrap();
        symlink(
            "/nix/store/os-release",
            root.path().join("nix/store/aos-system/os-release"),
        )
        .unwrap();

        validate_aos_root(root.path(), false).unwrap();
    }

    #[test]
    fn current_release_prefers_immutable_target_identity() {
        let root = tempdir().unwrap();
        fs::create_dir_all(root.path().join("usr/lib/aos/toplevel")).unwrap();
        fs::create_dir_all(root.path().join("etc")).unwrap();
        fs::write(
            root.path().join("usr/lib/aos/toplevel/os-release"),
            "ID=aos\nNAME=Current OS\nVERSION_ID=2.0.0\n",
        )
        .unwrap();
        fs::write(
            root.path().join("etc/os-release"),
            "ID=aos\nNAME=Stale OS\nVERSION_ID=1.0.0\n",
        )
        .unwrap();

        let release = os_release_in(root.path(), false).unwrap().unwrap();

        assert_eq!(release.name, "Current OS");
        assert_eq!(release.version, "2.0.0");
    }

    #[test]
    fn installed_release_fallback_requires_an_explicit_offline_target() {
        let root = tempdir().unwrap();
        fs::create_dir_all(root.path().join("etc")).unwrap();
        fs::write(
            root.path().join("etc/os-release"),
            "ID=aos\nNAME=Offline OS\nVERSION_ID=1.0.0\n",
        )
        .unwrap();

        assert_eq!(os_release_in(root.path(), false).unwrap(), None);
        let release = os_release_in(root.path(), true).unwrap().unwrap();
        assert_eq!(release.name, "Offline OS");
        assert_eq!(release.version, "1.0.0");
    }
}
