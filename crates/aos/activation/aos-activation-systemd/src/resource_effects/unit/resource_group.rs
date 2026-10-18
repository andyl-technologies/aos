//! Renders early package slices and checks their initial immutable image custody.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::{ResourceGroup, resource_group_name, scalar};
use crate::resource_effects::{digest, normalized_path, read_regular, reject_symlink_ancestors};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ImageCustody {
    target: PathBuf,
    seed_digest: String,
}

pub(super) fn seed_text(input: &ResourceGroup) -> Result<String> {
    resource_group_name(&input.name)?;
    Ok(format!(
        "[Unit]\nDescription={}\n\n[Slice]\n",
        scalar(&input.description)?
    ))
}

/// Renders only the selected early resource groups, without enablement links.
///
/// # Errors
/// Returns an error for malformed inputs, duplicate names, unsafe output paths,
/// or failure to write the exact shared seed definitions.
pub(crate) fn render_resource_groups(bytes: &[u8], output: &Path) -> Result<()> {
    let inputs: Vec<ResourceGroup> = serde_json::from_slice(bytes)?;
    let mut names = BTreeSet::new();
    let mut definitions = Vec::new();
    for input in inputs {
        let text = seed_text(&input)?;
        ensure!(
            names.insert(input.name.clone()),
            "duplicate resource group seed"
        );
        if input.bootstrap {
            definitions.push((format!("{}.slice", input.name), text));
        }
    }
    reject_symlink_ancestors(&output.join("entry"))?;
    fs::create_dir_all(output)?;
    for (name, text) in definitions {
        let path = output.join(name);
        ensure!(
            fs::symlink_metadata(&path)
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
            "resource group seed already exists"
        );
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(text.as_bytes())?;
    }
    Ok(())
}

fn canonical_member(target: &Path) -> Result<()> {
    let text = target.to_str().context("image group member is not UTF-8")?;
    normalized_path(text)?;
    let suffix = target
        .strip_prefix("/nix/store")
        .context("image group member is outside the immutable store")?;
    let mut parts = suffix.components();
    let Some(Component::Normal(root)) = parts.next() else {
        anyhow::bail!("image group has no store root")
    };
    let root = root.to_str().context("image group root is not UTF-8")?;
    ensure!(
        root.len() > 33
            && root.as_bytes()[32] == b'-'
            && root.as_bytes()[..32]
                .iter()
                .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(byte))
            && parts.next().is_some(),
        "image group is not a canonical store member"
    );
    Ok(())
}

pub(super) fn read_member(target: &Path) -> Result<Vec<u8>> {
    canonical_member(target)?;
    read_member_at(target)
}

fn read_member_at(target: &Path) -> Result<Vec<u8>> {
    use rustix::fs::{Mode, OFlags, open, openat};

    ensure!(target.is_absolute(), "image group member must be absolute");
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = open("/", directory_flags, Mode::empty())?;
    let mut components = target.components().skip(1).peekable();
    let member = loop {
        let component = components
            .next()
            .context("image group member has no leaf")?;
        let Component::Normal(name) = component else {
            anyhow::bail!("image group member contains traversal")
        };
        if components.peek().is_none() {
            break openat(
                &directory,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
        }
        directory = openat(&directory, name, directory_flags, Mode::empty())
            .context("image group member ancestor is not a pinned real directory")?;
    };
    let file = fs::File::from(member);
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.mode() & 0o222 == 0
            && metadata.len() <= 262_144,
        "image group member is not an owned read-only regular file"
    );
    let mut bytes = Vec::new();
    file.take(262_145).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 262_144,
        "image group member exceeds byte limit"
    );
    Ok(bytes)
}

pub(super) fn initial_at(
    path: &Path,
    input: &ResourceGroup,
    read: impl Fn(&Path) -> Result<Vec<u8>>,
) -> Result<Option<ImageCustody>> {
    reject_symlink_ancestors(path)?;
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_symlink() {
        return Ok(None);
    }
    ensure!(
        input.bootstrap,
        "image group alias is not selected for bootstrap"
    );
    let target = fs::read_link(path)?;
    canonical_member(&target)?;
    let seed = seed_text(input)?;
    ensure!(
        read(&target)? == seed.as_bytes(),
        "image group seed differs from selected policy"
    );
    Ok(Some(ImageCustody {
        target,
        seed_digest: digest(seed.as_bytes()),
    }))
}

/// Checks pending custody without granting authority to any replacement path.
pub(super) fn alias_at(
    path: &Path,
    custody: &ImageCustody,
    seed: &str,
    desired: &str,
    read: impl Fn(&Path) -> Result<Vec<u8>>,
) -> Result<bool> {
    reject_symlink_ancestors(path)?;
    canonical_member(&custody.target)?;
    ensure!(
        custody.seed_digest == digest(seed.as_bytes()),
        "pending image group seed differs"
    );
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
        Ok(metadata) if metadata.file_type().is_symlink() => {
            ensure!(
                fs::read_link(path)? == custody.target,
                "pending image group alias was replaced"
            );
            ensure!(
                read(&custody.target)? == seed.as_bytes(),
                "pending image group member changed"
            );
            Ok(true)
        }
        Ok(_) => {
            ensure!(
                read_regular(path, 262_144)?.as_deref() == Some(desired.as_bytes()),
                "pending image group regular file changed"
            );
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(bootstrap: bool) -> ResourceGroup {
        serde_json::from_value(serde_json::json!({
            "name":"aos-pkg-nginx", "description":"Package workers at 50%", "bootstrap":bootstrap
        }))
        .unwrap()
    }

    fn target() -> PathBuf {
        PathBuf::from("/nix/store/00000000000000000000000000000000-group-seed/aos-pkg-nginx.slice")
    }

    #[test]
    fn resource_group_seed_renderer_selects_bootstrap_without_enablement_or_revision() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("units");
        let bytes = serde_json::to_vec(&serde_json::json!([
            {"name":"aos-pkg-nginx", "description":"Package workers at 50%", "bootstrap":true},
            {"name":"aos-pkg-envoy", "bootstrap":false}
        ]))
        .unwrap();

        render_resource_groups(&bytes, &output).unwrap();

        assert_eq!(
            fs::read_to_string(output.join("aos-pkg-nginx.slice")).unwrap(),
            seed_text(&input(true)).unwrap()
        );
        assert_eq!(fs::read_dir(output).unwrap().count(), 1);
        assert_eq!(
            seed_text(&input(true)).unwrap(),
            "[Unit]\nDescription=Package workers at 50%%\n\n[Slice]\n"
        );
        let invalid = serde_json::to_vec(&serde_json::json!([
            {"name":"aos-pkg-nginx", "bootstrap":true, "untrusted":true}
        ]))
        .unwrap();
        assert!(render_resource_groups(&invalid, &directory.path().join("invalid")).is_err());
        assert!(!directory.path().join("invalid").exists());
    }

    #[test]
    fn resource_group_initial_alias_requires_bootstrap_exact_seed_and_canonical_member() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("aos-pkg-nginx.slice");
        std::os::unix::fs::symlink(target(), &path).unwrap();
        let seed = seed_text(&input(true)).unwrap();
        // The injected member reader models an already checked immutable source
        // without creating store artifacts or claiming release authentication.
        let read = |member: &Path| {
            assert_eq!(member, target());
            Ok(seed.as_bytes().to_vec())
        };

        let custody = initial_at(&path, &input(true), read).unwrap().unwrap();

        assert_eq!(custody.target, target());
        assert_eq!(custody.seed_digest, digest(seed.as_bytes()));
        assert!(initial_at(&path, &input(false), read).is_err());
        assert!(initial_at(&path, &input(true), |_| Ok(b"foreign seed".to_vec())).is_err());
        for foreign in [
            "../foreign",
            "/tmp/seed.slice",
            "/nix/store/invalid/seed.slice",
        ] {
            fs::remove_file(&path).unwrap();
            std::os::unix::fs::symlink(foreign, &path).unwrap();
            assert!(
                initial_at(&path, &input(true), |_| panic!("noncanonical member read")).is_err()
            );
        }
    }

    #[test]
    fn resource_group_pending_conversion_recovers_gaps_and_preserves_foreign_replacements() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("aos-pkg-nginx.slice");
        std::os::unix::fs::symlink(target(), &path).unwrap();
        let seed = seed_text(&input(true)).unwrap();
        let read = |_: &Path| Ok(seed.as_bytes().to_vec());
        let custody = initial_at(&path, &input(true), read).unwrap().unwrap();
        let bytes = serde_json::to_vec(&custody).unwrap();
        let retained: ImageCustody = serde_json::from_slice(&bytes).unwrap();
        let desired = "[Unit]\nDescription=owned\nDocumentation=file:revision\n\n[Slice]\n";

        assert!(alias_at(&path, &retained, &seed, desired, read).unwrap());
        fs::remove_file(&path).unwrap();
        assert!(!alias_at(&path, &retained, &seed, desired, read).unwrap());
        fs::write(&path, desired).unwrap();
        assert!(!alias_at(&path, &retained, &seed, desired, read).unwrap());
        fs::write(&path, "foreign").unwrap();
        assert!(alias_at(&path, &retained, &seed, desired, read).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "foreign");
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(
            "/nix/store/11111111111111111111111111111111-foreign/aos-pkg-nginx.slice",
            &path,
        )
        .unwrap();
        assert!(alias_at(&path, &retained, &seed, desired, read).is_err());
        assert_eq!(serde_json::to_vec(&retained).unwrap(), bytes);
        // Completed receipts use the normal regular-file reader, never custody.
        assert!(read_regular(&path, 262_144).is_err());
    }

    #[test]
    fn resource_group_immutable_member_reader_rejects_symlink_leaves_and_ancestors() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("seed.slice");
        fs::write(&source, "seed").unwrap();
        let alias = directory.path().join("alias.slice");
        std::os::unix::fs::symlink(&source, &alias).unwrap();
        assert!(read_member_at(&alias).is_err());
        let parent = directory.path().join("parent");
        std::os::unix::fs::symlink(directory.path(), &parent).unwrap();
        assert!(
            read_member_at(&parent.join("seed.slice"))
                .unwrap_err()
                .to_string()
                .contains("ancestor")
        );
    }
}
