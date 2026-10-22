//! Retires cold derived indexes without adopting names or bytes as authority.
//!
//! Classification is restricted to the generated flat namespace under the actual
//! objects root. All candidates are checked before any unlink. Original retained
//! descriptors keep uncertain physical effects charged through reconciliation.

use super::{SharedNamespaceObservation, invalid, same_inode, same_payload_binding};
use crate::host_quota::NativeProject;
use rustix::fs::{AtFlags, statat, unlinkat};
use std::{
    fs::File,
    io,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::Path,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Candidate {
    Temporary,
    Canonical,
}

impl SharedNamespaceObservation {
    /// Reports generated derived-index names in the exhaustive original scan.
    ///
    /// # Errors
    /// Refuses malformed names within the reserved flat surface namespace.
    pub(in crate::host_cache::owner) fn has_surface_indexes(&self) -> io::Result<bool> {
        for entry in &self.entries {
            if classify(&entry.relative)?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Retires only checked cold derived indexes under an already funded turn.
    ///
    /// This establishes no content identity or adoption authority. The caller
    /// retains original recovery funding, refreshes the exhaustive scan and
    /// authenticates actual project charges before releasing future copy holds.
    ///
    /// # Errors
    /// Refuses malformed reserved names, unsafe inode type, foreign custody,
    /// extra hard links, changed namespace, unlink or parent synchronization.
    pub(in crate::host_cache::owner) fn discard_surface_indexes(&self) -> io::Result<usize> {
        let mut candidates = Vec::new();
        candidates
            .try_reserve_exact(self.entries.len())
            .map_err(io::Error::other)?;
        for entry in &self.entries {
            let Some(kind) = classify(&entry.relative)? else {
                continue;
            };
            if !entry.metadata.is_file() {
                return Err(invalid("cold surface candidate is not a regular inode"));
            }
            let name = entry
                .name
                .to_str()
                .ok_or_else(|| invalid("surface name is not UTF-8"))?;
            let file = super::super::open_regular_at(&entry.parent, name)?;
            self.check_surface_file(&file, &entry.metadata, kind)?;
            candidates.push((entry, file, kind));
        }
        self.check_current()?;

        for (entry, file, kind) in &candidates {
            self.confinement.check_current()?;
            self.layout.recheck()?;
            self.check_root(&entry.parent)?;
            let name = entry
                .name
                .to_str()
                .ok_or_else(|| invalid("surface name is not UTF-8"))?;
            let named = super::super::open_regular_at(&entry.parent, name)?;
            self.check_surface_file(&named, &entry.metadata, *kind)?;
            self.check_surface_file(file, &entry.metadata, *kind)?;
            unlinkat(&entry.parent, name, AtFlags::empty())?;
            entry.parent.sync_all()?;
            let after = file.metadata()?;
            if !same_payload_binding(&entry.metadata, &after) || after.nlink() != 0 {
                return Err(invalid(
                    "surface retirement changed another inode or payload",
                ));
            }
            match statat(&entry.parent, name, AtFlags::SYMLINK_NOFOLLOW) {
                Err(rustix::io::Errno::NOENT) => {}
                Err(error) => return Err(error.into()),
                Ok(_) => return Err(invalid("surface name survived retirement or was replaced")),
            }
        }
        self.confinement.check_current()?;
        self.layout.recheck()?;
        Ok(candidates.len())
    }

    fn check_surface_file(
        &self,
        file: &File,
        expected: &std::fs::Metadata,
        kind: Candidate,
    ) -> io::Result<()> {
        let metadata = file.metadata()?;
        let project = NativeProject::inspect(file)?;
        let mode = metadata.mode() & 0o7777;
        let valid_mode = match kind {
            Candidate::Canonical => mode == 0o400,
            Candidate::Temporary => matches!(mode, 0o400 | 0o600),
        };
        if !metadata.is_file()
            || !same_inode(expected, &metadata)
            || metadata.nlink() != 1
            || metadata.uid() != self.uid
            || metadata.gid() != self.gid
            || !valid_mode
            || metadata.dev() != self.layout.directory_binding("layout-root")?.0
            || project.project_id != self.project_id
            || (project.device, project.inode) != (metadata.dev(), metadata.ino())
        {
            return Err(invalid(
                "cold surface inode differs from original native custody",
            ));
        }
        Ok(())
    }
}

fn classify(path: &Path) -> io::Result<Option<Candidate>> {
    if path.parent() != Some(Path::new("objects")) {
        return Ok(None);
    }
    let name = path
        .file_name()
        .ok_or_else(|| invalid("surface candidate has no name"))?
        .as_bytes();
    if let Some(token) = name.strip_prefix(b".terrane-surface-tmp:") {
        if lower_hex(token, 32) {
            return Ok(Some(Candidate::Temporary));
        }
        return Err(invalid("malformed surface temporary identifier"));
    }
    if let Some(key) = name.strip_prefix(b".terrane-surface:") {
        let Some(separator) = key.iter().position(|byte| *byte == b':') else {
            return Err(invalid("surface key has no version separator"));
        };
        let version = &key[..separator];
        let version_text =
            std::str::from_utf8(version).map_err(|_| invalid("surface version is not UTF-8"))?;
        let value = version_text
            .parse::<u16>()
            .map_err(|_| invalid("surface version overflows"))?;
        if value != 0 && version_text == value.to_string() && lower_hex(&key[separator + 1..], 64) {
            return Ok(Some(Candidate::Canonical));
        }
        return Err(invalid("malformed canonical surface key"));
    }
    if name.starts_with(b".terrane-surface") {
        return Err(invalid("unrecognized name in reserved surface namespace"));
    }
    Ok(None)
}

fn lower_hex(bytes: &[u8], length: usize) -> bool {
    bytes.len() == length
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn cold_surface_classification_is_exact_and_does_not_adopt_content() {
        let digest = "01".repeat(32);
        for version in [1, 2, 65535] {
            assert_eq!(
                classify(Path::new(&format!(
                    "objects/.terrane-surface:{version}:{digest}"
                )))
                .unwrap(),
                Some(Candidate::Canonical)
            );
        }
        assert_eq!(
            classify(Path::new(&format!(
                "objects/.terrane-surface-tmp:{}",
                "23".repeat(16)
            )))
            .unwrap(),
            Some(Candidate::Temporary)
        );
        for path in [
            "objects/unrelated",
            "chunks/.terrane-surface:2:bad",
            "objects/nested/.terrane-surface-tmp:bad",
        ] {
            assert_eq!(classify(Path::new(path)).unwrap(), None);
        }
        for name in [
            format!(".terrane-surface:0:{digest}"),
            format!(".terrane-surface:02:{digest}"),
            format!(".terrane-surface:65536:{digest}"),
            format!(
                ".terrane-surface:2:{}",
                digest.to_uppercase().replace('0', "A")
            ),
            format!(".terrane-surface:2:{digest}:extra"),
            ".terrane-surface-tmp:short".into(),
            ".terrane-surface-old".into(),
        ] {
            assert!(classify(&Path::new("objects").join(name)).is_err());
        }
        let malformed = std::ffi::OsStr::from_bytes(b"objects/.terrane-surface-tmp:\xff");
        assert!(classify(Path::new(malformed)).is_err());
    }
}
