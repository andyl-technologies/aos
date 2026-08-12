//! Versioned in-memory Nix `corepkgs` sources and virtual source identities.
//!
//! Stock Nix exposes generated sources through the hidden `nix/` search-path
//! prefix. The returned path values print like ordinary root paths (for
//! example `/fetchurl.nix`), but their contents do not come from the host root
//! filesystem. This module keeps that distinction explicit:
//!
//! ```text
//! SourcePath::RootFs("/fetchurl.nix")
//! SourcePath::Corepkgs(Nix2_34_8, "/fetchurl.nix")
//! ```
//!
//! Generated payloads are embedded byte-for-byte, including the leading
//! newline added by Nix's Meson `generate-header` step.

use crate::NixCompatProfile;
use std::fmt;

const NIX_2_24_12_FETCHURL: &[u8] = include_bytes!("corepkgs/nix_2_24_12/fetchurl.nix");
const NIX_2_24_12_DERIVATION_INTERNAL: &[u8] =
    include_bytes!("corepkgs/nix_2_24_12/derivation-internal.nix");
const NIX_2_34_8_FETCHURL: &[u8] = include_bytes!("corepkgs/nix_2_34_8/fetchurl.nix");

const NIX_2_24_12_ROOT: &[CorepkgsDirectoryEntry] = &[
    CorepkgsDirectoryEntry::regular(b"derivation-internal.nix"),
    CorepkgsDirectoryEntry::regular(b"fetchurl.nix"),
];
const NIX_2_34_8_ROOT: &[CorepkgsDirectoryEntry] =
    &[CorepkgsDirectoryEntry::regular(b"fetchurl.nix")];

/// Identifies either a real root-filesystem path or a profile-owned virtual path.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SourcePath {
    /// Reads through the evaluator's root-filesystem accessor.
    RootFs(Vec<u8>),
    /// Reads from the selected stock-Nix `corepkgs` table.
    Corepkgs(CorepkgsPath),
}

impl SourcePath {
    /// Creates a root-filesystem source identity without accessing the filesystem.
    pub fn root_fs(display_path: impl Into<Vec<u8>>) -> Self {
        Self::RootFs(display_path.into())
    }

    /// Creates a profile-owned virtual `corepkgs` source identity.
    ///
    /// # Errors
    ///
    /// Returns [`CorepkgsPathError`] unless `display_path` is a canonical
    /// absolute path.
    pub fn corepkgs(
        profile: NixCompatProfile,
        display_path: impl Into<Vec<u8>>,
    ) -> Result<Self, CorepkgsPathError> {
        CorepkgsPath::new(profile, display_path).map(Self::Corepkgs)
    }

    /// Returns the bytes exposed by path-to-string coercion.
    pub fn display_path(&self) -> &[u8] {
        match self {
            Self::RootFs(path) => path,
            Self::Corepkgs(path) => path.display_path(),
        }
    }

    /// Returns a typed accessor that preserves the path's source domain.
    pub fn accessor(&self) -> SourceAccessor<'_> {
        match self {
            Self::RootFs(path) => SourceAccessor::RootFs { path },
            Self::Corepkgs(path) => SourceAccessor::Corepkgs {
                path,
                entry: corepkgs_entry(path.profile(), path.display_path()),
            },
        }
    }

    /// Computes `dirOf` while preserving a virtual `corepkgs` identity.
    pub fn dir_of(&self) -> Self {
        let parent = parent_display_path(self.display_path());
        match self {
            Self::RootFs(_) => Self::RootFs(parent),
            Self::Corepkgs(path) => Self::Corepkgs(CorepkgsPath {
                profile: path.profile,
                display_path: parent,
            }),
        }
    }

    /// Concatenates path bytes using ordinary path-value semantics.
    ///
    /// Concatenation deliberately drops a virtual `corepkgs` identity. Stock
    /// Nix preserves the identity through `dirOf`, but path-plus-string
    /// produces an ordinary root-filesystem path with the same visible bytes.
    pub fn concat(&self, suffix: &[u8]) -> Self {
        let mut path = self.display_path().to_vec();
        let suffix = if path.ends_with(b"/") && suffix.starts_with(b"/") {
            &suffix[1..]
        } else {
            suffix
        };
        path.extend_from_slice(suffix);
        Self::RootFs(path)
    }
}

/// Identifies a path within one profile's in-memory `corepkgs` tree.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CorepkgsPath {
    profile: NixCompatProfile,
    display_path: Vec<u8>,
}

impl CorepkgsPath {
    /// Creates a canonical absolute virtual path.
    ///
    /// # Errors
    ///
    /// Returns [`CorepkgsPathError`] for a relative path, NUL byte, empty
    /// component, `.` or `..` component, or non-root trailing slash.
    pub fn new(
        profile: NixCompatProfile,
        display_path: impl Into<Vec<u8>>,
    ) -> Result<Self, CorepkgsPathError> {
        let display_path = display_path.into();
        validate_corepkgs_display_path(&display_path)?;
        Ok(Self {
            profile,
            display_path,
        })
    }

    /// Returns the owning stock-Nix compatibility profile.
    pub const fn profile(&self) -> NixCompatProfile {
        self.profile
    }

    /// Returns the bytes exposed by path-to-string coercion.
    pub fn display_path(&self) -> &[u8] {
        &self.display_path
    }
}

/// Reports why a virtual `corepkgs` display path is not canonical.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorepkgsPathError {
    reason: &'static str,
}

impl fmt::Display for CorepkgsPathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid virtual corepkgs path: {}", self.reason)
    }
}

impl std::error::Error for CorepkgsPathError {}

/// Selects the source backend without converting a virtual path into a host path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceAccessor<'a> {
    /// Delegates to the evaluator's filesystem implementation.
    RootFs {
        /// Visible filesystem path bytes.
        path: &'a [u8],
    },
    /// Resolves against an embedded profile-owned `corepkgs` tree.
    Corepkgs {
        /// Virtual path identity.
        path: &'a CorepkgsPath,
        /// Embedded entry, or `None` for a missing virtual path.
        entry: Option<CorepkgsEntry>,
    },
}

/// Describes an embedded `corepkgs` directory or regular file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CorepkgsEntry {
    /// The virtual root directory.
    Directory(CorepkgsDirectory),
    /// A generated regular source file.
    Regular(CorepkgsFile),
}

/// Describes one profile-owned virtual directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CorepkgsDirectory {
    profile: NixCompatProfile,
    display_path: &'static [u8],
    entries: &'static [CorepkgsDirectoryEntry],
}

impl CorepkgsDirectory {
    /// Returns the owning stock-Nix compatibility profile.
    pub const fn profile(self) -> NixCompatProfile {
        self.profile
    }

    /// Returns the visible absolute directory path.
    pub const fn display_path(self) -> &'static [u8] {
        self.display_path
    }

    /// Returns entries in bytewise name order.
    pub const fn entries(self) -> &'static [CorepkgsDirectoryEntry] {
        self.entries
    }
}

/// Describes one entry returned by virtual `readDir`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CorepkgsDirectoryEntry {
    name: &'static [u8],
    kind: CorepkgsFileType,
}

impl CorepkgsDirectoryEntry {
    const fn regular(name: &'static [u8]) -> Self {
        Self {
            name,
            kind: CorepkgsFileType::Regular,
        }
    }

    /// Returns the entry's basename.
    pub const fn name(self) -> &'static [u8] {
        self.name
    }

    /// Returns the entry type exposed by `builtins.readDir`.
    pub const fn kind(self) -> CorepkgsFileType {
        self.kind
    }
}

/// Classifies an embedded `corepkgs` directory entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CorepkgsFileType {
    /// A generated regular source file.
    Regular,
    /// A virtual directory.
    Directory,
}

/// Provides exact bytes and provenance for one generated source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CorepkgsFile {
    profile: NixCompatProfile,
    display_path: &'static [u8],
    bytes: &'static [u8],
    provenance: CorepkgsSourceProvenance,
}

impl CorepkgsFile {
    /// Returns the owning stock-Nix compatibility profile.
    pub const fn profile(self) -> NixCompatProfile {
        self.profile
    }

    /// Returns the visible absolute file path.
    pub const fn display_path(self) -> &'static [u8] {
        self.display_path
    }

    /// Returns the exact Meson-generated runtime payload.
    pub const fn bytes(self) -> &'static [u8] {
        self.bytes
    }

    /// Returns the payload's upstream and runtime provenance.
    pub const fn provenance(self) -> CorepkgsSourceProvenance {
        self.provenance
    }
}

/// Records where an embedded generated source came from and how it was verified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CorepkgsSourceProvenance {
    release_tag: &'static str,
    upstream_path: &'static str,
    runtime_sha256: &'static str,
    runtime_length: usize,
}

impl CorepkgsSourceProvenance {
    /// Returns the exact upstream Nix release tag.
    pub const fn release_tag(self) -> &'static str {
        self.release_tag
    }

    /// Returns the source path within the upstream Nix repository.
    pub const fn upstream_path(self) -> &'static str {
        self.upstream_path
    }

    /// Returns the SHA-256 hex digest observed from stock Nix's runtime bytes.
    pub const fn runtime_sha256(self) -> &'static str {
        self.runtime_sha256
    }

    /// Returns the byte length observed from stock Nix.
    pub const fn runtime_length(self) -> usize {
        self.runtime_length
    }
}

/// Resolves an exact hidden `nix/` search-path lookup to a virtual path.
///
/// Resolution and existence are deliberately separate. A canonical, nonempty
/// `nix/` lookup always receives a virtual identity, even when the selected
/// profile has no matching entry. Its [`SourceAccessor`] then reports
/// `entry: None`, allowing `pathExists` to return `false` without consulting
/// the root filesystem.
pub fn resolve_corepkgs_lookup(profile: NixCompatProfile, lookup: &[u8]) -> Option<SourcePath> {
    let suffix = lookup.strip_prefix(b"nix/")?;
    if suffix.is_empty() {
        return None;
    }
    let mut display_path = Vec::with_capacity(suffix.len() + 1);
    display_path.push(b'/');
    display_path.extend_from_slice(suffix);
    let path = CorepkgsPath::new(profile, display_path).ok()?;
    Some(SourcePath::Corepkgs(path))
}

/// Looks up an embedded entry by its visible absolute path.
pub fn corepkgs_entry(profile: NixCompatProfile, display_path: &[u8]) -> Option<CorepkgsEntry> {
    match (profile, display_path) {
        (NixCompatProfile::Nix2_24_12, b"/") => Some(CorepkgsEntry::Directory(CorepkgsDirectory {
            profile,
            display_path: b"/",
            entries: NIX_2_24_12_ROOT,
        })),
        (NixCompatProfile::Nix2_24_12, b"/fetchurl.nix") => {
            Some(CorepkgsEntry::Regular(CorepkgsFile {
                profile,
                display_path: b"/fetchurl.nix",
                bytes: NIX_2_24_12_FETCHURL,
                provenance: CorepkgsSourceProvenance {
                    release_tag: "2.24.12",
                    upstream_path: "src/libexpr/fetchurl.nix",
                    runtime_sha256: "a95556c086184507ae613a7a8ba4886647412a518b4f2e0467b439cd3a55bed9",
                    runtime_length: 1162,
                },
            }))
        }
        (NixCompatProfile::Nix2_24_12, b"/derivation-internal.nix") => {
            Some(CorepkgsEntry::Regular(CorepkgsFile {
                profile,
                display_path: b"/derivation-internal.nix",
                bytes: NIX_2_24_12_DERIVATION_INTERNAL,
                provenance: CorepkgsSourceProvenance {
                    release_tag: "2.24.12",
                    upstream_path: "src/libexpr/primops/derivation.nix",
                    runtime_sha256: "7cfcddebd37dfc85ef96352a72d51bfe6af457d4d986f38fb9f6ea7d1412c60d",
                    runtime_length: 1953,
                },
            }))
        }
        (NixCompatProfile::Nix2_34_8, b"/") => Some(CorepkgsEntry::Directory(CorepkgsDirectory {
            profile,
            display_path: b"/",
            entries: NIX_2_34_8_ROOT,
        })),
        (NixCompatProfile::Nix2_34_8, b"/fetchurl.nix") => {
            Some(CorepkgsEntry::Regular(CorepkgsFile {
                profile,
                display_path: b"/fetchurl.nix",
                bytes: NIX_2_34_8_FETCHURL,
                provenance: CorepkgsSourceProvenance {
                    release_tag: "2.34.8",
                    upstream_path: "src/libexpr/fetchurl.nix",
                    runtime_sha256: "b95cd173a041baf555b071de6a9df30c45ca350f9c41ab800551ba93918f238d",
                    runtime_length: 1351,
                },
            }))
        }
        (NixCompatProfile::Nix2_34_8, b"/derivation-internal.nix") => None,
        _ => None,
    }
}

fn validate_corepkgs_display_path(path: &[u8]) -> Result<(), CorepkgsPathError> {
    if !path.starts_with(b"/") {
        return Err(CorepkgsPathError {
            reason: "path is not absolute",
        });
    }
    if path.contains(&0) {
        return Err(CorepkgsPathError {
            reason: "path contains a NUL byte",
        });
    }
    if path != b"/" && path.ends_with(b"/") {
        return Err(CorepkgsPathError {
            reason: "path has a trailing slash",
        });
    }
    if path == b"/" {
        return Ok(());
    }
    if path[1..]
        .split(|byte| *byte == b'/')
        .any(|component| component.is_empty() || component == b"." || component == b"..")
    {
        return Err(CorepkgsPathError {
            reason: "path contains a non-canonical component",
        });
    }
    Ok(())
}

fn parent_display_path(path: &[u8]) -> Vec<u8> {
    if path == b"/" {
        return b"/".to_vec();
    }
    match path.iter().rposition(|byte| *byte == b'/') {
        Some(0) => b"/".to_vec(),
        Some(index) => path[..index].to_vec(),
        None => b".".to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn sha256_hex(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[test]
    fn runtime_payloads_match_recorded_stock_provenance() {
        for profile in [NixCompatProfile::Nix2_24_12, NixCompatProfile::Nix2_34_8] {
            let CorepkgsEntry::Regular(fetchurl) =
                corepkgs_entry(profile, b"/fetchurl.nix").expect("fetchurl is embedded")
            else {
                panic!("fetchurl must be a regular file");
            };
            assert_eq!(
                fetchurl.bytes().len(),
                fetchurl.provenance().runtime_length()
            );
            assert_eq!(
                sha256_hex(fetchurl.bytes()),
                fetchurl.provenance().runtime_sha256()
            );
            assert_eq!(fetchurl.bytes().first(), Some(&b'\n'));
        }

        let CorepkgsEntry::Regular(derivation) =
            corepkgs_entry(NixCompatProfile::Nix2_24_12, b"/derivation-internal.nix")
                .expect("2.24 embeds derivation-internal")
        else {
            panic!("derivation-internal must be a regular file");
        };
        assert_eq!(
            sha256_hex(derivation.bytes()),
            derivation.provenance().runtime_sha256()
        );
        assert_eq!(
            derivation.bytes().len(),
            derivation.provenance().runtime_length()
        );
        assert_eq!(derivation.bytes().first(), Some(&b'\n'));
        assert_eq!(
            corepkgs_entry(NixCompatProfile::Nix2_34_8, b"/derivation-internal.nix"),
            None
        );
    }

    #[test]
    fn exact_nix_prefix_resolves_existing_and_missing_virtual_paths() {
        let path = resolve_corepkgs_lookup(NixCompatProfile::Nix2_34_8, b"nix/fetchurl.nix")
            .expect("exact nix prefix resolves");
        assert_eq!(path.display_path(), b"/fetchurl.nix");

        assert_eq!(
            resolve_corepkgs_lookup(NixCompatProfile::Nix2_34_8, b"nix"),
            None
        );
        assert_eq!(
            resolve_corepkgs_lookup(NixCompatProfile::Nix2_34_8, b"nix/"),
            None
        );
        assert_eq!(
            resolve_corepkgs_lookup(NixCompatProfile::Nix2_34_8, b"nixos/fetchurl.nix"),
            None
        );
        let missing = resolve_corepkgs_lookup(NixCompatProfile::Nix2_34_8, b"nix/missing.nix")
            .expect("missing exact-prefix lookup still has a virtual identity");
        assert!(matches!(
            missing.accessor(),
            SourceAccessor::Corepkgs { entry: None, .. }
        ));
    }

    #[test]
    fn virtual_and_root_paths_share_display_bytes_but_not_source_identity() {
        let virtual_path =
            resolve_corepkgs_lookup(NixCompatProfile::Nix2_34_8, b"nix/fetchurl.nix")
                .expect("virtual path resolves");
        let root_path = SourcePath::root_fs(b"/fetchurl.nix".to_vec());

        assert_eq!(virtual_path.display_path(), root_path.display_path());
        assert_ne!(virtual_path, root_path);
        let old_profile_path =
            resolve_corepkgs_lookup(NixCompatProfile::Nix2_24_12, b"nix/fetchurl.nix")
                .expect("old profile virtual path resolves");
        assert_eq!(virtual_path.display_path(), old_profile_path.display_path());
        assert_ne!(virtual_path, old_profile_path);
        assert!(matches!(
            virtual_path.accessor(),
            SourceAccessor::Corepkgs {
                entry: Some(CorepkgsEntry::Regular(_)),
                ..
            }
        ));
        assert_eq!(
            root_path.accessor(),
            SourceAccessor::RootFs {
                path: b"/fetchurl.nix"
            }
        );
    }

    #[test]
    fn dir_of_preserves_virtual_identity_and_concat_drops_it() {
        let path = resolve_corepkgs_lookup(NixCompatProfile::Nix2_24_12, b"nix/fetchurl.nix")
            .expect("virtual path resolves");
        let directory = path.dir_of();
        assert_eq!(directory.display_path(), b"/");
        assert!(matches!(
            directory.accessor(),
            SourceAccessor::Corepkgs {
                entry: Some(CorepkgsEntry::Directory(_)),
                ..
            }
        ));

        let concatenated = directory.concat(b"/fetchurl.nix");
        assert_eq!(concatenated.display_path(), b"/fetchurl.nix");
        assert!(matches!(
            concatenated.accessor(),
            SourceAccessor::RootFs {
                path: b"/fetchurl.nix"
            }
        ));
    }

    #[test]
    fn root_directories_expose_profile_specific_sorted_entries() {
        let CorepkgsEntry::Directory(old_root) =
            corepkgs_entry(NixCompatProfile::Nix2_24_12, b"/").expect("old root exists")
        else {
            panic!("old root must be a directory");
        };
        assert_eq!(
            old_root
                .entries()
                .iter()
                .map(|entry| entry.name())
                .collect::<Vec<_>>(),
            [b"derivation-internal.nix".as_slice(), b"fetchurl.nix"]
        );

        let CorepkgsEntry::Directory(new_root) =
            corepkgs_entry(NixCompatProfile::Nix2_34_8, b"/").expect("new root exists")
        else {
            panic!("new root must be a directory");
        };
        assert_eq!(
            new_root
                .entries()
                .iter()
                .map(|entry| entry.name())
                .collect::<Vec<_>>(),
            [b"fetchurl.nix".as_slice()]
        );
    }
}
