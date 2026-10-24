//! Keeps bounded ordinary assertion data separate from opaque creator receipts.
//!
//! The private saved baseline contains only ordinary assertions:
//! ```toml
//! files = [] # Each row records a path, device, inode and exact claim bytes.
//! ```

use super::config::{Case, write_toml};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{self, Read},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
use terrane_linux::host_quota::open_host_path;
use terrane_sdk::bucket::enrollment::NativeInitialBucketEnrollment;

#[derive(Serialize, Deserialize, PartialEq, Eq)]
struct CapturedFile {
    path: PathBuf,
    device: u64,
    inode: u64,
    bytes: Vec<u8>,
}

/// Retains bounded ordinary creator observations solely for preservation assertions.
pub(super) struct Originals {
    directories: Vec<(PathBuf, u64, u64)>,
    files: Vec<CapturedFile>,
}

impl Originals {
    /// Captures bounded ordinary native observations without creating authority.
    ///
    /// # Errors
    /// Returns stale creator, missing native data, unsafe claim custody or resource-bound errors.
    pub fn capture(receipts: &[NativeInitialBucketEnrollment]) -> io::Result<Self> {
        let mut directories = Vec::new();
        let mut files = Vec::new();
        let mut total = 0usize;
        for receipt in receipts {
            receipt.verify_inline().map_err(super::source_error)?;
            for directory in receipt.directories() {
                directories.push((
                    directory.path().to_owned(),
                    directory.observed_metadata().dev(),
                    directory.observed_metadata().ino(),
                ));
            }
            for file in receipt.files() {
                total = total
                    .checked_add(file.expected_bytes().len())
                    .filter(|total| *total <= 2 * 1024 * 1024)
                    .ok_or_else(|| io::Error::other("original fixture byte bound exceeded"))?;
                files.push(CapturedFile {
                    path: file.path().to_owned(),
                    device: file.observed_metadata().dev(),
                    inode: file.observed_metadata().ino(),
                    bytes: file.expected_bytes().to_vec(),
                });
            }
        }
        if directories.len() + files.len() > 2048 {
            return Err(io::Error::other("original fixture entry bound exceeded"));
        }
        Ok(Self { directories, files })
    }

    /// Checks preservation of every original directory inode and exact creator file bytes.
    ///
    /// # Errors
    /// Returns native metadata or read errors.
    ///
    /// # Panics
    /// Panics if a required physical fixture invariant is not observed.
    pub fn verify(&self) -> io::Result<()> {
        for (path, device, inode) in &self.directories {
            let actual = fs::symlink_metadata(path)?;
            assert!(actual.is_dir());
            assert_eq!(
                (actual.dev(), actual.ino()),
                (*device, *inode),
                "original directory changed"
            );
        }
        for saved in &self.files {
            // These are root-supervised assertions about still-original ordinary
            // data, never a new receipt or read/service authority.
            let actual = fs::symlink_metadata(&saved.path)?;
            assert!(actual.is_file());
            assert_eq!(
                actual.len(),
                saved.bytes.len() as u64,
                "creator length changed"
            );
            assert_eq!((actual.dev(), actual.ino()), (saved.device, saved.inode));
            assert_eq!(
                fs::read(&saved.path)?,
                saved.bytes,
                "creator bytes changed during enrollment"
            );
        }
        Ok(())
    }

    /// Selects an actually created private snapshot hash path for access-denial checks.
    ///
    /// # Errors
    /// Returns an error if the genuine empty genesis has no snapshot path.
    pub fn present_private_hash(&self, case: &Case) -> io::Result<PathBuf> {
        self.files
            .iter()
            .find(|file| {
                file.path
                    .starts_with(case.root(1).join("publication/snapshots"))
            })
            .map(|file| file.path.clone())
            .ok_or_else(|| io::Error::other("genuine genesis has no hash-named snapshot"))
    }

    /// Checks actual original directory project assignments after a failed native operation.
    ///
    /// # Errors
    /// Returns native descriptor-open or project-inspection errors.
    pub fn assigned_original(&self, projects: [u32; 2]) -> io::Result<bool> {
        for (path, _, _) in &self.directories {
            let file = File::open(path)?;
            if projects
                .contains(&terrane_linux::host_quota::NativeProject::inspect(&file)?.project_id)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// Retains bounded permanent-claim observations solely for immutable-data assertions.
#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct Claims {
    files: Vec<CapturedFile>,
}

impl Claims {
    /// Captures bounded ordinary native observations without creating authority.
    ///
    /// # Errors
    /// Returns stale creator, missing native data, unsafe claim custody or resource-bound errors.
    pub fn capture() -> io::Result<Self> {
        let mut paths = vec![PathBuf::from(
            "/var/lib/terrane-host/project-claims.identity",
        )];
        match fs::read_dir("/var/lib/terrane-host/project-claims") {
            Ok(entries) => {
                for entry in entries {
                    paths.push(entry?.path());
                    if paths.len() > 129 {
                        return Err(io::Error::other("fixture claim entry bound exceeded"));
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        paths.sort();
        let mut files = Vec::new();
        let mut total = 0usize;
        for path in paths {
            let mut file = match open_host_path(&path, false) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            let metadata = file.metadata()?;
            if metadata.len() > 1024 * 1024 {
                return Err(io::Error::other("fixture claim file bound exceeded"));
            }
            let mut bytes = Vec::new();
            Read::by_ref(&mut file)
                .take(1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            total = total
                .checked_add(bytes.len())
                .filter(|total| *total <= 8 * 1024 * 1024)
                .ok_or_else(|| io::Error::other("fixture claim aggregate bound exceeded"))?;
            files.push(CapturedFile {
                path,
                device: metadata.dev(),
                inode: metadata.ino(),
                bytes,
            });
        }
        Ok(Self { files })
    }

    /// Checks that a preflight refusal preserved the complete global claim set.
    ///
    /// # Errors
    /// Returns bounded native claim-capture errors.
    ///
    /// # Panics
    /// Panics if a required physical fixture invariant is not observed.
    pub fn assert_unchanged(&self) -> io::Result<()> {
        assert!(
            Self::capture()? == *self,
            "preflight refusal changed global claims"
        );
        Ok(())
    }

    /// Durably stores ordinary immutable-claim assertion data under private fixture custody.
    ///
    /// # Errors
    /// Returns serialization, resource-bound, native write or synchronization errors.
    pub fn save(&self, case: &Case) -> io::Result<()> {
        write_toml(&case.path.join("claims-baseline.toml"), self, 0o600)
    }

    /// Reads bounded private assertion data without importing claim authority.
    ///
    /// # Errors
    /// Returns unsafe path, resource-bound, read or decoding errors.
    pub fn read_saved(case: &Case) -> io::Result<Self> {
        let path = case.path.join("claims-baseline.toml");
        let file = open_host_path(&path, false)?;
        if file.metadata()?.len() > 8 * 1024 * 1024 {
            return Err(io::Error::other("saved claim bound exceeded"));
        }
        let mut text = String::new();
        file.take(8 * 1024 * 1024 + 1).read_to_string(&mut text)?;
        if text.len() > 8 * 1024 * 1024 {
            return Err(io::Error::other("saved claim bound exceeded"));
        }
        toml::from_str(&text).map_err(super::source_error)
    }

    /// Checks exact bytes and native incarnations of previously observed permanent claims.
    ///
    /// # Errors
    /// Returns bounded native claim-capture errors.
    ///
    /// # Panics
    /// Panics if a required physical fixture invariant is not observed.
    pub fn verify_members(&self) -> io::Result<()> {
        let current = Self::capture()?;
        for expected in &self.files {
            assert!(
                current.files.iter().any(|actual| actual == expected),
                "permanent claim bytes or inode changed"
            );
        }
        Ok(())
    }
}

/// Reads the actual bounded administrative ledger phase.
///
/// # Errors
/// Returns native read, resource-bound, decode or missing-phase errors.
///
/// # Panics
/// Panics if a required physical fixture invariant is not observed.
pub(super) fn ledger_phase(path: &Path) -> io::Result<String> {
    let mut file = open_host_path(path, false)?;
    if file.metadata()?.len() > 1024 * 1024 {
        return Err(io::Error::other("fixture ledger exceeds bound"));
    }
    let mut text = String::new();
    Read::by_ref(&mut file)
        .take(1024 * 1024 + 1)
        .read_to_string(&mut text)?;
    if text.len() > 1024 * 1024 {
        return Err(io::Error::other("fixture ledger exceeds bound"));
    }
    let value: toml::Value = toml::from_str(&text).map_err(super::source_error)?;
    assert_eq!(
        value.get("version").and_then(toml::Value::as_integer),
        Some(3)
    );
    value
        .get("phase")
        .and_then(toml::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| io::Error::other("fixture ledger has no phase"))
}

/// Checks actual permanent initial claims against their complete durable ledger rows.
///
/// # Errors
/// Returns native reads, missing records, malformed data or resource-bound errors.
///
/// # Panics
/// Panics if a required physical fixture invariant is not observed.
pub(super) fn verify_initial_claims(case: &Case) -> io::Result<()> {
    let mut file = open_host_path(&case.ledger(), false)?;
    let mut text = String::new();
    Read::by_ref(&mut file)
        .take(1024 * 1024 + 1)
        .read_to_string(&mut text)?;
    if text.len() > 1024 * 1024 {
        return Err(io::Error::other("ledger bound exceeded"));
    }
    let ledger: toml::Value = toml::from_str(&text).map_err(super::source_error)?;
    let creators = ledger
        .get("creators")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| io::Error::other("missing actual creators"))?;
    let entries = ledger
        .get("entries")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| io::Error::other("missing actual entry preimages"))?;
    let roles = ledger
        .get("roles")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| io::Error::other("missing explicit role policy"))?;
    assert_eq!(creators.len(), 2);
    assert_eq!(roles.len(), 2);
    for owner in 0..2 {
        let directory = File::open(case.root(owner))?;
        let uuid = terrane_linux::host_quota::filesystem_uuid(&directory)?;
        let name = terrane_linux::host_quota::project_claim_name(&uuid, case.project(owner))?;
        let path = Path::new("/var/lib/terrane-host/project-claims").join(name);
        let mut file = open_host_path(&path, false)?;
        let mut bytes = String::new();
        Read::by_ref(&mut file)
            .take(1024 * 1024 + 1)
            .read_to_string(&mut bytes)?;
        if bytes.len() > 1024 * 1024 {
            return Err(io::Error::other("claim bound exceeded"));
        }
        let claim: toml::Value = toml::from_str(&bytes).map_err(super::source_error)?;
        assert_eq!(
            claim.get("version").and_then(toml::Value::as_integer),
            Some(2)
        );
        let parent = fs::metadata(&case.path)?;
        let ledger_binding = claim
            .get("ledger")
            .ok_or_else(|| io::Error::other("claim has no administrative ledger binding"))?;
        assert_eq!(
            ledger_binding
                .get("parent_device")
                .and_then(toml::Value::as_integer),
            i64::try_from(parent.dev()).ok()
        );
        assert_eq!(
            ledger_binding
                .get("parent_inode")
                .and_then(toml::Value::as_integer),
            i64::try_from(parent.ino()).ok()
        );
        assert_eq!(
            ledger_binding
                .get("file_name")
                .and_then(toml::Value::as_str),
            Some("enrollment.toml")
        );
        assert_eq!(claim.get("epoch"), ledger.get("epoch"));
        assert_eq!(claim.get("registry"), ledger.get("registry"));
        let matches = |value: &&toml::Value| {
            value.get("owner_id").and_then(toml::Value::as_str)
                == Some(super::config::OWNERS[owner])
                && value.get("domain").and_then(toml::Value::as_str)
                    == Some(super::config::DOMAINS[owner])
        };
        let creator = creators
            .iter()
            .find(matches)
            .ok_or_else(|| io::Error::other("missing exact creator"))?;
        let role = roles
            .iter()
            .find(matches)
            .ok_or_else(|| io::Error::other("missing exact role"))?;
        let expected: Vec<_> = entries.iter().filter(matches).cloned().collect();
        assert!(!expected.is_empty());
        assert_eq!(claim.get("creator"), Some(creator));
        assert_eq!(claim.get("role"), Some(role));
        assert_eq!(
            claim.get("entries").and_then(toml::Value::as_array),
            Some(&expected)
        );
        for entry in expected {
            assert!(entry.get("preimage").is_some());
            assert!(entry.get("project_preimage").is_some());
        }
    }
    Ok(())
}
