//! Retains private original-authority configuration independently of credentials.
//!
//! Decoded records are untrusted data, not authorization proofs. Native guard
//! factories separately validate physical registration and trusted imports.
//!
//! ```text
//! registration = [1, id, root, domain, root-dev, root-ino, lock-dev, lock-ino, control]
//! baseline = [1, id, reference, epoch, ordered-acl]
//! association = [1, commit, id, reference, epoch]
//! import = [1, registration, baseline, association]
//! ```

use std::{
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::{Component, Path, PathBuf},
};

use terrane_core::{cbor, properties::Domain, refs::RefName};

use super::{
    Error, validate_ancestors, validate_private_directory, validate_private_file, write_private,
};
use crate::store::LocalFs;

const LIMIT: usize = 65_536;
const RECORD_LIMIT: usize = 16 * 1024 * 1024;

/// Untrusted physical registration read from protected administrative storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RegistrationRecord {
    /// Administrative identifier; this value alone establishes no authority.
    pub(crate) id: [u8; 32],
    /// Exact configured absolute namespace root in raw Unix path representation.
    pub(crate) root: PathBuf,
    /// Configured canonical storage-domain pin.
    pub(crate) domain: String,
    /// Device number of the validated namespace root.
    pub(crate) root_device: u64,
    /// Inode number of the validated namespace root.
    pub(crate) root_inode: u64,
    /// Device number of the stable backend coordination file.
    pub(crate) coordination_device: u64,
    /// Inode number of the stable backend coordination file.
    pub(crate) coordination_inode: u64,
    /// Exact configured private sibling control directory.
    pub(crate) control: PathBuf,
}

/// Untrusted original bootstrap policy, preserving the ordered grant list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BootstrapRecord {
    /// Administrative identifier; this value alone establishes no authority.
    pub(crate) id: [u8; 32],
    /// Canonical original authoring reference, compared exactly after lookup.
    pub(crate) reference: String,
    /// Actual original writer-session epoch.
    pub(crate) epoch: u64,
    /// Original ordered principal and verb grants, independent of current policy.
    pub(crate) acl: Vec<(String, u8)>,
}

/// Associates an exact immutable commit with its retained original baseline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CommitAssociation {
    /// Exact immutable commit digest whose original context is associated.
    pub(crate) commit: [u8; 32],
    /// Administrative identifier; this value alone establishes no authority.
    pub(crate) id: [u8; 32],
    /// Canonical original authoring reference, compared exactly after lookup.
    pub(crate) reference: String,
    /// Actual original writer-session epoch.
    pub(crate) epoch: u64,
}

/// Contains untrusted retained source data awaiting native proof validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ImportRecord {
    /// Original physical registration retained as untrusted configuration data.
    pub(crate) registration: RegistrationRecord,
    /// Exact original bootstrap policy corresponding to the association.
    pub(crate) baseline: BootstrapRecord,
    /// Exact selected commit and original baseline lookup coordinates.
    pub(crate) association: CommitAssociation,
}

/// Encodes and decodes untrusted canonical administrative records.
pub(crate) trait Record: Sized {
    /// Encodes the exact versioned record without granting authority.
    ///
    /// # Errors
    /// Rejects invalid fields, inconsistent associations and excessive record sizes.
    fn encode(&self) -> Result<Vec<u8>, Error>;

    /// Decodes one complete canonical record as untrusted data.
    ///
    /// # Errors
    /// Rejects malformed, noncanonical, oversized, trailing or inconsistent data.
    fn decode(bytes: &[u8]) -> Result<Self, Error>;

    /// Returns a safe filename selector that supplies no authority.
    ///
    /// # Errors
    /// Rejects invalid fields required to construct the record selector.
    fn selector(&self) -> Result<String, Error>;
}

fn path_bytes(path: &Path) -> Result<&[u8], Error> {
    let bytes = path.as_os_str().as_bytes();
    if !path.is_absolute()
        || path.file_name().is_none()
        || bytes.contains(&0)
        || path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        || bytes
            .split(|byte| *byte == b'/')
            .skip(1)
            .any(|part| part.is_empty() || part == b"." || part == b"..")
        || bytes.len() > LIMIT
    {
        return Err(Error::PathEscape);
    }
    Ok(bytes)
}

fn reference(reference: &str) -> Result<(), Error> {
    if reference.len() > LIMIT || !reference.is_ascii() {
        return Err(Error::Denied);
    }
    RefName::parse(reference).map_err(|_| Error::Denied)?;
    Ok(())
}

fn header(decoder: &mut cbor::Decoder<'_>, length: usize) -> Result<(), Error> {
    if decoder.array(length).map_err(|_| Error::Denied)? != length
        || decoder.uint().map_err(|_| Error::Denied)? != 1
    {
        return Err(Error::Denied);
    }
    Ok(())
}

fn digest(decoder: &mut cbor::Decoder<'_>) -> Result<[u8; 32], Error> {
    decoder
        .bytes(32)
        .map_err(|_| Error::Denied)?
        .try_into()
        .map_err(|_| Error::Denied)
}

fn read_path(decoder: &mut cbor::Decoder<'_>) -> Result<PathBuf, Error> {
    let bytes = decoder.bytes(LIMIT).map_err(|_| Error::Denied)?;
    let path = PathBuf::from(std::ffi::OsString::from_vec(bytes.to_vec()));
    path_bytes(&path)?;
    Ok(path)
}

impl RegistrationRecord {
    fn append(&self, bytes: &mut Vec<u8>) -> Result<(), Error> {
        let root = path_bytes(&self.root)?;
        let control = path_bytes(&self.control)?;
        if self.root.parent() != self.control.parent() || self.root == self.control {
            return Err(Error::PathEscape);
        }
        if self.domain.len() > LIMIT {
            return Err(Error::Denied);
        }
        Domain::parse(&self.domain).map_err(|_| Error::Denied)?;
        cbor::write_array(bytes, 9);
        cbor::write_uint(bytes, 1);
        cbor::write_bytes(bytes, &self.id);
        cbor::write_bytes(bytes, root);
        cbor::write_text(bytes, &self.domain);
        for value in [
            self.root_device,
            self.root_inode,
            self.coordination_device,
            self.coordination_inode,
        ] {
            cbor::write_uint(bytes, value);
        }
        cbor::write_bytes(bytes, control);
        Ok(())
    }

    fn read(decoder: &mut cbor::Decoder<'_>) -> Result<Self, Error> {
        header(decoder, 9)?;
        let record = Self {
            id: digest(decoder)?,
            root: read_path(decoder)?,
            domain: decoder.text(LIMIT).map_err(|_| Error::Denied)?.to_owned(),
            root_device: decoder.uint().map_err(|_| Error::Denied)?,
            root_inode: decoder.uint().map_err(|_| Error::Denied)?,
            coordination_device: decoder.uint().map_err(|_| Error::Denied)?,
            coordination_inode: decoder.uint().map_err(|_| Error::Denied)?,
            control: read_path(decoder)?,
        };
        record.append(&mut Vec::new())?;
        Ok(record)
    }
}

impl BootstrapRecord {
    fn append(&self, bytes: &mut Vec<u8>) -> Result<(), Error> {
        reference(&self.reference)?;
        if self.acl.len() > LIMIT
            || self
                .acl
                .iter()
                .any(|(name, verbs)| name.is_empty() || name.len() > LIMIT || *verbs > 31)
        {
            return Err(Error::Denied);
        }
        cbor::write_array(bytes, 5);
        cbor::write_uint(bytes, 1);
        cbor::write_bytes(bytes, &self.id);
        cbor::write_text(bytes, &self.reference);
        cbor::write_uint(bytes, self.epoch);
        cbor::write_array(bytes, self.acl.len());
        for (name, verbs) in &self.acl {
            cbor::write_array(bytes, 2);
            cbor::write_text(bytes, name);
            cbor::write_uint(bytes, u64::from(*verbs));
        }
        Ok(())
    }

    fn read(decoder: &mut cbor::Decoder<'_>) -> Result<Self, Error> {
        header(decoder, 5)?;
        let id = digest(decoder)?;
        let reference = decoder.text(LIMIT).map_err(|_| Error::Denied)?.to_owned();
        let epoch = decoder.uint().map_err(|_| Error::Denied)?;
        let count = decoder.array(LIMIT).map_err(|_| Error::Denied)?;
        let mut acl = Vec::with_capacity(count);
        for _ in 0..count {
            if decoder.array(2).map_err(|_| Error::Denied)? != 2 {
                return Err(Error::Denied);
            }
            let name = decoder.text(LIMIT).map_err(|_| Error::Denied)?.to_owned();
            let verbs = u8::try_from(decoder.uint().map_err(|_| Error::Denied)?)
                .map_err(|_| Error::Denied)?;
            acl.push((name, verbs));
        }
        let record = Self {
            id,
            reference,
            epoch,
            acl,
        };
        record.append(&mut Vec::new())?;
        Ok(record)
    }

    /// Returns the baseline filename selector, preserving exact lookup fields.
    ///
    /// # Errors
    /// Rejects a malformed or oversized original reference.
    pub(crate) fn selector(&self) -> Result<String, Error> {
        reference(&self.reference)?;
        Ok(format!(
            "bootstrap-{}-{}-{}.cbor",
            hex(&self.id),
            blake3::hash(self.reference.as_bytes()).to_hex(),
            self.epoch
        ))
    }
}

impl CommitAssociation {
    fn append(&self, bytes: &mut Vec<u8>) -> Result<(), Error> {
        reference(&self.reference)?;
        cbor::write_array(bytes, 5);
        cbor::write_uint(bytes, 1);
        cbor::write_bytes(bytes, &self.commit);
        cbor::write_bytes(bytes, &self.id);
        cbor::write_text(bytes, &self.reference);
        cbor::write_uint(bytes, self.epoch);
        Ok(())
    }

    fn read(decoder: &mut cbor::Decoder<'_>) -> Result<Self, Error> {
        header(decoder, 5)?;
        let record = Self {
            commit: digest(decoder)?,
            id: digest(decoder)?,
            reference: decoder.text(LIMIT).map_err(|_| Error::Denied)?.to_owned(),
            epoch: decoder.uint().map_err(|_| Error::Denied)?,
        };
        reference(&record.reference)?;
        Ok(record)
    }

    /// Returns the selector for this exact immutable commit association.
    pub(crate) fn selector(&self) -> String {
        format!("commit-{}.cbor", hex(&self.commit))
    }
}

impl ImportRecord {
    /// Checks exact identifiers, references and epochs across retained source records.
    ///
    /// # Errors
    /// Rejects any disagreement between registration, baseline and association.
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.registration.id != self.baseline.id
            || self.baseline.id != self.association.id
            || self.baseline.reference != self.association.reference
            || self.baseline.epoch != self.association.epoch
        {
            return Err(Error::Denied);
        }
        Ok(())
    }

    fn append(&self, bytes: &mut Vec<u8>) -> Result<(), Error> {
        self.validate()?;
        cbor::write_array(bytes, 4);
        cbor::write_uint(bytes, 1);
        self.registration.append(bytes)?;
        self.baseline.append(bytes)?;
        self.association.append(bytes)?;
        Ok(())
    }

    fn read(decoder: &mut cbor::Decoder<'_>) -> Result<Self, Error> {
        header(decoder, 4)?;
        let record = Self {
            registration: RegistrationRecord::read(decoder)?,
            baseline: BootstrapRecord::read(decoder)?,
            association: CommitAssociation::read(decoder)?,
        };
        record.validate()?;
        Ok(record)
    }

    /// Returns the selector for the exact imported immutable commit.
    pub(crate) fn selector(&self) -> String {
        format!("import-{}.cbor", hex(&self.association.commit))
    }
}

macro_rules! record {
    ($name:ty, $selector:expr) => {
        impl Record for $name {
            fn selector(&self) -> Result<String, Error> {
                ($selector)(self)
            }
            fn encode(&self) -> Result<Vec<u8>, Error> {
                let mut bytes = Vec::new();
                self.append(&mut bytes)?;
                if bytes.len() > RECORD_LIMIT {
                    return Err(Error::Denied);
                }
                Ok(bytes)
            }
            fn decode(bytes: &[u8]) -> Result<Self, Error> {
                if bytes.len() > RECORD_LIMIT {
                    return Err(Error::Denied);
                }
                let mut decoder = cbor::Decoder::new(bytes);
                let record = Self::read(&mut decoder)?;
                decoder.finish().map_err(|_| Error::Denied)?;
                Ok(record)
            }
        }
    };
}
record!(RegistrationRecord, |_: &RegistrationRecord| Ok(
    "registration.cbor".to_owned()
));
record!(BootstrapRecord, |record: &BootstrapRecord| record
    .selector());
record!(CommitAssociation, |record: &CommitAssociation| Ok(
    record.selector()
));
record!(ImportRecord, |record: &ImportRecord| Ok(record.selector()));

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Creates the original physical registration under backend then control exclusion.
///
/// This initialization helper returns untrusted configuration data. The guard
/// must independently reread and validate it before minting original authority.
/// It must never be called by the existing-state reopen path.
///
/// # Errors
/// Rejects unsafe roots, coordination aliases or identities, conflicting
/// registration, invalid domains, entropy failures and failed durable operations.
pub(crate) async fn initialize_registration<F: LocalFs + Sync>(
    fs: &F,
    root: &Path,
    domain: &str,
    control: &Path,
    owner: u32,
) -> Result<RegistrationRecord, Error> {
    use std::os::unix::fs::MetadataExt;
    use terrane_core::bucket::BucketKey;

    validate_ancestors(fs, root).await?;
    validate_private_directory(fs, root, owner).await?;
    validate_ancestors(fs, control).await?;
    validate_private_directory(fs, control, owner).await?;
    let key = BucketKey::parse("CAPABILITIES").map_err(|_| Error::Denied)?;
    let coordination = root.join(key.lock_name());
    validate_ancestors(fs, &coordination).await?;
    let root_before = fs.symlink_metadata(root).await?;
    let coordination_before = fs.symlink_metadata(&coordination).await?;
    if !coordination_before.is_file()
        || coordination_before.file_type().is_symlink()
        || coordination_before.uid() != owner
        || coordination_before.nlink() != 1
    {
        return Err(Error::Denied);
    }

    let _backend = fs.lock_exclusive(&coordination).await?;
    validate_private_directory(fs, root, owner).await?;
    let root_after = fs.symlink_metadata(root).await?;
    let coordination_after = fs.symlink_metadata(&coordination).await?;
    if (root_before.dev(), root_before.ino()) != (root_after.dev(), root_after.ino())
        || (coordination_before.dev(), coordination_before.ino())
            != (coordination_after.dev(), coordination_after.ino())
        || !coordination_after.is_file()
        || coordination_after.file_type().is_symlink()
        || coordination_after.uid() != owner
        || coordination_after.nlink() != 1
    {
        return Err(Error::Denied);
    }
    let _configuration = configuration_lock(fs, control, owner, true).await?;
    let id = fs
        .random_bytes(32)
        .await?
        .try_into()
        .map_err(|_| Error::Denied)?;
    let record = RegistrationRecord {
        id,
        root: root.to_path_buf(),
        domain: domain.to_owned(),
        root_device: root_after.dev(),
        root_inode: root_after.ino(),
        coordination_device: coordination_after.dev(),
        coordination_inode: coordination_after.ino(),
        control: control.to_path_buf(),
    };
    retain(fs, control, owner, "registration.cbor", &record, true).await?;
    Ok(record)
}

/// Reads exact protected bytes; decoding does not grant authority.
///
/// # Errors
/// Rejects unsafe paths, owners, modes, aliases, missing or oversized files,
/// malformed records, mismatched selectors and filesystem failures.
pub(crate) async fn read<F: LocalFs + Sync, R: Record>(
    fs: &F,
    directory: &Path,
    owner: u32,
    selector: &str,
) -> Result<R, Error> {
    validate_ancestors(fs, directory).await?;
    validate_private_directory(fs, directory, owner).await?;
    let path = selected_path(directory, selector)?;
    validate_private_file(fs, &path, owner).await?;
    if fs.symlink_metadata(&path).await?.len() > RECORD_LIMIT as u64 {
        return Err(Error::Denied);
    }
    let record = R::decode(&fs.read_nofollow(&path).await?)?;
    if record.selector()? != selector {
        return Err(Error::Denied);
    }
    Ok(record)
}

/// Durably installs immutable bytes while the caller holds backend then config locks.
///
/// # Errors
/// Rejects unsafe protected state, invalid records, mismatched selectors,
/// existing initialization or conflicting bytes, and failed writes or synchronization.
pub(crate) async fn retain<F: LocalFs + Sync, R: Record>(
    fs: &F,
    directory: &Path,
    owner: u32,
    selector: &str,
    record: &R,
    initialize: bool,
) -> Result<(), Error> {
    validate_ancestors(fs, directory).await?;
    validate_private_directory(fs, directory, owner).await?;
    let path = selected_path(directory, selector)?;
    let bytes = record.encode()?;
    if record.selector()? != selector {
        return Err(Error::Denied);
    }
    match fs.symlink_metadata(&path).await {
        Ok(_) => {
            if initialize {
                return Err(Error::Denied);
            }
            validate_private_file(fs, &path, owner).await?;
            if fs.symlink_metadata(&path).await?.len() != bytes.len() as u64 {
                return Err(Error::Denied);
            }
            if fs.read_nofollow(&path).await? != bytes {
                return Err(Error::Denied);
            }
            // An earlier attempt may have installed these bytes but failed sync.
            fs.sync_file(&path).await?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            write_private(fs, &path, &bytes).await?;
            validate_private_file(fs, &path, owner).await?;
        }
        Err(error) => return Err(error.into()),
    }
    fs.sync_directory(directory).await?;
    Ok(())
}

/// Acquires protected configuration exclusion after backend exclusion.
///
/// The stable inode is never replaced; callers must not reverse this lock order.
///
/// # Errors
/// Rejects unsafe paths, ownership, modes or aliases, missing reopen state,
/// changed lock identities, and failed creation, synchronization or locking.
pub(crate) async fn configuration_lock<F: LocalFs + Sync>(
    fs: &F,
    directory: &Path,
    owner: u32,
    initialize: bool,
) -> Result<F::Lock, Error> {
    validate_ancestors(fs, directory).await?;
    validate_private_directory(fs, directory, owner).await?;
    let path = directory.join("retention.lock");
    match fs.symlink_metadata(&path).await {
        Ok(_) => validate_private_file(fs, &path, owner).await?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if !initialize {
                return Err(Error::Denied);
            }
            match write_private(fs, &path, &[]).await {
                Ok(()) => {}
                Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
            validate_private_file(fs, &path, owner).await?;
            fs.sync_directory(directory).await?;
        }
        Err(error) => return Err(error.into()),
    }
    let before = fs.symlink_metadata(&path).await?;
    let lock = fs.lock_exclusive(&path).await?;
    validate_private_file(fs, &path, owner).await?;
    let after = fs.symlink_metadata(&path).await?;
    use std::os::unix::fs::MetadataExt;
    if (before.dev(), before.ino()) != (after.dev(), after.ino()) {
        return Err(Error::Denied);
    }
    Ok(lock)
}

fn selected_path(directory: &Path, selector: &str) -> Result<PathBuf, Error> {
    if selector.is_empty()
        || !selector
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
        || !selector.ends_with(".cbor")
    {
        return Err(Error::PathEscape);
    }
    Ok(directory.join(selector))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "protected codec and filesystem fixtures fail the test directly"
)]
mod tests {
    use super::*;

    fn fixture() -> ImportRecord {
        ImportRecord {
            registration: RegistrationRecord {
                id: [9; 32],
                root: PathBuf::from("/tmp/data"),
                domain: "private:fixture".to_owned(),
                root_device: 1,
                root_inode: 2,
                coordination_device: 1,
                coordination_inode: 3,
                control: PathBuf::from("/tmp/control"),
            },
            baseline: BootstrapRecord {
                id: [9; 32],
                reference: "refs/heads/_/main".to_owned(),
                epoch: 3,
                acl: vec![("writer".to_owned(), 31), ("reader".to_owned(), 16)],
            },
            association: CommitAssociation {
                commit: [7; 32],
                id: [9; 32],
                reference: "refs/heads/_/main".to_owned(),
                epoch: 3,
            },
        }
    }

    #[test]
    fn retained_original_records_preserve_canonical_fields_and_reject_conflicts() {
        let record = fixture();
        let bytes = record.encode().unwrap();
        assert_eq!(ImportRecord::decode(&bytes).unwrap(), record);
        assert_eq!(
            RegistrationRecord::decode(&record.registration.encode().unwrap()).unwrap(),
            record.registration
        );
        assert_eq!(
            BootstrapRecord::decode(&record.baseline.encode().unwrap()).unwrap(),
            record.baseline
        );
        assert_eq!(
            CommitAssociation::decode(&record.association.encode().unwrap()).unwrap(),
            record.association
        );
        assert!(
            record
                .baseline
                .selector()
                .unwrap()
                .starts_with("bootstrap-0909")
        );
        assert!(record.association.selector().starts_with("commit-0707"));
        assert!(record.selector().starts_with("import-0707"));

        let mut wrong_version = bytes.clone();
        wrong_version[1] = 2;
        assert!(ImportRecord::decode(&wrong_version).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(ImportRecord::decode(&trailing).is_err());
        let mut mismatched = record.clone();
        mismatched.association.epoch += 1;
        assert!(mismatched.encode().is_err());
        mismatched = record.clone();
        mismatched.registration.id[0] ^= 1;
        assert!(mismatched.encode().is_err());
        mismatched = record.clone();
        mismatched.association.reference = "refs/heads/_/other".to_owned();
        assert!(mismatched.encode().is_err());
        mismatched = record.clone();
        mismatched.baseline.acl[0].0.clear();
        assert!(mismatched.encode().is_err());
        mismatched = record.clone();
        mismatched.baseline.acl[0].1 = 32;
        assert!(mismatched.encode().is_err());
        mismatched = record;
        mismatched.registration.root = PathBuf::from("/tmp/./data");
        assert!(mismatched.encode().is_err());
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn protected_retention_reopens_equal_bytes_and_rejects_conflicts_and_aliases() {
        use crate::store::TokioLocalFs;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let fs = TokioLocalFs;
        let directory = std::env::temp_dir().join(format!(
            "terrane-retention-{}",
            hex(&fs.random_bytes(16).await.unwrap())
        ));
        fs.create_dir_new(&directory).await.unwrap();
        let owner = fs.symlink_metadata(&directory).await.unwrap().uid();
        let lock = configuration_lock(&fs, &directory, owner, true)
            .await
            .unwrap();
        drop(lock);
        let lock = configuration_lock(&fs, &directory, owner, false)
            .await
            .unwrap();
        let original = fixture();
        let selector = original.baseline.selector().unwrap();
        retain(&fs, &directory, owner, &selector, &original.baseline, false)
            .await
            .unwrap();
        retain(&fs, &directory, owner, &selector, &original.baseline, false)
            .await
            .unwrap();
        let reopened: BootstrapRecord = read(&fs, &directory, owner, &selector).await.unwrap();
        assert_eq!(reopened, original.baseline);
        assert_eq!(
            fs.symlink_metadata(&directory.join(&selector))
                .await
                .unwrap()
                .mode()
                & 0o7777,
            0o600
        );

        let mut changed = original.baseline.clone();
        changed.acl.clear();
        assert!(
            retain(&fs, &directory, owner, &selector, &changed, false)
                .await
                .is_err()
        );
        assert!(
            retain(&fs, &directory, owner, &selector, &original.baseline, true)
                .await
                .is_err()
        );
        assert!(
            read::<_, BootstrapRecord>(&fs, &directory, owner.wrapping_add(1), &selector)
                .await
                .is_err()
        );
        assert!(
            read::<_, BootstrapRecord>(&fs, &directory, owner, "missing.cbor")
                .await
                .is_err()
        );

        let path = directory.join(&selector);
        let alias = directory.join("alias.cbor");
        fs.hard_link(&path, &alias).await.unwrap();
        assert!(
            read::<_, BootstrapRecord>(&fs, &directory, owner, &selector)
                .await
                .is_err()
        );
        fs.remove_file(&alias).await.unwrap();
        fs.set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .await
            .unwrap();
        assert!(
            read::<_, BootstrapRecord>(&fs, &directory, owner, &selector)
                .await
                .is_err()
        );
        fs.remove_file(&path).await.unwrap();
        fs.symlink(std::path::Path::new("unrelated"), &path)
            .await
            .unwrap();
        assert!(
            retain(&fs, &directory, owner, &selector, &original.baseline, false)
                .await
                .is_err()
        );
        fs.remove_file(&path).await.unwrap();
        drop(lock);
        fs.remove_file(&directory.join("retention.lock"))
            .await
            .unwrap();
        assert!(
            configuration_lock(&fs, &directory, owner, false)
                .await
                .is_err()
        );
        fs.remove_dir(&directory).await.unwrap();
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn physical_registration_uses_actual_opened_bucket_inodes() {
        use crate::{
            bucket::{FileBucket, FileBucketConfig, FileBucketPublicationConfig},
            repository::MetadataValidator,
            store::{TokioClock, TokioLocalFs},
        };
        use std::os::unix::fs::MetadataExt;
        use terrane_core::{bucket::BucketKey, chunking::ChunkProfile, refs::Locality};

        let fs = TokioLocalFs;
        let parent = std::env::temp_dir().join(format!(
            "terrane-original-registration-{}",
            hex(&fs.random_bytes(16).await.unwrap())
        ));
        fs.create_dir_new(&parent).await.unwrap();
        let root = parent.join("bucket");
        let control = parent.join("control");
        fs.create_dir_new(&control).await.unwrap();
        let owner = fs.symlink_metadata(&control).await.unwrap().uid();
        let profile = ChunkProfile::cdc_1m(fs.random_bytes(32).await.unwrap().try_into().unwrap());
        let bucket = FileBucket::open(
            FileBucketConfig {
                publication_control: Some(FileBucketPublicationConfig {
                    operator_uid: owner,
                    control: None,
                }),
                root: root.clone(),
                chunk_profile_name: "cdc-1m".to_owned(),
                chunk_profile: profile.clone(),
                locality: Locality::default(),
            },
            fs,
            TokioClock,
            MetadataValidator::new(profile),
        )
        .await
        .unwrap();

        let registration =
            initialize_registration(&fs, bucket.root(), "private:fixture", &control, owner)
                .await
                .unwrap();
        let reread: RegistrationRecord = read(&fs, &control, owner, "registration.cbor")
            .await
            .unwrap();
        assert_eq!(reread, registration);
        let actual_root = fs.symlink_metadata(&root).await.unwrap();
        let coordination = root.join(BucketKey::parse("CAPABILITIES").unwrap().lock_name());
        let actual_lock = fs.symlink_metadata(&coordination).await.unwrap();
        assert_eq!(
            (registration.root_device, registration.root_inode),
            (actual_root.dev(), actual_root.ino())
        );
        assert_eq!(
            (
                registration.coordination_device,
                registration.coordination_inode
            ),
            (actual_lock.dev(), actual_lock.ino())
        );
        assert!(
            initialize_registration(&fs, &root, "private:fixture", &control, owner)
                .await
                .is_err()
        );
        assert_eq!(
            read::<_, RegistrationRecord>(&fs, &control, owner, "registration.cbor")
                .await
                .unwrap(),
            registration
        );
        drop(bucket);

        let mut pending = vec![parent];
        let mut directories = Vec::new();
        while let Some(path) = pending.pop() {
            if fs.symlink_metadata(&path).await.unwrap().is_dir() {
                pending.extend(fs.read_dir(&path).await.unwrap());
                directories.push(path);
            } else {
                fs.remove_file(&path).await.unwrap();
            }
        }
        for directory in directories.into_iter().rev() {
            fs.remove_dir(&directory).await.unwrap();
        }
    }

    #[cfg(feature = "tokio")]
    struct FaultFs {
        failure: std::sync::atomic::AtomicU8,
    }

    #[cfg(feature = "tokio")]
    impl FaultFs {
        fn trip(&self, stage: u8) -> std::io::Result<()> {
            if self
                .failure
                .compare_exchange(
                    stage,
                    0,
                    std::sync::atomic::Ordering::SeqCst,
                    std::sync::atomic::Ordering::SeqCst,
                )
                .is_ok()
            {
                return Err(std::io::Error::other(
                    "injected administrative durability failure",
                ));
            }

            Ok(())
        }
    }

    #[cfg(feature = "tokio")]
    #[async_trait::async_trait]
    impl LocalFs for FaultFs {
        type Lock = crate::store::TokioFileLock;

        async fn random_bytes(&self, length: usize) -> std::io::Result<Vec<u8>> {
            crate::store::TokioLocalFs.random_bytes(length).await
        }

        async fn lock_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
            crate::store::TokioLocalFs.lock_exclusive(path).await
        }

        async fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
            crate::store::TokioLocalFs.read(path).await
        }

        async fn read_range(
            &self,
            path: &Path,
            range: crate::store::ByteRange,
        ) -> std::io::Result<Vec<u8>> {
            crate::store::TokioLocalFs.read_range(path, range).await
        }

        async fn write_new(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
            self.trip(1)?;
            crate::store::TokioLocalFs.write_new(path, bytes).await
        }

        async fn create_dir_all(&self, path: &Path) -> std::io::Result<()> {
            crate::store::TokioLocalFs.create_dir_all(path).await
        }

        async fn read_dir(&self, path: &Path) -> std::io::Result<Vec<PathBuf>> {
            crate::store::TokioLocalFs.read_dir(path).await
        }

        async fn metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
            crate::store::TokioLocalFs.metadata(path).await
        }

        async fn symlink_metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
            crate::store::TokioLocalFs.symlink_metadata(path).await
        }

        async fn remove_file(&self, path: &Path) -> std::io::Result<()> {
            crate::store::TokioLocalFs.remove_file(path).await
        }

        async fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
            crate::store::TokioLocalFs.rename(from, to).await
        }

        async fn rename_no_replace(&self, from: &Path, to: &Path) -> std::io::Result<()> {
            crate::store::TokioLocalFs.rename_no_replace(from, to).await
        }

        async fn sync_file(&self, path: &Path) -> std::io::Result<()> {
            self.trip(4)?;
            crate::store::TokioLocalFs.sync_file(path).await
        }

        async fn sync_directory(&self, path: &Path) -> std::io::Result<()> {
            self.trip(3)?;
            crate::store::TokioLocalFs.sync_directory(path).await
        }

        async fn read_nofollow(&self, path: &Path) -> std::io::Result<Vec<u8>> {
            crate::store::TokioLocalFs.read_nofollow(path).await
        }

        async fn set_permissions_and_sync(
            &self,
            path: &Path,
            permissions: std::fs::Permissions,
        ) -> std::io::Result<()> {
            self.trip(2)?;
            crate::store::TokioLocalFs
                .set_permissions_and_sync(path, permissions)
                .await
        }
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn retention_faults_never_report_durability_and_equal_retry_resyncs() {
        use std::os::unix::fs::MetadataExt;
        use std::sync::atomic::{AtomicU8, Ordering};
        let native = crate::store::TokioLocalFs;
        let directory = std::env::temp_dir().join(format!(
            "terrane-retention-fault-{}",
            hex(&native.random_bytes(16).await.unwrap())
        ));
        native.create_dir_new(&directory).await.unwrap();
        let owner = native.symlink_metadata(&directory).await.unwrap().uid();
        let baseline = fixture().baseline;
        let selector = baseline.selector().unwrap();
        let fs = FaultFs {
            failure: AtomicU8::new(1),
        };
        assert!(
            retain(&fs, &directory, owner, &selector, &baseline, false)
                .await
                .is_err()
        );
        assert!(
            native
                .symlink_metadata(&directory.join(&selector))
                .await
                .is_err()
        );

        fs.failure.store(3, Ordering::SeqCst);
        assert!(
            retain(&fs, &directory, owner, &selector, &baseline, false)
                .await
                .is_err()
        );
        assert!(
            native
                .symlink_metadata(&directory.join(&selector))
                .await
                .is_ok()
        );
        fs.failure.store(4, Ordering::SeqCst);
        assert!(
            retain(&fs, &directory, owner, &selector, &baseline, false)
                .await
                .is_err()
        );
        retain(&fs, &directory, owner, &selector, &baseline, false)
            .await
            .unwrap();
        let read_back: BootstrapRecord = read(&fs, &directory, owner, &selector).await.unwrap();
        assert_eq!(read_back, baseline);
        assert!(
            retain(
                &fs,
                &directory,
                owner,
                "bootstrap-wrong.cbor",
                &baseline,
                false
            )
            .await
            .is_err()
        );

        native
            .remove_file(&directory.join(&selector))
            .await
            .unwrap();
        fs.failure.store(2, Ordering::SeqCst);
        assert!(
            retain(&fs, &directory, owner, &selector, &baseline, false)
                .await
                .is_err()
        );
        // The failed call cannot authorize dependent publication, even if
        // the process umask happened to make the incomplete file private.
        assert!(
            native
                .symlink_metadata(&directory.join(&selector))
                .await
                .is_ok()
        );
        native
            .remove_file(&directory.join(&selector))
            .await
            .unwrap();
        native.remove_dir(&directory).await.unwrap();
    }
}
