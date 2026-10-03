//! Original normal-Root custody for one administrative Git evidence credential.
//!
//! The selected unit, actual startup owner and read-only PID1 credential copy
//! are joined here. Bytes and property values remain private custody on error;
//! a checksum, caller path or descriptor cannot construct this owner.

use std::fs::File;
use std::io;
use std::os::fd::AsFd as _;
use std::path::Path;

use aos_sandbox_linux::inventory::{MountId, ReadOnlyDirectorySnapshot};
use aos_sandbox_linux::path::{BeneathRoot, ResolvedFile};
use aos_systemd::{OwnedValue, Value};
use rustix::fs::{CWD, FileType, Mode, OFlags, ResolveFlags, openat2};

use super::{NormalRootStartupErrorV1, ProductionNormalRootStartupV1, service};

const DIRECTORY: &str = "/run/credentials/aos-sandbox-policy-authorityd.service";
const NAME: &str = "git-evidence-provision-v1";
const CONTEXT: &[u8] = b"system_u:object_r:aos_sandbox_policy_authority_credential_t";
pub(crate) const MAXIMUM_GIT_EVIDENCE_CREDENTIAL_BYTES: usize = 33_008;
const MAXIMUM_OBSERVATIONS: usize = 16;
const PROPERTIES: &[&str] = &[
    "LoadCredential",
    "LoadCredentialEncrypted",
    "SetCredential",
    "SetCredentialEncrypted",
    "ImportCredential",
    "ImportCredentialEx",
];

#[derive(Debug, thiserror::Error)]
pub(crate) enum RootGitEvidenceCredentialErrorV1 {
    #[error("original normal Root no longer matches")]
    Root(#[from] NormalRootStartupErrorV1),
    #[error("original Git credential kernel observation failed")]
    Linux(#[from] aos_sandbox_linux::Error),
    #[error("original Git credential I/O failed")]
    Io(#[from] io::Error),
    #[error("fixed Git credential profile differs")]
    Rejected,
}

impl From<rustix::io::Errno> for RootGitEvidenceCredentialErrorV1 {
    fn from(error: rustix::io::Errno) -> Self {
        Self::Io(io::Error::from_raw_os_error(error.raw_os_error()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Identity {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    bytes: u64,
    mtime: (i64, u64),
    ctime: (i64, u64),
    mount: MountId,
}

impl Identity {
    fn capture(
        file: impl std::os::fd::AsFd,
    ) -> Result<Self, RootGitEvidenceCredentialErrorV1> {
        let metadata = rustix::fs::fstat(&file)?;
        let bytes = u64::try_from(metadata.st_size)
            .map_err(|_| RootGitEvidenceCredentialErrorV1::Rejected)?;

        Ok(Self {
            device: metadata.st_dev,
            inode: metadata.st_ino,
            mode: metadata.st_mode,
            uid: metadata.st_uid,
            gid: metadata.st_gid,
            links: u64::from(metadata.st_nlink),
            bytes,
            mtime: (i64::from(metadata.st_mtime), u64::from(metadata.st_mtime_nsec)),
            ctime: (i64::from(metadata.st_ctime), u64::from(metadata.st_ctime_nsec)),
            mount: MountId::from_fd(file.as_fd())?,
        })
    }

    fn require(&self, kind: FileType, mode: u32) -> Result<(), RootGitEvidenceCredentialErrorV1> {
        if FileType::from_raw_mode(self.mode) != kind
            || self.mode & 0o7777 != mode
            || self.uid != 0
            || self.gid != 0
            || self.device == 0
            || self.inode == 0
        {
            return Err(RootGitEvidenceCredentialErrorV1::Rejected);
        }
        Ok(())
    }
}

pub(crate) struct RootGitEvidenceCredentialCustodyV1<'root> {
    root: &'root ProductionNormalRootStartupV1,
    directory_path: Option<File>,
    directory_reader: Option<File>,
    file: Option<ResolvedFile>,
    named_directories: Vec<File>,
    named_files: Vec<ResolvedFile>,
    fragment_bytes: Option<Vec<u8>>,
    directory_identity: Option<Identity>,
    file_identity: Option<Identity>,
    directory_snapshot: Option<ReadOnlyDirectorySnapshot>,
    observations: Vec<(Vec<OwnedValue>, Vec<OwnedValue>)>,
    readbacks: Vec<Vec<u8>>,
    source: Option<String>,
    admitted: bool,
}

impl<'root> RootGitEvidenceCredentialCustodyV1<'root> {
    pub(crate) fn new(root: &'root ProductionNormalRootStartupV1) -> Self {
        Self {
            root,
            directory_path: None,
            directory_reader: None,
            file: None,
            named_directories: Vec::new(),
            named_files: Vec::new(),
            fragment_bytes: None,
            directory_identity: None,
            file_identity: None,
            directory_snapshot: None,
            observations: Vec::new(),
            readbacks: Vec::new(),
            source: None,
            admitted: false,
        }
    }

    pub(crate) fn admit(&mut self) -> Result<bool, RootGitEvidenceCredentialErrorV1> {
        self.root.recheck()?;
        self.fragment_bytes = Some(
            self.root.fragment.read_bounded()
                .map_err(|_| NormalRootStartupErrorV1::Service)?,
        );
        self.source = selected_source(
            self.fragment_bytes.as_deref()
                .ok_or(RootGitEvidenceCredentialErrorV1::Rejected)?,
        )?;
        self.observe_delivery()?;

        if self.source.is_none() {
            require_copy_absent()?;
            self.root.recheck()?;
            return Ok(false);
        }

        // Both descriptions are staged before any metadata/xattr inspection.
        // O_PATH supplies the existing same-FD mount snapshot; it cannot be
        // treated as a readable fgetxattr description.
        self.directory_path = Some(open_directory(true)?);
        self.directory_reader = Some(open_directory(false)?);
        let path = self.directory_path.as_ref()
            .ok_or(RootGitEvidenceCredentialErrorV1::Rejected)?;
        let reader = self.directory_reader.as_ref()
            .ok_or(RootGitEvidenceCredentialErrorV1::Rejected)?;
        let identity = Identity::capture(reader)?;
        identity.require(FileType::Directory, 0o500)?;
        if Identity::capture(path)? != identity {
            return Err(RootGitEvidenceCredentialErrorV1::Rejected);
        }
        require_label_and_acl(reader)?;
        self.directory_snapshot = Some(ReadOnlyDirectorySnapshot::capture(path.as_fd())?);
        self.directory_identity = Some(identity);

        let beneath = BeneathRoot::from_owned(path.try_clone()?.into())?;
        self.file = Some(beneath.open_regular(Path::new(NAME))?);
        let file = self.file.as_ref()
            .ok_or(RootGitEvidenceCredentialErrorV1::Rejected)?;
        let identity = Identity::capture(file.as_fd())?;
        identity.require(FileType::RegularFile, 0o400)?;
        if identity.links != 1
            || identity.bytes == 0
            || identity.bytes > MAXIMUM_GIT_EVIDENCE_CREDENTIAL_BYTES as u64
        {
            return Err(RootGitEvidenceCredentialErrorV1::Rejected);
        }
        require_read_description(file.as_fd())?;
        require_label_and_acl(file.as_fd())?;
        self.file_identity = Some(identity);
        self.capture_bytes()?;
        self.admitted = true;
        self.recheck()?;

        Ok(true)
    }

    pub(crate) fn bytes(&self) -> Result<&[u8], RootGitEvidenceCredentialErrorV1> {
        self.readbacks.first()
            .map(Vec::as_slice)
            .ok_or(RootGitEvidenceCredentialErrorV1::Rejected)
    }

    pub(crate) fn recheck(&mut self) -> Result<(), RootGitEvidenceCredentialErrorV1> {
        if !self.admitted {
            return Err(RootGitEvidenceCredentialErrorV1::Rejected);
        }

        self.root.recheck()?;
        self.observe_delivery()?;
        self.check_descriptors_and_names()?;
        self.capture_bytes()?;
        if self.readbacks.first() != self.readbacks.last() {
            return Err(RootGitEvidenceCredentialErrorV1::Rejected);
        }
        self.check_descriptors_and_names()?;
        self.root.recheck()?;

        Ok(())
    }

    fn check_descriptors_and_names(&mut self) -> Result<(), RootGitEvidenceCredentialErrorV1> {
        let path = self.directory_path.as_ref()
            .ok_or(RootGitEvidenceCredentialErrorV1::Rejected)?;
        let reader = self.directory_reader.as_ref()
            .ok_or(RootGitEvidenceCredentialErrorV1::Rejected)?;
        let file = self.file.as_ref()
            .ok_or(RootGitEvidenceCredentialErrorV1::Rejected)?;

        if Some(&Identity::capture(path)?) != self.directory_identity.as_ref()
            || Some(&Identity::capture(reader)?) != self.directory_identity.as_ref()
            || Some(&Identity::capture(file.as_fd())?) != self.file_identity.as_ref()
            || Some(&ReadOnlyDirectorySnapshot::capture(path.as_fd())?) != self.directory_snapshot.as_ref()
        {
            return Err(RootGitEvidenceCredentialErrorV1::Rejected);
        }
        require_label_and_acl(reader)?;
        require_label_and_acl(file.as_fd())?;
        require_read_description(file.as_fd())?;

        if self.named_directories.len() >= MAXIMUM_OBSERVATIONS {
            return Err(RootGitEvidenceCredentialErrorV1::Rejected);
        }
        self.named_directories.push(open_directory(true)?);
        let named_directory = self.named_directories.last()
            .ok_or(RootGitEvidenceCredentialErrorV1::Rejected)?;
        if Some(&Identity::capture(named_directory)?) != self.directory_identity.as_ref()
            || Some(&ReadOnlyDirectorySnapshot::capture(named_directory.as_fd())?) != self.directory_snapshot.as_ref()
        {
            return Err(RootGitEvidenceCredentialErrorV1::Rejected);
        }
        let beneath = BeneathRoot::from_owned(named_directory.try_clone()?.into())?;
        self.named_files.push(beneath.open_regular(Path::new(NAME))?);
        let named = self.named_files.last()
            .ok_or(RootGitEvidenceCredentialErrorV1::Rejected)?;
        if Some(&Identity::capture(named.as_fd())?) != self.file_identity.as_ref() {
            return Err(RootGitEvidenceCredentialErrorV1::Rejected);
        }
        Ok(())
    }

    fn observe_delivery(&mut self) -> Result<(), RootGitEvidenceCredentialErrorV1> {
        if self.observations.len() >= MAXIMUM_OBSERVATIONS {
            return Err(RootGitEvidenceCredentialErrorV1::Rejected);
        }
        let values = service::read_properties(super::profile::UNIT, std::process::id(), PROPERTIES)?;
        self.observations.push(values);

        let (service_values, unit) = self.observations.last()
            .ok_or(RootGitEvidenceCredentialErrorV1::Rejected)?;
        require_delivery(service_values, self.source.as_deref())?;
        let [fragment, dropins, transient, invocation] = unit.as_slice() else {
            return Err(RootGitEvidenceCredentialErrorV1::Rejected);
        };
        for (value, signature) in [
            (fragment, "s"),
            (dropins, "as"),
            (transient, "b"),
            (invocation, "ay"),
        ] {
            require_signature(value, signature)?;
        }
        let decoded_unit = service::decode_unit(unit, super::profile::UNIT)?;
        let observation = service::immutable_observation(decoded_unit)?;
        service::require_same(&self.root.observed, &observation)?;
        Ok(())
    }

    fn capture_bytes(&mut self) -> Result<(), RootGitEvidenceCredentialErrorV1> {
        if self.readbacks.len() >= MAXIMUM_OBSERVATIONS {
            return Err(RootGitEvidenceCredentialErrorV1::Rejected);
        }
        // The allocation is in the owner before read_at can fail. A short
        // read or an error never erases the bytes already received.
        self.readbacks.push(Vec::new());
        let captured = self.readbacks.last_mut()
            .ok_or(RootGitEvidenceCredentialErrorV1::Rejected)?;
        let file = self.file.as_ref()
            .ok_or(RootGitEvidenceCredentialErrorV1::Rejected)?;
        let expected = self.file_identity.as_ref()
            .ok_or(RootGitEvidenceCredentialErrorV1::Rejected)?.bytes;

        let mut chunk = [0_u8; 4096];
        loop {
            let remaining = MAXIMUM_GIT_EVIDENCE_CREDENTIAL_BYTES + 1 - captured.len();
            let width = remaining.min(chunk.len());
            if width == 0 {
                return Err(RootGitEvidenceCredentialErrorV1::Rejected);
            }
            let read = rustix::io::pread(file.as_fd(), &mut chunk[..width], captured.len() as u64)?;
            if read == 0 {
                break;
            }
            captured.extend_from_slice(&chunk[..read]);
        }
        if captured.len() as u64 != expected {
            return Err(RootGitEvidenceCredentialErrorV1::Rejected);
        }
        Ok(())
    }
}

fn open_directory(path_only: bool) -> Result<File, RootGitEvidenceCredentialErrorV1> {
    let access = if path_only {
        OFlags::PATH
    } else {
        OFlags::RDONLY
    };

    Ok(File::from(openat2(
        CWD,
        DIRECTORY,
        access | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?))
}

fn require_copy_absent() -> Result<(), RootGitEvidenceCredentialErrorV1> {
    match std::fs::symlink_metadata(Path::new(DIRECTORY).join(NAME)) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err(RootGitEvidenceCredentialErrorV1::Rejected),
    }
}

fn require_read_description(
    file: impl std::os::fd::AsFd,
) -> Result<(), RootGitEvidenceCredentialErrorV1> {
    let flags = rustix::fs::fcntl_getfl(&file)?;
    if flags.contains(OFlags::PATH)
        || flags & OFlags::ACCMODE != OFlags::RDONLY
        || !rustix::io::fcntl_getfd(&file)?.contains(rustix::io::FdFlags::CLOEXEC)
    {
        return Err(RootGitEvidenceCredentialErrorV1::Rejected);
    }
    Ok(())
}

fn require_label_and_acl(
    file: impl std::os::fd::AsFd,
) -> Result<(), RootGitEvidenceCredentialErrorV1> {
    let mut context = [0_u8; 256];
    let length = rustix::fs::fgetxattr(&file, "security.selinux", &mut context[..])?;
    let actual = context[..length].strip_suffix(&[0]).unwrap_or(&context[..length]);
    if actual != CONTEXT {
        return Err(RootGitEvidenceCredentialErrorV1::Rejected);
    }
    let mut acl = [0_u8; 4096];
    for name in ["system.posix_acl_access", "system.posix_acl_default"] {
        match rustix::fs::fgetxattr(&file, name, &mut acl[..]) {
            Err(rustix::io::Errno::NODATA) => {}
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(RootGitEvidenceCredentialErrorV1::Rejected),
        }
    }
    Ok(())
}

fn selected_source(fragment: &[u8]) -> Result<Option<String>, RootGitEvidenceCredentialErrorV1> {
    let text = std::str::from_utf8(fragment).map_err(|_| RootGitEvidenceCredentialErrorV1::Rejected)?;
    let mut in_service = false;
    let mut source = None;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_service = line == "[Service]";
            continue;
        }
        if !in_service || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(mapping) = line.strip_prefix("LoadCredential=") {
            if mapping.is_empty() {
                if source.is_some() {
                    return Err(RootGitEvidenceCredentialErrorV1::Rejected);
                }
                continue;
            }
            let Some((id, path)) = mapping.split_once(':') else {
                // Preserve unrelated inherited-name declarations when this
                // purpose is absent. This purpose requires its fixed source.
                if mapping == NAME {
                    return Err(RootGitEvidenceCredentialErrorV1::Rejected);
                }
                continue;
            };
            if id == NAME {
                let suffix = path.strip_prefix("/run/credentials/@system/")
                    .ok_or(RootGitEvidenceCredentialErrorV1::Rejected)?;
                if source.is_some() || !credential_name(suffix) {
                    return Err(RootGitEvidenceCredentialErrorV1::Rejected);
                }
                source = Some(path.to_owned());
            }
        }
        // Alternate-purpose directives must not hide an overridden original
        // in PID1's effective credential map. No general unit parser is added.
        for prefix in ["LoadCredentialEncrypted=", "SetCredential=", "SetCredentialEncrypted="] {
            if let Some(mapping) = line.strip_prefix(prefix) {
                if mapping.split(':').next() == Some(NAME) {
                    return Err(RootGitEvidenceCredentialErrorV1::Rejected);
                }
            }
        }
    }
    Ok(source)
}

fn credential_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !matches!(name, "." | "..")
        && name.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn require_signature(
    value: &OwnedValue,
    expected: &str,
) -> Result<(), RootGitEvidenceCredentialErrorV1> {
    if value.value_signature().to_string() != expected {
        return Err(RootGitEvidenceCredentialErrorV1::Rejected);
    }
    Ok(())
}

fn require_delivery(
    values: &[OwnedValue],
    source: Option<&str>,
) -> Result<(), RootGitEvidenceCredentialErrorV1> {
    let [load, encrypted, literal, encrypted_literal, import, import_ex] = values else {
        return Err(RootGitEvidenceCredentialErrorV1::Rejected);
    };
    for (value, signature) in [
        (load, "a(ss)"),
        (encrypted, "a(ss)"),
        (literal, "a(say)"),
        (encrypted_literal, "a(say)"),
        (import, "as"),
        (import_ex, "a(ss)"),
    ] {
        require_signature(value, signature)?;
    }
    let mut found = 0;

    for value in [load, encrypted, literal, encrypted_literal] {
        let Value::Array(rows) = &**value else {
            return Err(RootGitEvidenceCredentialErrorV1::Rejected);
        };
        if source.is_some() && rows.len() > 64 {
            return Err(RootGitEvidenceCredentialErrorV1::Rejected);
        }
        for row in rows.inner() {
            let Value::Structure(row) = row else {
                return Err(RootGitEvidenceCredentialErrorV1::Rejected);
            };
            let [Value::Str(id), content] = row.fields() else {
                return Err(RootGitEvidenceCredentialErrorV1::Rejected);
            };
            if id.as_str() == NAME {
                if !std::ptr::eq(value, load)
                    || !matches!(content, Value::Str(path) if Some(path.as_str()) == source)
                {
                    return Err(RootGitEvidenceCredentialErrorV1::Rejected);
                }
                found += 1;
            }
        }
    }
    for value in [import, import_ex] {
        let Value::Array(patterns) = &**value else {
            return Err(RootGitEvidenceCredentialErrorV1::Rejected);
        };
        if source.is_some() && !patterns.is_empty() {
            return Err(RootGitEvidenceCredentialErrorV1::Rejected);
        }
    }
    if found != usize::from(source.is_some()) {
        return Err(RootGitEvidenceCredentialErrorV1::Rejected);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragment_admits_only_one_fixed_system_source() {
        let fragment = b"[Service]\nLoadCredential=git-evidence-provision-v1:/run/credentials/@system/git-v1\n";

        assert_eq!(
            selected_source(fragment).unwrap().as_deref(),
            Some("/run/credentials/@system/git-v1"),
        );
        assert_eq!(selected_source(b"[Service]\nLoadCredential=\n").unwrap(), None);
        assert_eq!(
            selected_source(b"[Service]\nLoadCredential=unrelated-inherited-name\n").unwrap(),
            None,
        );
        assert!(
            selected_source(b"[Service]\nLoadCredential=git-evidence-provision-v1\n").is_err(),
        );
        assert!(
            selected_source(b"[Service]\nLoadCredential=git-evidence-provision-v1:/tmp/input\n")
                .is_err(),
        );

        let duplicate = [fragment.as_slice(), fragment.as_slice()].concat();
        assert!(selected_source(&duplicate).is_err());
    }

    #[test]
    fn exact_array_signature_precedes_tuple_conversion() {
        let canonical = OwnedValue::try_from(Value::from(vec![("purpose", "source")])).unwrap();

        assert!(require_signature(&canonical, "a(ss)").is_ok());

        let wrong = OwnedValue::try_from(Value::from(Vec::<String>::new())).unwrap();
        assert!(require_signature(&wrong, "a(ss)").is_err());
        assert!(require_signature(&OwnedValue::from(1_u32), "ay").is_err());
    }

    #[test]
    fn absent_purpose_preserves_unrelated_imports_but_selected_purpose_refuses_them() {
        let source = "/run/credentials/@system/git-v1";
        let mut values = vec![
            OwnedValue::try_from(Value::from(Vec::<(&str, &str)>::new())).unwrap(),
            OwnedValue::try_from(Value::from(Vec::<(&str, &str)>::new())).unwrap(),
            OwnedValue::try_from(Value::from(Vec::<(&str, Vec<u8>)>::new())).unwrap(),
            OwnedValue::try_from(Value::from(Vec::<(&str, Vec<u8>)>::new())).unwrap(),
            OwnedValue::try_from(Value::from(vec!["unrelated-import"])).unwrap(),
            OwnedValue::try_from(Value::from(Vec::<(&str, &str)>::new())).unwrap(),
        ];

        assert!(require_delivery(&values, None).is_ok());

        values[0] = OwnedValue::try_from(Value::from(vec![(NAME, source)])).unwrap();
        assert!(require_delivery(&values, Some(source)).is_err());

        values[4] = OwnedValue::try_from(Value::from(Vec::<&str>::new())).unwrap();
        assert!(require_delivery(&values, Some(source)).is_ok());
        assert!(require_delivery(&values, None).is_err());
    }
}
