//! Retained protected files and whole-directory replacement detection.

use std::collections::BTreeSet;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use aos_sandbox_linux::path::{BeneathRoot, ResolveOptions};
use aos_sandbox_source_provider_protocol::{
    SourceProviderKeyTrustStateV1, SourceProviderSigningKeyV1,
};
use ed25519_dalek::SigningKey;
use rustix::fs::{FileType, FlockOperation, Mode, OFlags, Stat};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::SourceProviderSecurityError;
use crate::manifest::{
    SOURCE_PROVIDER_SECURITY_MANIFEST_BYTES, SourceProviderSecurityManifestV1,
    SourceProviderSecurityRoleV1,
};
use crate::route_file::{SOURCE_PROVIDER_ROUTE_FILE_BYTES, SourceProviderRouteFileV1};
use crate::trust_file::{MAXIMUM_SOURCE_PROVIDER_TRUST_FILE_BYTES, SourceProviderTrustFileV1};

const MANIFEST_NAME: &str = "source-provider-manifest";
const TRUST_NAME: &str = "source-provider-trust";
const ROUTE_NAME: &str = "current-route";
const ROOT_HELLO_KEY_NAME: &str = "root-mount-hello-signing-key";
const ROOT_RECORD_KEY_NAME: &str = "root-mount-record-signing-key";
const PROVIDER_HELLO_KEY_NAME: &str = "provider-hello-signing-key";
const PROVIDER_OUTCOME_KEY_NAME: &str = "provider-outcome-signing-key";
const SECRET_BYTES: usize = 48;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MetadataSnapshot {
    device: u64,
    inode: u64,
    mode: u32,
    owner: u32,
    group: u32,
    links: u64,
    size: i64,
    modified_seconds: i64,
    modified_nanoseconds: u64,
    changed_seconds: i64,
    changed_nanoseconds: u64,
}

impl MetadataSnapshot {
    const fn capture(value: &Stat) -> Self {
        Self {
            device: value.st_dev,
            inode: value.st_ino,
            mode: value.st_mode,
            owner: value.st_uid,
            group: value.st_gid,
            links: value.st_nlink,
            size: value.st_size,
            modified_seconds: value.st_mtime,
            modified_nanoseconds: value.st_mtime_nsec,
            changed_seconds: value.st_ctime,
            changed_nanoseconds: value.st_ctime_nsec,
        }
    }
}

struct RetainedPublicFile {
    descriptor: OwnedFd,
    metadata: MetadataSnapshot,
    exact: Vec<u8>,
    digest: [u8; 32],
    label: &'static str,
}

pub(crate) struct RetainedSecret {
    descriptor: OwnedFd,
    metadata: MetadataSnapshot,
    key_id: [u8; 16],
    signing_key: SigningKey,
    label: &'static str,
}

impl core::fmt::Debug for RetainedSecret {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("RetainedSecret([redacted])")
    }
}

impl RetainedSecret {
    pub(crate) const fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

pub(crate) struct ProtectedSourceProviderFiles {
    path: PathBuf,
    group: u32,
    role: SourceProviderSecurityRoleV1,
    directory: OwnedFd,
    directory_metadata: MetadataSnapshot,
    manifest_file: RetainedPublicFile,
    trust_file: RetainedPublicFile,
    route_file: RetainedPublicFile,
    secrets: [RetainedSecret; 2],
    manifest: SourceProviderSecurityManifestV1,
    trust: SourceProviderTrustFileV1,
    route: SourceProviderRouteFileV1,
}

impl ProtectedSourceProviderFiles {
    pub(crate) fn load(
        path: &Path,
        role: SourceProviderSecurityRoleV1,
    ) -> Result<Self, SourceProviderSecurityError> {
        validate_absolute_fixed_path(path)?;
        let group = rustix::process::getegid().as_raw();
        let directory = open_directory(path)?;
        let directory_metadata = validate_directory(&directory, group)?;
        require_exact_names(&directory, directory_metadata, group, role)?;

        let manifest_file = load_fixed_public(
            &directory,
            MANIFEST_NAME,
            "manifest",
            group,
            SOURCE_PROVIDER_SECURITY_MANIFEST_BYTES,
        )?;
        rustix::fs::flock(
            &manifest_file.descriptor,
            FlockOperation::NonBlockingLockExclusive,
        )
        .map_err(|error| {
            if error == rustix::io::Errno::AGAIN {
                SourceProviderSecurityError::AlreadyInUse
            } else {
                SourceProviderSecurityError::filesystem("manifest", "lock")
            }
        })?;
        let manifest = SourceProviderSecurityManifestV1::decode(&manifest_file.exact)?;
        if manifest.role() != role {
            return Err(SourceProviderSecurityError::format("manifest", "role"));
        }

        let trust_file = load_bounded_public(
            &directory,
            TRUST_NAME,
            "trust",
            group,
            104,
            MAXIMUM_SOURCE_PROVIDER_TRUST_FILE_BYTES,
        )?;
        let route_file = load_fixed_public(
            &directory,
            ROUTE_NAME,
            "route",
            group,
            SOURCE_PROVIDER_ROUTE_FILE_BYTES,
        )?;
        if trust_file.digest != *manifest.trust_file_sha256()
            || route_file.digest != *manifest.route_file_sha256()
        {
            return Err(SourceProviderSecurityError::Currentness);
        }
        let trust = SourceProviderTrustFileV1::decode(&trust_file.exact)?;
        let route = SourceProviderRouteFileV1::decode(&route_file.exact)?;
        validate_manifest_projections(&manifest, &trust, &route)?;

        let [
            (first_name, first_label, first_index),
            (second_name, second_label, second_index),
        ] = local_keys(role);
        let secrets = [
            load_secret(&directory, first_name, first_label, group)?,
            load_secret(&directory, second_name, second_label, group)?,
        ];
        validate_secret(&secrets[0], &manifest.signers()[first_index], &trust)?;
        validate_secret(&secrets[1], &manifest.signers()[second_index], &trust)?;
        if secrets[0].signing_key.verifying_key() == secrets[1].signing_key.verifying_key() {
            return Err(SourceProviderSecurityError::KeyMaterial {
                object: "role-local keys",
            });
        }

        let files = Self {
            path: path.to_path_buf(),
            group,
            role,
            directory,
            directory_metadata,
            manifest_file,
            trust_file,
            route_file,
            secrets,
            manifest,
            trust,
            route,
        };
        files.revalidate()?;
        Ok(files)
    }

    pub(crate) const fn manifest(&self) -> &SourceProviderSecurityManifestV1 {
        &self.manifest
    }

    pub(crate) const fn trust(&self) -> &SourceProviderTrustFileV1 {
        &self.trust
    }

    pub(crate) const fn route(&self) -> &SourceProviderRouteFileV1 {
        &self.route
    }

    pub(crate) const fn hello_key(&self) -> &RetainedSecret {
        &self.secrets[0]
    }

    pub(crate) const fn outcome_key(&self) -> &RetainedSecret {
        &self.secrets[1]
    }

    pub(crate) fn revalidate(&self) -> Result<(), SourceProviderSecurityError> {
        if rustix::process::geteuid().as_raw() != 0
            || rustix::process::getegid().as_raw() != self.group
            || validate_directory(&self.directory, self.group)? != self.directory_metadata
        {
            return Err(SourceProviderSecurityError::Currentness);
        }
        require_exact_names(
            &self.directory,
            self.directory_metadata,
            self.group,
            self.role,
        )?;
        validate_retained_public(&self.manifest_file, self.group)?;
        validate_retained_public(&self.trust_file, self.group)?;
        validate_retained_public(&self.route_file, self.group)?;
        for secret in &self.secrets {
            validate_retained_secret(secret, self.group)?;
        }

        let reopened = open_directory(&self.path)?;
        if validate_directory(&reopened, self.group)? != self.directory_metadata {
            return Err(SourceProviderSecurityError::Currentness);
        }
        require_exact_names(&reopened, self.directory_metadata, self.group, self.role)?;
        compare_reopened_public(&reopened, &self.manifest_file, self.group)?;
        compare_reopened_public(&reopened, &self.trust_file, self.group)?;
        compare_reopened_public(&reopened, &self.route_file, self.group)?;
        for (secret, (name, _, _)) in self.secrets.iter().zip(local_keys(self.role)) {
            compare_reopened_secret(&reopened, name, secret, self.group)?;
        }
        Ok(())
    }
}

fn validate_manifest_projections(
    manifest: &SourceProviderSecurityManifestV1,
    trust: &SourceProviderTrustFileV1,
    route: &SourceProviderRouteFileV1,
) -> Result<(), SourceProviderSecurityError> {
    let trust_set = trust.trust_set();
    let protected_route = route.route();
    let exact = trust_set.trust_generation() == manifest.trust_generation()
        && trust_set.trust_digest() == manifest.trust_digest()
        && trust_set.revocation_generation() == manifest.revocation_generation()
        && trust_set.revocation_digest() == manifest.revocation_digest()
        && protected_route.route_id() == manifest.route_id()
        && protected_route.route_generation() == manifest.route_generation()
        && protected_route.route_digest() == manifest.route_digest()
        && protected_route.provider_authority_id() == manifest.signers()[1].authority_id()
        && route.root_mount_authority_id() == manifest.signers()[0].authority_id()
        && route.proof_capabilities() == manifest.proof_capabilities()
        && route.allow_recursive() == manifest.allow_recursive()
        && route.allow_kernel_coupled() == manifest.allow_kernel_coupled();
    if !exact {
        return Err(SourceProviderSecurityError::Currentness);
    }

    for signer in manifest.signers() {
        let key = trust_set
            .keys()
            .iter()
            .find(|entry| entry.signer() == signer)
            .ok_or(SourceProviderSecurityError::format(
                "manifest",
                "trusted signer",
            ))?;
        if key.state() != SourceProviderKeyTrustStateV1::Eligible {
            return Err(SourceProviderSecurityError::format(
                "manifest",
                "current signer",
            ));
        }
    }
    let mut public_keys = Vec::with_capacity(4);
    for signer in manifest.signers() {
        let key = trust_set
            .keys()
            .iter()
            .find(|entry| entry.signer() == signer)
            .ok_or(SourceProviderSecurityError::format(
                "manifest",
                "trusted key",
            ))?;
        public_keys.push(*key.public_key());
    }
    if (0..4).any(|left| (left + 1..4).any(|right| public_keys[left] == public_keys[right])) {
        return Err(SourceProviderSecurityError::format(
            "manifest",
            "key collision",
        ));
    }
    Ok(())
}

fn local_keys(role: SourceProviderSecurityRoleV1) -> [(&'static str, &'static str, usize); 2] {
    match role {
        SourceProviderSecurityRoleV1::RootMount => [
            (ROOT_HELLO_KEY_NAME, "Root Mount hello key", 0),
            (ROOT_RECORD_KEY_NAME, "Root Mount record key", 2),
        ],
        SourceProviderSecurityRoleV1::Provider => [
            (PROVIDER_HELLO_KEY_NAME, "provider hello key", 1),
            (PROVIDER_OUTCOME_KEY_NAME, "provider outcome key", 3),
        ],
    }
}

fn expected_names(role: SourceProviderSecurityRoleV1) -> BTreeSet<Vec<u8>> {
    [MANIFEST_NAME, TRUST_NAME, ROUTE_NAME]
        .into_iter()
        .chain(local_keys(role).map(|entry| entry.0))
        .map(|name| name.as_bytes().to_vec())
        .collect()
}

fn require_exact_names(
    directory: &OwnedFd,
    expected_metadata: MetadataSnapshot,
    group: u32,
    role: SourceProviderSecurityRoleV1,
) -> Result<(), SourceProviderSecurityError> {
    // Path-resolution descriptors are O_PATH pins. Reopen `.` through the pin
    // so enumeration can never race through a reconstructed absolute path.
    let readable = rustix::fs::openat(
        directory,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| SourceProviderSecurityError::filesystem("directory", "open for enumeration"))?;
    if validate_directory(&readable, group)? != expected_metadata {
        return Err(SourceProviderSecurityError::Currentness);
    }

    let mut observed = BTreeSet::new();
    let entries = rustix::fs::Dir::read_from(&readable)
        .map_err(|_| SourceProviderSecurityError::filesystem("directory", "enumerate"))?;
    for entry in entries {
        let entry =
            entry.map_err(|_| SourceProviderSecurityError::filesystem("directory", "enumerate"))?;
        let name = entry.file_name().to_bytes();
        if matches!(name, b"." | b"..") {
            continue;
        }
        if !observed.insert(name.to_vec()) {
            return Err(SourceProviderSecurityError::DirectoryContents);
        }
    }
    if validate_directory(&readable, group)? != expected_metadata
        || validate_directory(directory, group)? != expected_metadata
    {
        return Err(SourceProviderSecurityError::Currentness);
    }
    if observed != expected_names(role) {
        return Err(SourceProviderSecurityError::DirectoryContents);
    }
    Ok(())
}

fn validate_absolute_fixed_path(path: &Path) -> Result<(), SourceProviderSecurityError> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() < 2
        || bytes[0] != b'/'
        || bytes[1] == b'/'
        || bytes.last() == Some(&b'/')
        || bytes.contains(&0)
        || bytes[1..]
            .split(|byte| *byte == b'/')
            .any(|part| part.is_empty() || matches!(part, b"." | b".."))
    {
        return Err(SourceProviderSecurityError::DirectoryPath);
    }
    Ok(())
}

fn open_directory(path: &Path) -> Result<OwnedFd, SourceProviderSecurityError> {
    let filesystem_root = rustix::fs::open(
        "/",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| SourceProviderSecurityError::filesystem("filesystem root", "open"))?;
    let root = BeneathRoot::from_owned(filesystem_root)
        .map_err(|_| SourceProviderSecurityError::filesystem("filesystem root", "adopt"))?;
    let relative = path
        .strip_prefix(Path::new("/"))
        .map_err(|_| SourceProviderSecurityError::DirectoryPath)?;
    let resolved = root
        .resolve(
            relative,
            ResolveOptions {
                no_mount_crossing: false,
                require_directory: true,
            },
        )
        .map_err(|_| SourceProviderSecurityError::filesystem("directory", "resolve"))?;
    let resolved = BeneathRoot::from_resolved(resolved)
        .map_err(|_| SourceProviderSecurityError::filesystem("directory", "adopt"))?;
    rustix::io::dup(resolved.as_fd())
        .map_err(|_| SourceProviderSecurityError::filesystem("directory", "duplicate"))
}

fn validate_directory(
    descriptor: &OwnedFd,
    group: u32,
) -> Result<MetadataSnapshot, SourceProviderSecurityError> {
    let stat = rustix::fs::fstat(descriptor)
        .map_err(|_| SourceProviderSecurityError::filesystem("directory", "inspect"))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != 0
        || stat.st_gid != group
        || stat.st_mode & 0o7777 != 0o550
    {
        return Err(SourceProviderSecurityError::Metadata {
            object: "directory",
        });
    }
    Ok(MetadataSnapshot::capture(&stat))
}

fn load_fixed_public(
    directory: &OwnedFd,
    name: &'static str,
    label: &'static str,
    group: u32,
    size: usize,
) -> Result<RetainedPublicFile, SourceProviderSecurityError> {
    let descriptor = open_child(directory, name, label)?;
    let metadata = validate_child(&descriptor, group, size, size, label)?;
    let exact = read_exact_size(&descriptor, size, label)?;
    let repeated = read_exact_size(&descriptor, size, label)?;
    if exact != repeated || validate_child(&descriptor, group, size, size, label)? != metadata {
        return Err(SourceProviderSecurityError::Currentness);
    }
    Ok(RetainedPublicFile {
        descriptor,
        metadata,
        digest: Sha256::digest(&exact).into(),
        exact,
        label,
    })
}

fn load_bounded_public(
    directory: &OwnedFd,
    name: &'static str,
    label: &'static str,
    group: u32,
    minimum: usize,
    maximum: usize,
) -> Result<RetainedPublicFile, SourceProviderSecurityError> {
    let descriptor = open_child(directory, name, label)?;
    let stat = rustix::fs::fstat(&descriptor)
        .map_err(|_| SourceProviderSecurityError::filesystem(label, "inspect"))?;
    let size = usize::try_from(stat.st_size)
        .map_err(|_| SourceProviderSecurityError::Metadata { object: label })?;
    let metadata = validate_child(&descriptor, group, minimum, maximum, label)?;
    let exact = read_exact_size(&descriptor, size, label)?;
    let repeated = read_exact_size(&descriptor, size, label)?;
    if exact != repeated || validate_child(&descriptor, group, minimum, maximum, label)? != metadata
    {
        return Err(SourceProviderSecurityError::Currentness);
    }
    Ok(RetainedPublicFile {
        descriptor,
        metadata,
        digest: Sha256::digest(&exact).into(),
        exact,
        label,
    })
}

fn load_secret(
    directory: &OwnedFd,
    name: &'static str,
    label: &'static str,
    group: u32,
) -> Result<RetainedSecret, SourceProviderSecurityError> {
    let descriptor = open_child(directory, name, label)?;
    let metadata = validate_child(&descriptor, group, SECRET_BYTES, SECRET_BYTES, label)?;
    let exact = Zeroizing::new(read_exact_array::<SECRET_BYTES>(&descriptor, label)?);
    let repeated = Zeroizing::new(read_exact_array::<SECRET_BYTES>(&descriptor, label)?);
    if exact[..] != repeated[..]
        || validate_child(&descriptor, group, SECRET_BYTES, SECRET_BYTES, label)? != metadata
    {
        return Err(SourceProviderSecurityError::Currentness);
    }
    let key_id = exact[..16]
        .try_into()
        .map_err(|_| SourceProviderSecurityError::KeyMaterial { object: label })?;
    let seed: &[u8; 32] = exact[16..]
        .try_into()
        .map_err(|_| SourceProviderSecurityError::KeyMaterial { object: label })?;
    if key_id == [0; 16] || seed == &[0; 32] {
        return Err(SourceProviderSecurityError::KeyMaterial { object: label });
    }
    let signing_key = SigningKey::from_bytes(seed);
    if signing_key.verifying_key().is_weak() {
        return Err(SourceProviderSecurityError::KeyMaterial { object: label });
    }
    Ok(RetainedSecret {
        descriptor,
        metadata,
        key_id,
        signing_key,
        label,
    })
}

fn validate_secret(
    secret: &RetainedSecret,
    signer: &SourceProviderSigningKeyV1,
    trust: &SourceProviderTrustFileV1,
) -> Result<(), SourceProviderSecurityError> {
    let public_key = secret.signing_key.verifying_key().to_bytes();
    let digest: [u8; 32] = Sha256::digest(public_key).into();
    let trusted = trust
        .trust_set()
        .keys()
        .iter()
        .find(|entry| entry.signer() == signer)
        .is_some_and(|entry| entry.public_key() == &public_key);
    if secret.key_id != signer.key_id()
        || digest != *signer.public_key_digest().as_bytes()
        || !trusted
    {
        return Err(SourceProviderSecurityError::KeyMaterial {
            object: secret.label,
        });
    }
    Ok(())
}

fn open_child(
    directory: &OwnedFd,
    name: &'static str,
    label: &'static str,
) -> Result<OwnedFd, SourceProviderSecurityError> {
    rustix::fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| SourceProviderSecurityError::filesystem(label, "open"))
}

fn validate_child(
    descriptor: &OwnedFd,
    group: u32,
    minimum: usize,
    maximum: usize,
    label: &'static str,
) -> Result<MetadataSnapshot, SourceProviderSecurityError> {
    let stat = rustix::fs::fstat(descriptor)
        .map_err(|_| SourceProviderSecurityError::filesystem(label, "inspect"))?;
    let size = usize::try_from(stat.st_size)
        .map_err(|_| SourceProviderSecurityError::Metadata { object: label })?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != 0
        || stat.st_gid != group
        || stat.st_nlink != 1
        || stat.st_mode & 0o7777 != 0o440
        || !(minimum..=maximum).contains(&size)
    {
        return Err(SourceProviderSecurityError::Metadata { object: label });
    }
    Ok(MetadataSnapshot::capture(&stat))
}

fn read_exact_size(
    descriptor: &OwnedFd,
    size: usize,
    label: &'static str,
) -> Result<Vec<u8>, SourceProviderSecurityError> {
    let mut output = vec![0; size];
    read_into(descriptor, &mut output, label)?;
    Ok(output)
}

fn read_exact_array<const N: usize>(
    descriptor: &OwnedFd,
    label: &'static str,
) -> Result<[u8; N], SourceProviderSecurityError> {
    let mut output = [0; N];
    read_into(descriptor, &mut output, label)?;
    Ok(output)
}

fn read_into(
    descriptor: &OwnedFd,
    output: &mut [u8],
    label: &'static str,
) -> Result<(), SourceProviderSecurityError> {
    let mut offset = 0;
    while offset < output.len() {
        let position = u64::try_from(offset)
            .map_err(|_| SourceProviderSecurityError::filesystem(label, "read"))?;
        let read = rustix::io::pread(descriptor, &mut output[offset..], position)
            .map_err(|_| SourceProviderSecurityError::filesystem(label, "read"))?;
        if read == 0 || read > output.len() - offset {
            return Err(SourceProviderSecurityError::filesystem(label, "read"));
        }
        offset += read;
    }
    let position = u64::try_from(output.len())
        .map_err(|_| SourceProviderSecurityError::filesystem(label, "read"))?;
    let mut trailing = Zeroizing::new([0; 1]);
    if rustix::io::pread(descriptor, &mut trailing[..], position)
        .map_err(|_| SourceProviderSecurityError::filesystem(label, "read"))?
        != 0
    {
        return Err(SourceProviderSecurityError::Metadata { object: label });
    }
    Ok(())
}

fn validate_retained_public(
    file: &RetainedPublicFile,
    group: u32,
) -> Result<(), SourceProviderSecurityError> {
    if validate_child(
        &file.descriptor,
        group,
        file.exact.len(),
        file.exact.len(),
        file.label,
    )? != file.metadata
    {
        return Err(SourceProviderSecurityError::Currentness);
    }
    let exact = read_exact_size(&file.descriptor, file.exact.len(), file.label)?;
    let repeated = read_exact_size(&file.descriptor, file.exact.len(), file.label)?;
    if validate_child(
        &file.descriptor,
        group,
        file.exact.len(),
        file.exact.len(),
        file.label,
    )? != file.metadata
        || exact != file.exact
        || repeated != exact
        || <[u8; 32]>::from(Sha256::digest(&exact)) != file.digest
    {
        return Err(SourceProviderSecurityError::Currentness);
    }
    Ok(())
}

fn validate_retained_secret(
    secret: &RetainedSecret,
    group: u32,
) -> Result<(), SourceProviderSecurityError> {
    if validate_child(
        &secret.descriptor,
        group,
        SECRET_BYTES,
        SECRET_BYTES,
        secret.label,
    )? != secret.metadata
    {
        return Err(SourceProviderSecurityError::Currentness);
    }
    let exact = Zeroizing::new(read_exact_array::<SECRET_BYTES>(
        &secret.descriptor,
        secret.label,
    )?);
    let repeated = Zeroizing::new(read_exact_array::<SECRET_BYTES>(
        &secret.descriptor,
        secret.label,
    )?);
    let seed: &[u8; 32] = exact[16..]
        .try_into()
        .map_err(|_| SourceProviderSecurityError::Currentness)?;
    let observed = SigningKey::from_bytes(seed);
    if validate_child(
        &secret.descriptor,
        group,
        SECRET_BYTES,
        SECRET_BYTES,
        secret.label,
    )? != secret.metadata
        || exact[..] != repeated[..]
        || exact[..16] != secret.key_id
        || observed.verifying_key() != secret.signing_key.verifying_key()
    {
        return Err(SourceProviderSecurityError::Currentness);
    }
    Ok(())
}

fn compare_reopened_public(
    directory: &OwnedFd,
    retained: &RetainedPublicFile,
    group: u32,
) -> Result<(), SourceProviderSecurityError> {
    let reopened = load_bounded_public(
        directory,
        match retained.label {
            "manifest" => MANIFEST_NAME,
            "trust" => TRUST_NAME,
            "route" => ROUTE_NAME,
            _ => return Err(SourceProviderSecurityError::Currentness),
        },
        retained.label,
        group,
        retained.exact.len(),
        retained.exact.len(),
    )?;
    if reopened.metadata != retained.metadata
        || reopened.exact != retained.exact
        || reopened.digest != retained.digest
    {
        return Err(SourceProviderSecurityError::Currentness);
    }
    Ok(())
}

fn compare_reopened_secret(
    directory: &OwnedFd,
    name: &'static str,
    retained: &RetainedSecret,
    group: u32,
) -> Result<(), SourceProviderSecurityError> {
    let reopened = load_secret(directory, name, retained.label, group)?;
    if reopened.metadata != retained.metadata
        || reopened.key_id != retained.key_id
        || reopened.signing_key.verifying_key() != retained.signing_key.verifying_key()
    {
        return Err(SourceProviderSecurityError::Currentness);
    }
    Ok(())
}
