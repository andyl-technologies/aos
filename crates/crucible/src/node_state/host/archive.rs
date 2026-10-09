//! Private persistent archive authentication and bounded immutable object storage.
//!
//! ```json
//! {"body":{"schema_version":1,"artifact":{},"objects":[]},"authentication":[]}
//! ```
//!
//! The authentication covers every byte and dependency edge under a versioned
//! domain. Keys stay in the host archive directory and are never capture fields.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    rc::Rc,
};

use crucible_node_contract::{CaptureManifest, ContentRef, HashRef, Validate, canonical};
use hmac::{Hmac, Mac};
use rustix::fs::{AtFlags, Mode, OFlags};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::super::closure::{bounded_record, limit};
use super::super::{StateError, StateErrorCode, StateLimits, schema};

#[path = "archive_decode.rs"]
mod decoding;

const AUTHENTICATION_DOMAIN: &[u8] = b"crucible.host-world-archive.authentication.v1\0";
type ArchiveMac = Hmac<Sha256>;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Object {
    pub reference: ContentRef,
    pub dependencies: Vec<ContentRef>,
    pub bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ArchiveBody {
    pub schema_version: u32,
    pub artifact: ContentRef,
    pub objects: Vec<Object>,
}

/// Owns the local persistent signing key and durable archive directory.
///
/// The key is generated from kernel randomness once, retained in a private
/// regular file, and reused after daemon restart. This type has no raw signing
/// API. Only authentic live host captures can issue a new signed source.
pub struct HostArchive {
    #[cfg(test)]
    pub(super) directory: std::path::PathBuf,
    directory_file: File,
    key: Zeroizing<[u8; 32]>,
    pub(super) limits: StateLimits,
}

/// Retains a host-authenticated immutable complete capture closure.
///
/// Construction is private to the installed archive. Public object hashes alone
/// cannot create this original-source provenance. Installed model qualification
/// remains required separately before capture admission or native restoration.
#[derive(Clone)]
pub struct HostArchiveRecord {
    pub(super) body: Rc<ArchiveBody>,
    pub(super) index: BTreeMap<HashRef, usize>,
    pub(super) manifest: CaptureManifest,
}

impl HostArchive {
    /// Opens or initializes an exclusively private persistent archive directory.
    ///
    /// Callers select a trusted local installation path. Existing directory and
    /// key permissions must exclude other users; symlinks and nonregular key
    /// files are refused. The key must be backed up separately from public
    /// capture artifacts when moving an installation.
    ///
    /// # Errors
    /// Refuses I/O failures, nonprivate paths, an invalid key, or invalid limits.
    pub fn open(directory: impl AsRef<Path>, limits: StateLimits) -> Result<Self, StateError> {
        let directory = directory.as_ref().to_path_buf();
        if limits.maximum_content_objects == 0 || limits.maximum_total_content_bytes == 0 {
            return Err(limit("host archive limits"));
        }
        match fs::create_dir(&directory) {
            Ok(()) => fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .map_err(storage)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(storage(error)),
        }
        let directory_file = File::from(
            rustix::fs::open(
                &directory,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| storage(error.into()))?,
        );
        let metadata = directory_file.metadata().map_err(storage)?;
        let effective_uid = rustix::process::geteuid().as_raw();
        if !metadata.is_dir()
            || metadata.uid() != effective_uid
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(refusal(
                "archive directory is not exclusively owned by the current effective user",
            ));
        }
        let key_name = "authentication-key-v1";
        match rustix::fs::openat(
            &directory_file,
            key_name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        ) {
            Ok(descriptor) => {
                let mut file = File::from(descriptor);
                let mut key = Zeroizing::new([0u8; 32]);
                let initialized = (|| {
                    File::open("/dev/urandom")
                        .map_err(storage)?
                        .read_exact(&mut *key)
                        .map_err(storage)?;
                    file.write_all(&*key).map_err(storage)?;
                    file.sync_all().map_err(storage)?;
                    directory_file.sync_all().map_err(storage)
                })();
                if let Err(error) = initialized {
                    // Never overwrite or auto-repair an existing key. A failed
                    // first write remains fail-closed and requires explicit
                    // installation repair before this archive can be reopened.
                    return Err(StateError::new(
                        error.code,
                        error.component,
                        format!(
                            "{}; incomplete new authentication key requires explicit installation repair",
                            error.reason
                        ),
                    ));
                }
            }
            Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(storage(error.into())),
        }
        // Validate the opened descriptor, avoiding path-check/open races and
        // refusing hard links to another location even when permissions match.
        let mut key_file = File::from(
            rustix::fs::openat(
                &directory_file,
                key_name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| storage(error.into()))?,
        );
        let metadata = key_file.metadata().map_err(storage)?;
        if !metadata.is_file()
            || metadata.uid() != effective_uid
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.len() != 32
        {
            return Err(refusal(
                "authentication key is not a private single-link 32-byte file owned by the current effective user",
            ));
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key_file.read_exact(&mut *key).map_err(storage)?;
        Ok(Self {
            #[cfg(test)]
            directory,
            directory_file,
            key,
            limits,
        })
    }

    /// Imports a bounded archive authenticated by this installation's persistent key.
    ///
    /// Authentication precedes semantic admission. The original source may be
    /// terminated; neither a source process nor saved execution permissions are
    /// required. Every byte and reference edge is bound by the authentication.
    ///
    /// # Errors
    /// Refuses unavailable files, excessive bytes, malformed editions, corrupt
    /// objects, inconsistent metadata, incomplete closure or failed authentication.
    pub fn load(&self, artifact: &ContentRef) -> Result<HostArchiveRecord, StateError> {
        artifact.validate().map_err(schema)?;
        let name = self.archive_name(artifact);
        let file = File::from(
            rustix::fs::openat(
                &self.directory_file,
                &name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| storage(error.into()))?,
        );
        let metadata = file.metadata().map_err(storage)?;
        let maximum = maximum_archive_bytes(self.limits)?;
        if !metadata.is_file() || metadata.len() > maximum as u64 {
            return Err(limit("host archive file bytes"));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(metadata.len() as usize)
            .map_err(|_| limit("host archive file allocation"))?;
        file.take(maximum as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(storage)?;
        if bytes.len() > maximum {
            return Err(limit("host archive file bytes"));
        }
        let body_bytes = self.authenticate_envelope(&bytes)?;
        let body = decoding::decode(body_bytes, self.limits)?;
        if &body.artifact != artifact {
            return Err(refusal("archive artifact differs"));
        }
        validate_body(body, self.limits)
    }

    pub(super) fn persist(&self, body: ArchiveBody) -> Result<HostArchiveRecord, StateError> {
        let record = validate_body(body, self.limits)?;
        let authentication: [u8; 32] = self.mac(&record.body)?.finalize().into_bytes().into();
        let signed = SignedArchiveRef {
            body: &record.body,
            authentication,
        };
        let name = self.archive_name(record.artifact());
        let temporary = format!("{}.pending", record.artifact().hash.digest);
        let mut file = File::from(
            rustix::fs::openat(
                &self.directory_file,
                &temporary,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|error| storage(error.into()))?,
        );
        let written = (|| {
            // Streaming integer arrays produce many tiny serializer writes.
            // Bound buffering independently of archive size, then flush before
            // the durability fence without changing authenticated bytes.
            let mut writer = std::io::BufWriter::with_capacity(64 * 1024, &mut file);
            serde_json::to_writer(&mut writer, &signed).map_err(schema)?;
            writer.flush().map_err(storage)?;
            drop(writer);
            file.sync_all().map_err(storage)?;
            rustix::fs::renameat(
                &self.directory_file,
                &temporary,
                &self.directory_file,
                &name,
            )
            .map_err(|error| storage(error.into()))?;
            self.directory_file.sync_all().map_err(storage)
        })();
        if written.is_err() {
            let _ = rustix::fs::unlinkat(&self.directory_file, &temporary, AtFlags::empty());
        }
        written?;
        Ok(record)
    }

    fn archive_name(&self, artifact: &ContentRef) -> String {
        format!("{}.host-world-v1.json", artifact.hash.digest)
    }

    fn authenticate_envelope<'a>(&self, bytes: &'a [u8]) -> Result<&'a [u8], StateError> {
        const PREFIX: &[u8] = b"{\"body\":";
        const AUTHENTICATION: &[u8] = b",\"authentication\":";
        let unsigned = bytes
            .strip_prefix(PREFIX)
            .ok_or_else(|| refusal("unsupported archive envelope edition"))?;
        let split = unsigned
            .windows(AUTHENTICATION.len())
            .rposition(|window| window == AUTHENTICATION)
            .ok_or_else(|| refusal("archive authentication envelope is incomplete"))?;
        let body = &unsigned[..split];
        let signature = unsigned[split + AUTHENTICATION.len()..]
            .strip_suffix(b"}")
            .ok_or_else(|| refusal("archive authentication envelope is incomplete"))?;
        if signature.len() > 129 {
            return Err(limit("archive authentication bytes"));
        }
        let authentication: [u8; 32] = serde_json::from_slice(signature).map_err(schema)?;
        let mut mac = ArchiveMac::new_from_slice(&*self.key).map_err(schema)?;
        mac.update(AUTHENTICATION_DOMAIN);
        mac.update(body);
        mac.verify_slice(&authentication)
            .map_err(|_| refusal("archive authentication failed"))?;
        Ok(body)
    }

    fn mac(&self, body: &ArchiveBody) -> Result<ArchiveMac, StateError> {
        let mut mac = ArchiveMac::new_from_slice(&*self.key).map_err(schema)?;
        mac.update(AUTHENTICATION_DOMAIN);
        struct MacWriter<'a>(&'a mut ArchiveMac);
        impl Write for MacWriter<'_> {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.update(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        // The closed declaration-order edition is identical at issuance and
        // import. Stream directly into the MAC rather than cloning the closure.
        serde_json::to_writer(MacWriter(&mut mac), body).map_err(schema)?;
        Ok(mac)
    }
}

#[derive(Serialize)]
struct SignedArchiveRef<'a> {
    body: &'a ArchiveBody,
    authentication: [u8; 32],
}

impl HostArchiveRecord {
    /// Returns the complete original manifest artifact identity.
    pub fn artifact(&self) -> &ContentRef {
        &self.body.artifact
    }

    /// Returns the original complete world manifest without granting execution.
    pub fn manifest(&self) -> &CaptureManifest {
        &self.manifest
    }

    /// Copies bounded immutable bytes from the authenticated complete closure.
    ///
    /// This read grants no native qualification or execution authority. An
    /// installed provider must independently match the requested reference to
    /// its enrolled model input before using these bytes in fresh realization.
    ///
    /// # Errors
    /// Refuses objects outside the authenticated closure, changed reference
    /// metadata, excess length, or unavailable bounded allocation.
    pub fn content_bytes(
        &self,
        reference: &ContentRef,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, StateError> {
        let object = self.object(reference)?;
        if object.bytes.len() > maximum_bytes {
            return Err(limit("authenticated immutable content read"));
        }
        reference.verify(&object.bytes).map_err(schema)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(object.bytes.len())
            .map_err(|_| limit("authenticated immutable content allocation"))?;
        bytes.extend_from_slice(&object.bytes);
        Ok(bytes)
    }

    pub(super) fn object(&self, reference: &ContentRef) -> Result<&Object, StateError> {
        self.index
            .get(&reference.hash)
            .and_then(|index| self.body.objects.get(*index))
            .filter(|object| &object.reference == reference)
            .ok_or_else(|| refusal("authenticated archive object unavailable or metadata differs"))
    }
}

pub(super) fn validate_for_capture(
    body: ArchiveBody,
    limits: StateLimits,
) -> Result<HostArchiveRecord, StateError> {
    validate_body(body, limits)
}

pub(super) fn take_capture_body(record: HostArchiveRecord) -> Result<ArchiveBody, StateError> {
    Rc::try_unwrap(record.body)
        .map_err(|_| refusal("capture archive still borrowed before issuance"))
}

fn validate_body(body: ArchiveBody, limits: StateLimits) -> Result<HostArchiveRecord, StateError> {
    if body.schema_version != 1 || body.objects.len() > limits.maximum_content_objects {
        return Err(limit("archive edition or object roster"));
    }
    let mut index = BTreeMap::new();
    let mut total = 0usize;
    let mut edges = 0usize;
    for (position, object) in body.objects.iter().enumerate() {
        if object.bytes.len() > limits.maximum_content_bytes
            || object.dependencies.len() > limits.maximum_content_objects
        {
            return Err(limit("archive object ceiling"));
        }
        total = total
            .checked_add(object.bytes.len())
            .ok_or_else(|| limit("archive total bytes"))?;
        edges = edges
            .checked_add(object.dependencies.len())
            .ok_or_else(|| limit("archive dependency edges"))?;
        if total > limits.maximum_total_content_bytes || edges > limits.maximum_dependency_edges {
            return Err(limit("archive aggregate closure"));
        }
        object.reference.verify(&object.bytes).map_err(schema)?;
        if index
            .insert(object.reference.hash.clone(), position)
            .is_some()
            || object
                .dependencies
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(refusal("archive repeats objects or dependency edges"));
        }
    }
    for object in &body.objects {
        for child in &object.dependencies {
            child.validate().map_err(schema)?;
            if index
                .get(&child.hash)
                .and_then(|position| body.objects.get(*position))
                .is_none_or(|found| &found.reference != child)
            {
                return Err(refusal("archive dependency closure is incomplete"));
            }
        }
    }
    let manifest_object = index
        .get(&body.artifact.hash)
        .and_then(|position| body.objects.get(*position))
        .filter(|object| object.reference == body.artifact)
        .ok_or_else(|| refusal("archive manifest unavailable"))?;
    bounded_record(&body.artifact, limits.maximum_record_bytes)?;
    let manifest: CaptureManifest =
        canonical::decode(&manifest_object.bytes, limits.maximum_record_bytes).map_err(schema)?;
    manifest.validate().map_err(schema)?;
    let canonical = canonical::canonical_json(&serde_json::to_value(&manifest).map_err(schema)?)
        .map_err(schema)?;
    if canonical != manifest_object.bytes {
        return Err(refusal("archive manifest is not canonical"));
    }
    // Refuse unreachable extra objects: authentication is a complete immutable
    // source registry, not an authorization to access arbitrary archived bytes.
    let mut pending = vec![body.artifact.clone()];
    let mut seen = BTreeSet::new();
    while let Some(reference) = pending.pop() {
        if seen.insert(reference.hash.clone()) {
            let position = index
                .get(&reference.hash)
                .ok_or_else(|| refusal("archive root missing"))?;
            pending.extend(body.objects[*position].dependencies.iter().cloned());
        }
    }
    if seen.len() != body.objects.len() {
        return Err(refusal("archive contains unbound source objects"));
    }
    Ok(HostArchiveRecord {
        body: Rc::new(body),
        index,
        manifest,
    })
}

fn maximum_archive_bytes(limits: StateLimits) -> Result<usize, StateError> {
    limits
        .maximum_total_content_bytes
        .checked_mul(4)
        .and_then(|bytes| bytes.checked_add(limits.maximum_record_bytes))
        .and_then(|bytes| {
            limits
                .maximum_dependency_edges
                .checked_mul(1024)
                .and_then(|overhead| bytes.checked_add(overhead))
        })
        .ok_or_else(|| limit("archive stream ceiling"))
}

pub(super) fn refusal(reason: impl Into<String>) -> StateError {
    StateError::new(StateErrorCode::NativeEvidence, "host archive", reason)
}

pub(super) fn storage(error: std::io::Error) -> StateError {
    StateError::new(
        StateErrorCode::Content,
        "host archive storage",
        error.to_string(),
    )
}
