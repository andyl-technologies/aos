//! Private signed metadata indexes with descriptor-owned streamed object storage.
//!
//! ```json
//! {"body":{"schema_version":1,"artifact":{},"objects":[],"owners":[]},
//!  "authentication":[0,1,2]}
//! ```
//! Object octets are separate regular files named by their content digest. The
//! abbreviated authentication denotes the complete 32-byte index MAC; neither
//! native image bytes nor private installation paths appear in the index JSON.
//! Nonempty object, dependency, evidence and artifact inventories use pages of
//! at most 256 elements; an empty inventory uses an empty outer array.

#[path = "complete_original_validation_origin.rs"]
pub(super) mod complete_original_validation_origin;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    sync::Arc,
};

use crucible_node_format::{CaptureManifest, ContentRef, Id, Position, Validate, canonical};
use hmac::{Hmac, Mac};
use rustix::fs::{AtFlags, Mode, OFlags};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::super::{StateError, StateErrorCode, schema};
use super::{NativeArchiveLimits, decode_record, native_error, refused, storage_error};

#[path = "complete_original_loader.rs"]
mod complete_original_loader;
use crate::node_contract::{NativeCaptureArtifact, NativeStateKey};
pub(super) use complete_original_loader::{admit, admit_decode, fixed_storage};

const AUTHENTICATION_DOMAIN: &[u8] = b"crucible.native-world-archive.authentication.v1\0";
type ArchiveMac = Hmac<Sha256>;

#[path = "storage/settled_history.rs"]
mod settled_history;

#[path = "storage/restored_write17.rs"]
mod restored_write17;
pub(super) use restored_write17::PendingRestoredArchive17;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Object {
    pub reference: ContentRef,
    #[serde(with = "pages")]
    pub dependencies: Vec<ContentRef>,
}

/// Describes one authenticated native reconstruction file without a host pathname.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeArtifactState {
    /// Names the installed native artifact role.
    pub role: Id,
    /// Gives its checked relative reconstruction name.
    pub name: String,
    /// Binds its complete exact native bytes.
    pub content: ContentRef,
}

/// Retains complete backend-bound state for one authoritative capture owner.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeOwnerState {
    /// Names the original authoritative capture owner.
    pub owner: Id,
    /// Enumerates every logical participant sharing this unchanged native state.
    pub participants: Vec<Id>,
    /// Keys bytes to the actual native implementation and installed codec.
    pub key: NativeStateKey,
    /// Retains the unchanged common coordinator capture cut.
    pub cut: Position,
    /// Binds the bounded complete native operation/prefix/ACK ledger.
    pub state: ContentRef,
    /// Binds every retained small original native evidence object.
    #[serde(with = "pages")]
    pub evidence: Vec<ContentRef>,
    /// Enumerates the complete separately streamed native image/resource roster.
    #[serde(with = "pages")]
    pub artifacts: Vec<NativeArtifactState>,
}

#[derive(Clone)]
pub(super) struct Index {
    pub schema_version: u16,
    pub artifact: ContentRef,
    pub objects: Vec<Object>,
    pub owners: Vec<NativeOwnerState>,
    pub selected_extensions: Option<ContentRef>,
    pub original_capture_journal: Option<ContentRef>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    body: Index,
    authentication: [u8; 32],
}

/// Owns the local persistent signer for installed native complete-world archives.
///
/// The API has no raw signing method. Only authentic installed live captures can
/// issue signed indexes. The private archive root must outlive native backing
/// leases; source process directories and original asset paths may be removed.
pub struct NativeArchive {
    directory: Arc<File>,
    key: Zeroizing<[u8; 32]>,
    pub(super) limits: NativeArchiveLimits,
}

/// Retains authenticated native metadata and independently owned durable backing.
#[derive(Clone)]
pub struct NativeArchiveRecord {
    complete_load: Option<complete_original_loader::CompleteLoadAdmission>,
    pub(super) index: Arc<Index>,
    pub(super) manifest: CaptureManifest,
    directory: Arc<File>,
    pub(super) limits: NativeArchiveLimits,
}

impl NativeArchive {
    /// Borrows the signer's original finite archive ceilings as DATA.
    ///
    /// This copy grants no capture, signing or restoration permission.
    pub(crate) fn original_restored_capture_limits_data(&self) -> NativeArchiveLimits {
        self.limits
    }

    /// Observes the signer's retained directory allocation without accessing it.
    ///
    /// The key and limits are inline. Filesystem/native storage is separate;
    /// this data observation grants no signing or restoration permission.
    pub fn retained_requested_storage_precredit_data(&self) -> usize {
        let Self {
            directory: _,
            key: _,
            limits: _,
        } = self;
        crate::node_contract::NodeRuntime::capture_shared_allocation_storage::<File>()
    }

    /// Opens a private native archive and initializes its separate persistent key.
    ///
    /// # Errors
    /// Refuses invalid limits, nonprivate or foreign-owned directories, symlinks,
    /// nonregular keys, hard-linked keys, I/O failure or incomplete key creation.
    pub fn open(
        directory: impl AsRef<Path>,
        limits: NativeArchiveLimits,
    ) -> Result<Self, StateError> {
        if limits.state.maximum_record_bytes == 0
            || limits.native.maximum_objects == 0
            || limits.native.maximum_total_artifact_bytes == 0
        {
            return Err(limit("native archive limits"));
        }
        match fs::create_dir(directory.as_ref()) {
            Ok(()) => fs::set_permissions(directory.as_ref(), fs::Permissions::from_mode(0o700))
                .map_err(storage_error)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(storage_error(error)),
        }
        let directory = Arc::new(File::from(
            rustix::fs::open(
                directory.as_ref(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(storage_error)?,
        ));
        let metadata = directory.metadata().map_err(storage_error)?;
        let uid = rustix::process::geteuid().as_raw();
        if !metadata.is_dir() || metadata.uid() != uid || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(refused(
                "native archive is not an exclusively private owned directory",
            ));
        }
        let key_name = "native-authentication-key-v1";
        match rustix::fs::openat(
            directory.as_ref(),
            key_name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        ) {
            Ok(fd) => {
                let mut file = File::from(fd);
                let mut key = Zeroizing::new([0u8; 32]);
                File::open("/dev/urandom")
                    .map_err(storage_error)?
                    .read_exact(&mut *key)
                    .map_err(storage_error)?;
                file.write_all(&*key).map_err(storage_error)?;
                file.sync_all().map_err(storage_error)?;
                directory.sync_all().map_err(storage_error)?;
            }
            Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(storage_error(error)),
        }
        let mut key_file = File::from(
            rustix::fs::openat(
                directory.as_ref(),
                key_name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(storage_error)?,
        );
        let metadata = key_file.metadata().map_err(storage_error)?;
        if !metadata.is_file()
            || metadata.uid() != uid
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.len() != 32
        {
            return Err(refused(
                "native archive key is not a private owned single-link 32-byte file",
            ));
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key_file.read_exact(&mut *key).map_err(storage_error)?;
        Ok(Self {
            directory,
            key,
            limits,
        })
    }

    /// Loads an independently authenticated native archive from its bounded index.
    ///
    /// Native files remain descriptor-backed. No image-sized JSON array or memory
    /// allocation is needed to authenticate their complete byte identities.
    ///
    /// # Errors
    /// Refuses absent/corrupt files, invalid MACs, unknown editions, malformed
    /// metadata, changed backend rosters or exceeded metadata/artifact ceilings.
    pub fn load(&self, artifact: &ContentRef) -> Result<NativeArchiveRecord, StateError> {
        artifact.validate().map_err(schema)?;
        let bytes = read_file(
            &self.directory,
            &index_name(artifact),
            self.limits.state.maximum_record_bytes,
        )?;
        let envelope: Envelope = decode_record(&bytes, self.limits.state.maximum_record_bytes)?;
        let body =
            canonical::canonical_json(&serde_json::to_value(&envelope.body).map_err(schema)?)
                .map_err(schema)?;
        let mut mac = self.mac(envelope.body.schema_version)?;
        mac.update(&body);
        mac.verify_slice(&envelope.authentication)
            .map_err(|_| refused("native archive authentication failed"))?;
        if &envelope.body.artifact != artifact {
            return Err(refused(
                "native archive artifact differs from the requested source",
            ));
        }
        self.record(envelope.body)
    }

    pub(super) fn persist(&self, index: Index) -> Result<NativeArchiveRecord, StateError> {
        let record = self.record(index)?;
        self.persist_record_data(record)
    }

    // The original path reaches this tail only after record(index). Current17
    // reaches it through the private completed terminal-write capsule instead.
    fn persist_record_data(
        &self,
        record: NativeArchiveRecord,
    ) -> Result<NativeArchiveRecord, StateError> {
        super::super::closure::bounded_record(
            record.index.as_ref(),
            self.limits.state.maximum_record_bytes,
        )?;
        let body = canonical::canonical_json(
            &serde_json::to_value(record.index.as_ref()).map_err(schema)?,
        )
        .map_err(schema)?;
        let mut mac = self.mac(record.index.schema_version)?;
        mac.update(&body);
        let authentication = mac.finalize().into_bytes().into();
        let bytes = canonical::canonical_json(
            &serde_json::to_value(Envelope {
                body: record.index.as_ref().clone(),
                authentication,
            })
            .map_err(schema)?,
        )
        .map_err(schema)?;
        if bytes.len() > self.limits.state.maximum_record_bytes {
            return Err(limit("native signed index"));
        }
        let name = index_name(record.artifact());
        match rustix::fs::openat(
            self.directory.as_ref(),
            &name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(_) => {
                if read_edition_file(
                    &self.directory,
                    &name,
                    record.index.schema_version,
                    bytes.len(),
                    self.limits.state.maximum_record_bytes,
                )? != bytes
                {
                    return Err(refused(
                        "native archive index cannot replace an existing source",
                    ));
                }
            }
            Err(rustix::io::Errno::NOENT) => write_file(
                &self.directory,
                &name,
                &mut bytes.as_slice(),
                bytes.len() as u64,
                None,
            )?,
            Err(error) => return Err(storage_error(error)),
        }
        Ok(record)
    }

    pub(super) fn store(
        &self,
        reference: &ContentRef,
        reader: &mut dyn Read,
    ) -> Result<(), StateError> {
        reference.validate().map_err(schema)?;
        let name = object_name(reference);
        match rustix::fs::openat(
            self.directory.as_ref(),
            &name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(_) => artifact(&self.directory, reference)?
                .verify()
                .map_err(native_error),
            Err(rustix::io::Errno::NOENT) => write_file(
                &self.directory,
                &name,
                reader,
                reference.length.get(),
                Some(reference),
            ),
            Err(error) => Err(storage_error(error)),
        }
    }

    fn mac(&self, edition: u16) -> Result<ArchiveMac, StateError> {
        let mut mac = ArchiveMac::new_from_slice(self.key.as_ref()).map_err(storage_error)?;
        let domain = match edition {
            1 => AUTHENTICATION_DOMAIN,
            2 => b"crucible.native-world-archive.authentication.v2\0",
            3 => b"crucible.native-world-archive.authentication.v3\0",
            _ => return Err(refused("unsupported native authentication edition")),
        };
        mac.update(domain);
        Ok(mac)
    }

    pub(super) fn record(&self, index: Index) -> Result<NativeArchiveRecord, StateError> {
        validate_index(&index, self.limits)?;
        let bytes = read_edition_file(
            &self.directory,
            &object_name(&index.artifact),
            index.schema_version,
            usize::try_from(index.artifact.length.get()).map_err(schema)?,
            self.limits.state.maximum_record_bytes,
        )?;
        index.artifact.verify(&bytes).map_err(schema)?;
        let manifest: CaptureManifest =
            canonical::decode(&bytes, self.limits.state.maximum_record_bytes).map_err(schema)?;
        let record = NativeArchiveRecord {
            complete_load: None,
            index: Arc::new(index),
            manifest,
            directory: Arc::clone(&self.directory),
            limits: self.limits,
        };
        if record.index.schema_version == 3 {
            super::complete_original_index::authenticate(&record)?;
        }
        for owner in &record.index.owners {
            record.owner_artifacts(&owner.owner)?;
        }
        Ok(record)
    }
}

impl NativeArchiveRecord {
    /// Reads mandatory index-three administrative history as authenticated data.
    ///
    /// This read does not qualify native restoration or fresh readiness. Installed
    /// source-specific native/host validators must independently authenticate and
    /// install the complete administrative history before execution.
    ///
    /// # Errors
    /// Refuses older archive editions, absent or unsettled administrative history,
    /// changed original owner/capture scope, incomplete typed dependencies or bounds.
    pub fn original_capture_journal(
        &self,
    ) -> Result<crate::node_contract::RuntimeOriginalCaptureJournal, StateError> {
        super::complete_original_index::authenticate(self)
    }

    /// Returns the authenticated complete CNP capture manifest.
    pub fn manifest(&self) -> &CaptureManifest {
        &self.manifest
    }

    /// Returns the canonical native archive artifact identity.
    pub fn artifact(&self) -> &ContentRef {
        &self.index.artifact
    }

    /// Borrows the complete signed native backend/owner roster.
    pub fn owners(&self) -> &[NativeOwnerState] {
        &self.index.owners
    }

    /// Reads one signed small core object under the caller's allocation ceiling.
    ///
    /// The object must belong to this archive's authenticated core closure. Native
    /// image files remain available through [`Self::owner_artifacts`] as streams;
    /// this method cannot turn an arbitrary path or image digest into source data.
    ///
    /// # Errors
    /// Refuses references outside the signed closure, changed bytes, unavailable
    /// files or lengths exceeding either the caller's or installed core limit.
    pub fn object_bytes(
        &self,
        reference: &ContentRef,
        maximum: usize,
    ) -> Result<Vec<u8>, StateError> {
        self.object(
            reference,
            maximum.min(self.limits.state.maximum_content_bytes),
        )
    }

    /// Opens owned verified artifact streams for one original native owner.
    ///
    /// # Errors
    /// Refuses unknown owners, missing files or changed complete artifact bytes.
    pub fn owner_artifacts(&self, owner: &Id) -> Result<Vec<NativeCaptureArtifact>, StateError> {
        let owner = super::owner_state(self, owner)?;
        owner
            .artifacts
            .iter()
            .map(|entry| {
                let file = File::from(
                    rustix::fs::openat(
                        self.directory.as_ref(),
                        object_name(&entry.content),
                        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(storage_error)?,
                );
                NativeCaptureArtifact::from_file(
                    entry.role.clone(),
                    entry.name.clone(),
                    entry.content.clone(),
                    file,
                )
                .map_err(native_error)
            })
            .collect()
    }

    pub(super) fn object(
        &self,
        reference: &ContentRef,
        maximum: usize,
    ) -> Result<Vec<u8>, StateError> {
        if !self
            .index
            .objects
            .iter()
            .any(|object| &object.reference == reference)
        {
            return Err(refused(
                "native core object is outside authenticated index closure",
            ));
        }
        // Complete index-three objects have authenticated exact lengths. Bound
        // their reader by that length before allocation, including changed-file
        // failure; legacy archive editions preserve their original read policy.
        let maximum = if self.index.schema_version == 3 {
            maximum.min(usize::try_from(reference.length.get()).map_err(schema)?)
        } else {
            maximum
        };
        let bytes = read_file(&self.directory, &object_name(reference), maximum)?;
        reference.verify(&bytes).map_err(schema)?;
        Ok(bytes)
    }
}

pub(in crate::node_state::native) fn validate_index(
    index: &Index,
    limits: NativeArchiveLimits,
) -> Result<(), StateError> {
    if !matches!(index.schema_version, 1..=3)
        || index.objects.len() > limits.state.maximum_content_objects
        || index.owners.len() > limits.state.maximum_owners_or_domains
    {
        return Err(limit("native archive index edition or inventory"));
    }
    if index.selected_extensions.is_some() && index.schema_version != 2 {
        return Err(refused(
            "legacy native inventory cannot carry selected semantics",
        ));
    }
    if index.schema_version >= 2
        && index
            .objects
            .windows(2)
            .any(|pair| pair[0].reference >= pair[1].reference)
    {
        return Err(refused(
            "typed native inventory is not a strict canonical set",
        ));
    }
    super::complete_original_index::validate_inventory(index)?;
    let mut identities = BTreeSet::new();
    let mut hashes = BTreeMap::new();
    let mut dependency_edges = 0usize;
    let mut bytes = 0u64;
    for object in &index.objects {
        object.reference.validate().map_err(schema)?;
        if object.reference.length.get() > limits.state.maximum_content_bytes as u64
            || object.dependencies.len() > limits.state.maximum_content_objects
            || !identities.insert(object.reference.clone())
        {
            return Err(limit("native core object inventory"));
        }
        if let Some(original) =
            hashes.insert(object.reference.hash.clone(), object.reference.clone())
        {
            if original.length != object.reference.length
                || (index.schema_version == 1 && original != object.reference)
            {
                return Err(refused("native digest has inconsistent typed metadata"));
            }
        } else {
            bytes = bytes
                .checked_add(object.reference.length.get())
                .ok_or_else(|| limit("native core bytes"))?;
        }
        if index.schema_version >= 2 {
            if object
                .dependencies
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            {
                return Err(refused(
                    "typed role dependencies are not a strict canonical set",
                ));
            }
            dependency_edges = dependency_edges
                .checked_add(object.dependencies.len())
                .ok_or_else(|| limit("typed dependency edges"))?;
            if dependency_edges > limits.state.maximum_dependency_edges {
                return Err(limit("typed dependency edges"));
            }
        }
    }
    if bytes > limits.state.maximum_total_content_bytes as u64
        || !identities.contains(&index.artifact)
    {
        return Err(limit("native complete core closure"));
    }
    if let Some(journal) = &index.original_capture_journal {
        journal.validate().map_err(schema)?;
        if !identities.contains(journal) {
            return Err(refused(
                "administrative journal is outside signed typed inventory",
            ));
        }
    }
    if let Some(selected) = &index.selected_extensions {
        selected.validate().map_err(schema)?;
        if !identities.contains(selected) {
            return Err(refused(
                "selected semantic root is outside signed typed inventory",
            ));
        }
    }
    if index.schema_version >= 2
        && index
            .objects
            .iter()
            .flat_map(|object| &object.dependencies)
            .any(|reference| !identities.contains(reference))
    {
        return Err(refused("typed dependency is outside signed inventory"));
    }
    let mut owners = BTreeSet::new();
    let mut native_objects = 0usize;
    let mut native_bytes = 0u64;
    for owner in &index.owners {
        owner.owner.validate().map_err(schema)?;
        owner.key.implementation.validate().map_err(schema)?;
        owner.key.profile.validate().map_err(schema)?;
        owner.key.schema.validate().map_err(schema)?;
        if !owners.insert(owner.owner.clone())
            || owner.participants.is_empty()
            || owner.participants.windows(2).any(|pair| pair[0] >= pair[1])
            || !identities.contains(&owner.state)
        {
            return Err(refused(
                "native owner identity, state or participants differ",
            ));
        }
        for participant in &owner.participants {
            participant.validate().map_err(schema)?;
        }
        for reference in &owner.evidence {
            if !identities.contains(reference) {
                return Err(refused("native evidence is outside signed core closure"));
            }
        }
        native_objects = native_objects
            .checked_add(1)
            .and_then(|count| count.checked_add(owner.evidence.len()))
            .ok_or_else(|| limit("native record count"))?;
        let mut names = BTreeSet::new();
        for entry in &owner.artifacts {
            entry.role.validate().map_err(schema)?;
            entry.content.validate().map_err(schema)?;
            crate::node_contract::validate_native_artifact_name(&entry.name)
                .map_err(native_error)?;
            if !names.insert((entry.role.clone(), entry.name.clone()))
                || entry.content.length.get() > limits.native.maximum_artifact_bytes
            {
                return Err(limit("native image file inventory"));
            }
            native_bytes = native_bytes
                .checked_add(entry.content.length.get())
                .ok_or_else(|| limit("native image bytes"))?;
            native_objects = native_objects
                .checked_add(1)
                .ok_or_else(|| limit("native image count"))?;
        }
    }
    if native_bytes > limits.native.maximum_total_artifact_bytes
        || native_objects > limits.native.maximum_objects
    {
        return Err(limit("native complete image closure"));
    }
    Ok(())
}

fn artifact(directory: &File, reference: &ContentRef) -> Result<NativeCaptureArtifact, StateError> {
    let file = File::from(
        rustix::fs::openat(
            directory,
            object_name(reference),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(storage_error)?,
    );
    NativeCaptureArtifact::from_file(
        Id::new("archive-object").map_err(schema)?,
        object_name(reference),
        reference.clone(),
        file,
    )
    .map_err(native_error)
}

// A complete manifest has a sealed reference length; a collision check has
// the new index's exact encoded length. Their failure paths must use these
// projected extents before allocation, not the unrelated global ceiling.
// Legacy index editions retain their original file-read policy.
pub(super) fn read_edition_file(
    directory: &File,
    name: &str,
    edition: u16,
    expected_length: usize,
    maximum: usize,
) -> Result<Vec<u8>, StateError> {
    let maximum = if edition == 3 {
        maximum.min(expected_length)
    } else {
        maximum
    };
    read_file(directory, name, maximum)
}

fn read_file(directory: &File, name: &str, maximum: usize) -> Result<Vec<u8>, StateError> {
    let maximum = u64::try_from(maximum).map_err(|_| limit("native file allocation ceiling"))?;
    let read_ceiling = maximum
        .checked_add(1)
        .ok_or_else(|| limit("native file allocation ceiling"))?;
    let file = File::from(
        rustix::fs::openat(
            directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(storage_error)?,
    );
    let metadata = file.metadata().map_err(storage_error)?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(limit("native file allocation"));
    }
    let length = usize::try_from(metadata.len()).map_err(|_| limit("native file geometry"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| limit("native file allocation"))?;
    file.take(read_ceiling)
        .read_to_end(&mut bytes)
        .map_err(storage_error)?;
    if bytes.len() != length {
        return Err(refused("native indexed file changed while reading"));
    }
    Ok(bytes)
}

fn write_file(
    directory: &File,
    name: &str,
    reader: &mut dyn Read,
    length: u64,
    expected: Option<&ContentRef>,
) -> Result<(), StateError> {
    let temporary = format!("{name}.pending");
    let descriptor = match rustix::fs::openat(
        directory,
        &temporary,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    ) {
        Ok(fd) => fd,
        Err(error) => return Err(storage_error(error)),
    };
    let mut file = File::from(descriptor);
    let written = (|| {
        let maximum = length
            .checked_add(1)
            .ok_or_else(|| limit("native streamed object length"))?;
        let copied = std::io::copy(&mut reader.take(maximum), &mut file).map_err(storage_error)?;
        if copied != length {
            return Err(refused(
                "native streamed object differs from declared length",
            ));
        }
        if let Some(expected) = expected {
            NativeCaptureArtifact::from_file(
                Id::new("archive-object").map_err(schema)?,
                name.to_owned(),
                expected.clone(),
                file.try_clone().map_err(storage_error)?,
            )
            .map_err(native_error)?;
        }
        file.sync_all().map_err(storage_error)?;
        rustix::fs::renameat_with(
            directory,
            &temporary,
            directory,
            name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(storage_error)?;
        directory.sync_all().map_err(storage_error)
    })();
    if written.is_err() {
        let _ = rustix::fs::unlinkat(directory, &temporary, AtFlags::empty());
    }
    written
}

fn object_name(reference: &ContentRef) -> String {
    format!("{}.native-object-v1", reference.hash.digest)
}

fn index_name(reference: &ContentRef) -> String {
    format!("{}.native-index-v1", reference.hash.digest)
}

fn limit(component: &str) -> StateError {
    StateError::new(
        StateErrorCode::ResourceLimit,
        component,
        "finite native archive ceiling exceeded",
    )
}

// Private index inventories use bounded pages so a large legitimate file roster
// does not weaken the public canonical parser's per-array element ceiling.
pub(super) mod pages {
    use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeSeq};

    const PAGE_SIZE: usize = 256;
    const MAXIMUM_ITEMS: usize = 65_536;

    pub(in crate::node_state::native) fn serialize<T: Serialize, S: Serializer>(
        values: &[T],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(values.len().div_ceil(PAGE_SIZE)))?;
        for page in values.chunks(PAGE_SIZE) {
            sequence.serialize_element(page)?;
        }
        sequence.end()
    }

    pub(in crate::node_state::native) fn deserialize<
        'de,
        T: Deserialize<'de>,
        D: Deserializer<'de>,
    >(
        deserializer: D,
    ) -> Result<Vec<T>, D::Error> {
        let pages = Vec::<Vec<T>>::deserialize(deserializer)?;
        let length = pages
            .iter()
            .try_fold(0usize, |length, page| {
                if page.is_empty() || page.len() > PAGE_SIZE {
                    return None;
                }
                length.checked_add(page.len())
            })
            .filter(|length| *length <= MAXIMUM_ITEMS)
            .ok_or_else(|| {
                serde::de::Error::custom("native index pages exceed bounded inventory")
            })?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(length)
            .map_err(|_| serde::de::Error::custom("native index page allocation refused"))?;
        for page in pages {
            values.extend(page);
        }
        Ok(values)
    }
}

impl NativeArchiveRecord {
    /// Names this archive/index visitor and its concrete typed Manifest child.
    ///
    /// Every owning iterator is priced by its actual element type. Descriptor,
    /// content, Source and loader counters remain separate enclosing terms.
    pub(crate) fn original_archive_owned_counter_scratch_data() -> usize {
        use crate::node_contract::{NodeRuntime, RuntimeError};
        use std::mem::size_of;
        NodeRuntime::capture_complete_archive_typed_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&Index>()
            + size_of::<[usize; 2]>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Option<usize>>()
            + size_of::<[Option<&ContentRef>; 2]>()
            + size_of::<std::iter::Flatten<std::array::IntoIter<Option<&ContentRef>, 2>>>()
            + size_of::<std::slice::Iter<'static, Object>>()
            + size_of::<&Object>()
            + size_of::<std::slice::Iter<'static, ContentRef>>()
            + size_of::<&ContentRef>()
            + size_of::<std::slice::Iter<'static, NativeOwnerState>>()
            + size_of::<&NativeOwnerState>()
            + size_of::<[&Id; 4]>()
            + size_of::<std::array::IntoIter<&Id, 4>>()
            + size_of::<&Id>()
            + size_of::<std::slice::Iter<'static, Id>>()
            + size_of::<std::slice::Iter<'static, NativeArtifactState>>()
            + size_of::<&NativeArtifactState>()
    }

    pub(crate) fn capture_owned_storage(
        &self,
    ) -> Result<usize, crate::node_contract::RuntimeError> {
        use crate::node_contract::{NodeRuntime, RuntimeError};
        let add = |a: usize, b: usize| a.checked_add(b).ok_or(RuntimeError::ResourceLimit);
        // Arc<Index> retains the actual index once. Charging each owning view
        // conservatively does not treat equal portable metadata as shared bytes.
        let mut bytes = add(
            std::mem::size_of::<Self>(),
            NodeRuntime::capture_shared_allocation_storage::<File>(),
        )?;
        bytes = add(
            bytes,
            NodeRuntime::capture_manifest_storage(&self.manifest)?,
        )?;
        bytes = add(bytes, index_owned_storage(&self.index)?)?;
        Ok(bytes)
    }
}

pub(in crate::node_state::native) fn index_owned_storage(
    index: &Index,
) -> Result<usize, crate::node_contract::RuntimeError> {
    use crate::node_contract::{NodeRuntime, RuntimeError};
    use std::mem::size_of;
    let add = |a: usize, b: usize| a.checked_add(b).ok_or(RuntimeError::ResourceLimit);
    let mut bytes = NodeRuntime::capture_shared_allocation_storage::<Index>();
    bytes = add(
        bytes,
        NodeRuntime::capture_reference_storage(&index.artifact)?,
    )?;
    for reference in [
        index.selected_extensions.as_ref(),
        index.original_capture_journal.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        bytes = add(bytes, NodeRuntime::capture_reference_storage(reference)?)?;
    }
    bytes = add(
        bytes,
        index
            .objects
            .capacity()
            .checked_mul(size_of::<Object>())
            .ok_or(RuntimeError::ResourceLimit)?,
    )?;
    for object in &index.objects {
        bytes = add(
            bytes,
            NodeRuntime::capture_reference_storage(&object.reference)?,
        )?;
        bytes = add(
            bytes,
            object
                .dependencies
                .capacity()
                .checked_mul(size_of::<ContentRef>())
                .ok_or(RuntimeError::ResourceLimit)?,
        )?;
        for reference in &object.dependencies {
            bytes = add(bytes, NodeRuntime::capture_reference_storage(reference)?)?;
        }
    }
    bytes = add(
        bytes,
        index
            .owners
            .capacity()
            .checked_mul(size_of::<NativeOwnerState>())
            .ok_or(RuntimeError::ResourceLimit)?,
    )?;
    for owner in &index.owners {
        if !owner.key.schema.extensions.is_empty() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        for id in [
            &owner.owner,
            &owner.key.implementation,
            &owner.key.profile,
            &owner.key.schema.id,
        ] {
            bytes = add(bytes, id.allocated_capacity())?;
        }
        bytes = add(
            bytes,
            NodeRuntime::capture_reference_storage(&owner.key.schema.definition)?,
        )?;
        bytes = add(
            bytes,
            NodeRuntime::capture_map_node_storage::<String, serde_json::Value>(),
        )?;
        bytes = add(
            bytes,
            owner
                .participants
                .capacity()
                .checked_mul(size_of::<Id>())
                .ok_or(RuntimeError::ResourceLimit)?,
        )?;
        for participant in &owner.participants {
            bytes = add(bytes, participant.allocated_capacity())?;
        }
        bytes = add(bytes, NodeRuntime::capture_reference_storage(&owner.state)?)?;
        bytes = add(
            bytes,
            owner
                .evidence
                .capacity()
                .checked_mul(size_of::<ContentRef>())
                .ok_or(RuntimeError::ResourceLimit)?,
        )?;
        for reference in &owner.evidence {
            bytes = add(bytes, NodeRuntime::capture_reference_storage(reference)?)?;
        }
        bytes = add(
            bytes,
            owner
                .artifacts
                .capacity()
                .checked_mul(size_of::<NativeArtifactState>())
                .ok_or(RuntimeError::ResourceLimit)?,
        )?;
        for artifact in &owner.artifacts {
            bytes = add(bytes, artifact.role.allocated_capacity())?;
            bytes = add(bytes, artifact.name.capacity())?;
            bytes = add(
                bytes,
                NodeRuntime::capture_reference_storage(&artifact.content)?,
            )?;
        }
    }
    Ok(bytes)
}

#[path = "original_evidence.rs"]
mod original_evidence;

impl NativeArchiveRecord {
    pub(crate) fn retained_descriptor_views_precredit_data(&self) -> usize {
        let Self {
            complete_load: _,
            index: _,
            manifest: _,
            directory,
            limits: _,
        } = self;
        let _: &File = directory.as_ref();
        1
    }
}
