//! Retains a new18 private key/File container under its independent Source row.
//!
//! This shares the original private key domain and complete executable identity.
//! It creates no old startup purpose, allocation row, ACK witness or native
//! admission. The explicit18 Source worker owns the actual constructor call.

use super::*;
use crate::node_adapters::cnp::semantic::source::{
    private_birth_clone_construction_data, private_birth_clone_counter_scratch_data,
};
use crate::node_contract::RuntimeError;
use std::mem::size_of;

/// Keeps complete clone/File children before the Birth can be assembled.
pub(in crate::node_adapters::cnp::semantic::packet_complete_source) struct NativeImport18PrivateBirthAttempt
{
    host: Option<ContentRef>,
    private_launch: Option<Id>,
    file: Option<File>,
    revision: Option<HostRevision>,
    started: bool,
    failed: bool,
}

impl NativeImport18PrivateBirthAttempt {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn new_data() -> Self {
        Self {
            host: None,
            private_launch: None,
            file: None,
            revision: None,
            started: false,
            failed: false,
        }
    }

    /// Names the actual by-value return from the empty partial-owner factory.
    ///
    /// This is construction work; it is not another retained heap allocation.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn new_construction_transient_data()
    -> usize {
        size_of::<Self>()
    }

    /// Counts actual complete child clones even after a later IO refusal.
    ///
    /// # Errors
    /// Refuses checked capacity overflow or backing beyond the supplied bound.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn retained_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let mut host_bytes = 0usize;
        if let Some(host) = &self.host {
            for capacity in [
                host.hash.algorithm.capacity(),
                host.hash.domain.capacity(),
                host.hash.digest.capacity(),
                host.media_type.capacity(),
            ] {
                host_bytes = host_bytes
                    .checked_add(capacity)
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
        }
        let id = self
            .private_launch
            .as_ref()
            .map_or(0, Id::allocated_capacity);
        let total = host_bytes
            .checked_add(id)
            .ok_or(RuntimeError::ResourceLimit)?;
        if total > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(total)
    }

    /// Quotes the exact String-clone requests and genuine fixed IO/hash work.
    ///
    /// # Errors
    /// Refuses checked String extent overflow or any axis beyond the bound.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn construction_storage_data(
        host: &ContentRef,
        private_launch: &Id,
        maximum: usize,
    ) -> Result<[usize; 3], RuntimeError> {
        let mut retained = private_launch.as_str().len();
        for text in [
            &host.hash.algorithm,
            &host.hash.domain,
            &host.hash.digest,
            &host.media_type,
        ] {
            retained = retained
                .checked_add(text.len())
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        let (clone_transient, clone_scratch) =
            private_birth_clone_construction_data(host, private_launch, maximum)?;
        // The first complete host clone remains retained while Id is cloned.
        // The independent clone return/input headers and both Some assignment
        // values supplement that already-declared partial-backing window.
        let transient = retained
            .checked_add(clone_transient)
            .and_then(|bytes| bytes.checked_add(size_of::<Option<ContentRef>>()))
            .and_then(|bytes| bytes.checked_add(size_of::<Option<Id>>()))
            .ok_or(RuntimeError::ResourceLimit)?;
        let scratch = Self::counter_scratch_data()
            .checked_add(clone_scratch)
            .ok_or(RuntimeError::ResourceLimit)?;
        if retained > maximum || transient > maximum || scratch > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok([retained, transient, scratch])
    }

    /// Names the real stream and partial-owner constructor controls.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn counter_scratch_data()
    -> usize {
        HOST_EXECUTABLE_STREAM_BYTES
            + private_birth_clone_counter_scratch_data()
            + size_of::<(usize, usize)>() // concrete clone quote local
            + size_of::<Result<(usize, usize), RuntimeError>>()
            + size_of::<Option<usize>>() // row checked-add result
            + size_of::<usize>() * 4 // clone T/S and new whole T/S locals
            + size_of::<usize>() // sequential and_then closure input
            + 384 // Pinned Linux File::open's small-C-string path for these literals.
            + size_of::<Self>()
            + size_of::<&mut Self>()
            + size_of::<&Self>()
            + size_of::<OriginalAckPeerBirth>()
            + size_of::<Option<OriginalAckPeerBirth>>()
            + size_of::<&mut Option<OriginalAckPeerBirth>>()
            + size_of::<&OriginalAckPeerBirth>()
            + size_of::<&ContentRef>()
            + size_of::<&Id>()
            + size_of::<ContentRef>()
            + size_of::<Id>()
            + size_of::<[&String; 4]>()
            + size_of::<std::array::IntoIter<&'static String, 4>>()
            + size_of::<File>() * 2
            + size_of::<std::fs::Metadata>() * 2
            + size_of::<Result<std::fs::Metadata, std::io::Error>>()
            + size_of::<Result<File, std::io::Error>>()
            + size_of::<HostRevision>() * 3
            + size_of::<Result<HostRevision, RuntimeError>>()
            + size_of::<blake3::Hasher>()
            + size_of::<blake3::Hash>()
            + hex_result_layout(blake3::Hash::to_hex)
            + size_of::<[u8; 32]>()
            + size_of::<&mut [u8]>()
            + size_of::<&[u8]>()
            + size_of::<&str>()
            + size_of::<u64>() * 3
            + size_of::<usize>() * 3
            + size_of::<bool>() * 2
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Result<(), std::io::Error>>()
            + size_of::<Result<usize, std::num::TryFromIntError>>()
            + size_of::<[usize; 3]>()
            + size_of::<Result<[usize; 3], RuntimeError>>()
            + size_of::<&mut Option<Vec<u8>>>() * 2
            + size_of::<(Option<Vec<u8>>, Option<Vec<u8>>)>()
            + size_of::<(Option<ContentRef>, Option<Id>, Option<File>, Option<HostRevision>)>()
    }
}

// Names the actual public method's concrete owned return layout without
// invoking the method, constructing a hash, or requiring a transitive crate.
fn hex_result_layout<T>(_: fn(&blake3::Hash) -> T) -> usize {
    size_of::<T>() + size_of::<fn(&blake3::Hash) -> T>()
}

impl OriginalAckPeerBirth {
    /// Installs the actual new18 private container before entropy and measurement.
    ///
    /// Its caller already admitted this component row and retains the attempt
    /// before entry. Neither this private container nor its ready bit signs an
    /// old/new ACK or grants native startup. New18 dispatch remains explicit.
    ///
    /// # Errors
    /// Refuses repeated custody, missing banks, foreign File/key identity or IO.
    /// Earlier clone/File outputs and both complete/partial input banks survive.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn retain_import18_private_birth_into_data(
        host: &ContentRef,
        private_launch: &Id,
        source: &mut Option<Vec<u8>>,
        registration: &mut Option<Vec<u8>>,
        attempt: &mut NativeImport18PrivateBirthAttempt,
        completed: &mut Option<Self>,
    ) -> Result<(), RuntimeError> {
        if attempt.started || completed.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        attempt.started = true;
        attempt.failed = true;
        if source.as_ref().is_none_or(Vec::is_empty)
            || registration.as_ref().is_none_or(Vec::is_empty)
        {
            return Err(RuntimeError::OwnerUnavailable);
        }
        attempt.host = Some(host.clone());
        attempt.private_launch = Some(private_launch.clone());
        attempt.file =
            Some(File::open("/proc/self/exe").map_err(|_| RuntimeError::OwnerUnavailable)?);
        attempt.revision = Some(read_revision(
            attempt
                .file
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
        )?);

        // All children exist before this nonallocating assembly. A mismatched
        // slot is restored rather than dropping any earlier completed child.
        let children = (
            attempt.host.take(),
            attempt.private_launch.take(),
            attempt.file.take(),
            attempt.revision.take(),
        );
        let (host_executable, private_launch, host_file, host_revision) = match children {
            (Some(host), Some(id), Some(file), Some(revision)) => (host, id, file, revision),
            (host, id, file, revision) => {
                attempt.host = host;
                attempt.private_launch = id;
                attempt.file = file;
                attempt.revision = revision;
                return Err(RuntimeError::OwnerUnavailable);
            }
        };
        *completed = Some(Self {
            process: std::process::id(),
            thread: std::thread::current().id(),
            key: [0; 32],
            birth_id: [0; 32],
            host_executable,
            host_file,
            host_revision,
            private_launch,
            source_birth: Vec::new(),
            expected_host_registration: Vec::new(),
            boot_started: std::cell::Cell::new(false),
            ready: false,
            failed: true,
            // This closes the legacy private writer. Only the explicit18 member
            // and wire path can use the new mechanism's separately funded banks.
            report_startup_required: true,
            report_startup: None,
            native_startup: None,
            native_import18: None,
            native_host_finalization: None,
            host_startup: std::cell::RefCell::new(None),
        });
        let owner = completed.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        match (source.take(), registration.take()) {
            (Some(source), Some(registration)) => {
                owner.source_birth = source;
                owner.expected_host_registration = registration;
            }
            (original_source, original_registration) => {
                *source = original_source;
                *registration = original_registration;
                return Err(RuntimeError::OwnerUnavailable);
            }
        }
        authenticate_file_identity(owner)?;
        File::open("/dev/urandom")
            .and_then(|mut random| random.read_exact(&mut owner.key))
            .map_err(|_| RuntimeError::OwnerUnavailable)?;
        owner.birth_id =
            blake3::derive_key("source-owned.packet-canonical-ack-birth/5", &owner.key);
        authenticate_file_identity(owner)?;
        owner.ready = true;
        owner.failed = false;
        attempt.failed = false;
        Ok(())
    }
}

fn read_revision(file: &File) -> Result<HostRevision, RuntimeError> {
    let metadata = file
        .metadata()
        .map_err(|_| RuntimeError::OwnerUnavailable)?;
    if !metadata.is_file() {
        return Err(RuntimeError::ForeignAuthority);
    }
    Ok(HostRevision {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        uid: metadata.uid(),
        mode: metadata.mode(),
        modified: (metadata.mtime(), metadata.mtime_nsec()),
        changed: (metadata.ctime(), metadata.ctime_nsec()),
    })
}

fn authenticate_file_identity(owner: &OriginalAckPeerBirth) -> Result<(), RuntimeError> {
    if owner.process != std::process::id() || owner.thread != std::thread::current().id() {
        return Err(RuntimeError::ForeignAuthority);
    }
    let current = File::open("/proc/self/exe").map_err(|_| RuntimeError::OwnerUnavailable)?;
    if read_revision(&owner.host_file)? != owner.host_revision
        || read_revision(&current)? != owner.host_revision
        || owner.host_revision.length != owner.host_executable.length.get()
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    let domain = b"cnp.blob.v1";
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"CNP/1\0");
    hasher.update(&(domain.len() as u32).to_be_bytes());
    hasher.update(domain);
    hasher.update(&owner.host_revision.length.to_be_bytes());
    let mut scratch = [0u8; HOST_EXECUTABLE_STREAM_BYTES];
    let mut offset = 0u64;
    while offset < owner.host_revision.length {
        let remaining = owner.host_revision.length - offset;
        let length = usize::try_from(remaining.min(scratch.len() as u64))
            .map_err(|_| RuntimeError::ResourceLimit)?;
        owner
            .host_file
            .read_exact_at(&mut scratch[..length], offset)
            .map_err(|_| RuntimeError::OwnerUnavailable)?;
        hasher.update(&scratch[..length]);
        offset += length as u64;
    }
    let digest = hasher.finalize().to_hex();
    if owner.host_executable.hash.algorithm != "blake3-256"
        || owner.host_executable.hash.domain != "cnp.blob.v1"
        || owner.host_executable.hash.digest != digest.as_str()
        || owner.host_executable.media_type != "application/octet-stream"
        || read_revision(&owner.host_file)? != owner.host_revision
        || read_revision(&current)? != owner.host_revision
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    if owner.process != std::process::id() || owner.thread != std::thread::current().id() {
        return Err(RuntimeError::ForeignAuthority);
    }
    Ok(())
}
