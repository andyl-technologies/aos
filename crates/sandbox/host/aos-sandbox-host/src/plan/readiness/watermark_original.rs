//! Retains the sole protected readiness-watermark persistence engine.
//!
//! Ordinary callers immediately delegate with transient destinations. A paid
//! Host-control caller retains the actual directory/current/temp files, native
//! errors, partial read and cleanup. This issues no readiness or floor proof.

use super::*;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::protected_file::{ReadinessAtomicWriteOriginalV2, ReadinessAtomicWritePurposeV2};
use std::{error::Error, io, mem::size_of};

/// Reports refusal while the actual watermark originals remain resident.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("readiness watermark persistence is incomplete or refused")]
pub(in crate::plan) struct ReadinessWatermarkClosedV2;

#[derive(Clone, Copy)]
enum First {
    Reentry,
    Directory,
    DirectoryMetadata,
    DirectoryPolicy,
    CurrentOpen,
    Read,
    Decode,
    Transition,
    Encode,
    Atomic,
}

#[derive(Clone, Copy)]
enum Destination {
    Retained,
    Ordinary,
}

#[derive(Clone, Copy)]
enum ReadFirst {
    Metadata,
    Policy,
    Read,
    Length,
}

#[derive(Clone, Copy)]
enum ReadPermissions {
    PrivateReadiness,
    PackagedPolicy,
}

#[derive(Default)]
pub(super) struct ProtectedReadOriginalV2 {
    file: Option<File>,
    metadata: Option<std::result::Result<rustix::fs::Stat, rustix::io::Errno>>,
    policy: Option<Result<usize>>,
    bytes: Vec<u8>,
    read: Option<io::Result<usize>>,
    length: Option<Result<()>>,
    first: Option<ReadFirst>,
}

impl ProtectedReadOriginalV2 {
    pub(super) fn new() -> Self {
        Self::default()
    }

    // The caller separately pays/open its actual path and namespace. This
    // source prices only this whole descriptor, bounded read and policy label.
    pub(super) fn receiving_demand_v2(maximum: usize, name_bytes: usize) -> Option<ResourceVector> {
        let reached = maximum.checked_add(1)?;
        let policy = b"backend readiness  is not a protected root-owned file"
            .len()
            .checked_add(name_bytes)?;
        // Both entry wrappers transfer the same OFD. Price their argument and
        // result planes and the permission policy's validation frames;
        // neither path creates another descriptor or native observation.
        let dispatch = size_of::<(&mut Self, OwnedFd, &'static str, usize, ReadPermissions)>()
            .checked_mul(3)?
            .checked_add(size_of::<ReadPermissions>().checked_mul(3)?)?
            .checked_add(
                size_of::<std::result::Result<(), ReadinessWatermarkClosedV2>>().checked_mul(3)?,
            )?;
        let bytes = size_of::<Self>()
            .checked_add(reached.checked_mul(3)?)?
            .checked_add(size_of::<[u8; 32]>())?
            .checked_add(dispatch)?
            .checked_add(policy)?;
        Some(
            ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
                .with(D::OpenFiles, 1)
                .with(D::OutputBytes, u64::try_from(reached).ok()?),
        )
    }

    pub(super) fn bytes_v2(&self) -> Option<&[u8]> {
        if self.first.is_none() && matches!(self.length, Some(Ok(()))) {
            Some(&self.bytes)
        } else {
            None
        }
    }

    pub(super) fn metadata_v2(&self) -> Option<&rustix::fs::Stat> {
        self.metadata.as_ref()?.as_ref().ok()
    }

    pub(super) fn observe_once_v2(
        &mut self,
        descriptor: OwnedFd,
        name: &'static str,
        maximum: usize,
    ) -> std::result::Result<(), ReadinessWatermarkClosedV2> {
        self.observe_with_permissions_once_v2(
            descriptor,
            name,
            maximum,
            ReadPermissions::PrivateReadiness,
        )
    }

    /// Reads a fixed public package artifact under its immutable-file policy.
    ///
    /// Only fixed package-artifact callers select this policy. Private
    /// credentials and watermarks retain their separate permission checks.
    ///
    /// # Errors
    /// Refuses reentry, invalid root-owned metadata, writable or nonpublic
    /// modes, size violations, and incomplete or failed native reads.
    pub(super) fn observe_packaged_once_v2(
        &mut self,
        descriptor: OwnedFd,
        name: &'static str,
        maximum: usize,
    ) -> std::result::Result<(), ReadinessWatermarkClosedV2> {
        self.observe_with_permissions_once_v2(
            descriptor,
            name,
            maximum,
            ReadPermissions::PackagedPolicy,
        )
    }

    fn observe_with_permissions_once_v2(
        &mut self,
        descriptor: OwnedFd,
        name: &'static str,
        maximum: usize,
        permissions: ReadPermissions,
    ) -> std::result::Result<(), ReadinessWatermarkClosedV2> {
        if self.file.is_some() {
            // The private caller must fence its once slot before opening a
            // descriptor. An ownership-programming violation cannot drop
            // either the held original or a second supplied native prefix.
            std::process::abort();
        }
        self.file = Some(File::from(descriptor));
        self.metadata = Some(fstat(self.file.as_ref().ok_or(ReadinessWatermarkClosedV2)?));
        if !matches!(self.metadata, Some(Ok(_))) {
            self.first = Some(ReadFirst::Metadata);
            return Err(ReadinessWatermarkClosedV2);
        }
        self.policy = Some(validate_file_metadata_v2(
            self.metadata
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(ReadinessWatermarkClosedV2)?,
            name,
            maximum,
            permissions,
        ));
        let Some(Ok(declared)) = self.policy.as_ref() else {
            self.first = Some(ReadFirst::Policy);
            return Err(ReadinessWatermarkClosedV2);
        };
        let declared = *declared;
        self.bytes = Vec::with_capacity(declared);
        self.read = Some(
            self.file
                .as_mut()
                .ok_or(ReadinessWatermarkClosedV2)?
                .take((maximum + 1) as u64)
                .read_to_end(&mut self.bytes),
        );
        if !matches!(self.read, Some(Ok(_))) {
            self.first = Some(ReadFirst::Read);
            return Err(ReadinessWatermarkClosedV2);
        }
        self.length = Some(
            if self.bytes.len() != declared || self.bytes.len() > maximum {
                Err(HostError::State(format!(
                    "backend readiness {name} changed while being read"
                )))
            } else {
                Ok(())
            },
        );
        if !matches!(self.length, Some(Ok(()))) {
            self.first = Some(ReadFirst::Length);
            return Err(ReadinessWatermarkClosedV2);
        }
        Ok(())
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            ReadFirst::Metadata => error(&self.metadata),
            ReadFirst::Policy => error(&self.policy),
            ReadFirst::Read => error(&self.read),
            ReadFirst::Length => error(&self.length),
        }
    }
}

/// Retains the actual once-only read, transition and atomic replacement.
///
/// The genuine caller prepays this shape before entry and independently owes
/// its enclosing Host-control and clock posts. Empty construction grants nothing.
pub(in crate::plan) struct ReadinessWatermarkOriginalV2 {
    entered: bool,
    destination: Destination,
    proposed: Option<ReadinessWatermark>,
    directory: Option<std::result::Result<OwnedFd, rustix::io::Errno>>,
    directory_metadata: Option<std::result::Result<rustix::fs::Stat, rustix::io::Errno>>,
    directory_policy: Option<Result<()>>,
    current_open: Option<std::result::Result<(), rustix::io::Errno>>,
    read: ProtectedReadOriginalV2,
    current: Option<std::result::Result<Option<ReadinessWatermark>, serde_json::Error>>,
    transition: Option<Result<()>>,
    encoded: Option<std::result::Result<Vec<u8>, serde_json::Error>>,
    atomic: ReadinessAtomicWriteOriginalV2,
    atomic_result: Option<
        std::result::Result<(), aos_sandbox_linux::protected_file::ReadinessAtomicWriteClosedV2>,
    >,
    first: Option<First>,
    closed: ReadinessWatermarkClosedV2,
}

impl ReadinessWatermarkOriginalV2 {
    /// Creates empty inline custody without allocation or IO.
    pub(in crate::plan) fn new() -> Self {
        Self {
            entered: false,
            destination: Destination::Retained,
            proposed: None,
            directory: None,
            directory_metadata: None,
            directory_policy: None,
            current_open: None,
            read: Default::default(),
            current: None,
            transition: None,
            encoded: None,
            atomic: ReadinessAtomicWriteOriginalV2::new(),
            atomic_result: None,
            first: None,
            closed: ReadinessWatermarkClosedV2,
        }
    }

    /// Quotes the concrete bounded read, typed JSON and atomic-write roster.
    pub(in crate::plan) fn receiving_demand_v2(actual_path_bound: usize) -> Option<ResourceVector> {
        let encoded = maximum_encoded_watermark_bytes_v2()?;
        let read_shape = ProtectedReadOriginalV2::receiving_demand_v2(
            MAXIMUM_WATERMARK_BYTES,
            READINESS_WATERMARK_FILE.len(),
        )?;
        let json_scratch = MAXIMUM_WATERMARK_BYTES.checked_mul(3)?;
        // The typed schema and a refused field/error token can coexist with
        // parser scratch. No generic JSON Value graph is decoded.
        let error_context = b"unknown field ``, expected one of `schema`, `publisher_generation`, `boot_id`, `artifact_sha256` at line  column invalid type: string, expected an array of length 32".len()
            .checked_add(40)?;
        // ErrorImpl owns Code::Message(Box<str>) plus line/column; the Code
        // tag occupies a further word. Formatting and into_boxed_str can hold
        // old/new backing beside the already decoded schema.
        let error_header = size_of::<(Box<str>, usize, usize)>().checked_add(size_of::<usize>())?;
        let message = MAXIMUM_WATERMARK_BYTES
            .checked_add(error_context)?
            .checked_mul(3)?;
        let schema_and_error = MAXIMUM_WATERMARK_BYTES
            .checked_add(message)?
            .checked_add(error_header)?;
        // serde_json::to_vec's initial Vec is 128 bytes, then grows geometrically.
        let encode_backing = encoded.max(128).checked_mul(3)?;
        let atomic = ReadinessAtomicWriteOriginalV2::receiving_shape_v2(
            ReadinessAtomicWritePurposeV2::Watermark,
            encoded,
        )?;
        let path = actual_path_bound
            .checked_add(1)?
            .checked_add(READINESS_WATERMARK_FILE.len() + 1)?;
        // The lower header is physically nested in Self: count it once, then
        // add the exact lower native-name backing and write/storage traffic.
        let memory = size_of::<Self>()
            .checked_sub(size_of::<ReadinessAtomicWriteOriginalV2>())?
            .checked_sub(size_of::<ProtectedReadOriginalV2>())?
            .checked_add(atomic.memory_bytes)?
            .checked_add(usize::try_from(read_shape.get(D::MemoryBytes)).ok()?)?
            .checked_add(json_scratch)?
            .checked_add(schema_and_error)?
            .checked_add(encode_backing)?
            .checked_add(path)?
            .checked_add(READINESS_WATERMARK_SCHEMA.len())?;
        Some(
            ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(memory).ok()?)
                .with(
                    D::OpenFiles,
                    1u64.checked_add(read_shape.get(D::OpenFiles))?
                        .checked_add(u64::try_from(atomic.open_files).ok()?)?,
                )
                // One directory plus the shared actual current/temp names.
                .with(
                    D::MetadataEntries,
                    u64::try_from(1usize.checked_add(atomic.namespace_entries)?).ok()?,
                )
                .with(
                    D::StorageBytes,
                    u64::try_from(MAXIMUM_WATERMARK_BYTES.checked_add(atomic.storage_bytes)?)
                        .ok()?,
                )
                .with(
                    D::OutputBytes,
                    read_shape
                        .get(D::OutputBytes)
                        .checked_add(u64::try_from(atomic.output_bytes).ok()?)?,
                ),
        )
    }

    /// Runs the existing protected watermark sequence once, retaining refusal.
    ///
    /// The existing failure-only cleanup remains independently attempted after
    /// an entered write/sync/rename/directory-sync failure. Its error is kept
    /// without replacing the primary cause; outer native posts remain owed.
    pub(super) fn persist_once_v2(
        &mut self,
        directory_path: &Path,
        proposed: ReadinessWatermark,
    ) -> std::result::Result<(), ReadinessWatermarkClosedV2> {
        if self.entered {
            self.first.get_or_insert(First::Reentry);
            return Err(ReadinessWatermarkClosedV2);
        }
        self.entered = true;
        self.proposed = Some(proposed);
        self.directory = Some(open(
            directory_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ));
        if !matches!(self.directory, Some(Ok(_))) {
            self.first = Some(First::Directory);
            return Err(ReadinessWatermarkClosedV2);
        }
        let directory = self
            .directory
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(ReadinessWatermarkClosedV2)?;
        self.directory_metadata = Some(fstat(directory));
        if !matches!(self.directory_metadata, Some(Ok(_))) {
            self.first = Some(First::DirectoryMetadata);
            return Err(ReadinessWatermarkClosedV2);
        }
        self.directory_policy = Some(validate_directory_metadata_v2(
            self.directory_metadata
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(ReadinessWatermarkClosedV2)?,
            "state directory",
        ));
        if !matches!(self.directory_policy, Some(Ok(()))) {
            self.first = Some(First::DirectoryPolicy);
            return Err(ReadinessWatermarkClosedV2);
        }
        match openat(
            directory,
            READINESS_WATERMARK_FILE,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(descriptor) => {
                self.current_open = Some(Ok(()));
                if self
                    .read
                    .observe_once_v2(
                        descriptor,
                        READINESS_WATERMARK_FILE,
                        MAXIMUM_WATERMARK_BYTES,
                    )
                    .is_err()
                {
                    self.first = Some(First::Read);
                    return Err(ReadinessWatermarkClosedV2);
                }
                if matches!(self.destination, Destination::Ordinary) {
                    // The old ordinary reader closes its file before parsing;
                    // only the paid retaining path keeps the third live OFD.
                    drop(self.read.file.take());
                }
                self.current =
                    Some(serde_json::from_slice::<ReadinessWatermark>(&self.read.bytes).map(Some));
            }
            Err(rustix::io::Errno::NOENT) => {
                self.current_open = Some(Err(rustix::io::Errno::NOENT));
                self.current = Some(Ok(None));
            }
            Err(cause) => {
                self.current_open = Some(Err(cause));
                self.first = Some(First::CurrentOpen);
                return Err(ReadinessWatermarkClosedV2);
            }
        }
        if matches!(self.destination, Destination::Ordinary) {
            // The original scoped current-file read drops its pure bytes after
            // parsing. The retained path keeps them through all outer posts.
            drop(std::mem::take(&mut self.read.bytes));
        }
        let Some(Ok(current)) = self.current.as_ref() else {
            self.first = Some(First::Decode);
            return Err(ReadinessWatermarkClosedV2);
        };
        let proposed = self.proposed.as_ref().ok_or(ReadinessWatermarkClosedV2)?;
        self.transition = Some(validate_watermark_transition(current.as_ref(), proposed));
        if !matches!(self.transition, Some(Ok(()))) {
            self.first = Some(First::Transition);
            return Err(ReadinessWatermarkClosedV2);
        }
        if current.as_ref() == Some(proposed) {
            return Ok(());
        }
        self.encoded = Some(serde_json::to_vec(proposed));
        let Some(Ok(bytes)) = self.encoded.as_ref() else {
            self.first = Some(First::Encode);
            return Err(ReadinessWatermarkClosedV2);
        };
        self.atomic_result = Some(self.atomic.replace_once_v2(
            directory.as_fd(),
            ReadinessAtomicWritePurposeV2::Watermark,
            bytes,
        ));
        if !matches!(self.atomic_result, Some(Ok(()))) {
            self.first = Some(First::Atomic);
            return Err(ReadinessWatermarkClosedV2);
        }
        Ok(())
    }

    /// Borrows the actual first cause without rereading or retrying.
    pub(in crate::plan) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Reentry => Some(&self.closed),
            First::Directory => error(&self.directory),
            First::DirectoryMetadata => error(&self.directory_metadata),
            First::DirectoryPolicy => error(&self.directory_policy),
            First::CurrentOpen => error(&self.current_open),
            First::Read => self.read.failure(),
            First::Decode => error(&self.current),
            First::Transition => error(&self.transition),
            First::Encode => error(&self.encoded),
            First::Atomic => self.atomic.failure().or_else(|| error(&self.atomic_result)),
        }
    }

    pub(super) fn persist_ordinary_once_v2(
        &mut self,
        directory: &Path,
        proposed: ReadinessWatermark,
    ) -> Result<()> {
        self.destination = Destination::Ordinary;
        self.persist_once_v2(directory, proposed)
            .map_err(|_| self.ordinary_error_v2())
    }

    fn ordinary_error_v2(&self) -> HostError {
        match self.first {
            Some(First::Decode) => {
                HostError::State("backend readiness watermark is malformed".to_owned())
            }
            Some(First::Encode) => {
                HostError::State("backend readiness watermark cannot encode".to_owned())
            }
            _ => ordinary_error_v2(self.failure()),
        }
    }
}

fn error<T, E: Error + 'static>(
    slot: &Option<std::result::Result<T, E>>,
) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

fn ordinary_error_v2(cause: Option<&(dyn Error + 'static)>) -> HostError {
    // Policy errors already carry the old State payload. Avoid displaying that
    // HostError into another State and duplicating its display prefix.
    if let Some(HostError::State(message)) =
        cause.and_then(|cause| cause.downcast_ref::<HostError>())
    {
        return HostError::State(message.clone());
    }
    HostError::State(
        cause
            .map(ToString::to_string)
            .unwrap_or_else(|| ReadinessWatermarkClosedV2.to_string()),
    )
}

pub(super) fn read_protected_descriptor_ordinary_v2(
    descriptor: OwnedFd,
    name: &'static str,
    maximum: usize,
) -> Result<Vec<u8>> {
    let mut original = ProtectedReadOriginalV2::default();
    original
        .observe_once_v2(descriptor, name, maximum)
        .map_err(|_| ordinary_error_v2(original.failure()))?;
    Ok(std::mem::take(&mut original.bytes))
}

pub(super) fn validate_directory_metadata_v2(
    metadata: &rustix::fs::Stat,
    label: &str,
) -> Result<()> {
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != 0
        || !protected_directory_permissions(metadata.st_mode)
    {
        return Err(HostError::State(format!(
            "backend readiness {label} is not a protected root-owned directory"
        )));
    }
    Ok(())
}

fn validate_file_metadata_v2(
    metadata: &rustix::fs::Stat,
    name: &'static str,
    maximum: usize,
    permissions: ReadPermissions,
) -> Result<usize> {
    let protected_mode = match permissions {
        ReadPermissions::PrivateReadiness => protected_file_permissions(metadata.st_mode),
        ReadPermissions::PackagedPolicy => metadata.st_mode & 0o7777 == 0o444,
    };
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != 0
        || metadata.st_nlink != 1
        || !protected_mode
    {
        return Err(HostError::State(format!(
            "backend readiness {name} is not a protected root-owned file"
        )));
    }
    let declared = usize::try_from(metadata.st_size)
        .map_err(|_| HostError::State(format!("backend readiness {name} is oversized")))?;
    if declared == 0 || declared > maximum {
        return Err(HostError::State(format!(
            "backend readiness {name} has an invalid size"
        )));
    }
    Ok(declared)
}

// Exact serde field order, fixed ASCII schema and decimal u64/u8 maxima.
fn maximum_encoded_watermark_bytes_v2() -> Option<usize> {
    b"{\"schema\":\"\",\"publisher_generation\":,\"boot_id\":[],\"artifact_sha256\":[]}"
        .len()
        .checked_add(READINESS_WATERMARK_SCHEMA.len())?
        .checked_add(20)?
        .checked_add(16 * 3 + 15)?
        .checked_add(32 * 3 + 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(mode: u32) -> rustix::fs::Stat {
        let file = tempfile::tempfile().unwrap();
        let mut metadata = fstat(&file).unwrap();
        metadata.st_uid = 0;
        metadata.st_nlink = 1;
        metadata.st_mode = (metadata.st_mode & !0o7777) | mode;
        metadata.st_size = 269;
        metadata
    }

    #[test]
    fn public_package_modes_do_not_admit_public_readiness_credentials() {
        for mode in [0o400, 0o600, 0o444, 0o644, 0o666] {
            let metadata = metadata(mode);
            let private = validate_file_metadata_v2(
                &metadata,
                "credential",
                269,
                ReadPermissions::PrivateReadiness,
            );
            let packaged = validate_file_metadata_v2(
                &metadata,
                "package",
                269,
                ReadPermissions::PackagedPolicy,
            );

            assert_eq!(
                private.is_ok(),
                matches!(mode, 0o400 | 0o600),
                "private mode {mode:o}"
            );
            assert_eq!(packaged.is_ok(), mode == 0o444, "package mode {mode:o}");
        }
    }

    #[test]
    fn packaged_metadata_rejects_writes_links_foreign_owners_and_invalid_sizes() {
        for (mode, uid, links, size) in [
            (0o444, 1000, 1, 269),
            (0o444, 0, 2, 269),
            (0o464, 0, 1, 269),
            (0o644, 0, 1, 269),
            (0o555, 0, 1, 269),
            (0o444, 0, 1, 0),
            (0o444, 0, 1, 270),
        ] {
            let mut changed = metadata(mode);
            changed.st_uid = uid;
            changed.st_nlink = links;
            changed.st_size = size;

            assert!(
                validate_file_metadata_v2(
                    &changed,
                    "package",
                    269,
                    ReadPermissions::PackagedPolicy,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn canonical_bound_and_native_names_have_no_field_fee() {
        let proposed = ReadinessWatermark {
            schema: READINESS_WATERMARK_SCHEMA.to_owned(),
            publisher_generation: u64::MAX,
            boot_id: [u8::MAX; 16],
            artifact_sha256: [u8::MAX; 32],
        };
        assert_eq!(
            serde_json::to_vec(&proposed).unwrap().len(),
            maximum_encoded_watermark_bytes_v2().unwrap()
        );
        let small = ReadinessWatermarkOriginalV2::receiving_demand_v2(32).unwrap();
        let large = ReadinessWatermarkOriginalV2::receiving_demand_v2(64).unwrap();
        assert_eq!(small.get(D::MetadataEntries), 3);
        assert_eq!(small.get(D::OpenFiles), 3);
        assert_eq!(large.get(D::MemoryBytes) - small.get(D::MemoryBytes), 32);
    }
}
