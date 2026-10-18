//! Admits each selected complete-archive creation phase before owning copies.
//!
//! The legacy loader keeps its original policy. This route reads the same local
//! signed index-three format, while file growth, DOMs, direct typed envelopes,
//! MAC canonicalization and manifest creation receive checked allocation credit.
//! Its private receipt records accounting provenance, never native/source rights.

use std::thread::{self, ThreadId};

use super::*;
use crate::node_contract::{NodeRuntime, RuntimeError};
use crate::node_state::native::{core_decode_credit, typed_index};

#[derive(Clone)]
pub(super) struct CompleteLoadAdmission {
    process: u32,
    thread: ThreadId,
    index: usize,
    directory: usize,
    maximum: usize,
}

impl CompleteLoadAdmission {
    /// Borrows historical local receipt facts; actual pointer roles stay separate.
    ///
    /// The owning archive verifies its real index/directory correspondence before
    /// and after serialization. This DATA cannot recreate a load admission.
    pub(super) fn borrowed_settled_history_data(&self) -> impl serde::Serialize + '_ {
        let Self {
            process,
            thread: _,
            index: _,
            directory: _,
            maximum,
        } = self;
        (
            process,
            "original-creator-thread-not-portable",
            maximum,
            "same-archive-index",
            "same-archive-directory",
        )
    }
}

pub(in crate::node_state::native) fn add(a: usize, b: usize) -> Result<usize, StateError> {
    a.checked_add(b)
        .ok_or_else(|| limit("complete loader allocation overflow"))
}

pub(in crate::node_state::native) fn admit(
    retained: usize,
    temporary: usize,
    maximum: usize,
) -> Result<(), StateError> {
    if add(retained, temporary)? > maximum {
        return Err(limit("complete loader named allocation peak"));
    }
    Ok(())
}

// Names are a validated 64-hex digest plus one fixed suffix. The same bound
// covers the sequential index/object name and cumulative String growth.
pub(in crate::node_state::native) fn fixed_storage() -> usize {
    std::mem::size_of::<NativeArchiveRecord>()
        + std::mem::size_of::<ArchiveMac>()
        + NodeRuntime::capture_shared_allocation_storage::<File>()
        + 4 * (64 + ".native-object-v1".len())
        + 8
        + core_decode_credit::scanner_storage()
        + std::mem::size_of::<std::fs::Metadata>()
        + std::mem::size_of::<File>()
        + 1 // Fixed changed-file sentinel; no reader growth bank.
        + 20 // Closed U64/I64 decimal formatter bank before visitor entry.
}

/// Reads only an admitted observed extent, including one changed-file byte.
pub(in crate::node_state::native) fn read_admitted(
    record_directory: &File,
    name: &str,
    maximum_record: usize,
    expected: Option<usize>,
    retained: usize,
    maximum_total: usize,
) -> Result<Vec<u8>, StateError> {
    // A digest-named FIFO must reach the regular-file check without waiting for
    // a writer. O_NONBLOCK leaves regular-file reads unchanged.
    let mut file = File::from(
        rustix::fs::openat(
            record_directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(storage_error)?,
    );
    let metadata = file.metadata().map_err(storage_error)?;
    let length = usize::try_from(metadata.len()).map_err(|_| limit("complete file extent"))?;
    let maximum = expected.map_or(maximum_record, |known| known.min(maximum_record));
    if !metadata.is_file() || length > maximum {
        return Err(limit("complete file extent"));
    }
    // Resize only within the admitted exact bank. A one-byte stack sentinel
    // detects later growth without read_to_end's probe/reallocation path.
    admit(retained, length, maximum_total)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| limit("complete file reserve"))?;
    admit(retained, bytes.capacity(), maximum_total)?;
    bytes.resize(length, 0);
    if let Err(error) = file.read_exact(&mut bytes) {
        return if error.kind() == std::io::ErrorKind::UnexpectedEof {
            Err(refused("complete indexed file changed while reading"))
        } else {
            Err(storage_error(error))
        };
    }
    let mut sentinel = [0u8; 1];
    if file.read(&mut sentinel).map_err(storage_error)? != 0 {
        return Err(refused("complete indexed file changed while reading"));
    }
    Ok(bytes)
}

/// Charges fixed closed shape before either strict DOM or typed decode exists.
pub(in crate::node_state::native) fn admit_decode(
    bytes: &Vec<u8>,
    retained: usize,
    maximum: usize,
) -> Result<core_decode_credit::DecodeCredit, StateError> {
    admit(add(retained, bytes.capacity())?, fixed_storage(), maximum)?;
    let credit = core_decode_credit::preflight_archive(bytes, maximum).map_err(schema)?;
    let requested = credit.total().map_err(schema)?;
    admit(
        add(add(retained, bytes.capacity())?, fixed_storage())?,
        requested,
        maximum,
    )?;
    Ok(credit)
}

impl NativeArchive {
    /// Loads complete index three under admitted file and decoder storage.
    ///
    /// This authenticates local signed metadata and its unchanged manifest;
    /// source-specific snapshot/journal validation and fresh adoption remain
    /// mandatory. The earlier loader does not issue this allocation receipt.
    ///
    /// # Errors
    /// Refuses another edition, malformed/corrupt files or metadata, failed MAC,
    /// changed source identity, missing administrative closure or finite excess.
    pub fn load_complete_original(
        &self,
        artifact: &ContentRef,
    ) -> Result<NativeArchiveRecord, StateError> {
        let maximum = self.limits.state.maximum_total_content_bytes;
        // The borrowed requested reference also survives every loader phase.
        // Its actual spare string capacity is independent of the decoded copy.
        let requested_reference =
            NodeRuntime::capture_reference_storage(artifact).map_err(schema)?;
        let fixed = add(fixed_storage(), requested_reference)?;
        admit(0, fixed, maximum)?;
        artifact.validate().map_err(schema)?;
        let bytes = read_admitted(
            &self.directory,
            &index_name(artifact),
            self.limits.state.maximum_record_bytes,
            None,
            fixed,
            maximum,
        )?;
        let decode_storage = admit_decode(&bytes, fixed, maximum)?;
        let value = canonical::parse_json(&bytes, self.limits.state.maximum_record_bytes)
            .map_err(schema)?;
        let (index, authentication) = typed_index::decode_complete_envelope(value)?;
        // The direct decoder excludes serde's untagged legacy retry trees.
        let owned_index = index_owned_storage(&index).map_err(schema)?;
        let serialization =
            NodeRuntime::capture_serialization_storage(&index, maximum).map_err(schema)?;
        let retained = add(fixed, add(bytes.capacity(), owned_index)?)?;
        admit(
            retained,
            add(decode_storage.total().map_err(schema)?, serialization)?,
            maximum,
        )?;
        let body = canonical::canonical_json(&serde_json::to_value(&index).map_err(schema)?)
            .map_err(schema)?;
        let mut mac = self.mac(3)?;
        mac.update(&body);
        mac.verify_slice(&authentication)
            .map_err(|_| refused("complete archive authentication failed"))?;
        if &index.artifact != artifact {
            return Err(refused("complete archive names another source artifact"));
        }
        drop(body);
        drop(bytes);
        // Inventory validation builds independently owned sets before manifest IO.
        let validation = index_validation_storage(&index).map_err(schema)?;
        admit(add(fixed, owned_index)?, validation, maximum)?;
        validate_index(&index, self.limits)?;
        let manifest_bytes = read_admitted(
            &self.directory,
            &object_name(&index.artifact),
            self.limits.state.maximum_record_bytes,
            Some(usize::try_from(index.artifact.length.get()).map_err(schema)?),
            add(fixed, owned_index)?,
            maximum,
        )?;
        let manifest_credit = admit_decode(&manifest_bytes, add(fixed, owned_index)?, maximum)?;
        index.artifact.verify(&manifest_bytes).map_err(schema)?;
        // The decode pass retains DOM plus typed containers. Validation creates
        // sorted-key clones; reserve a separate typed-container bank before it.
        // Canonical scratch is already a separately named part of DecodeCredit.
        admit(
            add(add(fixed, owned_index)?, manifest_bytes.capacity())?,
            add(
                manifest_credit.total().map_err(schema)?,
                manifest_credit.typed_containers,
            )?,
            maximum,
        )?;
        let manifest: CaptureManifest =
            canonical::decode(&manifest_bytes, self.limits.state.maximum_record_bytes)
                .map_err(schema)?;
        drop(manifest_bytes);
        let mut record = NativeArchiveRecord {
            complete_load: None,
            index: Arc::new(index),
            manifest,
            directory: Arc::clone(&self.directory),
            limits: self.limits,
        };
        super::super::complete_original_index::authenticate_admitted(
            &record,
            requested_reference,
            maximum,
        )?;
        record.collecting_complete_capture_provenance_admitted(requested_reference, maximum)?;
        let owned = record.capture_owned_storage().map_err(schema)?;
        admit(owned, fixed, maximum)?;
        record.complete_load = Some(CompleteLoadAdmission {
            process: std::process::id(),
            thread: thread::current().id(),
            index: Arc::as_ptr(&record.index) as usize,
            directory: Arc::as_ptr(&record.directory) as usize,
            maximum,
        });
        Ok(record)
    }
}

impl NativeArchiveRecord {
    pub(in crate::node_state::native) fn complete_load_is_selected(&self) -> bool {
        self.complete_load.is_some()
    }

    pub(in crate::node_state::native) fn read_complete_object_admitted(
        &self,
        reference: &ContentRef,
        extra_retained: usize,
        maximum: usize,
    ) -> Result<Vec<u8>, StateError> {
        if !self
            .index
            .objects
            .iter()
            .any(|object| &object.reference == reference)
        {
            return Err(refused("complete object is outside signed typed inventory"));
        }
        let retained = add(
            self.capture_owned_storage().map_err(schema)?,
            extra_retained,
        )?;
        admit(retained, fixed_storage(), maximum)?;
        let bytes = read_admitted(
            &self.directory,
            &object_name(reference),
            self.limits.state.maximum_record_bytes,
            Some(usize::try_from(reference.length.get()).map_err(schema)?),
            add(retained, fixed_storage())?,
            maximum,
        )?;
        reference.verify(&bytes).map_err(schema)?;
        Ok(bytes)
    }

    /// Identifies the full authenticated index-three body independently of its manifest.
    ///
    /// This identity covers owner keys, typed dependency edges and administrative
    /// roots. It describes preservation data and grants no restore or execution
    /// permission. The caller includes its other retained allocations in the
    /// finite archive budget before the temporary canonical representation exists.
    ///
    /// # Errors
    /// Refuses absent or foreign complete-load admission, another index edition,
    /// an oversized index, allocation failure or exhausted aggregate storage.
    pub fn complete_original_index_identity(
        &self,
        maximum_record_bytes: usize,
        additional_retained_bytes: usize,
    ) -> Result<ContentRef, StateError> {
        self.authenticate_complete_load_admission()
            .map_err(schema)?;

        let reference = super::complete_original_validation_origin::index_identity_data(
            self,
            maximum_record_bytes,
            additional_retained_bytes,
        )?;
        self.authenticate_complete_load_admission()
            .map_err(schema)?;
        Ok(reference)
    }

    pub(crate) fn authenticate_complete_load_admission(&self) -> Result<(), RuntimeError> {
        let original = self
            .complete_load
            .as_ref()
            .ok_or(RuntimeError::UnsupportedFacet)?;
        if original.process != std::process::id()
            || original.thread != thread::current().id()
            || original.index != Arc::as_ptr(&self.index) as usize
            || original.directory != Arc::as_ptr(&self.directory) as usize
            || original.maximum != self.limits.state.maximum_total_content_bytes
            || self.index.schema_version != 3
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}

fn index_validation_storage(index: &Index) -> Result<usize, RuntimeError> {
    let entries = index
        .objects
        .len()
        .checked_add(1)
        .ok_or(RuntimeError::ResourceLimit)?;
    let mut bytes = entries
        .checked_mul(
            NodeRuntime::capture_map_node_storage::<ContentRef, ()>()
                + NodeRuntime::capture_map_node_storage::<
                    crucible_node_contract::HashRef,
                    ContentRef,
                >(),
        )
        .ok_or(RuntimeError::ResourceLimit)?;
    for object in &index.objects {
        bytes = bytes
            .checked_add(NodeRuntime::capture_reference_storage(&object.reference)?)
            .and_then(|bytes| {
                bytes.checked_add(NodeRuntime::capture_reference_storage(&object.reference).ok()?)
            })
            .and_then(|bytes| bytes.checked_add(object.reference.hash.algorithm.len()))
            .and_then(|bytes| bytes.checked_add(object.reference.hash.domain.len()))
            .and_then(|bytes| bytes.checked_add(object.reference.hash.digest.len()))
            .ok_or(RuntimeError::ResourceLimit)?;
    }
    for owner in &index.owners {
        bytes = bytes
            .checked_add(NodeRuntime::capture_map_node_storage::<Id, ()>())
            .and_then(|bytes| bytes.checked_add(owner.owner.as_str().len()))
            .and_then(|bytes| bytes.checked_add(NodeRuntime::capture_map_node_storage::<&Id, ()>()))
            .ok_or(RuntimeError::ResourceLimit)?;
    }
    Ok(bytes)
}

#[cfg(test)]
#[path = "complete_original_loader_tests.rs"]
pub(in crate::node_state::native) mod tests;
