//! Reads original measured readonly file revisions without rerunning callbacks.
//!
//! Actual full source/ELF bytes are streamed at issuance. The original file
//! descriptors and complete Linux identity/revision facts then remain owned.
//! A current read verifies original kernel read leases and namespace fences;
//! unsupported leases retain complete bounded byte reads. Repeated aliases share
//! only a completed full-byte measurement within the same current read.
//! Each lease precedes
//! the initial complete measurement and is never reacquired or renewed. A pending
//! break or observed drift permanently revokes this original revision, even if
//! bytes are subsequently restored. This is installed source liveness, not an
//! accepted class or adversarial root protection.

mod retained;

use std::{
    cell::Cell,
    fs::{File, Metadata},
    os::unix::fs::{FileExt, MetadataExt},
    path::{Path, PathBuf},
    sync::Arc,
};

use crucible_host_resources::{LinuxReadLeaseFile, LinuxReadLeaseOwner};

use super::{PacketFixtureMeasurements, measurement, refused};
use crate::node_qualification::QualificationError;

#[derive(PartialEq, Eq)]
struct Facts {
    device: u64,
    inode: u64,
    bytes: u64,
    uid: u32,
    mode: u32,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl From<&Metadata> for Facts {
    fn from(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            bytes: metadata.len(),
            uid: metadata.uid(),
            mode: metadata.mode(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

struct Original {
    path: PathBuf,
    file: LinuxReadLeaseFile,
    facts: Facts,
    content: crucible_node_format::ContentRef,
}

pub(in super::super) struct CurrentFiles {
    originals: Vec<Original>,
    process: u32,
    revoked: Cell<bool>,
}

impl CurrentFiles {
    pub(in super::super) fn install(
        selected: &PacketFixtureMeasurements,
    ) -> Result<Self, QualificationError> {
        // Complete roster and serialized ownership are checked before paths,
        // files or vector slots are copied. Issuance hashes the retained fd itself.
        selected.authenticate()?;
        // Unsupported worker/kernel/filesystem support retains full-byte reads.
        // A successfully acquired lease can never fall back after its break.
        let owner = LinuxReadLeaseOwner::new().ok().map(Arc::new);
        let mut originals = Vec::new();
        originals.try_reserve_exact(10).map_err(|_| refused())?;
        originals.push(original(
            &selected.peer.path,
            &selected.peer.content,
            owner.as_ref(),
        )?);
        originals.push(original(
            Path::new("/proc/self/exe"),
            &selected.host,
            owner.as_ref(),
        )?);
        for source in &selected.sources {
            originals.push(original(&source.path, &source.content, owner.as_ref())?);
        }
        let installed = Self {
            originals,
            process: std::process::id(),
            revoked: Cell::new(false),
        };
        installed.current()?;
        Ok(installed)
    }

    /// Selects terminal complete-byte validation before any lease acquisition.
    ///
    /// The complete profile owns no notification worker. Every current read
    /// still hashes every distinct original revision and full content pin, and
    /// checks each original path/process/metadata before and after; observed
    /// drift remains sticky.
    /// This never downgrades an acquired token or attempts lease acquisition.
    pub(in super::super) fn install_complete_bytes(
        selected: &PacketFixtureMeasurements,
    ) -> Result<Self, QualificationError> {
        selected.authenticate()?;
        let files = [
            (selected.peer.path.as_path(), &selected.peer.content),
            (Path::new("/proc/self/exe"), &selected.host),
            (
                selected.sources[0].path.as_path(),
                &selected.sources[0].content,
            ),
            (
                selected.sources[1].path.as_path(),
                &selected.sources[1].content,
            ),
            (
                selected.sources[2].path.as_path(),
                &selected.sources[2].content,
            ),
            (
                selected.sources[3].path.as_path(),
                &selected.sources[3].content,
            ),
            (
                selected.sources[4].path.as_path(),
                &selected.sources[4].content,
            ),
            (
                selected.sources[5].path.as_path(),
                &selected.sources[5].content,
            ),
            (
                selected.sources[6].path.as_path(),
                &selected.sources[6].content,
            ),
            (
                selected.sources[7].path.as_path(),
                &selected.sources[7].content,
            ),
        ];
        complete_byte_originals(&files)
    }

    /// Reads only the original measured peer under the caller's finite fetch credit.
    pub(in super::super) fn peer_content(
        &self,
        expected: &crucible_node_format::ContentRef,
        maximum: usize,
    ) -> Result<Vec<u8>, QualificationError> {
        self.current()?;
        let peer = self.originals.first().ok_or_else(refused)?;
        let extent = usize::try_from(peer.facts.bytes).map_err(|_| refused())?;
        if extent == 0
            || extent > maximum
            || extent > 512 * 1024 * 1024
            || expected.length.get() != peer.facts.bytes
        {
            return Err(refused());
        }
        // Positional reads do not move the independently retained fd cursor.
        // Complete caller credit precedes allocation; no callback follows the
        // final same-path/fd/process check before returning original bytes.
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(extent).map_err(|_| refused())?;
        bytes.resize(extent, 0);
        peer.file
            .file()
            .read_exact_at(&mut bytes, 0)
            .map_err(measurement::io)?;
        expected.verify(&bytes)?;
        self.current()?;
        Ok(bytes)
    }

    /// Reads only the original measured host executable under the caller's finite fetch credit.
    pub(in super::super) fn host_content(
        &self,
        expected: &crucible_node_format::ContentRef,
        maximum: usize,
    ) -> Result<Vec<u8>, QualificationError> {
        self.current()?;
        let host = self.originals.get(1).ok_or_else(refused)?;
        let extent = usize::try_from(host.facts.bytes).map_err(|_| refused())?;
        if extent == 0
            || extent > maximum
            || extent > 512 * 1024 * 1024
            || expected != &host.content
            || expected.length.get() != host.facts.bytes
        {
            return Err(refused());
        }
        // Positional reads do not move the independently retained fd cursor.
        // Complete caller credit precedes allocation; no callback follows the
        // final same-path/fd/process check before returning original bytes.
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(extent).map_err(|_| refused())?;
        bytes.resize(extent, 0);
        host.file
            .file()
            .read_exact_at(&mut bytes, 0)
            .map_err(measurement::io)?;
        expected.verify(&bytes)?;
        self.current()?;
        Ok(bytes)
    }

    /// Reads a named original measured source file through its retained descriptor.
    pub(in super::super) fn source_content(
        &self,
        expected: &crucible_node_format::ContentRef,
        maximum: usize,
    ) -> Result<Vec<u8>, QualificationError> {
        self.current()?;
        let source = self
            .originals
            .iter()
            .skip(2)
            .find(|original| &original.content == expected)
            .ok_or_else(refused)?;
        let extent = usize::try_from(source.facts.bytes).map_err(|_| refused())?;
        if extent == 0 || extent > maximum || extent > 512 * 1024 * 1024 {
            return Err(refused());
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(extent).map_err(|_| refused())?;
        bytes.resize(extent, 0);
        source
            .file
            .file()
            .read_exact_at(&mut bytes, 0)
            .map_err(measurement::io)?;
        expected.verify(&bytes)?;
        self.current()?;
        Ok(bytes)
    }

    pub(in super::super) fn current(&self) -> Result<(), QualificationError> {
        if self.revoked.get() {
            return Err(refused());
        }
        let result = self.read_current().map(|_| ());
        if result.is_err() {
            self.revoked.set(true);
        }
        result
    }

    // The count reports actual full descriptor measurements in this pass.
    // No successful result or deduplication state survives the call.
    fn read_current(&self) -> Result<u32, QualificationError> {
        self.read_current_data::<QualificationError>()
    }

    /// Quotes the complete selected read, including path conversion and results.
    ///
    /// Only never-leased complete-byte originals have a closed native startup
    /// profile. The quote follows original owned paths/pins without kernel work.
    ///
    /// # Errors
    /// Refuses foreign/revoked originals, acquired leases or arithmetic overflow.
    pub(in super::super) fn original_native_startup_currentness_storage_data(
        &self,
    ) -> Result<usize, crucible_engine::node_contract::RuntimeError> {
        use crucible_engine::node_contract::RuntimeError;
        use std::mem::size_of;
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.revoked.get() || self.originals.len() != 10 {
            return Err(RuntimeError::OwnerUnavailable);
        }
        if self
            .originals
            .iter()
            .any(|original| original.file.lease().is_some())
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let mut maximum_path = 0usize;
        let mut maximum_media = 0usize;
        for original in &self.originals {
            maximum_path = maximum_path.max(original.path.as_os_str().as_encoded_bytes().len());
            maximum_media = maximum_media.max(original.content.media_type.capacity());
        }
        // File metadata path conversion uses either std's fixed 384-byte bank
        // or one owned NUL-terminated path. Sum both, conservatively.
        let dynamic = maximum_path
            .checked_add(1)
            .and_then(|bytes| bytes.checked_add(maximum_media))
            .and_then(|bytes| bytes.checked_add(9 + 11 + 64))
            .ok_or(RuntimeError::ResourceLimit)?;
        [
            PacketFixtureMeasurements::streaming_scratch_bytes(),
            size_of::<u16>(),
            size_of::<[Facts; 4]>(),
            size_of::<[Metadata; 5]>(),
            size_of::<blake3::Hasher>(),
            size_of::<blake3::Hash>(),
            std::mem::size_of_val(&blake3::Hash::from([0; 32]).to_hex()),
            size_of::<crucible_node_format::ContentRef>(),
            size_of::<(&File, u64)>(),
            size_of::<[u64; 4]>(),
            size_of::<[usize; 4]>(),
            384,
            dynamic,
        ]
        .into_iter()
        .try_fold(0usize, |sum, bytes| {
            sum.checked_add(bytes).ok_or(RuntimeError::ResourceLimit)
        })
    }

    /// Runs the unchanged complete descriptor/path pass with raw failure status.
    ///
    /// # Errors
    /// Refuses inadequate credit or any original namespace, bytes or revision
    /// drift. Observed file failures revoke the same original owner permanently.
    pub(in super::super) fn authenticate_original_native_startup_currentness(
        &self,
        maximum: usize,
    ) -> Result<(), crucible_engine::node_contract::RuntimeError> {
        if self.original_native_startup_currentness_storage_data()? > maximum {
            return Err(crucible_engine::node_contract::RuntimeError::ResourceLimit);
        }
        let result = self
            .read_current_data::<crucible_engine::node_contract::RuntimeError>()
            .map(|_| ());
        if result.is_err() {
            self.revoked.set(true);
        }
        result
    }

    fn read_current_data<E: measurement::MeasurementFailure>(&self) -> Result<u32, E> {
        if self.process != std::process::id() || self.originals.len() != 10 {
            return Err(E::refused());
        }
        let mut complete_measurements = 0_u16;
        for (index, original) in self.originals.iter().enumerate() {
            let descriptor = original.file.file().metadata().map_err(E::io)?;
            let path = std::fs::metadata(&original.path).map_err(E::io)?;
            if !descriptor.is_file()
                || !path.is_file()
                || Facts::from(&descriptor) != original.facts
                || Facts::from(&path) != original.facts
            {
                return Err(E::refused());
            }
            // Only an earlier completed full hash in THIS pass can cover an
            // alias. Exact revision facts and the entire ContentRef, including
            // media type, must match. A lease-only check never sets this bit.
            let measured_alias =
                self.originals[..index]
                    .iter()
                    .enumerate()
                    .any(|(earlier_index, earlier)| {
                        complete_measurements & (1_u16 << earlier_index) != 0
                            && earlier.facts == original.facts
                            && earlier.content == original.content
                    });
            let complete_read = original.file.lease().is_none() && !measured_alias;
            let measured = if let Some(lease) = original.file.lease() {
                lease.verify_current().map_err(|_| E::refused())?;
                original.file.file().metadata().map_err(E::io)?
            } else if measured_alias {
                original.file.file().metadata().map_err(E::io)?
            } else {
                measurement::measured_file_at_data::<E>(original.file.file(), &original.content)?
            };
            let path = std::fs::metadata(&original.path).map_err(E::io)?;
            if Facts::from(&measured) != original.facts || Facts::from(&path) != original.facts {
                return Err(E::refused());
            }
            if let Some(lease) = original.file.lease() {
                lease.verify_current().map_err(|_| E::refused())?;
            }
            // Mark only an actual full read after its own terminal fences.
            if complete_read {
                complete_measurements |= 1_u16 << index;
            }
        }
        Ok(complete_measurements.count_ones())
    }
}

// The fixed complete profile selects existing owner=None validation at birth.
// No lease owner is constructed and no successful token can enter this route.
fn complete_byte_originals(
    files: &[(&Path, &crucible_node_format::ContentRef); 10],
) -> Result<CurrentFiles, QualificationError> {
    let mut originals = Vec::new();
    originals.try_reserve_exact(10).map_err(|_| refused())?;
    for (path, reference) in files {
        originals.push(original(path, reference, None)?);
    }
    let installed = CurrentFiles {
        originals,
        process: std::process::id(),
        revoked: Cell::new(false),
    };
    installed.current()?;
    Ok(installed)
}

fn original(
    path: &Path,
    expected: &crucible_node_format::ContentRef,
    owner: Option<&Arc<LinuxReadLeaseOwner>>,
) -> Result<Original, QualificationError> {
    let file = LinuxReadLeaseFile::open(path, owner.cloned()).map_err(|_| refused())?;
    // The authoritative retained-descriptor measurement follows acquisition.
    // A conflicting preexisting writer declines the optimization altogether.
    let measured = measurement::measured_file_at(file.file(), expected)?;
    if let Some(lease) = file.lease() {
        lease.verify_current().map_err(|_| refused())?;
    }
    let facts = Facts::from(&measured);
    let selected = Facts::from(&std::fs::metadata(path).map_err(measurement::io)?);
    if facts != selected {
        return Err(refused());
    }
    Ok(Original {
        path: path.to_path_buf(),
        file,
        facts,
        content: expected.clone(),
    })
}

// Finish copied answers only after the original source revision is read again.
// The caller supplies its direct compiled current read, never a vendor predicate.
pub(in super::super) fn current_answer<T, E>(
    answer: T,
    current: impl FnOnce() -> Result<(), E>,
) -> Result<T, E> {
    current()?;
    Ok(answer)
}

#[cfg(test)]
#[path = "current_files/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "current_files/batch_tests.rs"]
mod batch_tests;

impl CurrentFiles {
    /// Counts the actual retained complete-byte file descriptors as data.
    ///
    /// Every Original owns one descriptor even when several paths select the
    /// same inode. A lease-backed view can additionally own a notification
    /// worker, so it refuses this closed complete-byte census.
    ///
    /// # Errors
    /// Refuses another creator process or unsupported leased descriptor owners.
    pub(in super::super) fn retained_descriptor_count_data(
        &self,
    ) -> Result<usize, crucible_engine::node_contract::RuntimeError> {
        use crucible_engine::node_contract::RuntimeError;
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        let Self {
            originals,
            process: _,
            revoked: _,
        } = self;
        originals.iter().try_fold(0usize, |count, original| {
            let Original {
                path: _,
                file,
                facts: _,
                content: _,
            } = original;
            if file.lease().is_some() {
                return Err(RuntimeError::UnsupportedFacet);
            }
            // Revocation prevents effects but does not erase this retained File.
            count.checked_add(1).ok_or(RuntimeError::ResourceLimit)
        })
    }
}
