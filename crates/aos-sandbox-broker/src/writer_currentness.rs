//! Retains shared physical writer observations without role admission.
//!
//! Actual role owners retain their journal, policy, ledger and independent
//! posts. This reservoir only owns the fresh native partials and first causes.

use std::error::Error;
use std::fs::File;
use std::path::Path;
use aos_sandbox_journal::framing::FrameError;
use aos_sandbox_journal::protected_storage::{
    ProtectedFailure, ProtectedFileNamesCurrentOriginalsV1, ProtectedJournalLocation,
    resolve_protected_directory_from_root_original,
};

/// Holds one complete or partial protected writer currentness observation.
///
/// This supplies custody and diagnostic DATA only. Its caller retains the
/// genuine owner, native funding and independent policy posts. Reentry cannot
/// repeat a native operation or replace any reached outcome.
#[must_use = "retain failed rooted and named-file originals through independent posts"]
pub struct WriterCurrentnessOriginalsV1<E> {
    entered: bool,
    reentered: bool,
    names_first: bool,
    ancestors: Vec<File>,
    root_error: Option<rustix::io::Errno>,
    directory: Option<Result<File, E>>,
    shared_directory_path: Option<std::path::PathBuf>,
    shared_directory_uid: Option<u32>,
    binding: Option<Result<(), E>>,
    names: Option<ProtectedFileNamesCurrentOriginalsV1<E>>,
    result: Option<Result<(), E>>,
    settled: bool,
}

#[derive(Debug, thiserror::Error)]
#[error("original writer currentness is closed")]
struct WriterCurrentnessClosedV1;

const CURRENTNESS_CLOSED: WriterCurrentnessClosedV1 = WriterCurrentnessClosedV1;

impl<E: ProtectedFailure + From<FrameError> + Error + 'static> WriterCurrentnessOriginalsV1<E> {
    /// Creates empty destinations without allocation, native IO or authority.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entered: false,
            reentered: false,
            names_first: false,
            ancestors: Vec::new(),
            root_error: None,
            directory: None,
            shared_directory_path: None,
            shared_directory_uid: None,
            binding: None,
            names: None,
            result: None,
            settled: false,
        }
    }

    /// Describes one fresh rooted-and-named observation's dominant resources.
    ///
    /// The path and name are DATA; this recipe neither pays nor authenticates
    /// them. The genuine caller derives these inputs from its actual owner and
    /// reserves this geometry before the native observation.
    ///
    /// # Errors
    /// Rejects a relative path, invalid basename or arithmetic overflow.
    pub fn fixed_demand_v1(
        directory: &Path,
        name: &str,
    ) -> Result<aos_sandbox_core::ResourceVector, E> {
        Self::fixed_demand_recipe_v6(directory, Some(name))
    }

    /// Prices one shared protected ancestry without fictitious file-name entries.
    ///
    /// # Errors
    /// Rejects a relative path or checked geometry overflow. This is DATA only.
    pub fn directory_demand_v6(directory: &Path) -> Result<aos_sandbox_core::ResourceVector, E> {
        Self::fixed_demand_recipe_v6(directory, None)
    }

    fn fixed_demand_recipe_v6(directory: &Path, name: Option<&str>) -> Result<aos_sandbox_core::ResourceVector, E> {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};

        let failed = || E::from(FrameError::LimitExceeded("writer currentness geometry"));
        if !directory.is_absolute() {
            return Err(E::BOUNDARY);
        }
        if let Some(name) = name {
            aos_sandbox_journal::protected_storage::validate_basename::<E>(name)?;
        }
        let named_files = if name.is_some() { 2 } else { 0 };
        let depth = directory.components()
            .filter(|part| matches!(part, std::path::Component::Normal(_)))
            .count().checked_add(1).ok_or_else(failed)?;
        let path = directory.as_os_str().as_encoded_bytes().len()
            .checked_add(name.map_or(0, str::len)).ok_or_else(failed)?;
        let memory = depth.checked_mul(std::mem::size_of::<File>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()))
            .and_then(|bytes| bytes.checked_add(path.checked_add(32)?.checked_mul(4)?))
            .and_then(|bytes| bytes.checked_add(8 * 256)).ok_or_else(failed)?;
        let files = depth.checked_add(named_files).ok_or_else(failed)?;
        // The rooted directory components and the distinct lock/data names
        // form the namespace. Four fstat results describe those same objects;
        // their native carriers are already included in the byte bound.
        let metadata = depth.checked_add(named_files).ok_or_else(failed)?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).map_err(|_| failed())?)
            .with(D::OpenFiles, u64::try_from(files).map_err(|_| failed())?)
            .with(D::MetadataEntries, u64::try_from(metadata).map_err(|_| failed())?))
    }

    /// Describes one names-only observation without charging a rooted traversal.
    ///
    /// This passive bound supplies no payment or permission to use the writer.
    ///
    /// # Errors
    /// Rejects an invalid fixed basename or arithmetic overflow.
    pub fn named_demand_v1(name: &str)
        -> Result<aos_sandbox_core::ResourceVector, E>
    {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};

        aos_sandbox_journal::protected_storage::validate_basename::<E>(name)?;
        let memory = name.len().checked_add(5).and_then(|bytes| bytes.checked_mul(2))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()))
            .and_then(|bytes| bytes.checked_add(8 * 256))
            .ok_or(E::from(FrameError::LimitExceeded("writer name geometry")))?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory)
                .map_err(|_| E::from(FrameError::LimitExceeded("writer name geometry")))?)
            .with(D::OpenFiles, 2)
            // Names-only observation reaches exactly the lock and data names.
            .with(D::MetadataEntries, 2))
    }

    /// Records caller-selected recipe order once without observing a file.
    ///
    /// # Errors
    /// Marks reentry without replacing the original native partials.
    pub fn begin(&mut self, names_first: bool) -> Result<(), E> {
        if self.entered {
            self.reentered = true;
            return Err(E::BOUNDARY);
        }
        self.entered = true;
        self.names_first = names_first;
        Ok(())
    }

    /// Parks the caller's recipe result as DATA, never a role permit.
    ///
    /// # Errors
    /// Reports the parked refusal or repeated entry.
    pub fn finish(&mut self, result: Result<(), E>) -> Result<(), E> {
        self.result = Some(result);
        if self.is_complete() {
            Ok(())
        } else {
            Err(E::BOUNDARY)
        }
    }

    /// Retains actual rooted traversal before physical binding.
    ///
    /// # Errors
    /// Parks every reached ancestor and the original native/typed refusal.
    pub fn observe_directory(
        &mut self, path: &Path, uid: u32,
    ) -> Result<&File, E> {
        self.directory = Some(resolve_protected_directory_from_root_original::<E>(
            path, uid, Some(&mut self.ancestors), Some(&mut self.root_error)));
        match self.directory.as_ref() {
            Some(Ok(directory)) => Ok(directory),
            _ => Err(E::BOUNDARY),
        }
    }

    /// Captures one same-interval protected ancestry without a writer-name check.
    ///
    /// The existing resolver retains every reached ancestor and native refusal.
    /// Borrowers still check each actual held writer directory and both names.
    ///
    /// # Errors
    /// Refuses reentry, unsafe ancestry, native errors or invalid protected UID.
    pub fn capture_directory_once_v6(&mut self, path: &Path, uid: u32) -> Result<(), E> {
        self.begin(false)?;
        self.shared_directory_path = Some(path.to_owned());
        self.shared_directory_uid = Some(uid);
        let observed = self.observe_directory(path, uid).map(|_| ());
        self.finish(observed)
    }

    /// Binds a separately retained writer to the actual shared directory sample.
    ///
    /// This performs the same held-directory native identity comparison. It
    /// supplies no writer, role, health, append or receiving authority.
    ///
    /// # Errors
    /// Retains incomplete/different path, UID, native identity or binding refusal.
    pub fn bind_shared_location_v6<P>(&mut self, shared: &Self, path: &Path, uid: u32,
        location: &ProtectedJournalLocation<P>) -> Result<(), E> {
        let result = (|| {
            if !shared.is_complete() || shared.settled
                || shared.shared_directory_path.as_deref() != Some(path)
                || shared.shared_directory_uid != Some(uid) {
                return Err(E::BOUNDARY);
            }
            let directory = match shared.directory.as_ref() {
                Some(Ok(directory)) => directory,
                _ => return Err(E::BOUNDARY),
            };
            location.require_opened_directory::<E>(directory)
        })();
        self.binding = Some(result);
        if matches!(self.binding, Some(Ok(()))) { Ok(()) } else { Err(E::BOUNDARY) }
    }

    /// Compares the reached directory with the actual held physical location.
    ///
    /// # Errors
    /// Retains metadata or identity mismatch in this same reservoir.
    pub fn bind_location<P>(
        &mut self, location: &ProtectedJournalLocation<P>,
    ) -> Result<(), E> {
        let directory = match self.directory.as_ref() {
            Some(Ok(directory)) => directory,
            _ => return Err(E::BOUNDARY),
        };
        self.binding = Some(location.require_opened_directory::<E>(directory));
        if matches!(self.binding, Some(Ok(()))) {
            Ok(())
        } else {
            Err(E::BOUNDARY)
        }
    }

    /// Compares actual reached and retained directory device/inode pairs.
    ///
    /// # Errors
    /// Retains the original metadata or physical binding refusal.
    pub fn bind_directory(&mut self, held: &File) -> Result<(), E> {
        let result = (|| {
            let current = match self.directory.as_ref() {
                Some(Ok(directory)) => directory,
                _ => return Err(E::BOUNDARY),
            };
            let held = rustix::fs::fstat(held).map_err(aos_sandbox_journal::protected_storage::rustix_io::<E>)?;
            let named = rustix::fs::fstat(current).map_err(aos_sandbox_journal::protected_storage::rustix_io::<E>)?;
            if held.st_dev != named.st_dev || held.st_ino != named.st_ino {
                return Err(E::BOUNDARY);
            }
            Ok(())
        })();
        self.binding = Some(result);
        if matches!(self.binding, Some(Ok(()))) {
            Ok(())
        } else {
            Err(E::BOUNDARY)
        }
    }

    /// Retains actual lock/data name observations beside the supplied originals.
    ///
    /// # Errors
    /// Keeps fresh partial files and original native failures on refusal.
    pub fn observe_names_at(
        &mut self, directory: &File, name: &str, uid: u32, lock: &File, file: &File,
    ) -> Result<(), E> {
        let names = self.names.insert(ProtectedFileNamesCurrentOriginalsV1::new());
        names.capture_once(directory, name, uid, lock, file);
        if names.is_complete() {
            Ok(())
        } else {
            Err(E::BOUNDARY)
        }
    }

    /// Retains the actual held location's lock/data name observations.
    ///
    /// # Errors
    /// Keeps fresh partial files and original native failures on refusal.
    pub fn observe_names<P>(
        &mut self, location: &ProtectedJournalLocation<P>, name: &str, uid: u32,
        lock: &File, file: &File,
    ) -> Result<(), E> {
        let names = self.names.insert(ProtectedFileNamesCurrentOriginalsV1::new());
        location.observe_named_files_once(name, uid, lock, file, names);
        if names.is_complete() {
            Ok(())
        } else {
            Err(E::BOUNDARY)
        }
    }

    /// Reports that this exact entered recipe completed positively.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        !self.reentered && matches!(self.result, Some(Ok(())))
    }

    /// Borrows the first actual rooted, named or semantic refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let directory = || self.root_error.as_ref()
            .map(|error| error as &(dyn Error + 'static))
            .or_else(|| self.directory.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _))
            .or_else(|| self.binding.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _));
        let names = || self.names.as_ref().and_then(ProtectedFileNamesCurrentOriginalsV1::failure)
            .map(|e| e as &(dyn Error + 'static));
        let native = if self.names_first {
            names().or_else(directory)
        } else {
            directory().or_else(names)
        };
        native.or_else(|| self.result.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _))
            .or_else(|| self.reentered.then_some(&CURRENTNESS_CLOSED as &(dyn Error + 'static)))
    }

    /// Disposes only fresh descriptors from a complete positive observation.
    ///
    /// The whole completion remains parked and reentry stays closed. Failed
    /// or incomplete traversals/names remain resident; this is no funding refund.
    pub fn settle_positive_once_v1(&mut self) {
        if !self.is_complete() || self.settled {
            return;
        }

        self.names = None;
        self.directory = None;
        self.shared_directory_path = None;
        // Dispose the actual Vec backing as well as its descriptors before
        // another sample reuses this prepaid peak; clear() would retain it.
        self.ancestors = Vec::new();
        self.settled = true;
    }

    /// Copies the completed held journal's original device, inode and byte length.
    ///
    /// This borrows the existing name-check sample before its positive disposal.
    /// It performs no IO and creates no native currentness or writer authority.
    /// A failed, incomplete, reentered or already disposed sample returns None.
    #[must_use]
    pub fn completed_held_file_boundary_data_v1(&self) -> Option<(u64, u64, u64)> {
        if !self.is_complete() || self.settled { return None; }
        self.names.as_ref()?.completed_held_file_boundary_data_v1()
    }

    /// Counts fresh native files currently retained by this observation.
    #[must_use]
    pub fn retained_file_count(&self) -> usize {
        self.ancestors.len() + usize::from(matches!(self.directory, Some(Ok(_))))
            + self.names.as_ref().map_or(0, ProtectedFileNamesCurrentOriginalsV1::retained_file_count)
    }
}

impl<E: ProtectedFailure + From<FrameError> + Error + 'static> Default for WriterCurrentnessOriginalsV1<E> {
    fn default() -> Self {
        Self::new()
    }
}

