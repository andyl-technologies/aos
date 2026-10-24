//! Retains actual immutable-file acquisition and measurement prefixes.
//!
//! This passive sink measures DATA through the same existing engine. A path,
//! file, completed measurement or comparison grants no launch or role authority.

use std::error::Error;

use super::*;

pub(super) struct InitialMeasurementSlotsV1 {
    pub(super) canonical_before: Option<std::io::Result<PathBuf>>,
    pub(super) opened: Option<Result<(), rustix::io::Errno>>,
    pub(super) canonical_measure: Option<std::io::Result<PathBuf>>,
    pub(super) initial_metadata: Option<std::io::Result<Metadata>>,
    pub(super) names: currentness::NamesOriginalV1,
    pub(super) digest: Option<Result<[u8; 32], ImmutableImageErrorV1>>,
    pub(super) expected: Option<Result<(), ImmutableImageErrorV1>>,
    pub(super) final_comparison: ImmutableFileRevalidationOriginalV1,
}

impl InitialMeasurementSlotsV1 {
    fn new() -> Self {
        Self {
            canonical_before: None,
            opened: None,
            canonical_measure: None,
            initial_metadata: None,
            names: currentness::NamesOriginalV1::new(),
            digest: None,
            expected: None,
            final_comparison: ImmutableFileRevalidationOriginalV1::new(),
        }
    }

    fn before_digest_failure(&self) -> Option<&(dyn Error + 'static)> {
        failure(&self.canonical_before)
            .or_else(|| failure(&self.opened))
            .or_else(|| failure(&self.canonical_measure))
            .or_else(|| failure(&self.initial_metadata))
            .or_else(|| self.names.failure())
    }
}

/// Refuses an immutable acquisition while retaining any unconsumed original.
///
/// Native causes remain on the acquisition destination. Only a file rejected
/// before entry can be returned from this error; entered files stay resident.
#[derive(Debug, thiserror::Error)]
#[error("immutable acquisition is incomplete or already entered")]
pub struct ImmutableFileAcquisitionRefusalV1 {
    original: Option<File>,
}

impl ImmutableFileAcquisitionRefusalV1 {
    /// Returns only an original rejected before the acquisition entered.
    #[must_use]
    pub fn into_rejected_original(self) -> Option<File> {
        self.original
    }
}

/// Owns original partial acquisition, metadata and measurement Results.
///
/// A genuine purpose supplies its actual locator or original file and pays
/// this destination before IO. This DATA receiver constructs no authority.
#[must_use = "keep the whole failed acquisition with its purpose owner"]
pub struct ImmutableFileAcquisitionOriginalV1 {
    pending: PendingImmutableFileV1,
    originals: InitialMeasurementSlotsV1,
    returned: Option<Result<(), ImmutableImageErrorV1>>,
    entered: bool,
    taken: bool,
    reentry: Option<ImmutableImageErrorV1>,
}

impl ImmutableFileAcquisitionOriginalV1 {
    /// Creates inert result destinations without native effects.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pending: PendingImmutableFileV1::default(),
            originals: InitialMeasurementSlotsV1::new(),
            returned: None,
            entered: false,
            taken: false,
            reentry: None,
        }
    }

    /// Opens and measures the bounded immutable DATA name once.
    ///
    /// # Errors
    /// Retains unavailable or unequal native/typed observations and refuses
    /// reentry without overwriting the original cause or repeating IO.
    pub fn open_and_measure_once(
        &mut self,
        path: PathBuf,
        expected_digest: Option<[u8; 32]>,
        maximum_bytes: u64,
        executable: bool,
    ) -> Result<(), ImmutableImageErrorV1> {
        self.enter_once()?;
        self.returned = Some(self.pending.open_and_measure_recipe(
            path, expected_digest, maximum_bytes, executable, Some(&mut self.originals),
        ));
        currentness::unit(&self.returned)
    }

    /// Opens an immutable DATA object with its exact declared byte length.
    ///
    /// Unlike image recipes, an exact zero-byte object is legitimate. The
    /// same name/mount/metadata/hash engine still requires a root-owned,
    /// non-writable regular file and compares the complete supplied digest.
    /// This constructs no role, origin, GC acknowledgement or admission.
    ///
    /// # Errors
    /// Retains failed acquisition, unequal exact length/content, unsafe names,
    /// metadata or mount, and rejects reentry without repeating native IO.
    pub fn open_and_measure_exact_data_once_v1(
        &mut self,
        path: PathBuf,
        expected_digest: [u8; 32],
        exact_bytes: u64,
    ) -> Result<(), ImmutableImageErrorV1> {
        self.enter_once()?;
        self.pending.exact_data_bytes = Some(exact_bytes);
        self.returned = Some(self.pending.open_and_measure_recipe(
            path, Some(expected_digest), exact_bytes, false, Some(&mut self.originals),
        ));
        currentness::unit(&self.returned)
    }

    /// Measures an actual returned original without reopening its DATA name.
    ///
    /// The original moves into its resident slot before any path/metadata read.
    /// This method cannot authenticate the caller's supplier or role.
    ///
    /// # Errors
    /// Retains native/typed measurement refusal. Reentry leaves the supplied
    /// original with the caller through the owning error return.
    pub fn measure_original_once(
        &mut self,
        path: PathBuf,
        original: File,
        expected_digest: Option<[u8; 32]>,
        maximum_bytes: u64,
        executable: bool,
    ) -> Result<(), ImmutableFileAcquisitionRefusalV1> {
        if self.enter_once().is_err() {
            return Err(ImmutableFileAcquisitionRefusalV1 { original: Some(original) });
        }
        self.pending.file = Some(original);
        self.pending.path = Some(path);
        self.returned = Some(self.pending.measure_parked_recipe(
            expected_digest, maximum_bytes, executable, Some(&mut self.originals),
        ));
        // The actual original stays in this owner on native or typed refusal.
        if matches!(self.returned, Some(Ok(()))) {
            Ok(())
        } else {
            Err(ImmutableFileAcquisitionRefusalV1 { original: None })
        }
    }

    /// Supplies the fixed owners and actual caller locator byte extent.
    ///
    /// The caller pays this DATA before construction and acquisition. A caller
    /// original supplied to measure_original_once is independently already owned;
    /// the one file here is the acquired or retained measurement slot.
    #[must_use]
    pub fn receiving_demand_v1(locator_bytes: usize) -> Option<aos_sandbox_model::ResourceVector> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

        let final_comparison = ImmutableFileRevalidationOriginalV1::receiving_demand_v1()?;
        let inline = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_sub(std::mem::size_of::<ImmutableFileRevalidationOriginalV1>())?;
        // Two kernel canonical names can coexist with the original locator.
        // Both hash buffers are inline in the actual nested owners; the shared
        // hash engine's ordinary stack buffer and hash state coexist with them.
        let memory = inline.checked_add(locator_bytes)?
            .checked_add(2_usize.checked_mul(4097)?)?
            .checked_add(8192)?
            .checked_add(2_usize.checked_mul(std::mem::size_of::<Sha256>())?)?
            .checked_add(std::mem::size_of::<ImmutableFileAcquisitionRefusalV1>())?;
        // Native result fields and comparison controls occupy the compiled
        // owner memory; this sampler creates no resident namespace entries.
        let own = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).ok()?)
            .with(D::OpenFiles, 1);
        own.checked_add(final_comparison).ok()
    }

    /// Bounds both actual digest reads of the sole initial measurement recipe.
    ///
    /// Initial measurement hashes once, then the same final immutable-name
    /// comparison hashes again. Each shared reader has its own trailing-byte
    /// allowance. Genuine callers pay this input separately from Memory.
    #[must_use]
    pub fn measurement_input_bytes_v1(maximum_bytes: u64) -> Option<u64> {
        maximum_bytes.checked_add(1)?.checked_mul(2)
    }

    /// Bounds measurement followed by the actual retained bounded byte read.
    ///
    /// Materialization performs one exact payload read between two further
    /// digest comparisons. This reuses the measurement supplier and does not
    /// change or duplicate any of those existing native read/hash loops.
    #[must_use]
    pub fn materialized_input_bytes_v1(maximum_bytes: u64) -> Option<u64> {
        Self::measurement_input_bytes_v1(maximum_bytes)?
            .checked_add(maximum_bytes.checked_add(1)?.checked_mul(2)?)?
            .checked_add(maximum_bytes)
    }

    /// Borrows the completed immutable measurement as nonauthorizing DATA.
    #[must_use]
    pub fn completed_measurement(&self) -> Option<&RetainedImmutableFileV1> {
        if self.reentry.is_some() || !matches!(self.returned, Some(Ok(()))) {
            return None;
        }
        self.pending.measurement().ok()
    }

    /// Revalidates the same completed measurement through its resident sink.
    ///
    /// This delegates to the existing pending-file engine and leaves the
    /// original acquisition prefix and first native cause resident.
    ///
    /// # Errors
    /// Refuses incomplete, taken or reentered acquisition and changed native
    /// names, metadata or bounded content.
    pub fn revalidate_completed(&mut self) -> Result<(), ImmutableImageErrorV1> {
        self.require_completed()?;
        self.pending.revalidate()
    }

    /// Reads bounded bytes through the same completed file and native sink.
    ///
    /// The actual purpose separately pays its bounded read buffer before this
    /// method; the fixed acquisition geometry includes no file-sized buffer.
    ///
    /// # Errors
    /// Refuses incomplete, taken or reentered acquisition, native read failure
    /// or content beyond the measurement's original maximum.
    pub fn read_completed_bounded(&mut self) -> Result<(), ImmutableImageErrorV1> {
        self.require_completed()?;
        self.pending.read_bounded()
    }

    /// Borrows the actual complete or partial bounded-read destination.
    ///
    /// Failed native reads leave their reached bytes in the pending owner.
    /// A refused initial acquisition or already moved measurement yields no
    /// bytes and cannot be turned into a completed measurement.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        if self.require_completed().is_err() { return &[]; }
        self.pending.bytes()
    }

    /// Moves only this own completed measurement once, retaining probe outcomes.
    #[must_use]
    pub fn take_completed_measurement_once(&mut self) -> Option<RetainedImmutableFileV1> {
        self.completed_measurement()?;
        if self.taken {
            return None;
        }
        let measured = self.pending.take_measurement()?;
        self.taken = true;
        Some(measured)
    }

    // The fixed backend adapter preserves the existing typed classifier while
    // the public diagnostic borrower continues to prefer actual native causes.
    pub(super) fn completion_failure_v1(&self) -> Option<&ImmutableImageErrorV1> {
        self.returned.as_ref().and_then(|result| result.as_ref().err())
    }

    /// Observes only the same available held acquisition prefix into a sink.
    ///
    /// A completed measurement uses its existing full revalidation engine.
    /// An incomplete held file yields only descriptor metadata and refuses
    /// completion; no file or path moves and no acquisition is retried. `None`
    /// means no original descriptor was reached or it was already transferred.
    /// This negative-observation DATA grants no immutable or role authority.
    ///
    /// # Errors
    /// A reached result retains native revalidation refusal, or refuses the
    /// incomplete metadata-only prefix and repeated entry into its sink.
    #[doc(hidden)]
    pub fn observe_available_held_once_v1(
        &self,
        original: &mut ImmutableFileRevalidationOriginalV1,
    ) -> Option<Result<(), ImmutableImageErrorV1>> {
        if let Some(measured) = self.pending.measured.as_ref() {
            return Some(measured.revalidate_retaining(original));
        }
        self.pending.file.as_ref().map(|file| original.observe_held_metadata_only_v1(file))
    }

    /// Borrows the earliest actual native or typed acquisition cause.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.originals.before_digest_failure()
            .or_else(|| self.pending.native_failure())
            .or_else(|| failure(&self.originals.digest))
            .or_else(|| failure(&self.originals.expected))
            .or_else(|| self.originals.final_comparison.failure())
            .or_else(|| failure(&self.returned))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }

    fn require_completed(&self) -> Result<(), ImmutableImageErrorV1> {
        if self.taken || self.completed_measurement().is_none() {
            return Err(ImmutableImageErrorV1::Provisioning);
        }
        Ok(())
    }

    fn enter_once(&mut self) -> Result<(), ImmutableImageErrorV1> {
        if self.entered {
            self.reentry.get_or_insert(ImmutableImageErrorV1::Provisioning);
            return Err(ImmutableImageErrorV1::Provisioning);
        }
        self.entered = true;
        Ok(())
    }
}

impl Default for ImmutableFileAcquisitionOriginalV1 {
    fn default() -> Self {
        Self::new()
    }
}

fn failure<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn owed_incomplete_file_observation_keeps_actual_descriptor_and_initial_cause() {
        use std::os::fd::AsRawFd as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("unmeasured-original");
        std::fs::write(&path, b"retained input").unwrap();
        let file = File::open(&path).unwrap();
        let descriptor = file.as_raw_fd();
        let mut acquisition = ImmutableFileAcquisitionOriginalV1::new();
        assert!(acquisition.measure_original_once(path.clone(), file, None, 4096, false).is_err());
        let first = acquisition.failure().unwrap() as *const dyn Error;
        std::fs::remove_file(path).unwrap();
        let mut owed = ImmutableFileRevalidationOriginalV1::new();

        assert!(matches!(acquisition.observe_available_held_once_v1(&mut owed), Some(Err(_))));

        assert!(!owed.is_complete());
        assert!(owed.failure().is_some());
        assert!(acquisition.completed_measurement().is_none());
        assert!(std::ptr::eq(acquisition.failure().unwrap(), first));
        assert_eq!(acquisition.pending.file.as_ref().unwrap().as_raw_fd(), descriptor);
        assert!(acquisition.pending.file.as_ref().unwrap().metadata().is_ok());
        let owed_first = owed.failure().unwrap() as *const dyn Error;
        assert!(matches!(acquisition.observe_available_held_once_v1(&mut owed), Some(Err(_))));
        assert!(std::ptr::eq(owed.failure().unwrap(), owed_first));
    }

    #[test]
    fn unreached_acquisition_has_no_available_descriptor_observation() {
        let acquisition = ImmutableFileAcquisitionOriginalV1::new();
        let mut owed = ImmutableFileRevalidationOriginalV1::new();

        assert!(acquisition.observe_available_held_once_v1(&mut owed).is_none());

        assert!(owed.failure().is_none());
        assert!(!owed.is_complete());
    }

    #[test]
    fn failed_original_measurement_keeps_the_actual_file_and_rejects_reentry_owningly() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("original");
        let mut file = File::create(&path).unwrap();
        file.write_all(b"measurement input").unwrap();
        let expected_identity = identity(&file.metadata().unwrap());
        let mut original = ImmutableFileAcquisitionOriginalV1::new();

        let failure = original.measure_original_once(path.clone(), file, None, 4096, false)
            .unwrap_err();
        assert!(failure.into_rejected_original().is_none());
        assert_eq!(identity(&original.pending.original().unwrap().metadata().unwrap()), expected_identity);
        assert!(original.completed_measurement().is_none());
        let first = original.failure().unwrap()
            .downcast_ref::<ImmutableImageErrorV1>().unwrap() as *const _;

        let replacement = File::open(&path).unwrap();
        let rejected = original.measure_original_once(path, replacement, None, 4096, false)
            .unwrap_err().into_rejected_original().unwrap();
        assert_eq!(identity(&rejected.metadata().unwrap()), expected_identity);
        assert_eq!(original.failure().unwrap()
            .downcast_ref::<ImmutableImageErrorV1>().unwrap() as *const _, first);
        assert!(original.take_completed_measurement_once().is_none());
        assert!(original.originals.initial_metadata.is_none());
    }

    #[test]
    fn failed_canonicalization_keeps_the_actual_native_error_before_any_open() {
        let path = PathBuf::from(format!(
            "/nix/store/rfc21-missing-acquisition-fixture-{}/does-not-exist", std::process::id(),
        ));
        assert!(!path.exists());
        let mut original = ImmutableFileAcquisitionOriginalV1::new();
        assert!(original.open_and_measure_once(path.clone(), None, 4096, false).is_err());
        let native = original.originals.canonical_before.as_ref().unwrap().as_ref().unwrap_err();
        let borrowed = original.failure().unwrap().downcast_ref::<std::io::Error>().unwrap();
        assert!(std::ptr::eq(native, borrowed));
        assert!(original.originals.opened.is_none());
        assert!(original.pending.file.is_none());

        let first = native as *const _;
        assert!(original.open_and_measure_once(path, None, 4096, false).is_err());
        assert_eq!(original.failure().unwrap().downcast_ref::<std::io::Error>().unwrap() as *const _, first);
    }
}

#[cfg(test)]
mod completed_native_port_tests {
    use super::*;

    #[test]
    fn refused_completed_ports_preserve_the_actual_initial_open_cause() {
        let missing = std::path::PathBuf::from(format!(
            "/nix/store/rfc21-missing-completed-port-fixture-{}/does-not-exist",
            std::process::id(),
        ));
        assert!(!missing.exists());
        let mut capture = ImmutableFileAcquisitionOriginalV1::new();
        assert!(capture.open_and_measure_once(missing, None, 4096, false).is_err());
        let original = capture.failure().unwrap() as *const (dyn Error + 'static);
        assert_eq!(capture.failure().unwrap().downcast_ref::<std::io::Error>()
            .unwrap().kind(), std::io::ErrorKind::NotFound);

        assert!(capture.revalidate_completed().is_err());
        assert!(capture.read_completed_bounded().is_err());

        assert!(std::ptr::eq(capture.failure().unwrap(), original));
        assert!(capture.completed_measurement().is_none());
        assert!(capture.bytes().is_empty());
    }
}
