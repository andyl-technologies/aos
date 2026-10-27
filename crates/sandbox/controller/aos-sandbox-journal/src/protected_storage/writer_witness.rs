//! Retains the existing Directory/Journal/Lock witness at its actual probes.
//!
//! The sole metadata operation and seven-field projection serve both ordinary
//! and retained storage. Comparison preserves its original lazy `||` order.
//! This is physical DATA: it enters no role, health gate, payer or writer scope.

use std::error::Error;
use std::fs::{File, Metadata};
use std::io;

use super::{FileIdentity, ProtectedFailure, ProtectedJournalLocation, ProtectedWriterNameWitness};

// Closed private storage dispositions share one actual metadata call. Neither
// selects a file, performs another effect or supplies an authority callback.
pub(super) trait MetadataDestination {
    type Output;
    fn store(self, result: io::Result<Metadata>) -> Self::Output;
}

pub(super) struct OrdinaryMetadata;

impl MetadataDestination for OrdinaryMetadata {
    type Output = io::Result<Metadata>;
    fn store(self, result: io::Result<Metadata>) -> Self::Output { result }
}

struct RetainedMetadata<'slot>(&'slot mut Option<io::Result<Metadata>>);

impl MetadataDestination for RetainedMetadata<'_> {
    type Output = ();
    fn store(self, result: io::Result<Metadata>) { *self.0 = Some(result); }
}

pub(super) fn observe_metadata_once<D: MetadataDestination>(file: &File, destination: D) -> D::Output {
    destination.store(file.metadata())
}

struct IdentityOriginal<E> {
    metadata: Option<io::Result<Metadata>>,
    projected: Option<Result<FileIdentity, E>>,
}

impl<E: ProtectedFailure> IdentityOriginal<E> {
    const fn new() -> Self { Self { metadata: None, projected: None } }

    fn observe_once(&mut self, file: &File) -> Result<FileIdentity, E> {
        observe_metadata_once(file, RetainedMetadata(&mut self.metadata));
        self.projected = Some(match &self.metadata {
            Some(Ok(metadata)) => Ok(FileIdentity::from_metadata(metadata)),
            _ => Err(E::BOUNDARY),
        });
        match &self.projected {
            Some(Ok(identity)) => Ok(*identity),
            _ => Err(E::BOUNDARY),
        }
    }
}

macro_rules! identity_step {
    (Ordinary, $owner:ident, $slot:ident, $file:expr) => { FileIdentity::of::<E>($file)? };
    (Retained, $owner:ident, $slot:ident, $file:expr) => { $owner.$slot.observe_once($file)? };
}

macro_rules! sample_recipe {
    ($mode:ident, $owner:ident, $directory:ident, $file:ident, $lock:ident) => {
        Ok(ProtectedWriterNameWitness {
            directory: identity_step!($mode, $owner, directory, $directory),
            file: identity_step!($mode, $owner, journal, $file),
            lock: identity_step!($mode, $owner, lock, $lock),
        })
    };
}

macro_rules! compare_recipe {
    ($mode:ident, $owner:ident, $directory:ident, $file:ident, $lock:ident, $witness:ident) => {{
        if identity_step!($mode, $owner, directory, $directory) != $witness.directory
            || identity_step!($mode, $owner, journal, $file) != $witness.file
            || identity_step!($mode, $owner, lock, $lock) != $witness.lock
        {
            return Err(E::STALE_NAME);
        }
        Ok(())
    }};
}

pub(super) fn sample_ordinary<E: ProtectedFailure>(directory: &File, file: &File, lock: &File)
    -> Result<ProtectedWriterNameWitness, E>
{
    sample_recipe!(Ordinary, unused, directory, file, lock)
}

pub(super) fn compare_ordinary<E: ProtectedFailure>(directory: &File, file: &File, lock: &File,
    witness: &ProtectedWriterNameWitness) -> Result<(), E>
{
    compare_recipe!(Ordinary, unused, directory, file, lock, witness)
}

/// Describes one fixed FileIdentity receiving destination without admission.
pub type FileIdentityReceivingFootprintV1 = WriterWitnessReceivingFootprintV1;

/// Retains one actual Metadata Result and its sole FileIdentity projection.
///
/// This passive sampler creates no FD, role, protected writer or payer. The
/// genuine purpose supplies its same already-held file and prices this owner
/// before reaching the existing FileIdentity probe frontier.
#[must_use = "retain the actual native metadata and projected identity on failure"]
pub struct FileIdentityOriginalsV1<E> {
    probe: IdentityOriginal<E>,
    returned: Option<Result<(), E>>,
    entered: bool,
    reentry: Option<E>,
    taken: bool,
    metadata_retired: bool,
}

impl<E: ProtectedFailure> FileIdentityOriginalsV1<E> {
    /// Creates inert native-result storage without acquisition or observation.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            probe: IdentityOriginal::new(),
            returned: None,
            entered: false,
            reentry: None,
            taken: false,
            metadata_retired: false,
        }
    }

    /// Supplies actual compiled native/model/return widths and named controls.
    #[must_use]
    pub fn receiving_footprint_v1() -> Option<FileIdentityReceivingFootprintV1> {
        let memory = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(std::mem::size_of::<io::Result<Metadata>>())?
            .checked_add(std::mem::size_of::<Result<FileIdentity, E>>())?
            .checked_add(std::mem::size_of::<Result<(), E>>())?
            .checked_add(std::mem::size_of::<FileIdentity>())?
            .checked_add(std::mem::size_of::<FileIdentityReceivingFootprintV1>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<usize>().checked_mul(6)?)?;
        // Metadata is read from an already-held file. Fixed native results and
        // identity fields occupy bytes above; this probe creates no namespace,
        // path, map or index entries.
        Some(FileIdentityReceivingFootprintV1 {
            memory_bytes: memory,
            open_files: 0,
            metadata_cells: 0,
        })
    }

    /// Borrows this actual completed identity without moving native custody.
    #[must_use]
    pub fn completed_identity(&self) -> Option<&FileIdentity> {
        if self.taken || self.reentry.is_some() || !matches!(self.returned, Some(Ok(()))) {
            return None;
        }
        self.probe.projected.as_ref().and_then(|result| result.as_ref().ok())
    }

    /// Borrows this sample's actual successful Metadata as comparison DATA.
    ///
    /// The whole native Result stays on this original. Borrowing it admits no
    /// file, peer, role or operation and performs no additional observation.
    #[must_use]
    pub fn completed_metadata(&self) -> Option<&Metadata> {
        self.completed_identity()?;
        self.probe.metadata.as_ref()?.as_ref().ok()
    }

    /// Moves only this own completed identity DATA once.
    #[must_use]
    pub fn take_completed_identity_once(&mut self) -> Option<FileIdentity> {
        let identity = *self.completed_identity()?;
        self.taken = true;
        Some(identity)
    }

    /// Drops only native successful Metadata after this own positive sample.
    ///
    /// Projected identity and whole completion remain resident. Negative,
    /// incomplete or reentered slots cannot retire any metadata.
    pub fn retire_positive_metadata_once_v1(&mut self) -> bool {
        if self.metadata_retired || self.reentry.is_some()
            || !matches!(self.returned, Some(Ok(())))
            || !matches!(self.probe.metadata, Some(Ok(_)))
            || !matches!(self.probe.projected, Some(Ok(_))) {
            return false;
        }
        self.probe.metadata = None;
        self.metadata_retired = true;
        true
    }
}

impl<E: ProtectedFailure + Error + 'static> FileIdentityOriginalsV1<E> {
    /// Borrows the original native cause before any stopping projection.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        if let Some(Err(cause)) = &self.probe.metadata { return Some(cause); }
        if let Some(Err(cause)) = &self.probe.projected { return Some(cause); }
        self.returned.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as &(dyn Error + 'static)))
    }
}

impl<E: ProtectedFailure> Default for FileIdentityOriginalsV1<E> {
    fn default() -> Self { Self::new() }
}

impl FileIdentity {
    /// Samples the same single metadata/projection engine into a retained sink.
    ///
    /// # Errors
    /// Retains native refusal before its boundary projection. Reentry records
    /// refusal without executing IO or overwriting any original outcome.
    pub fn of_retaining_v1<E: ProtectedFailure>(
        file: &File,
        originals: &mut FileIdentityOriginalsV1<E>,
    ) -> Result<(), E> {
        if originals.entered {
            originals.reentry.get_or_insert(E::BOUNDARY);
            return Err(E::BOUNDARY);
        }
        originals.entered = true;
        originals.returned = Some(originals.probe.observe_once(file).map(|_| ()));
        if matches!(originals.returned, Some(Ok(()))) { Ok(()) }
        else { Err(E::BOUNDARY) }
    }
}

/// Describes fixed receiving storage without issuing admission or a budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriterWitnessReceivingFootprintV1 {
    /// Actual owner/construction, metadata/projection and returned-value bytes.
    pub memory_bytes: usize,
    /// No new file description is opened or duplicated by these probes.
    pub open_files: usize,
    /// New namespace, path, map or index entries; held-file probes create none.
    pub metadata_cells: usize,
}

/// Retains one actual witness sample OR one lazy witness comparison.
///
/// The caller prepays this owner and retains it at the actual probe frontier.
/// Distinct primary and owed comparisons require distinct owners. Raw metadata
/// failures remain in their original `io::Result`; selected return values are
/// fixed stopping projections, and [`Self::failure`] borrows the actual cause.
/// Ordinary convenience methods retain their original owning error conversion.
#[must_use = "retain every reached native witness and its whole comparison"]
pub struct WriterWitnessOriginalsV1<E> {
    directory: IdentityOriginal<E>,
    journal: IdentityOriginal<E>,
    lock: IdentityOriginal<E>,
    witness: Option<Result<ProtectedWriterNameWitness, E>>,
    comparison: Option<Result<(), E>>,
    entered: bool,
    reentry: Option<E>,
    taken: bool,
    metadata_retired: bool,
}

impl<E: ProtectedFailure> WriterWitnessOriginalsV1<E> {
    /// Creates inert one-shot destinations without opening or observing files.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            directory: IdentityOriginal::new(), journal: IdentityOriginal::new(),
            lock: IdentityOriginal::new(), witness: None, comparison: None,
            entered: false, reentry: None, taken: false, metadata_retired: false,
        }
    }

    /// Supplies this actual type's fixed constructor/native/result geometry.
    ///
    /// Dynamic owners retained by the enclosing purpose remain separately paid.
    /// Returns `None` on checked representation arithmetic overflow.
    #[must_use]
    pub fn receiving_footprint_v1() -> Option<WriterWitnessReceivingFootprintV1> {
        let memory = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(std::mem::size_of::<io::Result<Metadata>>())?
            .checked_add(std::mem::size_of::<Result<FileIdentity, E>>())?
            .checked_add(std::mem::size_of::<Result<ProtectedWriterNameWitness, E>>())?
            .checked_add(std::mem::size_of::<Result<(), E>>())?
            .checked_add(std::mem::size_of::<FileIdentity>())?
            .checked_add(std::mem::size_of::<WriterWitnessReceivingFootprintV1>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<usize>().checked_mul(9)?)?;
        // All three probes use already-held Directory/Journal/Lock files.
        // Their fixed metadata and identity results occupy bytes above; neither
        // sampling nor lazy comparison creates namespace, path, map or index entries.
        Some(WriterWitnessReceivingFootprintV1 { memory_bytes: memory, open_files: 0,
            metadata_cells: 0 })
    }

    fn enter_once(&mut self) -> Result<(), E> {
        if self.entered {
            self.reentry.get_or_insert(E::BOUNDARY);
            return Err(E::BOUNDARY);
        }
        self.entered = true;
        Ok(())
    }

    /// Borrows this sample's actual completed witness without moving custody.
    #[must_use]
    pub fn completed_witness(&self) -> Option<&ProtectedWriterNameWitness> {
        if self.reentry.is_some() || self.taken { return None; }
        self.witness.as_ref().and_then(|result| result.as_ref().ok())
    }

    /// Moves this actual positive witness once without granting currentness.
    #[must_use]
    pub fn take_completed_witness_once(&mut self) -> Option<ProtectedWriterNameWitness> {
        if self.completed_witness().is_none() { return None; }
        match self.witness.take() {
            Some(Ok(witness)) => { self.taken = true; Some(witness) }
            original => { self.witness = original; None }
        }
    }

    /// Drops only positive native Metadata values after this entire comparison.
    ///
    /// The projected identities and compact one-shot outcome stay resident.
    /// Negative/incomplete probes remain untouched. No FD, charge, authority
    /// or later comparison is released or admitted by this disposition.
    pub fn retire_positive_metadata_once_v1(&mut self) -> bool {
        if self.metadata_retired || self.reentry.is_some()
            || !(self.taken || matches!(self.witness, Some(Ok(_)))
                || matches!(self.comparison, Some(Ok(()))))
            || [&self.directory, &self.journal, &self.lock].into_iter()
                .any(|probe| !matches!(probe.metadata, Some(Ok(_)))
                    || !matches!(probe.projected, Some(Ok(_))))
        {
            return false;
        }
        self.directory.metadata = None;
        self.journal.metadata = None;
        self.lock.metadata = None;
        self.metadata_retired = true;
        true
    }
}

impl<E: ProtectedFailure + Error + 'static> WriterWitnessOriginalsV1<E> {
    /// Borrows the earliest reached native or projected refusal in probe order.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        for probe in [&self.directory, &self.journal, &self.lock] {
            if let Some(Err(cause)) = &probe.metadata { return Some(cause); }
            if let Some(Err(cause)) = &probe.projected { return Some(cause); }
        }
        self.witness.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| self.comparison.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as &(dyn Error + 'static)))
    }
}

impl<E: ProtectedFailure> Default for WriterWitnessOriginalsV1<E> {
    fn default() -> Self { Self::new() }
}

impl<P> ProtectedJournalLocation<P> {
    /// Samples the actual Directory/Journal/Lock at the original probe frontiers.
    ///
    /// # Errors
    /// Retains native metadata refusal or reentry and returns a stopping marker.
    /// The same original's `failure()` exposes its actual owned native cause.
    pub fn writer_witness_retaining_v1<E: ProtectedFailure>(&self, file: &File, lock: &File,
        originals: &mut WriterWitnessOriginalsV1<E>) -> Result<(), E>
    {
        originals.enter_once()?;
        let directory = &self.directory;
        originals.witness = Some((|| {
            sample_recipe!(Retained, originals, directory, file, lock)
        })());
        if matches!(originals.witness, Some(Ok(_))) { Ok(()) } else { Err(E::BOUNDARY) }
    }

    /// Compares the same writer with the original lazy Directory/Journal/Lock order.
    ///
    /// # Errors
    /// Retains actual native or first stale-name refusal without later probes.
    /// Reentry closes the sink without replacing any reached original result.
    pub fn require_writer_witness_retaining_v1<E: ProtectedFailure>(&self,
        file: &File, lock: &File, witness: &ProtectedWriterNameWitness,
        originals: &mut WriterWitnessOriginalsV1<E>) -> Result<(), E>
    {
        originals.enter_once()?;
        let directory = &self.directory;
        originals.comparison = Some((|| {
            compare_recipe!(Retained, originals, directory, file, lock, witness)
        })());
        if matches!(originals.comparison, Some(Ok(()))) { Ok(()) }
        else { Err(E::STALE_NAME) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    enum Failure { Io(io::Error), Boundary, Stale }

    impl From<io::Error> for Failure {
        fn from(cause: io::Error) -> Self { Self::Io(cause) }
    }

    impl std::fmt::Display for Failure {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Io(cause) => std::fmt::Display::fmt(cause, formatter),
                Self::Boundary => formatter.write_str("boundary"),
                Self::Stale => formatter.write_str("stale"),
            }
        }
    }

    impl Error for Failure {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            match self { Self::Io(cause) => Some(cause), _ => None }
        }
    }

    impl ProtectedFailure for Failure {
        const BOUNDARY: Self = Self::Boundary;
        const UNSUPPORTED_OPEN: Self = Self::Boundary;
        const STALE_NAME: Self = Self::Stale;
    }

    #[test]
    fn single_identity_retains_the_actual_projection_without_other_witness_probes() {
        let directory = tempfile::tempdir().unwrap();
        let file = File::create(directory.path().join("identity")).unwrap();
        let expected = FileIdentity::of::<Failure>(&file).unwrap();
        let mut original = FileIdentityOriginalsV1::<Failure>::new();

        FileIdentity::of_retaining_v1(&file, &mut original).unwrap();

        assert!(original.completed_identity() == Some(&expected));
        assert!(matches!(original.probe.metadata, Some(Ok(_))));
        assert!(original.take_completed_identity_once() == Some(expected));
        assert!(original.retire_positive_metadata_once_v1());
        assert!(original.probe.metadata.is_none());
        assert!(original.take_completed_identity_once().is_none());
        assert!(FileIdentity::of_retaining_v1(&file, &mut original).is_err());
        assert!(original.completed_identity().is_none());
    }

    #[test]
    fn retained_sample_matches_the_actual_ordinary_probe_and_retires_only_positive_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let file = File::create(directory.path().join("journal")).unwrap();
        let lock = File::create(directory.path().join("lock")).unwrap();
        let location = ProtectedJournalLocation::from_original_parts((
            File::open(directory.path()).unwrap(), String::from("journal"), 0, (),
        ));
        // This ordinary physical fixture establishes no protected role or C/R.
        let ordinary = location.writer_witness::<Failure>(&file, &lock).unwrap();
        let mut originals = WriterWitnessOriginalsV1::<Failure>::new();

        location.writer_witness_retaining_v1(&file, &lock, &mut originals).unwrap();

        let retained = originals.completed_witness().unwrap();
        assert!(retained.directory() == ordinary.directory());
        assert!(retained.file() == ordinary.file());
        assert!(retained.lock() == ordinary.lock());
        assert!(matches!(originals.directory.metadata, Some(Ok(_))));
        assert!(matches!(originals.journal.metadata, Some(Ok(_))));
        assert!(matches!(originals.lock.metadata, Some(Ok(_))));
        assert!(originals.retire_positive_metadata_once_v1());
        assert!(originals.directory.metadata.is_none());
        assert!(originals.journal.metadata.is_none());
        assert!(originals.lock.metadata.is_none());
        assert!(originals.failure().is_none());
        let taken = originals.take_completed_witness_once().unwrap();
        assert!(taken.file() == ordinary.file());
        assert!(originals.take_completed_witness_once().is_none());
        assert!(!originals.retire_positive_metadata_once_v1());
    }

    #[test]
    fn first_directory_mismatch_keeps_its_original_and_never_probes_journal_or_lock() {
        let actual_directory = tempfile::tempdir().unwrap();
        let different_directory = tempfile::tempdir().unwrap();
        let file = File::create(actual_directory.path().join("journal")).unwrap();
        let lock = File::create(actual_directory.path().join("lock")).unwrap();
        let actual = ProtectedJournalLocation::from_original_parts((
            File::open(actual_directory.path()).unwrap(), String::from("journal"), 0, (),
        ));
        let different = ProtectedJournalLocation::from_original_parts((
            File::open(different_directory.path()).unwrap(), String::from("journal"), 0, (),
        ));
        let expected = different.writer_witness::<Failure>(&file, &lock).unwrap();
        let mut originals = WriterWitnessOriginalsV1::<Failure>::new();

        assert!(actual.require_writer_witness_retaining_v1(
            &file, &lock, &expected, &mut originals,
        ).is_err());

        assert!(matches!(originals.directory.metadata, Some(Ok(_))));
        assert!(matches!(originals.directory.projected, Some(Ok(_))));
        assert!(originals.journal.metadata.is_none());
        assert!(originals.lock.metadata.is_none());
        assert!(matches!(originals.comparison, Some(Err(Failure::Stale))));
        let first = originals.failure().unwrap().downcast_ref::<Failure>().unwrap() as *const Failure;
        assert!(!originals.retire_positive_metadata_once_v1());
        assert!(actual.require_writer_witness_retaining_v1(
            &file, &lock, &expected, &mut originals,
        ).is_err());
        assert_eq!(first, originals.failure().unwrap().downcast_ref::<Failure>().unwrap() as *const Failure);
        assert!(originals.journal.metadata.is_none());
        assert!(originals.lock.metadata.is_none());
    }

    #[test]
    fn actual_native_metadata_error_remains_the_same_borrowed_cause_after_closure() {
        let directory = tempfile::tempdir().unwrap();
        let raw = std::fs::metadata(directory.path().join("missing"));
        assert!(raw.is_err());
        let mut originals = WriterWitnessOriginalsV1::<Failure>::new();
        // Exercise the SAME private result destination with an actual native
        // Metadata Err. This tests result custody, not a protected role entry.
        RetainedMetadata(&mut originals.directory.metadata).store(raw);
        originals.directory.projected = Some(Err(Failure::Boundary));
        originals.entered = true;
        originals.witness = Some(Err(Failure::Boundary));
        let first = originals.failure().unwrap().downcast_ref::<io::Error>().unwrap() as *const io::Error;

        assert!(originals.enter_once().is_err());

        assert_eq!(first, originals.failure().unwrap().downcast_ref::<io::Error>().unwrap() as *const io::Error);
        assert!(!originals.retire_positive_metadata_once_v1());
        assert!(originals.completed_witness().is_none());
        let footprint = WriterWitnessOriginalsV1::<Failure>::receiving_footprint_v1().unwrap();
        assert_eq!(footprint.open_files, 0);
        assert_eq!(footprint.metadata_cells, 0);
        let identity = FileIdentityOriginalsV1::<Failure>::receiving_footprint_v1().unwrap();
        assert_eq!(identity.open_files, 0);
        assert_eq!(identity.metadata_cells, 0);
    }
}
