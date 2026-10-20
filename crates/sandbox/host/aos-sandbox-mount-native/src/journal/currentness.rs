//! Rechecks the same Mount writer through canonical retained name observations.
//!
//! Admission checks require healthy custody. Independently owed posts instead
//! use the same native view without reopening authority or checking health.

use aos_sandbox_broker::canonical_journal::captured::CapturedWriterGuardRecipeV1;
use aos_sandbox_broker::writer_currentness::WriterCurrentnessOriginalsV1;
use aos_sandbox_journal::protected_storage::ProtectedWriterNameWitness;

use super::*;

/// Retains actual same-writer path/name results and their first native cause.
pub type MountJournalCurrentnessOriginalsV1 = WriterCurrentnessOriginalsV1<MountJournalErrorV1>;

impl MountJournalV1 {
    pub(crate) fn require_protected_location(
        &self,
        directory: &Path,
        name: &str,
        uid: u32,
        limits: JournalLimits,
    ) -> Result<(), JournalError> {
        let read = self.native.read_view_v1();
        if read.protected_name() != Some(name)
            || read.protected_uid() != Some(uid)
            || read.limits() != limits
        {
            return Err(JournalError::Mechanical(MechanicalError::ProtectedBoundary));
        }
        if let Some(owner) = &self.captured {
            return owner
                .observe_guard_v1(read, CapturedWriterGuardRecipeV1::Directory(directory, uid));
        }
        let _current = read.require_directory::<JournalError>(directory, uid)?;
        self.ensure_healthy()
    }

    /// Rechecks the exact retained root-owned directory and both file names.
    ///
    /// # Errors
    /// Refuses an unhealthy or replaced writer and preserves actual native IO.
    pub fn validate_held_root_owned_at(
        &self,
        directory: impl AsRef<Path>,
        name: &str,
    ) -> Result<(), JournalError> {
        self.require_protected_location(directory.as_ref(), name, 0, self.native.limits())?;
        self.require_protected_names_current()
    }

    /// Rechecks only this same writer's protected file and lock names.
    ///
    /// # Errors
    /// Refuses poison, missing protected custody or either changed native name.
    pub fn validate_held_protected_names(&self) -> Result<(), JournalError> {
        self.ensure_protected_authority()?;
        self.require_protected_names_current()
    }

    /// Captures the existing physical witness of this held writer.
    ///
    /// # Errors
    /// Preserves missing custody or the original physical metadata failure.
    pub fn protected_writer_name_witness(
        &self,
    ) -> Result<ProtectedWriterNameWitness, JournalError> {
        self.native.read_view_v1().writer_witness()
    }

    /// Rejoins a physical witness with this same protected writer and names.
    ///
    /// # Errors
    /// Refuses another writer, changed names or native observation failure.
    pub fn validate_protected_writer_name_witness(
        &self,
        witness: &ProtectedWriterNameWitness,
    ) -> Result<(), JournalError> {
        self.require_protected_names_current()?;
        self.native.read_view_v1().require_writer_witness(witness)
    }

    pub(super) fn require_protected_names_current(&self) -> Result<(), JournalError> {
        let read = self.native.read_view_v1();
        if let Some(owner) = &self.captured {
            return owner.observe_guard_v1(read, CapturedWriterGuardRecipeV1::Names);
        }
        read.require_names()
    }

    /// Retains the existing directory-then-names admission recipe.
    ///
    /// # Errors
    /// Preserves original scope, path, metadata or name failures in the sink.
    pub fn validate_held_owned_at_for_uid_retaining(
        &self,
        directory: impl AsRef<Path>,
        name: &str,
        uid: u32,
        original: &mut MountJournalCurrentnessOriginalsV1,
    ) -> Result<(), JournalError> {
        original.begin(false)?;
        let result = (|| {
            self.require_location_in_original(
                directory.as_ref(),
                name,
                uid,
                self.native.limits(),
                original,
            )?;
            self.native.read_view_v1().observe_names_into(original)
        })();
        original.finish(result)
    }

    pub(crate) fn require_protected_location_retaining(
        &self,
        directory: &Path,
        name: &str,
        uid: u32,
        limits: JournalLimits,
        original: &mut MountJournalCurrentnessOriginalsV1,
    ) -> Result<(), JournalError> {
        original.begin(false)?;
        let result = self.require_location_in_original(directory, name, uid, limits, original);
        original.finish(result)
    }

    fn require_location_in_original(
        &self,
        directory: &Path,
        name: &str,
        uid: u32,
        limits: JournalLimits,
        original: &mut MountJournalCurrentnessOriginalsV1,
    ) -> Result<(), JournalError> {
        let read = self.native.read_view_v1();
        if read.protected_name() != Some(name)
            || read.protected_uid() != Some(uid)
            || read.limits() != limits
        {
            return Err(JournalError::Mechanical(MechanicalError::ProtectedBoundary));
        }
        read.observe_directory_binding_into(directory, uid, original)?;
        self.ensure_healthy()
    }

    /// Attempts an already-owed names post despite a prior primary refusal.
    ///
    /// # Errors
    /// Retains absent custody, repeated entry or actual original name failure.
    pub fn observe_held_names_post_retaining_v1(
        &self,
        original: &mut MountJournalCurrentnessOriginalsV1,
    ) -> Result<(), JournalError> {
        original.begin(true)?;
        let result = self.native.read_view_v1().observe_names_into(original);
        original.finish(result)
    }
}
