//! Validates the original immutable launch under independently admitted storage.
//!
//! The unchanged validator constructs temporary coordinator/policy DATA only.
//! It opens no effect path and creates no live Control, model, native policy,
//! bootstrap ACK or phase permission. All original decoded owners stay in place.

use super::*;
use crate::reference_packet::service::PacketNative5SourceLaunch;
use crate::reference_packet::service::complete_restore::import18::OriginalImport18DecodedBodyLoans;
use crate::reference_packet::service::native_startup::PacketNative5LaunchValidationStorage;

/// Admits the complete validator and observes its surviving original owner.
pub(in super::super) trait OriginalImport18LaunchValidationAdmission {
    /// Admits actual validation work beside every original retained population.
    ///
    /// # Errors
    /// Refuses incomplete original funding or changed enclosing custody.
    fn construct_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        row: [usize; 3],
    ) -> Result<(), ProviderError>;

    /// Observes original custody after either outcome of the real validator.
    ///
    /// The pure validator retains no new backing. Its returned diagnostic and
    /// temporary constructors stay covered by the admitted construction window.
    ///
    /// # Errors
    /// Refuses incomplete whole-owner observation or unavailable original credit.
    fn finish_data(&self, original: &OriginalImport18RawBootstrap) -> Result<(), ProviderError>;
}

/// Retains one spent validation occurrence and its original pre-read cut.
pub(super) struct Attempt {
    cut: OperationalDeadline,
    started: bool,
    complete: bool,
    row: Option<[usize; 3]>,
}

impl Attempt {
    /// Initializes fixed controls before any private bytes are received.
    pub(super) fn empty_data(cut: OperationalDeadline) -> Self {
        Self {
            cut,
            started: false,
            complete: false,
            row: None,
        }
    }

    /// Returns the independently calculated row, including after terminal refusal.
    #[cfg(test)]
    pub(super) fn row_data(&self) -> Option<[usize; 3]> {
        self.row
    }

    fn guard_cut(&self, cut: OperationalDeadline) -> Result<(), ProviderError> {
        if cut != self.cut || self.cut.is_expired() {
            return Err(refused());
        }
        Ok(())
    }

    fn completed_data(&self, cut: OperationalDeadline) -> Result<(), ProviderError> {
        self.guard_cut(cut)?;
        if !self.complete {
            return Err(refused());
        }
        Ok(())
    }
}

impl OriginalImport18RawBootstrap {
    /// Validates the actual original launch once without native model installation.
    ///
    /// The reconstructed initial row covers the allocation-free quote prewalk
    /// and actual formatter window before the complete constructor quote runs.
    /// Independent admission precedes the unchanged full launch validator.
    /// Every refusal spends this occurrence; original owners and the quote remain.
    ///
    /// # Errors
    /// Refuses retry, absent initial reconstruction, stale original custody/cut,
    /// short construction admission, invalid launch or terminal observation.
    pub(in super::super) fn validate_launch_data(
        &mut self,
        admission: &dyn OriginalImport18LaunchValidationAdmission,
    ) -> Result<(), ProviderError> {
        if self.launch_validation.started {
            return Err(refused());
        }
        self.launch_validation.started = true;

        let outcome = self.validate_current_launch(admission);
        let terminal = self.guard_launch_validation_inputs();
        outcome?;
        terminal?;
        self.launch_validation.complete = true;
        Ok(())
    }

    fn guard_launch_validation_inputs(&self) -> Result<(), ProviderError> {
        self.launch_validation.guard_cut(self.cut)?;
        if !self.initial_reconstructed {
            return Err(refused());
        }
        self.typed_bodies_data().map(|_| ())
    }

    fn validate_current_launch(
        &mut self,
        admission: &dyn OriginalImport18LaunchValidationAdmission,
    ) -> Result<(), ProviderError> {
        self.guard_launch_validation_inputs()?;
        self.admit_source_row(self.initial_construction.as_ref().ok_or_else(refused)?.row)?;
        let row = construction_data(
            self.typed_bodies_data()?.launch.launch_data(),
            self.bounds.requested_peak,
        )?;
        self.launch_validation.row = Some(row);
        admission.construct_data(self, row)?;
        self.guard_launch_validation_inputs()?;

        let outcome = self.typed_bodies_data()?.launch.launch_data().validate();
        // Observe the same owner even when the pure validator returns an error.
        let terminal = admission.finish_data(self);
        outcome?;
        terminal
    }

    /// Lends the same validated launch while original custody remains current.
    ///
    /// Only Copy DATA returns; neither the immutable shared owner nor its
    /// children move. This completed pure validation issues no native authority.
    /// The caller independently admits inspection and its result controls.
    ///
    /// # Errors
    /// Refuses incomplete/refused validation, changed/expired original custody,
    /// callback refusal or any terminal original input guard.
    pub(in super::super) fn with_validated_launch_data<R: Copy>(
        &self,
        inspect: impl FnOnce(&PacketNative5SourceLaunch) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.launch_validation.completed_data(self.cut)?;
        self.guard_launch_validation_inputs()?;
        let outcome = inspect(self.typed_bodies_data()?.launch.launch_data());
        let terminal = self
            .guard_launch_validation_inputs()
            .and_then(|()| self.launch_validation.completed_data(self.cut));
        let result = outcome?;
        terminal?;
        Ok(result)
    }
}

/// Quotes the complete pure validator before invoking its real constructors.
///
/// The defining initial formatter quote and counter admit this walk first.
/// Original retained backing remains independently charged by the bootstrap.
///
/// # Errors
/// Refuses unsupported geometry, arithmetic overflow or an insufficient peak.
pub(in crate::reference_packet::service) fn construction_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    let (temporary, scratch) = launch.validation_construction_storage_data(maximum)?;
    let scratch = scratch
        .checked_add(counter_scratch_data())
        .ok_or_else(refused)?;
    if temporary
        .checked_add(scratch)
        .is_none_or(|peak| peak > maximum)
    {
        return Err(refused());
    }
    Ok([0, temporary, scratch])
}

/// Names prewalk, actual launch loans, terminal and generic unit-result controls.
pub(in crate::reference_packet::service) fn counter_scratch_data() -> usize {
    PacketNative5SourceLaunch::validation_construction_counter_scratch_data()
        + private_body_owner_counter_scratch_data()
        + size_of::<Attempt>()
        + size_of::<&OriginalImport18RawBootstrap>() * 3
        + size_of::<&mut OriginalImport18RawBootstrap>() * 2
        + size_of::<&dyn OriginalImport18LaunchValidationAdmission>()
        + size_of::<&PacketNative5SourceLaunch>() * 2
        + size_of::<OperationalDeadline>() * 2
        + size_of::<[usize; 3]>() * 2
        + size_of::<Option<[usize; 3]>>()
        + size_of::<Result<[usize; 3], ProviderError>>()
        + size_of::<(usize, usize)>()
        + size_of::<Result<(usize, usize), ProviderError>>()
        + size_of::<Result<OriginalImport18DecodedBodyLoans<'static>, ProviderError>>() * 2
        + size_of::<OriginalImport18DecodedBodyLoans<'static>>() * 2
        + size_of::<Result<(), ProviderError>>() * 5
        + size_of::<usize>() * 2
        + size_of::<Option<usize>>()
        + size_of::<bool>()
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original import18 launch validation refused")
}
