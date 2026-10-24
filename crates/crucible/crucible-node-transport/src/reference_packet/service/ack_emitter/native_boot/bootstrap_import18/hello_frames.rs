//! Retains the actual Hello journal and literal bank under original initial custody.

use super::*;
use crate::native_hello::{OriginalNativeHelloJournal, OriginalNativeHelloReservation};
use crate::reference_packet::service::PacketNative5SourceLaunch;

/// Admits actual retained Hello storage around its allocating constructor.
pub(in super::super) trait OriginalImport18HelloFramesAdmission {
    /// Admits the stored constructor row before either backing allocation.
    ///
    /// # Errors
    /// Refuses unavailable original credit or incomplete enclosing custody.
    fn construct_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        construction: [usize; 3],
    ) -> Result<(), ProviderError>;

    /// Observes surviving journal/bank backing after either constructor outcome.
    ///
    /// # Errors
    /// Refuses unavailable original credit or an incomplete whole-owner census.
    fn finish_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        actual_backing: usize,
    ) -> Result<(), ProviderError>;
}

impl OriginalImport18RawBootstrap {
    /// Reserves the native Hello journal once after full definitions and roster.
    ///
    /// The original owner retains the empty constructor and every bank partial.
    /// This creates no public socket, exchange, negotiation, ACK or native model.
    ///
    /// # Errors
    /// Refuses re-entry, incomplete initial/roster custody, stale original guards,
    /// unavailable admission, framing/reservation failure or terminal custody.
    pub(in super::super) fn construct_hello_frames_data(
        &mut self,
        admission: &dyn OriginalImport18HelloFramesAdmission,
    ) -> Result<(), ProviderError> {
        if self.hello_frames_started {
            return Err(refused());
        }
        self.hello_frames_started = true;
        let outcome = self.construct_current_hello_frames(admission);
        let terminal = self.typed_bodies_data().map(|_| ());
        outcome?;
        terminal?;
        self.hello_frames_complete = true;
        Ok(())
    }

    fn construct_current_hello_frames(
        &mut self,
        admission: &dyn OriginalImport18HelloFramesAdmission,
    ) -> Result<(), ProviderError> {
        if !self.initial_reconstructed || !self.selection_authenticated || !self.hello_complete {
            return Err(refused());
        }
        self.typed_bodies_data()?;
        self.admit_source_row(self.initial_construction.as_ref().ok_or_else(refused)?.row)?;
        let launch = self.typed_bodies_data()?.launch.launch_data();
        let row = construction_data(launch)?;
        self.hello_frames_row = Some(row);
        admission.construct_data(self, row)?;
        let launch = self.typed_bodies_data()?.launch.launch_data();
        let (maximum, nesting) = limits_data(launch)?;
        let outcome = OriginalNativeHelloReservation::reserve_into_data(
            maximum,
            nesting,
            &mut self.hello_frames,
        );
        let terminal = self
            .hello_frames_backing_data()
            .and_then(|actual| admission.finish_data(self, actual));
        outcome?;
        terminal
    }

    /// Lends this same completed physical journal under original raw/typed guards.
    ///
    /// The caller independently admits inspection. Only Copy DATA may return.
    ///
    /// # Errors
    /// Refuses incomplete construction, stale custody, a callback or terminal guard.
    pub(in super::super) fn with_hello_frames_data<R: Copy>(
        &self,
        inspect: impl FnOnce(&OriginalNativeHelloJournal) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        if !self.hello_frames_complete {
            return Err(refused());
        }
        self.typed_bodies_data()?;
        let outcome = self
            .hello_frames
            .as_ref()
            .ok_or_else(refused)?
            .with_journal_data(inspect);
        let terminal = self.typed_bodies_data().map(|_| ());
        let result = outcome?;
        terminal?;
        Ok(result)
    }

    /// Counts actual surviving Hello literal and shared-bank backing.
    ///
    /// # Errors
    /// Refuses a stale creator, unavailable bank borrow or checked overflow.
    pub(super) fn hello_frames_backing_data(&self) -> Result<usize, ProviderError> {
        self.hello_frames
            .as_ref()
            .map_or(Ok(0), OriginalNativeHelloReservation::retained_backing_data)
    }

    /// Names separate actual journal inspection and original guard controls.
    pub(in super::super) fn hello_frames_loan_counter_scratch_data<R: Copy>() -> usize {
        OriginalNativeHelloReservation::journal_loan_counter_scratch_data::<R>()
            + counter_scratch_data()
            + private_body_owner_counter_scratch_data()
            + native_import18_private_prefix_counter_scratch_data()
    }
}

/// Quotes the defining journal/bank constructor from actual launch framing.
///
/// # Errors
/// Refuses invalid original framing or checked constructor-layout overflow.
pub(in crate::reference_packet::service) fn construction_data(
    launch: &PacketNative5SourceLaunch,
) -> Result<[usize; 3], ProviderError> {
    let (maximum, nesting) = limits_data(launch)?;
    let mut row = OriginalNativeHelloReservation::construction_data(maximum, nesting)?;
    row[2] = row[2]
        .checked_add(counter_scratch_data())
        .ok_or_else(exhausted)?;
    Ok(row)
}

fn limits_data(launch: &PacketNative5SourceLaunch) -> Result<(usize, usize), ProviderError> {
    Ok((
        usize::try_from(launch.limits.frame_bytes.get()).map_err(|_| refused())?,
        usize::try_from(launch.limits.nesting.get()).map_err(|_| refused())?,
    ))
}

/// Names the exact framing, original admission and terminal census controls.
pub(in crate::reference_packet::service) fn counter_scratch_data() -> usize {
    OriginalNativeHelloReservation::counter_scratch_data()
        + size_of::<&PacketNative5SourceLaunch>() * 2
        + size_of::<&OriginalImport18RawBootstrap>()
        + size_of::<&mut OriginalImport18RawBootstrap>()
        + size_of::<&dyn OriginalImport18HelloFramesAdmission>()
        + size_of::<&OriginalNativeHelloReservation>()
        + size_of::<Option<&OriginalNativeHelloReservation>>()
        + size_of::<[usize; 3]>()
        + size_of::<Result<[usize; 3], ProviderError>>()
        + size_of::<(usize, usize)>()
        + size_of::<Result<(usize, usize), ProviderError>>()
        + size_of::<usize>() * 2
        + size_of::<Result<(), ProviderError>>() * 4
}
