//! Retains and binds the original public descriptor without public protocol I/O.

use super::*;
use crate::client::OriginalNativePublicBirthChannel;

/// Admits the original public channel's physical deadline constructor.
pub(in super::super) trait OriginalImport18PublicChannelAdmission {
    /// Admits the independently derived row before either shared allocation.
    ///
    /// # Errors
    /// Refuses unavailable original credit or incomplete enclosing custody.
    fn construct_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        construction: [usize; 3],
    ) -> Result<(), ProviderError>;

    /// Observes actual surviving deadline backing after either outcome.
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
    /// Retains the public descriptor before the first private read or allocation.
    ///
    /// The caller keeps its input if this destination is occupied. The same
    /// descriptor remains here through subsequent credential/admission failures.
    ///
    /// # Errors
    /// Refuses an already started private read, occupied destination, missing
    /// descriptor or foreign creator. No I/O or socket duplication occurs.
    pub(in super::super) fn retain_public_channel_data(
        &mut self,
        stream: &mut Option<UnixStream>,
    ) -> Result<(), ProviderError> {
        if self.started {
            return Err(refused());
        }
        OriginalNativePublicBirthChannel::retain_into_data(
            stream,
            self.cut,
            &mut self.public_channel,
        )?;
        self.authenticate_origin()
    }

    /// Binds the retained socket once under the unchanged private receiver cut.
    ///
    /// Only completed initial, immutable selection, Hello roster and journal
    /// checks permit construction. This performs no public read/write and
    /// creates no negotiated feature, ACK, native policy, model or readiness.
    ///
    /// # Errors
    /// Refuses re-entry, incomplete custody, missing public descriptor, stale
    /// original guards, admission failure or physical cut/credential failure.
    pub(in super::super) fn construct_public_channel_data(
        &mut self,
        admission: &dyn OriginalImport18PublicChannelAdmission,
    ) -> Result<(), ProviderError> {
        if self.public_channel_started {
            return Err(refused());
        }
        self.public_channel_started = true;
        let outcome = self.construct_current_public_channel(admission);
        let terminal = self.typed_bodies_data().map(|_| ());
        outcome?;
        terminal?;
        self.public_channel_complete = true;
        Ok(())
    }

    fn construct_current_public_channel(
        &mut self,
        admission: &dyn OriginalImport18PublicChannelAdmission,
    ) -> Result<(), ProviderError> {
        if !self.initial_reconstructed
            || !self.selection_authenticated
            || !self.hello_complete
            || !self.hello_frames_complete
            || self.public_channel.is_none()
        {
            return Err(refused());
        }
        self.typed_bodies_data()?;
        self.admit_source_row(self.initial_construction.as_ref().ok_or_else(refused)?.row)?;
        let row = construction_data()?;
        self.public_channel_row = Some(row);
        admission.construct_data(self, row)?;
        let outcome = self
            .public_channel
            .as_mut()
            .ok_or_else(refused)?
            .bind_data();
        let terminal = self
            .public_channel_backing_data()
            .and_then(|actual| admission.finish_data(self, actual));
        outcome?;
        terminal
    }

    /// Checks the same completed physical binding under original typed custody.
    ///
    /// # Errors
    /// Refuses incomplete binding, changed creator/socket/deadline or expiration.
    pub(in super::super) fn authenticate_public_channel_data(&self) -> Result<(), ProviderError> {
        if !self.public_channel_complete {
            return Err(refused());
        }
        self.typed_bodies_data()?;
        let outcome = self
            .public_channel
            .as_ref()
            .ok_or_else(refused)?
            .completed_data(self.cut);
        let terminal = self.typed_bodies_data().map(|_| ());
        outcome?;
        terminal
    }

    /// Counts actual surviving shared cut backing, independently of expiration.
    ///
    /// # Errors
    /// Refuses foreign creator or checked requested-layout overflow.
    pub(super) fn public_channel_backing_data(&self) -> Result<usize, ProviderError> {
        self.public_channel.as_ref().map_or(
            Ok(0),
            OriginalNativePublicBirthChannel::retained_backing_data,
        )
    }
}

/// Prices the defining physical channel constructor, without a public exchange.
///
/// # Errors
/// Refuses checked requested-layout overflow.
pub(in crate::reference_packet::service) fn construction_data() -> Result<[usize; 3], ProviderError>
{
    let mut row = OriginalNativePublicBirthChannel::construction_data()?;
    row[2] = row[2]
        .checked_add(counter_scratch_data())
        .ok_or_else(exhausted)?;
    Ok(row)
}

/// Names actual channel retention, admission and terminal correspondence controls.
pub(in crate::reference_packet::service) fn counter_scratch_data() -> usize {
    OriginalNativePublicBirthChannel::counter_scratch_data()
        + size_of::<&OriginalImport18RawBootstrap>()
        + size_of::<&mut OriginalImport18RawBootstrap>()
        + size_of::<&dyn OriginalImport18PublicChannelAdmission>()
        + size_of::<&OriginalNativePublicBirthChannel>()
        + size_of::<Option<&OriginalNativePublicBirthChannel>>()
        + size_of::<&mut Option<UnixStream>>()
        + size_of::<[usize; 3]>()
        + size_of::<Result<[usize; 3], ProviderError>>()
        + size_of::<usize>()
        + size_of::<Result<(), ProviderError>>() * 4
}
