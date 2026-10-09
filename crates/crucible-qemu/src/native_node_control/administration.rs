//! Original reader preparation and historical observations over edition five.
//!
//! This transport supplies no modeled execution operation. Unknown native roots
//! stay explicit in every retained source observation; successful enrollment is
//! neither a stop attestation nor readiness or capture permission.

use std::os::unix::fs::MetadataExt;

use crucible_protocol::node_control::{
    NativeAdministrativeFacts, NativeAdministrativePreparation, NativeChannel, NativeCommandError,
    NativeControlEdition, NativeFrame, NativePhasePreparation,
};

use super::{NativeLaunchEndpoint, NativeQemuControlError};

/// Retains one prepared endpoint and the original source-observed reader record.
pub struct NativeAdministrationTransport {
    channel: NativeChannel,
    preparation: NativeAdministrativePreparation,
    original: Option<NativeAdministrativeFacts>,
    expected_process: Option<u32>,
    requested: bool,
    failed: bool,
}

impl NativeAdministrationTransport {
    /// Measures the actual inherited endpoint and queues complete original launch material.
    ///
    /// The installed launcher must pass the returned endpoint into the named
    /// descriptor slot and pin all original commitments before construction.
    /// These bytes provide compatibility correlation, never node qualification.
    ///
    /// # Errors
    /// Rejects invalid companion policy/descriptor or socket, metadata and framing failure.
    pub fn prepare(
        phase: NativePhasePreparation,
        policy_digest: [u8; 32],
        descriptor_slot: i32,
    ) -> Result<(Self, NativeLaunchEndpoint), NativeQemuControlError> {
        phase.validate()?;
        let edition = NativeControlEdition::Administration;
        let (channel, provider) = NativeChannel::supervised_pair_for_edition(edition)?;
        let descriptor = provider
            .prepared_descriptor()
            .try_clone_to_owned()
            .map_err(crucible_protocol::node_control::NativeChannelError::from)?;
        let metadata = std::fs::File::from(descriptor)
            .metadata()
            .map_err(crucible_protocol::node_control::NativeChannelError::from)?;
        let preparation = NativeAdministrativePreparation {
            phase: phase.clone(),
            policy_digest,
            descriptor_slot,
            socket_device: metadata.dev(),
            socket_inode: metadata.ino(),
        };
        preparation.validate()?;
        let scope_digest = phase.initialization.preparation.scope.identity_digest()?;
        if !channel.send(&NativeFrame::PrepareAdministration(Box::new(
            preparation.clone(),
        )))? {
            return Err(NativeCommandError::ResourceLimit.into());
        }
        Ok((
            Self {
                channel,
                preparation,
                original: None,
                expected_process: None,
                requested: false,
                failed: false,
            },
            NativeLaunchEndpoint {
                socket: provider.into_prepared_socket(),
                scope_digest,
                edition,
                initialization: Some(phase.initialization.clone()),
                phase_projection: Some(phase),
            },
        ))
    }

    /// Returns the immutable full endpoint preparation for the original native launch.
    pub fn preparation(&self) -> &NativeAdministrativePreparation {
        &self.preparation
    }

    /// Pins the actual supervised child process before accepting any native facts.
    ///
    /// # Errors
    /// Rejects zero, conflicting or late process bindings. This is data correlation,
    /// not an independently qualified execution-owner or readiness certificate.
    pub fn bind_process(&mut self, process_id: u32) -> Result<(), NativeQemuControlError> {
        if process_id == 0
            || self.requested
            || self.original.is_some()
            || self
                .expected_process
                .is_some_and(|original| original != process_id)
        {
            return Err(NativeCommandError::Conflict.into());
        }
        self.expected_process = Some(process_id);
        Ok(())
    }

    /// Requests the same original historical reader registration without native effects.
    ///
    /// # Errors
    /// Rejects unbound process custody, sticky divergence or physical socket failure.
    pub fn request_original(&mut self) -> Result<bool, NativeQemuControlError> {
        if self.failed || self.expected_process.is_none() {
            return Err(NativeCommandError::Conflict.into());
        }
        self.requested = true;
        Ok(self.channel.send(&NativeFrame::QueryAdministration {
            prepared_scope_hash: self
                .preparation
                .phase
                .initialization
                .preparation
                .scope
                .identity_digest()?,
            administration_commitment: self.preparation.identity_digest()?,
        })?)
    }

    /// Accepts only the matching original enrollment, retaining it before returning a view.
    ///
    /// Identical retry packets recover the same record. A differing record
    /// permanently refuses this transport; it never triggers reenrollment.
    ///
    /// # Errors
    /// Rejects unsolicited, foreign or changed facts and socket/codec failures.
    pub fn receive_original(
        &mut self,
    ) -> Result<Option<&NativeAdministrativeFacts>, NativeQemuControlError> {
        if self.failed || !self.requested {
            return Err(NativeCommandError::Conflict.into());
        }
        let frame = match self.channel.receive() {
            Ok(frame) => frame,
            Err(error) => {
                self.failed = true;
                return Err(error.into());
            }
        };
        let Some(frame) = frame else {
            return Ok(None);
        };
        let NativeFrame::AdministrationFacts(facts) = frame else {
            self.failed = true;
            return Err(NativeCommandError::Conflict.into());
        };
        // Retain the first full observed source record before validating it. A
        // mismatch leaves that original evidence available for containment.
        if let Some(original) = &self.original {
            if original != facts.as_ref() {
                self.failed = true;
                return Err(NativeCommandError::Conflict.into());
            }
        } else {
            self.original = Some(*facts);
        }
        let original = self.original.as_ref().ok_or(NativeCommandError::Conflict)?;
        if original.validate_against(&self.preparation).is_err()
            || Some(original.process_id.get()) != self.expected_process.map(u64::from)
        {
            self.failed = true;
            return Err(NativeCommandError::Conflict.into());
        }
        Ok(self.original.as_ref())
    }
}

#[cfg(test)]
#[path = "administration_tests.rs"]
mod tests;
