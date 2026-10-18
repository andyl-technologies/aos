//! Checks exact native connection-identity fields as inert retained history.

use super::*;
use crate::reference_packet::Native5Policy;
use crate::transport::original_frames::OriginalFrameReservation;

/// Preserves the complete ack identity DATA without a live connection identity.
pub(crate) struct HistoricalAckIdentity17 {
    actor_group: usize,
    frames_group: usize,
    policy_group: usize,
    pub(crate) authority: HistoricalAuthority17,
    pub(crate) admit_id: Id,
    pub(crate) admit_sequence: U64,
    pub(crate) literal_index: usize,
    pub(crate) literal_length: usize,
    pub(crate) literal_digest: [u8; 32],
}

impl HistoricalAckIdentity17 {
    /// Returns original actor, frame-bank and policy group ordinals.
    pub(crate) const fn group_ids_data(&self) -> (usize, usize, usize) {
        (self.actor_group, self.frames_group, self.policy_group)
    }

    /// Reads complete fields using one caller-owned capacity and alias ledger.
    ///
    /// # Errors
    /// Refuses malformed fields, unavailable backing or changed shared groups.
    pub(crate) fn read_settled17_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        Self::read_settled17_fields_data(input, ledger, build).map(|fields| fields.0)
    }

    /// Returns same-pass group IDs even during allocation-free validation.
    ///
    /// # Errors
    /// Refuses unknown fields/roles, row disagreement or incomplete shared roots.
    pub(crate) fn read_settled17_fields_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<(Option<Self>, (usize, usize, usize)), ProviderError> {
        let mut fields = Fields::object(input)?;
        exact(
            fields.named("schema")?,
            "source-private.native-ack-connection-identity-history/17",
        )?;
        exact(fields.named("actor_role")?, "native-connection-actor")?;
        let actor_group = reference::<crate::protocol_snapshot::ProtocolCaptureOwner>(
            ledger,
            MetadataSharedKind::ProtocolOwner,
        )?;
        let authority = crate::handshake::read_settled17_authority_data(
            fields.named("authority")?,
            ledger,
            build,
        )?;
        exact(fields.named("policy_role")?, "native-policy")?;
        let policy_group = reference::<Native5Policy>(ledger, MetadataSharedKind::NativePolicy)?;
        exact(fields.named("frames_role")?, "native-connection-frames")?;
        let frames_group =
            reference::<RefCell<OriginalFrameReservation>>(ledger, MetadataSharedKind::FrameBank)?;
        let admit_id = ledger.read::<Id>(fields.named("admit_id")?, build)?;
        let admit_sequence = ledger.read::<U64>(fields.named("admit_sequence")?, build)?;
        let literal_index = ledger.read::<usize>(fields.named("literal_index")?, build)?;
        let literal_length = ledger.read::<usize>(fields.named("literal_length")?, build)?;
        let literal_digest = inline_digest(fields.named("literal_digest")?, ledger)?;
        fields.finish()?;
        let groups = (actor_group, frames_group, policy_group);
        if !build {
            return Ok((None, groups));
        }
        Ok((
            Some(Self {
                actor_group,
                frames_group,
                policy_group,
                authority: authority.ok_or_else(invalid)?,
                literal_digest,
                admit_id: admit_id.ok_or_else(invalid)?,
                admit_sequence: admit_sequence.ok_or_else(invalid)?,
                literal_index: literal_index.ok_or_else(invalid)?,
                literal_length: literal_length.ok_or_else(invalid)?,
            }),
            groups,
        ))
    }
}

impl HistoricalType for HistoricalAckIdentity17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        Self::read_settled17_data(input, ledger, build)
    }
}

/// Preserves the complete restore identity DATA without a live connection identity.
pub(crate) struct HistoricalRestoreIdentity17 {
    actor_group: usize,
    frames_group: usize,
    policy_group: usize,
    pub(crate) authority: HistoricalAuthority17,
    pub(crate) request_id: Id,
    pub(crate) sequence: U64,
    pub(crate) literal_slot: usize,
    pub(crate) literal_length: usize,
    pub(crate) literal_digest: [u8; 32],
}

impl HistoricalRestoreIdentity17 {
    /// Returns original actor, frame-bank and policy group ordinals.
    pub(crate) const fn group_ids_data(&self) -> (usize, usize, usize) {
        (self.actor_group, self.frames_group, self.policy_group)
    }

    /// Reads complete fields using one caller-owned capacity and alias ledger.
    ///
    /// # Errors
    /// Refuses malformed fields, unavailable backing or changed shared groups.
    pub(crate) fn read_settled17_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        Self::read_settled17_fields_data(input, ledger, build).map(|fields| fields.0)
    }

    /// Returns same-pass group IDs even during allocation-free validation.
    ///
    /// # Errors
    /// Refuses unknown fields/roles, row disagreement or incomplete shared roots.
    pub(crate) fn read_settled17_fields_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<(Option<Self>, (usize, usize, usize)), ProviderError> {
        let mut fields = Fields::object(input)?;
        exact(
            fields.named("schema")?,
            "source-private.native-restoration-connection-identity-history/17",
        )?;
        exact(fields.named("actor_role")?, "native-connection-actor")?;
        let actor_group = reference::<crate::protocol_snapshot::ProtocolCaptureOwner>(
            ledger,
            MetadataSharedKind::ProtocolOwner,
        )?;
        let authority = crate::handshake::read_settled17_authority_data(
            fields.named("authority")?,
            ledger,
            build,
        )?;
        exact(fields.named("policy_role")?, "native-policy")?;
        let policy_group = reference::<Native5Policy>(ledger, MetadataSharedKind::NativePolicy)?;
        exact(fields.named("frames_role")?, "native-connection-frames")?;
        let frames_group =
            reference::<RefCell<OriginalFrameReservation>>(ledger, MetadataSharedKind::FrameBank)?;
        let request_id = ledger.read::<Id>(fields.named("request_id")?, build)?;
        let sequence = ledger.read::<U64>(fields.named("sequence")?, build)?;
        let literal_slot = ledger.read::<usize>(fields.named("literal_slot")?, build)?;
        let literal_length = ledger.read::<usize>(fields.named("literal_length")?, build)?;
        let literal_digest = inline_digest(fields.named("literal_digest")?, ledger)?;
        fields.finish()?;
        let groups = (actor_group, frames_group, policy_group);
        if !build {
            return Ok((None, groups));
        }
        Ok((
            Some(Self {
                actor_group,
                frames_group,
                policy_group,
                authority: authority.ok_or_else(invalid)?,
                literal_digest,
                request_id: request_id.ok_or_else(invalid)?,
                sequence: sequence.ok_or_else(invalid)?,
                literal_slot: literal_slot.ok_or_else(invalid)?,
                literal_length: literal_length.ok_or_else(invalid)?,
            }),
            groups,
        ))
    }
}

impl HistoricalType for HistoricalRestoreIdentity17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        Self::read_settled17_data(input, ledger, build)
    }
}

impl HistoricalAckIdentity17 {
    /// Checks the exact original incoming slot length and complete literal digest.
    ///
    /// # Errors
    /// Refuses another slot, incomplete input or changed original framing bytes.
    pub(crate) fn authenticate_frames_data(
        &self,
        frames: &HistoricalNativeFrameRoot17,
    ) -> Result<(), ProviderError> {
        if self.frames_group != frames.group {
            return Err(invalid());
        }
        let frame = frames
            .frames
            .frame(self.literal_index)
            .ok_or_else(invalid)?;
        if frame.direction != crate::transport::original_frames::FrameDirection::Incoming
            || !frame.complete
            || frame.transferred != frame.bytes.len()
            || frame.bytes.len() != self.literal_length
            || blake3::hash(frame.bytes).as_bytes() != &self.literal_digest
        {
            return Err(invalid());
        }
        Ok(())
    }
}

impl HistoricalRestoreIdentity17 {
    /// Checks the exact original incoming slot length and complete literal digest.
    ///
    /// # Errors
    /// Refuses another slot, incomplete input or changed original framing bytes.
    pub(crate) fn authenticate_frames_data(
        &self,
        frames: &HistoricalNativeFrameRoot17,
    ) -> Result<(), ProviderError> {
        if self.frames_group != frames.group {
            return Err(invalid());
        }
        let frame = frames.frames.frame(self.literal_slot).ok_or_else(invalid)?;
        if frame.direction != crate::transport::original_frames::FrameDirection::Incoming
            || !frame.complete
            || frame.transferred != frame.bytes.len()
            || frame.bytes.len() != self.literal_length
            || blake3::hash(frame.bytes).as_bytes() != &self.literal_digest
        {
            return Err(invalid());
        }
        Ok(())
    }
}

// New17 reconstruction retains children in the caller-owned attempt.
pub(in crate::connection::native_settled17) mod retained;
