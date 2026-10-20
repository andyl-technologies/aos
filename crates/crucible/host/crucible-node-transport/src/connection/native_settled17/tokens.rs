//! Retains actual ACK/Prepare token fields as inert DATA without native issuers.

use super::*;
use crate::reference_packet::{Native5Policy, service::ack_emitter::NativeAckBoot};

/// Retains a verified-Admit token's original DATA and checked shared relations.
pub(crate) struct HistoricalAckToken17 {
    pub(crate) identity: HistoricalAckIdentity17,
    pub(crate) authority: HistoricalAuthority17,
    pub(crate) original: crate::envelope::Envelope,
    boot_group: usize,
    policy_group: usize,
}

impl HistoricalAckToken17 {
    /// Reads complete inert token DATA through the caller's same ledger.
    ///
    /// # Errors
    /// Refuses malformed fields, incomplete shared roots or capacity disagreement.
    pub(crate) fn read_settled17_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        ledger.read(input, build)
    }

    /// Returns actor, frames, boot and policy archive-local groups.
    pub(crate) fn group_ids_data(&self) -> (usize, usize, usize, usize) {
        let (actor, frames, _) = self.identity.group_ids_data();
        (actor, frames, self.boot_group, self.policy_group)
    }
}

impl HistoricalAckToken17 {
    /// Reads complete inert fields and returns the same-pass shared groups.
    ///
    /// # Errors
    /// Refuses malformed fields/roles, unavailable backing or changed aliases.
    pub(crate) fn read_settled17_fields_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<(Option<Self>, (usize, usize, usize, usize)), ProviderError> {
        let mut fields = Fields::object(input)?;
        exact(
            fields.named("schema")?,
            "source-private.native-verified-admit-history/17",
        )?;
        let (identity, (actor_group, frames_group, identity_policy)) =
            HistoricalAckIdentity17::read_settled17_fields_data(
                fields.named("identity")?,
                ledger,
                build,
            )?;
        exact(fields.named("boot_role")?, "native-boot")?;
        let boot_group =
            reference::<RefCell<NativeAckBoot>>(ledger, MetadataSharedKind::NativeBoot)?;
        exact(fields.named("policy_role")?, "native-policy")?;
        let policy_group = reference::<Native5Policy>(ledger, MetadataSharedKind::NativePolicy)?;
        let authority = crate::handshake::read_settled17_authority_data(
            fields.named("authority")?,
            ledger,
            build,
        )?;
        let original =
            ledger.read::<crate::envelope::Envelope>(fields.named("original")?, build)?;
        fields.finish()?;
        if identity_policy != policy_group {
            return Err(invalid());
        }
        let groups = (actor_group, frames_group, boot_group, policy_group);
        if !build {
            return Ok((None, groups));
        }
        let identity = identity.ok_or_else(invalid)?;
        let authority = authority.ok_or_else(invalid)?;
        if !authority.same_registration_data(&identity.authority) {
            return Err(invalid());
        }
        Ok((
            Some(Self {
                identity,
                authority,
                original: original.ok_or_else(invalid)?,
                boot_group,
                policy_group,
            }),
            groups,
        ))
    }
}
impl HistoricalType for HistoricalAckToken17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        Self::read_settled17_fields_data(input, ledger, build).map(|fields| fields.0)
    }
}

/// Retains the full Prepare token DATA without installation or custody rights.
pub(crate) struct HistoricalPrepareToken17 {
    pub(crate) identity: HistoricalRestoreIdentity17,
    pub(crate) authority: HistoricalAuthority17,
    boot_group: usize,
    policy_group: usize,
    attempt_group: usize,
}

impl HistoricalPrepareToken17 {
    /// Reads complete inert token DATA through the caller's same ledger.
    ///
    /// # Errors
    /// Refuses malformed fields, incomplete shared roots or capacity disagreement.
    pub(crate) fn read_settled17_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        ledger.read(input, build)
    }

    /// Returns actor, frames, boot, policy and Prepare-attempt group ordinals.
    pub(crate) fn group_ids_data(&self) -> (usize, usize, usize, usize, usize) {
        let (actor, frames, _) = self.identity.group_ids_data();
        (
            actor,
            frames,
            self.boot_group,
            self.policy_group,
            self.attempt_group,
        )
    }
}

impl HistoricalPrepareToken17 {
    /// Reads complete inert fields and returns the same-pass shared groups.
    ///
    /// # Errors
    /// Refuses malformed fields/roles, unavailable backing or changed aliases.
    pub(crate) fn read_settled17_fields_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<(Option<Self>, (usize, usize, usize, usize, usize)), ProviderError> {
        let mut fields = Fields::object(input)?;
        exact(
            fields.named("schema")?,
            "source-private.native-verified-prepare-history/17",
        )?;
        let (identity, (actor_group, frames_group, identity_policy)) =
            HistoricalRestoreIdentity17::read_settled17_fields_data(
                fields.named("identity")?,
                ledger,
                build,
            )?;
        exact(fields.named("boot_role")?, "native-boot")?;
        let boot_group =
            reference::<RefCell<NativeAckBoot>>(ledger, MetadataSharedKind::NativeBoot)?;
        exact(fields.named("policy_role")?, "native-policy")?;
        let policy_group = reference::<Native5Policy>(ledger, MetadataSharedKind::NativePolicy)?;
        let authority = crate::handshake::read_settled17_authority_data(
            fields.named("authority")?,
            ledger,
            build,
        )?;
        exact(
            fields.named("attempt_role")?,
            "native-complete-restore-prepare",
        )?;
        let (layout, alignment) = NativeAckBoot::current_prepare_shared_layout17_data();
        if ledger.row_aligned(MetadataRecordKind::Shared, 1, alignment)? != layout {
            return Err(invalid());
        }
        let attempt_group =
            ledger.shared_reference(MetadataSharedKind::NativeRestorePrepareAttempt, layout)?;
        fields.finish()?;
        if identity_policy != policy_group {
            return Err(invalid());
        }
        let groups = (
            actor_group,
            frames_group,
            boot_group,
            policy_group,
            attempt_group,
        );
        if !build {
            return Ok((None, groups));
        }
        let identity = identity.ok_or_else(invalid)?;
        let authority = authority.ok_or_else(invalid)?;
        if !authority.same_registration_data(&identity.authority) {
            return Err(invalid());
        }
        Ok((
            Some(Self {
                identity,
                authority,
                boot_group,
                policy_group,
                attempt_group,
            }),
            groups,
        ))
    }
}
impl HistoricalType for HistoricalPrepareToken17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        Self::read_settled17_fields_data(input, ledger, build).map(|fields| fields.0)
    }
}

// New17 reconstruction retains children in the caller-owned attempt.
mod retained;
