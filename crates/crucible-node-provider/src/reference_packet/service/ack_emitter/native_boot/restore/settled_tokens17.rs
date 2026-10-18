//! Encodes real Commit and Hold relations as checked historical DATA.
//!
//! ```json
//! {"schema":"source-private.native-verified-held-history/17","boot_role":"native-boot","mapping_role":"native-archived-protocol-mapping","attempt_role":"native-complete-restore-commit","hold_role":"native-complete-restore-physical-hold"}
//! ```
//!
//! No reader in this module creates a token, physical Hold or installation grant.

use super::*;
use crate::retained_metadata::{MetadataObserver, aliases::MetadataSharedKind};
use serde::{Serialize, Serializer, ser::SerializeStruct};

struct HeldHistory<'a>(&'a VerifiedCompleteRestorationHeld);

impl NativeAckBoot {
    /// Checks the actual retained immutable policy without issuing native rights.
    ///
    /// # Errors
    /// Refuses a foreign creator or another original policy allocation.
    pub(crate) fn authenticate_settled17_policy_data(
        &self,
        policy: &Rc<crate::reference_packet::Native5Policy>,
    ) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        if self
            .policy
            .as_ref()
            .is_none_or(|actual| !Rc::ptr_eq(actual, policy))
        {
            return Err(refused());
        }
        Ok(())
    }
}

impl VerifiedCompleteRestoration {
    /// Checks the exact retained Boot, policy and mapping allocations.
    ///
    /// # Errors
    /// Refuses changed or borrowed native roots without consuming any owner.
    pub(crate) fn authenticate_settled17_roots_data(
        &self,
        boot: &Rc<RefCell<NativeAckBoot>>,
        policy: &Rc<crate::reference_packet::Native5Policy>,
        mapping: &Rc<RefCell<PreparedArchivedNativeProtocolMapping>>,
    ) -> Result<(), ProviderError> {
        self.authenticate_settled_history_edges_data()?;
        if !Rc::ptr_eq(boot, &self.boot) || !Rc::ptr_eq(policy, &self.policy) {
            return Err(refused());
        }
        self.authenticate_settled_history_mapping_data(mapping)
    }
}

impl VerifiedCompleteRestorationHeld {
    fn authenticate_settled_history_edges_data(&self) -> Result<(), ProviderError> {
        let owner = self.boot.try_borrow().map_err(|_| borrowed())?;
        let attempt = self.attempt.try_borrow().map_err(|_| borrowed())?;
        owner.ensure_origin()?;
        attempt.ensure_origin()?;
        if owner
            .restoration
            .as_ref()
            .is_none_or(|actual| !Rc::ptr_eq(actual, &self.attempt))
            || !Rc::ptr_eq(&self.mapping, &attempt.mapping)
            || attempt
                .physical_hold
                .as_ref()
                .is_none_or(|actual| !Rc::ptr_eq(actual, &self.hold))
        {
            return Err(refused());
        }
        Ok(())
    }

    /// Checks the exact retained Boot and mapping allocations.
    ///
    /// # Errors
    /// Refuses changed or borrowed native roots without consuming the Hold.
    pub(crate) fn authenticate_settled17_roots_data(
        &self,
        boot: &Rc<RefCell<NativeAckBoot>>,
        mapping: &Rc<RefCell<PreparedArchivedNativeProtocolMapping>>,
    ) -> Result<(), ProviderError> {
        self.authenticate_settled_history_edges_data()?;
        if !Rc::ptr_eq(boot, &self.boot) || !Rc::ptr_eq(mapping, &self.mapping) {
            return Err(refused());
        }
        Ok(())
    }

    /// Borrows all retained Hold relations without creating a portable permit.
    ///
    /// # Errors
    /// Refuses changed native roots or conflicting native dynamic borrows.
    pub(crate) fn borrowed_settled_history_data(
        &self,
    ) -> Result<impl Serialize + '_, ProviderError> {
        self.authenticate_settled_history_edges_data()?;
        Ok(HeldHistory(self))
    }

    /// Appends all four actual repeated Hold edges in field order.
    ///
    /// # Errors
    /// Refuses changed roots, unavailable banks or checked metadata overflow.
    pub(crate) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.authenticate_settled_history_edges_data()?;
        let Self {
            boot,
            mapping,
            attempt,
            hold,
        } = self;
        observer.shared_original(MetadataSharedKind::NativeBoot, boot.as_ref())?;
        observer.shared_original(MetadataSharedKind::ArchivedMapping, mapping.as_ref())?;
        observer.shared_original(
            MetadataSharedKind::NativeRestoreCommitAttempt,
            attempt.as_ref(),
        )?;
        observer.shared_original(
            MetadataSharedKind::NativeRestoredPhysicalHold,
            hold.as_ref(),
        )
    }

    /// Counts this borrowed view and both checked native dynamic-borrow headers.
    pub(crate) const fn settled_history_counter_scratch_data() -> usize {
        std::mem::size_of::<HeldHistory<'static>>()
            + std::mem::size_of::<std::cell::Ref<'static, NativeAckBoot>>()
            + std::mem::size_of::<std::cell::Ref<'static, NativeCompleteRestoreAttempt>>()
            + std::mem::size_of::<Result<(), ProviderError>>()
    }
}

impl Serialize for HeldHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0
            .authenticate_settled_history_edges_data()
            .map_err(serde::ser::Error::custom)?;
        let VerifiedCompleteRestorationHeld {
            boot: _,
            mapping: _,
            attempt: _,
            hold: _,
        } = self.0;
        let mut fields = serializer.serialize_struct("VerifiedHeldHistory17", 5)?;
        fields.serialize_field("schema", "source-private.native-verified-held-history/17")?;
        fields.serialize_field("boot_role", "native-boot")?;
        fields.serialize_field("mapping_role", "native-archived-protocol-mapping")?;
        fields.serialize_field("attempt_role", "native-complete-restore-commit")?;
        fields.serialize_field("hold_role", "native-complete-restore-physical-hold")?;
        fields.end()
    }
}

use crate::connection::HistoricalRestoreIdentity17;
use crate::handshake::HistoricalAuthority17;
use crate::protocol_snapshot::owned11::typed::{
    Fields, HistoricalType, Ledger, invalid, plain_string,
};
use crate::retained_metadata::records::MetadataRecordKind;

/// Owns checked Commit history without reconstructing a native token.
pub(crate) struct HistoricalCommitToken17 {
    pub(crate) identity: HistoricalRestoreIdentity17,
    pub(crate) authority: HistoricalAuthority17,
    boot_group: usize,
    policy_group: usize,
    attempt_group: usize,
}

impl HistoricalCommitToken17 {
    /// Checks exact fields and consumes every actual metadata and shared row.
    ///
    /// # Errors
    /// Refuses malformed fields, changed identity authorities or undefined roots.
    pub(crate) fn read_settled17_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        Self::read_settled17_fields_data(input, ledger, build).map(|result| result.0)
    }

    /// Returns actual role groups during both validation and construction.
    ///
    /// # Errors
    /// Refuses malformed fields, changed identity authorities or undefined roots.
    pub(crate) fn read_settled17_fields_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<(Option<Self>, (usize, usize, usize, usize, usize)), ProviderError> {
        let mut fields = Fields::object(input)?;
        exact(
            fields.named("schema")?,
            "source-private.native-verified-commit-history/17",
        )?;
        let identity_view = fields.named("identity")?;
        let (identity, (actor_group, frames_group, identity_policy)) =
            HistoricalRestoreIdentity17::read_settled17_fields_data(identity_view, ledger, build)?;
        exact(fields.named("boot_role")?, "native-boot")?;
        let boot_group = shared_reference_data::<RefCell<NativeAckBoot>>(
            ledger,
            MetadataSharedKind::NativeBoot,
        )?;
        exact(fields.named("policy_role")?, "native-policy")?;
        let policy_group = shared_reference_data::<crate::reference_packet::Native5Policy>(
            ledger,
            MetadataSharedKind::NativePolicy,
        )?;
        let authority_view = fields.named("authority")?;
        let authority =
            crate::handshake::read_settled17_authority_data(authority_view, ledger, build)?;
        exact(
            fields.named("attempt_role")?,
            "native-complete-restore-commit",
        )?;
        let attempt_group = shared_reference_data::<RefCell<NativeCompleteRestoreAttempt>>(
            ledger,
            MetadataSharedKind::NativeRestoreCommitAttempt,
        )?;
        fields.finish()?;

        // Equal canonical registration fields alone do not identify an actor;
        // the separate real alias groups remain mandatory enclosing joins.
        let mut identity_fields = Fields::object(identity_view)?;
        identity_fields.named("schema")?;
        identity_fields.named("actor_role")?;
        if identity_policy != policy_group || identity_fields.named("authority")? != authority_view
        {
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
        if !identity.authority.same_registration_data(&authority) {
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

    /// Returns actor, frame, Boot, policy and Commit groups from the same pass.
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

impl HistoricalType for HistoricalCommitToken17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        Self::read_settled17_data(input, ledger, build)
    }
}

/// Preserves all four independently checked Hold relations as inert group IDs.
pub(crate) struct HistoricalHeldToken17 {
    boot_group: usize,
    mapping_group: usize,
    attempt_group: usize,
    hold_group: usize,
}

impl HistoricalHeldToken17 {
    /// Checks the exact Hold grammar and consumes each actual repeated row.
    ///
    /// # Errors
    /// Refuses missing, reordered, additional or unresolved native role edges.
    pub(crate) fn read_settled17_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        Self::read_settled17_fields_data(input, ledger, build).map(|result| result.0)
    }

    /// Returns all actual role groups during validation and construction.
    ///
    /// # Errors
    /// Refuses changed framing, metadata layouts or incomplete shared roots.
    pub(crate) fn read_settled17_fields_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<(Option<Self>, (usize, usize, usize, usize)), ProviderError> {
        let mut fields = Fields::object(input)?;
        exact(
            fields.named("schema")?,
            "source-private.native-verified-held-history/17",
        )?;
        exact(fields.named("boot_role")?, "native-boot")?;
        let boot_group = shared_reference_data::<RefCell<NativeAckBoot>>(
            ledger,
            MetadataSharedKind::NativeBoot,
        )?;
        exact(
            fields.named("mapping_role")?,
            "native-archived-protocol-mapping",
        )?;
        let mapping_group = shared_reference_data::<RefCell<PreparedArchivedNativeProtocolMapping>>(
            ledger,
            MetadataSharedKind::ArchivedMapping,
        )?;
        exact(
            fields.named("attempt_role")?,
            "native-complete-restore-commit",
        )?;
        let attempt_group = shared_reference_data::<RefCell<NativeCompleteRestoreAttempt>>(
            ledger,
            MetadataSharedKind::NativeRestoreCommitAttempt,
        )?;
        exact(
            fields.named("hold_role")?,
            "native-complete-restore-physical-hold",
        )?;
        let hold_group = shared_reference_data::<PacketCompleteRestorePhysicalHold>(
            ledger,
            MetadataSharedKind::NativeRestoredPhysicalHold,
        )?;
        fields.finish()?;
        let groups = (boot_group, mapping_group, attempt_group, hold_group);
        Ok((
            build.then_some(Self {
                boot_group,
                mapping_group,
                attempt_group,
                hold_group,
            }),
            groups,
        ))
    }

    /// Returns Boot, mapping, Commit and physical-Hold groups in field order.
    pub(crate) const fn group_ids_data(&self) -> (usize, usize, usize, usize) {
        (
            self.boot_group,
            self.mapping_group,
            self.attempt_group,
            self.hold_group,
        )
    }
}

impl HistoricalType for HistoricalHeldToken17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        Self::read_settled17_data(input, ledger, build)
    }
}

fn shared_reference_data<T>(
    ledger: &mut Ledger<'_, '_, '_>,
    kind: MetadataSharedKind,
) -> Result<usize, ProviderError> {
    if ledger.row_aligned(MetadataRecordKind::Shared, 1, std::mem::align_of::<T>())?
        != std::mem::size_of::<T>()
    {
        return Err(invalid());
    }
    ledger.shared_reference(kind, std::mem::size_of::<T>())
}

fn exact(input: &[u8], expected: &str) -> Result<(), ProviderError> {
    if plain_string(input)? != expected {
        return Err(invalid());
    }
    Ok(())
}
