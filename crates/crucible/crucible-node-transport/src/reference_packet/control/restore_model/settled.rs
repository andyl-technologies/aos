//! Borrows the real physical restoration hold as historical DATA only.

use super::*;
use serde::{Serialize, Serializer, ser::SerializeStruct};

struct HoldHistory<'a>(&'a PacketCompleteRestorePhysicalHold);

impl Serialize for HoldHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.ensure_origin().map_err(serde::ser::Error::custom)?;
        let PacketCompleteRestorePhysicalHold {
            creator,
            thread,
            control_identity,
            phase,
            cursor,
            inventory_hash,
        } = self.0;
        let _ = (thread, control_identity);
        let mut state = serializer.serialize_struct("RestoredPhysicalHoldHistory", 7)?;
        state.serialize_field(
            "schema",
            "source-private.native-restored-physical-hold-history/17",
        )?;
        state.serialize_field("creator", creator)?;
        state.serialize_field("thread", "same-original-thread-history-only")?;
        state.serialize_field("control_identity_role", "current-native-control-identity")?;
        state.serialize_field(
            "phase",
            match phase.get() {
                HoldPhase::Preparing => "preparing",
                HoldPhase::Installing => "installing",
                HoldPhase::Held => "held",
                HoldPhase::Released => "released",
            },
        )?;
        state.serialize_field("cursor", cursor)?;
        state.serialize_field("inventory_hash", inventory_hash)?;
        state.end()
    }
}

impl PacketCompleteRestorePhysicalHold {
    /// Borrows every physical hold field without exporting its identity or gate.
    pub(crate) fn borrowed_settled_history_data(&self) -> impl Serialize + '_ {
        HoldHistory(self)
    }

    /// Checks the actual shared Control identity without interpreting gate data.
    ///
    /// # Errors
    /// Refuses a foreign process/thread or another live Control identity.
    pub(crate) fn authenticate_settled_history_control_identity_data(
        &self,
        identity: &Rc<()>,
    ) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        if !Rc::ptr_eq(identity, &self.control_identity) {
            return Err(refused());
        }
        Ok(())
    }

    /// Walks every actual hold child under the caller's preadmitted observer.
    ///
    /// The caller records the actual Rc hold edge once as NativeRestoredPhysicalHold.
    /// This walk records its real shared Control identity, never a reconstructed
    /// gate or identity obtained from a historical role label.
    ///
    /// # Errors
    /// Refuses a foreign process/thread, short banks or checked observer overflow.
    pub(crate) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        let Self {
            creator,
            thread: _,
            control_identity,
            phase,
            cursor,
            inventory_hash,
        } = self;
        observer.observe(creator)?;
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::NativeControlIdentity,
            control_identity.as_ref(),
        )?;
        let historical_phase = match phase.get() {
            HoldPhase::Preparing => 0usize,
            HoldPhase::Installing => 1,
            HoldPhase::Held => 2,
            HoldPhase::Released => 3,
        };
        observer.observe(&historical_phase)?;
        observer.observe(cursor)?;
        observer.observe(inventory_hash)
    }

    /// Counts this defining borrowed view and its returned serialization header.
    pub(crate) const fn settled_history_counter_scratch_data() -> usize {
        std::mem::size_of::<HoldHistory<'static>>()
            + std::mem::size_of::<Result<(), ProviderError>>()
    }
}
