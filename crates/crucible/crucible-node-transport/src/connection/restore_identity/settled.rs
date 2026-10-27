//! Borrows actual native connection identity as history, never as authority.
//!
//! The complete graph separately encodes actor, policy and frame payloads once.
//! Their repeated real Rc edges are recorded in one aggregate alias bank. The
//! assigned literal coordinates/digest remain inert history, not live currency.

use super::*;
use crate::retained_metadata::{MetadataObserver, aliases::MetadataSharedKind};
use serde::{Serialize, Serializer, ser::SerializeStruct};

struct IdentityHistory<'a>(&'a OriginalNativeRestorationConnectionIdentity);

impl OriginalNativeRestorationConnectionIdentity {
    /// Borrows all identity fields after the actual actor's origin check.
    ///
    /// # Errors
    /// Refuses another originating actor. This does not authenticate a new
    /// Connection, replay a literal or issue Capture/installation permission.
    pub(crate) fn borrowed_settled_history_data(
        &self,
    ) -> Result<impl Serialize + '_, ProviderError> {
        self.actor.ensure_current()?;
        Ok(IdentityHistory(self))
    }

    /// Checks this exact identity's registration and native policy allocation.
    ///
    /// # Errors
    /// Refuses another originating actor, registration or real policy allocation.
    pub(crate) fn authenticate_settled_history_roots_data(
        &self,
        authority: &ConnectionAuthority,
        policy: &Rc<Native5Policy>,
    ) -> Result<(), ProviderError> {
        self.actor.ensure_current()?;
        if !self.authority.same_registration(authority) || !Rc::ptr_eq(&self.policy, policy) {
            return Err(ProviderError::Correlation(
                "historical native identity roots",
            ));
        }
        Ok(())
    }

    /// Appends actual shared edges and complete field capacities without reset.
    ///
    /// # Errors
    /// Refuses another originating actor, exhausted admitted banks or checked overflow.
    pub(crate) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.actor.ensure_current()?;
        let Self {
            actor,
            authority,
            policy,
            frames,
            request_id,
            sequence,
            literal_slot,
            literal_length,
            literal_digest,
        } = self;
        observer.shared_original(MetadataSharedKind::ProtocolOwner, actor.as_ref())?;
        authority.observe_retained_metadata(observer)?;
        observer.shared_original(MetadataSharedKind::NativePolicy, policy.as_ref())?;
        observer.shared_original(MetadataSharedKind::FrameBank, frames.as_ref())?;
        observer.observe(request_id)?;
        observer.observe(sequence)?;
        observer.observe(literal_slot)?;
        observer.observe(literal_length)?;
        // The digest has a fixed actual 32-byte backing and no heap capacity.
        observer.observe(literal_digest.as_bytes())
    }

    /// Names actual borrowed identity, registrar, digest and error views.
    pub(crate) fn settled_history_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<IdentityHistory<'static>>()
            + size_of::<Result<IdentityHistory<'static>, ProviderError>>()
            + size_of::<&[u8; 32]>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<MetadataObserver<'static>>()
            + ConnectionAuthority::settled_history_counter_scratch_data()
            + field_view_bytes(
                |value: &'static OriginalNativeRestorationConnectionIdentity| {
                    let OriginalNativeRestorationConnectionIdentity {
                        actor,
                        authority,
                        policy,
                        frames,
                        request_id,
                        sequence,
                        literal_slot,
                        literal_length,
                        literal_digest,
                    } = value;
                    (
                        actor,
                        authority,
                        policy,
                        frames,
                        request_id,
                        sequence,
                        literal_slot,
                        literal_length,
                        literal_digest,
                    )
                },
            )
    }
}

impl Serialize for IdentityHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0
            .actor
            .ensure_current()
            .map_err(serde::ser::Error::custom)?;
        let OriginalNativeRestorationConnectionIdentity {
            actor,
            authority,
            policy,
            frames,
            request_id,
            sequence,
            literal_slot,
            literal_length,
            literal_digest,
        } = self.0;
        let _ = (actor, policy, frames);
        let mut state = serializer.serialize_struct("NativeIdentityHistory17", 10)?;
        state.serialize_field(
            "schema",
            "source-private.native-restoration-connection-identity-history/17",
        )?;
        state.serialize_field("actor_role", "native-connection-actor")?;
        state.serialize_field("authority", &authority.borrowed_settled_history_data())?;
        state.serialize_field("policy_role", "native-policy")?;
        state.serialize_field("frames_role", "native-connection-frames")?;
        state.serialize_field("request_id", request_id)?;
        state.serialize_field("sequence", sequence)?;
        state.serialize_field("literal_slot", literal_slot)?;
        state.serialize_field("literal_length", literal_length)?;
        state.serialize_field("literal_digest", literal_digest.as_bytes())?;
        state.end()
    }
}

const fn field_view_bytes<T: 'static, U>(_: fn(&'static T) -> U) -> usize {
    std::mem::size_of::<U>()
}
