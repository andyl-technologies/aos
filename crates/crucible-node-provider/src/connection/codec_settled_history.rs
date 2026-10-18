//! Borrows every actual controller/native codec field for the new history family.
//!
//! Existing old owning-codec entrypoints remain closed and unchanged. The new
//! wrapper composes actual defining policy fields and has no decoder or live
//! installation conversion. Byte contents use the bounded compact serializer;
//! output/DOM/canonical ownership remains independently caller-admitted.

use super::*;
use crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes;
use serde::{Serialize, ser::SerializeStruct};
use std::mem::size_of;

pub(crate) struct Native5CodecHistoricalData<'a>(&'a Native5CodecOwner);
struct ControllerPolicyHistoricalData<'a>(&'a ControllerNative5Policy);
struct InstalledContentHistoricalData<'a>(&'a InstalledContent);

impl Native5CodecOwner {
    pub(crate) fn settled_history_data(&self) -> Native5CodecHistoricalData<'_> {
        Native5CodecHistoricalData(self)
    }

    /// Appends actual capacities and graph aliases without clearing caller banks.
    pub(crate) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        match self {
            Self::ControllerPacket(policy) => {
                observer.boxed_value(policy.as_ref())?;
                policy.observe_retained_metadata(observer)
            }
            Self::NativePacket(policy) => {
                observer.shared_original(
                    crate::retained_metadata::aliases::MetadataSharedKind::NativePolicy,
                    policy.as_ref(),
                )?;
                policy.observe_retained_metadata(observer)
            }
        }
    }

    pub(crate) fn settled_history_counter_scratch_data() -> usize {
        ControllerNative5Policy::settled_history_counter_scratch_data()
            + Native5Policy::settled_history_counter_scratch_data()
            + size_of::<Native5CodecHistoricalData<'static>>()
            + size_of::<&Native5CodecOwner>()
            + size_of::<&Box<ControllerNative5Policy>>()
            + size_of::<&Rc<Native5Policy>>()
            + size_of::<&'static str>()
            + size_of::<&mut crate::retained_metadata::MetadataObserver<'static>>()
            + size_of::<&crate::handshake::RegistrationRead>()
            + size_of::<&crate::client::CnpRegistrarRead>()
            + size_of::<&crate::handshake::ConnectionAuthority>()
            + size_of::<&Rc<crate::protocol_snapshot::ProtocolCaptureOwner>>()
            + size_of::<&Rc<Native5CodecOwner>>()
            + size_of::<Option<&Rc<Native5CodecOwner>>>()
            + size_of::<bool>()
            + size_of::<Result<(), ProviderError>>()
    }
}

impl Serialize for Native5CodecHistoricalData<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("Native5CodecHistoricalData", 3)?;
        state.serialize_field("schema", "source-private.native5-codec-restored-settled/17")?;
        match self.0 {
            Native5CodecOwner::ControllerPacket(policy) => {
                state.serialize_field("kind", "controller")?;
                state.serialize_field("data", &ControllerPolicyHistoricalData(policy))?;
            }
            Native5CodecOwner::NativePacket(policy) => {
                state.serialize_field("kind", "native")?;
                state.serialize_field("data", &policy.borrowed_settled_history_data())?;
            }
        }
        state.end()
    }
}

impl Serialize for InstalledContentHistoricalData<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let InstalledContent { reference, bytes } = self.0;
        let mut state = serializer.serialize_struct("InstalledContentHistoricalData", 3)?;
        state.serialize_field("reference", reference)?;
        state.serialize_field("capacity", &bytes.allocation_capacity())?;
        state.serialize_field("bytes", &BorrowedCompactBytes::new(bytes.as_slice()))?;
        state.end()
    }
}

impl Serialize for ControllerPolicyHistoricalData<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let ControllerNative5Policy {
            metadata_extent,
            selection,
            coordinator,
            definition,
            connected,
            wire,
            capture_profile,
            confirmation_selection,
            confirmation_definition,
            ack_emitter_selection,
            ack_emitter_definition,
            complete_restore_selection,
            complete_restore_definitions,
            complete_restore_transfer_definitions,
            restore_input_emitter_selection,
            restore_input_emitter_definition,
            fresh_restore_allocation_selection,
            fresh_restore_allocation_definitions,
        } = self.0;
        let mut state = serializer.serialize_struct("ControllerPolicyHistoricalData", 19)?;
        state.serialize_field(
            "schema",
            "source-private.controller-native5-policy-restored-settled/17",
        )?;
        state.serialize_field("metadata_extent", metadata_extent)?;
        state.serialize_field("selection", selection)?;
        state.serialize_field("coordinator", &InstalledContentHistoricalData(coordinator))?;
        state.serialize_field("definition", definition)?;
        state.serialize_field("connected", connected)?;
        state.serialize_field("wire", &wire.protocol_view())?;
        state.serialize_field("capture_profile", capture_profile)?;
        state.serialize_field("confirmation_selection", confirmation_selection)?;
        state.serialize_field("confirmation_definition", confirmation_definition)?;
        state.serialize_field("ack_emitter_selection", ack_emitter_selection)?;
        state.serialize_field("ack_emitter_definition", ack_emitter_definition)?;
        state.serialize_field("complete_restore_selection", complete_restore_selection)?;
        state.serialize_field("complete_restore_definitions", complete_restore_definitions)?;
        state.serialize_field(
            "complete_restore_transfer_definitions",
            complete_restore_transfer_definitions,
        )?;
        state.serialize_field(
            "restore_input_emitter_selection",
            restore_input_emitter_selection,
        )?;
        state.serialize_field(
            "restore_input_emitter_definition",
            restore_input_emitter_definition,
        )?;
        state.serialize_field(
            "fresh_restore_allocation_selection",
            fresh_restore_allocation_selection,
        )?;
        state.serialize_field(
            "fresh_restore_allocation_definitions",
            fresh_restore_allocation_definitions,
        )?;
        state.end()
    }
}

// This closure is used only for its exact return type; no policy is constructed,
// borrowed or called by the static counter itself.
fn field_views<T>(_: impl FnOnce(&'static ControllerNative5Policy) -> T) -> usize {
    size_of::<T>()
}

impl ControllerNative5Policy {
    fn settled_history_counter_scratch_data() -> usize {
        field_views(|policy| {
            let ControllerNative5Policy {
                metadata_extent,
                selection,
                coordinator,
                definition,
                connected,
                wire,
                capture_profile,
                confirmation_selection,
                confirmation_definition,
                ack_emitter_selection,
                ack_emitter_definition,
                complete_restore_selection,
                complete_restore_definitions,
                complete_restore_transfer_definitions,
                restore_input_emitter_selection,
                restore_input_emitter_definition,
                fresh_restore_allocation_selection,
                fresh_restore_allocation_definitions,
            } = policy;
            (
                metadata_extent,
                selection,
                coordinator,
                definition,
                connected,
                wire,
                capture_profile,
                confirmation_selection,
                confirmation_definition,
                ack_emitter_selection,
                ack_emitter_definition,
                complete_restore_selection,
                complete_restore_definitions,
                complete_restore_transfer_definitions,
                restore_input_emitter_selection,
                restore_input_emitter_definition,
                fresh_restore_allocation_selection,
                fresh_restore_allocation_definitions,
            )
        }) + size_of::<ControllerPolicyHistoricalData<'static>>()
            + size_of::<&ControllerPolicyHistoricalData<'static>>()
            + size_of::<&ControllerNative5Policy>()
            + size_of::<InstalledContentHistoricalData<'static>>()
            + size_of::<&InstalledContentHistoricalData<'static>>()
            + size_of::<&InstalledContent>()
            + size_of::<&ContentRef>()
            + size_of::<&crucible_node_contract::Bytes>()
            + size_of::<usize>()
            + size_of::<&usize>()
            + size_of::<(
                &crucible_node_contract::Id,
                &crucible_node_contract::Id,
                crucible_node_contract::U64,
                &crucible_node_contract::Id,
                &crucible_node_contract::HashRef,
            )>()
            + BorrowedCompactBytes::requested_serialization_scratch_bytes()
    }
}

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn source_registrar_history_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<&Rc<crate::protocol_snapshot::ProtocolCaptureOwner>>()
            + size_of::<&crate::handshake::RegistrationRead>()
            + size_of::<&crate::client::CnpRegistrarRead>()
            + size_of::<&crate::handshake::ConnectionAuthority>()
            + size_of::<&Rc<Native5CodecOwner>>()
            + size_of::<Option<&Rc<Native5CodecOwner>>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<bool>()
    }

    pub(crate) fn authenticate_original_ack_emitter_history_data(
        &self,
        owner: &Rc<crate::protocol_snapshot::ProtocolCaptureOwner>,
        registration: &crate::handshake::RegistrationRead,
        codec: &Rc<Native5CodecOwner>,
    ) -> Result<(), ProviderError> {
        if !Rc::ptr_eq(owner, &self.protocol_owner)
            || self.role != EndpointRole::Controller
            || self
                .native5_codec
                .as_ref()
                .is_none_or(|actual| !Rc::ptr_eq(actual, codec))
            || !registration.same_authority_data(&self.authority)
        {
            return Err(ProviderError::Correlation(
                "historical ACK Connection parent differs",
            ));
        }
        Ok(())
    }

    pub(crate) fn authenticate_source_registrar_history_data(
        &self,
        read: &crate::client::CnpRegistrarRead,
    ) -> Result<(), ProviderError> {
        if self.role != EndpointRole::Controller || !read.same_authority_data(&self.authority) {
            return Err(ProviderError::Correlation(
                "historical Source Connection registrar differs",
            ));
        }
        Ok(())
    }
}
