//! Walks one actual immutable native policy payload for a shared Capture quote.
//!
//! The caller records the real policy Rc edge and invokes this child walk only
//! when the same-process typed identity roster reports a first payload visit.

use super::*;
use crate::retained_metadata::{MetadataObserver, NativeCaptureMetadataRoots};

impl Native5Policy {
    pub(crate) fn observe_unique_capture_metadata(
        &self,
        _roots: &mut NativeCaptureMetadataRoots,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        // Every present field is independently owned plain data. This delegates
        // to the exhaustive destructure; it does not invent another strong edge.
        self.observe_retained_metadata(observer)
    }

    pub(crate) fn authenticate_capture_request_header_data(
        &self,
        envelope: &Envelope,
    ) -> Result<(), ProviderError> {
        let [binding] = self.selection.realization.bindings.as_slice() else {
            return Err(ProviderError::Correlation(
                "native Capture selected binding roster",
            ));
        };
        if envelope.message != MessageKind::Request
            || envelope.method != Method::Begin
            || envelope.session_id.0.as_ref() != Some(&binding.authority.session_id)
            || envelope.incarnation_id.0.as_ref() != Some(&binding.authority.incarnation_id)
            || envelope.node_id.0.as_ref() != Some(&binding.compatibility.node_id)
            || envelope.capture_owner_id.0.as_ref() != Some(&binding.compatibility.capture_owner.id)
            || envelope.execution_owner_id.0.is_some()
            || envelope.operation_id.0.is_none()
            || envelope.request_id.0.is_none()
            || !envelope.extensions.is_empty()
            || envelope
                .body
                .get("kind")
                .and_then(serde_json::Value::as_str)
                != Some("capture")
            || envelope
                .body
                .get("extensions")
                .and_then(serde_json::Value::as_object)
                .is_none_or(|extensions| !extensions.is_empty())
        {
            return Err(ProviderError::Correlation(
                "native Capture selected next request header",
            ));
        }
        // This borrowed restriction precedes typed Begin allocation. The caller
        // must still run ordinary full body/schema/correlation validation.
        envelope.validate()
    }
}

impl Native5Policy {
    pub(in crate::reference_packet::service) fn with_capture_allocation_selection(
        self,
        selection: Option<
            super::super::capture_allocation::PacketNative5CaptureAllocationSelection,
        >,
    ) -> Result<Self, ProviderError> {
        match self.data.with_capture_allocation_selection(selection) {
            Ok(data) => Ok(Self { data }),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn capture_allocation_selection(
        &self,
    ) -> Option<super::super::capture_allocation::PacketNative5CaptureAllocationSelection> {
        self.capture_allocation_selection
    }

    pub(super) fn validate_capture_allocation_content(&self) -> Result<(), ProviderError> {
        self.data.validate_capture_allocation_content()
    }

    pub(super) fn validate_capture_allocation_negotiation(
        &self,
        authority: &ConnectionAuthority,
    ) -> Result<(), ProviderError> {
        if self.capture_allocation_selection.is_some()
            && !authority.selected_features().iter().any(|feature|
                feature.as_str() == super::super::capture_allocation::PACKET_NATIVE_CAPTURE_ALLOCATION_FEATURE)
        { return Err(capture_refused()); }
        Ok(())
    }
}

pub(super) struct CaptureCompactPolicyView<'a>(pub(super) &'a Native5Policy);
pub(super) struct CaptureOwnedPolicyView<'a>(pub(super) &'a Native5Policy);

macro_rules! capture_view {
    ($wrapper:ident, $old:ident, $tag:literal) => {
        impl Serialize for $wrapper<'_> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                if self.0.capture_allocation_selection.is_some() {
                    (
                        $tag,
                        &self.0.capture_allocation_selection,
                        &self.0.capture_allocation_definitions,
                        super::restore_input_policy::$old(self.0),
                    )
                        .serialize(serializer)
                } else {
                    super::restore_input_policy::$old(self.0).serialize(serializer)
                }
            }
        }
    };
}

capture_view!(
    CaptureCompactPolicyView,
    InputCompactPolicyView,
    "source-private.native5-policy-compact-capture-allocation/17"
);
capture_view!(
    CaptureOwnedPolicyView,
    InputOwnedPolicyView,
    "source-private.native5-policy-owned-capture-allocation/17"
);

fn capture_refused() -> ProviderError {
    ProviderError::Correlation("native original Observe allocation selection differs")
}
