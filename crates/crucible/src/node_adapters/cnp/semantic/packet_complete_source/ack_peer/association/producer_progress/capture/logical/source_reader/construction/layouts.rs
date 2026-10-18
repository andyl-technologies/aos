//! Names selected Source decoder elements, including nested collection values.
//!
//! A completed opaque result is often smaller than the fields parsed on its way
//! to completion. These explicit families include nested descriptor lanes,
//! implementation formats, model inventories/publications and typed protocol
//! variants. Provider-private historical authentication has a separate defining
//! geometry row and must be joined before this Source quote is consumed.

use super::*;

// The workspace pins this serde private module. These are real decoder buffer
// elements, not substitutes for the Value or native model allocation layouts.
type SerdeContent = serde::__private228::de::Content<'static>;

#[derive(Clone, Copy)]
pub(super) enum Family {
    Installation,
    First,
    Producer,
    Capture,
    World,
    Scalar,
}

impl Family {
    pub(super) fn element_layout_data(self) -> usize {
        let specific = match self {
            Self::Installation => installation_layouts().into_iter().max().unwrap_or(0),
            Self::First => first_layouts().into_iter().max().unwrap_or(0),
            Self::Producer => producer_layouts().into_iter().max().unwrap_or(0),
            Self::Capture => capture_layouts().into_iter().max().unwrap_or(0),
            Self::World => world_layouts().into_iter().max().unwrap_or(0),
            Self::Scalar => 0,
        };
        specific
            .max(common_layouts().into_iter().max().unwrap_or(0))
            .max(NodeRuntime::capture_closed_inline_storage())
    }

    pub(super) fn counter_scratch_data() -> usize {
        // Only one family array is constructed at a time, beside common max.
        size_of::<[usize; MAXIMUM_FAMILY_FIELDS]>()
            + size_of::<Self>()
            + size_of::<std::array::IntoIter<usize, MAXIMUM_FAMILY_FIELDS>>()
    }
}

const MAXIMUM_FAMILY_FIELDS: usize = 27;

fn common_layouts() -> [usize; 20] {
    [
        size_of::<String>(),
        size_of::<Value>(),
        size_of::<SerdeContent>(),
        size_of::<(SerdeContent, SerdeContent)>(),
        size_of::<ContentRef>(),
        size_of::<crucible_node_contract::Id>(),
        size_of::<crucible_node_contract::OwnerRef>(),
        size_of::<crucible_node_contract::OwnerBinding>(),
        size_of::<crucible_node_contract::NodeDescriptor>(),
        size_of::<crucible_node_contract::PortDescriptor>(),
        size_of::<crucible_node_contract::LaneDescriptor>(),
        size_of::<crucible_node_contract::NodeBinding>(),
        size_of::<crucible_node_contract::SchemaRef>(),
        size_of::<crucible_node_contract::FacetSelection>(),
        size_of::<crucible_node_contract::Endpoint>(),
        size_of::<crucible_node_provider::envelope::Envelope>(),
        size_of::<crucible_node_provider::bodies::RequestBody>(),
        size_of::<crucible_node_provider::bodies::ResponseBody>(),
        size_of::<crucible_node_provider::bodies::MethodResult>(),
        size_of::<crate::node_contract::OwnerIdentity>(),
    ]
}

fn installation_layouts() -> [usize; 17] {
    [
        size_of::<OriginalSourceRestoredInstallation17>(),
        size_of::<crucible_node_contract::ProviderManifest>(),
        size_of::<crucible_node_contract::NodeManifest>(),
        size_of::<crucible_node_contract::ImplementationIdentity>(),
        size_of::<crucible_node_contract::RealizationManifest>(),
        size_of::<crucible_node_contract::ResourceLimits>(),
        size_of::<crucible_node_contract::CapabilityProfile>(),
        size_of::<crucible_node_contract::GuaranteeProfile>(),
        size_of::<crucible_node_provider::bodies::RealizeRequest>(),
        size_of::<crucible_node_provider::reference_packet::control::PacketControlSelection>(),
        size_of::<crucible_node_provider::reference_packet::service::PacketNative5SourceLaunch>(),
        size_of::<crucible_node_provider::reference_packet::service::PacketConnectedSourceProgram>(
        ),
        size_of::<crucible_node_provider::reference_packet::PacketProgramDefinition>(),
        size_of::<crucible_node_provider::reference_packet::PacketEvent>(),
        size_of::<crucible_node_provider::reference_packet::connected::PacketConnectedDefinition>(),
        size_of::<crucible_node_provider::reference_packet::connected::PacketInputConnection>(),
        size_of::<crucible_node_provider::reference_service::InstalledContent>(),
    ]
}

fn first_layouts() -> [usize; 20] {
    [
        size_of::<OriginalSourceRestoredFirstObservationHistory17Read>(),
        size_of::<crucible_node_provider::protocol_snapshot::current_controller17::ValidatedHistoricalFirstRestorationObservation17>(),
        size_of::<crucible_node_provider::reference_packet::service::complete_restore::restoration_observe::PacketRestorationObservationRequest>(),
        size_of::<crucible_node_provider::reference_packet::control::PacketNativeRecord>(),
        size_of::<crucible_node_provider::reference_packet::control::PacketNative5UnderlyingRecord>(),
        size_of::<crucible_node_provider::reference_packet::service::complete_restore::PacketNativeRestoredRecord>(),
        size_of::<crucible_node_provider::reference_packet::PacketInventory>(),
        size_of::<crucible_node_provider::reference_packet::PacketGrant>(),
        size_of::<crucible_node_provider::reference_packet::PacketEvent>(),
        size_of::<crucible_node_provider::reference_packet::PacketPublication>(),
        size_of::<crucible_node_provider::reference_packet::connected::PacketConnectedNativeRecord>(),
        size_of::<crucible_node_provider::reference_packet::connected::PacketConnectedInventory>(),
        size_of::<crucible_node_provider::reference_packet::connected::PacketConnectedGrant>(),
        size_of::<crucible_node_provider::reference_packet::connected::PacketReaction>(),
        size_of::<crucible_node_provider::reference_packet::connected::PacketDeliveredInput>(),
        size_of::<crucible_node_provider::reference_packet::connected::PacketPendingPublication>(),
        size_of::<crucible_node_provider::reference_packet::connected::PacketConnectedPublication>(),
        size_of::<crucible_node_provider::reference_packet::connected::PacketStageRecord>(),
        size_of::<crucible_node_provider::reference_packet::connected::PacketCommitRecord>(),
        size_of::<crate::node_scheduling::NativeSchedulingObservation>(),
    ]
}

fn producer_layouts() -> [usize; 27] {
    [
        size_of::<super::super::super::producer_fields::ProducerAttemptFields17<'static>>(),
        size_of::<crate::node_contract::NodeRoute>(),
        size_of::<crate::node_contract::OperationRequest>(),
        size_of::<crate::node_contract::OperationOutcome>(),
        size_of::<crate::node_scheduling::InputPayload>(),
        size_of::<crucible_node_provider::bodies::ExactRunArguments>(),
        size_of::<crucible_node_provider::bodies::BeginRequest>(),
        size_of::<crucible_node_provider::bodies::PollRequest>(),
        size_of::<crucible_node_provider::bodies::RetireRequest>(),
        size_of::<crucible_node_provider::bodies::ObserveRequest>(),
        size_of::<crucible_node_provider::reference_packet::control::PacketNativeRecord>(),
        size_of::<crucible_node_provider::reference_packet::control::PacketNative5UnderlyingRecord>(),
        size_of::<crucible_node_provider::reference_packet::service::complete_restore::PacketNativeRestoredRecord>(),
        size_of::<crucible_node_provider::reference_packet::PacketInventory>(),
        size_of::<crucible_node_provider::reference_packet::PacketGrant>(),
        size_of::<crucible_node_provider::reference_packet::PacketEvent>(),
        size_of::<crucible_node_provider::reference_packet::PacketPublication>(),
        size_of::<crucible_node_provider::reference_packet::connected::PacketConnectedNativeRecord>(),
        size_of::<crucible_node_provider::reference_packet::connected::PacketConnectedInventory>(),
        size_of::<crucible_node_provider::reference_packet::connected::PacketConnectedGrant>(),
        size_of::<crucible_node_provider::reference_packet::connected::PacketReaction>(),
        size_of::<crucible_node_provider::reference_packet::connected::PacketDeliveredInput>(),
        size_of::<crucible_node_provider::reference_packet::connected::PacketPendingPublication>(),
        size_of::<crucible_node_provider::reference_packet::connected::PacketConnectedPublication>(),
        size_of::<crucible_node_provider::reference_packet::connected::PacketStageRecord>(),
        size_of::<crucible_node_provider::reference_packet::connected::PacketCommitRecord>(),
        size_of::<crate::node_scheduling::NativeSchedulingObservation>(),
    ]
}

fn capture_layouts() -> [usize; 7] {
    [
        size_of::<OriginalSourceCaptureHousekeeping17Read>(),
        size_of::<crucible_node_provider::protocol_snapshot::current_controller17::ValidatedHistoricalRestoredSettledCapture17>(),
        size_of::<crucible_node_provider::reference_packet::service::restored_settled_capture::PacketRestoredSettledCaptureRequest>(),
        size_of::<crucible_node_provider::reference_packet::service::restored_settled_capture::PacketRestoredSettledCaptureContext>(),
        size_of::<crucible_node_provider::reference_packet::service::restored_settled_capture::PacketRestoredSettledCaptureArtifact>(),
        size_of::<crucible_node_provider::reference_packet::service::restored_settled_confirmation::PacketRestoredSettledAfterConfirmationRequest>(),
        size_of::<crucible_node_provider::reference_packet::service::restored_settled_confirmation::PacketRestoredSettledAfterConfirmationReceipt>(),
    ]
}

fn world_layouts() -> [usize; 2] {
    [
        size_of::<SavedRuntimeActivation>(),
        size_of::<crate::node_contract::OwnerIdentity>(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    // The workspace pins this serde private module. These are real decoder buffer
    // elements, not substitutes for the Value or native model allocation layouts.
    type SerdeContent = serde::__private228::de::Content<'static>;

    #[test]
    fn selected_family_bounds_include_nested_collection_values_and_protocol_variants() {
        assert!(
            Family::Installation.element_layout_data()
                >= size_of::<crucible_node_contract::LaneDescriptor>()
        );
        assert!(
            Family::Installation.element_layout_data()
                >= size_of::<crucible_node_contract::ImplementationIdentity>()
        );
        assert!(
            Family::First.element_layout_data()
                >= size_of::<
                    crucible_node_provider::reference_packet::connected::PacketConnectedPublication,
                >()
        );
        assert!(
            Family::Producer.element_layout_data()
                >= size_of::<crate::node_contract::OperationOutcome>()
        );
        assert!(Family::Capture.element_layout_data()
            >= size_of::<crucible_node_provider::reference_packet::service::restored_settled_capture::PacketRestoredSettledCaptureArtifact>());
        assert!(
            Family::World.element_layout_data() >= size_of::<crate::node_contract::OwnerIdentity>()
        );
    }
}
