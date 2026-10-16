//! Selects exact framing and full cold native classes from installed Source data.
//!
//! Outer13 names inner14 and its independently authenticated original Report.
//! Decoding these historical owners never constructs a live startup member or
//! changes the separate restoration signer and fresh-target admission gates.

use super::*;
use crucible_node_provider::reference_packet::service::{
    native_owned11_snapshot_schema, native_owned13_snapshot_schema,
    native_snapshot::{
        PacketNativeBeforeProtocolPlan, PacketNativeOwned11SnapshotPlan,
        PacketNativeOwned11SnapshotValidationLayouts, PacketNativeOwned13SnapshotPlan,
        packet_native_owned11_snapshot_validation_layouts,
        packet_native_owned13_snapshot_validation_layouts,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::node_adapters::cnp::semantic::packet_complete_source) enum CompleteNativeSnapshotClass
{
    Legacy11,
    StartupCapture14,
}

pub(in crate::node_adapters::cnp::semantic::packet_complete_source) enum CompleteSnapshotPlan<'a> {
    Legacy(PacketNativeOwned11SnapshotPlan<'a>),
    Startup(PacketNativeOwned13SnapshotPlan<'a>),
}

impl CompleteNativeSnapshotClass {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn has_allocation(
        self,
    ) -> bool {
        self == Self::StartupCapture14
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn schema_id(
        self,
    ) -> &'static str {
        match self {
            Self::Legacy11 => "source-owned.packet-native-continuation/11",
            Self::StartupCapture14 => "source-owned.packet-native-continuation/13",
        }
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn schema_version(
        self,
    ) -> u16 {
        match self {
            Self::Legacy11 => 11,
            Self::StartupCapture14 => 13,
        }
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn schema(
        self,
    ) -> Result<SchemaRef, OperationFailure> {
        match self {
            Self::Legacy11 => native_owned11_snapshot_schema(),
            Self::StartupCapture14 => native_owned13_snapshot_schema(),
        }
        .map_err(unknown)
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn validate_snapshot<'a>(
        self,
        bytes: &'a [u8],
        maximum_input: usize,
        maximum_before: usize,
    ) -> Result<CompleteSnapshotPlan<'a>, crucible_node_provider::ProviderError> {
        match self {
            Self::Legacy11 => {
                PacketNativeOwned11SnapshotPlan::validate(bytes, maximum_input, maximum_before)
                    .map(CompleteSnapshotPlan::Legacy)
            }
            Self::StartupCapture14 => {
                PacketNativeOwned13SnapshotPlan::validate(bytes, maximum_input, maximum_before)
                    .map(CompleteSnapshotPlan::Startup)
            }
        }
    }

    pub(super) fn parser_layouts(self) -> PacketNativeOwned11SnapshotValidationLayouts {
        let mut layouts = match self {
            Self::Legacy11 => packet_native_owned11_snapshot_validation_layouts(),
            Self::StartupCapture14 => packet_native_owned13_snapshot_validation_layouts(),
        };
        layouts.plan_header_bytes = std::mem::size_of::<CompleteSnapshotPlan<'static>>();
        layouts.plan_header_alignment = std::mem::align_of::<CompleteSnapshotPlan<'static>>();
        layouts
    }

    pub(super) fn authenticate_native(
        self,
        plan: &ValidatedNativeOwnedProtocol11<'_, '_>,
    ) -> Result<(), OperationFailure> {
        match self {
            Self::Legacy11 => plan.complete_schema_identity().map(|_| ()),
            Self::StartupCapture14 => plan
                .complete_native_startup_capture_allocation_schema_identity()
                .map(|_| ()),
        }
        .map_err(unknown)
    }

    pub(super) fn reconstruct(
        self,
        plan: &mut ValidatedNativeOwnedProtocol11<'_, '_>,
        reference: &ContentRef,
        encoded: &mut Option<Vec<u8>>,
        completed: &mut Option<SealedHistoricalNativeState>,
    ) -> Result<(), OperationFailure> {
        match self {
            Self::Legacy11 => plan.reconstruct_sealed_into(reference, encoded, completed),
            Self::StartupCapture14 => plan
                .reconstruct_native_startup_capture_allocation_sealed_into(
                    reference, encoded, completed,
                ),
        }
        .map_err(unknown)
    }
}

impl<'a> CompleteSnapshotPlan<'a> {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn before(
        &self,
    ) -> &PacketNativeBeforeProtocolPlan<'a> {
        match self {
            Self::Legacy(plan) => plan.before(),
            Self::Startup(plan) => plan.before(),
        }
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn control_bytes(
        &self,
    ) -> &'a [u8] {
        match self {
            Self::Legacy(plan) => plan.control_bytes(),
            Self::Startup(plan) => plan.control_bytes(),
        }
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn control_reference_bytes(
        &self,
    ) -> &'a [u8] {
        match self {
            Self::Legacy(plan) => plan.control_reference_bytes(),
            Self::Startup(plan) => plan.control_reference_bytes(),
        }
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn allocation(
        &self,
    ) -> Option<&PacketNativeOwned13SnapshotPlan<'a>> {
        match self {
            Self::Legacy(_) => None,
            Self::Startup(plan) => Some(plan),
        }
    }
}

impl PacketCompleteArchivedOwnerData<'_> {
    pub(super) fn authenticate_snapshot_report_data(&self) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        if self.snapshot_class == CompleteNativeSnapshotClass::Legacy11 {
            return Ok(());
        }
        let journal = self
            .journal
            .as_ref()
            .ok_or_else(|| refused("cold Report journal absent"))?;
        let bytes = self
            .content
            .get(&journal.native_snapshot)
            .ok_or_else(|| refused("cold Report snapshot absent"))?;
        let plan = self
            .snapshot_class
            .validate_snapshot(
                bytes,
                bytes.len(),
                self.before_limits.json.maximum_input_bytes,
            )
            .map_err(unknown)?;
        let plan = plan
            .allocation()
            .ok_or_else(|| refused("cold selected Report marker absent"))?;
        let before = self
            .before
            .as_ref()
            .ok_or_else(|| refused("cold Report before owner absent"))?
            .historical()
            .map_err(unknown)?;
        let after = self
            .native
            .as_ref()
            .ok_or_else(|| refused("cold Report after owner absent"))?
            .historical()
            .map_err(unknown)?;
        let original = before
            .capture_allocation
            .as_ref()
            .ok_or_else(|| refused("cold original Report owner absent"))?;
        let settled = after
            .capture_allocation
            .as_ref()
            .ok_or_else(|| refused("cold settled Report owner absent"))?;
        let reference = original.report_reference_data();
        let body = self
            .content
            .get(reference)
            .ok_or_else(|| refused("cold original Report missing from full content closure"))?;
        if !self.owner.evidence.contains(reference)
            || settled.report_reference_data() != reference
            || original.report_bytes_data().as_slice() != body
            || settled.report_bytes_data().as_slice() != body
            || original.original_observe_data() != settled.original_observe_data()
        {
            return Err(refused(
                "cold original Report evidence or native owner differs",
            ));
        }
        crate::node_adapters::cnp::semantic::semantic_snapshot::authenticate_canonical_reference_bytes(plan.allocation_reference_bytes(), reference)?;
        plan.authenticate_allocation_bytes(body).map_err(unknown)?;
        let control = self
            .content
            .get(&journal.native_control)
            .ok_or_else(|| refused("cold outer Control missing from closure"))?;
        if plan.control_bytes() != control {
            return Err(refused(
                "cold outer Control differs from its archived full reference",
            ));
        }
        crate::node_adapters::cnp::semantic::semantic_snapshot::authenticate_canonical_reference_bytes(plan.control_reference_bytes(), &journal.native_control)?;
        let last = before
            .connection
            .frames
            .frames()
            .last()
            .ok_or_else(|| refused("cold pending Capture literal absent"))?;
        if last.direction
            != crucible_node_provider::transport::original_frames::FrameDirection::Incoming
            || !last.complete
            || last.transferred != last.bytes.len()
            || last.bytes.len() < 4
            || u32::from_be_bytes(last.bytes[..4].try_into().map_err(unknown)?) as usize
                != last.bytes.len() - 4
            || plan.capture_request_bytes() != &last.bytes[4..]
        {
            return Err(refused(
                "cold outer Capture differs from the original incoming literal",
            ));
        }
        Ok(())
    }
}
