//! Selects exact framing and full cold native classes from installed Source data.
//!
//! Explicit outer13/inner14 and outer14/inner15 retain their original Report.
//! Decoding these historical owners never constructs a live startup member or
//! changes the separate restoration signer and fresh-target admission gates.

use super::*;
use crucible_node_transport::reference_packet::service::{
    native_owned11_snapshot_schema, native_owned13_snapshot_schema,
    native_snapshot::{
        PacketNativeBeforeProtocolPlan, PacketNativeOwned11SnapshotPlan,
        PacketNativeOwned11SnapshotValidationLayouts, PacketNativeOwned13SnapshotPlan,
        PacketNativeOwned14SnapshotPlan, native_owned14_snapshot_schema,
        packet_native_owned11_snapshot_validation_layouts,
        packet_native_owned13_snapshot_validation_layouts,
        packet_native_owned14_snapshot_validation_layouts,
    },
};

impl PacketCompleteSemanticSource {
    /// Borrows the exact installed schema selected by the actual legacy Source.
    ///
    /// The closed selection distinguishes ordinary11, startup14 and invocation15.
    /// It is correspondence DATA only: currentness, live purpose, native Capture
    /// admission and complete cold validation remain separate obligations. This
    /// getter neither creates a definition nor accepts the new settled family.
    ///
    /// # Errors
    /// Refuses foreign or failed Source selection, absent/duplicate schema rows,
    /// or a full provider definition that differs from the same binding roster.
    pub fn original_complete_native_snapshot_schema_data(
        &self,
    ) -> Result<&SchemaRef, OperationFailure> {
        let class = self.selected_complete_native_snapshot_class()?;
        let installation = self.installation();
        let provider = &installation.provider.implementation.formats;
        let binding = &installation.binding.compatibility.implementation.formats;
        let mut selected = None;
        for schema in provider {
            if schema.id.as_str() == class.schema_id() {
                if selected.is_some()
                    || schema.version != class.schema_version()
                    || !schema.extensions.is_empty()
                {
                    return Err(refused("selected native schema is duplicate or differs"));
                }
                selected = Some(schema);
            }
        }

        let schema = selected.ok_or_else(|| refused("selected native schema is absent"))?;
        let mut count = 0usize;
        for candidate in binding {
            if candidate.id.as_str() == class.schema_id() {
                if candidate != schema {
                    return Err(refused("selected native binding schema differs"));
                }
                count = count
                    .checked_add(1)
                    .ok_or_else(|| refused("selected native schema count overflow"))?;
            }
        }

        if count != 1 {
            return Err(refused(
                "selected native binding schema is absent or duplicate",
            ));
        }

        Ok(schema)
    }

    /// Names the fixed borrowed selection views before legacy key comparison.
    pub fn original_complete_native_snapshot_schema_counter_scratch_data() -> usize {
        use std::mem::size_of;
        Self::original_invocation_snapshot_declaration_counter_scratch_data()
            + size_of::<CompleteNativeSnapshotClass>()
            + size_of::<Result<CompleteNativeSnapshotClass, OperationFailure>>()
            + 2 * size_of::<&SchemaRef>()
            + size_of::<Option<&SchemaRef>>()
            + size_of::<Result<&SchemaRef, OperationFailure>>()
            + 2 * size_of::<std::slice::Iter<'static, SchemaRef>>()
            + 2 * size_of::<&Vec<SchemaRef>>()
            + size_of::<usize>()
            + size_of::<Option<usize>>()
            + size_of::<Result<usize, OperationFailure>>()
            + size_of::<&crate::node_adapters::cnp::CnpSemanticInstallation>()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::node_adapters::cnp::semantic::packet_complete_source) enum CompleteNativeSnapshotClass
{
    Legacy11,
    StartupCapture14,
    InvocationCapture15,
}

pub(in crate::node_adapters::cnp::semantic::packet_complete_source) enum CompleteSnapshotPlan<'a> {
    Legacy(PacketNativeOwned11SnapshotPlan<'a>),
    Startup(PacketNativeOwned13SnapshotPlan<'a>),
    Invocation(PacketNativeOwned14SnapshotPlan<'a>),
}

impl CompleteNativeSnapshotClass {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn has_allocation(
        self,
    ) -> bool {
        matches!(self, Self::StartupCapture14 | Self::InvocationCapture15)
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn schema_id(
        self,
    ) -> &'static str {
        match self {
            Self::Legacy11 => "source-owned.packet-native-continuation/11",
            Self::StartupCapture14 => "source-owned.packet-native-continuation/13",
            Self::InvocationCapture15 => "source-owned.packet-native-continuation/14",
        }
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn schema_version(
        self,
    ) -> u16 {
        match self {
            Self::Legacy11 => 11,
            Self::StartupCapture14 => 13,
            Self::InvocationCapture15 => 14,
        }
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn schema(
        self,
    ) -> Result<SchemaRef, OperationFailure> {
        match self {
            Self::Legacy11 => native_owned11_snapshot_schema(),
            Self::StartupCapture14 => native_owned13_snapshot_schema(),
            Self::InvocationCapture15 => native_owned14_snapshot_schema(),
        }
        .map_err(unknown)
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn validate_snapshot<'a>(
        self,
        bytes: &'a [u8],
        maximum_input: usize,
        maximum_before: usize,
    ) -> Result<CompleteSnapshotPlan<'a>, crucible_node_transport::ProviderError> {
        match self {
            Self::Legacy11 => {
                PacketNativeOwned11SnapshotPlan::validate(bytes, maximum_input, maximum_before)
                    .map(CompleteSnapshotPlan::Legacy)
            }
            Self::StartupCapture14 => {
                PacketNativeOwned13SnapshotPlan::validate(bytes, maximum_input, maximum_before)
                    .map(CompleteSnapshotPlan::Startup)
            }
            Self::InvocationCapture15 => {
                PacketNativeOwned14SnapshotPlan::validate(bytes, maximum_input, maximum_before)
                    .map(CompleteSnapshotPlan::Invocation)
            }
        }
    }

    pub(super) fn parser_layouts(self) -> PacketNativeOwned11SnapshotValidationLayouts {
        let mut layouts = match self {
            Self::Legacy11 => packet_native_owned11_snapshot_validation_layouts(),
            Self::StartupCapture14 => packet_native_owned13_snapshot_validation_layouts(),
            Self::InvocationCapture15 => packet_native_owned14_snapshot_validation_layouts(),
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
            Self::InvocationCapture15 => plan
                .complete_native_invocation_capture_schema_identity()
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
            Self::InvocationCapture15 => plan
                .reconstruct_native_invocation_capture_sealed_into(reference, encoded, completed),
        }
        .map_err(unknown)
    }
}

impl<'a> CompleteSnapshotPlan<'a> {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn snapshot_class(
        &self,
    ) -> CompleteNativeSnapshotClass {
        match self {
            Self::Legacy(_) => CompleteNativeSnapshotClass::Legacy11,
            Self::Startup(_) => CompleteNativeSnapshotClass::StartupCapture14,
            Self::Invocation(_) => CompleteNativeSnapshotClass::InvocationCapture15,
        }
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn before(
        &self,
    ) -> &PacketNativeBeforeProtocolPlan<'a> {
        match self {
            Self::Legacy(plan) => plan.before(),
            Self::Startup(plan) => plan.before(),
            Self::Invocation(plan) => plan.before(),
        }
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn control_bytes(
        &self,
    ) -> &'a [u8] {
        match self {
            Self::Legacy(plan) => plan.control_bytes(),
            Self::Startup(plan) => plan.control_bytes(),
            Self::Invocation(plan) => plan.control_bytes(),
        }
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn control_reference_bytes(
        &self,
    ) -> &'a [u8] {
        match self {
            Self::Legacy(plan) => plan.control_reference_bytes(),
            Self::Startup(plan) => plan.control_reference_bytes(),
            Self::Invocation(plan) => plan.control_reference_bytes(),
        }
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn allocation_reference_bytes(
        &self,
    ) -> Option<&'a [u8]> {
        match self {
            Self::Legacy(_) => None,
            Self::Startup(plan) => Some(plan.allocation_reference_bytes()),
            Self::Invocation(plan) => Some(plan.allocation_reference_bytes()),
        }
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn authenticate_allocation_bytes(
        &self,
        bytes: &[u8],
    ) -> Result<(), OperationFailure> {
        match self {
            Self::Legacy(_) => return Err(refused("legacy snapshot has no original Report")),
            Self::Startup(plan) => plan.authenticate_allocation_bytes(bytes),
            Self::Invocation(plan) => plan.authenticate_allocation_bytes(bytes),
        }
        .map_err(unknown)
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn capture_request_bytes(
        &self,
    ) -> &'a [u8] {
        match self {
            Self::Legacy(plan) => plan.capture_request_bytes(),
            Self::Startup(plan) => plan.capture_request_bytes(),
            Self::Invocation(plan) => plan.capture_request_bytes(),
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
        let allocation_reference_bytes = plan
            .allocation_reference_bytes()
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
        crate::node_adapters::cnp::semantic::semantic_snapshot::authenticate_canonical_reference_bytes(allocation_reference_bytes, reference)?;
        plan.authenticate_allocation_bytes(body)?;
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
            != crucible_node_transport::transport::original_frames::FrameDirection::Incoming
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

#[cfg(test)]
mod invocation_plan_tests {
    use super::*;
    use crucible_node_transport::protocol_snapshot::compact_bytes::BorrowedCompactBytes;
    use serde_json::json;

    #[test]
    fn selected_invocation_plan_preserves_report_bytes_without_promoting_framing_to_cold_owner()
    -> Result<(), OperationFailure> {
        // This is framing DATA with an intentionally invalid native model.
        // It is never a birth, archive owner, opaque ticket or live permission.
        let before = br#"["source-private.cnp-protocol/11",["source-private.native-state/15",null,null,null,null],[],[]]"#;
        let report = br#"{"report":"original borrowed body"}"#;
        let reference = canonical::content_ref(report,
            crucible_node_transport::reference_packet::service::capture_allocation::PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA).map_err(unknown)?;
        let control = json!({
            "administrative_cut":{}, "captured_process":"1", "control":{},
            "local_cursor":{}, "model":{}, "schema":"source-owned.packet-native-control-state/6"
        });
        let control_bytes = canonical::canonical_json(&control).map_err(unknown)?;
        let value = json!({
            "capture":{}, "capture_request":{}, "control":control,
            "control_reference":canonical::content_ref(&control_bytes,"application/json").map_err(unknown)?,
            "endpoint":["source-owned.packet-native-endpoint-state/14",{},null,null,null,{},
                "same-original-native-protocol-service-context/15",[],0,[],0,1,0,true,
                ["source-private.native-capture-allocation-owner-reference/14",reference]],
            "protocol":["source-private.native-before-protocol/14",
                canonical::content_ref(before,"application/json").map_err(unknown)?,before.len()+17,
                serde_json::to_value(BorrowedCompactBytes::new(before)).map_err(unknown)?],
            "schema":"source-owned.packet-native-continuation/14"
        });
        let encoded = canonical::canonical_json(&value).map_err(unknown)?;
        let plan = CompleteNativeSnapshotClass::InvocationCapture15
            .validate_snapshot(&encoded, encoded.len(), before.len() + 17)
            .map_err(unknown)?;
        assert_eq!(
            plan.snapshot_class(),
            CompleteNativeSnapshotClass::InvocationCapture15
        );
        plan.before()
            .authenticate_original_bytes(before)
            .map_err(unknown)?;
        plan.authenticate_allocation_bytes(report)?;
        let decoded: ContentRef =
            serde_json::from_slice(plan.allocation_reference_bytes().unwrap()).map_err(unknown)?;
        assert_eq!(decoded, reference);
        assert_eq!(plan.control_bytes(), control_bytes);
        assert_eq!(plan.capture_request_bytes(), b"{}");

        let mut changed = report.to_vec();
        changed[1] ^= 1;
        assert!(plan.authenticate_allocation_bytes(&changed).is_err());
        for old in [
            CompleteNativeSnapshotClass::Legacy11,
            CompleteNativeSnapshotClass::StartupCapture14,
        ] {
            assert!(
                old.validate_snapshot(&encoded, encoded.len(), before.len() + 17)
                    .is_err()
            );
        }
        let limits = OwnedProtocol11DataLimits {
            json: HistoricalJsonLimits {
                maximum_input_bytes: before.len(),
                maximum_nodes: 256,
                maximum_depth: 16,
                maximum_owned_backing_bytes: 8192,
                maximum_tree_entries: 256,
            },
            content: CompactMetadata8Limits {
                content: CompactContentLimits {
                    max_input_bytes: before.len(),
                    max_rows: 16,
                    max_groups: 16,
                    max_first_group_capacity_bytes: 8192,
                },
                maximum_metadata_capacity_bytes: 8192,
            },
            maximum_metadata_rows: 32,
            maximum_literal_backing_bytes: 8192,
        };
        let mut aliases = [];
        assert!(ValidatedNativeOwnedProtocol11::validate(before, limits, &mut aliases).is_err());
        Ok(())
    }

    #[test]
    fn legacy_snapshot_class_names_match_each_actual_compiled_definition()
    -> Result<(), Box<dyn std::error::Error>> {
        for class in [
            CompleteNativeSnapshotClass::Legacy11,
            CompleteNativeSnapshotClass::StartupCapture14,
            CompleteNativeSnapshotClass::InvocationCapture15,
        ] {
            let schema = class
                .schema()
                .map_err(|error| std::io::Error::other(error.reason))?;
            assert_eq!(schema.id.as_str(), class.schema_id());
            assert_eq!(schema.version, class.schema_version());
        }
        Ok(())
    }
}
