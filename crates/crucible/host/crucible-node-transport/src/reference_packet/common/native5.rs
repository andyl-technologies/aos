//! Authenticates live edition-five grants against complete original native custody.
//!
//! This codec covers newly born complete-world sources. Restored historical input
//! requires a separate fresh-native association and cannot use the live equality
//! path. Portable grant bytes never install a common runtime admission.

use super::super::{
    connected::PacketCommitRecord, coordinator::PacketNative5CoordinatorInstallation,
};
use super::*;
use crucible_node_format::{ContentRef, ContractError, Phase};

/// Retains one live exact admission in the complete-original-lineage dialect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNative5CommonGrant {
    /// Selects `source-owned.packet-common-grant.v5` exclusively.
    pub schema: String,
    /// Names the original common runtime-issued operation.
    pub operation: Id,
    /// Retains its complete actual node and native owner route.
    pub route: PacketCommonRoute,
    /// Retains the complete native-three and genuine host-owner activation.
    pub activation: PacketCommonActivation,
    /// Retains the original full interval and exact stop convention.
    pub request: PacketCommonRequest,
    /// Retains actual source-consumed custody for reactive nodes; producers use null.
    pub input: Option<super::PacketConnectedCommonInput>,
    /// Retains the original actual source input stream position.
    pub input_watermark: U64,
}

pub(crate) struct LiveNative5Grant<'a> {
    pub(crate) bytes: &'a [u8],
    pub(crate) selection: &'a PacketControlSelection,
    pub(crate) active: &'a WorldActivateRequest,
    pub(crate) operation: &'a Id,
    pub(crate) begin: &'a BeginRequest,
    pub(crate) arguments: &'a ExactRunArguments,
    pub(crate) installed: &'a PacketNative5CoordinatorInstallation,
    pub(crate) consumed: Option<(&'a PacketCommitRecord, &'a ContentRef)>,
}

impl PacketNative5CommonGrant {
    pub(crate) fn authenticate_live(scope: LiveNative5Grant<'_>) -> Result<Self, ProviderError> {
        let LiveNative5Grant {
            bytes,
            selection,
            active,
            operation,
            begin,
            arguments,
            installed,
            consumed,
        } = scope;
        installed.validate(selection)?;
        let original: Self = serde_json::from_value(canonical::parse_json(bytes, 8192)?)
            .map_err(ContractError::from)?;
        if canonical::canonical_json(
            &serde_json::to_value(&original).map_err(ContractError::from)?,
        )? != bytes
        {
            return Err(ProviderError::Frame("native5 live grant canonical bytes"));
        }
        let binding = &selection.realization.bindings[0];
        let owner = PacketCommonOwner {
            owner: selection.realization.owners[0].id.clone(),
            incarnation: binding.authority.incarnation_id.clone(),
            generation: binding.authority.owner_generation,
        };
        let owners: Vec<PacketCommonOwner> =
            serde_json::from_value(installed.template["activation"]["owners"].clone())
                .map_err(ContractError::from)?;
        let (kind, start, limit) = match original.request {
            PacketCommonRequest::ExactRun {
                start,
                limit,
                boundary_policy: PacketCommonBoundaryPolicy::HorizonPark,
            } => (BeginKind::ExactRun, start, limit),
            PacketCommonRequest::BoundarySettle { start, limit }
                if start.time_ps == limit.time_ps =>
            {
                (BeginKind::BoundarySettle, start, limit)
            }
            _ => return Err(ProviderError::Correlation("native5 live stop convention")),
        };
        start.validate()?;
        limit.validate()?;
        if original.schema != "source-owned.packet-common-grant.v5"
            || original.operation != *operation
            || original.route.node != selection.realization.descriptors[0].id
            || original.route.owners != [owner]
            || original.activation.owners != owners
            || original.activation.generation != active.world_generation
            || original.activation.activation_id != active.activation_id
            || original.activation.world_binding_hash != selection.world
            || original.activation.boundary
                != Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl)
            || arguments.grant_id != original.operation
            || arguments.start != start
            || arguments.limit != limit
            || arguments.input_watermark != original.input_watermark
            || begin.kind != kind
            || arguments.boundary_policy != BoundaryPolicy::OrdinaryStop
            || start > limit
        {
            return Err(ProviderError::Correlation(
                "native5 live original admission",
            ));
        }
        match (&original.input, consumed) {
            (None, None) if original.input_watermark.get() == 0 => {}
            (Some(input), Some((record, reference))) => {
                input.cut.validate()?;
                input.commit_record.validate()?;
                if input.cut != record.cut
                    || input.commit_record != *reference
                    || record.original.request_id.0.as_ref() != Some(&input.commit_request_id)
                    || original.input_watermark != record.cut.batch_sequence
                    || original.input_watermark.get() == 0
                    || limit > record.cut.cutoff
                {
                    return Err(ProviderError::Correlation(
                        "native5 live source-consumed custody",
                    ));
                }
                // Fresh-live consumption must belong to this exact source. Old
                // captured envelopes cannot be enrolled by matching payload IDs.
                if record.cut.session_id != binding.authority.session_id
                    || record.cut.incarnation_id != binding.authority.incarnation_id
                    || record.cut.node_id != binding.compatibility.node_id
                    || record.cut.owner_generation != binding.authority.owner_generation
                    || record.cut.input_epoch != binding.authority.input_epoch
                    || record.cut.execution_owner_id != selection.realization.owners[0].id
                    || record.cut.activation_id != active.activation_id
                    || record.cut.world_generation != active.world_generation
                    || record.cut.world_binding_hash != selection.world
                {
                    return Err(ProviderError::Correlation("native5 live consumption scope"));
                }
            }
            _ => return Err(ProviderError::Correlation("native5 live input population")),
        }
        Ok(original)
    }

    // This distinct path requires the actual spent native scope and its verified
    // signed Commit cut. The live validator above retains exact zero-cut rules.
    pub(crate) fn authenticate_restored_producer(
        scope: LiveNative5Grant<'_>,
        permit: &crate::reference_packet::service::ack_emitter::OriginalRestoredProducerRead<'_>,
    ) -> Result<Self, ProviderError> {
        let boundary = permit.activation_boundary_data()?;
        let LiveNative5Grant {
            bytes,
            selection,
            active,
            operation,
            begin,
            arguments,
            installed,
            consumed,
        } = scope;
        installed.validate(selection)?;
        let original: Self = serde_json::from_value(canonical::parse_json(bytes, 8192)?)
            .map_err(ContractError::from)?;
        if canonical::canonical_json(
            &serde_json::to_value(&original).map_err(ContractError::from)?,
        )? != bytes
        {
            return Err(ProviderError::Frame("native5 live grant canonical bytes"));
        }
        let binding = &selection.realization.bindings[0];
        let owner = PacketCommonOwner {
            owner: selection.realization.owners[0].id.clone(),
            incarnation: binding.authority.incarnation_id.clone(),
            generation: binding.authority.owner_generation,
        };
        let owners: Vec<PacketCommonOwner> =
            serde_json::from_value(installed.template["activation"]["owners"].clone())
                .map_err(ContractError::from)?;
        let (kind, start, limit) = match original.request {
            PacketCommonRequest::ExactRun {
                start,
                limit,
                boundary_policy: PacketCommonBoundaryPolicy::HorizonPark,
            } => (BeginKind::ExactRun, start, limit),
            PacketCommonRequest::BoundarySettle { start, limit }
                if start.time_ps == limit.time_ps =>
            {
                (BeginKind::BoundarySettle, start, limit)
            }
            _ => return Err(ProviderError::Correlation("native5 live stop convention")),
        };
        start.validate()?;
        limit.validate()?;
        if original.input.is_some() || original.input_watermark.get() != 0 || consumed.is_some() {
            return Err(ProviderError::Correlation(
                "restored Producer admits no new input",
            ));
        }
        if original.schema != "source-owned.packet-common-grant.v5"
            || original.operation != *operation
            || original.route.node != selection.realization.descriptors[0].id
            || original.route.owners != [owner]
            || original.activation.owners != owners
            || original.activation.generation != active.world_generation
            || original.activation.activation_id != active.activation_id
            || original.activation.world_binding_hash != selection.world
            || original.activation.boundary != boundary
            || arguments.grant_id != original.operation
            || arguments.start != start
            || arguments.limit != limit
            || arguments.input_watermark != original.input_watermark
            || begin.kind != kind
            || arguments.boundary_policy != BoundaryPolicy::OrdinaryStop
            || start > limit
        {
            return Err(ProviderError::Correlation(
                "native5 live original admission",
            ));
        }
        match (&original.input, consumed) {
            (None, None) if original.input_watermark.get() == 0 => {}
            (Some(input), Some((record, reference))) => {
                input.cut.validate()?;
                input.commit_record.validate()?;
                if input.cut != record.cut
                    || input.commit_record != *reference
                    || record.original.request_id.0.as_ref() != Some(&input.commit_request_id)
                    || original.input_watermark != record.cut.batch_sequence
                    || original.input_watermark.get() == 0
                    || limit > record.cut.cutoff
                {
                    return Err(ProviderError::Correlation(
                        "native5 live source-consumed custody",
                    ));
                }
                // Fresh-live consumption must belong to this exact source. Old
                // captured envelopes cannot be enrolled by matching payload IDs.
                if record.cut.session_id != binding.authority.session_id
                    || record.cut.incarnation_id != binding.authority.incarnation_id
                    || record.cut.node_id != binding.compatibility.node_id
                    || record.cut.owner_generation != binding.authority.owner_generation
                    || record.cut.input_epoch != binding.authority.input_epoch
                    || record.cut.execution_owner_id != selection.realization.owners[0].id
                    || record.cut.activation_id != active.activation_id
                    || record.cut.world_generation != active.world_generation
                    || record.cut.world_binding_hash != selection.world
                {
                    return Err(ProviderError::Correlation("native5 live consumption scope"));
                }
            }
            _ => return Err(ProviderError::Correlation("native5 live input population")),
        }
        Ok(original)
    }
}
