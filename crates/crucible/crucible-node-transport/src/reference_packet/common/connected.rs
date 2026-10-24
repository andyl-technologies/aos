//! Full original common admissions joined to actual consumed-input edition 4.
//!
//! This portable correlation record is produced only beneath an opaque runtime
//! admission. The owning native source still verifies its actual private peer,
//! activation, completed byte journal and unchanged baseline Begin before effects.

use super::super::{
    connected::PacketCommitRecord, coordinator::PacketConnectedCoordinatorInstallation,
    input::PacketInputCut,
};
use super::*;
use crucible_node_format::{ContentRef, ContractError, Phase};

/// Retains the actual original consumed prefix required by a connected grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketConnectedCommonInput {
    /// Retains the unchanged whole staged cut and its original byte commitments.
    pub cut: PacketInputCut,
    /// Names the actual completed original source-consumed Input request.
    pub commit_request_id: Id,
    /// Binds the complete native source-consumed record, not the staging ACK.
    pub commit_record: ContentRef,
}

/// Retains one exact common admission with its original connected input custody.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketConnectedCommonGrant {
    /// Selects `source-owned.packet-common-grant.v4` exclusively.
    pub schema: String,
    /// Names the original runtime-issued operation.
    pub operation: Id,
    /// Retains its complete original node and native owner association.
    pub route: PacketCommonRoute,
    /// Retains the complete native-three and host-owner published activation.
    pub activation: PacketCommonActivation,
    /// Retains the original full exclusive interval and stop convention.
    pub request: PacketCommonRequest,
    /// Retains genuine consumed custody even when the actual prefix is empty.
    pub input_batch: PacketConnectedCommonInput,
    /// Retains the positive actual source input stream position.
    pub input_watermark: U64,
}

impl PacketConnectedCommonGrant {
    // These separately owned original records are checked as one conjunction;
    // none is replaced by a caller-created aggregate that could omit a parent.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn authenticate(
        bytes: &[u8],
        selection: &PacketControlSelection,
        active: &WorldActivateRequest,
        operation: &Id,
        begin: &BeginRequest,
        arguments: &ExactRunArguments,
        installed: &PacketConnectedCoordinatorInstallation,
        consumed: &PacketCommitRecord,
        consumed_reference: &ContentRef,
    ) -> Result<Self, ProviderError> {
        installed.validate(selection)?;
        let original: Self = serde_json::from_value(canonical::parse_json(bytes, 8192)?)
            .map_err(ContractError::from)?;
        if canonical::canonical_json(
            &serde_json::to_value(&original).map_err(ContractError::from)?,
        )? != bytes
        {
            return Err(ProviderError::Frame(
                "packet original connected admission canonical bytes",
            ));
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
            _ => {
                return Err(ProviderError::Correlation(
                    "packet connected common stop convention",
                ));
            }
        };
        start.validate()?;
        limit.validate()?;
        original.input_batch.cut.validate()?;
        original.input_batch.commit_record.validate()?;
        if original.schema != "source-owned.packet-common-grant.v4"
            || original.operation != *operation
            || original.route.node != selection.realization.descriptors[0].id
            || original.route.owners != [owner]
            || original.activation.owners != owners
            || original.activation.generation != active.world_generation
            || original.activation.activation_id != active.activation_id
            || original.activation.world_binding_hash != selection.world
            || original.activation.boundary
                != Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl)
            || original.input_batch.cut != consumed.cut
            || original.input_batch.commit_record != *consumed_reference
            || consumed.original.request_id.0.as_ref()
                != Some(&original.input_batch.commit_request_id)
            || original.input_watermark != consumed.cut.batch_sequence
            || original.input_watermark != arguments.input_watermark
            || original.input_watermark.get() == 0
            || arguments.grant_id != original.operation
            || arguments.start != start
            || arguments.limit != limit
            || begin.kind != kind
            || arguments.boundary_policy != BoundaryPolicy::OrdinaryStop
            || start > limit
            || limit > consumed.cut.cutoff
        {
            return Err(ProviderError::Correlation(
                "packet original connected admission/source consumption",
            ));
        }
        Ok(original)
    }
}
