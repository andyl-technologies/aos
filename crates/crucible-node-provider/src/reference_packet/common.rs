//! Closed original common-grant correlation for the output-only packet source.
//!
//! The host writes this body from an actual opaque common admission. Decoding it
//! never grants permission: the native dispatcher also requires its authenticated
//! original peer, installed owner, active world and matching baseline Begin.
//! This selected source has no input lane; null ingress is an explicit property
//! of the installed descriptor, not inferred EOF or an empty staged batch.
//!
//! ```text
//! {"schema":"source-owned.packet-common-grant.v1","operation":"original",
//!  "route":{"node":"packet","owners":[...]},"activation":{...},
//!  "request":{"ExactRun":{...}},"input_batch":null,"input_watermark":"0"}
//! ```

use crucible_node_contract::{HashRef, Id, Position, U64, Validate, canonical};
use serde::{Deserialize, Serialize};

use crate::{ProviderError, bodies::*};

use super::control::PacketControlSelection;

/// Retains one original common owner without reconstructing native authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketCommonOwner {
    /// Names the independently installed stable native owner.
    pub owner: Id,
    /// Names the actual original provider incarnation.
    pub incarnation: Id,
    /// Retains the original positive owner generation.
    pub generation: U64,
}

/// Retains the complete indivisible original common node route.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketCommonRoute {
    /// Names the exact source-installed public node.
    pub node: Id,
    /// Contains the complete actual original owner roster.
    pub owners: Vec<PacketCommonOwner>,
}

/// Retains full original common activation data without issuing an opaque token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketCommonActivation {
    /// Retains the positive original whole-world generation.
    pub generation: U64,
    /// Names the original complete durable publication.
    pub activation_id: Id,
    /// Binds the exact independently installed original world.
    pub world_binding_hash: HashRef,
    /// Contains the complete original owner roster.
    pub owners: Vec<PacketCommonOwner>,
    /// Retains the original zero initialization cut independently of grant time.
    pub boundary: Position,
}

/// Preserves the selected common administrative stop convention.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacketCommonBoundaryPolicy {
    /// Parks at the exclusive full cut without executing a callback at equality.
    HorizonPark,
}

/// Preserves supported original common request bytes and exclusive bounds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum PacketCommonRequest {
    /// Retains a full exact half-open interval and its selected stop semantics.
    ExactRun {
        /// Gives the actual original start cut.
        start: Position,
        /// Gives the exclusive physical boundary ceiling.
        limit: Position,
        /// Retains the source-qualified administrative stop convention.
        boundary_policy: PacketCommonBoundaryPolicy,
    },
    /// Retains finite same-instant phase settlement without a new physical tick.
    BoundarySettle {
        /// Gives the original reached start position.
        start: Position,
        /// Gives the original exclusive same-instant cut.
        limit: Position,
    },
}

/// Retains explicit absent ingress under the installed output-only role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacketAbsentIngress {}

/// Retains the complete original no-ingress common association before callbacks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketCommonGrant {
    /// Names the exact source-selected versioned correlation grammar.
    pub schema: String,
    /// Names the unchanged original common operation.
    pub operation: Id,
    /// Retains its complete current original native route.
    pub route: PacketCommonRoute,
    /// Retains its original full whole-world activation data.
    pub activation: PacketCommonActivation,
    /// Retains the original supported common grant without translation loss.
    pub request: PacketCommonRequest,
    /// Must be explicitly null because this profile admits no input lane.
    #[serde(deserialize_with = "required_null")]
    pub input_batch: Option<PacketAbsentIngress>,
    /// Must be zero; it cannot stand for future producer closure.
    pub input_watermark: U64,
}

fn required_null<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<PacketAbsentIngress>, D::Error> {
    Option::<PacketAbsentIngress>::deserialize(deserializer)
}

impl PacketCommonGrant {
    /// Checks complete correlation against installed native scope and original Begin.
    ///
    /// # Errors
    /// Refuses oversized/malformed or changed original association, incomplete
    /// owner coverage, nonzero/staged ingress, unsupported policies and wrong cuts.
    /// These checks never authenticate a client-supplied common authority.
    pub fn authenticate(
        bytes: &[u8],
        selection: &PacketControlSelection,
        active: &WorldActivateRequest,
        operation: &Id,
        begin: &BeginRequest,
        arguments: &ExactRunArguments,
    ) -> Result<Self, ProviderError> {
        let original: Self = serde_json::from_value(canonical::parse_json(bytes, 8192)?)
            .map_err(crucible_node_contract::ContractError::from)?;
        if selection.realization.bindings.len() != 1
            || selection.realization.owners.len() != 1
            || selection.realization.descriptors.len() != 1
        {
            return Err(ProviderError::Correlation("packet common singleton scope"));
        }
        let binding = &selection.realization.bindings[0];
        let owner = PacketCommonOwner {
            owner: selection.realization.owners[0].id.clone(),
            incarnation: binding.authority.incarnation_id.clone(),
            generation: binding.authority.owner_generation,
        };
        let zero = Position::new(
            U64::new(0),
            U64::new(0),
            crucible_node_contract::Phase::BoundaryControl,
        );
        let (kind, start, limit) = match &original.request {
            PacketCommonRequest::ExactRun {
                start,
                limit,
                boundary_policy: PacketCommonBoundaryPolicy::HorizonPark,
            } => (BeginKind::ExactRun, *start, *limit),
            PacketCommonRequest::BoundarySettle { start, limit }
                if start.time_ps == limit.time_ps =>
            {
                (BeginKind::BoundarySettle, *start, *limit)
            }
            _ => {
                return Err(ProviderError::Correlation(
                    "packet common settlement interval",
                ));
            }
        };
        start.validate()?;
        limit.validate()?;
        if original.schema != "source-owned.packet-common-grant.v1"
            || original.operation != *operation
            || original.route.node != selection.realization.descriptors[0].id
            || original.route.owners != [owner.clone()]
            || original.activation.owners != [owner]
            || original.activation.generation != active.world_generation
            || original.activation.activation_id != active.activation_id
            || original.activation.world_binding_hash != selection.world
            || original.activation.boundary != zero
            || original.input_batch.is_some()
            || original.input_watermark.get() != 0
            || arguments.input_watermark != original.input_watermark
            || arguments.grant_id != original.operation
            || begin.kind != kind
            || arguments.start != start
            || arguments.limit != limit
            || arguments.boundary_policy != BoundaryPolicy::OrdinaryStop
            || start > limit
        {
            return Err(ProviderError::Correlation(
                "packet complete original common grant",
            ));
        }
        Ok(original)
    }
}
