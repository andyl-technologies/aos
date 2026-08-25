//! Scenario-bound guest selectable request resolution.
//!
//! This module is the semantic boundary between one node-qualified, paused
//! guest ABI request and the campaign choice model. It resolves only exact
//! scenario declarations, decodes an optional narrowed domain under the
//! declaration contract, derives a stable opportunity coordinate, and builds
//! replies from already validated selections. It performs no QEMU operation or
//! repository write.

use crucible::{NodeId, ScenarioDefForm};
use crucible_campaign::{
    CampaignCodecError, CampaignHash, ChoiceCoordinate, ChoiceDiscovery, ChoiceDomain,
    ChoiceOpportunity, ScenarioDefId, Selection,
};
use crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest;
use crucible_protocol::{SelectableProtocolError, SelectionReply};
use thiserror::Error;

/// Failure while resolving or replying to one guest selectable request.
#[derive(Debug, Error)]
pub enum GuestSelectableError {
    /// The frozen scenario catalog does not declare the requested name.
    #[error("guest requested unknown scenario selectable `{0}`")]
    UnknownSelectable(String),
    /// The declaration belongs to another producer or guest node.
    #[error("guest selectable `{selectable}` is not owned by node `{node}`")]
    SourceMismatch {
        /// Requested stable selectable name.
        selectable: String,
        /// Node that produced the pending request.
        node: String,
    },
    /// The narrowed domain or derived choice records violate the campaign model.
    #[error("guest selectable campaign contract failed: {0}")]
    Campaign(#[from] CampaignCodecError),
    /// The selected reply cannot be represented by the guest ABI.
    #[error("guest selectable reply encoding failed: {0}")]
    Protocol(#[from] SelectableProtocolError),
}

/// Resolves one exact paused guest request into self-contained choice records.
///
/// The scheduler coordinate commits to the node, trap instruction count, and
/// vCPU. The producer coordinate commits to the scenario declaration's
/// semantic identity and guest protocol version. The request's logical
/// instance remains the opportunity instance key; transport sequence numbers
/// deliberately do not perturb semantic identity.
///
/// # Errors
///
/// Returns [`GuestSelectableError`] when the name is absent, the declaration
/// belongs to another source, narrowed-domain bytes are malformed or broaden
/// the scenario declaration, or canonical record construction fails.
pub(crate) fn resolve_guest_selectable(
    scenario: ScenarioDefId,
    source: &ScenarioDefForm,
    node: &NodeId,
    pending: &SelectablePlanPendingRequest,
) -> Result<ChoiceDiscovery, GuestSelectableError> {
    let request = pending.request();
    let declaration = source
        .selectables()
        .declaration(request.selectable_id())
        .ok_or_else(|| {
            GuestSelectableError::UnknownSelectable(request.selectable_id().to_owned())
        })?;
    let protocol_version = match declaration.source() {
        crucible_campaign::ChoiceSource::Guest {
            node: owner,
            protocol_version,
        } if owner == &node.name => *protocol_version,
        _ => {
            return Err(GuestSelectableError::SourceMismatch {
                selectable: request.selectable_id().to_owned(),
                node: node.name.clone(),
            });
        }
    };
    let domain = request.narrowed_domain().map_or_else(
        || Ok(declaration.domain().clone()),
        ChoiceDomain::from_canonical_bytes,
    )?;
    let coordinate = ChoiceCoordinate {
        scheduler: scheduler_coordinate(node, pending),
        producer: producer_coordinate(declaration.semantic_id().as_hash(), protocol_version),
    };
    let opportunity = ChoiceOpportunity::new(
        scenario,
        declaration,
        &domain,
        coordinate,
        request.instance_key(),
        None,
    )?;
    ChoiceDiscovery::new(declaration.clone(), domain, opportunity).map_err(Into::into)
}

/// Builds one exact ABI reply from a replay-validated selection.
///
/// # Errors
///
/// Returns [`GuestSelectableError`] when the selection does not name the
/// resolved opportunity/domain or the ABI cannot encode its canonical value.
pub(crate) fn selected_guest_reply(
    pending: &SelectablePlanPendingRequest,
    discovery: &ChoiceDiscovery,
    selection: &Selection,
) -> Result<SelectionReply, GuestSelectableError> {
    selection.validate_resolved_references(discovery.opportunity(), discovery.domain())?;
    let opportunity = discovery.opportunity().id()?.content_id().digest();
    let domain = discovery.domain().id()?.content_id().digest();
    SelectionReply::selected(
        pending.request().sequence(),
        opportunity,
        domain,
        selection.value().canonical_bytes(),
    )
    .map_err(Into::into)
}

fn scheduler_coordinate(node: &NodeId, pending: &SelectablePlanPendingRequest) -> CampaignHash {
    let mut material = Vec::with_capacity(8 + node.name.len() + 8 + 4);
    material.extend_from_slice(&(node.name.len() as u64).to_be_bytes());
    material.extend_from_slice(node.name.as_bytes());
    material.extend_from_slice(&pending.icount().to_be_bytes());
    material.extend_from_slice(&pending.vcpu_index().to_be_bytes());
    CampaignHash::derive(
        "crucible.guest-selectable.scheduler-coordinate.v1",
        &material,
    )
}

fn producer_coordinate(declaration: CampaignHash, protocol_version: u32) -> CampaignHash {
    let mut material = Vec::with_capacity(36);
    material.extend_from_slice(&declaration.as_bytes());
    material.extend_from_slice(&protocol_version.to_be_bytes());
    CampaignHash::derive(
        "crucible.guest-selectable.producer-coordinate.v1",
        &material,
    )
}

#[cfg(test)]
mod tests;
