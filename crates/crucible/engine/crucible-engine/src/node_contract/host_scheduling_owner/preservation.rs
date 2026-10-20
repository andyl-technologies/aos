//! Selects a separate common-state preservation factory without widening source one.
//!
//! Edition two remains an unqualified component until native capture and fresh
//! whole-world restoration are operational. Its metadata grants no capture.

use super::*;

pub(super) const PROFILE: &str = "source-owned.host-scheduling-original-lineage/2";

#[derive(Clone, Copy, PartialEq)]
pub(super) enum Edition {
    Unsupported,
    OriginalLineage,
    CompleteOriginalLineage,
}

/// Encodes the distinct original common-state continuation factory definition.
///
/// # Errors
/// Reports failure to canonically encode the fixed source-owned definition.
pub fn host_scheduling_continuation_owner_definition() -> Result<Vec<u8>, OperationFailure> {
    canonical::canonical_json(&json!({
        "schema":"source-owned.host-scheduling-owner/2",
        "state":"complete original Runtime7 and Scheduling1 queues, credits, deliveries, input commitments, native ancestry and typed body closure; no independent model queue",
        "origin":"core-issued bounded original ticket under actual PID/thread/runtime custody; portable decoded records cannot construct a ticket",
        "restore":"one fresh original slot; complete native source/target journals and opaque Runtime7 context before Arm; exact scheduler source seal before one cache installation; no operation or acknowledgement replay",
        "profile":PROFILE,
        "qualification":"unsupported until complete native capture and genuine whole fresh restoration qualify this selected implementation; source-one remains unchanged"
    })).map_err(failure)
}

/// Encodes the source-two initializer for explicit original host state roles.
///
/// # Errors
/// Refuses invalid or duplicate domain/connection roles or encoding failure.
pub fn host_scheduling_continuation_owner_configuration(
    domains: &HostSchedulingDomains,
) -> Result<Vec<u8>, OperationFailure> {
    validate_domains(domains)?;
    canonical::canonical_json(&json!({
        "schema":"source-owned.host-scheduling-configuration/2",
        "definition":definition(Edition::OriginalLineage)?,
        "domains":domains
    }))
    .map_err(failure)
}

/// Returns the distinct source-two preparation codec without readiness authority.
///
/// # Errors
/// Reports invalid fixed identity or definition encoding failure.
pub fn host_scheduling_continuation_owner_preparation_schema() -> Result<SchemaRef, OperationFailure>
{
    Ok(SchemaRef {
        id: Id::new("source-owned.host-scheduling-owner-preparation/2").map_err(failure)?,
        version: 2,
        definition: definition(Edition::OriginalLineage)?,
        extensions: Default::default(),
    })
}

pub(super) fn definition(edition: Edition) -> Result<ContentRef, OperationFailure> {
    match edition {
        Edition::Unsupported => definition_ref(),
        Edition::CompleteOriginalLineage => canonical::content_ref(
            &super::complete::host_scheduling_complete_owner_definition()?,
            "application/json",
        )
        .map_err(failure),
        Edition::OriginalLineage => canonical::content_ref(
            &host_scheduling_continuation_owner_definition()?,
            "application/json",
        )
        .map_err(failure),
    }
}

pub(super) fn configuration(
    edition: Edition,
    domains: &HostSchedulingDomains,
) -> Result<Vec<u8>, OperationFailure> {
    match edition {
        Edition::Unsupported => host_scheduling_owner_configuration(domains),
        Edition::OriginalLineage => host_scheduling_continuation_owner_configuration(domains),
        Edition::CompleteOriginalLineage => {
            super::complete::host_scheduling_complete_owner_configuration(domains)
        }
    }
}

pub(super) fn preparation(edition: Edition) -> Result<SchemaRef, OperationFailure> {
    match edition {
        Edition::Unsupported => host_scheduling_owner_preparation_schema(),
        Edition::OriginalLineage => host_scheduling_continuation_owner_preparation_schema(),
        Edition::CompleteOriginalLineage => {
            super::complete::host_scheduling_complete_owner_preparation_schema()
        }
    }
}

impl HostSchedulingOwner {
    /// Creates the distinct source-two component before any native capture occurs.
    ///
    /// CaptureNone and Unsupported remain enforced during component development.
    /// This constructor never changes source-one compatibility or qualifies a
    /// portable descriptor as capture authority.
    ///
    /// # Errors
    /// Refuses foreign source-two metadata, incomplete domains, unsupported
    /// capability claims or exhausted complete metadata credit.
    pub fn new_continuation(
        selection: HostSchedulingSelection,
        world: HashRef,
    ) -> Result<Self, OperationFailure> {
        Self::create(selection, world, Edition::OriginalLineage, None)
    }

    /// Retains one original source-two ticket beneath a genuine fresh source revision.
    ///
    /// The original ticket is consumed without copying its body closure. It must
    /// originate in source two with the same complete compatibility and domain
    /// roles. Native restoration and pre-Ready journal installation remain
    /// independent default-refusing requirements.
    ///
    /// # Errors
    /// Refuses foreign ticket birth, unsupported legacy/source-one capture,
    /// changed compatible selection or invalid fresh source metadata.
    pub fn restore_continuation(
        selection: HostSchedulingSelection,
        world: HashRef,
        ticket: HostSchedulingOriginalContinuationTicket,
    ) -> Result<Self, OperationFailure> {
        ticket.authenticate_birth().map_err(failure)?;
        let record = ticket.record();
        if record.source.descriptor.model_ref != definition(Edition::OriginalLineage)?
            || record.source.descriptor != selection.descriptor
            || record.source.binding.compatibility != selection.binding.compatibility
            || record.source.domains != selection.domains
            || record.source.operating_policy != selection.operating_policy
            || record.source.guarantees != selection.guarantees
            || record.source.owner.owner != selection.owner.owner
            || record.scheduling.world_binding_hash != world
            || !matches!(
                record.runtime,
                HostSchedulingRuntimeRecord::OriginalLineage(_)
            )
        {
            return Err(failure(
                "fresh host source differs from original continuation ticket",
            ));
        }
        Self::create(selection, world, Edition::OriginalLineage, Some(ticket))
    }
}

#[cfg(test)]
mod tests {
    // These source-selection controls panic only when closed fixture setup fails.
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn selection_two() -> (HostSchedulingSelection, HashRef) {
        let original = super::super::tests::source_owner();
        let source = original.source();
        let mut selection = source.selection().clone();
        let definition = definition(Edition::OriginalLineage).unwrap();
        let configuration = canonical::content_ref(
            &host_scheduling_continuation_owner_configuration(&selection.domains).unwrap(),
            "application/json",
        )
        .unwrap();
        selection.descriptor.model_ref = definition.clone();
        selection.descriptor.configuration_ref = configuration.clone();
        selection.descriptor.initialization_ref = configuration.clone();
        selection.binding.compatibility.profile_ref = definition;
        selection.binding.compatibility.configuration_ref = configuration;
        selection
            .binding
            .compatibility
            .implementation
            .formats
            .retain(|schema| {
                schema.id.as_str() != "source-owned.host-scheduling-owner-preparation/1"
            });
        selection
            .binding
            .compatibility
            .implementation
            .formats
            .push(host_scheduling_continuation_owner_preparation_schema().unwrap());
        selection
            .binding
            .compatibility
            .implementation
            .formats
            .sort_by(|left, right| left.id.cmp(&right.id));
        selection.owner.node_bindings[0].binding_hash = selection.binding.identity().unwrap();
        (selection, source.world().clone())
    }

    #[test]
    fn source_two_definition_does_not_open_source_one_or_claim_capture() {
        let (selection, world) = selection_two();
        assert!(HostSchedulingOwner::new(selection.clone(), world.clone()).is_err());
        let owner = HostSchedulingOwner::new_continuation(selection, world).unwrap();
        let source = owner.source();
        source
            .authenticate_preparation_source(source.world())
            .unwrap();
        assert!(source.authenticate_current().is_err());
        assert_eq!(
            source.selection().guarantees.capture_scope,
            crucible_node_format::CaptureScope::None
        );
        assert_eq!(
            source.selection().guarantees.continuation,
            crucible_node_format::Continuation::Unsupported
        );
        assert!(source.original_ticket.is_none());
    }

    #[test]
    fn source_two_refuses_capture_metadata_promotion_without_operational_closure() {
        let (mut selection, world) = selection_two();
        selection.guarantees.capture_scope = crucible_node_format::CaptureScope::CompleteModel;
        selection.guarantees.continuation = crucible_node_format::Continuation::Exact;
        let bytes =
            canonical::canonical_json(&serde_json::to_value(&selection.guarantees).unwrap())
                .unwrap();
        selection.binding.compatibility.guarantees_ref =
            canonical::content_ref(&bytes, "application/json").unwrap();
        selection.owner.node_bindings[0].binding_hash = selection.binding.identity().unwrap();
        assert!(HostSchedulingOwner::new_continuation(selection, world).is_err());
    }
}
