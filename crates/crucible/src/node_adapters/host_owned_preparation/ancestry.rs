//! Authenticates bounded source preparation ancestry before retaining model bodies.

use super::*;

pub(super) struct OriginalPreparation {
    pub(super) native: ContentRef,
    pub(super) references: Vec<ContentRef>,
}

pub(super) fn authenticate(
    source: &crate::node_state::AuthenticatedNativeSource<'_>,
    descriptor: &NodeDescriptor,
    maximum: usize,
) -> Result<OriginalPreparation, OperationFailure> {
    let outer = source
        .native()
        .map_err(|error| failure(&error.to_string()))?;
    let mut remaining = maximum
        .checked_sub(outer.len())
        .ok_or_else(|| failure("public finite-model envelope exhausts ancestry credit"))?;
    let source_owner = source
        .archive()
        .manifest()
        .owners
        .iter()
        .find(|captured| captured.capture_owner_id == source.owner().owner)
        .ok_or_else(|| failure("public finite-model source capture owner is absent"))?;
    let mut current = outer;
    let mut references = Vec::new();
    references
        .try_reserve_exact(64 * 9)
        .map_err(|_| failure("public finite-model ancestry reservation failed"))?;
    let mut generation = None;
    let mut expected_model = None;
    let mut native = None;
    for depth in 0..64 {
        let wire: Wire = decode(current, maximum)?;
        validate_wire_scope(&wire, &descriptor.id)?;
        let native_bytes = body(source, &wire.native_state, &mut remaining)?;
        let preparation = body(source, &wire.world_preparation, &mut remaining)?;
        let session_bytes = body(source, &wire.session, &mut remaining)?;
        let common_bytes = body(source, &wire.ready, &mut remaining)?;
        let native_ready = body(source, &wire.native_ready, &mut remaining)?;
        let original_model = body(source, &wire.original_model, &mut remaining)?;
        let world = OriginalWorldPreparation::decode(preparation, maximum)?;
        let coordinator = body(source, &world.coordinator, &mut remaining)?;
        let publication = body(source, &world.publication, &mut remaining)?;
        world.validate_publication(publication, maximum)?;
        let prepared = world.node(&descriptor.id)?;
        let session: Session = decode(session_bytes, maximum)?;
        let common: Ready = decode(common_bytes, maximum)?;
        let origin = match (
            &wire.previous,
            session.format.as_str(),
            &session.source_preparation,
        ) {
            (None, "crucible.host.original-owned-model-session", None) => {
                wire.original_model == descriptor.initialization_ref
                    && prepared.boundary
                        == Position::new(0.into(), 0.into(), Phase::BoundaryControl)
            }
            (Some(previous), "crucible.host.restored-owned-model-session", Some(source)) => {
                previous == source
            }
            _ => false,
        };
        if !origin
            || (depth == 0 && world.activation != source.runtime().source_activation)
            || world.activation.world_binding_hash
                != source.runtime().source_activation.world_binding_hash
            || generation.is_some_and(|later| world.activation.generation >= later)
            || prepared.owners.len() != 1
            || prepared.prepared_owners.len() != 1
            || prepared.ready_receipt != wire.ready
            || (depth == 0
                && source_owner.binding_hashes.as_slice() != std::slice::from_ref(&session.binding))
            || prepared.prepared_owners[0].binding_hashes.as_slice()
                != std::slice::from_ref(&session.binding)
            || prepared.prepared_owners[0].prepared_token.as_str()
                != format!("host/model-prepared/{}", wire.session.hash.digest)
            || session.version != 1
            || session.world_hash != world.activation.world_binding_hash
            || session.node != descriptor.id
            || session.owners != prepared.owners
            || session.complete_original_owners != world.activation.owners
            || session.initialization != descriptor.initialization_ref
            || session.initial_native_state != wire.original_model
            || session.original_native_ready != wire.native_ready
            || common.format != "crucible.host.public-owned-model-ready"
            || common.version != 1
            || common.world != world.activation
            || common.session != wire.session
            || common.initial_native_state != wire.original_model
            || common.original_native_ready != wire.native_ready
            || common.inventory != prepared.state_inventory
            || common.boundary != prepared.boundary
            || common.boundary != world.activation.boundary
            || common.owners != prepared.owners
            || original_model.is_empty()
            || coordinator.is_empty()
        {
            return Err(failure(
                "public finite-model original preparation ancestry differs",
            ));
        }
        let original_owner = &prepared.owners[0];
        let mut expected_ready = b"host-model-owned-inactive-v1".to_vec();
        expected_ready.extend_from_slice(&prepared.boundary.time_ps.get().to_le_bytes());
        expected_ready.extend_from_slice(original_owner.owner.as_str().as_bytes());
        expected_ready.push(0);
        expected_ready.extend_from_slice(original_owner.incarnation.as_str().as_bytes());
        expected_ready.extend_from_slice(&original_owner.generation.get().to_le_bytes());
        if native_ready != expected_ready {
            return Err(failure("public finite-model original native Ready differs"));
        }
        // A restored session's initial bytes must be the actual previous native
        // model, not another signed leaf with a self-consistent hash.
        let model = state::public_owned_native_model_reference(native_bytes, maximum)?;
        if expected_model
            .as_ref()
            .is_some_and(|expected| expected != &model)
        {
            return Err(failure(
                "restored public session changed its original native model",
            ));
        }
        expected_model = wire.previous.as_ref().map(|_| wire.original_model.clone());
        generation = Some(world.activation.generation);
        if depth == 0 {
            native = Some(wire.native_state.clone());
        }
        for reference in [
            wire.native_state,
            wire.world_preparation,
            wire.session,
            wire.ready,
            wire.native_ready,
            wire.original_model,
            world.coordinator,
            world.publication,
        ] {
            references.push(reference);
        }
        let Some(previous) = wire.previous else {
            references.sort();
            references.dedup();
            return Ok(OriginalPreparation {
                native: native
                    .ok_or_else(|| failure("public finite-model native source is absent"))?,
                references,
            });
        };
        if depth == 63 {
            return Err(failure(
                "public finite-model ancestry exceeds generation credit",
            ));
        }
        current = body(source, &previous, &mut remaining)?;
        references.push(previous);
    }
    Err(failure("public finite-model ancestry credit exhausted"))
}
