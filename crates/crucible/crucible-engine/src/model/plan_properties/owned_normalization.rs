//! In-place DSL normalization of admitted assertion predicates.

use super::*;

#[cfg(test)]
mod tests;

pub(super) fn resolve_events(world: &World, events: &mut [Event]) -> Result<(), EngineError> {
    for event in events {
        if let Some(trigger) = &mut event.trigger {
            resolve_predicate(trigger, world)?;
        }
    }
    Ok(())
}

pub(super) fn resolve_assertions(
    world: &World,
    _plan: &Plan,
    mut assertions: Vec<AssertionDef>,
) -> Result<Vec<AssertionDef>, EngineError> {
    for assertion in &mut assertions {
        match &mut assertion.property {
            Property::Always { predicate }
            | Property::Sometimes { predicate }
            | Property::AfterQuiescence { predicate }
            | Property::Reachable { predicate, .. } => resolve_predicate(predicate, world)?,
            Property::Eventually {
                trigger, property, ..
            } => {
                resolve_predicate(trigger, world)?;
                resolve_predicate(property, world)?;
            }
        }
    }
    Ok(assertions)
}

pub(super) fn canonicalize_assertions(assertions: &mut [AssertionDef]) -> Result<(), EngineError> {
    for assertion in assertions.iter_mut() {
        match &mut assertion.property {
            Property::Always { predicate }
            | Property::Sometimes { predicate }
            | Property::AfterQuiescence { predicate }
            | Property::Reachable { predicate, .. } => canonicalize_predicate(predicate)?,
            Property::Eventually {
                trigger, property, ..
            } => {
                canonicalize_predicate(trigger)?;
                canonicalize_predicate(property)?;
            }
        }
    }
    // Duplicate IDs were rejected before this step, so the old secondary
    // material comparison cannot affect the resulting order.
    assertions.sort_unstable_by(|left, right| left.id.cmp(&right.id));
    Ok(())
}

fn canonicalize_predicate(predicate: &mut Predicate) -> Result<(), EngineError> {
    match predicate {
        Predicate::AllOf { predicates } | Predicate::AnyOf { predicates } => {
            for predicate in predicates.iter_mut() {
                canonicalize_predicate(predicate)?;
            }
            admit_array::<(String, Predicate)>(predicates.len())?;
            let mut keyed = Vec::new();
            keyed
                .try_reserve_exact(predicates.len())
                .map_err(|source| {
                    scenario_serialization_error(format!(
                        "reserve canonical predicate ordering: {source}"
                    ))
                })?;
            for predicate in predicates.drain(..) {
                let key = canonical_predicate_material(&predicate)?;
                keyed.push((key, predicate));
            }
            // Stable order for equal material keys preserves the previous
            // canonicalization even when distinct leaves render identically.
            // Rust's stable slice sort uses at most one typed backing slice.
            admit_array::<(String, Predicate)>(keyed.len())?;
            keyed.sort_by(|left, right| left.0.cmp(&right.0));
            // Draining preserves the admitted original Vec capacity. Moving
            // exactly the same children back does not allocate another image.
            predicates.extend(keyed.into_iter().map(|(_, predicate)| predicate));
        }
        Predicate::Once { predicate } | Predicate::Not { predicate } => {
            canonicalize_predicate(predicate)?;
        }
        _ => {}
    }
    Ok(())
}

fn admit_array<T>(count: usize) -> Result<(), EngineError> {
    crate::owned_decode::charge_array::<T>(count)
        .map_err(|source| EngineError::ArtifactDecodeAdmission { source })
}

fn resolve_predicate(predicate: &mut Predicate, world: &World) -> Result<(), EngineError> {
    match predicate {
        Predicate::Named { name, nodes } if nodes.is_empty() => {
            // The four known DSL forms allocate only the enumerated typed
            // children and node strings. Unknown names remain in place.
            match name.as_str() {
                "no_crashed_nodes" => {
                    let count = world.vm_nodes().len();
                    admit_array::<Predicate>(count.max(2))?;
                    admit_array::<Predicate>(1)?;
                    for node in world.vm_nodes() {
                        admit_array::<u8>(node.id.name.len())?;
                    }
                }
                "quiescent" => {}
                name if name.starts_with("node_alive:") || name.starts_with("node_crashed:") => {
                    let Some((_, node)) = name.split_once(':') else {
                        return Ok(());
                    };
                    admit_array::<u8>(node.len())?;
                    admit_array::<Predicate>(1)?;
                }
                _ => return Ok(()),
            }
            if let Some(resolved) = resolve_named_predicate_dsl_for_context(name, world) {
                *predicate = resolved;
            }
        }
        Predicate::AllOf { predicates } | Predicate::AnyOf { predicates } => {
            for predicate in predicates {
                resolve_predicate(predicate, world)?;
            }
        }
        Predicate::Once { predicate } | Predicate::Not { predicate } => {
            resolve_predicate(predicate, world)?;
        }
        _ => {}
    }
    Ok(())
}
