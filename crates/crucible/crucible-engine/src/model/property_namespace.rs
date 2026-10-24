//! Backend-neutral property admission over an installed observable namespace.
//!
//! A namespace describes names and supported predicate surfaces. It does not
//! authenticate provider capabilities or invent observations; installed world
//! compilers populate it only after checking their actual observation adapters.
//! The legacy world adapter preserves its historical VM-only predicate policy.

use super::*;

/// Selects an observation surface used by a property predicate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PropertyObservation {
    /// Observes actual captured console bytes.
    Console,
    /// Observes qualified guest execution coverage.
    Coverage,
    /// Observes qualified memory or register samples.
    Memory,
    /// Observes actual completions of the selected I/O kind.
    Io(IoEventKind),
    /// Observes native lifecycle transitions.
    Lifecycle,
    /// Observes opted-in white-box guest markers.
    GuestMarker,
}

/// Names logical property targets and their installed observation surfaces.
///
/// This pure admission context is separate from VM declarations. Declaring a
/// surface here supplies no live authority. The owning compiler must derive
/// each entry from an authenticated installed adapter and retain that binding
/// in the immutable world model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PropertyNamespace {
    nodes: BTreeMap<NodeId, BTreeSet<PropertyObservation>>,
    network: bool,
    quiescence: bool,
    named_predicates: BTreeSet<String>,
    legacy_named_predicates: bool,
}

impl PropertyNamespace {
    /// Constructs a finite namespace without creating VM or device definitions.
    ///
    /// `network` and `quiescence` require installed adapters for those world
    /// predicates. `named_predicates` enumerates actual installed host oracles;
    /// an undeclared name cannot silently evaluate as an unsupported false fact.
    ///
    /// # Errors
    /// Refuses excessive inventories or empty/oversized logical names.
    pub fn new(
        nodes: BTreeMap<NodeId, BTreeSet<PropertyObservation>>,
        network: bool,
        quiescence: bool,
        named_predicates: BTreeSet<String>,
    ) -> Result<Self, EngineError> {
        if nodes.len() > 1024
            || named_predicates.len() > 256
            || nodes.keys().any(|node| !valid_name(&node.name))
            || named_predicates.iter().any(|name| !valid_name(name))
        {
            return Err(scenario_serialization_error(
                "property namespace exceeds finite name bounds",
            ));
        }
        Ok(Self {
            nodes,
            network,
            quiescence,
            named_predicates,
            legacy_named_predicates: false,
        })
    }

    /// Projects a legacy world's exact historical property namespace.
    ///
    /// Legacy properties reference VM participants, permit opaque named host
    /// predicates, and restrict guest markers to opted-in VM nodes. This
    /// adapter preserves those rules without qualifying a new backend surface.
    #[must_use]
    pub fn from_world(world: &World) -> Self {
        let nodes = world
            .vm_nodes()
            .iter()
            .map(|node| {
                let mut observations = BTreeSet::from([
                    PropertyObservation::Console,
                    PropertyObservation::Coverage,
                    PropertyObservation::Memory,
                    PropertyObservation::Lifecycle,
                ]);
                observations.extend(
                    [
                        IoEventKind::Any,
                        IoEventKind::BlockRead,
                        IoEventKind::BlockWrite,
                        IoEventKind::Fsync,
                        IoEventKind::NineP,
                        IoEventKind::Network,
                    ]
                    .map(PropertyObservation::Io),
                );
                if node.white_box == WhiteBoxPolicy::Enabled {
                    observations.insert(PropertyObservation::GuestMarker);
                }
                (node.id.clone(), observations)
            })
            .collect();
        Self {
            nodes,
            network: true,
            quiescence: true,
            named_predicates: BTreeSet::new(),
            legacy_named_predicates: true,
        }
    }

    fn validate_assertions(&self, assertions: &[AssertionDef]) -> Result<(), EngineError> {
        let node_ids = self.nodes.keys().collect::<BTreeSet<_>>();
        let white_box_node_ids = self
            .nodes
            .iter()
            .filter(|(_, surfaces)| surfaces.contains(&PropertyObservation::GuestMarker))
            .map(|(node, _)| node)
            .collect();
        let mut assertion_ids = BTreeSet::new();
        for assertion in assertions {
            if !assertion_ids.insert(assertion.id.clone()) {
                return Err(EngineError::PropertyDuplicateAssertionId {
                    id: assertion.id.clone(),
                });
            }
        }

        for assertion in assertions {
            if matches!(assertion.property, Property::AfterQuiescence { .. }) && !self.quiescence {
                return Err(scenario_serialization_error(
                    "property requires installed whole-world quiescence evidence",
                ));
            }
            validate_property_for_world(
                &assertion.property,
                &node_ids,
                &assertion_ids,
                &white_box_node_ids,
            )?;
            match &assertion.property {
                Property::Always { predicate }
                | Property::Sometimes { predicate }
                | Property::AfterQuiescence { predicate }
                | Property::Reachable { predicate, .. } => self.validate_surfaces(predicate)?,
                Property::Eventually {
                    trigger, property, ..
                } => {
                    self.validate_surfaces(trigger)?;
                    self.validate_surfaces(property)?;
                }
            }
        }
        Ok(())
    }

    fn validate_surfaces(&self, predicate: &Predicate) -> Result<(), EngineError> {
        match predicate {
            Predicate::ConsoleMatch { node, .. } => {
                self.require_surface(node, PropertyObservation::Console)
            }
            Predicate::CoveragePoint { node, .. } => {
                self.require_surface(node, PropertyObservation::Coverage)
            }
            Predicate::MemoryPredicate { node, .. } => {
                self.require_surface(node, PropertyObservation::Memory)
            }
            Predicate::IoPattern {
                node,
                kind: IoEventKind::Any,
            } if self.nodes.get(node).is_some_and(|surfaces| {
                surfaces
                    .iter()
                    .any(|surface| matches!(surface, PropertyObservation::Io(_)))
            }) =>
            {
                Ok(())
            }
            Predicate::IoPattern { node, kind } => {
                self.require_surface(node, PropertyObservation::Io(*kind))
            }
            Predicate::NodeState { node, .. } => {
                self.require_surface(node, PropertyObservation::Lifecycle)
            }
            Predicate::NetworkMatch { .. } if !self.network => Err(scenario_serialization_error(
                "property requires an installed network observation adapter",
            )),
            Predicate::Quiescent if !self.quiescence => Err(scenario_serialization_error(
                "property requires installed whole-world quiescence evidence",
            )),
            Predicate::Named { name, .. }
                if !self.legacy_named_predicates && !self.named_predicates.contains(name) =>
            {
                Err(scenario_serialization_error(
                    "property names an uninstalled host predicate oracle",
                ))
            }
            Predicate::AllOf { predicates } | Predicate::AnyOf { predicates } => {
                for predicate in predicates {
                    self.validate_surfaces(predicate)?;
                }
                Ok(())
            }
            Predicate::Once { predicate } | Predicate::Not { predicate } => {
                self.validate_surfaces(predicate)
            }
            _ => Ok(()),
        }
    }

    fn require_surface(
        &self,
        node: &NodeId,
        surface: PropertyObservation,
    ) -> Result<(), EngineError> {
        if self
            .nodes
            .get(node)
            .is_some_and(|surfaces| surfaces.contains(&surface))
        {
            Ok(())
        } else {
            Err(scenario_serialization_error(
                "property requires an uninstalled node observation surface",
            ))
        }
    }
}

impl Properties {
    /// Admits assertions against actual logical names and observation adapters.
    ///
    /// It reuses the existing predicate validation and canonical assertion
    /// ordering. No VM declarations or backend substitutions are constructed.
    ///
    /// # Errors
    /// Refuses invalid predicate structure/names, duplicate assertions or any
    /// required observation surface absent from the installed namespace.
    pub fn from_assertions_for_namespace(
        namespace: &PropertyNamespace,
        assertions: Vec<AssertionDef>,
    ) -> Result<Self, EngineError> {
        namespace.validate_assertions(&assertions)?;
        Ok(Self::from_canonical_assertions(canonical_assertions(
            &assertions,
        )))
    }

    /// Decodes unchanged compact property bytes for a backend-neutral namespace.
    ///
    /// The existing binary magic, tags, canonical material and identity remain
    /// unchanged. Only the static name/surface admission context differs.
    ///
    /// # Errors
    /// Refuses malformed/trailing binary input, an identity mismatch or any
    /// assertion unavailable under the supplied installed namespace.
    pub fn from_compact_binary_for_namespace(
        namespace: &PropertyNamespace,
        bytes: &[u8],
    ) -> Result<Self, EngineError> {
        let mut reader = ScenarioBinaryReader::new(bytes, PROPERTIES_BINARY_MAGIC)?;
        let id = reader.read_hash()?;
        let count = reader.read_collection_count("properties.assertion")?;
        let mut assertions = Vec::with_capacity(count);
        for _ in 0..count {
            assertions.push(read_assertion_binary(&mut reader)?);
        }
        reader.finish()?;

        let properties = Self::from_assertions_for_namespace(namespace, assertions)?;
        validate_serialized_id("properties", id, properties.content_hash())?;
        Ok(properties)
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 256
}

#[cfg(test)]
#[path = "property_namespace_tests.rs"]
mod tests;
