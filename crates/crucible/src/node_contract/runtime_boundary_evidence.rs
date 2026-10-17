//! Bounded original boundary proof retrieval beneath authenticated observations.

use std::collections::{BTreeMap, BTreeSet};

use crucible_node_contract::ContentRef;

use super::*;
use crate::node_scheduling::{InputPayload, ValidatedSchedulingObservation};

impl NodeRuntime {
    /// Reads the complete source-selected evidence for an original stopped observation.
    ///
    /// The opaque observation must still match the actual retaining adapter.
    /// Dependency roles come from its installed codec, rather than JSON shape.
    /// Returned immutable bytes confer no dispatch or input-consumption authority.
    ///
    /// # Errors
    /// Refuses foreign, busy or changed original owners, unavailable codecs,
    /// invalid full references, corrupt bodies, or complete count/byte overruns.
    pub fn scheduling_evidence(
        &mut self,
        original: &ValidatedSchedulingObservation,
        limits: InputProvenanceLimits,
    ) -> Result<Vec<InputPayload>, RuntimePollFailure> {
        self.validate_activation(&original.activation)
            .map_err(RuntimePollFailure::Admission)?;
        let route = self
            .checked_route(&original.observation.node)
            .map_err(RuntimePollFailure::Admission)?;
        self.validate_owners_available(&route)
            .map_err(RuntimePollFailure::Admission)?;
        let ceiling = InputProvenanceLimits::default();
        if limits.maximum_objects > ceiling.maximum_objects
            || limits.maximum_bytes > ceiling.maximum_bytes
        {
            return Err(RuntimePollFailure::Admission(RuntimeError::ResourceLimit));
        }

        let result = (|| {
            let handle = self
                .nodes
                .get(&route.node)
                .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?;
            if original.observation.owners != route.owners {
                return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
            }
            handle
                .validate_scheduling_observation(&original.activation, &original.observation)
                .map_err(RuntimePollFailure::Native)?;
            let mut roots = BTreeSet::from([original.observation.proof_ref.clone()]);
            roots.extend(
                original
                    .observation
                    .bounds
                    .iter()
                    .map(|bound| bound.proof_ref.clone()),
            );
            roots.extend(
                original
                    .observation
                    .external_inputs
                    .iter()
                    .map(|input| input.proof_ref.clone()),
            );
            if let Some(progress) = &original.observation.input_progress {
                roots.insert(progress.proof_ref.clone());
            }
            let mut retained = BTreeMap::new();
            for root in roots {
                // This existing codec hook declares its complete flattened closure.
                // It is validated independently before any body is accepted.
                let dependencies = handle
                    .input_provenance_dependencies(&original.activation, &root, limits)
                    .map_err(RuntimePollFailure::Native)?;
                let unique: BTreeSet<&ContentRef> = dependencies.iter().collect();
                if unique.len() != dependencies.len() || unique.contains(&root) {
                    return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
                }
                handle
                    .validate_input_provenance_dependencies(
                        &original.activation,
                        &root,
                        &dependencies,
                    )
                    .map_err(RuntimePollFailure::Native)?;
                let references: Vec<_> = std::iter::once(root).chain(dependencies).collect();
                input_provenance::reserve_objects(&retained, &references, limits)?;
                let objects = handle
                    .read_boundary_evidence(&original.activation, &references, limits.maximum_bytes)
                    .map_err(RuntimePollFailure::Native)?;
                handle
                    .validate_boundary_evidence(&original.activation, &references, &objects)
                    .map_err(RuntimePollFailure::Native)?;
                input_provenance::retain_objects(&mut retained, &references, objects)?;
            }
            handle
                .validate_scheduling_observation(&original.activation, &original.observation)
                .map_err(RuntimePollFailure::Native)?;
            Ok(retained.into_values().collect())
        })();
        if result.is_err() {
            // Failed proof adoption cannot leave a changed owner eligible for grants.
            self.contain_roster(&route);
        }
        result
    }
}
