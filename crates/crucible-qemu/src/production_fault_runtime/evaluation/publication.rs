//! Precommit ownership for production evaluation publication.
//!
//! A live adapter commit can make architectural state visible before control
//! returns to the controller. Every collection published after that point is
//! therefore reserved and owned here before the commit begins. Publication
//! then consists only of moves into capacity that this type already secured.

use super::*;

/// Owns one complete postcommit publication batch.
pub(super) struct StagedEvaluationPublication {
    emitted_events: Vec<ReferencedSignalEvent>,
    node_boot_requests: Vec<NodeId>,
    search_choices: Vec<BindingSearchChoice>,
    coordinate: FaultCoordinate,
    expected_observations: usize,
}

impl StagedEvaluationPublication {
    /// Reserves every persistent destination and takes preview-owned records.
    pub(super) fn stage(
        runtime: &mut ProductionFaultRuntime,
        coordinate: FaultCoordinate,
        preview: &mut BindingEvaluation,
    ) -> Result<Self, ProductionFaultRuntimeError> {
        let emitted_count = preview.emitted_events.len();
        runtime
            .emitted_events
            .try_reserve_exact(emitted_count)
            .map_err(|_| {
                runtime_collection_reservation(
                    "event_records",
                    runtime.emitted_events.len(),
                    emitted_count,
                    runtime.resource_limits,
                )
            })?;

        let expected_observations = preview.observations.len();
        runtime
            .pending_qemu_observations
            .try_reserve_exact(expected_observations)
            .map_err(|_| {
                runtime_collection_reservation(
                    "event_records",
                    runtime.pending_qemu_observations.len(),
                    expected_observations,
                    runtime.resource_limits,
                )
            })?;

        let node_boot_requests = stage_node_boot_requests(
            &preview.actions,
            &runtime.pending_node_boot,
            runtime.resource_limits,
        )?;

        if !preview.search_choices.is_empty() {
            runtime.resource_limits.reserve(
                "search_states",
                u64::try_from(runtime.pending_search_choices.len()).map_err(|_| {
                    FaultResourceLimitError::Representation {
                        field: "search_states",
                        value: u64::MAX,
                    }
                })?,
                1,
            )?;
            runtime.resource_limits.reserve(
                "search_choices_per_state",
                0,
                u64::try_from(preview.search_choices.len()).map_err(|_| {
                    FaultResourceLimitError::Representation {
                        field: "search_choices_per_state",
                        value: u64::MAX,
                    }
                })?,
            )?;
            runtime
                .pending_search_choices
                .try_reserve_exact(1)
                .map_err(|_| {
                    runtime_collection_reservation(
                        "search_states",
                        runtime.pending_search_choices.len(),
                        1,
                        runtime.resource_limits,
                    )
                })?;
        }

        Ok(Self {
            emitted_events: std::mem::take(&mut preview.emitted_events),
            node_boot_requests,
            search_choices: std::mem::take(&mut preview.search_choices),
            coordinate,
            expected_observations,
        })
    }

    /// Returns the deterministic event records expected from the live run.
    pub(super) fn emitted_events(&self) -> &[ReferencedSignalEvent] {
        &self.emitted_events
    }

    /// Returns the deterministic explorer choices expected from the live run.
    pub(super) fn search_choices(&self) -> &[BindingSearchChoice] {
        &self.search_choices
    }

    /// Returns the exact controller-observation capacity reserved for commit.
    pub(super) const fn expected_observations(&self) -> usize {
        self.expected_observations
    }

    /// Publishes the staged batch without allocating.
    pub(super) fn publish(mut self, runtime: &mut ProductionFaultRuntime) {
        runtime.emitted_events.append(&mut self.emitted_events);
        runtime.pending_node_boot = self.node_boot_requests;
        if !self.search_choices.is_empty() {
            runtime
                .pending_search_choices
                .push((self.coordinate, self.search_choices));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::production_fault_runtime::test_support::{lifecycle_action, test_host_manifests};
    use crucible::model::SearchChoiceId;

    #[test]
    fn production_evaluation_publication_is_owned_before_commit() {
        let plan = FaultSignalPlan::new(Vec::new(), Vec::new(), FaultResourceLimits::default())
            .unwrap_or_else(|error| panic!("empty plan should be valid: {error}"));
        let nodes = QemuNodeSet::new();
        let mut runtime = ProductionFaultRuntime::new(
            plan,
            None,
            SignalBoundarySnapshot::default(),
            ContentHash::from_bytes(b"staged-evaluation-publication"),
            test_host_manifests(),
            &nodes,
        )
        .unwrap_or_else(|error| panic!("empty production runtime should build: {error}"));
        let coordinate = FaultCoordinate {
            virtual_nanos: 17,
            retired_instructions: Some(23),
        };
        let choice = BindingSearchChoice {
            id: SearchChoiceId::from_content_hash(ContentHash::from_bytes(b"staged-choice")),
            candidates_digest: ContentHash::from_bytes(b"staged-candidates"),
            candidate_count: 2,
            selected_index: Some(1),
            overridden: true,
        };
        let mut preview = BindingEvaluation {
            actions: vec![lifecycle_action(
                NodeLifecycleTransition::Boot,
                NodeBootPolicy::Immediate,
            )],
            observations: vec![FaultObservation {
                semantic_version: crucible::model::FAULT_RUNTIME_STATE_VERSION,
                kind: FaultObservationKind::EffectApplied,
                coordinate,
                binding: None,
                target: None,
                opportunity: None,
                evidence: ContentHash::from_bytes(b"staged-observation"),
            }],
            search_choices: vec![choice.clone()],
            ..BindingEvaluation::default()
        };

        let publication =
            StagedEvaluationPublication::stage(&mut runtime, coordinate, &mut preview)
                .unwrap_or_else(|error| panic!("publication should stage before commit: {error}"));

        assert!(preview.search_choices.is_empty());
        assert_eq!(publication.search_choices(), std::slice::from_ref(&choice));
        assert_eq!(publication.expected_observations(), 1);
        publication.publish(&mut runtime);
        assert_eq!(runtime.node_boot_requests()[0].name, "node-a");
        assert_eq!(
            runtime.pending_search_choices[0],
            (coordinate, vec![choice])
        );
    }
}
