//! Causal publication ordering for restored terminal generations.

use super::*;

pub(in crate::vm_lifecycle::quantum_loop) trait RestoredGenerationRelease {
    fn require_runnable_publication(&mut self, node: &NodeId) -> Result<(), SchedulerError>;

    fn resume_restored_generation(&mut self, node: &NodeId) -> Result<(), SchedulerError>;
}

impl RestoredGenerationRelease for ProductionVmLifecycleLoop {
    fn require_runnable_publication(&mut self, node: &NodeId) -> Result<(), SchedulerError> {
        self.inner
            .loop_impl()
            .require_vm_node_activity(node, SchedulerNodeActivity::Runnable)
    }

    fn resume_restored_generation(&mut self, node: &NodeId) -> Result<(), SchedulerError> {
        self.inner.backend_mut().resume_restored_generation(node)?;
        Ok(())
    }
}

/// Releases a restored QEMU generation only after scheduler publication.
pub(in crate::vm_lifecycle::quantum_loop) fn release_restored_generation_after_scheduler_publication(
    release: &mut impl RestoredGenerationRelease,
    node: &NodeId,
    service_state: ProductionNodeServiceState,
) -> Result<(), SchedulerError> {
    if service_state == ProductionNodeServiceState::Running {
        release.require_runnable_publication(node)?;
        release.resume_restored_generation(node)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Eq, PartialEq)]
    enum Call {
        Require,
        Resume,
    }

    struct RecordingRelease {
        calls: Vec<Call>,
        reject_publication: bool,
    }

    impl RestoredGenerationRelease for RecordingRelease {
        fn require_runnable_publication(&mut self, _node: &NodeId) -> Result<(), SchedulerError> {
            self.calls.push(Call::Require);
            if self.reject_publication {
                Err(SchedulerError::BoundaryViolation {
                    message: String::from("scheduler publication is absent"),
                })
            } else {
                Ok(())
            }
        }

        fn resume_restored_generation(&mut self, _node: &NodeId) -> Result<(), SchedulerError> {
            self.calls.push(Call::Resume);
            Ok(())
        }
    }

    #[test]
    fn restored_generation_release_is_causally_gated_by_scheduler_publication() {
        let node = NodeId {
            name: String::from("node-a"),
        };
        let mut accepted = RecordingRelease {
            calls: Vec::new(),
            reject_publication: false,
        };
        release_restored_generation_after_scheduler_publication(
            &mut accepted,
            &node,
            ProductionNodeServiceState::Running,
        )
        .unwrap_or_else(|error| panic!("published generation should resume: {error}"));
        assert_eq!(accepted.calls, [Call::Require, Call::Resume]);

        for service_state in [
            ProductionNodeServiceState::PoweredOff,
            ProductionNodeServiceState::PermanentlyFailed,
        ] {
            let mut retained = RecordingRelease {
                calls: Vec::new(),
                reject_publication: false,
            };
            release_restored_generation_after_scheduler_publication(
                &mut retained,
                &node,
                service_state,
            )
            .unwrap_or_else(|error| panic!("non-running generation should stay retained: {error}"));
            assert!(retained.calls.is_empty());
        }

        let mut rejected = RecordingRelease {
            calls: Vec::new(),
            reject_publication: true,
        };
        assert!(
            release_restored_generation_after_scheduler_publication(
                &mut rejected,
                &node,
                ProductionNodeServiceState::Running,
            )
            .is_err()
        );
        assert_eq!(rejected.calls, [Call::Require]);
    }
}
