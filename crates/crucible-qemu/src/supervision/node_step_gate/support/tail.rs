//! Launch identity helpers and the single-node send authorizer.

use super::*;

pub(in crate::supervision::node_step_gate) fn launch_artifact(
    kind: &str,
    path: &Path,
) -> QemuLaunchArtifact {
    let path = path_text(path);
    QemuLaunchArtifact::new(
        crucible::ContentHash::from_canonical_material(GATE_DOMAIN, &format!("{kind}={path}")),
        path,
    )
}

pub(in crate::supervision::node_step_gate) fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

pub(in crate::supervision::node_step_gate) fn node_id(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

/// Send authorizer for the single-node run.
///
/// The gate has one VM and one router slot and never routes a real cross-node
/// frame, so authorization is unconditional.
pub(in crate::supervision::node_step_gate) struct GateSendAuthorizer;

impl SchedulerSendAuthorizer for GateSendAuthorizer {
    fn authorize_cross_node_send(
        &self,
        producer: &SchedulerNodeId,
        consumer: &SchedulerNodeId,
    ) -> Result<SchedulerSendAuthorization, SchedulerError> {
        Ok(SchedulerSendAuthorization {
            producer: producer.clone(),
            consumer: consumer.clone(),
            topology_epoch: 0,
        })
    }
}
