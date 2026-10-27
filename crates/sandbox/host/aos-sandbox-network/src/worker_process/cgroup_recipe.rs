//! Shares the two closed worker placements without turning paths into grants.
//!
//! The receiving constructor is paired with the actual same-F aggregate and
//! Native owner. The ordinary facade retains its historical control slice.
//! READY remains the existing V1 wire layout: its cgroup bytes identify which
//! exact expected placement the caller must validate, not an execution permit.

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkerCgroupPlacementV4 {
    Ordinary,
    Receiving,
}

#[derive(Clone, Copy)]
pub(crate) enum WorkerCgroupRoleV4 {
    Preparation,
    Observation,
}

impl WorkerCgroupPlacementV4 {
    pub(crate) const fn parent(self) -> &'static str {
        match self {
            Self::Ordinary => "aos.slice/aos-control.slice",
            Self::Receiving => "aoscomponents.slice/aoscomponents-network.slice",
        }
    }

    fn prefix(self, role: WorkerCgroupRoleV4) -> &'static str {
        match (self, role) {
            (Self::Ordinary, WorkerCgroupRoleV4::Preparation) => {
                "aos.slice/aos-control.slice/aos-sandbox-network-worker@"
            }
            (Self::Ordinary, WorkerCgroupRoleV4::Observation) => {
                "aos.slice/aos-control.slice/aos-sandbox-network-observation-worker@"
            }
            (Self::Receiving, WorkerCgroupRoleV4::Preparation) => {
                "aoscomponents.slice/aoscomponents-network.slice/aos-sandbox-network-worker@"
            }
            (Self::Receiving, WorkerCgroupRoleV4::Observation) => {
                "aoscomponents.slice/aoscomponents-network.slice/aos-sandbox-network-observation-worker@"
            }
        }
    }

    /// Checks only the fixed role/placement path grammar.
    ///
    /// # Errors
    /// Rejects a different slice, unit role, suffix or noncanonical instance.
    pub(crate) fn require_path(
        self,
        path: &str,
        role: WorkerCgroupRoleV4,
    ) -> Result<(), NetworkWorkerProcessError> {
        let instance = path
            .strip_prefix(self.prefix(role))
            .and_then(|value| value.strip_suffix(".service"))
            .ok_or(NetworkWorkerProcessError::PeerMismatch)?;
        validate_systemd_socket_instance_fields(instance)
            .map_err(|_| NetworkWorkerProcessError::PeerMismatch)
    }
}

// Only encoding already-constructed private READY data accepts either exact
// model. Every constructor/decoder and native consumer chooses one placement
// intrinsically; a selected decoder never falls through to the ordinary path.
pub(crate) fn require_constructed_ready_path(
    path: &str,
    role: WorkerCgroupRoleV4,
) -> Result<(), NetworkWorkerProcessError> {
    let placement = if path.starts_with(WorkerCgroupPlacementV4::Ordinary.prefix(role)) {
        WorkerCgroupPlacementV4::Ordinary
    } else {
        WorkerCgroupPlacementV4::Receiving
    };
    placement.require_path(path, role)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placements_and_roles_do_not_accept_each_others_unit() {
        for placement in [
            WorkerCgroupPlacementV4::Ordinary,
            WorkerCgroupPlacementV4::Receiving,
        ] {
            for role in [
                WorkerCgroupRoleV4::Preparation,
                WorkerCgroupRoleV4::Observation,
            ] {
                let valid = format!("{}0-984321-543_876-0.service", placement.prefix(role));
                assert!(placement.require_path(&valid, role).is_ok());
                let other = match placement {
                    WorkerCgroupPlacementV4::Ordinary => WorkerCgroupPlacementV4::Receiving,
                    WorkerCgroupPlacementV4::Receiving => WorkerCgroupPlacementV4::Ordinary,
                };
                assert!(other.require_path(&valid, role).is_err());
                let other_role = match role {
                    WorkerCgroupRoleV4::Preparation => WorkerCgroupRoleV4::Observation,
                    WorkerCgroupRoleV4::Observation => WorkerCgroupRoleV4::Preparation,
                };
                assert!(placement.require_path(&valid, other_role).is_err());
                assert!(
                    placement
                        .require_path(&format!("{valid}/child"), role)
                        .is_err()
                );
            }
        }
    }
}
