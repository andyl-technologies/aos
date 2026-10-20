//! Captures one fixed two-role pair on the existing readonly census connection.
//!
//! These observations establish neither absence nor effect permission. The
//! enclosing Host must compare its authenticated historical target and retain
//! fresh cgroup/PIDFD membership originals through all independently owed posts.

use super::*;
use crate::sandbox::{ExactUnitRole, PostUnrefUnitObservation, SandboxUnitName};

const ROLES: [ExactUnitRole; 2] = [ExactUnitRole::Payload, ExactUnitRole::Guardian];

pub(super) struct OwnedCleanupOriginalV8 {
    incarnation: [u8; 16],
    client: Option<SystemdClient>,
    observations: [[Option<Result<PostUnrefUnitObservation>>; 2]; 2],
    timeouts: [[Option<tokio::time::error::Elapsed>; 2]; 2],
    pair: Option<Result<()>>,
}

impl OwnedCleanupOriginalV8 {
    pub(super) fn new(incarnation: [u8; 16]) -> Self {
        Self {
            incarnation,
            client: None,
            observations: std::array::from_fn(|_| std::array::from_fn(|_| None)),
            timeouts: std::array::from_fn(|_| std::array::from_fn(|_| None)),
            pair: None,
        }
    }

    pub(super) fn receiving_memory_v8(materialized: usize) -> Option<usize> {
        // The common fixed-property supplier already covers concrete Vec
        // growth, both Environment arrays and decoded string bodies. The
        // returned observation retains a path plus copies of active/substate;
        // two full materialized extents dominate those copies across all four
        // calls. Their inline carriers are in RuntimeDiscoveryOriginalV5.
        super::super::readonly_manager::readonly_client_storage_v2()?
            .checked_add(materialized.checked_mul(2)?)
    }

    pub(super) fn construct_client_once_v8(
        &mut self,
        connection: zbus::Connection,
        manager: ManagerProxy<'static>,
    ) {
        self.client = Some(SystemdClient::readonly_from_manager_v8(connection, manager));
    }

    pub(super) fn observation_v8(
        &self,
        round: usize,
        role: ExactUnitRole,
    ) -> Option<&PostUnrefUnitObservation> {
        let role = match role {
            ExactUnitRole::Payload => 0,
            ExactUnitRole::Guardian => 1,
        };
        self.observations
            .get(round)?
            .get(role)?
            .as_ref()?
            .as_ref()
            .ok()
    }

    pub(super) fn unit_error_v8(&self, round: usize, role: usize) -> Option<&Error> {
        self.observations
            .get(round)?
            .get(role)?
            .as_ref()?
            .as_ref()
            .err()
    }

    pub(super) fn unit_failure_v8(
        &self,
        round: usize,
        role: usize,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        self.timeouts
            .get(round)?
            .get(role)?
            .as_ref()
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.unit_error_v8(round, role).map(|cause| cause as _))
    }

    pub(super) fn require_listing_v8(&self, round: usize, rows: &[ListUnitsEntry]) -> Result<()> {
        let name = SandboxUnitName::from_incarnation(self.incarnation);
        let mut present = 0;
        for (role_index, role) in ROLES.into_iter().enumerate() {
            let observation = self.observation_v8(round, role).ok_or_else(refused)?;
            let expected = match role {
                ExactUnitRole::Payload => name.as_str(),
                ExactUnitRole::Guardian => name.guardian(),
            };
            let mut matching = rows.iter().filter(|row| row.name == expected);
            match observation {
                PostUnrefUnitObservation::Absent => {
                    if matching.next().is_some() {
                        return Err(refused());
                    }
                }
                PostUnrefUnitObservation::Present(observation) => {
                    let row = matching.next().ok_or_else(refused)?;
                    if matching.next().is_some()
                        || row.object_path != observation.object_path
                        || row.load_state != "loaded"
                        || row.active_state != observation.active_state
                        || row.sub_state != observation.sub_state
                        || !row.followed.is_empty()
                        || row.job_id != 0
                        || !row.job_type.is_empty()
                        || row.job_object_path.as_str() != "/"
                        || rows
                            .iter()
                            .filter(|other| other.object_path == row.object_path)
                            .count()
                            != 1
                    {
                        return Err(refused());
                    }
                    present += 1;
                }
            }
            if self.timeouts[round][role_index].is_some() {
                return Err(refused());
            }
        }
        if present != rows.len() {
            return Err(refused());
        }
        Ok(())
    }

    pub(super) fn compare_pair_once_v8(&mut self) {
        self.pair = Some((|| {
            for role in ROLES {
                let before = self.observation_v8(0, role).ok_or_else(refused)?;
                let after = self.observation_v8(1, role).ok_or_else(refused)?;
                if before != after {
                    return Err(refused());
                }
            }
            Ok(())
        })());
    }

    pub(super) fn completed_pair_v8(&self) -> bool {
        matches!(self.pair, Some(Ok(())))
    }

    pub(super) fn pair_failure_v8(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.pair.as_ref()?.as_ref().err().map(|cause| cause as _)
    }

    pub(super) fn drop_positive_client_v8(&mut self) {
        // Only the enclosing positive body close calls this. Failed clients
        // retain their native connection graph.
        self.client = None;
    }
}

impl RuntimeDiscoveryOriginalV5 {
    pub(super) async fn observe_owned_round_v8(
        &mut self,
        round: usize,
        deadline: tokio::time::Instant,
    ) {
        for (role_index, role) in ROLES.into_iter().enumerate() {
            let mut cancellation = self
                .native
                .as_ref()
                .map(|native| native.cancellation_fence_v5());
            let positive = {
                let Some(owned) = self.owned.as_mut() else {
                    return;
                };
                let name = SandboxUnitName::from_incarnation(owned.incarnation);
                if let Some(client) = owned.client.as_ref() {
                    match tokio::time::timeout_at(
                        deadline,
                        client.observe_unreferenced_exact_unit_v8(&name, role),
                    )
                    .await
                    {
                        Ok(result) => owned.observations[round][role_index] = Some(result),
                        Err(cause) => owned.timeouts[round][role_index] = Some(cause),
                    }
                }
                matches!(owned.observations[round][role_index], Some(Ok(_)))
            };
            if positive {
                if let Some(cancellation) = cancellation.as_mut() {
                    cancellation.complete();
                }
            } else {
                let _ = self.refuse(First::OwnedUnit(round, role_index));
            }
        }
    }
}

pub(super) fn zbus_cause_v8(cause: &Error) -> Option<&zbus::Error> {
    match cause {
        Error::Zbus(cause) | Error::SystemdUnavailable(cause) => Some(cause),
        _ => None,
    }
}

fn refused() -> Error {
    Error::HostLaunchRetained("Host owned census has unknown, changed or incomplete unit identity")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::{ExactUnitObservation, ExactUnitState};

    fn present() -> (OwnedCleanupOriginalV8, ListUnitsEntry) {
        let name = SandboxUnitName::from_incarnation([1; 16]);
        let observation = ExactUnitObservation {
            role: ExactUnitRole::Payload,
            object_path: "/org/freedesktop/systemd1/unit/payload".try_into().unwrap(),
            binding: Some([2; 32]),
            invocation_id: Some([3; 16]),
            active_state: "active".to_owned(),
            sub_state: "running".to_owned(),
            state: ExactUnitState::ActiveRunning,
            cgroup: Some(name.cgroup_path()),
            main_pid: std::num::NonZeroU32::new(4),
        };
        let row = ListUnitsEntry {
            name: name.as_str().to_owned(),
            description: String::new(),
            load_state: "loaded".to_owned(),
            active_state: "active".to_owned(),
            sub_state: "running".to_owned(),
            followed: String::new(),
            object_path: observation.object_path.clone(),
            job_id: 0,
            job_type: String::new(),
            job_object_path: "/".try_into().unwrap(),
        };
        let mut original = OwnedCleanupOriginalV8::new([1; 16]);
        for round in 0..2 {
            original.observations[round][0] =
                Some(Ok(PostUnrefUnitObservation::Present(observation.clone())));
            original.observations[round][1] = Some(Ok(PostUnrefUnitObservation::Absent));
        }
        (original, row)
    }

    #[test]
    fn complete_listing_rejects_unknown_duplicate_alias_job_and_substituted_path() {
        let (original, row) = present();
        assert!(original.require_listing_v8(0, &[row.clone()]).is_ok());
        assert!(original.require_listing_v8(0, &[]).is_err());
        assert!(
            original
                .require_listing_v8(0, &[row.clone(), row.clone()])
                .is_err()
        );
        for change in 0..5 {
            let mut changed = row.clone();
            match change {
                0 => {
                    changed.name = SandboxUnitName::from_incarnation([9; 16])
                        .as_str()
                        .to_owned()
                }
                1 => changed.followed = row.name.clone(),
                2 => changed.job_id = 10,
                3 => changed.object_path = "/different".try_into().unwrap(),
                _ => changed.active_state = "inactive".to_owned(),
            }
            assert!(
                original.require_listing_v8(0, &[changed]).is_err(),
                "change {change}"
            );
        }
    }

    #[test]
    fn changed_manager_target_never_completes_the_two_round_pair() {
        let (mut original, _) = present();
        original.compare_pair_once_v8();
        assert!(original.completed_pair_v8());
        let Some(Ok(PostUnrefUnitObservation::Present(observation))) =
            original.observations[1][0].as_mut()
        else {
            panic!("missing fixture observation");
        };
        observation.invocation_id = Some([10; 16]);

        original.compare_pair_once_v8();

        assert!(!original.completed_pair_v8());
        assert!(original.pair_failure_v8().is_some());
    }
}
