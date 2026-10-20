//! Retains fresh readonly role ownership beside the complete global census.
//!
//! Four fixed probes reuse the exact Stop preparation's current root, PIDFD,
//! membership and population engine. They create no Stop job, old Launch owner,
//! namespace adoption or effect permission. Enclosing Host Source posts retain
//! the whole probe graph and its first cause before any positive disposition.

use super::*;
use aos_sandbox_linux::cgroup::{
    HostRuntimeCgroupAbsenceOriginalV5, HostRuntimeCgroupAbsenceRefusalV5,
};
use aos_systemd::{ExactUnitRole, HostRuntimeDiscoveryOriginalV5, PostUnrefUnitObservation};

const ROLES: [ExactUnitRole; 2] = [ExactUnitRole::Payload, ExactUnitRole::Guardian];

#[derive(Clone, Copy)]
enum First {
    Scope,
    Role(usize, usize),
    CleanupRole(usize, usize),
    Closed,
}

pub(crate) struct HostOwnedRuntimeProofOriginalV8 {
    probes: [[systemd::StopQuiescenceOriginalV3; 2]; 2],
    results: [[Option<Result<()>>; 2]; 2],
    incarnation: Option<[u8; 16]>,
    next: usize,
    first: Option<First>,
    cleanup_posts: [[Option<Result<()>>; 2]; 2],
}

impl HostOwnedRuntimeProofOriginalV8 {
    pub(crate) fn new() -> Self {
        Self {
            probes: std::array::from_fn(|_| {
                std::array::from_fn(|_| systemd::StopQuiescenceOriginalV3::new())
            }),
            results: std::array::from_fn(|_| std::array::from_fn(|_| None)),
            incarnation: None,
            next: 0,
            first: None,
            cleanup_posts: std::array::from_fn(|_| std::array::from_fn(|_| None)),
        }
    }

    pub(crate) fn receiving_demand_v8() -> Option<aos_sandbox_core::ResourceVector> {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
        let mut complete = ResourceVector::ZERO.with(
            D::MemoryBytes,
            u64::try_from(2 * std::mem::size_of::<Self>()).ok()?,
        );
        let each = systemd::StopQuiescenceOriginalV3::receiving_demand_v3()?;
        for _ in 0..4 {
            complete = complete.checked_add(each).ok()?;
        }
        Some(complete)
    }

    pub(crate) fn cleanup_posts_demand_v1() -> Option<aos_sandbox_core::ResourceVector> {
        let each = systemd::StopQuiescenceOriginalV3::cleanup_post_receiving_demand_v1()?;
        let mut complete = aos_sandbox_core::ResourceVector::ZERO;
        for _ in 0..4 {
            complete = complete.checked_add(each).ok()?;
        }
        Some(complete)
    }

    pub(crate) fn cleanup_posts_completed_v1(&self) -> bool {
        self.completed_v8()
            && self
                .cleanup_posts
                .iter()
                .flatten()
                .all(|result| matches!(result, Some(Ok(()))))
    }

    pub(crate) fn completed_v8(&self) -> bool {
        self.first.is_none()
            && self.next == 2
            && self.incarnation.is_some()
            && self
                .results
                .iter()
                .flatten()
                .all(|result| matches!(result, Some(Ok(()))))
    }

    pub(crate) fn failure_v8(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::Role(round, role) | First::CleanupRole(round, role) => self.probes[round][role]
                .failure()
                .or_else(|| {
                    self.results[round][role]
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                })
                .or_else(|| {
                    self.cleanup_posts[round][role]
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                }),
            First::Scope | First::Closed => Some(&REFUSED),
        }
    }
}

impl RetainedPayloadWorkerV1<'_> {
    pub(crate) fn finish_inventory_owned_roles_after_cleanup_v1(
        &self,
        original: &mut HostOwnedRuntimeProofOriginalV8,
    ) -> Result<()> {
        if original.cleanup_posts.iter().flatten().any(Option::is_some) {
            return Err(HostError::Fence(
                "cleanup cannot replace or repeat its initial native ownership",
            ));
        }
        for round in 0..2 {
            for role in 0..2 {
                // An actually absent role has no synthetic PIDFD. Every role
                // that was present retains its SAME original PIDFD/monitor and
                // independently observes death/population after the effects.
                original.cleanup_posts[round][role] = Some(
                    if original.probes[round][role].has_cleanup_native_owner_v1() {
                        original.probes[round][role]
                            .confirm_owned_cleanup_absence_once_v1(&self.worker.cgroup_root)
                    } else {
                        Ok(())
                    },
                );
                if !matches!(original.cleanup_posts[round][role], Some(Ok(()))) {
                    original
                        .first
                        .get_or_insert(First::CleanupRole(round, role));
                }
            }
        }
        if original.cleanup_posts_completed_v1() {
            Ok(())
        } else {
            Err(HostError::Fence(
                "cleanup initial native owners remain live or ambiguous",
            ))
        }
    }

    pub(crate) fn capture_inventory_owned_roles_v8(
        &self,
        original: &mut HostOwnedRuntimeProofOriginalV8,
        discovery: &HostRuntimeDiscoveryOriginalV5,
        incarnation: [u8; 16],
    ) -> Result<()> {
        if original.next == 2 {
            original.first.get_or_insert(First::Closed);
            return Err(HostError::Fence("Host owned role census cannot reenter"));
        }
        let round = original.next;
        original.next += 1;
        if incarnation == [0; 16] || original.incarnation.is_some_and(|old| old != incarnation) {
            original.first.get_or_insert(First::Scope);
        }
        original.incarnation.get_or_insert(incarnation);
        for (index, role) in ROLES.into_iter().enumerate() {
            original.results[round][index] =
                Some(match discovery.owned_unit_observation_v8(round, role) {
                    Some(PostUnrefUnitObservation::Absent) => Ok(()),
                    Some(PostUnrefUnitObservation::Present(observation))
                        if observation.role == role =>
                    {
                        original.probes[round][index]
                            .capture_owned_inventory_once_v8(&self.worker.cgroup_root, observation)
                    }
                    _ => Err(HostError::Fence(
                        "Host owned role lacks its exact manager observation",
                    )),
                });
            if !matches!(original.results[round][index], Some(Ok(()))) {
                original.first.get_or_insert(First::Role(round, index));
            }
        }
        if original.first.is_some() {
            Err(HostError::Fence(
                "Host owned role census failed; native prefixes retained",
            ))
        } else {
            Ok(())
        }
    }

    pub(crate) fn capture_inventory_owned_cgroup_v8(
        &self,
        original: &HostOwnedRuntimeProofOriginalV8,
        kernel: &mut HostRuntimeCgroupAbsenceOriginalV5,
    ) -> std::result::Result<(), HostRuntimeCgroupAbsenceRefusalV5> {
        let round = original
            .next
            .checked_sub(1)
            .filter(|round| *round < 2)
            .ok_or(HostRuntimeCgroupAbsenceRefusalV5)?;
        // This independently owed global round still runs after a failed role
        // probe. Missing proof means no selected-child exception, never adoption.
        kernel.capture_next_owned_cleanup_once_v8(
            &self.worker.cgroup_root,
            original
                .incarnation
                .ok_or(HostRuntimeCgroupAbsenceRefusalV5)?,
            original.probes[round][0].owned_inventory_anchor_v8(),
            original.probes[round][1].owned_inventory_anchor_v8(),
        )
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Host owned role census is incomplete or changed")]
struct OwnedRuntimeProofRefusalV8;

static REFUSED: OwnedRuntimeProofRefusalV8 = OwnedRuntimeProofRefusalV8;
