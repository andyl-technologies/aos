//! Publishes a standing Source's live roster from the real supervisor owner.
//!
//! Publication occurs under the same state and outer locks as decisions. It
//! enters no operation and does not renew an original clock. The containing
//! Main's nominal Source payer authenticates enrollment; public observations
//! alone cannot attach a publisher. Publishers must not call back into their
//! supervisor while handling a snapshot.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::host_services::process_birth::AuthenticatedSourceHostPurpose;

/// Describes one coherent live roster and its unchanged outer clock.
#[derive(Clone, Copy, Debug)]
pub struct SourceSupervisionSnapshot {
    /// Current fixed class policy, captured with its actual revision.
    pub budgets: HostOperationBudgets,
    /// Revision of this Source's actual node policy owner.
    pub roster_revision: u64,
    /// Same original-start cap and its current sticky disposition.
    pub outer: HostOuterCapBinding,
}

/// Publishes live observations through an already prepaid Source transport.
///
/// Implementations own their physical publication and cancellation descriptors.
/// They must retain immutable subject, cap and origin, reject stale revisions,
/// and invalidate publication if an update cannot be represented. This is a
/// same-process interface; it is never placed in a public shared-memory region.
pub trait SourceSupervisionPublisher: std::fmt::Debug + Send + Sync {
    /// Publishes one coherent owner snapshot without entering an operation.
    ///
    /// # Errors
    /// Refuses changed immutable identity, invalid geometry or uncertain
    /// physical publication. A failed publisher must leave readers unable to
    /// accept its previous observation as the current live owner state.
    fn publish(&self, snapshot: SourceSupervisionSnapshot) -> Result<(), HostSupervisionError>;

    /// Invalidates the existing physical publication after uncertain ownership.
    ///
    /// This keeps prior observations from acting as current authority. The same
    /// retained transport and charge remain owned; no new event or clock is made.
    fn invalidate(&self);
}

impl HostOperationSupervisor {
    /// Enrolls a prepaid Source publication in its actual node supervisor.
    ///
    /// The same authenticated Main Source purpose is checked before publication.
    /// The supervisor keeps only a weak borrow, so this does not create a cycle
    /// or prolong Source after its real physical control owners have closed.
    ///
    /// # Errors
    /// Refuses another Main, a root rather than node roster, a second live
    /// Source publisher, expired authority or poisoned synchronization.
    pub fn retain_source_publication(
        &self,
        purpose: &AuthenticatedSourceHostPurpose,
        publisher: &Arc<dyn SourceSupervisionPublisher>,
    ) -> Result<(), HostSupervisionError> {
        purpose
            .verify_supervisor(self)
            .map_err(|_| HostSupervisionError::Unavailable)?;
        if self.shared.budget_owner == 0 {
            return Err(HostSupervisionError::InvalidBudget);
        }
        let mut held = self.shared.source_publisher.lock().map_err(|poisoned| {
            drop(poisoned);
            invalidate_sources(&self.shared);
            HostSupervisionError::Unavailable
        })?;
        if held.as_ref().and_then(Weak::upgrade).is_some() {
            return Err(HostSupervisionError::CapacityExhausted);
        }
        // Publication is retained before its initial observation. An uncertain
        // failure keeps the same nominal publisher in its caller's paid keeper.
        *held = Some(Arc::downgrade(publisher));
        drop(held);
        publish_owner(&self.shared)
    }
}

pub(super) fn publish_owner(shared: &Arc<Shared>) -> Result<(), HostSupervisionError> {
    super::action_loan::publish_owner(shared)?;
    let publisher = shared
        .source_publisher
        .lock()
        .map_err(|poisoned| {
            let held = poisoned.into_inner();
            let publisher = held.as_ref().and_then(Weak::upgrade);
            drop(held);
            if let Some(publisher) = publisher {
                publisher.invalidate();
            }
            HostSupervisionError::Unavailable
        })?
        .as_ref()
        .and_then(Weak::upgrade);
    let Some(publisher) = publisher else {
        return Ok(());
    };
    let mut state = shared.state.lock().map_err(|_| {
        publisher.invalidate();
        HostSupervisionError::Unavailable
    })?;
    let mut outer = shared.outer.lock().map_err(|_| {
        publisher.invalidate();
        HostSupervisionError::Unavailable
    })?;
    let supervisor = HostOperationSupervisor {
        shared: Arc::clone(shared),
    };
    #[cfg(feature = "private-measurement-domain")]
    if let Err(error) = supervisor.require_measurement_interval(&mut state, &mut outer) {
        publisher.invalidate();
        return Err(error);
    }
    state.cap_revision = outer.revision;
    state.cap_allowance = outer.allowance;
    state.cap_state = outer.state;
    refresh_cap(&mut state, supervisor.elapsed());
    outer.state = state.cap_state;
    publisher.publish(SourceSupervisionSnapshot {
        budgets: state.budgets,
        roster_revision: state.policy_revision,
        outer: HostOuterCapBinding {
            cap_id: shared.cap_id,
            original_monotonic_ns: shared.original_monotonic_ns,
            revision: outer.revision,
            allowance: outer.allowance,
            state: outer.state,
        },
    })
}

/// Invalidates actual retained Source publishers after uncertain shared ownership.
///
/// The fixed finite roster is observed without issuing or refunding anything.
/// Each upgraded owner is dropped outside the outer lock, so final physical
/// custody destruction cannot recursively acquire a still-held cap lock.
pub(super) fn invalidate_sources(shared: &Arc<Shared>) {
    let final_owner = {
        let outer = shared
            .outer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        outer.rosters.last_key_value().map(|(&id, _)| id)
    };
    let Some(final_owner) = final_owner else {
        return;
    };
    let mut cursor = None;
    loop {
        let next = {
            let outer = shared
                .outer
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let bounds = (
                cursor.map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded),
                std::ops::Bound::Included(final_owner),
            );
            outer
                .rosters
                .range(bounds)
                .next()
                .map(|(&id, (_, owner))| (id, owner.as_ref().and_then(Weak::upgrade)))
        };
        let Some((id, owner)) = next else {
            break;
        };
        cursor = Some(id);
        if let Some(owner) = owner {
            let held = owner
                .source_publisher
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let publisher = held.as_ref().and_then(Weak::upgrade);
            drop(held);
            if let Some(publisher) = publisher {
                publisher.invalidate();
            }
        }
    }
}
