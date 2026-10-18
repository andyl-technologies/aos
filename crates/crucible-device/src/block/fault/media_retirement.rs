//! Retirement of media and flash continuations that can never be named again.
//!
//! A media or flash contributor is the identity of one resolved binding
//! action. Re-upserting a binding mints a new contributor, and a replaced or
//! removed action never returns, so its continuation is consulted again only
//! through a directive that already carries it. The host knows which actions
//! are live; this module knows which directives are still in flight. A
//! continuation whose contributor is in neither set is retired:
//!
//! ```text
//! retire(c)  <=>  c not in live  AND  c not named by any retained directive
//! ```
//!
//! Retired media counters are dropped. Retired flash continuations fold their
//! changed cells into the device-level residual, so reads stay bit-identical.

use std::collections::BTreeSet;

use super::*;

impl BlockFaultState {
    /// Retires every continuation that is neither live nor still referenced.
    ///
    /// Returns the number of retired continuations.
    pub(in crate::block::fault) fn retire_inactive_media_contributors_untracked(
        &mut self,
        live: &BTreeSet<[u8; 32]>,
    ) -> usize {
        let media_candidates = self
            .media
            .rules()
            .keys()
            .filter(|contributor| !live.contains(*contributor))
            .copied()
            .collect::<Vec<_>>();
        let flash_candidates = self
            .flash
            .continuations()
            .keys()
            .filter(|contributor| !live.contains(*contributor))
            .copied()
            .collect::<Vec<_>>();
        if media_candidates.is_empty() && flash_candidates.is_empty() {
            return 0;
        }

        let referenced = self.referenced_media_contributors();
        let mut retired = 0;
        for contributor in media_candidates {
            if !referenced.contains(&contributor) && self.media.retire(&contributor) {
                retired += 1;
            }
        }
        for contributor in flash_candidates {
            if !referenced.contains(&contributor) && self.flash.retire_continuation(&contributor) {
                retired += 1;
            }
        }
        self.observation_changed |= retired > 0;
        retired
    }

    /// Collects every media and flash contributor a retained directive names.
    ///
    /// These are the only carriers through which a non-live contributor can
    /// reach the media stage, a flash read, or a deferred program or erase.
    pub(in crate::block::fault) fn referenced_media_contributors(&self) -> BTreeSet<[u8; 32]> {
        let execution = self.execution_pending.values().flat_map(|pending| {
            std::iter::once(&pending.opportunity.admission).chain(pending.execution.iter())
        });
        let persistence = self
            .request_persistence_pending
            .values()
            .flat_map(|pending| {
                std::iter::once(&pending.opportunity.resolved).chain(pending.persistence.iter())
            });
        let delivery = self.delivery_pending.values().flat_map(|pending| {
            std::iter::once(&pending.opportunity.resolved).chain(pending.delivery.iter())
        });
        let directives = self
            .pending
            .values()
            .chain(
                self.service_pending
                    .values()
                    .map(|pending| &pending.directive),
            )
            .chain(execution)
            .chain(persistence)
            .chain(delivery);

        let mut referenced = BTreeSet::new();
        for directive in directives {
            referenced.extend(directive.media_rules.iter().map(|rule| rule.contributor));
            referenced.extend(
                directive
                    .persistence_media_rules
                    .iter()
                    .map(|rule| rule.contributor),
            );
        }
        for directive in self.pending_persistence_media.values() {
            referenced.extend(directive.flash_rules.iter().map(|rule| rule.contributor));
        }
        referenced
    }
}
