//! Exact ownership-chain transitions shared by admission and historical replay.
//!
//! Renewal preserves the entire signed claim's semantic tuple. Advancement
//! changes only desired assignment semantics on the same exclusive owner;
//! it is not a lease-expiry retirement or migration mechanism. Comparing the
//! receipt-authenticated desired generation prevents two distinct meanings
//! from being accepted at one epoch/generation.

use super::{OwnershipClaimAction, OwnershipClaimV1, RecoveredOwnershipLease};

pub(super) fn is_valid_successor(
    claim: &OwnershipClaimV1,
    prior: &RecoveredOwnershipLease,
) -> bool {
    if claim.node() != prior.node()
        || claim.expected_prior() != Some(prior.expected_renewal_fence())
    {
        return false;
    }

    match claim.action() {
        OwnershipClaimAction::Acquire => false,
        OwnershipClaimAction::Renew => {
            claim.assignment() == prior.assignment()
                && claim.desired_generation() == prior.desired_generation()
        }
        OwnershipClaimAction::Advance => {
            let proposed = claim.assignment();
            let previous = prior.assignment();
            proposed.sandbox() == previous.sandbox()
                && proposed.incarnation() == previous.incarnation()
                && proposed.epoch() == previous.epoch()
                && proposed.digest() != previous.digest()
                && claim.desired_generation() > prior.desired_generation()
        }
    }
}
