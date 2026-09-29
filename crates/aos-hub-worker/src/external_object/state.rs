//! Pure compact-turn transitions; durability and authentication belong to adapter.
//!
//! A repeated unknown begin never issues another permit, even for identical
//! input. No timeout, HEAD, SQL restore or revocation clears a pending turn.
//!
//! ```text
//! head = {version: 1, scope, configuration, floor, pending, receipts}
//! receipts = "<canonical nonnegative decimal>"
//! pending = null | {intent, dispatch_nonce}
//! ```

use anyhow::{ensure, Result};
use aos_hub_core::storage_authority::{
    control::StorageAuthorityObjectScope,
    lease::{EpochLeaseFloor, LeaseClock, LeaseInteger},
};
use serde::{Deserialize, Serialize};

use super::{
    config::Config,
    protocol::{digest, digest_string, GuardReply, Intent, Pending, Receipt},
};

pub(super) const MAX_RECEIPTS: i64 = 100_000;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Head {
    pub version: u8,
    pub scope: StorageAuthorityObjectScope,
    pub configuration: String,
    pub floor: EpochLeaseFloor,
    pub pending: Option<Pending>,
    pub receipts: LeaseInteger,
}

impl Head {
    pub(super) fn initialize(config: &Config, intent: &Intent, clock: LeaseClock) -> Result<Self> {
        let cohort = config.cohort(&intent.cohort_digest)?;
        ensure!(
            intent.scope == config.scope(cohort, intent.scope.full_key.clone())?,
            "configured scope mismatch"
        );
        let floor = EpochLeaseFloor::initialize_fresh_guard(
            cohort.authority.clone(),
            config.executor_identity.clone(),
            intent.scope.full_key.clone(),
            &config.timing_profile,
            clock,
        )?;
        Ok(Self {
            version: 1,
            scope: intent.scope.clone(),
            configuration: digest(config)?,
            floor,
            pending: None,
            receipts: LeaseInteger::new(0)?,
        })
    }

    pub(super) fn validate(
        &self,
        config: &Config,
        scope: &StorageAuthorityObjectScope,
    ) -> Result<()> {
        scope.guard_name()?;
        ensure!(
            config
                .cohorts
                .iter()
                .any(|cohort| cohort.authority == self.floor.authority),
            "floor creation facts differ from configured authority"
        );
        ensure!(
            self.version == 1
                && self.scope == *scope
                && self.configuration == digest(config)?
                && scope.guard_namespace_id == config.guard_namespace_id
                && self.floor.full_key == scope.full_key
                && self.floor.authority.authority_id == scope.physical_authority_id
                && self.floor.executor_identity == config.executor_identity
                && self.receipts.get() <= MAX_RECEIPTS,
            "retained object pins differ"
        );
        // The foundational floor's validator is private; new dispatch still
        // uses its full validation. Parsed terminal/replay state also rejects
        // incomplete/fork-shaped retained commitments rather than ignoring them.
        let floor = &self.floor;
        ensure!(
            floor.generation.get()
                <= aos_hub_core::storage_authority::control::MAX_AUTHORITY_GENERATION
                && ((floor.generation.get() == 0) == floor.admission_digest.is_none())
                && (floor.admission_digest.is_none() == floor.publication_digest.is_none())
                && ((floor.lease_sequence.get() == 0) == floor.payload_digest.is_none())
                && (floor.generation.get() > 0 || floor.lease_sequence.get() == 0)
                && (!floor.retired || floor.denied)
                && (!floor.denied || floor.generation.get() > 0),
            "corrupt retained floor shape"
        );
        for commitment in [
            &floor.admission_digest,
            &floor.publication_digest,
            &floor.payload_digest,
        ]
        .into_iter()
        .flatten()
        {
            ensure!(
                digest_string(commitment),
                "corrupt retained floor commitment"
            );
        }
        if let Some(turn) = &self.pending {
            turn.intent.validate()?;
            ensure!(
                turn.intent.scope == self.scope && digest_string(&turn.dispatch_nonce),
                "corrupt pending turn"
            );
        }
        Ok(())
    }

    /// Returns replay before lease checks and clears only its matching turn.
    pub(super) fn replay(&self, intent: &Intent, receipt: &Receipt) -> Result<(Self, GuardReply)> {
        receipt.validate()?;
        ensure!(
            receipt.turn.intent == *intent,
            "retained operation context changed"
        );
        let mut next = self.clone();
        if next.pending.as_ref() == Some(&receipt.turn) {
            next.pending = None;
        }
        Ok((
            next,
            GuardReply::Terminal {
                receipt: receipt.clone(),
            },
        ))
    }

    pub(super) fn begin(
        &self,
        config: &Config,
        intent: Intent,
        lease: &[u8],
        nonce: String,
        clock: LeaseClock,
    ) -> Result<(Self, GuardReply)> {
        self.validate(config, &intent.scope)?;
        intent.validate()?;
        ensure!(
            self.pending.is_none(),
            "unknown object turn blocks dispatch"
        );
        ensure!(
            self.receipts.get() < MAX_RECEIPTS && digest_string(&nonce),
            "object receipt capacity exhausted or invalid nonce"
        );
        let cohort = config.cohort(&intent.cohort_digest)?;
        ensure!(
            cohort.authority == self.floor.authority,
            "authority creation facts changed"
        );
        let validated = config.verifier()?.validate_lease(
            lease,
            cohort,
            &config.timing_profile,
            &self.floor,
            &self.scope.full_key,
            intent.effect.lease_effect(),
            clock,
        )?;
        let mut next = self.clone();
        next.floor = validated.next_floor;
        let turn = Pending {
            intent,
            dispatch_nonce: nonce,
        };
        next.pending = Some(turn.clone());
        Ok((
            next.clone(),
            GuardReply::Dispatch {
                turn,
                floor: next.floor,
            },
        ))
    }

    pub(super) fn terminal(&self, receipt: &Receipt) -> Result<Self> {
        receipt.validate()?;
        ensure!(
            self.pending.as_ref() == Some(&receipt.turn),
            "terminal does not match pending turn"
        );
        let mut next = self.clone();
        next.receipts = LeaseInteger::new(
            self.receipts
                .get()
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("receipt count exhausted"))?,
        )?;
        ensure!(
            next.receipts.get() <= MAX_RECEIPTS,
            "object receipt capacity exhausted"
        );
        next.pending = None;
        Ok(next)
    }
}
