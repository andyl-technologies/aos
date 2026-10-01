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
    #[serde(default)]
    pub observation: Option<super::observation::Pending>,
    #[serde(default)]
    pub visible_receipt: Option<VisibleReceipt>,
    pub receipts: LeaseInteger,
    #[serde(default)]
    pub incarnation: aos_hub_core::direct_upload::WireInteger,
    #[serde(default)]
    // Heap ownership bounds the compact head layout; serde keeps the existing JSON.
    pub stage: Option<Box<super::stage::state::Session>>,
}

/// One current positive publication pointer; receipts remain immutable KV records.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct VisibleReceipt {
    pub kind: VisibleKind,
    pub operation_id: String,
    pub receipt_digest: String,
    pub context_digest: String,
    pub incarnation: aos_hub_core::direct_upload::WireInteger,
    pub stage_configuration: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum VisibleKind {
    MetadataPut,
    DestinationClose,
}

impl VisibleReceipt {
    pub(super) fn validate(&self, head: &Head) -> Result<()> {
        ensure!(
            super::protocol::id(&self.operation_id)
                && digest_string(&self.receipt_digest)
                && digest_string(&self.context_digest)
                && self.incarnation == head.incarnation
                && self.incarnation.get() > 0
                && match self.kind {
                    VisibleKind::MetadataPut => self.stage_configuration.is_none(),
                    VisibleKind::DestinationClose => self
                        .stage_configuration
                        .as_ref()
                        .is_some_and(|value| digest_string(value)),
                },
            "current visible receipt pointer differs"
        );
        Ok(())
    }
}

impl Head {
    /// Checks uncertainty without treating time or provider absence as settlement.
    ///
    /// # Errors
    /// Returns an error for any pending observation, mutation or active stage.
    pub(super) fn require_cleanup_ready(&self) -> Result<()> {
        ensure!(
            self.pending.is_none()
                && self.observation.is_none()
                && self
                    .stage
                    .as_ref()
                    .is_none_or(|stage| stage.cleanup_ready()),
            "frozen physical effect remains unknown or active"
        );
        Ok(())
    }

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
            observation: None,
            visible_receipt: None,
            receipts: LeaseInteger::new(0)?,
            incarnation: aos_hub_core::direct_upload::WireInteger::new(0),
            stage: None,
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
        ensure!(
            self.incarnation.get() <= super::stage::state::MAX_INCARNATION,
            "corrupt retained incarnation counter"
        );
        if let Some(visible) = &self.visible_receipt {
            visible.validate(self)?;
        }
        if let Some(stage) = &self.stage {
            stage.validate_shape(self)?;
        }
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
        if let Some(slot) = &self.observation {
            slot.validate()?;
            ensure!(
                slot.scope() == &self.scope
                    && slot.stamp.physical_authority_id == self.scope.physical_authority_id
                    && slot.stamp.incarnation.as_str() == self.incarnation.get().to_string()
                    && self.pending.is_none()
                    && self.stage.is_none()
                    && self.visible_receipt.is_some(),
                "corrupt observation slot"
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
            !matches!(intent.effect, super::protocol::Effect::Put { .. })
                || self.incarnation.get() < super::stage::state::MAX_INCARNATION,
            "object incarnation capacity exhausted"
        );
        ensure!(
            self.pending.is_none() && self.stage.is_none() && self.observation.is_none(),
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
        if matches!(
            receipt.turn.intent.effect,
            super::protocol::Effect::Put { .. }
        ) {
            next.incarnation = aos_hub_core::direct_upload::WireInteger::new(
                self.incarnation
                    .get()
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("object incarnation exhausted"))?,
            );
            next.visible_receipt = Some(VisibleReceipt {
                kind: VisibleKind::MetadataPut,
                operation_id: receipt.turn.intent.operation_id.clone(),
                receipt_digest: digest(receipt)?,
                context_digest: receipt.turn.intent.context.clone(),
                incarnation: next.incarnation,
                stage_configuration: None,
            });
        }
        if matches!(
            receipt.outcome,
            super::protocol::Outcome::DeleteAcknowledged { .. }
                | super::protocol::Outcome::DeleteAbsent
        ) {
            // Keep all historical receipts, but an acknowledged deletion can
            // no longer provide a current positive observation pointer.
            next.visible_receipt = None;
        }
        Ok(next)
    }
}
