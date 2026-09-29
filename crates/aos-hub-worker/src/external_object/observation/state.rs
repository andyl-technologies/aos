//! Pure observation admission and exact terminal clearing under one head CAS.

use anyhow::{ensure, Result};
use aos_hub_core::storage_authority::{
    external_object::observation::ObservationExpectation,
    lease::{LeaseClock, LeaseEffect, LeaseInteger},
    GuardIncarnation, StorageGuardStamp,
};

use super::super::{
    config::Config,
    state::{Head, MAX_RECEIPTS},
};
use super::protocol::{Intent, Pending, Receipt};

pub(in crate::external_object) fn begin(
    head: &Head,
    config: &Config,
    intent: Intent,
    lease: &[u8],
    nonce: String,
    clock: LeaseClock,
) -> Result<(Head, Pending)> {
    head.validate(config, &intent.object.scope)?;
    intent.validate()?;
    ensure!(
        head.pending.is_none()
            && head.stage.is_none()
            && head.observation.is_none()
            && head.receipts.get() < MAX_RECEIPTS,
        "unknown object turn or receipt capacity blocks observation"
    );
    // Active multipart ownership stays excluded. A compact current positive
    // receipt pointer is required; the adapter checks its immutable KV record.
    head.visible_receipt
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("current positive publication proof absent"))?
        .validate(head)?;
    let stamp = StorageGuardStamp {
        physical_authority_id: head.scope.physical_authority_id.clone(),
        incarnation: GuardIncarnation::parse(head.incarnation.get().to_string())?,
    };
    if let ObservationExpectation::KnownStamp { stamp: expected } = &intent.expectation {
        ensure!(expected == &stamp, "known incarnation no longer current");
    }
    let cohort = config.cohort(&intent.object.cohort_digest)?;
    ensure!(
        cohort.authority == head.floor.authority,
        "authority creation facts changed"
    );
    let validated = config.verifier()?.validate_lease(
        lease,
        cohort,
        &config.timing_profile,
        &head.floor,
        &head.scope.full_key,
        LeaseEffect::Head,
        clock,
    )?;
    let turn = Pending {
        intent,
        dispatch_nonce: nonce,
        stamp,
    };
    turn.validate()?;
    let mut next = head.clone();
    next.floor = validated.next_floor;
    next.observation = Some(turn.clone());
    Ok((next, turn))
}

pub(in crate::external_object) fn terminal(head: &Head, receipt: &Receipt) -> Result<Head> {
    receipt.validate()?;
    ensure!(
        head.observation.as_ref() == Some(&receipt.turn)
            && head.incarnation.get().to_string() == receipt.turn.stamp.incarnation.as_str(),
        "terminal differs from locked observation"
    );
    let mut next = head.clone();
    next.receipts = LeaseInteger::new(
        head.receipts
            .get()
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("receipt count exhausted"))?,
    )?;
    ensure!(
        next.receipts.get() <= MAX_RECEIPTS,
        "receipt capacity exhausted"
    );
    next.observation = None;
    Ok(next)
}
