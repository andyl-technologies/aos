//! Positive destination-copy prefixes retained across foreground invocations.
//!
//! Each cursor belongs to one immutable physical reservation. Advancing it
//! requires independently reading every exact positive copy receipt in the wave;
//! elapsed time, provider HEAD and a prepared mutation never advance progress.
//! The versioned journal key stores a JSON unsigned integer:
//!
//! ```text
//! direct-guard/copy-progress/v1/<reservation-operation-id> -> 64
//! ```

use anyhow::{ensure, Result};

use crate::external_object::MAX_PENDING_DESTINATION_PARTS;

/// Bounds new copies across one foreground invocation, below the journal limit.
pub(crate) const MAX_COPY_PARTS_PER_INVOCATION: usize = 32;

/// Checks one bounded contiguous wave, including its exact acknowledgement replay.
///
/// # Errors
/// Refuses changed progress, skipped parts, an oversized wave or an invalid end.
pub(super) fn validate_advance(current: u32, after: u32, through: u32, total: u32) -> Result<()> {
    ensure!(
        (current == after || current == through)
            && after < through
            && through <= total
            && through - after <= MAX_PENDING_DESTINATION_PARTS as u32,
        "direct destination copy cursor changed or exceeds one wave"
    );
    Ok(())
}

/// Selects at most one journal-sized wave after a checked positive prefix.
///
/// # Errors
/// Refuses a prefix outside the admitted original's part catalogue.
pub(super) fn next_wave(total: usize, copied_through: u32) -> Result<std::ops::Range<usize>> {
    let after = usize::try_from(copied_through)?;
    ensure!(
        after <= total,
        "direct copied prefix exceeds original parts"
    );
    Ok(after
        ..after
            .saturating_add(MAX_COPY_PARTS_PER_INVOCATION)
            .min(total))
}

#[cfg(target_arch = "wasm32")]
pub(super) mod journal {
    use aos_hub_db::direct_upload::DirectManifestPart;
    use worker::{Env, Storage};

    use super::*;
    use crate::direct_guard::{runtime, state::Reservation, transport::Turn};

    fn key(owner: &Reservation) -> String {
        format!(
            "direct-guard/copy-progress/v1/{}",
            owner.binding.reservation_operation_id
        )
    }

    /// Reads the positive prefix scoped to the immutable physical reservation.
    ///
    /// # Errors
    /// Refuses unreadable progress or a cursor beyond the admitted original.
    pub(in crate::direct_guard) async fn read(
        storage: &Storage,
        owner: &Reservation,
    ) -> Result<u32> {
        let count: u32 = runtime::read(storage, &key(owner)).await?.unwrap_or(0);
        ensure!(
            count <= owner.admission.intent.part_count()?,
            "direct destination copy cursor outside original"
        );
        Ok(count)
    }

    /// Reads exact positive part receipts inside the acknowledged prefix.
    ///
    /// # Errors
    /// Refuses an out-of-range page, unresolved effect or different original.
    pub(in crate::direct_guard) async fn parts(
        env: &Env,
        storage: &Storage,
        turn: &Turn,
        owner: &Reservation,
        after: u32,
        through: u32,
    ) -> Result<Vec<DirectManifestPart>> {
        ensure!(
            through <= read(storage, owner).await?,
            "direct destination copy page exceeds acknowledged prefix"
        );
        positive_parts(env, storage, turn, after, through).await
    }

    async fn positive_parts(
        env: &Env,
        storage: &Storage,
        turn: &Turn,
        after: u32,
        through: u32,
    ) -> Result<Vec<DirectManifestPart>> {
        crate::external_object::acknowledged_destination_parts(
            env,
            storage,
            &turn.admission,
            &turn.complete,
            turn.placement_id,
            after,
            through,
        )
        .await
    }

    /// Advances only after independently reading every positive original receipt.
    ///
    /// # Errors
    /// Refuses changed progress, unresolved or missing receipts, another original
    /// or a failure to retain the new cursor.
    pub(in crate::direct_guard) async fn acknowledge(
        env: &Env,
        storage: &Storage,
        turn: &Turn,
        owner: &Reservation,
        after: u32,
        through: u32,
    ) -> Result<u32> {
        let current = read(storage, owner).await?;
        validate_advance(
            current,
            after,
            through,
            owner.admission.intent.part_count()?,
        )?;
        positive_parts(env, storage, turn, after, through).await?;
        runtime::write(storage, &key(owner), &through).await?;
        Ok(through)
    }
}
