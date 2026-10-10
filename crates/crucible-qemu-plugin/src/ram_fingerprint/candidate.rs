//! Computes a private dirty-page candidate under the retained physical owner.

// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;

/// GPL-private evidence for the single no-ack capture-close attempt.
#[repr(C)]
#[derive(Default)]
pub(crate) struct CaptureClose {
    /// Identifies the capture whose single close attempt produced this evidence.
    pub(crate) generation: u64,
    /// Preserves the actual native status independently of the observing failure.
    pub(crate) status: c_int,
    /// Is one only when the claim made its sole explicit no-ack close attempt.
    pub(crate) attempted: u32,
}

impl RootCache {
    /// Borrows the committed baseline without replacing it or retiring dirties.
    pub(super) fn observe_candidate(
        &self,
        apis: NativeApis,
        scope: Scope,
        owner_token: u64,
        cleanup: &mut CaptureClose,
    ) -> Result<(RamRootDigest, u64), RamError> {
        if owner_token == 0 || self.frozen || self.pending.is_some() || self.restore.is_some() {
            return Err(RamError::Invariant(
                "RAM candidate lacks exclusive observer admission",
            ));
        }
        let view = self
            .view
            .as_ref()
            .ok_or("RAM candidate has no committed baseline")?;
        let budget = self
            .budget
            .as_ref()
            .ok_or("RAM candidate has no original metadata account")?;
        if !budget.shares_account_with(&view.budget)
            || !budget.shares_account_with(view.snapshot.metadata_budget())
        {
            return Err(RamError::Invariant(
                "RAM candidate belongs to another metadata account",
            ));
        }

        // The claim stays outside the unwind boundary. Both a failed page read
        // and a panic therefore reach the same explicit close-evidence route.
        let mut claim = CaptureClaim::open(apis, false, owner_token)?;
        cleanup.generation = claim.header.capture_generation;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            claim.validate_header()?;
            if claim.header.topology_generation != view.topology_generation
                || claim.header.region_count as usize != view.native_regions.len()
                || claim.header.metadata_budget_bytes != budget.limit_bytes()
            {
                return Err(RamError::Invariant(
                    "RAM candidate differs from its admitted baseline",
                ));
            }
            validate_borrowed_regions(&claim, &view.native_regions)?;
            let (snapshot, _) = consume_pages(
                &claim,
                &view.native_regions,
                view.snapshot.clone(),
                false,
                view.source.as_deref(),
            )?;
            let digest = snapshot.scoped_root(scope).map_err(display_error)?;
            let bytes = snapshot
                .topology()
                .regions()
                .iter()
                .try_fold(0_u64, |total, region| {
                    if scope.includes(region.class()) {
                        total
                            .checked_add(region.logical_length())
                            .ok_or(RamError::Invariant("RAM candidate byte count overflow"))
                    } else {
                        Ok(total)
                    }
                })?;
            Ok((digest, bytes))
        }))
        .unwrap_or(Err(RamError::Invariant(
            "RAM candidate observation panicked",
        )));

        if let Some(status) = claim.close_without_ack() {
            cleanup.status = status;
            cleanup.attempted = 1;
            if status != 0 && result.is_ok() {
                return Err(RamError::Native {
                    operation: "close RAM observation without acknowledgement",
                    status,
                });
            }
        }
        // A close refusal never replaces the initiating failure. Native retains
        // the failed claim's custody, while the caller retains both statuses.
        result
    }
}

fn validate_borrowed_regions(
    claim: &CaptureClaim,
    regions: &[RegionDescriptor],
) -> Result<(), RamError> {
    for (index, expected) in regions.iter().enumerate() {
        let mut native = CaptureRegion::default();
        status(
            (claim.apis.region)(
                claim.header.capture_generation,
                claim.owner_token,
                index as u32,
                &mut native,
            ),
            "validate admitted RAM region",
        )?;
        if native.id_length as usize != expected.id().len()
            || native.id_length > 255
            || native.class != u32::from(expected.class() as u8)
            || native.mask != u32::from(expected.coverage_mask())
            || native.reserved != 0
            || native.logical_length != expected.logical_length()
            || &native.id[..native.id_length as usize] != expected.id().as_bytes()
        {
            return Err(RamError::Invariant(
                "RAM capture changed its sealed region descriptor",
            ));
        }
    }
    Ok(())
}
