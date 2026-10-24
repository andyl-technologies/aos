//! Preflights the concrete decoded native17 owners independently of source rows.
//!
//! This optional accumulator is inert requested-layout data. It grants no live
//! action or allocation allowance. Old readers leave it absent. Source Rc/Box
//! records do not imply decoded allocations: callers charge only the target
//! containers they actually construct, and the enclosing graph charges its
//! final inline root once.

use super::{Ledger, ValidatedHistoricalJson, invalid};
use crate::ProviderError;
use crate::retained_metadata::records::MetadataRecordKind;
use std::alloc::Layout;
use std::mem::{align_of, size_of};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);

pub(super) struct Native17Targets {
    session: u64,
    generation: u64,
    suspension_depth: usize,
    top_generation: u64,
    finished: bool,
    failed: bool,
    root_charged: bool,
    maximum: usize,
    requested: usize,
}

/// Carries one non-cloneable suspension for one enabled ledger session.
///
/// Fields are private and finish refuses an outstanding suspension. This token
/// only avoids charging a validation-only repeated view; it conveys no alias or
/// source authority and cannot be used with another ledger.
pub(crate) struct Native17TargetPause {
    session: u64,
    generation: u64,
    previous_generation: u64,
    depth: usize,
}

impl<'a, 'scratch, 'input> Ledger<'a, 'scratch, 'input> {
    /// Binds an independently admitted empty target-cache scratch bank once.
    ///
    /// # Errors
    /// Refuses a repeated binding or populated scratch. Its backing remains in
    /// the enclosing partial decode owner and is charged separately there.
    pub(crate) fn bind_native17_target_groups_data(
        &mut self,
        groups: &'scratch mut [bool],
    ) -> Result<(), ProviderError> {
        if self.native17_target_groups.is_some() || groups.iter().any(|value| *value) {
            self.fail_native17_targets_data();
            return Err(invalid());
        }
        self.native17_target_groups = Some(groups);
        Ok(())
    }
}

impl Ledger<'_, '_, '_> {
    /// Starts the native17-only concrete target preflight before target builds.
    ///
    /// # Errors
    /// Refuses a repeated start or exhausted session discriminator.
    pub(crate) fn begin_native17_targets_data(
        &mut self,
        maximum_requested: usize,
    ) -> Result<(), ProviderError> {
        if self.native17_targets.is_some() {
            self.fail_native17_targets_data();
            return Err(invalid());
        }
        let session = NEXT_SESSION
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| invalid())?;
        self.native17_targets = Some(Native17Targets {
            session,
            generation: 0,
            suspension_depth: 0,
            top_generation: 0,
            finished: false,
            failed: false,
            root_charged: false,
            maximum: maximum_requested,
            requested: 0,
        });
        Ok(())
    }

    /// Charges one concrete target vector's reserved backing in either pass.
    ///
    /// # Errors
    /// Refuses overflow, failed planning or requested storage beyond the bound.
    pub(crate) fn native17_target_vector_data<T>(
        &mut self,
        capacity: usize,
    ) -> Result<(), ProviderError> {
        if !self.native17_targets_active_data()? {
            return Ok(());
        }
        let Some(bytes) = capacity.checked_mul(size_of::<T>()) else {
            self.fail_native17_targets_data();
            return Err(invalid());
        };
        if Layout::array::<T>(capacity).is_err() {
            self.fail_native17_targets_data();
            return Err(invalid());
        }
        self.charge_native17_targets_data(bytes)
    }

    /// Charges one actual target Box allocation, excluding its inline handle.
    ///
    /// # Errors
    /// Refuses failed planning or requested storage beyond the bound.
    pub(crate) fn native17_target_box_data<T>(&mut self) -> Result<(), ProviderError> {
        self.charge_native17_targets_data(size_of::<T>())
    }

    /// Charges one actual target Rc/Arc allocation and its two-count header.
    ///
    /// Source shared owners decoded inline must not call this method.
    ///
    /// # Errors
    /// Refuses invalid combined layouts or requested storage beyond the bound.
    pub(crate) fn native17_target_shared_data<T>(&mut self) -> Result<(), ProviderError> {
        if !self.native17_targets_active_data()? {
            return Ok(());
        }
        let Ok((layout, _)) = Layout::new::<[usize; 2]>().extend(Layout::new::<T>()) else {
            self.fail_native17_targets_data();
            return Err(invalid());
        };
        self.charge_native17_targets_data(layout.pad_to_align().size())
    }

    /// Charges the repository's source-pinned bound for a concrete target tree.
    ///
    /// The node bound includes a possible empty root; it is separate from the
    /// target keys' and values' recursively charged backing.
    ///
    /// # Errors
    /// Refuses layout overflow or requested storage beyond the bound.
    pub(crate) fn native17_target_tree_data<K, V>(
        &mut self,
        entries: usize,
    ) -> Result<(), ProviderError> {
        if !self.native17_targets_active_data()? {
            return Ok(());
        }
        let Some(key_value_bytes) = size_of::<K>().checked_add(size_of::<V>()) else {
            self.fail_native17_targets_data();
            return Err(invalid());
        };
        let result = crate::retained_metadata::requested_storage::tree_storage_data(
            1,
            entries,
            key_value_bytes,
            align_of::<K>().max(align_of::<V>()),
        );
        let bytes = match result {
            Ok(bytes) => bytes,
            Err(error) => {
                self.fail_native17_targets_data();
                return Err(error);
            }
        };
        self.charge_native17_targets_data(bytes)
    }

    /// Charges one final cached target Arc slice at its first actual build site.
    ///
    /// Returns whether this target group needs its recursively owned children.
    /// The temporary Vec staging bank is counted independently by the ledger's
    /// selected_slice_staging_bytes, as in the concrete selected-slice builder.
    ///
    /// # Errors
    /// Refuses missing cache scratch, unknown groups, overflow or excess demand.
    pub(crate) fn native17_target_shared_slice_data<T>(
        &mut self,
        group: usize,
        count: usize,
    ) -> Result<bool, ProviderError> {
        if !self.native17_targets_active_data()? {
            return Ok(false);
        }
        let Some(seen) = self
            .native17_target_groups
            .as_mut()
            .and_then(|groups| groups.get_mut(group))
        else {
            self.fail_native17_targets_data();
            return Err(invalid());
        };
        if *seen {
            return Ok(false);
        }
        *seen = true;
        let layout = Layout::array::<T>(count)
            .and_then(|payload| Layout::new::<[usize; 2]>().extend(payload));
        let Ok((layout, _)) = layout else {
            self.fail_native17_targets_data();
            return Err(invalid());
        };
        self.charge_native17_targets_data(layout.pad_to_align().size())?;
        Ok(true)
    }

    /// Reports whether concrete native17 target accounting is enabled.
    pub(crate) fn has_native17_targets_data(&self) -> bool {
        self.native17_targets.is_some()
    }

    /// Reports whether the enabled target plan is inside a private suspension.
    ///
    /// Immutable evidence walkers may run while the once ledger is suspended;
    /// this observation cannot create, resume or discard a suspension token.
    pub(crate) fn native17_targets_suspended_data(&self) -> bool {
        self.native17_targets
            .as_ref()
            .is_some_and(|plan| plan.suspension_depth != 0)
    }

    /// Charges the final graph DTO's inline header exactly once.
    ///
    /// Nested inline children, including Option payloads, are already part of
    /// this layout and must not be charged separately.
    ///
    /// # Errors
    /// Refuses absent planning, duplicate roots or a suspended/failed plan.
    pub(crate) fn native17_target_inline_root_data<T>(&mut self) -> Result<(), ProviderError> {
        let plan = self.native17_targets.as_mut().ok_or_else(invalid)?;
        if plan.root_charged || plan.suspension_depth != 0 || plan.failed || plan.finished {
            plan.failed = true;
            return Err(invalid());
        }
        plan.root_charged = true;
        self.charge_native17_targets_data(size_of::<T>())
    }

    /// Marks a graph header already embedded in the admitted enclosing owner.
    ///
    /// This records no allocation: the containing DecodeAttempt layout already
    /// contains this entire inline child. Dynamic target backing is still charged
    /// at each concrete construction site in both passes.
    ///
    /// # Errors
    /// Refuses absent, repeated, suspended, failed or completed planning.
    pub(crate) fn native17_target_embedded_root_data(&mut self) -> Result<(), ProviderError> {
        let plan = self.native17_targets.as_mut().ok_or_else(invalid)?;
        if plan.root_charged || plan.suspension_depth != 0 || plan.failed || plan.finished {
            plan.failed = true;
            return Err(invalid());
        }
        plan.root_charged = true;
        Ok(())
    }

    /// Suspends target charges during one concrete validation-only repeated view.
    ///
    /// # Errors
    /// Refuses failed, completed or discriminator-exhausted suspensions.
    pub(crate) fn suspend_native17_targets_data(
        &mut self,
    ) -> Result<Native17TargetPause, ProviderError> {
        let Some(plan) = self.native17_targets.as_mut() else {
            return Ok(Native17TargetPause {
                session: 0,
                generation: 0,
                previous_generation: 0,
                depth: 0,
            });
        };
        if plan.failed || plan.finished {
            plan.failed = true;
            return Err(invalid());
        }
        let Some(generation) = plan.generation.checked_add(1) else {
            plan.failed = true;
            return Err(invalid());
        };
        plan.generation = generation;
        let previous_generation = plan.top_generation;
        plan.top_generation = plan.generation;
        let Some(depth) = plan.suspension_depth.checked_add(1) else {
            plan.failed = true;
            return Err(invalid());
        };
        plan.suspension_depth = depth;
        Ok(Native17TargetPause {
            session: plan.session,
            generation: plan.generation,
            previous_generation,
            depth: plan.suspension_depth,
        })
    }

    /// Completes the exact outstanding validation-only suspension.
    ///
    /// # Errors
    /// Refuses another ledger/session, a stale token or any failed read.
    pub(crate) fn resume_native17_targets_data(
        &mut self,
        token: Native17TargetPause,
    ) -> Result<(), ProviderError> {
        let Some(plan) = self.native17_targets.as_mut() else {
            return if token.session == 0 && token.depth == 0 {
                Ok(())
            } else {
                Err(invalid())
            };
        };
        if plan.failed
            || plan.finished
            || token.session != plan.session
            || token.generation != plan.top_generation
            || token.depth != plan.suspension_depth
            || token.depth == 0
        {
            plan.failed = true;
            return Err(invalid());
        }
        plan.top_generation = token.previous_generation;
        plan.suspension_depth -= 1;
        Ok(())
    }

    /// Returns the complete target demand after all target and root charges.
    ///
    /// # Errors
    /// Refuses absent/failed planning, an outstanding suspension or no root.
    pub(crate) fn finish_native17_targets_data(&mut self) -> Result<usize, ProviderError> {
        let plan = self.native17_targets.as_mut().ok_or_else(invalid)?;
        if plan.failed || plan.finished || plan.suspension_depth != 0 || !plan.root_charged {
            plan.failed = true;
            return Err(invalid());
        }
        plan.finished = true;
        Ok(plan.requested)
    }

    pub(super) fn fail_native17_targets_data(&mut self) {
        if let Some(plan) = &mut self.native17_targets {
            plan.failed = true;
        }
    }

    fn native17_targets_active_data(&self) -> Result<bool, ProviderError> {
        match &self.native17_targets {
            Some(plan) if plan.failed || plan.finished => Err(invalid()),
            Some(plan) => Ok(plan.suspension_depth == 0),
            None => Ok(false),
        }
    }

    fn charge_native17_targets_data(&mut self, bytes: usize) -> Result<(), ProviderError> {
        let Some(plan) = &mut self.native17_targets else {
            return Ok(());
        };
        if plan.failed || plan.finished {
            return Err(invalid());
        }
        if plan.suspension_depth != 0 {
            return Ok(());
        }
        let Some(requested) = plan.requested.checked_add(bytes) else {
            plan.failed = true;
            return Err(invalid());
        };
        if requested > plan.maximum {
            plan.failed = true;
            return Err(ProviderError::ResourceExhausted(
                "native17 decoded target storage",
            ));
        }
        plan.requested = requested;
        Ok(())
    }

    pub(super) fn native17_target_json_data(
        &mut self,
        plan: &ValidatedHistoricalJson<'_, '_>,
    ) -> Result<(), ProviderError> {
        if !self.native17_targets_active_data()? {
            return Ok(());
        }
        // These rows were already validated against the exact target JSON types.
        // Only this consumed prefix is charged; later typed fields keep theirs.
        let mut records = self.rows.clone();
        for _ in 0..plan.consumed_record_count() {
            let row = records.next().ok_or_else(invalid)??;
            match row.kind {
                MetadataRecordKind::String => self.native17_target_vector_data::<u8>(row.extent)?,
                MetadataRecordKind::Vector => {
                    self.native17_target_vector_data::<serde_json::Value>(row.extent)?
                }
                MetadataRecordKind::Tree => {
                    self.native17_target_tree_data::<String, serde_json::Value>(row.extent)?
                }
                _ => return Err(invalid()),
            }
        }
        Ok(())
    }
}
