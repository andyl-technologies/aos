//! Coordinates bounded recurring local work beneath immutable permanent ownership.
//!
//! Each observation, progress selection and physical request independently
//! resolves current owner, DATA, Original controls and the same whole live
//! lease. A completed bounded call never ends ownership or certifies future
//! absence. Restoration through fresh placements is a separate operation.

use super::{CollectionError, denied, session};
use crate::bucket::{BucketBinding, FileBucket};
use crate::gc::lease::Collector;
use crate::guard::{Guard, OriginalAuthority};
use crate::selected_bridge::{native_copied_placement, native_permanent_local};
use crate::store::native_publication_effects::collection_permanent_local as effects;
use crate::store::{Clock, ContentValidator, LocalFs, StoreFailure};
use std::collections::BTreeSet;
use terrane_format::gc::{GcError, GcLease, Windows};

/// Reports actual bounded native completions without terminating permanent ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reconciliation {
    /// The number of genuinely acknowledged residue requests in this call.
    pub reclaimed: usize,
    /// The number of durably selected current observation events in this call.
    pub selected_events: usize,
}

/// Holds one configured live collector session for recurring permanently owned work.
pub struct Recovery<'configuration, F, B, V, C> {
    guard: &'configuration Guard<FileBucket<F, B, V>, C>,
    authority: &'configuration OriginalAuthority,
    session: session::Session,
    windows: Windows,
}

impl<'configuration, F, B, V, C> Recovery<'configuration, F, B, V, C>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    /// Acquires an actual current maintenance lease without granting permanent ownership.
    ///
    /// # Errors
    /// Refuses another coordinator, invalid current retention windows, competing
    /// ownership, unavailable clocks, invalid whole leases,
    /// configured authority refusal or incomplete native lease durability.
    pub async fn start(
        guard: &'configuration Guard<FileBucket<F, B, V>, C>,
        authority: &'configuration OriginalAuthority,
        holder: String,
        duration: u64,
        coordinator: &crate::ref_advance::Coordinator<FileBucket<F, B, V>, C, F>,
        windows: Windows,
    ) -> Result<Self, CollectionError> {
        if !std::ptr::eq(guard, coordinator.guard()) {
            return Err(denied().into());
        }
        let maximum = coordinator.maximum_commit_duration();
        let commit = maximum
            .as_secs()
            .checked_add(u64::from(maximum.subsec_nanos() != 0))
            .ok_or(GcError::Exhausted)?;
        if windows.commit() != commit
            || windows.grace() <= commit
            || windows.deletion() < windows.grace()
        {
            return Err(GcError::Window.into());
        }
        Windows::new(
            windows.commit(),
            windows.grace(),
            windows.deletion(),
            windows.retention(),
        )?;
        let lease = Collector::new(guard, authority)
            .acquire(holder, duration)
            .await?
            .lease;
        let clock = guard.clock().retain_native_clock().map_err(|_| denied())?;
        Ok(Self {
            guard,
            authority,
            session: session::Session::new(lease, duration, clock)?,
            windows,
        })
    }

    /// Borrows the whole currently acknowledged collector lease.
    pub fn lease(&self) -> &GcLease {
        self.session.lease()
    }

    /// Restores verified owned source content through a fresh secure placement.
    ///
    /// The permanent family remains burned and owned. Extraction is collector-only;
    /// complete content and dependency verification precede actual fresh admission.
    /// Cancellation poisons the Session and queued native work retains its holds.
    ///
    /// # Errors
    /// Refuses invalid selected ownership, stale lease or Original controls,
    /// missing or corrupt sources, invalid dependencies, unsafe physical state,
    /// secure-ID collisions and incomplete native staging or publication.
    pub async fn restore(
        &mut self,
        owner_key: &str,
    ) -> Result<crate::pack::PackId, CollectionError> {
        let operation = self.session.operation()?;
        self.session
            .renew(&Collector::new(self.guard, self.authority))
            .await?;
        self.session.recheck()?;
        let holder = crate::bucket::held::SingleHeld::acquire(self.guard.store()).await?;
        let held = holder.destination();
        let observed = held.observe_publication_unrepaired().await?;
        let owner = native_permanent_local::qualify(
            self.guard,
            self.authority,
            &self.session,
            &held,
            &observed,
            owner_key,
            None,
        )
        .await?;
        let source = std::sync::Arc::new(effects::extract_owned(held.fs(), &owner).await?);
        let fresh =
            crate::bucket::permanent_restore::candidate::admit(&held, &owner, source).await?;
        self.session.recheck()?;
        operation.complete();
        Ok(fresh)
    }

    /// Reconciles bounded currently observed candidates under an actual selected owner.
    ///
    /// The key selects a candidate only. Genuine immutable history and current
    /// configured prerequisites provide permission independently on every step.
    /// Fully observed candidate passes may complete after all accumulated duties
    /// resolve. Completion never certifies future absence or ends ownership.
    /// Cancellation poisons the Session while queued workers retain exclusions.
    ///
    /// # Errors
    /// Refuses unknown owners, visibility-only burns, stale lease or current
    /// inputs, unsafe canonical families, exhausted bounds, physical replacement,
    /// partial native effects and missing real durability acknowledgments.
    ///
    /// # Panics
    /// In test builds, panics if opt-in phase diagnostics cannot write to
    /// standard error.
    pub async fn reconcile(
        &mut self,
        owner_key: &str,
        maximum_requests: usize,
    ) -> Result<Reconciliation, CollectionError> {
        if maximum_requests == 0 || maximum_requests > 4096 {
            return Err(denied().into());
        }
        let operation = self.session.operation()?;
        #[cfg(test)]
        let trace = crate::ref_advance::NativeTrace::new(
            self.guard.store().root(),
            "permanent-reconciliation",
        );
        let mut report = Reconciliation {
            reclaimed: 0,
            selected_events: 0,
        };
        loop {
            #[cfg(test)]
            trace.mark("loop-renewal-start");
            // Each bounded traversal starts with an acknowledged whole renewal.
            // The previous native work has returned and released its checked
            // borrows; its expiry-specific predicates cannot authorize this work.
            self.session
                .renew(&Collector::new(self.guard, self.authority))
                .await?;
            #[cfg(test)]
            trace.mark("loop-renewal-acknowledged");
            self.session.recheck()?;
            let holder = crate::bucket::held::SingleHeld::acquire(self.guard.store()).await?;
            let held = holder.destination();
            let observed = held.observe_publication_unrepaired().await?;
            #[cfg(test)]
            trace.mark("loop-publication-observed");
            let owner = native_permanent_local::qualify(
                self.guard,
                self.authority,
                &self.session,
                &held,
                &observed,
                owner_key,
                None,
            )
            .await?;
            let checked = native_copied_placement::qualify_current_owned(
                self.guard,
                self.authority,
                &self.session,
                &held,
                &observed,
                &owner,
                (Some(owner.controls()), &self.windows),
            )
            .await?;
            let history = native_permanent_local::history::selected(held.fs(), &owner).await?;
            #[cfg(test)]
            trace.mark("loop-current-inputs-and-history-qualified");
            let current_cycles = candidate_cycles(held.fs(), held.root()).await?;
            let cycles = history.batch(&current_cycles);
            let observation =
                std::sync::Arc::new(effects::observe(held.fs(), &checked, cycles, &history).await?);
            #[cfg(test)]
            trace.mark("loop-native-observation-returned");
            let rows = observation
                .progress()
                .map_err(crate::selected_bridge::native_restore_failure)?;
            let next = history.next(&rows);
            let artifacts = checked.artifacts(&held).await?;
            #[cfg(test)]
            trace.mark("loop-fresh-artifacts-prepared");
            let (_, phase) =
                effects::publish_observed(held.fs(), &checked, &artifacts, &observation).await?;
            #[cfg(test)]
            trace.mark("loop-progress-acknowledged");
            report.selected_events += 1;

            // Drop every checked borrow before independently resolving the
            // new selected event. The old operation cannot authorize its child.
            drop(artifacts);
            drop(observation);
            drop(checked);
            drop(owner);
            drop(observed);
            drop(held);
            drop(holder);
            let Some(next) = next else {
                if phase == terrane_format::gc::retirement::PassPhase::PassCompleted {
                    break;
                }
                // The initial event must be Open. Independently resolve it and
                // repeat the complete native traversal before selecting completion.
                continue;
            };
            if report.reclaimed == maximum_requests {
                break;
            }

            // Requalify the selected duty and complete current DATA under the
            // same whole lease as its Planned event. The next loop renews only
            // after this request has actually returned and released its holds.
            #[cfg(test)]
            trace.mark("reclaim-qualification-start");
            let holder = crate::bucket::held::SingleHeld::acquire(self.guard.store()).await?;
            let held = holder.destination();
            let observed = held.observe_publication_unrepaired().await?;
            let owner = native_permanent_local::qualify(
                self.guard,
                self.authority,
                &self.session,
                &held,
                &observed,
                owner_key,
                None,
            )
            .await?;
            let checked = native_copied_placement::qualify_current_owned(
                self.guard,
                self.authority,
                &self.session,
                &held,
                &observed,
                &owner,
                (Some(owner.controls()), &self.windows),
            )
            .await?;
            let history = native_permanent_local::history::selected(held.fs(), &owner).await?;
            let current_cycles = candidate_cycles(held.fs(), held.root()).await?;
            let mut cycles = history.batch(&current_cycles);
            if let terrane_format::gc::retirement::ObservedArtifact::Trash(cycle) = next.artifact
                && cycles.binary_search(&cycle).is_err()
            {
                if cycles.len() == native_permanent_local::history::NATIVE_BATCH_CYCLES {
                    cycles.pop();
                }
                cycles.push(cycle);
                cycles.sort_unstable();
            }
            let observation =
                std::sync::Arc::new(effects::observe(held.fs(), &checked, cycles, &history).await?);
            let request =
                native_permanent_local::qualify_reclaim(&checked, &held, next.artifact).await?;
            #[cfg(test)]
            trace.mark("reclaim-current-inputs-and-observation-qualified");
            effects::reclaim(held.fs(), &request, observation).await?;
            #[cfg(test)]
            trace.mark("reclaim-acknowledged");
            report.reclaimed += 1;
            // The next iteration observes actual outcomes and selects another
            // event, including late residues. No successful absence is cached.
        }
        self.session.recheck()?;
        operation.complete();
        #[cfg(test)]
        trace.mark("reconciliation-completed");
        Ok(report)
    }
}

async fn candidate_cycles<F: LocalFs + BucketBinding>(
    fs: &F,
    root: &std::path::Path,
) -> Result<Vec<u64>, StoreFailure> {
    let trash = root.join("trash");
    let paths = match fs.read_dir(&trash).await {
        Ok(paths) => paths,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(StoreFailure::with_source(
                crate::store::StoreErrorKind::Unavailable { retry_after: None },
                error,
            ));
        }
    };
    let mut cycles = BTreeSet::new();
    for path in paths {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(denied)?;
        let cycle = name.parse::<u64>().map_err(|_| denied())?;
        if path != trash.join(cycle.to_string()) || name != cycle.to_string() {
            return Err(denied());
        }
        cycles.insert(cycle);
    }
    // This list chooses candidates only. Native requests independently verify
    // every actual leaf and ancestor; listing grants no all-family absence.
    Ok(cycles.into_iter().collect())
}
