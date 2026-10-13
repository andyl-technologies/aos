//! Installs a closed immutable cohort with one retained physical worker.
//!
//! Every primitive retains complete inputs and physical checks. Only acknowledged
//! changed preimages are rebound, from actual nofollow reads and incarnations.

#[path = "immutable_cohort/scope.rs"]
pub(super) mod scope;

use super::{
    FencePolicy, MetadataStamp, NativeEffectFailure, Plan, PrimitiveWorker, check_parents,
    open_native, projection,
};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::mpsc;

#[cfg(test)]
#[path = "immutable_cohort_timings.rs"]
mod timings;

/// Fixes canonical bytes and freshly observed absent staging and target names.
pub(super) struct Install {
    /// The unique freshly absent staging name in the target's directory.
    pub(super) temporary: PathBuf,
    /// The canonical immutable destination observed absent by the producer.
    pub(super) target: PathBuf,
    /// The complete canonical body fixed by the closed Raw mutation.
    pub(super) bytes: Vec<u8>,
    /// The independently configured payload owner and leaf protection policy.
    pub(super) policy: FencePolicy,
}

/// Owns fixed commands and a result channel populated only by native execution.
pub(super) struct Request {
    installs: Vec<Install>,
    result: mpsc::Sender<()>,
    scope: Option<scope::Scope>,
}

impl Request {
    /// Copies the actual fixed canonical targets for native callback observation.
    #[cfg(all(test, feature = "tokio"))]
    pub(super) fn targets(&self) -> Vec<PathBuf> {
        self.installs
            .iter()
            .map(|install| install.target.clone())
            .collect()
    }
}

/// Takes acknowledgment exclusively from the completed retained worker.
pub(super) struct Receipt {
    result: mpsc::Receiver<()>,
}

impl Receipt {
    /// Rejects callback success without actual completed native checks.
    ///
    /// # Errors
    /// Returns `Unsupported` when the native worker has not acknowledged.
    pub(super) fn take(self) -> Result<(), NativeEffectFailure> {
        self.result.try_recv().map_err(|_| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "native cohort acknowledgment unavailable",
            )
            .into()
        })
    }
}

/// Fixes the complete private cohort and its one-shot native acknowledgment.
pub(super) fn request(installs: Vec<Install>) -> (Plan, Receipt) {
    request_scoped(installs, None)
}

/// Fixes optional closed Raw provenance without changing native receipt authority.
pub(super) fn request_scoped(
    installs: Vec<Install>,
    scope: Option<scope::Scope>,
) -> (Plan, Receipt) {
    let (result, receiver) = mpsc::channel();
    (
        Plan::InstallImmutableCohort(Request {
            installs,
            result,
            scope,
        }),
        Receipt { result: receiver },
    )
}

/// Runs immutable installs without rebuilding or redispatching the projection.
///
/// # Errors
/// Preserves primitive or fresh-check refusal, uncertain durability and changed
/// acknowledged preimages. Earlier installed artifacts remain unselected.
///
/// # Panics
/// Panics in test builds if enabled cohort diagnostics cannot write to standard error.
pub(super) fn execute(
    worker: &mut PrimitiveWorker,
    mut request: Request,
) -> Result<(), NativeEffectFailure> {
    #[cfg(test)]
    let timings = request.installs.first().map(|install| {
        let path = install.target.parent().unwrap_or(&install.target);
        timings::CohortTimings::new(path)
    });
    #[cfg(test)]
    if let Some(timings) = &timings {
        timings.count("initial-names", worker.names.len());
        timings.count("initial-preimages", worker.preimages.len());
        timings.count("initial-pairs", worker.pairs.len());
        timings.count("planned-installs", request.installs.len());
        timings.count(
            "expected-install-bytes",
            request
                .installs
                .iter()
                .map(|install| install.bytes.len())
                .sum(),
        );
    }
    // Scope never substitutes for complete entry verification, including
    // previously acknowledged outputs from earlier bounded cohorts.
    if request.scope.is_some() {
        projection::Projection {
            exclusions: &worker.exclusions,
            names: &worker.names,
            preimages: &worker.preimages,
            final_check: worker.final_check.as_ref(),
            pairs: &worker.pairs,
            #[cfg(test)]
            faults: &worker.faults,
        }
        .check(None, None)?;
    }
    let mut cohort = Cohort::new(worker, request.scope.take());
    for install in request.installs {
        cohort.activate(&install.temporary, &install.target);
        #[cfg(test)]
        let primitive_span = timings.as_ref().map(|timings| timings.span("write-new"));
        cohort.execute(Plan::WriteNew {
            path: install.temporary.clone(),
            bytes: install.bytes.clone(),
        })?;
        #[cfg(test)]
        drop(primitive_span);
        #[cfg(test)]
        let rebind_span = timings
            .as_ref()
            .map(|timings| timings.span("staging-rebind"));
        let staging = cohort.rebind(&install.temporary, &install.bytes, install.policy, None)?;
        #[cfg(test)]
        drop(rebind_span);
        #[cfg(all(test, feature = "tokio"))]
        super::wait_test_gate(
            &mut cohort.worker.gates,
            super::TestGatePhase::AfterCohortStaging,
        )?;

        #[cfg(test)]
        let primitive_span = timings.as_ref().map(|timings| timings.span("sync-file"));
        cohort.execute(Plan::SyncFile {
            path: install.temporary.clone(),
        })?;
        #[cfg(test)]
        drop(primitive_span);
        #[cfg(test)]
        let primitive_span = timings
            .as_ref()
            .map(|timings| timings.span("rename-no-replace"));
        cohort.execute(Plan::RenameNoReplace {
            from: install.temporary.clone(),
            to: install.target.clone(),
        })?;
        #[cfg(test)]
        drop(primitive_span);
        #[cfg(test)]
        let rebind_span = timings
            .as_ref()
            .map(|timings| timings.span("target-rebind"));
        cohort.rebind(
            &install.target,
            &install.bytes,
            install.policy,
            Some(staging),
        )?;
        #[cfg(test)]
        drop(rebind_span);
        cohort.finish_install(&install.temporary, &install.target);
    }

    let worker = &*cohort.worker;
    #[cfg(test)]
    let projection_span = timings
        .as_ref()
        .map(|timings| timings.span("final-projection"));
    projection::Projection {
        exclusions: &worker.exclusions,
        names: &worker.names,
        preimages: &worker.preimages,
        final_check: worker.final_check.as_ref(),
        pairs: &worker.pairs,
        #[cfg(test)]
        faults: &worker.faults,
    }
    .check(None, None)?;
    #[cfg(test)]
    drop(projection_span);
    #[cfg(test)]
    let _send_span = timings.as_ref().map(|timings| timings.span("actual-send"));
    request.result.send(()).map_err(io::Error::other)?;
    Ok(())
}

/// Keeps incremental classification beside this operation's exclusive worker borrow.
///
/// Only its rebind/removal methods change retained rows. It accepts no replacement
/// worker, so prepared classification cannot cross into another worker or operation.
struct Cohort<'worker> {
    worker: &'worker mut PrimitiveWorker,
    scope: Option<scope::Scope>,
    prepared: bool,
}

impl<'worker> Cohort<'worker> {
    fn new(worker: &'worker mut PrimitiveWorker, scope: Option<scope::Scope>) -> Self {
        Self {
            worker,
            scope,
            prepared: false,
        }
    }

    /// Preserves the first full preparation after the original activation point.
    fn activate(&mut self, temporary: &Path, target: &Path) {
        if let Some(scope) = &mut self.scope {
            scope.activate(temporary, target);
            if !self.prepared {
                scope.prepare(&self.worker.preimages);
                self.prepared = true;
            }
        }
    }

    fn execute(&mut self, plan: Plan) -> Result<(), NativeEffectFailure> {
        self.worker.execute_scoped(plan, None, self.scope.as_ref())
    }

    /// Reclassifies only after every variant passed the original physical rebind.
    ///
    /// A partial failing rebind still exits with its original error. No later
    /// primitive or classification lookup occurs on that failure path.
    fn rebind(
        &mut self,
        path: &Path,
        bytes: &[u8],
        policy: FencePolicy,
        expected: Option<MetadataStamp>,
    ) -> io::Result<MetadataStamp> {
        let captured = rebind(self.worker, path, bytes, policy, expected)?;
        if let Some(scope) = &mut self.scope {
            scope.refresh_path(&self.worker.preimages, path);
        }
        Ok(captured)
    }

    fn finish_install(&mut self, temporary: &Path, target: &Path) {
        if let Some(scope) = &mut self.scope {
            scope.promote(target);
        }
        // Successful rename consumed this exact staging incarnation. As in the
        // ordinary install, its old predicate no longer enters later commands.
        self.worker.preimages.retain(|read| read.path != temporary);
        if let Some(scope) = &mut self.scope {
            scope.forget_path(temporary);
        }
    }
}

/// Recaptures every retained policy variant of one acknowledged changed name.
fn rebind(
    worker: &mut PrimitiveWorker,
    path: &Path,
    bytes: &[u8],
    policy: FencePolicy,
    expected: Option<MetadataStamp>,
) -> io::Result<MetadataStamp> {
    let mut captured = None;
    for read in worker.preimages.iter_mut().filter(|read| read.path == path) {
        check_parents(path, &read.parents, read.owner)?;
        let file = open_native(path, false)?;
        let opened = MetadataStamp::checked(&file.metadata()?)?;
        read.policy.validate(opened)?;
        policy.validate(opened)?;
        if expected.is_some_and(|stamp| !opened.same_incarnation(stamp))
            || captured.is_some_and(|stamp: MetadataStamp| !opened.same_incarnation(stamp))
        {
            return Err(io::Error::other("acknowledged cohort incarnation changed"));
        }

        let mut actual = Vec::new();
        (&file)
            .take(u64::try_from(bytes.len().saturating_add(1)).map_err(io::Error::other)?)
            .read_to_end(&mut actual)?;
        let named = MetadataStamp::checked(&std::fs::symlink_metadata(path)?)?;
        read.policy.validate(named)?;
        if !named.same_incarnation(opened) || actual != bytes {
            return Err(io::Error::other("acknowledged cohort preimage changed"));
        }
        check_parents(path, &read.parents, read.owner)?;

        read.expected = Some(actual);
        read.identity = Some(opened.identity);
        read.metadata = Some(opened);
        captured = Some(opened);
    }
    captured.ok_or_else(|| io::Error::other("missing changed cohort preimage"))
}
