//! Produces actual no-follow residue observations under the whole current Frame.
//!
//! A fixed request covers pack, index and explicitly discovered canonical trash
//! cycles. Its result is not universal absence or permission to delete a later
//! instance; each reclaim request checks the same opened instance again. Discovery
//! synchronizes actual absent anchors before they can resolve selected duties.

use super::super::{FencePolicy, NativeEffectFailure, Path, PathBuf, Plan, Worker};
use super::recipes::Recipes;
use super::{ExtractedPair, NativePermanentObservation, physical::Leaf};
use crate::pack::PackId;
use std::io;
use std::sync::{Arc, mpsc};
use terrane_format::gc::retirement::PermanentDeleteOperation;

/// Distinguishes neutral discovery from independently qualified collector extraction.
pub(in super::super::super) enum ObservationPurpose {
    /// Observes instances and synchronizes absence without reading residue bodies.
    Discover,
    /// Reads a fixed owned pair for subsequent complete independent validation.
    ExtractEligible,
}

/// Fixes canonical family observations derived inside a genuine current producer.
pub(in super::super::super) struct ObservationRequest {
    root: PathBuf,
    control: PathBuf,
    operation_path: PathBuf,
    key: String,
    bytes: Vec<u8>,
    pack: [u8; 16],
    cycles: Vec<u64>,
    visited: Vec<u64>,
    owner: u32,
    purpose: ObservationPurpose,
    result: mpsc::Sender<NativePermanentObservation>,
}

impl ObservationRequest {
    /// Borrows the real selected operation path for test-only fault classification.
    #[cfg(all(test, feature = "tokio"))]
    pub(in super::super::super) fn path(&self) -> &Path {
        &self.operation_path
    }
}

/// Receives only an actual complete native observation, never unit completion.
pub(in super::super::super) struct ObservationReceiver(mpsc::Receiver<NativePermanentObservation>);

impl ObservationReceiver {
    /// Takes the observation after current, physical and absence durability checks.
    ///
    /// # Errors
    /// Refuses unexecuted, failed or no-op workers and disconnected result channels.
    pub(in super::super::super) fn take(
        self,
    ) -> Result<NativePermanentObservation, NativeEffectFailure> {
        self.0
            .try_recv()
            .map_err(|_| io::Error::other("permanent observation receipt absent").into())
    }
}

/// Fixes bounded canonical family paths, without granting authority to the input.
///
/// # Errors
/// Refuses malformed operation association or duplicate/out-of-order trash cycles.
pub(in super::super::super) fn plan(
    root: &Path,
    control: &Path,
    key: &str,
    bytes: Vec<u8>,
    traversal: (Vec<u64>, Vec<u64>),
    owner: u32,
    purpose: ObservationPurpose,
) -> Result<(Plan, ObservationReceiver), NativeEffectFailure> {
    let (cycles, visited) = traversal;
    let operation = PermanentDeleteOperation::decode(&bytes).map_err(io::Error::other)?;
    operation
        .authorization
        .check_key(key)
        .map_err(io::Error::other)?;
    if cycles.len() > terrane_format::gc::retirement::MAX_OBSERVATIONS - 2
        || cycles.windows(2).any(|pair| pair[0] >= pair[1])
        || visited.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(io::Error::other("permanent observation cycles are not canonical").into());
    }
    let pack = operation.authorization.exclusion().pack;
    let (result, receiver) = mpsc::channel();
    Ok((
        Plan::ObservePermanentLocal(Box::new(ObservationRequest {
            root: root.to_owned(),
            control: control.to_owned(),
            operation_path: control.join(key),
            key: key.to_owned(),
            bytes,
            pack,
            cycles,
            visited,
            owner,
            purpose,
            result,
        })),
        ObservationReceiver(receiver),
    ))
}

/// Accumulates leaf-loop diagnostics without logging at every physical fence.
///
/// These test-only process monotonic intervals never enter a deadline, receipt
/// or authority predicate. The worker scope has its own origin, independent of
/// the producer scope and any injected collector clock.
#[cfg(test)]
struct LeafTimings {
    enabled: bool,
    refresh: std::time::Duration,
    capture: std::time::Duration,
    check: std::time::Duration,
}

#[cfg(test)]
impl LeafTimings {
    fn new() -> Self {
        Self {
            enabled: std::env::var_os("TERRANE_REF_PHASE_TRACE").is_some(),
            refresh: std::time::Duration::ZERO,
            capture: std::time::Duration::ZERO,
            check: std::time::Duration::ZERO,
        }
    }

    fn start(&self) -> Option<crate::diagnostic_clock::Tick> {
        self.enabled.then(crate::diagnostic_clock::tick)
    }

    fn record(
        started: Option<crate::diagnostic_clock::Tick>,
        accumulated: &mut std::time::Duration,
    ) {
        if let Some(started) = started {
            *accumulated += crate::diagnostic_clock::elapsed(started);
        }
    }

    /// Reports successful loop regions, excluding diagnostic output itself.
    ///
    /// # Panics
    /// Panics if enabled diagnostics cannot write to standard error.
    fn report(&self, trace: &crate::ref_advance::NativeTrace) {
        if self.enabled {
            trace.mark(&format!(
                "leaf-loop-complete refresh_total={:?} capture_total={:?} check_total={:?}",
                self.refresh, self.capture, self.check,
            ));
        }
    }
}

/// Observes the fixed family under actual retained exclusions and current inputs.
///
/// # Errors
/// Refuses an unrelated current preimage, unsafe leaf or parent, replacement,
/// unknown absence, failed directory durability, expired/current authority, and
/// filesystem failures.
///
/// # Panics
/// In test builds, panics if opt-in phase diagnostics cannot write to
/// standard error.
pub(in super::super) fn execute(
    request: ObservationRequest,
    mut worker: Worker,
) -> Result<(), NativeEffectFailure> {
    #[cfg(test)]
    let trace = crate::ref_advance::NativeTrace::new(&request.root, "permanent-observation-worker");
    worker
        .projection
        .root(&request.root, request.owner, false)?;
    worker
        .projection
        .root(&request.control, request.owner, true)?;
    let read = worker
        .projection
        .exact(&request.operation_path, Some(&request.bytes))?;
    if !matches!(read.policy, FencePolicy::ProtectedRecord { owner } if owner == request.owner) {
        return Err(io::Error::other("permanent operation lacks protected preimage").into());
    }
    #[cfg(test)]
    trace.mark("initial-refresh-start");

    worker.refresh(&[])?;
    #[cfg(test)]
    trace.mark("initial-refresh-complete");

    let id = PackId::from_random_bytes(request.pack);
    let mut keys = vec![id.pack_key(), id.index_key()];
    keys.extend(
        request
            .cycles
            .iter()
            .map(|cycle| format!("trash/{cycle}/{id}")),
    );
    #[cfg(test)]
    trace.mark(&format!("leaf-paths-fixed count={}", keys.len()));
    #[cfg(test)]
    let mut leaf_timings = LeafTimings::new();

    let mut leaves = Vec::new();
    let recipes = Recipes::new(&worker.projection);
    // The fixed leaf vector is one readonly observation request. Whole current
    // authority brackets its physical capture; each leaf independently checks
    // actual ancestry, nofollow incarnation, policy and absence under the same
    // retained exclusions. This does not authorize extraction or reclamation.
    #[cfg(test)]
    let refresh_started = leaf_timings.start();
    worker.refresh(&[])?;
    #[cfg(test)]
    LeafTimings::record(refresh_started, &mut leaf_timings.refresh);

    for key in keys {
        #[cfg(test)]
        let capture_started = leaf_timings.start();
        leaves.push(Leaf::capture(
            &worker,
            &recipes,
            request.root.join(key),
            request.owner,
        )?);
        #[cfg(test)]
        LeafTimings::record(capture_started, &mut leaf_timings.capture);
    }
    #[cfg(test)]
    let refresh_started = leaf_timings.start();
    worker.refresh(&[])?;
    #[cfg(test)]
    LeafTimings::record(refresh_started, &mut leaf_timings.refresh);

    for leaf in &leaves {
        #[cfg(test)]
        let check_started = leaf_timings.start();
        leaf.check(&worker.projection.exclusions)?;
        #[cfg(test)]
        LeafTimings::record(check_started, &mut leaf_timings.check);
    }
    #[cfg(test)]
    leaf_timings.report(&trace);

    if matches!(request.purpose, ObservationPurpose::Discover) {
        let mut synchronized = std::collections::BTreeSet::new();
        for leaf in &leaves {
            if leaf.is_present() {
                continue;
            }
            // A prior worker may have unlinked this name without finishing its
            // directory sync. Read-only absence cannot resolve that Planned
            // duty. Sync the actual absent anchor's retained parent, including
            // the first missing ancestor when the family directory is absent.
            worker.refresh(&[])?;
            leaf.check(&worker.projection.exclusions)?;
            let parent = leaf
                .checked_path()
                .parent()
                .and_then(|path| recipes.name(&worker.projection, path))
                .ok_or_else(|| io::Error::other("permanent sync parent is not retained"))?;
            let directory =
                super::effects::parent_from_recipe(&worker, leaf.checked_path(), parent)?;
            if synchronized.insert(directory.path.clone()) {
                worker.directory_sync(&directory, false, &[])?;
            }
            leaf.check(&worker.projection.exclusions)?;
            worker.refresh(&[])?;
        }
    }

    #[cfg(test)]
    if matches!(request.purpose, ObservationPurpose::Discover) {
        trace.mark("walk-capture-start");
    }
    let walk = if matches!(request.purpose, ObservationPurpose::Discover) {
        Some(super::walk::CandidateWalk::capture(
            &worker,
            &request.root,
            &request.cycles,
            &request.visited,
            request.owner,
        )?)
    } else {
        None
    };
    #[cfg(test)]
    if walk.is_some() {
        trace.mark("walk-capture-complete");
    }
    let extraction = match request.purpose {
        ObservationPurpose::Discover => None,
        ObservationPurpose::ExtractEligible => {
            #[cfg(test)]
            trace.mark("pair-extraction-start");
            worker.refresh(&[])?;
            let (pack, pack_metadata) = leaves
                .get_mut(0)
                .ok_or_else(|| io::Error::other("permanent pack observation missing"))?
                .read_whole(&worker.projection.exclusions)?;
            worker.refresh(&[])?;
            let (index, index_metadata) = leaves
                .get_mut(1)
                .ok_or_else(|| io::Error::other("permanent index observation missing"))?
                .read_whole(&worker.projection.exclusions)?;
            worker.refresh(&[])?;
            #[cfg(test)]
            trace.mark("pair-extraction-complete");
            Some(ExtractedPair {
                pack,
                index,
                pack_metadata,
                index_metadata,
            })
        }
    };
    if let Some(walk) = &walk {
        #[cfg(test)]
        trace.mark("walk-check-start");
        walk.check(&worker)?;
        #[cfg(test)]
        trace.mark("walk-check-complete");
    }
    #[cfg(test)]
    trace.mark("final-refresh-start");
    worker.refresh(&[])?;
    #[cfg(test)]
    trace.mark("final-refresh-complete");

    let receipt = NativePermanentObservation {
        root: request.root,
        control: request.control,
        pack: request.pack,
        operation_key: request.key,
        operation_bytes: request.bytes,
        leaves,
        exclusions: Arc::clone(&worker.projection.exclusions),
        extraction,
        walk,
    };
    let _ = request.result.send(receipt);
    #[cfg(test)]
    trace.mark("receipt-send-returned");
    Ok(())
}
