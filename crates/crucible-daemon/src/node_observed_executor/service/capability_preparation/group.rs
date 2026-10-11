//! Runs slow complete native actions in independently owning bounded lanes.
//!
//! Only installed configuration, original requests and durable storage handles
//! cross threads. The lane creates and retains its own non-Send catalog/runtime.
//! Terminal metadata never releases its capacity before actual native retirement.

mod execution;
mod refusals;
pub(in crate::node_observed_executor::service::capability_preparation) mod retirement_auth;
mod round_credit;
mod worker;

pub(in crate::node_observed_executor::service) use refusals::Refusal;
use refusals::Refusals;

// A turn shares this attempt ceiling between ordinary and fallback refusals.
// Synchronous backend callbacks have no latency guarantee from this counter.
const MAXIMUM_REFUSAL_ATTEMPTS_PER_TURN: usize = 8;

use super::super::{ActorStorage, NodeObservationServiceConfig};
use super::ledger::{CapabilityPreparationLedger, CapabilityReservation, SealedCompletion};
use super::{
    CapabilityPreparationAction, CapabilityPreparationRequest, CapabilityPreparationState,
    NodeObservationServiceError, refused,
};
use crate::node_observed_executor::{InstalledIoArtifact, InstalledNodeCatalog};
use crucible_cas::content_store::{ImmutableBlobBackend, MutableRefBackend};
use crucible_node_contract::ContentRef;
use std::{
    collections::{BTreeMap, VecDeque},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

#[derive(Clone)]
pub(in crate::node_observed_executor::service) struct Installation {
    companion: PathBuf,
    expected: ContentRef,
    parent: PathBuf,
    timeout: Duration,
    maximum_worlds: usize,
    artifacts: Vec<InstalledIoArtifact>,
}

impl Installation {
    pub(in crate::node_observed_executor::service) fn from_configuration(
        configuration: &NodeObservationServiceConfig,
    ) -> Self {
        Self {
            companion: configuration.device_executable.clone(),
            expected: configuration.expected_device.clone(),
            parent: configuration.socket_parent.clone(),
            timeout: configuration.control_timeout,
            maximum_worlds: configuration.maximum_worlds,
            artifacts: configuration.installed_artifacts.clone(),
        }
    }

    fn catalog(&self) -> Result<InstalledNodeCatalog, NodeObservationServiceError> {
        let mut catalog = InstalledNodeCatalog::new(
            self.companion.clone(),
            self.expected.clone(),
            self.parent.clone(),
            self.timeout,
            self.maximum_worlds,
        )
        .map_err(refused)?;
        catalog
            .install_artifacts(self.artifacts.clone())
            .map_err(refused)?;
        Ok(catalog)
    }
}

struct Submission {
    request: CapabilityPreparationRequest,
    reservation: CapabilityReservation,
    ledger: CapabilityPreparationLedger,
    archive: PathBuf,
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
}

struct Lane {
    retired: Arc<AtomicBool>,
    pending: Arc<Mutex<Option<Submission>>>,
    spawn_failed: bool,
    sealed_failure: Option<SealedCompletion>,
}

pub(in crate::node_observed_executor::service) struct Lanes {
    owners: BTreeMap<String, Lane>,
    refusals: Refusals,
    poll_fallback_next: bool,
}

impl Lanes {
    pub(in crate::node_observed_executor::service) fn new() -> Self {
        Self {
            owners: BTreeMap::new(),
            refusals: Refusals::new(),
            poll_fallback_next: false,
        }
    }

    pub(in crate::node_observed_executor::service) fn len(&self) -> usize {
        self.owners.len()
    }

    pub(in crate::node_observed_executor::service) fn is_empty(&self) -> bool {
        self.owners.is_empty() && self.refusals.len() == 0
    }

    pub(in crate::node_observed_executor::service) fn selects(
        request: &CapabilityPreparationRequest,
    ) -> bool {
        !matches!(request.action, CapabilityPreparationAction::Observe {})
            && request.candidates.iter().any(|candidate| candidate.selections.iter()
                .any(|selection| matches!(selection.kind, crate::node_observed_executor::InstalledNodeKind::Gem5ClosedPreserving { .. })))
    }

    pub(in crate::node_observed_executor::service) fn start(
        &mut self,
        request: CapabilityPreparationRequest,
        reservation: CapabilityReservation,
        ledger: CapabilityPreparationLedger,
        storage: &ActorStorage,
        stopping: Arc<AtomicBool>,
    ) -> Option<Refusal> {
        if stopping.load(Ordering::Acquire) {
            // Reservation already owns the exact durable request. No catalog,
            // native slot, or thread is created for this data-only refusal.
            return self.refuse(reservation, ledger);
        }

        let execution = request.execution.clone();
        let retired = Arc::new(AtomicBool::new(false));
        let pending = Arc::new(Mutex::new(Some(Submission {
            request,
            reservation,
            ledger,
            archive: storage.capability_archive.clone(),
            blobs: storage.blobs.clone(),
            refs: storage.refs.clone(),
        })));
        let installation = storage.capability_installation.clone();
        // Publish the finite owning slot before spawning. A spawn refusal keeps
        // the complete original reservation for same-byte durable reconciliation.
        self.owners.insert(
            execution.clone(),
            Lane {
                retired: retired.clone(),
                pending: pending.clone(),
                spawn_failed: false,
                sealed_failure: None,
            },
        );
        let result = thread::Builder::new()
            .name(format!("crucible-capability-{execution}"))
            .spawn(move || run(pending, retired, installation, stopping));
        if result.is_err()
            && let Some(owner) = self.owners.get_mut(&execution)
        {
            owner.spawn_failed = true;
        }
        None
    }

    fn refuse(
        &mut self,
        reservation: CapabilityReservation,
        ledger: CapabilityPreparationLedger,
    ) -> Option<Refusal> {
        let mut original = Some(Refusal::new(reservation, ledger));
        self.refusals.retain_original(&mut original);
        original
    }

    fn poll_fallback(&mut self, originals: &mut VecDeque<Refusal>) -> bool {
        let Some(original) = originals.front_mut() else {
            return false;
        };
        if original.poll() {
            originals.pop_front();
        } else {
            // Keep the same failed original and allocation, moving it behind
            // the unvisited originals. Success never swaps a visited row back.
            originals.rotate_left(1);
        }
        true
    }

    fn poll_refusals(&mut self, originals: &mut VecDeque<Refusal>) {
        let mut map_remaining = self.refusals.len();
        let mut fallback_remaining = originals.len();
        for _ in 0..MAXIMUM_REFUSAL_ATTEMPTS_PER_TURN {
            let use_fallback =
                fallback_remaining != 0 && (self.poll_fallback_next || map_remaining == 0);
            let attempted = if use_fallback {
                fallback_remaining -= 1;
                self.poll_fallback(originals)
            } else if map_remaining != 0 {
                map_remaining -= 1;
                self.refusals.poll()
            } else {
                false
            };
            self.poll_fallback_next = !self.poll_fallback_next;
            if !attempted {
                break;
            }
        }
    }

    pub(in crate::node_observed_executor::service) fn poll(
        &mut self,
        held_refusals: &mut VecDeque<Refusal>,
    ) {
        self.poll_refusals(held_refusals);
        for owner in self.owners.values_mut() {
            if !owner.spawn_failed {
                continue;
            }
            let Ok(pending) = owner.pending.try_lock() else {
                continue;
            };
            let Some(submission) = pending.as_ref() else {
                continue;
            };
            if owner.sealed_failure.is_none() {
                owner.sealed_failure = submission
                    .ledger
                    .seal_completion(
                        &submission.reservation,
                        CapabilityPreparationState::Unavailable {
                            reason: "owning native lane could not start".into(),
                        },
                    )
                    .ok();
            }
            if let Some(sealed) = &owner.sealed_failure
                && submission
                    .ledger
                    .place_completion(&submission.reservation, sealed)
                    .is_ok()
            {
                owner.retired.store(true, Ordering::Release);
            }
        }
        self.owners
            .retain(|_, owner| !owner.retired.load(Ordering::Acquire));
    }
}

fn run(
    pending: Arc<Mutex<Option<Submission>>>,
    retired: Arc<AtomicBool>,
    installation: Installation,
    stopping: Arc<AtomicBool>,
) {
    let mut submission = match pending.lock() {
        Ok(mut pending) => pending.take(),
        Err(_) => return,
    };
    let mut worker = None;
    let initialized = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if stopping.load(Ordering::Acquire) {
            return Err(NodeObservationServiceError::Unavailable);
        }
        let catalog = installation.catalog()?;
        worker = Some(worker::Worker::new(&mut submission, catalog)?);
        Ok::<(), NodeObservationServiceError>(())
    }));
    let error = match initialized {
        Ok(Ok(())) => {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                worker
                    .as_mut()
                    .ok_or_else(|| refused("owning complete worker absent"))?
                    .execute_once()
            }));
            match result {
                Ok(Ok(())) => None,
                Ok(Err(error)) => Some(error.to_string()),
                Err(_) => {
                    Some("original complete native action unwound; custody remains held".into())
                }
            }
        }
        Ok(Err(error)) => Some(error.to_string()),
        Err(_) => Some("original inactive lane preparation unwound".into()),
    };
    if let (Some(worker), Some(reason)) = (&mut worker, &error) {
        worker.fail(reason.clone());
    }
    let mut sealed_failure = None;
    loop {
        // Keep every owning wrapper outside callback unwind scopes. No retry in
        // this loop invokes preparation, dispatch, capture or original suffix.
        let released = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if let Some(worker) = &mut worker {
                return worker.reconcile();
            }
            let submission = submission
                .as_ref()
                .ok_or_else(|| refused("original lane reservation absent"))?;
            if sealed_failure.is_none() {
                sealed_failure = Some(
                    submission.ledger.seal_completion(
                        &submission.reservation,
                        CapabilityPreparationState::Unavailable {
                            reason: error
                                .as_deref()
                                .unwrap_or("inactive preparation failed")
                                .chars()
                                .take(512)
                                .collect(),
                        },
                    )?,
                );
            }
            submission.ledger.place_completion(
                &submission.reservation,
                sealed_failure
                    .as_ref()
                    .ok_or_else(|| refused("original refusal seal absent"))?,
            )?;
            Ok(true)
        }));
        if matches!(released, Ok(Ok(true))) {
            retired.store(true, Ordering::Release);
            return;
        }
        if let Some(deadline) =
            crate::supervision::ProcessDeadline::after(Duration::from_millis(10))
        {
            deadline.pause(Duration::from_millis(10));
        } else {
            thread::yield_now();
        }
    }
}
