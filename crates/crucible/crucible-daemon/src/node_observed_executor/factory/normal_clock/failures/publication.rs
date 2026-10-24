//! Injects one lost storage acknowledgement around a real durable root write.

use super::*;
use crate::node_observed_executor::StoredWorldActivationPublisher;
use crucible_engine::node_contract::{
    ActivationRecord, PreparedWorldPublication, ValidatedNodePreparation,
};
use crucible_store::content_store::{
    ContentId, DirectoryBlobBackend, DirectoryRefBackend, MutableRefBackend,
    RefBackendCapabilities, RefCasOutcome, RefName, RefPublicationGuard, RefScanPage, StoreError,
};
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

pub(super) struct FaultRefs {
    pub(super) inner: Arc<DirectoryRefBackend>,
    pub(super) after: bool,
    pub(super) attempted: AtomicBool,
    pub(super) placed: AtomicBool,
}

impl MutableRefBackend for FaultRefs {
    fn capabilities(&self) -> RefBackendCapabilities {
        self.inner.capabilities()
    }
    fn acquire_publication_guard(&self) -> Result<Box<dyn RefPublicationGuard + '_>, StoreError> {
        self.inner.acquire_publication_guard()
    }
    fn read_ref(&self, name: &RefName) -> Result<Option<ContentId>, StoreError> {
        self.inner.read_ref(name)
    }
    fn scan_refs(
        &self,
        name: &RefName,
        after: Option<&RefName>,
        maximum: usize,
    ) -> Result<RefScanPage, StoreError> {
        self.inner.scan_refs(name, after, maximum)
    }
    fn compare_exchange(
        &self,
        name: &RefName,
        expected: Option<ContentId>,
        next: ContentId,
    ) -> Result<RefCasOutcome, StoreError> {
        if !name.as_str().starts_with("node-world-activations/") {
            return self.inner.compare_exchange(name, expected, next);
        }
        // A repeated write refuses; an experiment cannot retry its first root.
        if self.attempted.swap(true, Ordering::AcqRel) || !self.after {
            return Err(StoreError::Incompatible);
        }
        match self.inner.compare_exchange(name, expected, next)? {
            RefCasOutcome::Advanced { next: placed } if placed == next => {
                self.placed.store(true, Ordering::Release);
                Err(StoreError::Incompatible)
            }
            other => Ok(other),
        }
    }
}

pub(super) struct FailurePublisher {
    pub(super) stored: StoredWorldActivationPublisher,
    pub(super) first: Option<PreparedWorldPublication>,
    pub(super) returned: Option<PublicationStatus>,
    pub(super) calls: usize,
}

impl ActivationPublisher for FailurePublisher {
    fn retain_initial_coordinator(
        &mut self,
        record: &ActivationRecord,
        nodes: Vec<ValidatedNodePreparation>,
        coordinator: InputPayload,
    ) -> Result<(), RuntimeError> {
        self.stored
            .retain_initial_coordinator(record, nodes, coordinator)
    }
    fn prepare_coordinator(
        &mut self,
        record: &ActivationRecord,
        nodes: &[ValidatedNodePreparation],
    ) -> Result<InputPayload, RuntimeError> {
        self.stored.prepare_coordinator(record, nodes)
    }
    fn publish_complete(
        &mut self,
        record: &ActivationRecord,
        prepared: &PreparedWorldPublication,
    ) -> PublicationStatus {
        self.calls += 1;
        if self.first.is_some() {
            return PublicationStatus::Unknown;
        }
        // First complete bytes stay retained even if the real backend unwinds.
        self.first = Some(prepared.clone());
        let status = self.stored.publish_complete(record, prepared);
        self.returned = Some(status);
        status
    }
    fn reconcile_complete(
        &mut self,
        record: &ActivationRecord,
        prepared: &PreparedWorldPublication,
    ) -> PublicationStatus {
        if self.first.as_ref() != Some(prepared) {
            return PublicationStatus::Unknown;
        }
        self.stored.reconcile_complete(record, prepared)
    }
    fn publish(&mut self, _: &ActivationRecord) -> PublicationStatus {
        PublicationStatus::NotCommitted
    }
    fn reconcile(&mut self, _: &ActivationRecord) -> PublicationStatus {
        PublicationStatus::Unknown
    }
}

pub(super) struct PublicationFailure {
    pub(super) catalog: InstalledNodeCatalog,
    pub(super) execution: ExecutionId,
    pub(super) after: bool,
    pub(super) blobs: Arc<DirectoryBlobBackend>,
    pub(super) refs: Arc<FaultRefs>,
    pub(super) publisher: FailurePublisher,
    pub(super) original: Option<OriginalClockQualificationRun>,
    pub(super) error: Option<RuntimeError>,
    pub(super) gate: Option<RuntimePollFailure>,
    pub(super) unexpected: Option<WorldActivation>,
    pub(super) before: Option<Status>,
    pub(super) after_status: Option<Status>,
    pub(super) report: Option<InputPayload>,
    pub(super) attempted: bool,
    pub(super) complete: bool,
}

impl PublicationFailure {
    pub(super) fn new(
        catalog: &InstalledNodeCatalog,
        root: &Path,
        execution: ExecutionId,
        after: bool,
    ) -> Result<Self, NodeObservedError> {
        let name = if after {
            "publication-after-commit"
        } else {
            "publication-before-commit"
        };
        let catalog = InstalledNodeCatalog::new_with_bounded_runtime_wake(
            catalog.device_executable.clone(),
            catalog.device_identity.clone(),
            root.join(name),
            catalog.control_timeout,
            1,
        )?;
        let blobs = Arc::new(DirectoryBlobBackend::new(
            name,
            root.join(format!("{name}-blobs")),
        ));
        let refs = Arc::new(FaultRefs {
            inner: Arc::new(DirectoryRefBackend::new(root.join(format!("{name}-refs")))),
            after,
            attempted: AtomicBool::new(false),
            placed: AtomicBool::new(false),
        });
        let stored = StoredWorldActivationPublisher::new(
            blobs.clone(),
            refs.clone(),
            RefName::new(format!("node-world-activations/normal-clock-{name}"))?,
        )?;
        Ok(Self {
            catalog,
            execution,
            after,
            blobs,
            refs,
            publisher: FailurePublisher {
                stored,
                first: None,
                returned: None,
                calls: 0,
            },
            original: None,
            error: None,
            gate: None,
            unexpected: None,
            before: None,
            after_status: None,
            report: None,
            attempted: false,
            complete: false,
        })
    }

    pub(super) fn execute(
        &mut self,
        profile: &InstalledNormalClockProfile,
        source: &OriginalClockQualificationRun,
    ) -> Result<(), NodeObservedError> {
        source.current()?;
        if self.attempted {
            return Err(refused("Clock publication failure already attempted"));
        }
        self.attempted = true;
        self.original = Some(
            self.catalog
                .prepare_original_clock_qualification(profile, self.execution)?,
        );
        let run = self
            .original
            .as_mut()
            .ok_or_else(|| refused("Clock failure original absent"))?;
        run.current()?;
        run.arm_attempted = true;
        run.failed = true;
        let runtime = run
            .runtime
            .as_mut()
            .ok_or_else(|| refused("Clock failure runtime absent"))?;
        runtime.arm_all()?;
        self.before = Some(status(runtime, &run.node)?);
        let coordinator = runtime
            .initial_coordinator_snapshot(&run.graph, MAXIMUM_ACTIVATION_COORDINATOR_BYTES)?;
        self.publisher.retain_initial_coordinator(
            &run.proposal,
            runtime.prepared_node_records()?.to_vec(),
            coordinator,
        )?;
        match runtime.activate(&mut self.publisher) {
            Err(error) => self.error = Some(error),
            Ok(activation) => {
                self.unexpected = Some(activation);
                return Err(refused("faulted Clock publication unexpectedly activated"));
            }
        }
        // The genuinely committed source handle is deliberately supplied to the
        // unactivated failed runtime. NotActivated must precede foreign-scope work.
        let activation = source
            .activation
            .as_ref()
            .ok_or_else(|| refused("Clock source activation absent"))?;
        self.gate = match runtime.observe_scheduling(activation, &run.node) {
            Err(error) => Some(error),
            Ok(_) => return Err(refused("failed publication opened Clock execution gate")),
        };
        self.after_status = Some(status(runtime, &run.node)?);
        self.authenticate(source)?;
        let run = self
            .original
            .as_ref()
            .ok_or_else(|| refused("Clock failed original absent"))?;
        let first = self
            .publisher
            .first
            .as_ref()
            .ok_or_else(|| refused("Clock first complete publication absent"))?;
        self.report = Some(report(&(
            "crucible.original-clock-publication-failure/1",
            crate::node_observed_executor::factory::execution_text(self.execution),
            &crucible_engine::node_contract::SavedRuntimeActivation::from(&run.proposal),
            first.nodes(),
            first.prepared_owners(),
            first.coordinator_snapshot(),
            self.before,
            self.after_status,
            "publication-failed",
            "not-activated",
            disposition(
                self.publisher
                    .returned
                    .ok_or_else(|| refused("Clock publication disposition absent"))?,
            ),
            disposition(if self.after {
                PublicationStatus::Committed
            } else {
                PublicationStatus::NotCommitted
            }),
        ))?);
        self.complete = true;
        Ok(())
    }

    pub(super) fn authenticate(
        &mut self,
        source: &OriginalClockQualificationRun,
    ) -> Result<(), NodeObservedError> {
        source.current()?;
        let run = self
            .original
            .as_mut()
            .ok_or_else(|| refused("Clock failure original absent"))?;
        run.current()?;
        let initial = (
            Lifecycle::Prepared,
            PhysicalState::Suspended,
            Some(run.proposal.boundary),
        );
        if !self.attempted
            || !run.arm_attempted
            || !run.failed
            || run.activation.is_some()
            || run.next != 0
            || self.unexpected.is_some()
            || !matches!(self.error, Some(RuntimeError::PublicationFailed))
            || !matches!(
                self.gate,
                Some(RuntimePollFailure::Admission(RuntimeError::NotActivated))
            )
            || self.before != Some(initial)
            || self.after_status != Some(initial)
            || self.publisher.calls != 1
            || self.publisher.returned != Some(PublicationStatus::Unknown)
            || !self.refs.attempted.load(Ordering::Acquire)
            || self.refs.placed.load(Ordering::Acquire) != self.after
            || run.scenario.canonical_bytes()? != source.scenario.canonical_bytes()?
            || run.origin.source != source.origin.source
        {
            return Err(refused(
                "Clock failed publication custody or knowledge changed",
            ));
        }
        let runtime = run
            .runtime
            .as_mut()
            .ok_or_else(|| refused("Clock failed runtime lost"))?;
        if status(runtime, &run.node)? != initial {
            return Err(refused("Clock failure native state changed"));
        }
        let first = self
            .publisher
            .first
            .as_ref()
            .ok_or_else(|| refused("Clock retained first publication absent"))?;
        first
            .coordinator_snapshot()
            .reference
            .verify(&first.coordinator_snapshot().bytes)?;
        let actual = self
            .publisher
            .stored
            .reconcile_complete(&run.proposal, first);
        if actual
            != if self.after {
                PublicationStatus::Committed
            } else {
                PublicationStatus::NotCommitted
            }
        {
            return Err(refused(
                "Clock original durable publication knowledge changed",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_store::content_store::ObjectKind;

    fn refs(root: &Path, after: bool) -> FaultRefs {
        FaultRefs {
            inner: Arc::new(DirectoryRefBackend::new(root.to_owned())),
            after,
            attempted: AtomicBool::new(false),
            placed: AtomicBool::new(false),
        }
    }

    #[test]
    fn before_commit_fault_leaves_real_activation_root_absent_without_retry()
    -> Result<(), StoreError> {
        let directory = tempfile::tempdir().map_err(|_| StoreError::Incompatible)?;
        let refs = refs(directory.path(), false);
        let name = RefName::new("node-world-activations/clock-before")?;
        let original = ContentId::for_bytes(ObjectKind::Trace, 2, b"original publication");

        assert!(refs.compare_exchange(&name, None, original).is_err());
        assert!(refs.attempted.load(Ordering::Acquire));
        assert!(!refs.placed.load(Ordering::Acquire));
        assert_eq!(refs.inner.read_ref(&name)?, None);
        assert!(refs.compare_exchange(&name, None, original).is_err());
        assert_eq!(refs.inner.read_ref(&name)?, None);
        Ok(())
    }

    #[test]
    fn after_commit_fault_loses_ack_but_retains_real_first_root() -> Result<(), StoreError> {
        let directory = tempfile::tempdir().map_err(|_| StoreError::Incompatible)?;
        let refs = refs(directory.path(), true);
        let name = RefName::new("node-world-activations/clock-after")?;
        let original = ContentId::for_bytes(ObjectKind::Trace, 2, b"original publication");
        let replacement = ContentId::for_bytes(ObjectKind::Trace, 2, b"replacement");

        assert!(refs.compare_exchange(&name, None, original).is_err());
        assert!(refs.attempted.load(Ordering::Acquire));
        assert!(refs.placed.load(Ordering::Acquire));
        assert_eq!(refs.inner.read_ref(&name)?, Some(original));
        assert!(
            refs.compare_exchange(&name, Some(original), replacement)
                .is_err()
        );
        assert_eq!(refs.inner.read_ref(&name)?, Some(original));
        Ok(())
    }
}
