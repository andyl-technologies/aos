//! Runs the private installed candidate through actual common-runtime windows.
//!
//! The owning thread keeps both custody queues outside callback unwind scopes.
//! A run result is observational evidence; it does not accept the full normative
//! population or supply an ordinary factory qualification token.

#[path = "harness_failure.rs"]
mod failure;

use crucible::{
    node_contract::{
        ActivationPublisher, ActivationRecord, NodeRuntime, PreparedWorldPublication,
        PublicationStatus, RuntimeCustodyQueue, RuntimeCustodySupervisor, RuntimeError,
        RuntimeLimits, SimulationNode, ValidatedNodePreparation,
    },
    node_scheduling::InputPayload,
};
use crucible_cas::content_store::{
    BlobHandle, ContentId, DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend,
    MutableRefBackend, ObjectKind, RefName,
};
use crucible_node_contract::*;
use crucible_node_provider::{
    ProviderError,
    client::{ObservationHandle, ObservationLimits},
    reference_device::DeviceGrant,
};
use std::{
    cell::RefCell,
    path::PathBuf,
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering},
    sync::{Arc, mpsc},
    task::{Context, Poll, Waker},
    time::Duration,
};

static QUALIFICATION_ACTOR_RESERVED: AtomicBool = AtomicBool::new(false);

struct QualificationActorLease;

impl Drop for QualificationActorLease {
    fn drop(&mut self) {
        QUALIFICATION_ACTOR_RESERVED.store(false, Ordering::Release);
    }
}

use super::{
    candidate::{PrivateCandidate, entropy},
    criteria::ReferenceQualificationCriteria,
    custody::PublicReferenceCustodyQueue,
    launch::{ObservedPublicPreparation, PublicLaunchRequest, launch},
    package::InstalledPublicReferencePackage,
    unit::SemanticQualificationUnit,
    witness::{OriginalPublicWindowWitness, collect_original_windows},
};
use crate::node_observed_executor::activation::StoredWorldActivationPublisher;
use crate::node_qualification::{
    ReferenceExpectedWindow, ReferenceOracleContract, ReferenceWindowObservation,
};
use crate::node_qualification::{ReferenceWindowCase, collect_reference_window};

/// Retains the durable original result after authentic native reclamation.
pub(super) struct CandidateHarnessResult {
    original_result: ContentId,
    retirement_result: ContentId,
    succeeded: bool,
    original_bytes: Vec<u8>,
    retirement_bytes: Vec<u8>,
    unit: Option<SemanticQualificationUnit>,
    criteria: Option<ReferenceQualificationCriteria>,
    population_result: Option<ContentId>,
    source_reviews: Option<super::source_metadata_reviews::SourceMetadataReviews>,
}

impl CandidateHarnessResult {
    pub(super) fn original_result(&self) -> ContentId {
        self.original_result
    }

    pub(super) fn retirement_result(&self) -> ContentId {
        self.retirement_result
    }

    pub(super) fn population_result(&self) -> Option<ContentId> {
        self.population_result
    }

    pub(super) fn source_reviews(
        &self,
    ) -> Option<&super::source_metadata_reviews::SourceMetadataReviews> {
        self.source_reviews.as_ref()
    }

    #[cfg(test)]
    pub(super) fn take_source_reviews_for_test(
        &mut self,
    ) -> Option<super::source_metadata_reviews::SourceMetadataReviews> {
        self.source_reviews.take()
    }

    #[cfg(test)]
    pub(super) fn replace_source_reviews_for_test(
        &mut self,
        review: super::source_metadata_reviews::SourceMetadataReviews,
    ) {
        self.source_reviews = Some(review);
    }

    pub(super) fn succeeded(&self) -> bool {
        self.succeeded
    }

    pub(super) fn original_bytes(&self) -> &[u8] {
        &self.original_bytes
    }

    pub(super) fn retirement_bytes(&self) -> &[u8] {
        &self.retirement_bytes
    }

    /// Borrows the source-measured plan installed before the first native child.
    pub(super) fn qualification_context(
        &self,
    ) -> Option<(&SemanticQualificationUnit, &ReferenceQualificationCriteria)> {
        Some((self.unit.as_ref()?, self.criteria.as_ref()?))
    }
}

/// Starts a source-owned actor; dropping the receiver cannot drop native custody.
pub(super) fn start(
    directory: PathBuf,
) -> Result<
    mpsc::Receiver<Result<CandidateHarnessResult, super::run_error::QualificationRunError>>,
    std::io::Error,
> {
    QUALIFICATION_ACTOR_RESERVED
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "installed qualification actor already reserved",
            )
        })?;
    let lease = QualificationActorLease;
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("reference-qualification".into())
        .spawn(move || {
            let _lease = lease;
            let result = run_actor(directory, || {
                let _ = sender.send(Err(super::run_error::QualificationRunError::Refused(
                    "original qualification issuance unavailable; custody retained",
                )));
            })
            .map_err(super::run_error::QualificationRunError::from);
            let _ = sender.send(result);
        })?;
    Ok(receiver)
}

struct Actor {
    private: PathBuf,
    blobs: Arc<DirectoryBlobBackend>,
    refs: Arc<DirectoryRefBackend>,
    peers: PublicReferenceCustodyQueue,
    worlds: RuntimeCustodyQueue,
    runtime: Option<NodeRuntime>,
    candidate: Option<PrivateCandidate>,
    observers: Vec<Rc<RefCell<Option<ObservationHandle>>>>,
    transmission_observers:
        Vec<Rc<RefCell<Option<crucible_node_provider::client::TransmissionObservationHandle>>>>,
    windows: Vec<Vec<ReferenceWindowObservation>>,
    runtime_retries: Vec<Vec<super::runtime_retries::RuntimeCachedRecovery>>,
    probes: Vec<serde_json::Value>,
    prepared_probes: Vec<serde_json::Value>,
    resends: Vec<serde_json::Value>,
    conflict_observers:
        Vec<Rc<RefCell<Option<crucible_node_provider::client::OriginalConflictObservationHandle>>>>,
    conflict_policies:
        Vec<Rc<super::source_original_conflict_policy::SourceOriginalConflictPolicy>>,
    lifecycle_policies: Vec<Rc<super::source_lifecycle_resend_policy::SourceLifecycleResendPolicy>>,
    lifecycle_native_origins: Vec<Rc<RefCell<Option<super::native::NativePublicEnrollment>>>>,
    phase: &'static str,
    planned: Vec<Vec<ReferenceWindowCase>>,
    oracles: Vec<ReferenceOracleContract>,
    unit: Option<SemanticQualificationUnit>,
    criteria: Option<ReferenceQualificationCriteria>,
}

fn run_actor(
    directory: PathBuf,
    unavailable: impl FnOnce(),
) -> Result<CandidateHarnessResult, ProviderError> {
    use std::os::unix::fs::DirBuilderExt;
    if !directory.is_absolute() {
        return Err(ProviderError::Frame(
            "qualification directory must be absolute",
        ));
    }
    std::fs::DirBuilder::new().mode(0o700).create(&directory)?;
    let mut actor = Actor {
        blobs: Arc::new(DirectoryBlobBackend::new(
            "installed-reference-qualification",
            directory.join("blobs"),
        )),
        refs: Arc::new(DirectoryRefBackend::new(directory.join("refs"))),
        private: directory.join("native"),
        peers: PublicReferenceCustodyQueue::new(2)?,
        worlds: RuntimeCustodyQueue::new(1).map_err(failure)?,
        runtime: None,
        candidate: None,
        observers: (0..2).map(|_| Rc::new(RefCell::new(None))).collect(),
        transmission_observers: (0..2).map(|_| Rc::new(RefCell::new(None))).collect(),
        windows: (0..2).map(|_| Vec::with_capacity(3)).collect(),
        runtime_retries: (0..2).map(|_| Vec::with_capacity(3)).collect(),
        probes: Vec::with_capacity(2),
        prepared_probes: Vec::with_capacity(2),
        resends: Vec::with_capacity(2),
        conflict_observers: (0..2).map(|_| Rc::new(RefCell::new(None))).collect(),
        conflict_policies: Vec::with_capacity(2),
        lifecycle_policies: Vec::with_capacity(2),
        lifecycle_native_origins: (0..2).map(|_| Rc::new(RefCell::new(None))).collect(),
        phase: "source-enrollment",
        planned: Vec::with_capacity(2),
        oracles: Vec::with_capacity(2),
        unit: None,
        criteria: None,
    };
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&actor.private)?;
    let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| actor.execute()));
    let result = match attempt {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err("original native callback unwound".into()),
    };
    let succeeded = result.is_ok();
    let source_roots = actor.peers.source_roots();
    // Encoding and storage do not discharge native custody. Reclaim originals
    // first, retaining the result value even if its encoding has not succeeded.
    drop(actor.runtime.take());
    let mut context = Context::from_waker(Waker::noop());
    let mut original_peers = Vec::with_capacity(2);
    loop {
        let world = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            actor.worlds.poll_reclamation(&mut context)
        }));
        let native = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            actor.peers.poll_reclamation()
        }));
        if matches!(world, Ok(Poll::Ready(Ok(())))) || actor.worlds.reserved_worlds() == 0 {
            while let Some(peer) = actor.peers.take_reclaimed() {
                original_peers.push(peer);
            }
        }
        if actor.worlds.reserved_worlds() == 0 && actor.peers.outstanding() == 0 {
            break;
        }
        // Disconnected receivers and repeated native callback errors cannot turn
        // owning supervision into a busy loop or destroy the original objects.
        let _ = native;
        std::thread::sleep(Duration::from_millis(10));
    }
    // Seal original observations once. Placement may lose its acknowledgement,
    // but that cannot authorize a fresh snapshot or replace an original failure.
    let sealed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let failed_original;
        let original = match &result {
            Ok(original) => original,
            Err(error) => {
                failed_original = actor.failed_original(error);
                &failed_original
            }
        };
        let original_bytes = canonical::canonical_json(original)?;
        let original_result = ContentId::for_bytes(ObjectKind::Trace, 1, &original_bytes);
        let retirement_bytes = canonical::canonical_json(&serde_json::json!({
            "schema":"crucible.reference.candidate-retirement.v1", "original_result":original_result.encode(),
            "reclaimed_original_peers": original_peers.len(), "world_reservations":actor.worlds.reserved_worlds(),
            "original_source_roots":source_roots,
            "original_scopes":original_peers.iter().map(|peer| serde_json::json!({
                "activation":crucible::node_contract::SavedRuntimeActivation::from(&peer.scope.activation),
                "owner":peer.scope.owner,"implementation":peer.scope.implementation,
                "original_provider_pid":peer.custody.provider_pid(),
                "publication":publication_name(peer.scope.publication),
                "original_private_launch_bytes":peer.scope.private_launch.len(),
                "original_private_hello_bytes":peer.scope.original_hello.len(),
            })).collect::<Vec<_>>()
        }))?;
        let retirement_result = ContentId::for_bytes(ObjectKind::Trace, 1, &retirement_bytes);
        Ok::<_, ProviderError>((
            original_result,
            original_bytes,
            retirement_result,
            retirement_bytes,
        ))
    }));
    let (original_result, original_bytes, retirement_result, retirement_bytes) = match sealed {
        Ok(Ok(sealed)) => sealed,
        // Notification contains no native permission. The parked actor keeps
        // every original journal, peer and context; encoding is never retried.
        Ok(Err(_)) | Err(_) => {
            unavailable();
            loop {
                std::thread::park_timeout(Duration::from_secs(1));
            }
        }
    };
    loop {
        let stored = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let stored_original = actor.persist(&original_bytes, "qualification/original")?;
            let stored_retirement = actor.persist(&retirement_bytes, "qualification/retirement")?;
            if stored_original != original_result || stored_retirement != retirement_result {
                return Err(ProviderError::Correlation(
                    "original placement identity changed",
                ));
            }
            Ok::<_, ProviderError>(())
        }));
        if matches!(stored, Ok(Ok(()))) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let mut original = CandidateHarnessResult {
        original_result,
        retirement_result,
        succeeded,
        original_bytes,
        retirement_bytes,
        unit: actor.unit.take(),
        criteria: actor.criteria.take(),
        population_result: None,
        source_reviews: None,
    };
    if original.qualification_context().is_some() {
        // The plan was retained before first Child. Keep original native
        // journals alive until the full population, including missing cases,
        // is durable; dropping a caller cannot discard failed original rows.
        // Preparation runs once while the owning actor retains all native
        // journals. Neither errors nor unwinds may re-enter inspection.
        let prepared = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || -> Result<_, ProviderError> {
                let predecessor = super::issuer::issue_native_report(&original).map_err(failure)?;
                original.source_reviews = Some(
                    super::source_metadata_reviews::SourceMetadataReviews::collect_once(
                        &original,
                        &predecessor,
                    )
                    .map_err(failure)?,
                );
                let attempted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    super::issuer::issue_report(&original)
                }));
                let issued = match attempted {
                    Ok(Ok(issued)) => issued,
                    Ok(Err(error)) => {
                        // A later authentication refusal is still the original failed
                        // attempt. It must not cause a second successful measurement.
                        original.source_reviews = Some(
                            super::source_metadata_reviews::SourceMetadataReviews::failed(
                                &original,
                                &predecessor,
                                &error.to_string(),
                                false,
                                original.source_reviews(),
                            )
                            .map_err(failure)?,
                        );
                        super::issuer::issue_report(&original).map_err(failure)?
                    }
                    Err(_) => {
                        original.source_reviews = Some(
                            super::source_metadata_reviews::SourceMetadataReviews::failed(
                                &original,
                                &predecessor,
                                "original source review authentication unwound; outcome unknown",
                                true,
                                original.source_reviews(),
                            )
                            .map_err(failure)?,
                        );
                        super::issuer::issue_report(&original).map_err(failure)?
                    }
                };
                Ok((predecessor, issued))
            },
        ));
        let prepared = match prepared {
            Ok(result) => result.map_err(|error| error.to_string()),
            Err(_) => Err("original qualification issuance unwound; outcome unknown".to_owned()),
        };
        let (predecessor, issued) = match prepared {
            Ok(prepared) => prepared,
            Err(diagnostic) => {
                // Keep this stack's original_peers, original context and raw
                // outcome alive. Only a fixed diagnostic storage write retries;
                // the unavailable population cannot become a later Pass.
                let diagnostic = if diagnostic.len() <= 4096 {
                    diagnostic
                } else {
                    "original qualification issuance failed; diagnostic ceiling".to_owned()
                };
                let diagnostic_record = serde_json::json!({
                    "schema":"crucible.reference.original-issuance-unavailable.v1",
                    "original_result":original.original_result().encode(),
                    "retirement_result":original.retirement_result().encode(),
                    "unknown":true,"diagnostic":diagnostic,
                    "custody":"original actor/journals/context remain retained; no inspection retry",
                });
                let bytes = match canonical::canonical_json(&diagnostic_record) {
                    Ok(bytes) => bytes,
                    Err(_) => br#"{"schema":"crucible.reference.original-issuance-unavailable.v1","unknown":true}"#.to_vec(),
                };
                // Notify the caller without returning or releasing custody.
                // Diagnostic I/O may remain unavailable; that does not permit
                // a replacement attempt or change Unknown into cessation.
                unavailable();
                loop {
                    let _stored = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        actor.persist(&bytes, "qualification/issuance-unavailable")
                    }));
                    std::thread::park_timeout(Duration::from_secs(1));
                }
            }
        };
        loop {
            let stored = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                actor.persist(
                    predecessor.bytes(),
                    "qualification/native-predecessor-report",
                )?;
                actor.persist_population(&original, &issued)
            }));
            if let Ok(Ok(reference)) = stored {
                original.population_result = Some(reference);
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    // Complete private native journals remain owned until every original root
    // and the full declared population are durable. Secrets are never emitted.
    drop(original_peers);
    Ok(original)
}

fn publication_name(status: Option<PublicationStatus>) -> &'static str {
    match status {
        None => "not_attempted",
        Some(PublicationStatus::NotCommitted) => "not_committed",
        Some(PublicationStatus::Committed) => "committed",
        Some(PublicationStatus::Unknown) => "unknown",
    }
}

impl Actor {
    fn persist_population(
        &self,
        original: &CandidateHarnessResult,
        issued: &crate::node_qualification::IssuedQualification,
    ) -> Result<ContentId, ProviderError> {
        let (unit, criteria) = original
            .qualification_context()
            .ok_or(ProviderError::Frame(
                "original predeclared source context absent",
            ))?;
        let mut objects = std::collections::BTreeMap::new();
        for (reference, bytes) in unit.objects.iter().chain(criteria.objects.iter()) {
            reference.verify(bytes)?;
            if objects
                .insert(reference.clone(), bytes.as_slice())
                .is_some_and(|first| first != bytes)
            {
                return Err(ProviderError::Correlation("source evidence object changed"));
            }
        }
        if let Some(reviews) = original.source_reviews() {
            for (reference, bytes) in reviews.objects() {
                reference.verify(bytes)?;
                if objects
                    .insert(reference.clone(), bytes)
                    .is_some_and(|prior| prior != bytes)
                {
                    return Err(ProviderError::Correlation(
                        "source review evidence object changed",
                    ));
                }
            }
        }
        for (reference, bytes) in issued.objects() {
            reference.verify(bytes.as_slice())?;
            if objects
                .insert(reference.clone(), bytes.as_slice())
                .is_some_and(|first| first != bytes.as_slice())
            {
                return Err(ProviderError::Correlation(
                    "issued original evidence object changed",
                ));
            }
        }
        let mut roots = Vec::with_capacity(objects.len());
        for (index, (reference, bytes)) in objects.into_iter().enumerate() {
            let object =
                self.persist(bytes, &format!("qualification/population/object/{index}"))?;
            roots.push(serde_json::json!({"reference":reference,"object":object.encode()}));
        }
        let report = self.persist(issued.bytes(), "qualification/population/report")?;
        let original_inspections = original
            .source_reviews()
            .ok_or(ProviderError::Frame(
                "original source review attempt absent",
            ))?
            .inspection_bytes()
            .map_err(failure)?;
        let (inspection_root, artifact_root) = match original_inspections {
            Some(bytes) => (
                Some(self.persist(&bytes.metadata, "qualification/metadata-inspection")?),
                Some(self.persist(&bytes.artifacts, "qualification/artifact-integrity")?),
            ),
            None => (None, None),
        };
        let envelope = canonical::canonical_json(&serde_json::json!({
            "schema":"crucible.reference.original-population-roots.v1",
            "report":issued.reference(),"report_object":report.encode(),
            "metadata_inspection":inspection_root.map(|root|root.encode()),
            "artifact_integrity":artifact_root.map(|root|root.encode()),
            "original_result":original.original_result().encode(),
            "retirement_result":original.retirement_result().encode(),
            "objects":roots,"qualification_accepted":false
        }))?;
        // The manifest is a sibling of the object/report directory. Directory
        // references cannot simultaneously use one name as a file and parent.
        self.persist(&envelope, "qualification/population-manifest")
    }

    /// Retains the original failed or incomplete population without retry labels.
    fn persist(&self, bytes: &[u8], name: &str) -> Result<ContentId, ProviderError> {
        let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
        let _guard = self.refs.acquire_publication_guard().map_err(failure)?;
        let receipt = self
            .blobs
            .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))
            .map_err(failure)?;
        if !receipt.is_durable() {
            return Err(ProviderError::Frame("candidate evidence not durable"));
        }
        let reference = RefName::new(name).map_err(failure)?;
        match self
            .refs
            .compare_exchange(&reference, None, id)
            .map_err(failure)?
        {
            crucible_cas::content_store::RefCasOutcome::Advanced { next } if next == id => Ok(id),
            crucible_cas::content_store::RefCasOutcome::Conflict {
                current: Some(current),
                ..
            } if current == id => Ok(id),
            _ => Err(ProviderError::Correlation(
                "original candidate result slot differs",
            )),
        }
    }

    fn execute(&mut self) -> Result<serde_json::Value, ProviderError> {
        let package = InstalledPublicReferencePackage::built_in().map_err(failure)?;
        self.candidate = Some(PrivateCandidate::new(
            Rc::clone(&package),
            U64::new(1000),
            U64::new(1_000_000_000),
        )?);
        let candidate = self
            .candidate
            .as_mut()
            .ok_or(ProviderError::Frame("original candidate metadata absent"))?;
        self.phase = "predeclared-fixture";
        for installed in &candidate.installations {
            let cases = (0..3)
                .map(|quantum| window_case(installed, quantum))
                .collect::<Result<Vec<_>, _>>()?;
            self.oracles.push(oracle_contract(installed, &cases)?);
            self.planned.push(cases);
        }
        self.phase = "predeclared-qualification-unit";
        let unit = super::context::measure(candidate, &self.oracles)?;
        let criteria =
            ReferenceQualificationCriteria::build(unit.identity.clone()).map_err(failure)?;
        self.unit = Some(unit);
        self.criteria = Some(criteria);
        let lifecycle_world = Rc::new(super::source_lifecycle_world::SourceLifecycleWorld::new(
            candidate.activation.clone(),
        ));
        let bindings = candidate
            .installations
            .iter()
            .map(|installed| {
                installed.profile.bind_qualified(
                    installed.bootstrap.authority.clone(),
                    &installed.qualifications,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let grants = self
            .planned
            .iter()
            .flatten()
            .map(|case| case.grant.clone())
            .collect::<Vec<_>>();
        for (installed, cases) in candidate.installations.iter().zip(&self.planned) {
            self.lifecycle_policies.push(Rc::new(
                super::source_lifecycle_resend_policy::SourceLifecycleResendPolicy::new(
                    installed,
                    super::source_lifecycle_resend_plan::SourceLifecycleResendPlan::build(
                        installed,
                        &candidate.activation,
                        cases,
                    )?,
                    bindings.clone(),
                    grants.clone(),
                    Rc::clone(&lifecycle_world),
                    self.observers.clone(),
                    self.lifecycle_native_origins.clone(),
                )?,
            ));
        }
        for (index, (installed, cases)) in candidate
            .installations
            .iter()
            .zip(&self.planned)
            .enumerate()
        {
            let lifecycle = super::source_lifecycle_resend_plan::SourceLifecycleResendPlan::build(
                installed,
                &candidate.activation,
                cases,
            )?;
            let plan = super::source_original_conflict_plan::SourceOriginalConflictPlan::build(
                installed, &lifecycle,
            )?;
            self.conflict_policies.push(Rc::new(
                super::source_original_conflict_policy::SourceOriginalConflictPolicy::new(
                    plan,
                    installed.bootstrap.owner_id.clone(),
                    Rc::clone(&self.lifecycle_policies[index]),
                )?,
            ));
        }
        self.phase = "native-preparation";
        let slot = self
            .worlds
            .reserve_world(&candidate.activation, RuntimeLimits::default())
            .map_err(failure)?;
        let mut prepared = Vec::with_capacity(2);
        for (index, installed) in candidate.installations.iter_mut().enumerate() {
            prepared.push(launch(
                installed,
                &self.peers,
                PublicLaunchRequest {
                    directory: self.private.join(installed.profile.descriptor.id.as_str()),
                    activation: candidate.activation.clone(),
                    owner: candidate.activation.owners[index].clone(),
                    source_roots: vec![
                        package.identity().clone(),
                        candidate.definition.qualification().clone(),
                    ],
                    closed_ingress: index == 1,
                    hello_id: Id::new(format!("hello/{index}"))?,
                    connection_id: Id::new(format!("connection/{index}"))?,
                    controller_nonce: entropy()?,
                    observation_sink: Rc::clone(&self.observers[index]),
                    transmission_sink: Rc::clone(&self.transmission_observers[index]),
                    lifecycle_policy: Rc::clone(&self.lifecycle_policies[index]),
                    conflict_policy: Rc::clone(&self.conflict_policies[index]),
                    conflict_sink: Rc::clone(&self.conflict_observers[index]),
                    observation_limits: ObservationLimits {
                        maximum_requests: 1024,
                        maximum_objects: 1024,
                        maximum_bytes: 8 * 1024 * 1024,
                    },
                },
            )?);
        }
        self.phase = "complete-graph-admission";
        let graph = candidate.definition.admit_candidate(
            &candidate.installations,
            &prepared
                .iter()
                .map(|node| &node.prepared)
                .collect::<Vec<_>>(),
        )?;
        let mut observations = Vec::with_capacity(2);
        let mut nodes: Vec<Box<dyn SimulationNode>> = Vec::with_capacity(2);
        for (original, installed) in prepared.into_iter().zip(&candidate.installations) {
            let ObservedPublicPreparation {
                prepared,
                observations: observer,
                probe,
                prepared_probe,
                resends,
            } = original;
            self.probes.push(probe);
            self.prepared_probes.push(prepared_probe);
            self.resends.push(resends);
            observations.push(observer);
            nodes.push(Box::new(
                prepared
                    .into_node(&graph, &installed.profile.descriptor.id, installed, 8)
                    .map_err(|error| failure(error.reason))?,
            ));
        }
        self.runtime = Some(
            NodeRuntime::new(
                &graph,
                nodes,
                candidate.activation.clone(),
                RuntimeLimits::default(),
                slot,
            )
            .map_err(|error| failure(&error.error))?,
        );
        let runtime = self
            .runtime
            .as_mut()
            .ok_or(ProviderError::Frame("original candidate runtime absent"))?;
        self.phase = "actual-readiness";
        runtime.arm_all().map_err(failure)?;
        let coordinator = runtime
            .initial_coordinator_snapshot(&graph, 1024 * 1024)
            .map_err(failure)?;
        let stored = StoredWorldActivationPublisher::new(
            self.blobs.clone(),
            self.refs.clone(),
            RefName::new("node-world-activations/candidate").map_err(failure)?,
        )
        .map_err(failure)?
        .with_prepared_coordinator(
            candidate.activation.clone(),
            runtime.prepared_node_records().map_err(failure)?.to_vec(),
            coordinator.clone(),
        )
        .map_err(failure)?;
        let mut publisher = Publisher {
            stored,
            peers: self.peers.clone(),
            original: None,
            lifecycle_world: Rc::clone(&lifecycle_world),
        };
        self.phase = "complete-world-publication";
        let activation = runtime.activate(&mut publisher).map_err(failure)?;
        runtime.scheduler(&graph, &activation).map_err(failure)?;
        for node in graph.node_ids() {
            let observation = runtime
                .observe_scheduling(&activation, node)
                .map_err(failure)?;
            runtime
                .scheduler(&graph, &activation)
                .map_err(failure)?
                .accept_boundary_observation(observation)
                .map_err(failure)?;
        }
        self.phase = "original-native-windows";
        let mut context = Context::from_waker(Waker::noop());
        for (index, quantum) in [(1usize, 0usize), (0, 0), (0, 1), (1, 1), (0, 2), (1, 2)] {
            // The single connection credit remains in original custody until
            // consumer input ACK. Consume the pending prefix before granting
            // another producer window; no horizon or capacity is widened.
            let case = &self.planned[index][quantum];
            self.windows[index].push(
                collect_reference_window(runtime, &graph, &activation, case, &mut context)
                    .map_err(failure)?,
            );
            self.phase = "original-runtime-cached-recovery";
            let window = self.windows[index].last().ok_or(ProviderError::Frame(
                "original window unavailable for recovery",
            ))?;
            self.runtime_retries[index].push(super::runtime_retries::collect(
                runtime,
                &graph,
                &activation,
                case,
                window,
                &mut context,
            )?);
            self.phase = "original-native-windows";
        }
        self.phase = "independent-window-oracle";
        let mut witnesses = Vec::<OriginalPublicWindowWitness>::with_capacity(2);
        for (index, installed) in candidate.installations.iter().enumerate() {
            let contract = &self.oracles[index];
            witnesses.push(collect_original_windows(
                installed,
                &observations[index],
                contract,
                &activation,
                &self.windows[index],
            )?);
        }
        let mut lifecycle_resends = Vec::with_capacity(2);
        for (index, installed) in candidate.installations.iter().enumerate() {
            let safe = super::source_resend_plan::SourceResendPlan::build(installed)?;
            let transmissions = self.transmission_observers[index].borrow();
            let transmissions = transmissions.as_ref().ok_or(ProviderError::Correlation(
                "original lifecycle transmission archive absent",
            ))?;
            let cohort = self.lifecycle_policies[index].collect(transmissions, safe.requests())?;
            #[cfg(test)]
            let cohort = {
                let mut retained = cohort;
                retained["reader_adverse_controls"] = self.lifecycle_policies[index]
                    .verify_reader_adverse_controls(&self.lifecycle_policies[(index + 1) % 2])?;
                retained
            };
            lifecycle_resends.push(cohort);
        }
        let mut wire_conflicts = Vec::with_capacity(2);
        for (index, policy) in self.conflict_policies.iter().enumerate() {
            let observer = self.conflict_observers[index].borrow();
            let observer = observer.as_ref().ok_or(ProviderError::Correlation(
                "original conflict archive absent",
            ))?;
            wire_conflicts.push(policy.collect(observer)?);
        }
        let original = publisher
            .original
            .ok_or(ProviderError::Frame("actual complete publication absent"))?;
        Ok(
            serde_json::json!({"schema":"crucible.reference.candidate-original.v1","implementation":package.identity(),
                "activation":crucible::node_contract::SavedRuntimeActivation::from(activation.record()),
                "source_probes":self.probes,"prepared_probes":self.prepared_probes,"wire_resends":self.resends,"lifecycle_resend_premises":self.lifecycle_policies.iter().map(|policy|policy.retained_premises()).collect::<Vec<_>>(),"lifecycle_resends":lifecycle_resends,"wire_conflicts":wire_conflicts,"runtime_cached_recovery":self.runtime_retries,"prepared_nodes":original.nodes(),"prepared_owners":original.prepared_owners(),"coordinator":coordinator,"windows":witnesses.iter().map(|witness|serde_json::json!({
                    "reference":witness.reference,"bytes":witness.bytes})).collect::<Vec<_>>()
            }),
        )
    }
}

struct Publisher {
    stored: StoredWorldActivationPublisher,
    peers: PublicReferenceCustodyQueue,
    original: Option<PreparedWorldPublication>,
    lifecycle_world: Rc<super::source_lifecycle_world::SourceLifecycleWorld>,
}
impl ActivationPublisher for Publisher {
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
        self.original = Some(prepared.clone());
        if self
            .peers
            .record_publication(record, prepared, PublicationStatus::Unknown)
            .is_err()
        {
            return PublicationStatus::Unknown;
        }
        let status = self.stored.publish_complete(record, prepared);
        if self
            .peers
            .record_publication(record, prepared, status)
            .is_err()
        {
            return PublicationStatus::Unknown;
        }
        if status == PublicationStatus::Committed
            && self
                .lifecycle_world
                .record_committed(record, prepared, status)
                .is_err()
        {
            return PublicationStatus::Unknown;
        }
        status
    }
    fn reconcile_complete(
        &mut self,
        record: &ActivationRecord,
        prepared: &PreparedWorldPublication,
    ) -> PublicationStatus {
        if self.original.as_ref() != Some(prepared)
            || self
                .peers
                .record_publication(record, prepared, PublicationStatus::Unknown)
                .is_err()
        {
            return PublicationStatus::Unknown;
        }
        let status = self.stored.reconcile_complete(record, prepared);
        if self
            .peers
            .record_publication(record, prepared, status)
            .is_err()
        {
            return PublicationStatus::Unknown;
        }
        if status == PublicationStatus::Committed
            && self
                .lifecycle_world
                .record_committed(record, prepared, status)
                .is_err()
        {
            return PublicationStatus::Unknown;
        }
        status
    }
    fn publish(&mut self, _: &ActivationRecord) -> PublicationStatus {
        PublicationStatus::NotCommitted
    }
    fn reconcile(&mut self, _: &ActivationRecord) -> PublicationStatus {
        PublicationStatus::Unknown
    }
}

pub(super) fn window_case(
    installed: &super::installation::SourcePublicReferenceInstallation,
    quantum: u64,
) -> Result<ReferenceWindowCase, ProviderError> {
    let name = installed.profile.descriptor.id.as_str();
    let time = quantum
        .checked_mul(installed.bootstrap.quantum_ps.get())
        .ok_or(ProviderError::Frame("candidate window overflow"))?;
    let end = time
        .checked_add(installed.bootstrap.quantum_ps.get())
        .ok_or(ProviderError::Frame("candidate window overflow"))?;
    let batch = Id::new(format!("candidate/{name}/batch/{quantum}"))?;
    Ok(ReferenceWindowCase {
        node: installed.profile.descriptor.id.clone(),
        stage: Id::new(format!("candidate/{name}/stage/{quantum}"))?,
        batch: batch.clone(),
        operation: Id::new(format!("candidate/{name}/operation/{quantum}"))?,
        input_cut: Position::new(
            U64::new(
                time.checked_add(1)
                    .ok_or(ProviderError::Frame("candidate sampling overflow"))?,
            ),
            U64::new(0),
            Phase::BoundaryControl,
        ),
        grant: DeviceGrant {
            owner_id: installed.profile.owner.id.clone(),
            incarnation_id: installed.bootstrap.authority.incarnation_id.clone(),
            generation: installed.bootstrap.authority.owner_generation,
            window_id: Id::new(format!("candidate/{name}/window/{quantum}"))?,
            input_batch_id: batch,
            quantum: U64::new(quantum),
            start: Position::new(U64::new(time), U64::new(0), Phase::BoundaryControl),
            publication: Position::new(U64::new(end), U64::new(0), Phase::Publication),
            host_budget_ns: installed.bootstrap.host_budget_ns,
        },
    })
}

pub(super) fn oracle_contract(
    installed: &super::installation::SourcePublicReferenceInstallation,
    cases: &[ReferenceWindowCase],
) -> Result<ReferenceOracleContract, ProviderError> {
    let expected_payload = br#"{"bytes_processed":"0","checksum":"0"}"#;
    let input = canonical::content_ref(expected_payload, "application/octet-stream")?;
    let empty = canonical::content_ref(b"", "application/octet-stream")?;
    let expected = cases
        .iter()
        .enumerate()
        .map(|(index, case)| {
            Ok(ReferenceExpectedWindow {
                window: case.grant.window_id.clone(),
                batch: case.batch.clone(),
                input: if installed.profile.descriptor.id.as_str() == "consumer" && index >= 1 {
                    input.clone()
                } else {
                    empty.clone()
                },
            })
        })
        .collect::<Result<Vec<_>, ProviderError>>()?;
    Ok(ReferenceOracleContract {
        owner: installed.profile.owner.id.clone(),
        incarnation: installed.bootstrap.authority.incarnation_id.clone(),
        generation: installed.bootstrap.authority.owner_generation,
        quantum_ps: installed.bootstrap.quantum_ps,
        host_budget_ns: installed.bootstrap.host_budget_ns,
        first_quantum: U64::new(0),
        first_time_ps: U64::new(0),
        initial_checksum: U64::new(0),
        maximum_windows: 3,
        maximum_input_bytes: 4096,
        expected_windows: expected,
    })
}
fn failure(error: impl std::fmt::Display) -> ProviderError {
    ProviderError::Io(std::io::Error::other(error.to_string()))
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- Actual native fixture failure must fail the test
// crucible-lint: allow rust-allow -- Actual native fixture failure must fail the test
#[allow(
    clippy::unwrap_used,
    reason = "Actual native fixture failure must fail the test"
)]
mod source_probe_native_test {
    use super::*;
    #[test]
    #[ignore = "requires compiled installed source-built reference implementation package"]
    fn actual_guarded_pre_realization_refusals_preserve_original_native_world() {
        let nonce = super::super::candidate::entropy().unwrap();
        let short = nonce
            .as_slice()
            .iter()
            .take(8)
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let path = PathBuf::from(format!("/tmp/p-probes-{short}"));
        let receiver = super::start(path.clone()).unwrap();
        let original = receiver.recv().unwrap().unwrap();
        assert!(
            original.succeeded(),
            "failed original retained at {}",
            path.display()
        );
        let value = canonical::parse_json(original.original_bytes(), 16 * 1024 * 1024).unwrap();
        let probes = value["source_probes"].as_array().unwrap();
        assert_eq!(probes.len(), 2);
        for probe in probes {
            assert_eq!(
                probe["premises"]["provider_before"],
                probe["premises"]["provider_after"]
            );
            assert_eq!(
                probe["premises"]["controls"]["cases"]
                    .as_array()
                    .unwrap()
                    .len(),
                3
            );
            let bytes: Vec<u8> =
                serde_json::from_value(probe["original_snapshot_bytes"].clone()).unwrap();
            let snapshot = canonical::parse_json(&bytes, 1024 * 1024).unwrap();
            assert_eq!(snapshot["recording_complete"], true);
            assert_eq!(snapshot["observed_unknown"], false);
            assert_eq!(
                snapshot["evidence"]["requests"].as_array().unwrap().len(),
                3
            );
        }
        eprintln!(
            "source-built provider-only cohort: six original rejected controls, two unchanged native premises, full common world/windows/oracle/reap; original {}",
            original.original_result().encode()
        );
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- Actual native fixture failure must fail the test
// crucible-lint: allow rust-allow -- Actual native fixture failure must fail the test
#[allow(
    clippy::unwrap_used,
    reason = "Actual native fixture failure must fail the test"
)]
mod prepared_adverse_native_test {
    use super::*;

    #[test]
    #[ignore = "requires compiled installed source-built reference implementation package"]
    fn actual_prepared_adverse_controls_preserve_original_first_native_quantum() {
        let nonce = super::super::candidate::entropy().unwrap();
        let short = nonce
            .as_slice()
            .iter()
            .take(8)
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let path = PathBuf::from(format!("/tmp/pp-probes-{short}"));
        let mut original = super::start(path.clone()).unwrap().recv().unwrap().unwrap();
        assert!(
            original.succeeded(),
            "failed original retained at {}",
            path.display()
        );
        super::super::source_metadata_reviews::adversarial_tests::verify(&mut original).unwrap();
        let report = super::super::issuer::issue_report(&original).unwrap();
        let report: crate::node_qualification::QualificationClaim =
            serde_json::from_value(canonical::parse_json(report.bytes(), 4 * 1024 * 1024).unwrap())
                .unwrap();
        assert_eq!(
            report
                .requirements
                .iter()
                .filter(|row| row.disposition
                    == crate::node_qualification::RequirementDisposition::Passed)
                .count(),
            4
        );
        assert_eq!(
            report
                .requirements
                .iter()
                .filter(|row| row.disposition
                    == crate::node_qualification::RequirementDisposition::NotExecuted)
                .count(),
            368
        );
        assert_eq!(
            report
                .requirements
                .iter()
                .filter(|row| row.disposition
                    == crate::node_qualification::RequirementDisposition::NotApplicable)
                .count(),
            10
        );
        let value = canonical::parse_json(original.original_bytes(), 16 * 1024 * 1024).unwrap();
        let probes = value["prepared_probes"].as_array().unwrap();
        assert_eq!(probes.len(), 2);
        for probe in probes {
            let premises = &probe["premises"];
            assert_eq!(premises["provider_before"], premises["provider_after"]);
            assert_eq!(premises["controls"]["cases"].as_array().unwrap().len(), 6);
            assert_eq!(premises["controls"]["unchanged_pending_page"], true);
            assert_eq!(
                premises["initial_gate"]["schema"],
                "crucible.reference.original-prepared-gate.v1"
            );
            let bytes: Vec<u8> =
                serde_json::from_value(probe["original_snapshot_bytes"].clone()).unwrap();
            let snapshot = canonical::parse_json(&bytes, 1024 * 1024).unwrap();
            assert_eq!(snapshot["recording_complete"], true);
            assert_eq!(snapshot["observed_unknown"], false);
            assert_eq!(
                snapshot["evidence"]["requests"].as_array().unwrap().len(),
                6
            );
        }
        let resends = value["wire_resends"].as_array().unwrap();
        assert_eq!(resends.len(), 2);
        for cohort in resends {
            let premises = &cohort["premises"];
            assert_eq!(premises["before"], premises["after"]);
            assert_eq!(premises["exact_original_count"], 3);
            let original_bytes: Vec<u8> =
                serde_json::from_value(cohort["original_snapshot_bytes"].clone()).unwrap();
            let transmitted_bytes: Vec<u8> =
                serde_json::from_value(cohort["transmitted_snapshot_bytes"].clone()).unwrap();
            for (field, bytes) in [
                ("original_snapshot", original_bytes.as_slice()),
                ("transmitted_snapshot", transmitted_bytes.as_slice()),
            ] {
                let reference: ContentRef =
                    serde_json::from_value(premises[field].clone()).unwrap();
                reference.verify(bytes).unwrap();
            }
            let transmitted = canonical::parse_json(&transmitted_bytes, 1024 * 1024).unwrap();
            assert_eq!(transmitted["incomplete"], false);
            assert_eq!(transmitted["rows"].as_array().unwrap().len(), 3);
            for row in transmitted["rows"].as_array().unwrap() {
                assert_eq!(row["origin"], "controller");
                assert_eq!(row["write_completed"], true);
                assert_eq!(row["semantic_response_verified"], true);
            }
        }
        let owners = value["windows"].as_array().unwrap();
        let recoveries = value["runtime_cached_recovery"].as_array().unwrap();
        assert_eq!(recoveries.len(), 2);
        for owner in recoveries {
            let windows = owner.as_array().unwrap();
            assert_eq!(windows.len(), 3);
            for recovery in windows {
                for (reference_field, bytes_field) in [
                    ("outcome", "outcome_bytes"),
                    ("visible_coordinator", "visible_coordinator_bytes"),
                ] {
                    let reference: ContentRef =
                        serde_json::from_value(recovery[reference_field].clone()).unwrap();
                    let bytes: Bytes =
                        serde_json::from_value(recovery[bytes_field].clone()).unwrap();
                    reference.verify(bytes.as_slice()).unwrap();
                }
            }
        }
        assert_eq!(owners.len(), 2);
        for owner in owners {
            let bytes: Bytes = serde_json::from_value(owner["bytes"].clone()).unwrap();
            let reference: ContentRef = serde_json::from_value(owner["reference"].clone()).unwrap();
            reference.verify(bytes.as_slice()).unwrap();
            let witness = canonical::parse_json(bytes.as_slice(), 8 * 1024 * 1024).unwrap();
            assert_eq!(witness["windows"].as_array().unwrap().len(), 3);
            assert_eq!(witness["windows"][0]["original_grant"]["quantum"], "0");
            assert_eq!(witness["independent_oracle"]["windows"], "3");
            let cycles = &witness["supported_cycles"]["cycles"];
            assert_eq!(cycles.as_array().unwrap().len(), 3);
            for cycle in cycles.as_array().unwrap() {
                let sequences = ["input", "begin", "close", "consumption"].map(|kind| {
                    serde_json::from_value::<U64>(cycle[kind]["wire_sequence"].clone()).unwrap()
                });
                assert!(sequences.windows(2).all(|pair| pair[0] < pair[1]));
            }
            let supported = &witness["supported_preparation"];
            assert_eq!(
                supported["schema"],
                "crucible.reference.original-supported-preparation.v1"
            );
            let mut previous = 0;
            for control in [
                "discovery",
                "realization",
                "admission",
                "readiness",
                "global_activation",
            ] {
                let sequence: U64 =
                    serde_json::from_value(supported[control]["wire_sequence"].clone()).unwrap();
                assert!(sequence.get() > previous);
                previous = sequence.get();
                let request: ContentRef =
                    serde_json::from_value(supported[control]["request"].clone()).unwrap();
                let response: ContentRef =
                    serde_json::from_value(supported[control]["response"].clone()).unwrap();
                assert!(request.length.get() > 0 && response.length.get() > 0);
            }
        }
        let retired = canonical::parse_json(original.retirement_bytes(), 1024 * 1024).unwrap();
        assert_eq!(retired["reclaimed_original_peers"], 2);
        assert_eq!(retired["world_reservations"], 0);
        eprintln!(
            "source-built original prepared cohort persisted at {}: twelve controls, authentic unsupported and body-scope refusals, original gates and pending revision-zero oracle, six independently checked native windows, original groups reclaimed; partial qualification only",
            path.display()
        );
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- A failed authentic native cohort must fail its test
// crucible-lint: allow rust-allow -- A failed authentic native cohort must fail its test
#[allow(
    clippy::unwrap_used,
    reason = "A failed authentic native cohort must fail its test"
)]
mod completed_lifecycle_resend_native_test {
    use super::*;

    #[test]
    #[ignore = "requires compiled installed source-built reference implementation package"]
    fn actual_completed_lifecycle_duplicates_preserve_nonempty_native_input() {
        let nonce = super::super::candidate::entropy().unwrap();
        let short = nonce
            .as_slice()
            .iter()
            .take(8)
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let path = PathBuf::from(format!("/tmp/lc-resends-{short}"));
        let original = super::start(path.clone()).unwrap().recv().unwrap().unwrap();
        assert!(
            original.succeeded(),
            "failed original retained at {}",
            path.display()
        );
        let value = canonical::parse_json(original.original_bytes(), 16 * 1024 * 1024).unwrap();
        let cohorts = value["lifecycle_resends"].as_array().unwrap();
        assert_eq!(cohorts.len(), 2);
        for cohort in cohorts {
            assert_eq!(cohort["selected"].as_array().unwrap().len(), 10);
            assert_eq!(cohort["reader_adverse_controls"]["data_only"], true);
            let reader_cases = cohort["reader_adverse_controls"]["cases"]
                .as_array()
                .unwrap();
            assert_eq!(reader_cases.len(), 6);
            assert!(
                reader_cases
                    .iter()
                    .all(|case| case["data_only"] == true && case["refused"] == true)
            );
            let originals: Bytes =
                serde_json::from_value(cohort["original_snapshot_bytes"].clone()).unwrap();
            let originals = canonical::parse_json(originals.as_slice(), 8 * 1024 * 1024).unwrap();
            assert_eq!(originals["recording_complete"], true);
            assert_eq!(originals["observed_unknown"], false);
            assert_eq!(
                originals["evidence"]["requests"].as_array().unwrap().len(),
                13
            );
            let wire: Bytes =
                serde_json::from_value(cohort["transmitted_snapshot_bytes"].clone()).unwrap();
            let wire = canonical::parse_json(wire.as_slice(), 8 * 1024 * 1024).unwrap();
            assert_eq!(wire["incomplete"], false);
            assert_eq!(wire["rows"].as_array().unwrap().len(), 13);
            assert!(
                wire["rows"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|row| row["write_completed"] == true
                        && row["semantic_response_verified"] == true)
            );
        }
        assert_eq!(value["windows"].as_array().unwrap().len(), 2);
        let report = super::super::issuer::issue_report(&original).unwrap();
        let report: crate::node_qualification::QualificationClaim =
            serde_json::from_value(canonical::parse_json(report.bytes(), 4 * 1024 * 1024).unwrap())
                .unwrap();
        assert_eq!(
            report
                .requirements
                .iter()
                .filter(|row| row.disposition
                    == crate::node_qualification::RequirementDisposition::Passed)
                .count(),
            4
        );
        assert_eq!(
            report
                .requirements
                .iter()
                .filter(|row| row.disposition
                    == crate::node_qualification::RequirementDisposition::NotExecuted)
                .count(),
            368
        );
        eprintln!(
            "actual original lifecycle duplicates: two Ready/world controls and two native Input/Begin/Close/Consumed cycles per provider, thirteen real transmissions per archive; three-window independent checksum/input oracle and original process reclamation; partial original {} at {}",
            original.original_result().encode(),
            path.display()
        );
    }

    #[test]
    #[ignore = "requires compiled installed source-built reference implementation package"]
    fn actual_same_id_changed_material_preserves_original_native_progress() {
        let nonce = super::super::candidate::entropy().unwrap();
        let short = nonce
            .as_slice()
            .iter()
            .take(8)
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let path = PathBuf::from(format!("/tmp/id-conflicts-{short}"));
        let original = super::start(path.clone()).unwrap().recv().unwrap().unwrap();
        assert!(
            original.succeeded(),
            "original failed attempt retained at {}",
            path.display()
        );
        let value = canonical::parse_json(original.original_bytes(), 16 * 1024 * 1024).unwrap();
        let cohorts = value["wire_conflicts"].as_array().unwrap();
        assert_eq!(cohorts.len(), 2);
        for cohort in cohorts {
            assert_eq!(cohort["original_premises"].as_array().unwrap().len(), 3);
            assert_eq!(cohort["wire"]["incomplete"], false);
            let rows = cohort["wire"]["rows"].as_array().unwrap();
            assert_eq!(rows.len(), 3);
            assert!(rows.iter().all(|row| row["write_completed"] == true
                && row["conflict_refusal_verified"] == true
                && row["original_identity"] != row["attempted_identity"]));
        }
        assert_eq!(value["windows"].as_array().unwrap().len(), 2);
        assert_eq!(value["lifecycle_resends"].as_array().unwrap().len(), 2);
        let issued = super::super::issuer::issue_report(&original).unwrap();
        let report: crate::node_qualification::QualificationClaim =
            serde_json::from_value(canonical::parse_json(issued.bytes(), 4 * 1024 * 1024).unwrap())
                .unwrap();
        assert_eq!(
            report
                .requirements
                .iter()
                .filter(|row| row.disposition
                    == crate::node_qualification::RequirementDisposition::Passed)
                .count(),
            4
        );
        assert_eq!(
            report
                .requirements
                .iter()
                .filter(|row| row.disposition
                    == crate::node_qualification::RequirementDisposition::NotExecuted)
                .count(),
            368
        );
        eprintln!(
            "six actual same-ID changed-material refusals retain original receipts, input prefixes and three-window native checksum oracle; original {} at {}",
            original.original_result().encode(),
            path.display()
        );
    }
}
