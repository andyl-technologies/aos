//! Admits explicit conditional sources through the original owning observation actor.
//!
//! Portable source identities are loaded through the independently installed
//! archive signer. The catalog derives the full original world/context and a
//! distinct replay profile before any model readiness or response is available.

use crucible::node_adapters::transcript::TranscriptArchive;
use crucible_cas::content_store::{BlobHandle, ObjectKind, RefName};
use crucible_node_contract::{Id, Validate};

use super::*;

pub(super) struct ReplaySubmission {
    pub(super) sources: BTreeMap<Id, ContentRef>,
    pub(super) configuration: Vec<u8>,
}

pub(super) struct ReplayRequest {
    pub(super) ledger: String,
    pub(super) execution: ExecutionId,
    pub(super) sources: BTreeMap<Id, ContentRef>,
    pub(super) configuration: Vec<u8>,
}

pub(super) fn submit(
    request: ReplayRequest,
    workers: &mut BTreeMap<ExecutionId, ActorWorker>,
    catalog: &InstalledNodeCatalog,
    maximum_worlds: usize,
    storage: &ActorStorage,
    queued: Option<&PreparationReservation>,
) -> Result<ObservedAttemptState, NodeObservationServiceError> {
    let ReplayRequest {
        ledger,
        execution,
        sources,
        configuration,
    } = request;
    let original_raw_request = ConditionalPreparationRequest {
        ledger: ledger.clone(),
        execution: execution
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        sources: sources.clone(),
        configuration: crucible_node_contract::Bytes::new(configuration.clone()),
    };
    let configuration = NodeRunConfiguration::from_json(&configuration).map_err(refused)?;
    let original_configuration = crucible_node_contract::canonical::canonical_json(
        &serde_json::to_value(&configuration).map_err(refused)?,
    )
    .map_err(refused)?;
    if let Some(owned) = workers.get_mut(&execution) {
        let original = owned
            .replay
            .as_ref()
            .ok_or_else(|| refused("ordinary fresh execution cannot become conditional replay"))?;
        if original.sources != sources || original.configuration != original_configuration {
            return Err(refused(
                "conditional retry changed original sources or context",
            ));
        }
        if let Some(preparations) = &storage.preparations {
            let original = preparations.reserve(&original_raw_request)?;
            if original.original_dispatch {
                return Err(refused(
                    "live conditional cursor omits its original admission commitment",
                ));
            }
        }
        return owned
            .worker
            .submit(&ledger, &owned.request, &owned.admission)
            .map_err(refused);
    }
    if storage
        .repository
        .observed_execution_state(execution)
        .map_err(refused)?
        .is_some()
    {
        // A new actor does not inherit the original cursor or runtime authority.
        // Historical observations remain available through the state endpoint.
        return Err(refused(
            "conditional execution already belongs to an original actor",
        ));
    }
    if workers.len() >= maximum_worlds {
        return Err(NodeObservationServiceError::Capacity);
    }
    let archive = storage
        .transcripts
        .as_ref()
        .ok_or_else(|| refused("conditional source archive is not installed in this actor"))?;
    let authenticated = sources
        .iter()
        .map(|(node, reference)| {
            archive
                .load(reference)
                .map(|source| (node.clone(), source))
                .map_err(refused)
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let preparations = storage
        .preparations
        .as_ref()
        .ok_or_else(|| refused("conditional source admission ledger is unavailable"))?;
    let direct;
    let reservation = if let Some(original) = queued {
        let retry = preparations.reserve(&original_raw_request)?;
        if !original.original_dispatch
            || retry.original_dispatch
            || retry.record.request != original.record.request
            || retry.record.execution != original.record.execution
        {
            return Err(refused(
                "conditional queue changed original admission custody",
            ));
        }
        original
    } else {
        direct = preparations.reserve(&original_raw_request)?;
        if !direct.original_dispatch {
            return Err(refused(
                "conditional source nonce already belongs to original admission custody",
            ));
        }
        &direct
    };

    let prepared = catalog
        .select_conditional_replay(authenticated, &configuration)
        .and_then(|recipe| recipe.prepare(catalog, execution))
        .map_err(refused)?;
    let context = super::super::backend::input_context_bytes(
        &prepared.world.scenario,
        &prepared.configuration,
    )
    .map_err(refused)?;
    let inputs = ContentId::for_bytes(ObjectKind::Trace, 1, &context);
    let receipt = storage
        .blobs
        .put_if_absent(inputs, &BlobHandle::from_bytes(context))
        .map_err(refused)?;
    if !receipt.is_durable() {
        return Err(refused("conditional input context is not durably retained"));
    }
    let publisher = super::super::StoredWorldActivationPublisher::new(
        storage.blobs.clone(),
        storage.refs.clone(),
        RefName::new(format!(
            "node-world-activations/{}",
            execution
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ))
        .map_err(refused)?,
    )
    .map_err(refused)?;
    let backend = NodeObservedBackend::from_conditional_replay(
        prepared,
        publisher,
        storage.blobs.clone(),
        inputs,
        execution,
    )
    .map_err(refused)?;
    let scenario = backend.scenario_artifact();
    storage
        .repository
        .publish_scenario_artifact(
            scenario.scenario(),
            scenario.payload_schema(),
            scenario.payload().to_vec(),
        )
        .map_err(refused)?;
    let config = backend.configuration_artifact();
    storage
        .repository
        .publish_configuration_artifact(
            config.scenario(),
            config.scenario_artifact(),
            config.configuration(),
            config.payload_schema(),
            config.payload().to_vec(),
        )
        .map_err(refused)?;
    let request = backend.request(execution).map_err(refused)?;
    let admission = backend.admission().clone();
    let worker =
        ObservedAttemptWorker::new(storage.repository.clone(), backend, 1).map_err(refused)?;
    workers.insert(
        execution,
        ActorWorker {
            worker,
            request,
            admission,
            replay: Some(ReplaySubmission {
                sources,
                configuration: original_configuration,
            }),
        },
    );
    let owned = workers
        .get_mut(&execution)
        .ok_or_else(|| refused("conditional actor custody disappeared"))?;
    let result = owned
        .worker
        .submit(&ledger, &owned.request, &owned.admission)
        .map_err(refused);
    let outcome = match &result {
        Ok(original) => ConditionalPreparationState::Admitted {
            observed_request: crucible_node_contract::Bytes::new(
                original.request().canonical_bytes(),
            ),
        },
        Err(_) => ConditionalPreparationState::Unavailable {},
    };
    preparations.complete(reservation, outcome)?;
    result
}

impl NodeObservationService {
    /// Installs a private source archive beside the ordinary native catalog.
    ///
    /// The signer is an owned local capability, never a portable request key or
    /// certificate. Ordinary fresh submissions retain their existing semantics.
    ///
    /// # Errors
    /// Refuses the same finite actor/custody and installation conditions as
    /// [`Self::start`]. Signed sources are separately authenticated on submission.
    pub fn start_with_transcript_archive(
        configuration: NodeObservationServiceConfig,
        archive: TranscriptArchive,
        repository: Arc<CampaignRepository>,
        blobs: Arc<dyn ImmutableBlobBackend>,
        refs: Arc<dyn MutableRefBackend>,
    ) -> Result<Self, NodeObservationServiceError> {
        Self::start_inner(configuration, Some(archive), repository, blobs, refs)
    }

    /// Admits unchanged conditional replay from complete original signed sources.
    ///
    /// Source actor IDs and configuration must match the authenticated installed
    /// context. This operation cannot select fresh physical execution, reduce or
    /// minimize a changed context, or waive the original world's nondeterminism.
    /// Current-actor retries use the original cursor; a retired actor's historical
    /// result remains available through [`Self::state`] without new execution.
    ///
    /// # Errors
    /// Refuses missing signer, invalid/oversized sources, changed installation or
    /// original context, unsupported trajectories, exhausted custody or storage.
    pub fn submit_conditional_replay(
        &self,
        ledger: String,
        execution: ExecutionId,
        sources: BTreeMap<Id, ContentRef>,
        configuration: Vec<u8>,
    ) -> Result<ObservedAttemptState, NodeObservationServiceError> {
        if sources.len() != 2 || configuration.len() > 4096 || ledger.len() > 128 {
            return Err(NodeObservationServiceError::Capacity);
        }
        for reference in sources.values() {
            reference.validate().map_err(refused)?;
        }
        let (reply, response) = mpsc::sync_channel(1);
        self.send(Command::ConditionalReplay {
            request: ReplayRequest {
                ledger,
                execution,
                sources,
                configuration,
            },
            reply,
        })?;
        response
            .recv()
            .map_err(|_| NodeObservationServiceError::Unavailable)?
    }
}
