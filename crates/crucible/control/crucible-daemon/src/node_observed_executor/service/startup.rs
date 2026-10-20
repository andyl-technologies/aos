//! Starts the owning actor and transfers installed catalog custody to its thread.

use super::*;

impl NodeObservationService {
    /// Starts the actor after validating bounds and preparing its owned ledgers.
    ///
    /// # Errors
    /// Preserves startup refusals for invalid capacity, ledger or thread setup,
    /// unavailable custody, and installed-catalog measurement.
    pub(super) fn start_inner_installed(
        configuration: NodeObservationServiceConfig,
        transcripts: Option<crucible_engine::node_adapters::transcript::TranscriptArchive>,
        installations: vendor_installation::ActorInstallations,
        repository: Arc<CampaignRepository>,
        blobs: Arc<dyn ImmutableBlobBackend>,
        refs: Arc<dyn MutableRefBackend>,
    ) -> Result<Self, NodeObservationServiceError> {
        if configuration.maximum_pending_requests == 0
            || configuration.maximum_pending_requests > 64
            || configuration.maximum_worlds == 0
            || configuration.maximum_worlds > 64
        {
            return Err(NodeObservationServiceError::Capacity);
        }
        let preparations = if transcripts.is_some() {
            Some(ConditionalPreparationLedger::new(
                blobs.clone(),
                refs.clone(),
            )?)
        } else {
            None
        };
        let capabilities = CapabilityPreparationLedger::new(blobs.clone(), refs.clone())?;
        let actor_capabilities = capabilities.clone();
        let debug = DebugLedger::new(blobs.clone(), refs.clone())?;
        let actor_debug = debug.clone();
        let preserving_debug = debug_preserving::Ledger::new(blobs.clone(), refs.clone())?;
        let actor_preserving_debug = preserving_debug.clone();
        let root_preparations = RootPreparationLedger::new(blobs.clone(), refs.clone())?;
        let actor_root_preparations = root_preparations.clone();
        let root_installation =
            root_preparation::worker::Installation::from_configuration(&configuration)?;
        let capability_installation =
            capability_preparation::group::Installation::from_configuration(&configuration);
        let capability_archive = configuration.socket_parent.join("capability-clock-archive");
        let condition_archive = configuration
            .socket_parent
            .join("condition-preserving-archive");
        let (commands, receiver) = mpsc::sync_channel(configuration.maximum_pending_requests);
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let stopping = Arc::new(AtomicBool::new(false));
        let roots = Arc::new(Mutex::new(BTreeSet::new()));
        let actor_stopping = Arc::clone(&stopping);
        let actor_roots = Arc::clone(&roots);
        let retired = Arc::new(AtomicBool::new(false));
        let actor_retired = Arc::clone(&retired);
        let actor_preparations = preparations.clone();
        let actor_repository = Arc::clone(&repository);
        thread::Builder::new()
            .name("crucible-node-observer".into())
            .spawn(move || {
                let catalog = InstalledNodeCatalog::new(
                    configuration.device_executable,
                    configuration.expected_device,
                    configuration.socket_parent,
                    configuration.control_timeout,
                    configuration.maximum_worlds,
                )
                .and_then(|mut catalog| {
                    catalog.install_artifacts(configuration.installed_artifacts)?;
                    if let Some(original) = installations.original {
                        catalog
                            .install_behavioral_acceptance(original.behavioral, original.limits)?;
                        catalog.install_original_lineage_authority(original.source)?;
                    }
                    if let Some(vendor) = installations.vendor {
                        vendor.install(&mut catalog)?;
                    }
                    Ok(catalog)
                });
                match catalog {
                    Ok(catalog) => {
                        let _ = ready_sender.send(Ok(()));
                        run_actor(
                            catalog,
                            configuration.maximum_worlds,
                            ActorStorage {
                                preparations: actor_preparations,
                                capabilities: actor_capabilities,
                                debug: actor_debug,
                                preserving_debug: actor_preserving_debug,
                                root_preparations: actor_root_preparations,
                                root_installation,
                                capability_installation,
                                capability_archive,
                                condition_archive,
                                transcripts,
                                repository: actor_repository,
                                blobs,
                                refs,
                            },
                            ActorControl {
                                receiver,
                                stopping: actor_stopping,
                                roots: actor_roots,
                                retired: actor_retired,
                            },
                        );
                    }
                    Err(error) => {
                        let _ = ready_sender.send(Err(refused(error)));
                    }
                }
            })
            .map_err(refused)?;
        ready_receiver
            .recv()
            .map_err(|_| NodeObservationServiceError::Unavailable)??;
        Ok(Self {
            repository,
            commands,
            stopping,
            roots,
            retired,
            preparations,
            capabilities,
            debug,
            preserving_debug,
            root_preparations,
        })
    }
}
