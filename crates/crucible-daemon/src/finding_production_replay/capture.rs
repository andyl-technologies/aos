//! Capture validation and bounded lifecycle-object collection.

use super::*;

pub(super) fn validate_capture_content(
    finding_kind: FindingKind,
    model_reproduction: &[u8],
    shared_context: &FindingProductionReplaySharedContext,
    retained_selected_side: FindingProductionReplaySelectedSide,
    sides: &[FindingProductionReplayExecutionSide],
    campaign_replay_closure: &[u8],
    limits: FindingProductionReplayCaptureLimits,
) -> Result<(), FindingProductionReplayCaptureError> {
    let model = crucible::ReproductionArtifact::from_compact_binary(model_reproduction).map_err(
        |error| FindingProductionReplayCaptureError::Model {
            operation: "decode",
            error: Box::new(error),
        },
    )?;
    model
        .replay()
        .map_err(|error| FindingProductionReplayCaptureError::Model {
            operation: "replay",
            error: Box::new(error),
        })?;
    let scenario = model.scenario_form();
    validate_shared_context(scenario, shared_context, limits)?;
    let closure = GuardedCampaignReplayClosure::from_canonical_bytes(campaign_replay_closure)
        .map_err(FindingProductionReplayCaptureError::ReplayClosure)?;
    closure
        .validate_for_schedule(scenario, model.schedule())
        .map_err(FindingProductionReplayCaptureError::ReplayClosure)?;

    let actual_selected_side = selected_side(sides)?;
    if actual_selected_side != retained_selected_side {
        return Err(FindingProductionReplayCaptureError::SelectedSideMismatch);
    }
    match (finding_kind, sides) {
        (FindingKind::Divergence, [_, _])
        | (
            FindingKind::PropertyViolation,
            [
                FindingProductionReplayExecutionSide {
                    outcome: FindingProductionReplayTerminalOutcome::Failed,
                    ..
                },
            ],
        )
        | (
            FindingKind::Timeout,
            [
                FindingProductionReplayExecutionSide {
                    outcome: FindingProductionReplayTerminalOutcome::Timeout,
                    ..
                },
            ],
        ) => {}
        _ => return Err(FindingProductionReplayCaptureError::InvalidSideCount),
    }
    for side in sides {
        validate_execution_side(side, scenario, shared_context.recipe, limits)?;
    }
    Ok(())
}

pub(super) fn validate_shared_context(
    scenario: &crucible::ScenarioDefForm,
    context: &FindingProductionReplaySharedContext,
    limits: FindingProductionReplayCaptureLimits,
) -> Result<(), FindingProductionReplayCaptureError> {
    if context.recipe.run_ceiling_icount == 0
        || context.recipe.lifecycle_quantum_budget == 0
        || context.recipe.rendezvous_interval_icount == Some(0)
    {
        return Err(FindingProductionReplayCaptureError::InvalidRecipe);
    }
    validate_deployment(scenario, &context.deployment, limits)?;
    validate_lifecycle_objects(scenario, &context.lifecycle_objects, limits)
}

/// Typed result of capture at a private production boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FindingProductionReplayCaptureOutcome<T = FindingProductionReplayCapture> {
    /// Every replay dependency was captured and authenticated.
    Complete(T),
    /// Execution completed, but the named portable evidence was unavailable.
    Incomplete(FindingProductionReplayIncomplete),
}

/// Closed reasons a completed private replay cannot be exported for production replay.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum FindingProductionReplayIncomplete {
    /// A continuation snapshot began after sequence zero without its retained prefix.
    #[error("the complete scheduler event-log prefix was not retained")]
    MissingEventLogPrefix,
    /// The lifecycle did not publish a terminal all-node fingerprint set.
    #[error("terminal all-node fingerprints were not captured")]
    MissingTerminalFingerprints,
    /// The scenario references signal objects but no signal store was retained.
    #[error("signal artifact storage was not retained")]
    MissingSignalArtifactStore,
    /// The scenario references World I/O objects but no World store was retained.
    #[error("World artifact storage was not retained")]
    MissingWorldArtifactStore,
    /// Complete evidence exceeds the active campaign publication allowance.
    #[error("the complete replay evidence exceeds the publication byte limit")]
    PublicationLimitExceeded,
}

/// Failure to build, encode, or authenticate a production replay capture.
#[derive(Debug, Error)]
pub enum FindingProductionReplayCaptureError {
    /// A fixed capture bound was exceeded.
    #[error("finding production replay exceeded `{limit}`")]
    LimitExceeded {
        /// Stable bound name.
        limit: &'static str,
    },
    /// The production instruction or quantum bound was zero.
    #[error("finding production replay recipe contains a zero execution bound")]
    InvalidRecipe,
    /// The installed runtime identity is empty, oversized, or inconsistent.
    #[error("finding production replay installed runtime identity is invalid")]
    InvalidRuntimeIdentity,
    /// An installed QEMU/plugin pair could not be authenticated.
    #[error("authenticate installed finding replay runtime: {0}")]
    RuntimeAuthentication(#[source] crucible_qemu::QemuLaunchArtifactIdentityError),
    /// An authenticated installed runtime differs from the capture prerequisite.
    #[error("installed finding replay runtime differs from the captured identity")]
    RuntimeIdentity,
    /// Guest kernel, root-image, or initrd inputs are incomplete or inconsistent.
    #[error("finding production replay guest deployment is incomplete or inconsistent")]
    InvalidGuestDeployment,
    /// A configured guest file could not be captured before lifecycle teardown.
    #[error("{operation} finding replay guest asset `{path}`: {source}")]
    GuestAssetIo {
        /// Closed filesystem operation.
        operation: &'static str,
        /// Selected producer-side path.
        path: std::path::PathBuf,
        /// Typed filesystem failure.
        #[source]
        source: std::io::Error,
    },
    /// The capture differs from its campaign reproduction or observed signature.
    #[error("finding production replay campaign binding is inconsistent")]
    CaptureBinding,
    /// The capture has neither one ordinary side nor two divergent sides.
    #[error("finding production replay must contain one ordinary side or two divergent sides")]
    InvalidSideCount,
    /// Two claimed divergence executions have no causal mismatch.
    #[error("paired finding production replay sides do not diverge")]
    PairedSidesDoNotDiverge,
    /// The retained side selector does not match first-location semantics.
    #[error("finding production replay selected side is inconsistent")]
    SelectedSideMismatch,
    /// One scheduler entry is unauthenticated or out of sequence.
    #[error("finding production replay event log is invalid")]
    InvalidEventLog,
    /// Terminal fingerprints do not name every scenario VM exactly once.
    #[error("finding production replay terminal fingerprint set is incomplete or inconsistent")]
    InvalidTerminalFingerprints,
    /// The resolved effect trace is absent, extraneous, or malformed.
    #[error("finding production replay resolved-effect trace is incomplete or inconsistent")]
    InvalidResolvedEffectTrace,
    /// A lifecycle object is missing, extraneous, or has another content hash.
    #[error("finding production replay lifecycle object closure is incomplete or inconsistent")]
    InvalidLifecycleObjects,
    /// The embedded model reproduction is invalid.
    #[error("finding production replay model {operation} failed: {error}")]
    Model {
        /// Closed model operation that failed.
        operation: &'static str,
        /// Typed engine failure.
        error: Box<crucible::EngineError>,
    },
    /// The authenticated campaign choice closure is invalid.
    #[error("finding production replay choice closure is invalid: {0}")]
    ReplayClosure(#[source] GuardedCampaignReplayClosureError),
    /// A campaign reproduction or signature binding could not be decoded.
    #[error("finding production replay campaign binding is invalid: {0}")]
    Campaign(#[source] crucible_campaign::CampaignCodecError),
    /// The portable payload uses another schema version.
    #[error("unsupported finding production replay schema {actual}")]
    UnsupportedSchema {
        /// Version read from the payload.
        actual: u32,
    },
    /// The portable payload could not be decoded.
    #[error("decode finding production replay: {0}")]
    Decode(#[source] ciborium::de::Error<std::io::Error>),
    /// The encoded container declarations exceed the bounded decoder contract.
    #[error("finding production replay has an unsafe or malformed CBOR container declaration")]
    DecodeBounds,
    /// The portable payload could not be encoded.
    #[error("encode finding production replay: {0}")]
    Encode(#[source] ciborium::ser::Error<std::io::Error>),
    /// The payload decoded but was not byte-canonical.
    #[error("finding production replay encoding is not canonical")]
    Noncanonical,
    /// A retained DAG store operation failed.
    #[error("finding production replay lifecycle store failed: {0}")]
    Store(#[source] crucible::DagStoreError),
    /// Signal artifact traversal rejected the retained closure.
    #[error("finding production replay signal artifact closure failed: {0}")]
    SignalArtifacts(#[source] crucible_api::LifecycleApiError),
    /// Production lifecycle configuration could not project replay inputs.
    #[error("resolve finding production replay lifecycle inputs: {0}")]
    Lifecycle(#[source] crucible_api::LifecycleApiError),
}

/// Captures the complete signal and World object closure from producer stores.
///
/// The returned map owns bytes and contains no source-store path. Duplicate
/// objects shared by signal and World references appear once.
///
/// # Errors
///
/// Returns [`FindingProductionReplayCaptureError`] when an object is missing,
/// unauthenticated, or exceeds the scenario's authored lifecycle byte bound.
pub fn capture_finding_replay_lifecycle_objects(
    finding: &FindingReproductionArtifact,
    signal_store: Option<&dyn DagStore>,
    world_store: Option<&dyn DagStore>,
) -> Result<
    FindingProductionReplayCaptureOutcome<BTreeMap<ContentHash, Vec<u8>>>,
    FindingProductionReplayCaptureError,
> {
    capture_finding_replay_lifecycle_objects_with_limits(
        finding,
        signal_store,
        world_store,
        FindingProductionReplayCaptureLimits::for_finding(finding),
    )
}

/// Captures lifecycle objects under a caller-supplied effective byte budget.
///
/// This variant lets publication paths apply an aggregate evidence allowance
/// before returning owned object bytes, while standalone capture retains the
/// authored scenario limits through [`capture_finding_replay_lifecycle_objects`].
///
/// # Errors
///
/// Returns [`FindingProductionReplayCaptureError`] when an object is missing,
/// unauthenticated, or exceeds `limits`.
pub fn capture_finding_replay_lifecycle_objects_with_limits(
    finding: &FindingReproductionArtifact,
    signal_store: Option<&dyn DagStore>,
    world_store: Option<&dyn DagStore>,
    limits: FindingProductionReplayCaptureLimits,
) -> Result<
    FindingProductionReplayCaptureOutcome<BTreeMap<ContentHash, Vec<u8>>>,
    FindingProductionReplayCaptureError,
> {
    capture_finding_replay_lifecycle_objects_with_budget(
        finding,
        signal_store,
        world_store,
        limits,
        FindingProductionReplayBudget {
            precharged_identities: &BTreeSet::new(),
            precharged_bytes: 0,
            total_byte_limit: limits.max_lifecycle_bytes,
        },
    )
}

pub(crate) struct FindingProductionReplayBudget<'a> {
    pub(crate) precharged_identities: &'a BTreeSet<ContentHash>,
    pub(crate) precharged_bytes: u64,
    pub(crate) total_byte_limit: u64,
}

pub(crate) fn capture_finding_replay_lifecycle_objects_with_budget(
    finding: &FindingReproductionArtifact,
    signal_store: Option<&dyn DagStore>,
    world_store: Option<&dyn DagStore>,
    limits: FindingProductionReplayCaptureLimits,
    budget: FindingProductionReplayBudget<'_>,
) -> Result<
    FindingProductionReplayCaptureOutcome<BTreeMap<ContentHash, Vec<u8>>>,
    FindingProductionReplayCaptureError,
> {
    let scenario = finding.artifact.scenario_form();
    let plan = scenario.plan().fault_signals();
    if !plan.programs().is_empty() && signal_store.is_none() {
        return Ok(FindingProductionReplayCaptureOutcome::Incomplete(
            FindingProductionReplayIncomplete::MissingSignalArtifactStore,
        ));
    }
    if scenario.world().io_nodes().next().is_some() && world_store.is_none() {
        return Ok(FindingProductionReplayCaptureOutcome::Incomplete(
            FindingProductionReplayIncomplete::MissingWorldArtifactStore,
        ));
    }
    let mut objects = match signal_store {
        Some(store) => match crucible_api::collect_signal_artifact_objects_with_budget(
            plan,
            store,
            limits.max_lifecycle_bytes,
            budget.precharged_identities,
            budget.precharged_bytes,
            budget.total_byte_limit,
        ) {
            Ok(objects) => objects,
            Err(crucible_api::LifecycleApiError::ResourceLimit(limit))
                if limit.field == "finding_production_replay_lifecycle_bytes" =>
            {
                return Err(FindingProductionReplayCaptureError::LimitExceeded {
                    limit: "finding-production-replay-lifecycle-bytes",
                });
            }
            Err(crucible_api::LifecycleApiError::ResourceLimit(limit))
                if limit.field == "finding_production_replay_static_bytes" =>
            {
                return Err(FindingProductionReplayCaptureError::LimitExceeded {
                    limit: "finding-production-replay-static-bytes",
                });
            }
            Err(error) => {
                return Err(FindingProductionReplayCaptureError::SignalArtifacts(error));
            }
        },
        None => BTreeMap::new(),
    };
    if objects.len() > limits.max_lifecycle_objects {
        return Err(FindingProductionReplayCaptureError::LimitExceeded {
            limit: "finding-production-replay-lifecycle-object-count",
        });
    }
    let mut retained_lifecycle_bytes = objects.values().try_fold(0_u64, |total, bytes| {
        charge_bytes(
            total,
            bytes.len(),
            limits.max_lifecycle_bytes,
            "finding-production-replay-lifecycle-bytes",
        )
    })?;
    let mut retained_total_bytes =
        objects
            .iter()
            .try_fold(budget.precharged_bytes, |total, (identity, bytes)| {
                if budget.precharged_identities.contains(identity) {
                    Ok(total)
                } else {
                    charge_bytes(
                        total,
                        bytes.len(),
                        budget.total_byte_limit,
                        "finding-production-replay-static-bytes",
                    )
                }
            })?;
    if let Some(store) = world_store {
        for node in scenario.world().io_nodes() {
            let identity = match &node.kind {
                crucible::WorldIoNodeKind::Block { base_image, .. } => base_image.hash(),
                crucible::WorldIoNodeKind::NineP { tree, .. } => tree.hash(),
            };
            if objects.contains_key(&identity) {
                continue;
            }
            let bytes = store
                .get(&identity)
                .map_err(FindingProductionReplayCaptureError::Store)?;
            if ContentHash::from_bytes(&bytes) != identity {
                return Err(FindingProductionReplayCaptureError::InvalidLifecycleObjects);
            }
            if objects.len() >= limits.max_lifecycle_objects {
                return Err(FindingProductionReplayCaptureError::LimitExceeded {
                    limit: "finding-production-replay-lifecycle-object-count",
                });
            }
            retained_lifecycle_bytes = charge_bytes(
                retained_lifecycle_bytes,
                bytes.len(),
                limits.max_lifecycle_bytes,
                "finding-production-replay-lifecycle-bytes",
            )?;
            if !budget.precharged_identities.contains(&identity) {
                retained_total_bytes = charge_bytes(
                    retained_total_bytes,
                    bytes.len(),
                    budget.total_byte_limit,
                    "finding-production-replay-static-bytes",
                )?;
            }
            objects.insert(identity, bytes);
        }
    }
    validate_lifecycle_objects(scenario, &objects, limits)?;
    Ok(FindingProductionReplayCaptureOutcome::Complete(objects))
}

pub(super) fn selected_side(
    sides: &[FindingProductionReplayExecutionSide],
) -> Result<FindingProductionReplaySelectedSide, FindingProductionReplayCaptureError> {
    match sides {
        [_] => Ok(FindingProductionReplaySelectedSide::Observed),
        [expected, reproduced] => {
            let comparison =
                compare_event_log_determinism(&expected.event_log, &reproduced.event_log);
            let mismatch = comparison
                .mismatch()
                .ok_or(FindingProductionReplayCaptureError::PairedSidesDoNotDiverge)?;
            mismatch
                .first_location()
                .ok_or(FindingProductionReplayCaptureError::PairedSidesDoNotDiverge)?;
            if mismatch.expected_location.is_some() {
                Ok(FindingProductionReplaySelectedSide::Expected)
            } else {
                Ok(FindingProductionReplaySelectedSide::Reproduced)
            }
        }
        _ => Err(FindingProductionReplayCaptureError::InvalidSideCount),
    }
}

pub(super) fn validate_runtime_identity(
    identity: &FindingProductionReplayRuntimeIdentity,
) -> Result<(), FindingProductionReplayCaptureError> {
    let fields = [
        identity.qemu_build_id.as_str(),
        identity.qemu_atomic_patch_hash.as_str(),
        identity.plugin_abi.as_str(),
        identity.shmem_abi_version.as_str(),
    ];
    if fields
        .iter()
        .any(|field| field.is_empty() || field.len() > MAX_RUNTIME_IDENTITY_FIELD_BYTES)
        || identity.shmem_abi_version != crucible::SHMEM_ABI_VERSION.to_string()
    {
        return Err(FindingProductionReplayCaptureError::InvalidRuntimeIdentity);
    }
    Ok(())
}

pub(super) fn validate_deployment(
    scenario: &crucible::ScenarioDefForm,
    deployment: &FindingProductionReplayDeployment,
    limits: FindingProductionReplayCaptureLimits,
) -> Result<(), FindingProductionReplayCaptureError> {
    validate_runtime_identity(&deployment.runtime)?;

    let expected_architectures = scenario
        .world()
        .vm_nodes()
        .iter()
        .map(|node| node.arch)
        .collect::<BTreeSet<_>>();
    let actual_architectures = deployment
        .guest_assets
        .iter()
        .map(|assets| assets.architecture)
        .collect::<BTreeSet<_>>();
    if expected_architectures.is_empty()
        || actual_architectures != expected_architectures
        || actual_architectures.len() != deployment.guest_assets.len()
        || deployment
            .guest_assets
            .windows(2)
            .any(|pair| pair[0].architecture >= pair[1].architecture)
    {
        return Err(FindingProductionReplayCaptureError::InvalidGuestDeployment);
    }

    let mut retained_bytes = 0_u64;
    let mut retained_identities = BTreeSet::new();
    for assets in &deployment.guest_assets {
        if assets.kernel.bytes.is_empty()
            || assets.root_image.bytes.is_empty()
            || assets.kernel.identity != ContentHash::from_bytes(&assets.kernel.bytes)
            || assets.root_image.identity != ContentHash::from_bytes(&assets.root_image.bytes)
            || assets.kernel_cmdline_prefix.as_ref().is_some_and(|prefix| {
                prefix.len() > MAX_RUNTIME_IDENTITY_FIELD_BYTES || prefix.contains('\0')
            })
        {
            return Err(FindingProductionReplayCaptureError::InvalidGuestDeployment);
        }
        for asset in [&assets.kernel, &assets.root_image] {
            if retained_identities.insert(asset.identity) {
                retained_bytes = charge_bytes(
                    retained_bytes,
                    asset.bytes.len(),
                    limits.max_guest_asset_bytes,
                    "finding-production-replay-guest-asset-bytes",
                )?;
            }
        }
    }
    if let Some(initrd) = &deployment.initrd {
        if initrd.bytes.is_empty() || initrd.identity != ContentHash::from_bytes(&initrd.bytes) {
            return Err(FindingProductionReplayCaptureError::InvalidGuestDeployment);
        }
        if retained_identities.insert(initrd.identity) {
            charge_bytes(
                retained_bytes,
                initrd.bytes.len(),
                limits.max_guest_asset_bytes,
                "finding-production-replay-guest-asset-bytes",
            )?;
        }
    }

    for node in scenario.world().vm_nodes() {
        let assets = deployment
            .guest_assets
            .iter()
            .find(|assets| assets.architecture == node.arch)
            .ok_or(FindingProductionReplayCaptureError::InvalidGuestDeployment)?;
        if node
            .kernel
            .is_some_and(|expected| expected.hash() != assets.kernel.identity)
            || node
                .root_image
                .is_some_and(|expected| expected.hash() != assets.root_image.identity)
            || node.initrd.is_some_and(|expected| {
                deployment
                    .initrd
                    .as_ref()
                    .is_none_or(|initrd| expected.hash() != initrd.identity)
            })
        {
            return Err(FindingProductionReplayCaptureError::InvalidGuestDeployment);
        }
    }
    Ok(())
}

pub(super) fn validate_execution_side(
    side: &FindingProductionReplayExecutionSide,
    scenario: &crucible::ScenarioDefForm,
    recipe: FindingProductionReplayRecipe,
    limits: FindingProductionReplayCaptureLimits,
) -> Result<(), FindingProductionReplayCaptureError> {
    if side.completed_quanta > recipe.lifecycle_quantum_budget
        || side.event_log.len() > limits.max_events_per_side
    {
        return Err(FindingProductionReplayCaptureError::LimitExceeded {
            limit: if side.completed_quanta > recipe.lifecycle_quantum_budget {
                "finding-production-replay-completed-quanta"
            } else {
                "finding-production-replay-event-count"
            },
        });
    }
    validate_event_log_parts(&side.event_log, &[], side.frontier)?;
    let mut event_bytes = 0usize;
    for entry in &side.event_log {
        event_bytes = event_bytes
            .checked_add(entry.canonical_material_len())
            .ok_or(FindingProductionReplayCaptureError::LimitExceeded {
                limit: "finding-production-replay-event-bytes",
            })?;
    }
    if event_bytes > limits.max_event_bytes_per_side {
        return Err(FindingProductionReplayCaptureError::LimitExceeded {
            limit: "finding-production-replay-event-bytes",
        });
    }

    let expected_nodes = scenario
        .world()
        .vm_nodes()
        .iter()
        .map(|node| node.id.clone())
        .collect::<BTreeSet<_>>();
    let actual_nodes = side
        .terminal_fingerprints
        .iter()
        .map(|sample| sample.node.clone())
        .collect::<BTreeSet<_>>();
    if expected_nodes.is_empty()
        || actual_nodes != expected_nodes
        || actual_nodes.len() != side.terminal_fingerprints.len()
        || side
            .terminal_fingerprints
            .iter()
            .any(|sample| sample.at != side.frontier)
    {
        return Err(FindingProductionReplayCaptureError::InvalidTerminalFingerprints);
    }

    let plan = scenario.plan().fault_signals();
    match (plan.programs().is_empty(), &side.resolved_effect_trace) {
        (true, None) => {}
        (false, Some(bytes)) => {
            ResolvedEffectTrace::from_canonical_bytes(bytes, plan.resource_limits())
                .map_err(|_| FindingProductionReplayCaptureError::InvalidResolvedEffectTrace)?;
        }
        (true, Some(_)) | (false, None) => {
            return Err(FindingProductionReplayCaptureError::InvalidResolvedEffectTrace);
        }
    }
    Ok(())
}

pub(super) fn charge_bytes(
    current: u64,
    additional: usize,
    limit: u64,
    limit_name: &'static str,
) -> Result<u64, FindingProductionReplayCaptureError> {
    let additional = u64::try_from(additional)
        .map_err(|_| FindingProductionReplayCaptureError::LimitExceeded { limit: limit_name })?;
    let total = current
        .checked_add(additional)
        .ok_or(FindingProductionReplayCaptureError::LimitExceeded { limit: limit_name })?;
    if total > limit {
        return Err(FindingProductionReplayCaptureError::LimitExceeded { limit: limit_name });
    }
    Ok(total)
}

pub(super) fn validate_lifecycle_objects(
    scenario: &crucible::ScenarioDefForm,
    objects: &BTreeMap<ContentHash, Vec<u8>>,
    limits: FindingProductionReplayCaptureLimits,
) -> Result<(), FindingProductionReplayCaptureError> {
    if objects.len() > limits.max_lifecycle_objects {
        return Err(FindingProductionReplayCaptureError::LimitExceeded {
            limit: "finding-production-replay-lifecycle-object-count",
        });
    }
    let mut total = 0u64;
    for (identity, bytes) in objects {
        if ContentHash::from_bytes(bytes) != *identity {
            return Err(FindingProductionReplayCaptureError::InvalidLifecycleObjects);
        }
        total = charge_bytes(
            total,
            bytes.len(),
            limits.max_lifecycle_bytes,
            "finding-production-replay-lifecycle-bytes",
        )?;
    }
    let memory = MemoryDagStore::new();
    for (identity, bytes) in objects {
        if memory
            .put(bytes)
            .map_err(FindingProductionReplayCaptureError::Store)?
            != *identity
        {
            return Err(FindingProductionReplayCaptureError::InvalidLifecycleObjects);
        }
    }

    let mut expected =
        crucible_api::collect_signal_artifact_objects(scenario.plan().fault_signals(), &memory)
            .map_err(FindingProductionReplayCaptureError::SignalArtifacts)?;
    for node in scenario.world().io_nodes() {
        let identity = match &node.kind {
            crucible::WorldIoNodeKind::Block { base_image, .. } => base_image.hash(),
            crucible::WorldIoNodeKind::NineP { tree, .. } => tree.hash(),
        };
        let bytes = memory
            .get(&identity)
            .map_err(FindingProductionReplayCaptureError::Store)?;
        expected.insert(identity, bytes);
    }
    if expected != *objects {
        return Err(FindingProductionReplayCaptureError::InvalidLifecycleObjects);
    }
    Ok(())
}
