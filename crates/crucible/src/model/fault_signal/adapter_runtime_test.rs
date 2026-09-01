//! Tests extracted from the adjacent production module.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::*;

fn id(value: &str) -> FaultObjectId {
    FaultObjectId::parse(value)
        .unwrap_or_else(|error| panic!("test object ID must be valid: {error}"))
}

fn manifest(adapter: FaultAdapter) -> FaultCapabilityManifest {
    let capabilities = EffectKind::all()
        .iter()
        .filter(|kind| kind.descriptor().adapter == adapter)
        .map(|kind| {
            FaultCapabilityId::parse(kind.descriptor().capability)
                .unwrap_or_else(|error| panic!("registry capability must be valid: {error}"))
        })
        .collect::<BTreeSet<_>>();
    FaultCapabilityManifest {
        backend: id(adapter_name(adapter)),
        capabilities,
        bounds: BTreeMap::new(),
    }
}

fn network_action() -> ResolvedBindingAction {
    let effect = EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        EffectLifetime::Persistent,
        EffectSpecification::Network(NetworkEffectSpecification::Availability {
            state: NetworkAvailabilityState::Down,
            queued_policy: NetworkInFlightPolicy::Drop,
            in_flight_policy: NetworkInFlightPolicy::Drop,
        }),
    )
    .unwrap_or_else(|error| panic!("test effect must be valid: {error}"));
    ResolvedBindingAction {
        kind: BindingActionKind::UpsertPersistent,
        binding: id("outage-binding"),
        target: ResolvedFaultTarget::NetworkSegment {
            segment: id("wan-segment"),
            direction: FaultDirection::AToB,
        },
        phase: FaultPhase::Admit,
        effect: Arc::new(effect),
        mapping_output: Arc::new(ResolvedMappingOutput::Activation { active: true }),
        mapped_digest: ContentHash::from_bytes(b"mapped"),
        transition_sequence: 1,
        opportunity: None,
        coordinate: FaultCoordinate {
            virtual_nanos: 10,
            retired_instructions: None,
        },
        cause: BindingActionCause::Signal,
        expected_precondition: None,
    }
}

fn manifests() -> FaultAdapterManifests {
    FaultAdapterManifests {
        network: manifest(FaultAdapter::Network),
        storage: manifest(FaultAdapter::Storage),
        node: manifest(FaultAdapter::Node),
    }
}

struct TransactionProbe {
    ledger: TransactionalFaultAdapters,
    reject_commit: bool,
    evidence: ContentHash,
}

impl TransactionProbe {
    fn new(reject_commit: bool) -> Self {
        Self {
            ledger: TransactionalFaultAdapters::new(manifests(), FaultResourceLimits::default())
                .unwrap_or_else(|error| panic!("transaction probe: {error}")),
            reject_commit,
            evidence: ContentHash::from_bytes(b"backend-evidence"),
        }
    }
}

impl FaultActionSink for TransactionProbe {
    fn prepare_batch(
        &mut self,
        actions: &[ResolvedBindingAction],
    ) -> Result<PreparedActionBatch, Box<RejectedActionBatch>> {
        self.ledger.prepare_batch(actions)
    }

    fn abort_batch(&mut self, transaction: ContentHash) -> Result<(), FaultRuntimeError> {
        self.ledger.abort_batch(transaction)
    }

    fn commit_batch(
        &mut self,
        transaction: ContentHash,
    ) -> Result<PreparedActionBatch, FaultActionCommitError> {
        if self.reject_commit {
            self.ledger
                .abort_batch(transaction)
                .map_err(FaultActionCommitError::Fatal)?;
            return Err(FaultActionCommitError::Rejected(Box::new(
                RejectedActionBatch {
                    error: FaultRuntimeError::AdapterActionMismatch,
                    observations: Vec::new(),
                    rejected_action: None,
                },
            )));
        }
        let mut committed = self.ledger.commit_batch(transaction)?;
        for result in &mut committed.results {
            result.observation.evidence = self.evidence;
        }
        Ok(committed)
    }
}

#[test]
fn prepared_state_is_invisible_until_commit_and_abort_is_exact() {
    let mut runtime = TransactionalAdapterRuntime::new(
        FaultAdapter::Network,
        manifest(FaultAdapter::Network),
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("adapter runtime: {error}"));
    let initial = runtime.state_digest();
    let action = network_action();
    let prepared = runtime
        .prepare_batch(std::slice::from_ref(&action))
        .unwrap_or_else(|error| panic!("prepare: {}", error.error));
    assert_eq!(runtime.state_digest(), initial);
    assert!(runtime.composition_groups().is_empty());
    runtime
        .abort_batch(prepared.transaction)
        .unwrap_or_else(|error| panic!("abort: {error}"));
    assert_eq!(runtime.state_digest(), initial);

    let prepared = runtime
        .prepare_batch(&[action])
        .unwrap_or_else(|error| panic!("prepare again: {}", error.error));
    runtime
        .commit_batch(prepared.transaction)
        .unwrap_or_else(|error| panic!("commit: {error}"));
    assert_ne!(runtime.state_digest(), initial);
    assert_eq!(runtime.composition_groups().len(), 1);
}

#[test]
fn capability_and_cross_adapter_checks_fail_before_staging() {
    let mut missing = manifest(FaultAdapter::Network);
    missing.capabilities.clear();
    let mut runtime = TransactionalAdapterRuntime::new(
        FaultAdapter::Network,
        missing,
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("adapter runtime: {error}"));
    let action = network_action();
    let rejection = match runtime.prepare_batch(&[action]) {
        Ok(_) => panic!("missing capability must reject"),
        Err(rejection) => rejection,
    };
    assert!(matches!(
        rejection.error,
        FaultRuntimeError::MissingCapability(_)
    ));
    assert!(runtime.composition_groups().is_empty());
}

#[test]
fn checkpoint_round_trip_revalidates_live_capabilities() {
    let mut runtime = TransactionalAdapterRuntime::new(
        FaultAdapter::Network,
        manifest(FaultAdapter::Network),
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("adapter runtime: {error}"));
    let action = network_action();
    let prepared = runtime
        .prepare_batch(&[action])
        .unwrap_or_else(|error| panic!("prepare: {}", error.error));
    runtime
        .commit_batch(prepared.transaction)
        .unwrap_or_else(|error| panic!("commit: {error}"));

    let checkpoint = runtime
        .checkpoint()
        .unwrap_or_else(|error| panic!("checkpoint: {error}"));
    let restored = TransactionalAdapterRuntime::restore(
        FaultAdapter::Network,
        manifest(FaultAdapter::Network),
        &checkpoint,
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("restore: {error}"));
    assert_eq!(restored, runtime);

    let different_limits = FaultResourceLimits {
        active_contributions_per_target: 1,
        ..FaultResourceLimits::default()
    };
    assert_eq!(
        TransactionalAdapterRuntime::restore(
            FaultAdapter::Network,
            manifest(FaultAdapter::Network),
            &checkpoint,
            different_limits,
        ),
        Err(FaultRuntimeError::VersionOrIdentityMismatch)
    );

    let mut insufficient = manifest(FaultAdapter::Network);
    insufficient.capabilities.clear();
    assert!(matches!(
        TransactionalAdapterRuntime::restore(
            FaultAdapter::Network,
            insufficient,
            &checkpoint,
            FaultResourceLimits::default(),
        ),
        Err(FaultRuntimeError::AdapterActionMismatch)
    ));

    let mut corrupt = checkpoint;
    corrupt.bytes.push(b' ');
    assert_eq!(
        TransactionalAdapterRuntime::restore(
            FaultAdapter::Network,
            manifest(FaultAdapter::Network),
            &corrupt,
            FaultResourceLimits::default(),
        ),
        Err(FaultRuntimeError::AdapterCheckpointDigest)
    );
}

#[test]
fn mirrored_sink_returns_backend_evidence_and_commits_both_views() {
    let mut state = TransactionalFaultAdapters::new(manifests(), FaultResourceLimits::default())
        .unwrap_or_else(|error| panic!("adapter state: {error}"));
    let mut backend = TransactionProbe::new(false);
    let expected_evidence = backend.evidence;
    let action = network_action();
    let mut sink = MirroredFaultActionSink::new(&mut state, &mut backend);
    let prepared = sink
        .prepare_batch(&[action])
        .unwrap_or_else(|error| panic!("prepare: {}", error.error));
    let committed = sink
        .commit_batch(prepared.transaction)
        .unwrap_or_else(|error| panic!("commit: {error}"));
    assert_eq!(committed.results[0].observation.evidence, expected_evidence);
    assert_eq!(
        state
            .adapter(FaultAdapter::Network)
            .composition_groups()
            .len(),
        1
    );
    assert_eq!(
        backend
            .ledger
            .adapter(FaultAdapter::Network)
            .composition_groups()
            .len(),
        1
    );
}

#[test]
fn mirrored_sink_restores_canonical_state_after_backend_commit_rejection() {
    let mut state = TransactionalFaultAdapters::new(manifests(), FaultResourceLimits::default())
        .unwrap_or_else(|error| panic!("adapter state: {error}"));
    let before = state.clone();
    let mut backend = TransactionProbe::new(true);
    let action = network_action();
    let mut sink = MirroredFaultActionSink::new(&mut state, &mut backend);
    let prepared = sink
        .prepare_batch(&[action])
        .unwrap_or_else(|error| panic!("prepare: {}", error.error));
    let rejection = match sink.commit_batch(prepared.transaction) {
        Ok(_) => panic!("backend commit must reject"),
        Err(FaultActionCommitError::Rejected(rejection)) => rejection,
        Err(FaultActionCommitError::Fatal(error)) => {
            panic!("backend rejection must not be fatal: {error}")
        }
    };
    assert_eq!(rejection.error, FaultRuntimeError::AdapterActionMismatch);
    assert_eq!(state, before);
    assert!(
        backend
            .ledger
            .adapter(FaultAdapter::Network)
            .composition_groups()
            .is_empty()
    );
}

#[test]
fn host_state_evidence_excludes_locked_replay_authorization() {
    let limits = FaultResourceLimits::default();
    let recorded_action = network_action();
    let mut recorded_sink = HostFaultActionSink::new(limits);
    let recorded_prepared = recorded_sink
        .prepare_batch(std::slice::from_ref(&recorded_action))
        .unwrap_or_else(|error| panic!("recorded prepare: {}", error.error));
    let recorded = recorded_sink
        .commit_batch(recorded_prepared.transaction)
        .unwrap_or_else(|error| panic!("recorded commit: {error}"));

    let mut replay_action = recorded_action.clone();
    replay_action.expected_precondition = recorded.results[0].precondition;
    assert_ne!(replay_action.id(), recorded_action.id());
    assert_eq!(
        replay_action.committed_state_id(),
        recorded_action.committed_state_id()
    );

    let mut replay_sink = HostFaultActionSink::new(limits);
    let replay_prepared = replay_sink
        .prepare_batch(std::slice::from_ref(&replay_action))
        .unwrap_or_else(|error| panic!("replay prepare: {}", error.error));
    let replay = replay_sink
        .commit_batch(replay_prepared.transaction)
        .unwrap_or_else(|error| panic!("replay commit: {error}"));

    assert_eq!(
        replay.results[0].observation.evidence,
        recorded.results[0].observation.evidence
    );
    assert_eq!(replay_sink.state().digest(), recorded_sink.state().digest());
}
