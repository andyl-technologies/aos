//! One-shot Network preparation execution and finalization.
//!
//! This module closes the internal preparation transaction without advertising
//! Network Apply. A fresh execution consumes the only `Prepared -> Ambiguous`
//! permit before a worker dispatch can exist. Once the worker has established
//! systemd custody and proved whole-unit quiescence, finalization independently
//! observes the retained namespace twice, commits that exact physical result,
//! and publishes it only through the fixed-pin namespace catalog.
//!
//! Recovery never recreates a worker dispatch. An ambiguous operation may only
//! be reconciled by retained-descriptor observation, while an already committed
//! result may only be projected into the namespace catalog.

use aos_sandbox_core::{ObjectDigest, RawPairedClockSample};
use aos_sandbox_linux::pidfd::{NamespaceFd, SingleThreadedProcess};
use sha2::{Digest as _, Sha256};

use crate::PreparedNetworkObservationV1;
use crate::authorization::NetworkAdmissionError;
use crate::broker::{
    NetworkBrokerError, NetworkLifecycleAdmissionCoordinator, NetworkPrepareExecutionOutcomeV1,
};
use crate::catalog::ResolvedNetworkPreparationV1;
use crate::kernel_observation::NetworkKernelObservationV1;
use crate::kernel_plan::NetworkKernelPlanV1;
use crate::namespace_catalog::{
    NetworkNamespaceCatalogError, NetworkNamespaceCatalogOutcomeV1, NetworkNamespaceCatalogV1,
};
use crate::namespace_observer::{
    NetworkKernelObservationReaders, NetworkNamespaceObserverError,
    StableNetworkKernelObservationV1, observe_stable_prepared_network_kernel,
    observe_stable_recovered_network_kernel,
};
use crate::preparation_catalog::NetworkPreparationCatalogV1;
use crate::state::{CommittedNetworkResultV1, NetworkStateError, VerifiedNetworkResultV1};
use crate::worker_runtime::PreparedNetworkWorkerOutput;
use crate::worker_runtime::RecoveredNetworkPreparationObservation;

/// Reports a rejected preparation transition, observation, commit, or publication.
#[derive(Debug, thiserror::Error)]
pub enum NetworkPreparationRuntimeError {
    /// Durable broker state or authenticated dispatch construction failed.
    #[error(transparent)]
    Broker(#[from] NetworkBrokerError),
    /// Independent retained-descriptor observation failed.
    #[error(transparent)]
    Observer(#[from] NetworkNamespaceObserverError),
    /// The observation could not form an exact durable result.
    #[error(transparent)]
    State(#[from] NetworkStateError),
    /// Fixed-pin validation or namespace catalog publication failed.
    #[error(transparent)]
    NamespaceCatalog(#[from] NetworkNamespaceCatalogError),
    /// The observation worker proof did not match the retained preparation.
    #[error("Network observation worker proof did not match durable preparation custody")]
    ObservationProof,
}

/// Carries the exact inputs needed to finalize one quiescent preparation worker.
#[derive(Clone, Copy)]
pub struct NetworkPreparationFinalizationInput<'a> {
    request_body: &'a [u8],
    resolution: &'a ResolvedNetworkPreparationV1,
    kernel_plan: &'a NetworkKernelPlanV1,
    worker_output: &'a PreparedNetworkWorkerOutput,
}

impl<'a> NetworkPreparationFinalizationInput<'a> {
    /// Binds the durable request, protected resolution, plan, and worker result.
    #[must_use]
    pub const fn new(
        request_body: &'a [u8],
        resolution: &'a ResolvedNetworkPreparationV1,
        kernel_plan: &'a NetworkKernelPlanV1,
        worker_output: &'a PreparedNetworkWorkerOutput,
    ) -> Self {
        Self {
            request_body,
            resolution,
            kernel_plan,
            worker_output,
        }
    }
}

/// Carries the exact inputs needed to observe an ambiguous preparation recovery.
#[derive(Clone, Copy)]
pub struct NetworkPreparationRecoveryInput<'a> {
    request_id: [u8; 16],
    effect_digest: ObjectDigest,
    request_body: &'a [u8],
    resolution: &'a ResolvedNetworkPreparationV1,
    kernel_plan: &'a NetworkKernelPlanV1,
    namespace: &'a NamespaceFd,
}

impl<'a> NetworkPreparationRecoveryInput<'a> {
    /// Binds an ambiguous journal identity to its retained observation inputs.
    #[must_use]
    pub const fn new(
        request_id: [u8; 16],
        effect_digest: ObjectDigest,
        request_body: &'a [u8],
        resolution: &'a ResolvedNetworkPreparationV1,
        kernel_plan: &'a NetworkKernelPlanV1,
        namespace: &'a NamespaceFd,
    ) -> Self {
        Self {
            request_id,
            effect_digest,
            request_body,
            resolution,
            kernel_plan,
            namespace,
        }
    }
}

#[derive(Clone, Copy)]
struct DurableObservationBindings<'a> {
    request_id: [u8; 16],
    effect_digest: ObjectDigest,
    request_body: &'a [u8],
    resolution: &'a ResolvedNetworkPreparationV1,
    kernel_boot_id: [u8; 16],
    namespace_device: u64,
    namespace_inode: u64,
    kernel_plan_digest: ObjectDigest,
}

/// Reports the durable and catalog effects of one finalized preparation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizedNetworkPreparationV1 {
    observation: NetworkKernelObservationV1,
    observation_digest: ObjectDigest,
    result: CommittedNetworkResultV1,
    publication: NetworkNamespaceCatalogOutcomeV1,
}

/// Reports durable commit and publication from a separated observation worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalizedNetworkPreparationCommitV1 {
    observation_digest: ObjectDigest,
    result: CommittedNetworkResultV1,
    publication: NetworkNamespaceCatalogOutcomeV1,
}

impl FinalizedNetworkPreparationCommitV1 {
    /// Returns the stable complete-observation commitment.
    #[must_use]
    pub const fn observation_digest(self) -> ObjectDigest {
        self.observation_digest
    }

    /// Returns the exact durable creation result.
    #[must_use]
    pub const fn result(self) -> CommittedNetworkResultV1 {
        self.result
    }

    /// Returns whether catalog publication was new or an exact replay.
    #[must_use]
    pub const fn publication(self) -> NetworkNamespaceCatalogOutcomeV1 {
        self.publication
    }
}

impl FinalizedNetworkPreparationV1 {
    /// Returns the complete independently validated kernel observation.
    #[must_use]
    pub const fn observation(&self) -> &NetworkKernelObservationV1 {
        &self.observation
    }

    /// Returns the stable observation commitment.
    #[must_use]
    pub const fn observation_digest(&self) -> ObjectDigest {
        self.observation_digest
    }

    /// Returns the exact durable creation result.
    #[must_use]
    pub const fn result(&self) -> CommittedNetworkResultV1 {
        self.result
    }

    /// Returns whether catalog publication was new or an exact replay.
    #[must_use]
    pub const fn publication(&self) -> NetworkNamespaceCatalogOutcomeV1 {
        self.publication
    }
}

/// Prevalidates and consumes one fresh preparation into a worker dispatch.
///
/// This is the only production preparation entry point that can release effect
/// authority. All caller-controlled request, plan, catalog, and dispatch
/// validation completes before the clock sample or durable transition. Expired
/// authority becomes an authenticated Aborted tombstone without a dispatch.
///
/// # Errors
///
/// Returns [`NetworkPreparationRuntimeError`] unless the exact request remains
/// Prepared, its complete prospective dispatch authenticates, the clock has
/// valid continuity, and the terminal journal transition succeeds.
pub fn begin_network_preparation_once<F>(
    coordinator: &mut NetworkLifecycleAdmissionCoordinator,
    request_id: [u8; 16],
    effect_digest: ObjectDigest,
    request_body: &[u8],
    kernel_plan: NetworkKernelPlanV1,
    trusted_clock: &mut F,
) -> Result<NetworkPrepareExecutionOutcomeV1, NetworkPreparationRuntimeError>
where
    F: FnMut() -> Result<RawPairedClockSample, NetworkAdmissionError>,
{
    coordinator
        .begin_prepare_effect_once(
            request_id,
            effect_digest,
            request_body,
            kernel_plan,
            trusted_clock,
        )
        .map_err(Into::into)
}

/// Observes, commits, and publishes one wholly quiescent preparation result.
///
/// [`PreparedNetworkWorkerOutput`] is constructible only by the one-shot worker
/// executor after confirmed systemd custody and whole-cgroup quiescence. The
/// observer then takes two independent complete snapshots before this function
/// can commit or publish anything. Namespace publication performs a fresh
/// fixed-pin device/inode check.
///
/// # Errors
///
/// Returns [`NetworkPreparationRuntimeError`] for substituted worker authority,
/// either failed or unequal observation, a durable tuple mismatch, an absent or
/// changed fixed pin, or a conflicting namespace catalog row. Once the durable
/// commit succeeds, retry with [`publish_committed_network_preparation`] rather
/// than attempting to execute or commit the worker again.
#[allow(clippy::too_many_arguments)]
pub fn finalize_executed_network_preparation(
    coordinator: &mut NetworkLifecycleAdmissionCoordinator,
    preparations: &NetworkPreparationCatalogV1,
    namespaces: &mut NetworkNamespaceCatalogV1,
    readers: NetworkKernelObservationReaders<'_>,
    input: NetworkPreparationFinalizationInput<'_>,
    initial_host_namespace: &NamespaceFd,
    observer: &SingleThreadedProcess,
) -> Result<FinalizedNetworkPreparationV1, NetworkPreparationRuntimeError> {
    let namespace_identity = input.worker_output.namespace().identity();
    let bindings = DurableObservationBindings {
        request_id: input.worker_output.request_id(),
        effect_digest: input.worker_output.effect_digest(),
        request_body: input.request_body,
        resolution: input.resolution,
        kernel_boot_id: input.worker_output.kernel_boot_id(),
        namespace_device: namespace_identity.device,
        namespace_inode: namespace_identity.inode,
        kernel_plan_digest: input.worker_output.kernel_plan_digest(),
    };

    finalize_observed_network_preparation(coordinator, preparations, namespaces, bindings, || {
        observe_stable_prepared_network_kernel(
            readers,
            input.kernel_plan,
            input.worker_output,
            initial_host_namespace,
            observer,
        )
    })
}

/// Commits and publishes one capability-separated observation-worker proof.
///
/// The proof is constructible only after the fixed observer authenticates the
/// broker, retypes both namespace descriptors, validates the canonical plan,
/// obtains two equal complete snapshots, and wholly exits its systemd cgroup.
/// This function rebinds every durable and physical field before committing.
///
/// # Errors
///
/// Returns [`NetworkPreparationRuntimeError::ObservationProof`] when any proof
/// field differs from the quiescent effect-worker output or canonical plan, and
/// otherwise propagates durable commit or fixed-pin publication failures.
pub fn finalize_observation_worker_preparation(
    coordinator: &mut NetworkLifecycleAdmissionCoordinator,
    preparations: &NetworkPreparationCatalogV1,
    namespaces: &mut NetworkNamespaceCatalogV1,
    input: NetworkPreparationFinalizationInput<'_>,
    proof: PreparedNetworkObservationV1,
) -> Result<FinalizedNetworkPreparationCommitV1, NetworkPreparationRuntimeError> {
    let namespace_identity = input.worker_output.namespace().identity();
    if proof.request_id() != input.worker_output.request_id()
        || proof.effect_digest() != input.worker_output.effect_digest()
        || proof.kernel_plan_digest() != input.worker_output.kernel_plan_digest()
        || proof.kernel_plan_digest() != input.kernel_plan.digest()
        || proof.kernel_boot_id() != input.worker_output.kernel_boot_id()
        || proof.namespace() != namespace_identity
        || proof.observed_state() != crate::NetworkNamespaceObservedStateV1::default_drop()
    {
        return Err(NetworkPreparationRuntimeError::ObservationProof);
    }

    let verified = VerifiedNetworkResultV1::verify_preparation(
        proof.request_id(),
        ObjectDigest::from_bytes(Sha256::digest(input.request_body).into()),
        input.resolution,
        proof.kernel_boot_id(),
        namespace_identity.device,
        namespace_identity.inode,
        proof.kernel_plan_digest(),
        proof.observation_digest(),
    )?;
    let result = coordinator.commit_verified_preparation(
        proof.request_id(),
        proof.effect_digest(),
        verified,
    )?;
    let publication =
        publish_committed_network_preparation(coordinator, preparations, namespaces, result)?;

    Ok(FinalizedNetworkPreparationCommitV1 {
        observation_digest: proof.observation_digest(),
        result,
        publication,
    })
}

/// Re-observes, commits, and publishes one ambiguous preparation after restart.
///
/// The coordinator derives a read-only observation token from the exact
/// ambiguous journal row and its matching retained namespace descriptor. This
/// path has no API that can mint or transmit another worker dispatch.
///
/// # Errors
///
/// Returns [`NetworkPreparationRuntimeError`] unless durable custody exactly
/// matches the current descriptor and plan, both complete observations agree,
/// the result commits against the original request and effect, and fixed-pin
/// catalog publication succeeds.
#[allow(clippy::too_many_arguments)]
pub fn finalize_recovered_ambiguous_network_preparation(
    coordinator: &mut NetworkLifecycleAdmissionCoordinator,
    preparations: &NetworkPreparationCatalogV1,
    namespaces: &mut NetworkNamespaceCatalogV1,
    readers: NetworkKernelObservationReaders<'_>,
    input: NetworkPreparationRecoveryInput<'_>,
    initial_host_namespace: &NamespaceFd,
    observer: &SingleThreadedProcess,
) -> Result<FinalizedNetworkPreparationV1, NetworkPreparationRuntimeError> {
    let recovered: RecoveredNetworkPreparationObservation<'_> = coordinator
        .recover_ambiguous_preparation_observation(
            input.request_id,
            input.effect_digest,
            input.namespace,
        )?;
    let namespace_identity = recovered.namespace().identity();
    let bindings = DurableObservationBindings {
        request_id: recovered.request_id(),
        effect_digest: recovered.effect_digest(),
        request_body: input.request_body,
        resolution: input.resolution,
        kernel_boot_id: recovered.kernel_boot_id(),
        namespace_device: namespace_identity.device,
        namespace_inode: namespace_identity.inode,
        kernel_plan_digest: recovered.kernel_plan_digest(),
    };

    finalize_observed_network_preparation(coordinator, preparations, namespaces, bindings, || {
        observe_stable_recovered_network_kernel(
            readers,
            input.kernel_plan,
            recovered,
            initial_host_namespace,
            observer,
        )
    })
}

fn finalize_observed_network_preparation(
    coordinator: &mut NetworkLifecycleAdmissionCoordinator,
    preparations: &NetworkPreparationCatalogV1,
    namespaces: &mut NetworkNamespaceCatalogV1,
    bindings: DurableObservationBindings<'_>,
    observe: impl FnOnce() -> Result<StableNetworkKernelObservationV1, NetworkNamespaceObserverError>,
) -> Result<FinalizedNetworkPreparationV1, NetworkPreparationRuntimeError> {
    let mut context = (coordinator, preparations, namespaces);
    let (observation, result, publication) = run_finalization_sequence(
        &mut context,
        |_| observe().map_err(Into::into),
        |context, observation| {
            let verified = VerifiedNetworkResultV1::verify_preparation(
                bindings.request_id,
                ObjectDigest::from_bytes(Sha256::digest(bindings.request_body).into()),
                bindings.resolution,
                bindings.kernel_boot_id,
                bindings.namespace_device,
                bindings.namespace_inode,
                bindings.kernel_plan_digest,
                observation.digest(),
            )?;

            context
                .0
                .commit_verified_preparation(bindings.request_id, bindings.effect_digest, verified)
                .map_err(Into::into)
        },
        |context, result| {
            publish_committed_network_preparation(context.0, context.1, context.2, result)
        },
    )?;

    Ok(FinalizedNetworkPreparationV1 {
        observation: observation.observation().clone(),
        observation_digest: observation.digest(),
        result,
        publication,
    })
}

fn run_finalization_sequence<Context, Observation, Committed, Publication, Error>(
    context: &mut Context,
    observe: impl FnOnce(&mut Context) -> Result<Observation, Error>,
    commit: impl FnOnce(&mut Context, &Observation) -> Result<Committed, Error>,
    publish: impl FnOnce(&mut Context, Committed) -> Result<Publication, Error>,
) -> Result<(Observation, Committed, Publication), Error>
where
    Committed: Copy,
{
    let observation = observe(context)?;
    let committed = commit(context, &observation)?;
    let publication = publish(context, committed)?;

    Ok((observation, committed, publication))
}

/// Publishes one exact committed preparation without recreating effect authority.
///
/// This is the crash-recovery continuation after the observation commit. The
/// coordinator must reproduce the protected resolution and portable assignment,
/// and the namespace catalog independently reopens the fixed pin before either
/// a new publication or an exact replay can succeed.
///
/// # Errors
///
/// Returns [`NetworkPreparationRuntimeError`] when the committed result is not
/// current, its protected preparation changed, its fixed pin is absent or was
/// substituted, or its namespace catalog row conflicts.
pub fn publish_committed_network_preparation(
    coordinator: &NetworkLifecycleAdmissionCoordinator,
    preparations: &NetworkPreparationCatalogV1,
    namespaces: &mut NetworkNamespaceCatalogV1,
    result: CommittedNetworkResultV1,
) -> Result<NetworkNamespaceCatalogOutcomeV1, NetworkPreparationRuntimeError> {
    let publication = coordinator.namespace_publication(result, preparations)?;

    namespaces.publish(publication).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::cell::Cell;
    use std::fs;
    use std::num::NonZeroU32;
    use std::os::unix::fs::MetadataExt as _;
    use std::path::PathBuf;

    use aos_proto::aos::sandbox::local::v1::{ApplyNetworkRequest, Audience, NetworkAction};
    use aos_sandbox_core::format::encode_sandbox_spec;
    use aos_sandbox_core::model::{
        AssignmentManifestV1, IdentityProfile, NetworkKind, NetworkProfile, ResourceProfile,
        SandboxAncestry, UnmappableIdentityPolicy,
    };
    use aos_sandbox_core::{
        AssignmentEpoch, CanonicalAssignmentManifestV1, DesiredGeneration, FeatureRef,
        IncarnationId, MediaType, NamespaceGeneration, NodeId, ObjectDescriptor, PortableMediaType,
        ProjectId, ProtocolVersion, RawClockProvenance, RawPairedClockSample, ResourceVector,
        SandboxId, descriptor_for_bytes,
    };
    use aos_sandbox_linux::boot::KernelBootId;
    use aos_sandbox_protocol::{PeerCredentials, PeerPolicy};
    use buffa::Message as _;
    use tempfile::TempDir;

    use super::*;
    use crate::broker::tests::Fixture;
    use crate::{
        DurableNetworkPhase, NetworkAdmissionOutcome, NetworkAllocationPolicyV1,
        NetworkLifecycleStateStore, NetworkNamespaceCatalogV1, NetworkPolicyCatalogV1,
        NetworkPolicyProfileV1, NetworkPolicyProgramV1, NetworkPreparationCatalogOutcomeV1,
        NetworkPreparationReservationV1, NetworkStateStore,
    };

    const NODE: NodeId = NodeId::from_bytes([31; 16]);
    const REQUEST_ID: [u8; 16] = [7; 16];
    const TEST_BOOT_ID: [u8; 16] = [50; 16];

    struct RealFinalizationCase {
        _root: TempDir,
        fixture: Fixture,
        operation_directory: PathBuf,
        lifecycle_directory: PathBuf,
        namespace_directory: PathBuf,
        pin_directory: PathBuf,
        pin_path: PathBuf,
        preparations: NetworkPreparationCatalogV1,
        namespaces: Option<NetworkNamespaceCatalogV1>,
        coordinator: Option<NetworkLifecycleAdmissionCoordinator>,
        request: Vec<u8>,
        resolution: ResolvedNetworkPreparationV1,
        plan: NetworkKernelPlanV1,
        effect_digest: ObjectDigest,
        pin_device: u64,
        pin_inode: u64,
    }

    impl RealFinalizationCase {
        fn new() -> Self {
            let root = TempDir::new().unwrap();
            let preparation_directory = root.path().join("preparation");
            let operation_directory = root.path().join("operations");
            let lifecycle_directory = root.path().join("lifecycle");
            let namespace_directory = root.path().join("namespaces");
            let pin_directory = root.path().join("pins");
            for directory in [
                &preparation_directory,
                &operation_directory,
                &lifecycle_directory,
                &namespace_directory,
                &pin_directory,
            ] {
                fs::create_dir(directory).unwrap();
            }

            let fixture = Fixture::new();
            let authority = fixture.authority();
            let profile =
                NetworkProfile::new(NetworkKind::Isolated, Vec::new(), Vec::new()).unwrap();
            let program = NetworkPolicyProgramV1::new(
                NetworkKind::Isolated,
                ObjectDigest::from_bytes([81; 32]),
                None,
                Vec::new(),
            )
            .unwrap();
            let policy = NetworkPolicyCatalogV1::new(
                NODE,
                1,
                vec![
                    NetworkPolicyProfileV1::new(
                        profile.clone(),
                        program,
                        NetworkAllocationPolicyV1::isolated(),
                    )
                    .unwrap(),
                ],
            )
            .unwrap();
            let spec = sandbox_spec(profile);
            let manifest = assignment_manifest(&spec);
            let assignment = manifest.broker_assignment().unwrap();
            let reservation = NetworkPreparationReservationV1::new(&manifest, &spec).unwrap();
            let mut preparations =
                NetworkPreparationCatalogV1::open_for_test(&preparation_directory, policy, 1)
                    .unwrap();
            let prepared = preparations.reserve(reservation, &authority).unwrap();
            assert!(matches!(
                prepared,
                NetworkPreparationCatalogOutcomeV1::Reserved(_)
            ));
            let resolution = prepared.preparation().resolution().clone();
            let handle = *resolution.reserved_network_handle();
            let namespace_plan = preparations
                .plan_for_resolution(handle, &resolution)
                .unwrap();
            let program = preparations
                .program_for_resolution(handle, &resolution)
                .unwrap();
            let plan = NetworkKernelPlanV1::compile(assignment, namespace_plan, program).unwrap();
            let request = prepare_request(assignment);
            let creation =
                NetworkStateStore::open_for_test(&operation_directory, &authority, 0).unwrap();
            let lifecycle =
                NetworkLifecycleStateStore::open_for_test(&lifecycle_directory, &authority)
                    .unwrap();
            let mut coordinator =
                NetworkLifecycleAdmissionCoordinator::new(authority, creation, lifecycle);
            let NetworkAdmissionOutcome::Prepared { effect_digest } = coordinator
                .admit_apply_intent(
                    &request,
                    &fixture.artifacts(&request),
                    prepared.preparation(),
                    ProtocolVersion::new(1, 0),
                    peer(),
                    peer_policy(),
                    &clock(),
                )
                .unwrap()
            else {
                panic!("runtime fixture did not prepare a fresh operation");
            };

            let pin_path = pin_directory.join(encode_handle(&handle));
            fs::File::create(&pin_path).unwrap();
            let pin_metadata = fs::metadata(&pin_path).unwrap();
            let namespaces = NetworkNamespaceCatalogV1::open_for_test(
                &namespace_directory,
                &pin_directory,
                TEST_BOOT_ID,
                [91; 16],
            )
            .unwrap();

            Self {
                _root: root,
                fixture,
                operation_directory,
                lifecycle_directory,
                namespace_directory,
                pin_directory,
                pin_path,
                preparations,
                namespaces: Some(namespaces),
                coordinator: Some(coordinator),
                request,
                resolution,
                plan,
                effect_digest,
                pin_device: pin_metadata.dev(),
                pin_inode: pin_metadata.ino(),
            }
        }

        fn coordinator(&self) -> &NetworkLifecycleAdmissionCoordinator {
            self.coordinator.as_ref().unwrap()
        }

        fn coordinator_mut(&mut self) -> &mut NetworkLifecycleAdmissionCoordinator {
            self.coordinator.as_mut().unwrap()
        }

        fn namespaces(&self) -> &NetworkNamespaceCatalogV1 {
            self.namespaces.as_ref().unwrap()
        }

        fn begin(&mut self) {
            let request = self.request.clone();
            let plan = self.plan.clone();
            let effect_digest = self.effect_digest;
            let outcome = begin_network_preparation_once(
                self.coordinator_mut(),
                REQUEST_ID,
                effect_digest,
                &request,
                plan,
                &mut || Ok(clock()),
            )
            .unwrap();
            assert!(matches!(
                outcome,
                NetworkPrepareExecutionOutcomeV1::Dispatch(_)
            ));
        }

        fn bind_pin_custody(&mut self) {
            let effect_digest = self.effect_digest;
            let handle = *self.resolution.reserved_network_handle();
            let plan_digest = self.plan.digest();
            let device = self.pin_device;
            let inode = self.pin_inode;
            self.coordinator_mut()
                .bind_effect_namespace_custody(
                    REQUEST_ID,
                    effect_digest,
                    handle,
                    TEST_BOOT_ID,
                    device,
                    inode,
                    plan_digest,
                )
                .unwrap();
        }

        fn commit(&mut self, observation_digest: ObjectDigest) -> CommittedNetworkResultV1 {
            let verified = VerifiedNetworkResultV1::verify_preparation(
                REQUEST_ID,
                ObjectDigest::from_bytes(Sha256::digest(&self.request).into()),
                &self.resolution,
                TEST_BOOT_ID,
                self.pin_device,
                self.pin_inode,
                self.plan.digest(),
                observation_digest,
            )
            .unwrap();
            let effect_digest = self.effect_digest;

            self.coordinator_mut()
                .commit_verified_preparation(REQUEST_ID, effect_digest, verified)
                .unwrap()
        }

        fn reopen_coordinator(&mut self) {
            drop(self.coordinator.take());
            let authority = self.fixture.authority();
            let creation =
                NetworkStateStore::open_for_test(&self.operation_directory, &authority, 0).unwrap();
            let lifecycle =
                NetworkLifecycleStateStore::open_for_test(&self.lifecycle_directory, &authority)
                    .unwrap();
            self.coordinator = Some(NetworkLifecycleAdmissionCoordinator::new(
                authority, creation, lifecycle,
            ));
        }

        fn reopen_namespaces(&mut self) {
            drop(self.namespaces.take());
            self.namespaces = Some(
                NetworkNamespaceCatalogV1::open_for_test(
                    &self.namespace_directory,
                    &self.pin_directory,
                    TEST_BOOT_ID,
                    [92; 16],
                )
                .unwrap(),
            );
        }

        fn assert_no_catalog_row(&self) {
            assert!(
                self.namespaces()
                    .current_namespace_identity(*self.resolution.reserved_network_handle())
                    .is_err()
            );
        }
    }

    fn descriptor(kind: PortableMediaType, marker: u8) -> ObjectDescriptor {
        ObjectDescriptor::new(
            MediaType::new(kind.as_str().to_owned()).unwrap(),
            ObjectDigest::from_bytes([marker; 32]),
            u64::from(marker) + 1,
        )
    }

    fn sandbox_spec(network_profile: NetworkProfile) -> aos_sandbox_core::model::SandboxSpec {
        aos_sandbox_core::model::SandboxSpec::new(
            FeatureRef::new("aos.sandbox.runtime.linux-systemd", 1, 0).unwrap(),
            IdentityProfile::PrivateUserns {
                id_range_size: NonZeroU32::new(65_536).unwrap(),
                unmappable_policy: UnmappableIdentityPolicy::Reject,
                required_features: Vec::new(),
            },
            ResourceProfile::new(Vec::new()).unwrap(),
            descriptor(PortableMediaType::Environment, 71),
            descriptor(PortableMediaType::View, 72),
            Vec::new(),
            network_profile,
            Vec::new(),
        )
        .unwrap()
    }

    fn assignment_manifest(
        spec: &aos_sandbox_core::model::SandboxSpec,
    ) -> CanonicalAssignmentManifestV1 {
        let spec_bytes = encode_sandbox_spec(spec);
        let spec_descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::SandboxSpec.as_str().to_owned()).unwrap(),
            &spec_bytes,
        );
        CanonicalAssignmentManifestV1::new(
            AssignmentManifestV1::new(
                SandboxId::from_bytes([2; 16]),
                ProjectId::from_bytes([4; 16]),
                SandboxAncestry::new(SandboxId::from_bytes([2; 16]), Vec::new()).unwrap(),
                IncarnationId::from_bytes([3; 16]),
                NODE,
                AssignmentEpoch::new(4),
                DesiredGeneration::new(5),
                NamespaceGeneration::new(6),
                spec_descriptor,
                descriptor(PortableMediaType::Policy, 70),
                spec.environment().clone(),
                spec.root_view().clone(),
                Vec::new(),
                ObjectDigest::from_bytes([73; 32]),
                ResourceVector::ZERO,
                Vec::new(),
            )
            .unwrap(),
        )
    }

    fn prepare_request(assignment: aos_sandbox_core::BrokerAssignment) -> Vec<u8> {
        let mut request = ApplyNetworkRequest::default();
        let header = request.header.get_or_insert_default();
        header.protocol_major = 1;
        header.protocol_minor = 0;
        header.request_id = REQUEST_ID.to_vec();
        header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
        header.deadline_boottime_nanoseconds = 180;
        header.maximum_response_bytes = 4096;
        let fence = request.fence.get_or_insert_default();
        fence.sandbox_id = assignment.sandbox().as_bytes().to_vec();
        fence.incarnation_id = assignment.incarnation().as_bytes().to_vec();
        fence.assignment_epoch = assignment.epoch().get();
        fence.desired_generation = assignment.desired_generation().get();
        fence.assignment_digest = assignment.digest().as_bytes().to_vec();
        request.action = NetworkAction::NETWORK_ACTION_PREPARE.into();
        request.encode_to_vec()
    }

    fn peer() -> PeerCredentials {
        PeerCredentials {
            uid: 100,
            gid: 200,
            pid: Some(300),
        }
    }

    fn peer_policy() -> PeerPolicy {
        PeerPolicy {
            uid: 100,
            gid: Some(200),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        }
    }

    fn clock() -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            TEST_BOOT_ID,
            150,
            100,
        )
        .unwrap()
    }

    fn encode_handle(handle: &[u8; 32]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";

        let mut output = String::with_capacity(64);
        for byte in handle {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Boundary {
        FirstObservation,
        SecondObservation,
        Commit,
        PinVerification,
        Publication,
    }

    #[derive(Default)]
    struct SequenceCounts {
        observations: Cell<usize>,
        commits: Cell<usize>,
        publications: Cell<usize>,
    }

    fn exercise_sequence(
        failure: Option<Boundary>,
        counts: &mut SequenceCounts,
    ) -> Result<(usize, usize, usize), Boundary> {
        run_finalization_sequence(
            counts,
            |counts| {
                for boundary in [Boundary::FirstObservation, Boundary::SecondObservation] {
                    if failure == Some(boundary) {
                        return Err(boundary);
                    }
                    counts.observations.set(counts.observations.get() + 1);
                }
                Ok(counts.observations.get())
            },
            |counts, observations| {
                if failure == Some(Boundary::Commit) {
                    return Err(Boundary::Commit);
                }
                counts.commits.set(counts.commits.get() + 1);
                Ok(*observations)
            },
            |counts, committed| {
                if failure == Some(Boundary::PinVerification) {
                    return Err(Boundary::PinVerification);
                }
                if failure == Some(Boundary::Publication) {
                    return Err(Boundary::Publication);
                }
                counts.publications.set(counts.publications.get() + 1);
                Ok(committed)
            },
        )
    }

    #[test]
    fn every_finalization_boundary_stops_later_authority() {
        for failed in [
            Boundary::FirstObservation,
            Boundary::SecondObservation,
            Boundary::Commit,
            Boundary::PinVerification,
            Boundary::Publication,
        ] {
            let mut counts = SequenceCounts::default();

            assert_eq!(exercise_sequence(Some(failed), &mut counts), Err(failed));
            assert_eq!(
                counts.commits.get(),
                usize::from(matches!(
                    failed,
                    Boundary::PinVerification | Boundary::Publication
                ))
            );
            assert_eq!(counts.publications.get(), 0);
        }
    }

    #[test]
    fn successful_finalization_observes_twice_before_one_commit_and_publication() {
        let mut counts = SequenceCounts::default();

        let completed = exercise_sequence(None, &mut counts).unwrap();

        assert_eq!(completed, (2, 2, 2));
        assert_eq!(counts.observations.get(), 2);
        assert_eq!(counts.commits.get(), 1);
        assert_eq!(counts.publications.get(), 1);
    }

    #[test]
    fn first_vs_second_observation_mismatch_leaves_real_catalog_empty() {
        let mut case = RealFinalizationCase::new();
        case.begin();
        case.bind_pin_custody();

        let result = run_finalization_sequence(
            &mut case,
            |_| -> Result<ObjectDigest, NetworkPreparationRuntimeError> {
                let first = ObjectDigest::from_bytes([54; 32]);
                let second = ObjectDigest::from_bytes([55; 32]);
                if first != second {
                    return Err(NetworkNamespaceObserverError::Changed.into());
                }
                Ok(first)
            },
            |case, digest| Ok(case.commit(*digest)),
            |case, committed| {
                publish_committed_network_preparation(
                    case.coordinator.as_ref().unwrap(),
                    &case.preparations,
                    case.namespaces.as_mut().unwrap(),
                    committed,
                )
            },
        );

        assert!(matches!(
            result,
            Err(NetworkPreparationRuntimeError::Observer(
                NetworkNamespaceObserverError::Changed
            ))
        ));
        let snapshot = case.coordinator().preparation_recovery_snapshot().unwrap();
        let entry = &snapshot.entries()[0];
        assert_eq!(entry.phase(), DurableNetworkPhase::Ambiguous);
        assert!(entry.result().is_none());
        case.assert_no_catalog_row();
    }

    #[test]
    fn crash_after_ambiguity_before_custody_cannot_redispatch_or_publish() {
        let mut case = RealFinalizationCase::new();
        case.begin();
        case.reopen_coordinator();

        let namespace = NamespaceFd::current_network().unwrap();
        assert!(
            case.coordinator()
                .recover_ambiguous_preparation_observation(
                    REQUEST_ID,
                    case.effect_digest,
                    &namespace,
                )
                .is_err()
        );
        let request = case.request.clone();
        let plan = case.plan.clone();
        let effect_digest = case.effect_digest;
        assert!(
            begin_network_preparation_once(
                case.coordinator_mut(),
                REQUEST_ID,
                effect_digest,
                &request,
                plan,
                &mut || Ok(clock()),
            )
            .is_err()
        );
        let snapshot = case.coordinator().preparation_recovery_snapshot().unwrap();
        let entry = &snapshot.entries()[0];
        assert_eq!(entry.phase(), DurableNetworkPhase::Ambiguous);
        assert!(entry.custody().is_none());
        case.assert_no_catalog_row();
    }

    #[test]
    fn restart_recovery_is_observation_only_and_rejects_tuple_substitution() {
        let mut case = RealFinalizationCase::new();
        case.begin();
        let namespace = NamespaceFd::current_network().unwrap();
        let identity = namespace.identity();
        let effect_digest = case.effect_digest;
        let handle = *case.resolution.reserved_network_handle();
        let plan_digest = case.plan.digest();
        case.coordinator_mut()
            .bind_effect_namespace_custody(
                REQUEST_ID,
                effect_digest,
                handle,
                KernelBootId::current().unwrap().into_bytes(),
                identity.device,
                identity.inode,
                plan_digest,
            )
            .unwrap();
        case.reopen_coordinator();

        let recovered = case
            .coordinator()
            .recover_ambiguous_preparation_observation(REQUEST_ID, case.effect_digest, &namespace)
            .unwrap();
        assert_eq!(recovered.namespace().identity(), identity);
        assert_eq!(recovered.kernel_plan_digest(), case.plan.digest());
        for (request_id, effect) in [
            ([8; 16], case.effect_digest),
            (REQUEST_ID, ObjectDigest::from_bytes([99; 32])),
        ] {
            assert!(
                case.coordinator()
                    .recover_ambiguous_preparation_observation(request_id, effect, &namespace)
                    .is_err()
            );
        }

        let request = case.request.clone();
        let plan = case.plan.clone();
        let effect_digest = case.effect_digest;
        assert!(
            begin_network_preparation_once(
                case.coordinator_mut(),
                REQUEST_ID,
                effect_digest,
                &request,
                plan,
                &mut || Ok(clock()),
            )
            .is_err()
        );
        case.assert_no_catalog_row();
    }

    #[test]
    fn crash_after_commit_resumes_with_publication_only() {
        let mut case = RealFinalizationCase::new();
        case.begin();
        case.bind_pin_custody();
        let committed = case.commit(ObjectDigest::from_bytes([54; 32]));
        case.reopen_coordinator();

        let outcome = publish_committed_network_preparation(
            case.coordinator.as_ref().unwrap(),
            &case.preparations,
            case.namespaces.as_mut().unwrap(),
            committed,
        )
        .unwrap();

        assert_eq!(outcome, NetworkNamespaceCatalogOutcomeV1::Published);
        let identity = case
            .namespaces()
            .current_namespace_identity(*case.resolution.reserved_network_handle())
            .unwrap();
        assert_eq!(identity.namespace_device(), case.pin_device);
        assert_eq!(identity.namespace_inode(), case.pin_inode);
    }

    #[test]
    fn committed_publication_replays_exactly_after_catalog_reopen() {
        let mut case = RealFinalizationCase::new();
        case.begin();
        case.bind_pin_custody();
        let committed = case.commit(ObjectDigest::from_bytes([54; 32]));
        assert_eq!(
            publish_committed_network_preparation(
                case.coordinator.as_ref().unwrap(),
                &case.preparations,
                case.namespaces.as_mut().unwrap(),
                committed,
            )
            .unwrap(),
            NetworkNamespaceCatalogOutcomeV1::Published,
        );
        case.reopen_namespaces();

        assert_eq!(
            publish_committed_network_preparation(
                case.coordinator.as_ref().unwrap(),
                &case.preparations,
                case.namespaces.as_mut().unwrap(),
                committed,
            )
            .unwrap(),
            NetworkNamespaceCatalogOutcomeV1::Replay,
        );
    }

    #[test]
    fn pin_inode_substitution_after_commit_cannot_create_catalog_row() {
        let mut case = RealFinalizationCase::new();
        case.begin();
        case.bind_pin_custody();
        let committed = case.commit(ObjectDigest::from_bytes([54; 32]));
        let displaced_pin = case.pin_path.with_extension("displaced");
        fs::rename(&case.pin_path, displaced_pin).unwrap();
        fs::File::create(&case.pin_path).unwrap();
        assert_ne!(fs::metadata(&case.pin_path).unwrap().ino(), case.pin_inode);

        assert!(
            publish_committed_network_preparation(
                case.coordinator.as_ref().unwrap(),
                &case.preparations,
                case.namespaces.as_mut().unwrap(),
                committed,
            )
            .is_err()
        );
        assert_eq!(
            case.coordinator()
                .preparation_recovery_snapshot()
                .unwrap()
                .entries()[0]
                .phase(),
            DurableNetworkPhase::Committed,
        );
        case.assert_no_catalog_row();
    }
}
