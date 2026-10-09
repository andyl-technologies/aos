//! Host-owned installed providers and native enrollment before graph sealing.

mod archive_artifacts;
mod cached_artifacts;
mod clock_label;
mod gem5_profile;
mod host_state;
mod io;
mod kvm;

mod native_state;
mod profile;
mod reference_public;
mod scripted;
mod semantics;
mod transcript;
mod trust;

#[cfg(test)]
mod artifact_tests;

#[cfg(test)]
mod semantic_terminal_tests;

pub(super) use transcript::replay_stepper::{ReplayStep, ReplayStepper};

pub use clock_label::{InstalledClockLabelFactory, InstalledClockLabelProfile};
pub use gem5_profile::InstalledGem5ClosedProfile;
pub use host_state::InstalledHostStateFactory;
pub use io::{InstalledHostIoProfile, InstalledIoArtifact, InstalledIoArtifactSource};
pub use kvm::{
    MAX_KVM_CANDIDATE_POLICY_BYTES, load_installed_kvm_candidate, prepare_installed_kvm_candidate,
};
pub use native_state::{
    InstalledGem5Isa, NativeCapturePoint, NativeWorldOutcome, NativeWorldRecord,
    NativeWorldRequest, NativeWorldRetention, NativeWorldService,
};
pub use reference_public::{
    InstalledPublicReferencePackage, InstalledReferenceQualifier, QualificationRunError,
    ReferenceQualificationObservation, ReferenceQualificationRun,
};
pub use scripted::InstalledScriptedSourceProfile;
pub use semantics::InstalledHostSemanticProfile;
pub use transcript::{
    InstalledConditionalReplay, InstalledRecordedWorld, InstalledReferenceRecording,
    InstalledReplayRecipe,
};

use std::{
    collections::BTreeMap,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use crucible::{
    node_adapters::{HostModel, HostModelNode, HostModelResources, ReferenceDeviceNode},
    node_admission::{AdmissionLimits, AdmittedGraph},
    node_contract::{
        ActivationRecord, OwnerIdentity, PreparedRealization, RuntimeCustodyQueue,
        RuntimeCustodySupervisor, RuntimeLimits, SimulationNode,
    },
};
use crucible_campaign::ExecutionId;
use crucible_cas::content_store::{
    BlobHandle, ContentId, ImmutableBlobBackend, MutableRefBackend, ObjectKind, RefName,
};
use crucible_device::{
    clock::VirtualClock,
    netlink::{LinkFaults, NetLink},
};
use crucible_node_contract::{
    ContentRef, HashRef, Id, LiveAuthority, NodeBinding, Phase, Position, U64, Validate, canonical,
};
use crucible_node_provider::reference_device::ReferenceDevice;
use serde::{Deserialize, Serialize};

use super::{NodeObservedBackend, NodeObservedError, StoredWorldActivationPublisher};
use crate::node_scenario::{NodeRunConfiguration, NodeScenario};

/// Selects an actual implementation supported by the local installed catalog.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "implementation", rename_all = "snake_case", deny_unknown_fields)]
pub enum InstalledNodeKind {
    /// Runs the owned host integer clock with no timers or autonomous work.
    HostClock,
    /// Runs an independently enrolled host assertion program and original state.
    HostSemantics {
        /// Binds immutable compact properties and qualified input projections.
        profile: InstalledHostSemanticProfile,
    },
    /// Runs the installed closed gem5 model with original live public readiness.
    /// Preservation remains unsupported in this distinct initial edition.
    Gem5Closed {
        /// Selects the independently installed fixed guest and native poll policy.
        isa: InstalledGem5Isa,
    },
    /// Runs native block or 9p storage with independently enrolled immutable input.
    HostIo {
        /// Binds the native storage codec, immutable input and positive timing.
        profile: InstalledHostIoProfile,
    },
    /// Publishes independently enrolled finite immutable native request events.
    HostScripted {
        /// Binds the complete source script and its ordinary public consumer.
        profile: InstalledScriptedSourceProfile,
    },
    /// Runs a fault-free byte-preserving exact host link between named nodes.
    HostNetLink {
        /// Names the public checksum producer whose output feeds the link.
        producer: Id,
        /// Names the public checksum consumer fed by the link output.
        consumer: Id,
        /// Binds the native frame source identifier without truncation.
        source_node: u32,
        /// Selects positive exact native delivery latency in picoseconds.
        latency_ps: U64,
        /// Selects the positive conservative native latency floor.
        floor_ps: U64,
    },
    /// Runs native checksum windows with a shared byte-preserving public schema.
    ReferenceNativeLinked {
        /// Selects the positive fixed simulation window in picoseconds.
        quantum_ps: U64,
        /// Selects the finite physical host execution budget in nanoseconds.
        host_budget_ns: U64,
        /// Selects a source with no ingress or a causally admitted consumer.
        closed_ingress: bool,
    },
    /// Runs output-only controlled checksum windows with permanently closed ingress.
    ReferenceDevice {
        /// Selects the positive simulated window duration in picoseconds.
        quantum_ps: U64,
        /// Selects the positive physical host budget in nanoseconds.
        host_budget_ns: U64,
    },
}

impl<'de> Deserialize<'de> for InstalledNodeKind {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = InstalledNodeKindWire::deserialize(deserializer)?;
        Ok(match wire {
            InstalledNodeKindWire::HostClock {} => Self::HostClock,
            InstalledNodeKindWire::HostSemantics { profile } => Self::HostSemantics { profile },
            InstalledNodeKindWire::Gem5Closed { isa } => Self::Gem5Closed { isa },
            InstalledNodeKindWire::HostIo { profile } => Self::HostIo { profile },
            InstalledNodeKindWire::HostScripted { profile } => Self::HostScripted { profile },
            InstalledNodeKindWire::ReferenceDevice {
                quantum_ps,
                host_budget_ns,
            } => Self::ReferenceDevice {
                quantum_ps,
                host_budget_ns,
            },
            InstalledNodeKindWire::ReferenceNativeLinked {
                quantum_ps,
                host_budget_ns,
                closed_ingress,
            } => Self::ReferenceNativeLinked {
                quantum_ps,
                host_budget_ns,
                closed_ingress,
            },
            InstalledNodeKindWire::HostNetLink {
                producer,
                consumer,
                source_node,
                latency_ps,
                floor_ps,
            } => Self::HostNetLink {
                producer,
                consumer,
                source_node,
                latency_ps,
                floor_ps,
            },
        })
    }
}

#[derive(Deserialize)]
#[serde(tag = "implementation", rename_all = "snake_case", deny_unknown_fields)]
enum InstalledNodeKindWire {
    /// Runs the owned host integer clock with no timers or autonomous work.
    HostClock {},
    HostSemantics {
        profile: InstalledHostSemanticProfile,
    },
    Gem5Closed {
        isa: InstalledGem5Isa,
    },
    HostIo {
        profile: InstalledHostIoProfile,
    },
    HostScripted {
        profile: InstalledScriptedSourceProfile,
    },
    /// Runs a fault-free byte-preserving exact host link between named nodes.
    HostNetLink {
        /// Names the public checksum producer whose output feeds the link.
        producer: Id,
        /// Names the public checksum consumer fed by the link output.
        consumer: Id,
        /// Binds the native frame source identifier without truncation.
        source_node: u32,
        /// Selects positive exact native delivery latency in picoseconds.
        latency_ps: U64,
        /// Selects the positive conservative native latency floor.
        floor_ps: U64,
    },
    /// Runs native checksum windows with a shared byte-preserving public schema.
    ReferenceNativeLinked {
        /// Selects the positive fixed simulation window in picoseconds.
        quantum_ps: U64,
        /// Selects the finite physical host execution budget in nanoseconds.
        host_budget_ns: U64,
        /// Selects a source with no ingress or a causally admitted consumer.
        closed_ingress: bool,
    },
    /// Runs output-only controlled checksum windows with permanently closed ingress.
    ReferenceDevice {
        /// Selects the positive simulated window duration in picoseconds.
        quantum_ps: U64,
        /// Selects the positive physical host budget in nanoseconds.
        host_budget_ns: U64,
    },
}

/// Associates one semantic node and indivisible owner with an installed profile.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledNodeSelection {
    /// Names the public logical node.
    pub node: Id,
    /// Names its complete execution and capture owner.
    pub owner: Id,
    /// Selects one actual implemented profile and its bounded timing parameters.
    pub kind: InstalledNodeKind,
}

/// Owns one genuinely inactive installed world and its authenticated definition.
///
/// Preparation alone grants no RUN or reconstruction authority. The consumer
/// must retain its reserved retirement custody and use the common all-owner
/// readiness/activation barrier before any modeled execution.
pub struct InstalledPreparedWorld {
    /// Retains the exact immutable authored definition authenticated by admission.
    pub scenario: NodeScenario,
    /// Seals the complete measured native owner and implementation inventory.
    pub graph: AdmittedGraph,
    /// Owns all original inactive native resources and their retirement slot.
    pub realization: PreparedRealization,
}

#[derive(Default)]
struct PreparationSource<'a> {
    activation: Option<&'a crucible::node_contract::SavedRuntimeActivation>,
    preserved_cut: Option<Position>,
}

// Keeps original preservation lineage and its optional installed semantic
// selection together; neither may be substituted during native enrollment.
struct SelectedPreparation<'a> {
    source: PreparationSource<'a>,
    label: Option<&'a clock_label::ClockLabelPolicy>,
}

/// Owns trusted local installation measurements and finite world retirement slots.
///
/// This catalog is host configuration, never a provider-supplied claim. The
/// expected device identity must come from the operator's qualified source-built
/// package inventory. The host implementation is measured from `/proc/self/exe`.
/// The catalog regenerates every selected closed profile from installed code and
/// accepts only its exact immutable world, rather than arbitrary proof strings.
pub struct InstalledNodeCatalog {
    host_executable: PathBuf,
    host_identity: ContentRef,
    device_executable: PathBuf,
    device_identity: ContentRef,
    socket_parent: PathBuf,
    control_timeout: Duration,
    custody: RuntimeCustodyQueue,
    artifacts: BTreeMap<String, InstalledIoArtifact>,
}

impl InstalledNodeCatalog {
    /// Opens a measured source-qualified device installation on the owner thread.
    ///
    /// # Errors
    /// Refuses a relative executable/socket path, absent or changed executable,
    /// zero/excessive control timeout, malformed expected identity, or unavailable
    /// finite retirement capacity. Expected hashes are installed host policy.
    pub fn new(
        device_executable: PathBuf,
        expected_device: ContentRef,
        socket_parent: PathBuf,
        control_timeout: Duration,
        maximum_worlds: usize,
    ) -> Result<Self, NodeObservedError> {
        if !device_executable.is_absolute()
            || !socket_parent.is_absolute()
            || control_timeout.is_zero()
            || control_timeout > Duration::from_secs(60)
        {
            return Err(refused(
                "invalid installed provider paths or control timeout",
            ));
        }
        expected_device.validate()?;
        let device_identity = measure_executable(&device_executable)?;
        if device_identity != expected_device {
            return Err(refused(
                "installed device differs from qualified package identity",
            ));
        }
        let host_executable = PathBuf::from("/proc/self/exe");
        let host_identity = measure_executable(&host_executable)?;
        let custody = RuntimeCustodyQueue::new(maximum_worlds).map_err(native)?;
        Ok(Self {
            host_executable,
            host_identity,
            device_executable,
            device_identity,
            socket_parent,
            control_timeout,
            custody,
            artifacts: BTreeMap::new(),
        })
    }

    /// Enrolls independently qualified immutable host artifacts before admission.
    ///
    /// Paths are private operator configuration. Portable node selections only
    /// refer to their content identities and cannot install or replace artifacts.
    /// Path entries are opened without following their final symlink and measured
    /// before any registry entry changes. Explicit archive-only entries enroll
    /// expected identities for signed recovery; they cannot construct fresh
    /// native resources. Recovery independently authenticates complete archive
    /// bytes against these expected identities before native allocation.
    ///
    /// # Errors
    /// Refuses changed files, malformed references, reused identities with another
    /// source, any artifact exceeding 4 MiB, more than 64 artifacts, or an
    /// aggregate exceeding 16 MiB. A refusal leaves the installed registry
    /// unchanged. Missing path entries never become archive-only enrollment.
    pub fn install_artifacts(
        &mut self,
        artifacts: Vec<InstalledIoArtifact>,
    ) -> Result<(), NodeObservedError> {
        if artifacts.len() > 64 {
            return Err(refused(
                "installed artifact enrollment exceeds its finite count ceiling",
            ));
        }
        let mut installed = self.artifacts.clone();
        for artifact in artifacts {
            artifact.expected.validate()?;
            if artifact.expected.length.get() > io::MAXIMUM_IO_ARTIFACT_BYTES as u64 {
                return Err(refused(
                    "installed artifact exceeds its finite byte ceiling",
                ));
            }
            let key = artifact.expected.hash.digest.clone();
            if let Some(original) = installed.get(&key) {
                if original.expected != artifact.expected || original.source != artifact.source {
                    return Err(refused("installed artifact identity cannot be replaced"));
                }
            } else {
                installed.insert(key, artifact);
            }
        }
        let total = installed
            .values()
            .try_fold(0u64, |total, artifact| {
                total.checked_add(artifact.expected.length.get())
            })
            .ok_or_else(|| refused("installed immutable artifact byte count overflowed"))?;
        if installed.len() > 64 || total > 16 * 1024 * 1024 {
            return Err(refused(
                "installed immutable artifact registry exceeds its finite ceiling",
            ));
        }
        for artifact in installed.values() {
            if matches!(artifact.source, InstalledIoArtifactSource::Path(_)) {
                io::read_artifact(artifact)?;
            }
        }
        self.artifacts = installed;
        Ok(())
    }

    /// Resolves selected actual implementations into a complete immutable scenario.
    ///
    /// Installed profiles include clocks, checksum windows, byte-preserving links
    /// and finite scripted requests feeding native storage. Guest CPUs and
    /// external ingress require independently qualified catalog entries.
    ///
    /// # Errors
    /// Refuses duplicate/oversized owner rosters or invalid profile parameters.
    pub fn scenario(
        &self,
        selections: &[InstalledNodeSelection],
    ) -> Result<NodeScenario, NodeObservedError> {
        if selections
            .iter()
            .any(|selection| matches!(selection.kind, InstalledNodeKind::Gem5Closed { .. }))
        {
            return native_state::public_catalog::scenario(self, selections);
        }
        Ok(profile::build_world(
            selections,
            &self.host_identity,
            &self.device_identity,
            &self.artifacts,
        )?
        .scenario)
    }

    /// Prepares actual inactive resources and seals their complete mixed graph.
    ///
    /// One complete retirement slot is reserved before any native child exists.
    /// All implementation identities and native owners are measured and enrolled
    /// before graph sealing. Native RUN remains disabled until the observed worker
    /// reserves the execution nonce and durably publishes the all-owner barrier.
    ///
    /// # Errors
    /// Refuses changed authored bytes, unavailable custody, stale installations,
    /// native startup, complete graph qualification, or activation-storage setup.
    pub fn prepare(
        &mut self,
        selections: &[InstalledNodeSelection],
        scenario: NodeScenario,
        configuration: NodeRunConfiguration,
        execution: ExecutionId,
        blobs: Arc<dyn ImmutableBlobBackend>,
        refs: Arc<dyn MutableRefBackend>,
    ) -> Result<NodeObservedBackend, NodeObservedError> {
        let InstalledPreparedWorld {
            scenario,
            graph,
            realization: prepared,
        } = self.prepare_world(selections, scenario, execution)?;
        let context = super::backend::input_context_bytes(&scenario, &configuration)?;
        let inputs = ContentId::for_bytes(ObjectKind::Trace, 1, &context);
        let receipt = blobs.put_if_absent(inputs, &BlobHandle::from_bytes(context))?;
        if !receipt.is_durable() {
            return Err(refused("input context is not durably retained"));
        }
        let reference = RefName::new(format!(
            "node-world-activations/{}",
            execution_text(execution)
        ))?;
        let stored = StoredWorldActivationPublisher::new(Arc::clone(&blobs), refs, reference)?;
        let publisher: Box<dyn crucible::node_contract::ActivationPublisher> = if selections
            .iter()
            .any(|selection| matches!(selection.kind, InstalledNodeKind::Gem5Closed { .. }))
        {
            native_state::public_catalog::publisher(stored)?
        } else {
            Box::new(stored)
        };
        NodeObservedBackend::from_prepared(
            InstalledPreparedWorld {
                scenario,
                graph,
                realization: prepared,
            },
            configuration,
            publisher,
            blobs,
            inputs,
            execution,
        )
    }

    /// Allocates actual inactive resources and seals their complete native graph.
    ///
    /// This preparation boundary is reusable by observed execution and installed
    /// host-state bridges. It performs no activation, grants no observed nonce
    /// permit, and accepts no imported native capture as authority. Original
    /// native custody always owns its pre-reserved complete retirement slot.
    ///
    /// # Errors
    /// Refuses mismatched authored profiles, changed installed artifacts, native
    /// allocation or enrollment failures, incomplete graph qualification, and
    /// unavailable finite retirement capacity.
    pub fn prepare_world(
        &mut self,
        selections: &[InstalledNodeSelection],
        scenario: NodeScenario,
        execution: ExecutionId,
    ) -> Result<InstalledPreparedWorld, NodeObservedError> {
        if selections
            .iter()
            .any(|selection| matches!(selection.kind, InstalledNodeKind::Gem5Closed { .. }))
        {
            return native_state::public_catalog::prepare(self, selections, scenario, execution);
        }
        let artifacts = self.artifacts.clone();
        Ok(self
            .prepare_world_with_source(
                selections,
                scenario,
                execution,
                PreparationSource::default(),
                &artifacts,
                None,
            )?
            .0)
    }

    /// Seals fresh installed host authority for an authenticated complete source.
    ///
    /// This method measures the original installed profiles again and enrolls
    /// actual inactive native models before graph admission. It derives fresh
    /// incarnations from the new execution nonce and advances each original
    /// owner/world generation. It grants no restoration or activation token.
    /// Temporary enrollment resources remain in the owning retirement queue.
    ///
    /// # Errors
    /// Refuses unsupported selections, foreign signed source compatibility, reused
    /// incarnations, generation overflow, changed installations or admission.
    pub fn prepare_host_restore_graph(
        &mut self,
        selections: &[InstalledNodeSelection],
        scenario: &NodeScenario,
        record: &crucible::node_state::HostArchiveRecord,
        execution: ExecutionId,
    ) -> Result<(AdmittedGraph, ActivationRecord), NodeObservedError> {
        if selections.iter().any(|selection| {
            !matches!(
                selection.kind,
                InstalledNodeKind::HostClock
                    | InstalledNodeKind::HostIo { .. }
                    | InstalledNodeKind::HostScripted { .. }
                    | InstalledNodeKind::HostSemantics { .. }
            )
        }) || record.manifest().world_binding_hash != scenario.world.identity()?
            || record.manifest().scenario_ref != scenario.world.scenario_ref
        {
            return Err(refused(
                "signed source is not the exact supported installed host world",
            ));
        }
        let source = record.source_activation(4 * 1024 * 1024).map_err(native)?;
        let artifacts = archive_artifacts::materialize(&self.artifacts, selections, record)?;
        let (prepared, target) = self.prepare_world_with_source(
            selections,
            scenario.clone(),
            execution,
            PreparationSource {
                activation: Some(&source),
                preserved_cut: Some(record.manifest().cut),
            },
            artifacts.registry(),
            None,
        )?;
        drop(prepared.realization);
        Ok((prepared.graph, target))
    }

    fn prepare_world_with_source(
        &mut self,
        selections: &[InstalledNodeSelection],
        scenario: NodeScenario,
        execution: ExecutionId,
        source: PreparationSource<'_>,
        artifacts: &BTreeMap<String, InstalledIoArtifact>,
        recorder: Option<&mut transcript::ReferenceRecorder<'_>>,
    ) -> Result<(InstalledPreparedWorld, ActivationRecord), NodeObservedError> {
        self.prepare_world_with_selected_label(
            selections,
            scenario,
            execution,
            artifacts,
            recorder,
            SelectedPreparation {
                source,
                label: None,
            },
        )
    }

    fn prepare_world_with_selected_label(
        &mut self,
        selections: &[InstalledNodeSelection],
        scenario: NodeScenario,
        execution: ExecutionId,
        artifacts: &BTreeMap<String, InstalledIoArtifact>,
        mut recorder: Option<&mut transcript::ReferenceRecorder<'_>>,
        preparation: SelectedPreparation<'_>,
    ) -> Result<(InstalledPreparedWorld, ActivationRecord), NodeObservedError> {
        let SelectedPreparation { source, label } = preparation;
        let mut resolved = profile::build_world(
            selections,
            &self.host_identity,
            &self.device_identity,
            artifacts,
        )?;
        if let Some(label) = label {
            if resolved.scenario.canonical_bytes()? != label.base.canonical_bytes()? {
                return Err(refused(
                    "Clock label differs from actual installed baseline",
                ));
            }
            resolved.scenario = label.labeled.clone();
        }
        if scenario.canonical_bytes()? != resolved.scenario.canonical_bytes()? {
            return Err(refused(
                "authored world differs from complete installed profile selection",
            ));
        }
        if measure_executable(&self.host_executable)? != self.host_identity
            || measure_executable(&self.device_executable)? != self.device_identity
        {
            return Err(refused(
                "installed implementation changed before native preparation",
            ));
        }
        let session = Id::new(format!("session/{}", execution_text(execution)))?;
        let activation_id = Id::new(format!("activation/{}", execution_text(execution)))?;
        let host_receipt_bytes = canonical::canonical_json(&serde_json::json!({
            "format":"crucible.local-node-enrollment","version":1,"execution":execution_text(execution),
            "host":self.host_identity,"device":self.device_identity}))?;
        let host_receipt = canonical::content_ref(&host_receipt_bytes, "application/json")?;
        let mut bindings = Vec::new();
        let mut owners = Vec::new();
        for selected in &scenario.compatibility {
            let incarnation = Id::new(format!(
                "incarnation/{}",
                canonical::hash(
                    "crucible.local-owner-incarnation.v1",
                    format!(
                        "{}:{}",
                        execution_text(execution),
                        selected.execution_owner.id
                    )
                    .as_bytes()
                )?
                .digest
            ))?;
            let generation = match source.activation {
                Some(source) => {
                    let original = source
                        .owners
                        .iter()
                        .find(|owner| owner.owner == selected.execution_owner.id)
                        .ok_or_else(|| {
                            refused("signed source owner roster differs from installed graph")
                        })?;
                    if incarnation == original.incarnation {
                        return Err(refused(
                            "restore execution reuses original owner incarnation",
                        ));
                    }
                    original.generation.checked_add(U64::new(1))?
                }
                None => U64::new(1),
            };
            owners.push(OwnerIdentity {
                owner: selected.execution_owner.id.clone(),
                incarnation: incarnation.clone(),
                generation,
            });
            bindings.push(NodeBinding {
                compatibility: selected.clone(),
                authority: LiveAuthority {
                    schema_version: 1,
                    session_id: session.clone(),
                    incarnation_id: incarnation,
                    realization_id: session.clone(),
                    activation_id: None,
                    world_generation: U64::new(0),
                    owner_generation: generation,
                    input_epoch: session.clone(),
                    host_receipt: host_receipt.clone(),
                    extensions: Default::default(),
                },
                extensions: Default::default(),
            });
        }
        owners.sort();
        let target = ActivationRecord {
            generation: match source.activation {
                Some(source) => source.generation.checked_add(U64::new(1))?,
                None => U64::new(1),
            },
            activation_id,
            world_binding_hash: scenario.world.identity()?,
            owners,
            boundary: source.preserved_cut.unwrap_or(Position::new(
                U64::new(0),
                U64::new(0),
                Phase::BoundaryControl,
            )),
        };
        let limits = RuntimeLimits {
            maximum_nodes: selections.len(),
            maximum_owners: selections.len(),
            maximum_operations: 65_536,
            maximum_retained_outputs: 65_536,
        };
        let slot = self
            .custody
            .reserve_world(&target, limits)
            .map_err(native)?;
        let mut devices = BTreeMap::new();
        let mut models = BTreeMap::new();
        for (selection, binding) in selections.iter().zip(&bindings) {
            match &selection.kind {
                InstalledNodeKind::HostNetLink {
                    source_node,
                    latency_ps,
                    floor_ps,
                    ..
                } => {
                    models.insert(
                        selection.node.clone(),
                        HostModel::Link(Box::new(
                            NetLink::new(
                                *source_node,
                                latency_ps.get(),
                                floor_ps.get(),
                                LinkFaults::none(),
                            )
                            .map_err(native)?,
                        )),
                    );
                }
                InstalledNodeKind::HostIo { profile } => {
                    models.insert(
                        selection.node.clone(),
                        io::build_model(selection, profile, artifacts)?,
                    );
                }
                InstalledNodeKind::HostScripted { profile } => {
                    models.insert(
                        selection.node.clone(),
                        scripted::build_model(selection, profile, artifacts)?,
                    );
                }
                InstalledNodeKind::Gem5Closed { .. } => {
                    return Err(refused(
                        "closed gem5 requires its original public preparation bridge",
                    ));
                }
                InstalledNodeKind::HostClock => {
                    models.insert(
                        selection.node.clone(),
                        HostModel::Clock(VirtualClock::new()),
                    );
                }
                InstalledNodeKind::HostSemantics { profile } => {
                    models.insert(
                        selection.node.clone(),
                        HostModel::Semantics(Box::new(semantics::build_model(
                            selection, selections, profile, artifacts,
                        )?)),
                    );
                }
                InstalledNodeKind::ReferenceDevice { .. }
                | InstalledNodeKind::ReferenceNativeLinked { .. } => {
                    let child = ReferenceDevice::spawn(
                        &self.device_executable,
                        &self.socket_parent,
                        selection.owner.clone(),
                        binding.authority.incarnation_id.clone(),
                        binding.authority.owner_generation,
                        self.control_timeout,
                    )
                    .map_err(native)?;
                    devices.insert(selection.node.clone(), child);
                }
            }
        }
        let mut content = scenario
            .content
            .iter()
            .map(|entry| {
                (
                    entry.reference.hash.digest.clone(),
                    (entry.reference.clone(), entry.bytes.clone()),
                )
            })
            .collect::<BTreeMap<_, _>>();
        content.insert(
            host_receipt.hash.digest.clone(),
            (host_receipt, host_receipt_bytes),
        );
        let mut installed = BTreeMap::new();
        installed.insert(
            self.host_identity.hash.digest.clone(),
            (self.host_identity.clone(), self.host_executable.clone()),
        );
        installed.insert(
            self.device_identity.hash.digest.clone(),
            (self.device_identity.clone(), self.device_executable.clone()),
        );
        let evidence = trust::InstalledEvidence::new(
            &scenario, &bindings, &devices, &models, content, installed,
        )?;
        let admission_limits = AdmissionLimits {
            maximum_content_bytes: 512 * 1024 * 1024,
            maximum_total_content_bytes: 2 * 1024 * 1024 * 1024,
            ..AdmissionLimits::default()
        };
        let graph = if let Some(label) = label {
            let profile = self.clock_label_profile()?;
            if label.labeled.canonical_bytes()? != profile.labeled.canonical_bytes()? {
                return Err(refused("installed Clock label changed before admission"));
            }
            let registry = profile.registry()?;
            scenario.admit(
                &bindings,
                &clock_label::LabelAdmission {
                    original: &evidence,
                    registry: &registry,
                },
                admission_limits,
            )?
        } else {
            scenario.admit(&bindings, &evidence, admission_limits)?
        };
        let mut nodes: Vec<Box<dyn SimulationNode>> = Vec::new();
        for selection in selections {
            match &selection.kind {
                InstalledNodeKind::Gem5Closed { .. } => {
                    return Err(refused(
                        "closed gem5 native custody cannot become a host model",
                    ));
                }
                InstalledNodeKind::HostClock
                | InstalledNodeKind::HostSemantics { .. }
                | InstalledNodeKind::HostNetLink { .. }
                | InstalledNodeKind::HostIo { .. }
                | InstalledNodeKind::HostScripted { .. } => {
                    let model = models
                        .remove(&selection.node)
                        .ok_or_else(|| refused("enrolled host model custody disappeared"))?;
                    nodes.push(Box::new(
                        HostModelNode::new(
                            &graph,
                            &selection.node,
                            model,
                            &evidence,
                            HostModelResources::default(),
                        )
                        .map_err(native)?,
                    ));
                }
                InstalledNodeKind::ReferenceDevice { .. }
                | InstalledNodeKind::ReferenceNativeLinked { .. } => {
                    let child = devices
                        .remove(&selection.node)
                        .ok_or_else(|| refused("enrolled child custody disappeared"))?;
                    nodes.push(Box::new(
                        ReferenceDeviceNode::from_prepared(
                            &graph,
                            &selection.node,
                            child,
                            &evidence,
                            limits.maximum_operations,
                        )
                        .map_err(native)?,
                    ));
                }
            }
        }
        if let Some(recorder) = recorder.as_mut() {
            let mut wrapped = Vec::new();
            if let Err(error) = wrapped.try_reserve_exact(nodes.len()) {
                drop(PreparedRealization::new(nodes, target, limits, slot));
                return Err(native(error));
            }
            let mut remaining = nodes.into_iter();
            while let Some(node) = remaining.next() {
                match recorder.wrap(&graph, &target, node, &evidence) {
                    Ok(node) => wrapped.push(node),
                    Err(failure) => {
                        wrapped.push(failure.node);
                        wrapped.extend(remaining);
                        // Construction refusal transfers every native handle,
                        // including earlier wrappers, to the original reserved
                        // world slot. No standalone drop loses its roster.
                        drop(PreparedRealization::new(wrapped, target, limits, slot));
                        return Err(failure.error);
                    }
                }
            }
            nodes = wrapped;
        }
        let prepared = PreparedRealization::new(nodes, target.clone(), limits, slot);
        Ok((
            InstalledPreparedWorld {
                scenario,
                graph,
                realization: prepared,
            },
            target,
        ))
    }

    /// Returns owning cleanup supervision for polling on every daemon actor turn.
    pub fn custody(&self) -> &RuntimeCustodyQueue {
        &self.custody
    }

    pub(super) fn authenticate_cache_selection(
        &self,
        selections: &[InstalledNodeSelection],
        scenario: &NodeScenario,
    ) -> Result<(), NodeObservedError> {
        if measure_executable(&self.host_executable)? != self.host_identity
            || measure_executable(&self.device_executable)? != self.device_identity
        {
            return Err(refused(
                "installed implementation changed before cache reuse",
            ));
        }
        let artifacts = cached_artifacts::materialize(&self.artifacts, selections, scenario)?;
        let selected = profile::build_world(
            selections,
            &self.host_identity,
            &self.device_identity,
            artifacts.registry(),
        )?
        .scenario;
        if selected.canonical_bytes()? != scenario.canonical_bytes()? {
            return Err(refused(
                "cached scenario differs from exact installed implementation/model",
            ));
        }
        Ok(())
    }

    pub(super) fn authenticate_recorded(
        &self,
        scenario: &NodeScenario,
        configuration: &NodeRunConfiguration,
        request: &crucible_campaign::observed_node_attempt::ObservedAttemptRequest,
    ) -> Result<(), NodeObservedError> {
        profile::authenticate_recorded(scenario, configuration, request)
    }
}

pub(super) fn measure_executable(path: &Path) -> Result<ContentRef, NodeObservedError> {
    let mut file = File::open(path).map_err(native)?;
    let length = file.metadata().map_err(native)?.len();
    if length == 0 || length > 512 * 1024 * 1024 {
        return Err(refused(
            "installed executable exceeds bounded measurement limit",
        ));
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"CNP/1\0");
    hasher.update(&("cnp.blob.v1".len() as u32).to_be_bytes());
    hasher.update(b"cnp.blob.v1");
    hasher.update(&length.to_be_bytes());
    let mut buffer = [0u8; 8192];
    let mut consumed = 0u64;
    loop {
        let count = file.read(&mut buffer).map_err(native)?;
        if count == 0 {
            break;
        }
        consumed = consumed
            .checked_add(count as u64)
            .filter(|total| *total <= length)
            .ok_or_else(|| refused("installed executable changed during measurement"))?;
        hasher.update(&buffer[..count]);
    }
    if consumed != length {
        return Err(refused("installed executable changed during measurement"));
    }
    Ok(ContentRef {
        hash: HashRef {
            algorithm: "blake3-256".into(),
            domain: "cnp.blob.v1".into(),
            digest: hasher.finalize().to_hex().to_string(),
        },
        length: U64::new(length),
        media_type: "application/octet-stream".into(),
    })
}

fn native(error: impl std::fmt::Debug) -> NodeObservedError {
    NodeObservedError::Native(format!("{error:?}"))
}
fn refused(reason: &str) -> NodeObservedError {
    NodeObservedError::Native(reason.to_owned())
}

fn execution_text(execution: ExecutionId) -> String {
    execution
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
