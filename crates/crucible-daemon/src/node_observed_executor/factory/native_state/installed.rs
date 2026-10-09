//! Owns installed mixed-world capacity and locally fresh inactive realizations.
//!
//! One process-lifetime native supervisor bounds every world and actor. Live
//! preparation reserves both native and whole-runtime custody before spawning;
//! cold preparation reserves authenticated image custody before graph admission
//! and leaves child allocation to the already installed restoration capsule.

use std::{
    fs::File,
    io::Read,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    rc::Rc,
    time::Duration,
};

use crucible::{
    node_adapters::{
        HostModel, HostModelNode, HostModelResources,
        gem5::{Gem5ArchiveInstallation, Gem5NodePreparation},
    },
    node_admission::{AdmissionLimits, AdmittedGraph},
    node_contract::{
        ActivationRecord, OwnerIdentity, PreparedRealization, RuntimeCustodyQueue,
        RuntimeCustodySupervisor, RuntimeLimits, SimulationNode,
    },
    node_state::{NativeArchiveRecord, PublicationKnowledge},
};
use crucible_device::clock::VirtualClock;
use crucible_node_contract::{Id, LiveAuthority, NodeBinding, Phase, Position, U64};
use crucible_node_provider::gem5::{
    Gem5CustodySlot, Gem5Launch, Gem5NativeProcess, Gem5ProcessImageTools,
};

use super::super::{InstalledGem5ClosedProfile, NodeObservedError, measure_executable, refused};
use super::{
    custody::{Gem5CustodyQueue, NativeBacking, NativeOwnerScope},
    evidence::{MixedEvidence, ReservedMixedRestore},
    profile::{MixedProfile, native_resources},
};

/// Shares installed native capacity across all worlds and actor lifetimes.
pub(super) struct InstalledMixedEngine {
    pub(super) native: Gem5CustodyQueue,
    pub(super) runtime: RuntimeCustodyQueue,
    pub(super) root: PathBuf,
    pub(super) installed: Rc<InstalledGem5ClosedProfile>,
    host: PathBuf,
}

pub(super) struct MixedLiveWorld {
    pub(super) profile: Rc<MixedProfile>,
    pub(super) graph: Rc<AdmittedGraph>,
    pub(super) evidence: Rc<MixedEvidence>,
    pub(super) target: ActivationRecord,
    pub(super) realization: PreparedRealization,
    pub(super) namespace: PathBuf,
}

/// Retains the reserved original image lease without claiming native readiness.
pub(super) struct MixedColdPlan {
    pub(super) profile: Rc<MixedProfile>,
    pub(super) graph: Rc<AdmittedGraph>,
    pub(super) evidence: Rc<MixedEvidence>,
    pub(super) target: ActivationRecord,
    pub(super) archive: NativeArchiveRecord,
    pub(super) slot: Box<dyn Gem5CustodySlot>,
    pub(super) namespace: PathBuf,
}

impl InstalledMixedEngine {
    pub(super) fn new(root: PathBuf, maximum_worlds: usize) -> Result<Self, NodeObservedError> {
        private_parent(&root)?;
        Ok(Self {
            native: Gem5CustodyQueue::installed(maximum_worlds).map_err(error)?,
            runtime: RuntimeCustodyQueue::new(maximum_worlds).map_err(error)?,
            root,
            installed: InstalledGem5ClosedProfile::built_in()?,
            host: PathBuf::from("/proc/self/exe"),
        })
    }

    pub(super) fn with_runtime(
        root: PathBuf,
        runtime: RuntimeCustodyQueue,
    ) -> Result<Self, NodeObservedError> {
        private_parent(&root)?;
        Ok(Self {
            native: Gem5CustodyQueue::installed(8).map_err(error)?,
            runtime,
            root,
            installed: InstalledGem5ClosedProfile::built_in()?,
            host: PathBuf::from("/proc/self/exe"),
        })
    }

    /// Prepares an actual closed native peer and clock beneath reserved custody.
    pub(super) fn prepare_live(&self, isa: &str) -> Result<MixedLiveWorld, NodeObservedError> {
        self.prepare_live_selected(isa, false, None)
    }

    pub(super) fn prepare_public_initial(
        &self,
        isa: &str,
        activation_id: Id,
    ) -> Result<MixedLiveWorld, NodeObservedError> {
        self.prepare_live_selected(isa, true, Some(activation_id))
    }

    fn prepare_live_selected(
        &self,
        isa: &str,
        public: bool,
        activation_id: Option<Id>,
    ) -> Result<MixedLiveWorld, NodeObservedError> {
        let profile = Rc::new(if public {
            MixedProfile::build_public(
                self.installed.clone(),
                &measure_executable(&self.host)?,
                isa,
            )?
        } else {
            MixedProfile::build(
                self.installed.clone(),
                &measure_executable(&self.host)?,
                isa,
            )?
        });
        let mut target = fresh_target(&profile, None)?;
        if let Some(activation_id) = activation_id {
            target.activation_id = activation_id;
        }
        let runtime_slot = self
            .runtime
            .reserve_world(&target, runtime_limits())
            .map_err(error)?;
        let files = [
            "native_executable",
            "controller",
            "model",
            "dmtcp_launch",
            "dmtcp_restart",
            "mtcp_restart",
            "image_guard",
            "auditor",
        ]
        .into_iter()
        .map(|key| {
            self.installed
                .artifact(key)
                .and_then(|artifact| File::open(artifact.path).map_err(error))
        })
        .chain(std::iter::once(
            self.installed
                .guest(isa)
                .and_then(|guest| File::open(guest.path).map_err(error)),
        ))
        .collect::<Result<Vec<_>, _>>()?;
        let cpu = cpu_owner(&target)?;
        let slot = self
            .native
            .reserve(NativeOwnerScope {
                activation: target.clone(),
                owner: cpu.clone(),
                publication: PublicationKnowledge::NotAttempted,
                backing: NativeBacking::Fresh { files },
            })
            .map_err(error)?;
        let namespace = self.namespace()?;
        let mut native =
            Gem5NativeProcess::spawn(launch(&self.installed, isa, &cpu, &namespace)?, slot)
                .map_err(|failure| refused(&format!("initial native spawn: {failure}")))?;
        let capture = native
            .capture(
                Id::new(format!("initial/{}", fresh_nonce()?))?,
                &namespace.join("initial"),
            )
            .map_err(|failure| refused(&format!("initial native image capture: {failure}")))?;
        let auditor = self.installed.artifact("auditor")?;
        let certificate = native
            .qualify_capture(&capture, &namespace, &auditor, self.installed.as_ref())
            .map_err(|failure| {
                refused(&format!("initial native closure qualification: {failure}"))
            })?;
        let authority = native
            .qualify_exact(
                &capture,
                &certificate,
                &auditor,
                self.installed.as_ref(),
                self.installed.maximum_microsteps(),
            )
            .map_err(|failure| {
                refused(&format!("initial native exact qualification: {failure}"))
            })?;
        let clock = HostModel::Clock(VirtualClock::new());
        let receipt = MixedEvidence::live_enrollment_receipt(&profile, &clock, &native, &authority)
            .map_err(|failure| refused(&format!("initial mixed enrollment receipt: {failure}")))?;
        let bindings = bindings(&profile, &target, &receipt.reference)?;
        let evidence = Rc::new(
            MixedEvidence::enroll_live(
                &profile, &bindings, &clock, &native, &authority, &self.host,
            )
            .map_err(|failure| refused(&format!("initial mixed enrollment: {failure}")))?,
        );
        let graph = Rc::new(
            profile
                .scenario
                .admit(&bindings, evidence.as_ref(), admission_limits())
                .map_err(|failure| refused(&format!("initial mixed graph admission: {failure}")))?,
        );
        let mut clock = HostModelNode::new(
            &graph,
            &Id::new("clock")?,
            clock,
            evidence.as_ref(),
            host_resources(),
        )
        .map_err(|failure| refused(&failure.reason))?;
        if public {
            clock
                .qualify_public_initial_clock(&graph, evidence.as_ref())
                .map_err(|failure| refused(&failure.reason))?;
        }
        let qualification = evidence.qualify_prepared(&native, &authority)?;
        let prepared =
            Gem5NodePreparation::from_prepared(&graph, &Id::new("cpu")?, native, &qualification)
                .map_err(|failure| refused(&failure.error.reason))?;
        let cpu = if public {
            prepared
                .into_qualified_simulation_node(&graph, authority, native_resources(isa)?)
                .map_err(|failure| refused(&failure.error.reason))?
                .into_public_initial_preparation(&graph, &qualification)
                .map_err(|failure| refused(&failure.error.reason))?
        } else {
            prepared
                .into_qualified_capturing_simulation_node(
                    &graph,
                    authority,
                    native_resources(isa)?,
                    archive_installation(&self.installed, &namespace)?,
                )
                .map_err(|failure| refused(&failure.error.reason))?
        };
        let nodes: Vec<Box<dyn SimulationNode>> = vec![Box::new(clock), Box::new(cpu)];
        let realization =
            PreparedRealization::new(nodes, target.clone(), runtime_limits(), runtime_slot);
        Ok(MixedLiveWorld {
            profile,
            graph,
            evidence,
            target,
            realization,
            namespace,
        })
    }

    /// Admits a fresh inactive reserved-image realization without allocating a child.
    pub(super) fn prepare_cold(
        &self,
        archive: NativeArchiveRecord,
        isa: &str,
    ) -> Result<MixedColdPlan, NodeObservedError> {
        let profile = Rc::new(MixedProfile::build(
            self.installed.clone(),
            &measure_executable(&self.host)?,
            isa,
        )?);
        let target = fresh_target(&profile, Some(&archive))?;
        let cpu = cpu_owner(&target)?;
        let artifacts = archive.owner_artifacts(&cpu.owner).map_err(error)?;
        let slot = self
            .native
            .reserve(NativeOwnerScope {
                activation: target.clone(),
                owner: cpu,
                publication: PublicationKnowledge::NotAttempted,
                backing: NativeBacking::Archived {
                    source: Box::new(archive.clone()),
                    artifacts,
                },
            })
            .map_err(error)?;
        let reservation =
            ReservedMixedRestore::new(archive.clone(), target.clone(), self.native.clone())?;
        let clock = HostModel::Clock(VirtualClock::new());
        let receipt = MixedEvidence::reserved_enrollment_receipt(&profile, &clock, &reservation)?;
        let bindings = bindings(&profile, &target, &receipt.reference)?;
        let evidence = Rc::new(MixedEvidence::enroll_reserved_restore(
            &profile,
            &bindings,
            &clock,
            reservation,
            &self.host,
        )?);
        let graph = Rc::new(profile.scenario.admit(
            &bindings,
            evidence.as_ref(),
            admission_limits(),
        )?);
        let namespace = self.namespace()?;
        Ok(MixedColdPlan {
            profile,
            graph,
            evidence,
            target,
            archive,
            slot,
            namespace,
        })
    }

    fn namespace(&self) -> Result<PathBuf, NodeObservedError> {
        let nonce = fresh_nonce()?;
        let root = self.root.join(&nonce[..32]);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .map_err(error)?;
        // Roots remain owned data until the authentic supervisor transfers the
        // original capsule. No temporary-directory Drop may remove live images.
        for name in [
            "native",
            "images",
            "temporary",
            "initial",
            "captures",
            "historical",
        ] {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(root.join(name))
                .map_err(error)?;
        }
        Ok(root)
    }
}

pub(super) fn runtime_limits() -> RuntimeLimits {
    RuntimeLimits {
        maximum_nodes: 2,
        maximum_owners: 2,
        maximum_operations: 4096,
        maximum_retained_outputs: 4096,
    }
}

pub(super) fn host_resources() -> HostModelResources {
    HostModelResources {
        maximum_capture_bytes: 64 * 1024 * 1024,
        maximum_operations: 4096,
    }
}

pub(super) fn archive_installation(
    installed: &Rc<InstalledGem5ClosedProfile>,
    namespace: &Path,
) -> Result<Gem5ArchiveInstallation, NodeObservedError> {
    Ok(Gem5ArchiveInstallation {
        auditor: installed.artifact("auditor")?,
        verifier: installed.clone(),
        owned_scope: namespace.to_owned(),
        captures_root: namespace.join("captures"),
        maximum_captures: 16,
    })
}

fn launch(
    installed: &InstalledGem5ClosedProfile,
    isa: &str,
    owner: &OwnerIdentity,
    namespace: &Path,
) -> Result<Gem5Launch, NodeObservedError> {
    Ok(Gem5Launch {
        executable: installed.artifact("native_executable")?,
        owner_script: installed.artifact("controller")?,
        model_script: installed.artifact("model")?,
        guest: installed.guest(isa)?,
        guest_isa: isa.into(),
        owner: owner.owner.clone(),
        incarnation: owner.incarnation.clone(),
        generation: owner.generation,
        resource_root: namespace.join("native"),
        timeout: Duration::from_secs(60),
        process_images: Some(Gem5ProcessImageTools {
            launcher: installed.artifact("dmtcp_launch")?,
            restarter: installed.artifact("dmtcp_restart")?,
            reconstruction_executable: installed.artifact("mtcp_restart")?,
            resource_helper: installed.artifact("image_guard")?,
            image_root: namespace.join("images"),
            temporary_root: namespace.join("temporary"),
        }),
    })
}

fn fresh_target(
    profile: &MixedProfile,
    source: Option<&NativeArchiveRecord>,
) -> Result<ActivationRecord, NodeObservedError> {
    let previous = source
        .map(|record| record.source_activation())
        .transpose()
        .map_err(error)?;
    let world = profile.scenario.world.identity()?;
    if source.is_some_and(|record| record.manifest().world_binding_hash != world) {
        return Err(refused(
            "mixed source selects another installed backend or guest",
        ));
    }
    let owners = profile
        .scenario
        .owners
        .iter()
        .map(|binding| {
            let generation = match previous.as_ref() {
                Some(previous) => previous
                    .owners
                    .iter()
                    .find(|owner| owner.owner == binding.owner.id)
                    .ok_or_else(|| refused("mixed source owner absent"))?
                    .generation
                    .checked_add(U64::new(1))?,
                None => U64::new(1),
            };
            Ok(OwnerIdentity {
                owner: binding.owner.id.clone(),
                incarnation: Id::new(format!("mixed/{}", fresh_nonce()?))?,
                generation,
            })
        })
        .collect::<Result<Vec<_>, NodeObservedError>>()?;
    Ok(ActivationRecord {
        generation: previous
            .map(|record| record.generation.checked_add(U64::new(1)))
            .transpose()?
            .unwrap_or(U64::new(1)),
        activation_id: Id::new(format!("mixed/{}", fresh_nonce()?))?,
        world_binding_hash: world,
        owners,
        boundary: source
            .map(|record| record.manifest().cut)
            .unwrap_or(Position::new(
                U64::new(0),
                U64::new(0),
                Phase::BoundaryControl,
            )),
    })
}

fn bindings(
    profile: &MixedProfile,
    target: &ActivationRecord,
    receipt: &crucible_node_contract::ContentRef,
) -> Result<Vec<NodeBinding>, NodeObservedError> {
    let session = Id::new(format!("mixed/{}", fresh_nonce()?))?;
    profile
        .scenario
        .compatibility
        .iter()
        .map(|selected| {
            let owner = target
                .owners
                .iter()
                .find(|owner| owner.owner == selected.execution_owner.id)
                .ok_or_else(|| refused("mixed authoritative owner absent"))?;
            Ok(NodeBinding {
                compatibility: selected.clone(),
                authority: LiveAuthority {
                    schema_version: 1,
                    session_id: session.clone(),
                    incarnation_id: owner.incarnation.clone(),
                    realization_id: session.clone(),
                    activation_id: None,
                    // This binding owns inactive realization custody. Only the
                    // complete activation barrier publishes target.generation.
                    world_generation: U64::new(0),
                    owner_generation: owner.generation,
                    input_epoch: session.clone(),
                    host_receipt: receipt.clone(),
                    extensions: Default::default(),
                },
                extensions: Default::default(),
            })
        })
        .collect()
}

fn cpu_owner(target: &ActivationRecord) -> Result<OwnerIdentity, NodeObservedError> {
    target
        .owners
        .iter()
        .find(|owner| owner.owner.as_str() == "owner/cpu")
        .cloned()
        .ok_or_else(|| refused("mixed CPU owner absent"))
}

fn admission_limits() -> AdmissionLimits {
    AdmissionLimits {
        maximum_content_bytes: 512 * 1024 * 1024,
        maximum_total_content_bytes: 2 * 1024 * 1024 * 1024,
        ..AdmissionLimits::default()
    }
}

fn fresh_nonce() -> Result<String, NodeObservedError> {
    let mut entropy = [0_u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut entropy))
        .map_err(error)?;
    Ok(entropy.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn private_parent(path: &Path) -> Result<(), NodeObservedError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path).map_err(error)?;
    if !path.is_absolute()
        || !metadata.is_dir()
        || metadata.mode() & 0o777 != 0o700
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || std::fs::canonicalize(path).map_err(error)? != path
    {
        return Err(refused(
            "installed mixed root must be canonical, locally owned and private",
        ));
    }
    Ok(())
}

fn error(error: impl std::fmt::Display) -> NodeObservedError {
    refused(&error.to_string())
}

#[cfg(test)]
#[path = "initial_preparation_tests.rs"]
mod initial_preparation_tests;
