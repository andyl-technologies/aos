//! Allocates genuine initial Root/Clock owners beneath pre-reserved supervisors.
//!
//! The installed profile is regenerated before spawning. Both the native slot
//! and whole-runtime slot already own the target; every subsequent failure
//! transfers the real process and complete raw journals to that supervisor.

use std::{
    fs::{self, File},
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    rc::Rc,
    time::Duration,
};

use crucible::{
    node_adapters::{
        HostModel, HostModelNode, HostModelResources,
        arm_root::{ArmRootArchiveInstallation, ArmRootNodePreparation, ArmRootNodeResources},
    },
    node_admission::{AdmissionLimits, AdmittedGraph},
    node_contract::{
        ActivationRecord, OwnerIdentity, PreparedRealization, RuntimeCustodyQueue,
        RuntimeCustodySupervisor, RuntimeLimits, SimulationNode,
    },
    node_state::{NativeArchiveRecord, PublicationKnowledge},
};
use crucible_device::clock::VirtualClock;
use crucible_node_contract::{Id, Phase, Position};
use crucible_node_provider::gem5::{ArmRootLaunch, ArmRootNativeProcess};

use super::super::{NodeObservedError, measure_executable, refused};
use super::{
    custody::{RootBacking, RootCustodyQueue, RootScope},
    evidence::{ReservedRootRestore, RootEvidence, fresh_nonce},
    profile::RootWorldProfile,
    qualification::RootPreparedQualification,
};

pub(super) struct RootInstalledEngine {
    pub(super) native: RootCustodyQueue,
    pub(super) runtime: RuntimeCustodyQueue,
    root: PathBuf,
    host: PathBuf,
}

pub(super) struct RootLiveWorld {
    pub(super) profile: Rc<RootWorldProfile>,
    pub(super) graph: Rc<AdmittedGraph>,
    pub(super) evidence: Rc<RootEvidence>,
    #[cfg(test)]
    pub(super) target: ActivationRecord,
    pub(super) realization: PreparedRealization,
    #[cfg(test)]
    pub(super) namespace: PathBuf,
}

pub(super) struct RootColdPlan {
    pub(super) profile: Rc<RootWorldProfile>,
    pub(super) graph: Rc<AdmittedGraph>,
    pub(super) evidence: Rc<RootEvidence>,
    pub(super) target: ActivationRecord,
    pub(super) archive: NativeArchiveRecord,
    pub(super) slot: Box<dyn crucible_node_provider::gem5::ArmRootCustodySlot>,
    pub(super) namespace: PathBuf,
}

impl RootInstalledEngine {
    #[cfg(test)]
    pub(super) fn new(root: PathBuf) -> Result<Self, NodeObservedError> {
        Self::with_runtime(root, RuntimeCustodyQueue::new(8).map_err(error)?)
    }

    pub(super) fn with_runtime(
        root: PathBuf,
        runtime: RuntimeCustodyQueue,
    ) -> Result<Self, NodeObservedError> {
        validate_private_root(&root)?;
        Ok(Self {
            native: RootCustodyQueue::installed()?,
            runtime,
            root,
            host: PathBuf::from("/proc/self/exe"),
        })
    }

    pub(super) fn prepare_initial(&self) -> Result<RootLiveWorld, NodeObservedError> {
        use std::os::unix::ffi::OsStrExt;
        let nonce = fresh_nonce()?;
        let suffix = nonce
            .get(..24)
            .ok_or_else(|| refused("Root namespace nonce geometry differs"))?;
        let namespace = self.root.join(format!("root-{suffix}"));
        if namespace
            .join("temporary/control.sock")
            .as_os_str()
            .as_bytes()
            .len()
            > 107
        {
            return Err(refused(
                "Root private control endpoint exceeds the installed Linux socket bound",
            ));
        }
        private_directory(&namespace)?;
        for child in ["native", "images", "temporary", "captures", "initial-image"] {
            private_directory(&namespace.join(child))?;
        }
        let root_owner = OwnerIdentity {
            owner: Id::new("owner/root")?,
            incarnation: Id::new(format!("root/{}", fresh_nonce()?))?,
            generation: 1.into(),
        };
        let clock_owner = OwnerIdentity {
            owner: Id::new("owner/clock")?,
            incarnation: Id::new(format!("clock/{}", fresh_nonce()?))?,
            generation: 1.into(),
        };
        let launch = ArmRootLaunch::installed(
            root_owner.owner.clone(),
            root_owner.incarnation.clone(),
            root_owner.generation,
            namespace.join("native"),
            namespace.join("images"),
            namespace.join("temporary"),
            Duration::from_secs(120),
        )
        .map_err(error)?;
        let profile = Rc::new(RootWorldProfile::build(
            &launch,
            &measure_executable(&self.host)?,
        )?);
        let target = ActivationRecord {
            activation_id: Id::new(format!("root-world/{}", fresh_nonce()?))?,
            generation: 1.into(),
            world_binding_hash: profile.scenario.world.identity()?,
            owners: vec![clock_owner.clone(), root_owner.clone()],
            boundary: Position::new(0.into(), 0.into(), Phase::BoundaryControl),
        };
        let runtime_slot = self
            .runtime
            .reserve_world(&target, runtime_limits())
            .map_err(error)?;
        let installed = launch.installed_model()["artifacts"]
            .as_object()
            .ok_or_else(|| refused("Root installed native backing roster is absent"))?;
        let files = installed
            .values()
            .map(|artifact| {
                let path = artifact["path"]
                    .as_str()
                    .ok_or_else(|| refused("Root installed backing path is absent"))?;
                File::open(path).map_err(error)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let native_slot = self.native.reserve(RootScope {
            activation: target.clone(),
            owner: root_owner,
            publication: PublicationKnowledge::NotAttempted,
            backing: RootBacking::Fresh(files),
        })?;

        let mut native = ArmRootNativeProcess::spawn(launch, native_slot).map_err(error)?;
        let image = native
            .capture(
                Id::new(format!("root-initial/{}", fresh_nonce()?))?,
                &namespace.join("initial-image"),
            )
            .map_err(error)?;
        let certificate = native.qualify_capture(&image, &namespace).map_err(error)?;
        let authority = native.qualify_exact(&image, &certificate).map_err(error)?;
        let clock = HostModel::Clock(VirtualClock::new());
        let (evidence, bindings) = RootEvidence::enroll_live(
            profile.clone(),
            &clock,
            &native,
            &authority,
            self.host.clone(),
            &clock_owner,
        )?;
        let graph = Rc::new(
            profile
                .scenario
                .admit(&bindings, evidence.as_ref(), admission_limits())
                .map_err(error)?,
        );
        let mut clock = HostModelNode::new(
            &graph,
            &Id::new("clock")?,
            clock,
            evidence.as_ref(),
            host_resources(),
        )
        .map_err(operation_error)?;
        clock
            .qualify_public_preserving_initial_clock(&graph, evidence.as_ref())
            .map_err(operation_error)?;
        let qualification =
            RootPreparedQualification::new(&profile, &graph, &native, &authority, None)?;
        let preparation = ArmRootNodePreparation::from_prepared(
            &graph,
            &Id::new("root")?,
            native,
            &qualification,
        )
        .map_err(|failure| operation_error(failure.error))?;
        let root = preparation
            .into_qualified_preserving_node(
                &graph,
                authority,
                ArmRootNodeResources::default(),
                ArmRootArchiveInstallation {
                    owned_scope: namespace.clone(),
                    captures_root: namespace.join("captures"),
                    maximum_captures: 8,
                },
            )
            .map_err(|failure| operation_error(failure.error))?;
        let nodes: Vec<Box<dyn SimulationNode>> = vec![Box::new(clock), Box::new(root)];
        let realization =
            PreparedRealization::new(nodes, target.clone(), runtime_limits(), runtime_slot);
        Ok(RootLiveWorld {
            profile,
            graph,
            evidence,
            #[cfg(test)]
            target,
            realization,
            #[cfg(test)]
            namespace,
        })
    }

    #[cfg(test)]
    pub(super) fn poll_reclamation(&self) -> Result<bool, NodeObservedError> {
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        if let std::task::Poll::Ready(Err(failure)) = self.runtime.poll_reclamation(&mut context) {
            return Err(error(failure));
        }
        Ok(self.runtime.reserved_worlds() == 0 && self.native.all_groups_reclaimed())
    }

    pub(super) fn prepare_cold(
        &self,
        archive: NativeArchiveRecord,
    ) -> Result<RootColdPlan, NodeObservedError> {
        let previous = archive.source_activation().map_err(error)?;
        if previous.owners.len() != 2 {
            return Err(refused(
                "Root cold source omits its complete original roster",
            ));
        }
        let mut owners = Vec::new();
        owners.try_reserve_exact(2).map_err(error)?;
        for name in ["owner/clock", "owner/root"] {
            let original = previous
                .owners
                .iter()
                .find(|owner| owner.owner.as_str() == name)
                .ok_or_else(|| refused("Root cold source selects another logical owner"))?;
            owners.push(OwnerIdentity {
                owner: original.owner.clone(),
                incarnation: Id::new(format!("root-cold/{}", fresh_nonce()?))?,
                generation: original.generation.checked_add(1.into())?,
            });
        }
        let nonce = fresh_nonce()?;
        let suffix = nonce
            .get(..24)
            .ok_or_else(|| refused("Root cold namespace geometry differs"))?;
        let namespace = self.root.join(format!("root-{suffix}"));
        // The transport geometry is checked before creating any namespace or
        // consuming native custody; restore uses the same private socket leaf.
        if namespace
            .join("native/control.sock")
            .as_os_str()
            .as_encoded_bytes()
            .len()
            > 107
        {
            return Err(refused(
                "Root cold control socket exceeds the installed transport geometry",
            ));
        }
        private_directory(&namespace)?;
        for child in [
            "native",
            "images",
            "temporary",
            "captures",
            "initial-image",
            "historical",
        ] {
            private_directory(&namespace.join(child))?;
        }
        let root = &owners[1];
        let launch = ArmRootLaunch::installed(
            root.owner.clone(),
            root.incarnation.clone(),
            root.generation,
            namespace.join("native"),
            namespace.join("images"),
            namespace.join("temporary"),
            Duration::from_secs(120),
        )
        .map_err(error)?;
        let profile = Rc::new(RootWorldProfile::build(
            &launch,
            &measure_executable(&self.host)?,
        )?);
        if profile.scenario.world.identity()? != archive.manifest().world_binding_hash {
            return Err(refused(
                "Root cold source differs from independently regenerated installed world",
            ));
        }
        let target = ActivationRecord {
            activation_id: Id::new(format!("root-world/{}", fresh_nonce()?))?,
            generation: previous.generation.checked_add(1.into())?,
            world_binding_hash: archive.manifest().world_binding_hash.clone(),
            boundary: archive.manifest().cut,
            owners,
        };
        let artifacts = match self
            .native
            .retained_artifacts(&archive, &target.owners[1].owner)?
        {
            Some(artifacts) => artifacts,
            None => archive
                .owner_artifacts(&target.owners[1].owner)
                .map_err(error)?,
        };
        let slot = self.native.reserve(RootScope {
            activation: target.clone(),
            owner: target.owners[1].clone(),
            publication: PublicationKnowledge::NotAttempted,
            backing: RootBacking::Archived {
                source: Box::new(archive.clone()),
                artifacts,
            },
        })?;
        let reserved =
            ReservedRootRestore::new(archive.clone(), target.clone(), self.native.clone())?;
        let clock = HostModel::Clock(VirtualClock::new());
        let (evidence, bindings) =
            RootEvidence::enroll_reserved(profile.clone(), &clock, reserved, self.host.clone())?;
        let graph = Rc::new(
            profile
                .scenario
                .admit(&bindings, evidence.as_ref(), admission_limits())
                .map_err(error)?,
        );
        Ok(RootColdPlan {
            profile,
            graph,
            evidence,
            target,
            archive,
            slot,
            namespace,
        })
    }
}

pub(super) fn runtime_limits() -> RuntimeLimits {
    RuntimeLimits::default()
}

pub(super) fn host_resources() -> HostModelResources {
    HostModelResources::default()
}

fn admission_limits() -> AdmissionLimits {
    AdmissionLimits {
        maximum_content_bytes: 512 * 1024 * 1024,
        maximum_total_content_bytes: 2 * 1024 * 1024 * 1024,
        ..AdmissionLimits::default()
    }
}

fn private_directory(path: &Path) -> Result<(), NodeObservedError> {
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(error)?;
    validate_private_root(path)
}

fn validate_private_root(path: &Path) -> Result<(), NodeObservedError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::symlink_metadata(path).map_err(error)?;
    if !metadata.is_dir()
        || path.canonicalize().map_err(error)? != path
        || metadata.permissions().mode() & 0o777 != 0o700
        || metadata.uid() != rustix::process::getuid().as_raw()
    {
        return Err(refused(
            "Root world namespace lacks canonical private owner custody",
        ));
    }
    Ok(())
}

fn operation_error(error: crucible::node_contract::OperationFailure) -> NodeObservedError {
    refused(&error.reason)
}

fn error(error: impl std::fmt::Display) -> NodeObservedError {
    refused(&error.to_string())
}
