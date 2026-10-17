//! Enrolls actual Root/Clock resources independently of portable profile claims.
//!
//! Live enrollment borrows the current native authority and authentic original
//! session. Cold enrollment uses its separately owned reserved-image successor;
//! an enrollment receipt never certifies native Ready or constructs authority.

use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, Read, Write},
    path::PathBuf,
    rc::Rc,
};

use crucible::{
    node_adapters::{HostModel, HostModelQualification},
    node_admission::{AdmissionEvidence, EvidenceError, QualificationClaim},
    node_contract::{ActivationRecord, EffectKnowledge, OperationFailure},
    node_state::NativeArchiveRecord,
};
use crucible_node_contract::{
    ContentRef, Id, ImplementationIdentity, LiveAuthority, NodeBinding, NodeDescriptor, SchemaRef,
    canonical,
};
use crucible_node_provider::gem5::{
    ArmRootExactAuthority, ArmRootNativeProcess, InstalledArmRootMechanism,
};

use super::super::{NodeObservedError, measure_executable, refused};
use super::{custody::RootCustodyQueue, profile::RootWorldProfile, qualification::RootPeer};
use crate::node_scenario::ScenarioContent;

mod admission;
mod immutable;

pub(super) use immutable::RootImmutableEvidence;

pub(super) struct RootEvidence {
    pub(super) profile: Rc<RootWorldProfile>,
    pub(super) bindings: BTreeMap<Id, NodeBinding>,
    pub(super) receipt: ScenarioContent,
    scope: RootAuthorityScope,
    clock: Vec<u8>,
    assets: BTreeMap<ContentRef, PathBuf>,
}

impl RootEvidence {
    pub(super) fn enroll_live(
        profile: Rc<RootWorldProfile>,
        clock: &HostModel,
        native: &ArmRootNativeProcess,
        authority: &ArmRootExactAuthority,
        host: PathBuf,
        clock_owner: &crucible::node_contract::OwnerIdentity,
    ) -> Result<(Rc<Self>, Vec<NodeBinding>), NodeObservedError> {
        if !matches!(clock, HostModel::Clock(_)) {
            return Err(refused(
                "Root world cannot enroll another Host model as its integer Clock",
            ));
        }
        let clock = clock.initialization_bytes(1024).map_err(operation_error)?;
        let selected_clock = profile
            .scenario
            .descriptors
            .iter()
            .find(|descriptor| descriptor.id.as_str() == "clock")
            .ok_or_else(|| refused("Root selected Clock initialization is absent"))?;
        selected_clock.initialization_ref.verify(&clock)?;
        let peer = RootPeer::measure(&profile, native, authority, None)?;
        let launch = native.launch().map_err(display_error)?;
        let clock_compatibility = profile
            .scenario
            .compatibility
            .iter()
            .find(|binding| binding.node_id.as_str() == "clock")
            .ok_or_else(|| refused("Root world integer Clock compatibility is absent"))?;
        if clock_owner.owner != clock_compatibility.execution_owner.id
            || clock_owner.generation.get() == 0
        {
            return Err(refused(
                "Root actual owned Clock targets another locally prepared owner",
            ));
        }
        let world = profile.scenario.world.identity()?;
        let clock_ref = canonical::content_ref(&clock, "application/octet-stream")?;
        let enrollment = LiveEnrollment {
            schema: "crucible.root-clock-live-enrollment.v1",
            world: &world,
            installed: &profile.installed,
            clock: &clock_ref,
            clock_owner,
            native: &peer,
        };
        let bytes = metadata_bytes(&enrollment)?;
        let receipt = ScenarioContent {
            reference: canonical::content_ref(&bytes, "application/json")?,
            bytes,
        };
        let mut bindings = BTreeMap::new();
        for compatibility in &profile.scenario.compatibility {
            let (incarnation_id, owner_generation) = if compatibility.node_id.as_str() == "root" {
                if compatibility.execution_owner.id != *launch.owner() {
                    return Err(refused(
                        "Root native owner differs from selected indivisible owner",
                    ));
                }
                (launch.incarnation().clone(), launch.generation())
            } else if compatibility.node_id.as_str() == "clock" {
                (clock_owner.incarnation.clone(), clock_owner.generation)
            } else {
                return Err(refused("Root world contains an uninstalled participant"));
            };
            bindings.insert(
                compatibility.node_id.clone(),
                NodeBinding {
                    compatibility: compatibility.clone(),
                    authority: LiveAuthority {
                        schema_version: 1,
                        session_id: Id::new(format!("root-session/{}", fresh_nonce()?))?,
                        incarnation_id,
                        realization_id: Id::new(format!("root-realization/{}", fresh_nonce()?))?,
                        activation_id: None,
                        world_generation: 0.into(),
                        owner_generation,
                        input_epoch: Id::new(format!("root-input-epoch/{}", fresh_nonce()?))?,
                        host_receipt: receipt.reference.clone(),
                        extensions: crucible_node_contract::Extensions::new(),
                    },
                    extensions: crucible_node_contract::Extensions::new(),
                },
            );
        }
        if InstalledArmRootMechanism::load()
            .map_err(display_error)?
            .document()
            != launch.installed_model()
        {
            return Err(refused(
                "Root installation changed during actual enrollment",
            ));
        }
        let assets = installed_assets(&profile, &bindings, host)?;
        let ordered = bindings.values().cloned().collect();
        Ok((
            Rc::new(Self {
                profile,
                bindings,
                receipt,
                scope: RootAuthorityScope::Live(Box::new(peer)),
                clock,
                assets,
            }),
            ordered,
        ))
    }

    pub(super) fn enroll_reserved(
        profile: Rc<RootWorldProfile>,
        clock: &HostModel,
        reservation: ReservedRootRestore,
        host: PathBuf,
    ) -> Result<(Rc<Self>, Vec<NodeBinding>), NodeObservedError> {
        reservation.authenticate()?;
        if !matches!(clock, HostModel::Clock(_))
            || reservation.target.world_binding_hash != profile.scenario.world.identity()?
        {
            return Err(refused(
                "Root reserved enrollment selects another owned model or world",
            ));
        }
        let clock = clock.initialization_bytes(1024).map_err(operation_error)?;
        let descriptor = profile
            .scenario
            .descriptors
            .iter()
            .find(|node| node.id.as_str() == "clock")
            .ok_or_else(|| refused("Root reserved Clock descriptor is absent"))?;
        descriptor.initialization_ref.verify(&clock)?;
        let enrollment = ReservedEnrollment {
            schema: "crucible.root-clock-reserved-enrollment.v1",
            source: reservation.source.artifact(),
            target: crucible::node_contract::SavedRuntimeActivation::from(&reservation.target),
            installed: &profile.installed,
            clock: &descriptor.initialization_ref,
        };
        let bytes = metadata_bytes(&enrollment)?;
        let receipt = ScenarioContent {
            reference: canonical::content_ref(&bytes, "application/json")?,
            bytes,
        };
        let mut bindings = BTreeMap::new();
        for compatibility in &profile.scenario.compatibility {
            let owner = reservation
                .target
                .owners
                .iter()
                .find(|owner| owner.owner == compatibility.execution_owner.id)
                .ok_or_else(|| refused("Root owned reserved binding owner is absent"))?;
            bindings.insert(
                compatibility.node_id.clone(),
                NodeBinding {
                    compatibility: compatibility.clone(),
                    authority: LiveAuthority {
                        schema_version: 1,
                        session_id: Id::new(format!("root-session/{}", fresh_nonce()?))?,
                        incarnation_id: owner.incarnation.clone(),
                        realization_id: Id::new(format!("root-realization/{}", fresh_nonce()?))?,
                        activation_id: None,
                        world_generation: 0.into(),
                        owner_generation: owner.generation,
                        input_epoch: Id::new(format!("root-input-epoch/{}", fresh_nonce()?))?,
                        host_receipt: receipt.reference.clone(),
                        extensions: crucible_node_contract::Extensions::new(),
                    },
                    extensions: crucible_node_contract::Extensions::new(),
                },
            );
        }
        let assets = installed_assets(&profile, &bindings, host)?;
        let ordered = bindings.values().cloned().collect();
        Ok((
            Rc::new(Self {
                profile,
                bindings,
                receipt,
                scope: RootAuthorityScope::Reserved(Box::new(reservation)),
                clock,
                assets,
            }),
            ordered,
        ))
    }

    pub(super) fn immutable_content(
        &self,
        reference: &ContentRef,
        maximum: usize,
    ) -> Result<Vec<u8>, EvidenceError> {
        let metadata = self
            .profile
            .scenario
            .content
            .iter()
            .find(|body| &body.reference == reference)
            .or_else(|| (&self.receipt.reference == reference).then_some(&self.receipt));
        if let Some(body) = metadata {
            if body.bytes.len() > maximum.min(16 * 1024 * 1024) {
                return Err(evidence(
                    "Root metadata exceeds selected finite content credit",
                ));
            }
            reference.verify(&body.bytes).map_err(contract_error)?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(body.bytes.len())
                .map_err(|_| evidence("Root metadata allocation is unavailable"))?;
            bytes.extend_from_slice(&body.bytes);
            return Ok(bytes);
        }
        let path = self
            .assets
            .get(reference)
            .ok_or_else(|| evidence("Root content has no installed original backing"))?;
        if reference.length.get() > maximum.min(512 * 1024 * 1024) as u64 {
            return Err(evidence(
                "Root immutable asset exceeds selected finite byte credit",
            ));
        }
        if measure_executable(path).map_err(observed_error)? != *reference {
            return Err(evidence("Root original installed asset changed"));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(reference.length.get() as usize)
            .map_err(|_| evidence("Root installed asset allocation is unavailable"))?;
        File::open(path)
            .map_err(|error| evidence(&error.to_string()))?
            .take(reference.length.get() + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| evidence(&error.to_string()))?;
        reference.verify(&bytes).map_err(contract_error)?;
        Ok(bytes)
    }

    pub(super) fn authenticate_scope(&self) -> Result<(), EvidenceError> {
        match &self.scope {
            RootAuthorityScope::Live(peer) => peer.verify_kernel().map_err(observed_error),
            RootAuthorityScope::Reserved(reservation) => {
                reservation.authenticate().map_err(observed_error)
            }
        }
    }

    pub(super) fn authenticate_binding(&self, binding: &NodeBinding) -> Result<(), EvidenceError> {
        if self.bindings.get(&binding.compatibility.node_id) != Some(binding)
            || binding.authority.host_receipt != self.receipt.reference
        {
            return Err(evidence(
                "Root authority is not the locally issued actual enrollment",
            ));
        }
        self.receipt
            .reference
            .verify(&self.receipt.bytes)
            .map_err(contract_error)?;
        self.authenticate_scope()
    }
}

impl HostModelQualification for RootEvidence {
    fn authenticate_model(
        &self,
        model: &HostModel,
        descriptor: &NodeDescriptor,
        binding: &NodeBinding,
    ) -> Result<(), OperationFailure> {
        if descriptor.id.as_str() != "clock"
            || !matches!(model, HostModel::Clock(_))
            || !self.profile.scenario.descriptors.contains(descriptor)
            || self.bindings.get(&descriptor.id) != Some(binding)
            || model.initialization_bytes(1024)? != self.clock
        {
            return Err(OperationFailure {
                effects: EffectKnowledge::None,
                reason: "Root world Clock differs from its original actually owned integer model"
                    .into(),
            });
        }
        self.authenticate_scope().map_err(|error| OperationFailure {
            effects: EffectKnowledge::None,
            reason: error.to_string(),
        })
    }
}

pub(super) fn evidence(message: &str) -> EvidenceError {
    EvidenceError {
        message: message.to_owned(),
    }
}
fn contract_error(error: crucible_node_contract::ContractError) -> EvidenceError {
    evidence(&error.to_string())
}
fn observed_error(error: NodeObservedError) -> EvidenceError {
    evidence(&error.to_string())
}
fn operation_error(error: OperationFailure) -> NodeObservedError {
    refused(&error.reason)
}
fn display_error(error: impl std::fmt::Display) -> NodeObservedError {
    refused(&error.to_string())
}

// Borrow the original measured scope until its serialized geometry is reserved.
#[derive(serde::Serialize)]
struct LiveEnrollment<'a> {
    schema: &'static str,
    world: &'a crucible_node_contract::HashRef,
    installed: &'a ContentRef,
    clock: &'a ContentRef,
    clock_owner: &'a crucible::node_contract::OwnerIdentity,
    native: &'a RootPeer,
}

pub(super) fn metadata_bytes(
    enrollment: &impl serde::Serialize,
) -> Result<Vec<u8>, NodeObservedError> {
    let mut writer = EnrollmentCredit {
        remaining: 16 * 1024 * 1024,
    };
    serde_json::to_writer(&mut writer, enrollment).map_err(display_error)?;
    // This closed DTO contains only strings, booleans and integral counters;
    // canonical ordering changes no scalar length after the preceding preflight.
    let value = serde_json::to_value(enrollment)?;
    let bytes = canonical::canonical_json(&value)?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(refused(
            "Root common metadata exceeds its reserved geometry",
        ));
    }
    Ok(bytes)
}

struct EnrollmentCredit {
    remaining: usize,
}

impl Write for EnrollmentCredit {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.remaining = self
            .remaining
            .checked_sub(bytes.len())
            .ok_or_else(|| io::Error::other("Root enrollment metadata credit exhausted"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn fresh_nonce() -> Result<String, NodeObservedError> {
    // Operational session freshness is outside the modeled RNG stream.
    let mut entropy = [0_u8; 32];
    File::open("/dev/urandom")
        .map_err(display_error)?
        .read_exact(&mut entropy)
        .map_err(display_error)?;
    Ok(entropy.iter().map(|byte| format!("{byte:02x}")).collect())
}

// Reserved image custody authenticates inactive enrollment, never native Ready.
enum RootAuthorityScope {
    Live(Box<RootPeer>),
    Reserved(Box<ReservedRootRestore>),
}

pub(super) struct ReservedRootRestore {
    pub(super) source: NativeArchiveRecord,
    pub(super) target: ActivationRecord,
    queue: RootCustodyQueue,
}

impl ReservedRootRestore {
    pub(super) fn new(
        source: NativeArchiveRecord,
        target: ActivationRecord,
        queue: RootCustodyQueue,
    ) -> Result<Self, NodeObservedError> {
        let previous = source.source_activation().map_err(display_error)?;
        if target.world_binding_hash != source.manifest().world_binding_hash
            || target.boundary != source.manifest().cut
            || target.activation_id == previous.activation_id
            || target.generation != previous.generation.checked_add(1.into())?
            || target.owners.len() != 2
            || previous.owners.len() != 2
        {
            return Err(refused(
                "Root reserved image targets another source cut or generation",
            ));
        }
        for (actual, original) in target.owners.iter().zip(&previous.owners) {
            if actual.owner != original.owner
                || actual.incarnation == original.incarnation
                || actual.generation != original.generation.checked_add(1.into())?
            {
                return Err(refused(
                    "Root reserved owner roster is not the exact fresh source mapping",
                ));
            }
        }
        let reserved = Self {
            source,
            target,
            queue,
        };
        reserved.authenticate()?;
        Ok(reserved)
    }

    fn authenticate(&self) -> Result<(), NodeObservedError> {
        let root = self
            .target
            .owners
            .iter()
            .find(|owner| owner.owner.as_str() == "owner/root")
            .ok_or_else(|| refused("Root reserved native owner is absent"))?;
        self.queue.verify_reserved(&self.target, root, &self.source)
    }
}

fn installed_assets(
    profile: &RootWorldProfile,
    bindings: &BTreeMap<Id, NodeBinding>,
    host: PathBuf,
) -> Result<BTreeMap<ContentRef, PathBuf>, NodeObservedError> {
    let mut assets = BTreeMap::new();
    let installed = InstalledArmRootMechanism::load().map_err(display_error)?;
    let artifacts = installed.document()["artifacts"]
        .as_object()
        .ok_or_else(|| refused("Root installed asset roster is absent"))?;
    if artifacts.len() != 33 {
        return Err(refused(
            "Root installation omits source/tool/configuration artifacts",
        ));
    }
    for artifact in artifacts.values() {
        let path = PathBuf::from(
            artifact["path"]
                .as_str()
                .ok_or_else(|| refused("Root installed asset path is absent"))?,
        );
        let reference = measure_executable(&path)?;
        if path.canonicalize().map_err(display_error)? != path || !path.starts_with("/nix/store") {
            return Err(refused(
                "Root immutable asset is outside canonical installed custody",
            ));
        }
        assets.insert(reference, path);
    }
    let original_manifest = option_env!("CRUCIBLE_GEM5_ARM_ROOT_MODEL_MANIFEST")
        .ok_or_else(|| refused("Root installed source policy was not compiled"))?;
    assets.insert(profile.installed.clone(), PathBuf::from(original_manifest));
    assets.insert(measure_executable(&host)?, host);
    for binding in bindings.values() {
        for artifact in &binding.compatibility.implementation.artifacts {
            if !assets.contains_key(&artifact.content) {
                return Err(refused(
                    "Root selected implementation asset lacks independently measured installed backing",
                ));
            }
        }
    }

    if measure_executable(PathBuf::from(original_manifest).as_path())? != profile.installed {
        return Err(refused(
            "Root immutable manifest differs from the complete installed selection",
        ));
    }
    Ok(assets)
}

#[derive(serde::Serialize)]
struct ReservedEnrollment<'a> {
    schema: &'static str,
    source: &'a ContentRef,
    target: crucible::node_contract::SavedRuntimeActivation,
    installed: &'a ContentRef,
    clock: &'a ContentRef,
}
