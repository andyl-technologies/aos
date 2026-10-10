//! Authenticates actual mixed resources without deriving authority from profiles.
//!
//! Live enrollment measures the owned clock and independently qualified parked
//! native peer. Cold enrollment authenticates an actually reserved signed-image
//! lease; it contains no child/readiness claim. Only a later current-peer check
//! produces the separate preparation qualifier under the installed capsule.

use std::{
    collections::BTreeMap,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    rc::Rc,
};

use crucible::{
    node_adapters::{HostModel, HostModelQualification, gem5::Gem5PreparationQualification},
    node_admission::{AdmissionEvidence, AdmittedGraph, EvidenceError, QualificationClaim},
    node_contract::{ActivationRecord, EffectKnowledge, OperationFailure},
    node_state::NativeArchiveRecord,
};
use crucible_node_contract::{
    ContentRef, HashRef, Id, ImplementationIdentity, NodeBinding, NodeDescriptor, Phase, Position,
    SchemaRef, U64, canonical,
};
use crucible_node_provider::gem5::{
    Gem5Boundary, Gem5ExactAuthority, Gem5Launch, Gem5NativeProcess, Gem5OpaqueProfileVerifier,
};

use super::super::{InstalledGem5ClosedProfile, NodeObservedError, measure_executable, refused};
use super::{custody::Gem5CustodyQueue, profile::MixedProfile};
use crate::node_scenario::{NodeScenario, ScenarioContent};

mod admission;
mod immutable;

pub(super) use immutable::MixedImmutableEvidence;

const MAXIMUM_CONTENT_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_INSTALLED_ARTIFACT_BYTES: usize = 512 * 1024 * 1024;

/// Owns the actual inactive archive lease independently of future native readiness.
pub(super) struct ReservedMixedRestore {
    source: NativeArchiveRecord,
    target: ActivationRecord,
    queue: Gem5CustodyQueue,
}

impl ReservedMixedRestore {
    /// Takes an already reserved lease and verifies its exact signed source/target.
    ///
    /// # Errors
    /// Refuses missing/in-use custody, another archive or an incomplete owner roster.
    pub(super) fn new(
        source: NativeArchiveRecord,
        target: ActivationRecord,
        queue: Gem5CustodyQueue,
    ) -> Result<Self, NodeObservedError> {
        let reservation = Self {
            source,
            target,
            queue,
        };
        reservation.verify()?;
        Ok(reservation)
    }

    fn verify(&self) -> Result<(), NodeObservedError> {
        if self.target.owners.len() != 2
            || self.source.owners().len() != 2
            || self.source.manifest().world_binding_hash != self.target.world_binding_hash
            || self.source.manifest().cut != self.target.boundary
        {
            return Err(refused("reserved mixed source or target is incomplete"));
        }
        let owner = self
            .target
            .owners
            .iter()
            .find(|owner| owner.owner.as_str() == "owner/cpu")
            .ok_or_else(|| refused("reserved mixed CPU owner is absent"))?;
        self.queue
            .verify_reserved_restore(&self.target, owner, &self.source)
            .map_err(|error| refused(&error.to_string()))
    }
}

enum NativeEnrollment {
    Live(Box<LivePeer>),
    Reserved(Box<ReservedMixedRestore>),
}

/// Retains immutable admission scope and authentic live or inactive owned resources.
pub(super) struct MixedEvidence {
    scenario: NodeScenario,
    installed: Rc<InstalledGem5ClosedProfile>,
    isa: String,
    qualification: ContentRef,
    bindings: BTreeMap<Id, NodeBinding>,
    clock: Vec<u8>,
    host_clocks: BTreeMap<Id, Vec<u8>>,
    receipt: ScenarioContent,
    native: NativeEnrollment,
    assets: BTreeMap<String, (ContentRef, PathBuf)>,
}

impl MixedEvidence {
    /// Commits to the original actually measured live resources and certificate.
    ///
    /// # Errors
    /// Refuses an unqualified/foreign peer, changed native assets or a non-clock model.
    pub(super) fn live_enrollment_receipt(
        profile: &MixedProfile,
        clock: &HostModel,
        native: &Gem5NativeProcess,
        authority: &Gem5ExactAuthority,
    ) -> Result<ScenarioContent, NodeObservedError> {
        Self::live_enrollment_receipt_selected(profile, clock, &[], native, authority)
    }

    pub(super) fn live_enrollment_receipt_selected(
        profile: &MixedProfile,
        clock: &HostModel,
        extra: &[(Id, HostModel)],
        native: &Gem5NativeProcess,
        authority: &Gem5ExactAuthority,
    ) -> Result<ScenarioContent, NodeObservedError> {
        let clock = clock_bytes(profile, clock)?;
        let extra = host_clock_bytes(profile, extra)?;
        let peer = LivePeer::measure(profile, native, authority)?;
        if peer.boundary.tick != U64::new(0)
            || peer.boundary.logical_position
                != Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl)
        {
            return Err(refused(
                "fresh native enrollment is not at the actual installed initialization cut",
            ));
        }
        let mut body = serde_json::json!({
            "schema":"crucible.mixed-live-enrollment.v1",
            "world":profile.scenario.world.identity()?,"package":profile.installed.identity(),
            "clock":canonical::content_ref(&clock,"application/octet-stream")?,
            "native":peer.commitment(),
        });
        if !extra.is_empty() {
            body["schema"] = "crucible.mixed-host-clock-list-live-enrollment.v1".into();
            body["host_clocks"] = serde_json::to_value(extra.iter().map(|(node, bytes)| {
                let selected = profile.host_clocks.iter().find(|selected| &selected.node == node)
                    .ok_or_else(|| refused("actual host Clock lost its source owner"))?;
                Ok(serde_json::json!({
                    "node":node, "owner":selected.owner,
                    "initialization":canonical::content_ref(bytes,"application/octet-stream")?,
                }))
            }).collect::<Result<Vec<_>, NodeObservedError>>()?)?;
        }
        receipt(&body)
    }

    /// Commits to an actual inactive source-image lease, without claiming a child.
    ///
    /// # Errors
    /// Refuses a missing/foreign reservation, changed world or non-clock model.
    pub(super) fn reserved_enrollment_receipt(
        profile: &MixedProfile,
        clock: &HostModel,
        reservation: &ReservedMixedRestore,
    ) -> Result<ScenarioContent, NodeObservedError> {
        reservation.verify()?;
        if profile.scenario.world.identity()? != reservation.target.world_binding_hash {
            return Err(refused(
                "reserved native lease selects another complete world",
            ));
        }
        let clock = clock_bytes(profile, clock)?;
        receipt(&serde_json::json!({
            "schema":"crucible.mixed-reserved-enrollment.v1",
            "world":profile.scenario.world.identity()?,"package":profile.installed.identity(),
            "clock":canonical::content_ref(&clock,"application/octet-stream")?,
            "signed_source":reservation.source.artifact(),
            "activation":reservation.target.activation_id,"generation":reservation.target.generation,
            "owners":reservation.target.owners.iter().map(|owner|serde_json::json!({
                "owner":owner.owner,"incarnation":owner.incarnation,"generation":owner.generation,
            })).collect::<Vec<_>>(),
            "cut":reservation.target.boundary,"native_readiness":false,
        }))
    }

    /// Enrolls a real clock and independently qualified native peer before graph sealing.
    ///
    /// # Errors
    /// Refuses foreign profile/bindings/receipts, actual resources or host code.
    pub(super) fn enroll_live(
        profile: &MixedProfile,
        bindings: &[NodeBinding],
        clock: &HostModel,
        native: &Gem5NativeProcess,
        authority: &Gem5ExactAuthority,
        host_executable: &Path,
    ) -> Result<Self, NodeObservedError> {
        Self::enroll_live_selected(
            profile,
            bindings,
            (clock, &[]),
            native,
            authority,
            host_executable,
        )
    }

    pub(super) fn enroll_live_selected(
        profile: &MixedProfile,
        bindings: &[NodeBinding],
        clocks: (&HostModel, &[(Id, HostModel)]),
        native: &Gem5NativeProcess,
        authority: &Gem5ExactAuthority,
        host_executable: &Path,
    ) -> Result<Self, NodeObservedError> {
        let (clock, extra) = clocks;
        let receipt =
            Self::live_enrollment_receipt_selected(profile, clock, extra, native, authority)?;
        let peer = LivePeer::measure(profile, native, authority)?;
        let result = Self::assemble(
            profile,
            bindings,
            clock,
            host_executable,
            receipt,
            NativeEnrollment::Live(Box::new(peer)),
            extra,
        )?;
        result.check_native_binding(native)?;
        Ok(result)
    }

    /// Enrolls the actually owned inactive archive lease before capsule installation.
    ///
    /// # Errors
    /// Refuses foreign bindings/source/target or unavailable reserved native custody.
    pub(super) fn enroll_reserved_restore(
        profile: &MixedProfile,
        bindings: &[NodeBinding],
        clock: &HostModel,
        reservation: ReservedMixedRestore,
        host_executable: &Path,
    ) -> Result<Self, NodeObservedError> {
        let receipt = Self::reserved_enrollment_receipt(profile, clock, &reservation)?;
        for owner in &reservation.target.owners {
            let binding = bindings
                .iter()
                .find(|binding| binding.compatibility.execution_owner.id == owner.owner)
                .ok_or_else(|| refused("reserved owner has no exact live binding"))?;
            if binding.authority.incarnation_id != owner.incarnation
                || binding.authority.owner_generation != owner.generation
                || binding.authority.world_generation.get() != 0
            {
                return Err(refused(
                    "reserved binding differs from actual target incarnation",
                ));
            }
        }
        Self::assemble(
            profile,
            bindings,
            clock,
            host_executable,
            receipt,
            NativeEnrollment::Reserved(Box::new(reservation)),
            &[],
        )
    }

    fn assemble(
        profile: &MixedProfile,
        bindings: &[NodeBinding],
        clock: &HostModel,
        host_executable: &Path,
        receipt: ScenarioContent,
        native: NativeEnrollment,
        extra: &[(Id, HostModel)],
    ) -> Result<Self, NodeObservedError> {
        let host = measure_executable(host_executable)?;
        if std::fs::canonicalize(host_executable).map_err(io_error)?
            != std::fs::canonicalize(std::env::current_exe().map_err(io_error)?)
                .map_err(io_error)?
        {
            return Err(refused(
                "mixed host code is not the actual owning controller",
            ));
        }
        let regenerated = profile.regenerate(&host)?;
        if profile
            .scenario
            .canonical_bytes()
            .map_err(|error| refused(&error.to_string()))?
            != regenerated
                .scenario
                .canonical_bytes()
                .map_err(|error| refused(&error.to_string()))?
            || profile.qualification != regenerated.qualification
            || bindings.len() != 2 + profile.host_clocks.len()
        {
            return Err(refused(
                "mixed profile differs from actual installed semantics",
            ));
        }
        let mut selected = BTreeMap::new();
        for binding in bindings {
            if !profile
                .scenario
                .compatibility
                .contains(&binding.compatibility)
                || binding.authority.host_receipt != receipt.reference
                || selected
                    .insert(binding.compatibility.node_id.clone(), binding.clone())
                    .is_some()
            {
                return Err(refused(
                    "mixed binding or original enrollment receipt differs",
                ));
            }
        }
        let mut assets =
            BTreeMap::from([(host.hash.digest.clone(), (host, host_executable.to_owned()))]);
        for name in [
            "native_executable",
            "controller",
            "model",
            "dmtcp_launch",
            "dmtcp_restart",
            "mtcp_restart",
            "image_guard",
            "auditor",
        ] {
            let asset = profile.installed.artifact(name)?;
            assets.insert(
                asset.content.hash.digest.clone(),
                (asset.content, asset.path),
            );
        }
        let guest = profile.installed.guest(&profile.isa)?;
        assets.insert(
            guest.content.hash.digest.clone(),
            (guest.content, guest.path),
        );
        Ok(Self {
            scenario: profile.scenario.clone(),
            installed: profile.installed.clone(),
            isa: profile.isa.clone(),
            qualification: profile.qualification.clone(),
            bindings: selected,
            clock: clock_bytes(profile, clock)?,
            host_clocks: host_clock_bytes(profile, extra)?,
            receipt,
            native,
            assets,
        })
    }

    /// Produces preparation policy only after independently certifying the actual peer.
    ///
    /// # Errors
    /// Refuses foreign target/incarnation/native code, missing actual live authority
    /// or changes to an originally enrolled unchanged stopped peer.
    pub(super) fn qualify_prepared(
        &self,
        native: &Gem5NativeProcess,
        authority: &Gem5ExactAuthority,
    ) -> Result<MixedPreparedQualification, NodeObservedError> {
        self.check_native_binding(native)?;
        let peer = LivePeer::measure_selected(&self.installed, &self.isa, native, authority)?;
        if let NativeEnrollment::Live(original) = &self.native {
            original.verify_unchanged(native)?;
        }
        Ok(MixedPreparedQualification {
            world: self.scenario.world.identity()?,
            binding: self.binding("cpu")?.clone(),
            descriptor: self.descriptor("cpu")?.clone(),
            installed: self.installed.clone(),
            peer,
        })
    }

    /// Reads original immutable scope under the caller's preallocation ceiling.
    ///
    /// # Errors
    /// Refuses unknown references, changed bytes/metadata and oversized allocations.
    pub(super) fn immutable_content(
        &self,
        reference: &ContentRef,
        maximum: usize,
    ) -> Result<Vec<u8>, EvidenceError> {
        let maximum = maximum.min(MAXIMUM_INSTALLED_ARTIFACT_BYTES);
        if reference.length.get() > maximum as u64 {
            return Err(evidence(
                "mixed immutable content exceeds its original ceiling",
            ));
        }
        let original = self
            .scenario
            .content
            .iter()
            .find(|object| &object.reference == reference)
            .or_else(|| (&self.receipt.reference == reference).then_some(&self.receipt));
        if let Some(original) = original {
            if original.bytes.len() > MAXIMUM_CONTENT_BYTES {
                return Err(evidence("mixed metadata exceeds its installed ceiling"));
            }
            original
                .reference
                .verify(&original.bytes)
                .map_err(contract_evidence)?;
            return Ok(original.bytes.clone());
        }
        let (expected, path) = self
            .assets
            .get(&reference.hash.digest)
            .ok_or_else(|| evidence("mixed immutable content is not installed"))?;
        if expected != reference {
            return Err(evidence("mixed installed reference metadata differs"));
        }
        let count = usize::try_from(reference.length.get())
            .map_err(|_| evidence("mixed content length is unrepresentable"))?;
        let mut file = File::open(path).map_err(|error| evidence(&error.to_string()))?;
        let metadata = file
            .metadata()
            .map_err(|error| evidence(&error.to_string()))?;
        if !metadata.is_file() || metadata.len() != reference.length.get() {
            return Err(evidence("mixed installed artifact geometry changed"));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(count)
            .map_err(|_| evidence("mixed content allocation is unavailable"))?;
        file.by_ref()
            .take(reference.length.get())
            .read_to_end(&mut bytes)
            .map_err(|error| evidence(&error.to_string()))?;
        let mut trailing = [0u8; 1];
        if file
            .read(&mut trailing)
            .map_err(|error| evidence(&error.to_string()))?
            != 0
        {
            return Err(evidence(
                "mixed installed artifact grew during bounded read",
            ));
        }
        reference.verify(&bytes).map_err(contract_evidence)?;
        Ok(bytes)
    }

    fn binding(&self, node: &str) -> Result<&NodeBinding, NodeObservedError> {
        self.bindings
            .values()
            .find(|binding| binding.compatibility.node_id.as_str() == node)
            .ok_or_else(|| refused("mixed node is absent from actual enrollment"))
    }

    fn descriptor(&self, node: &str) -> Result<&NodeDescriptor, NodeObservedError> {
        self.scenario
            .descriptors
            .iter()
            .find(|descriptor| descriptor.id.as_str() == node)
            .ok_or_else(|| refused("mixed descriptor is absent from actual enrollment"))
    }

    fn check_native_binding(&self, native: &Gem5NativeProcess) -> Result<(), NodeObservedError> {
        let binding = self.binding("cpu")?;
        let launch = native.launch();
        if launch.owner != binding.compatibility.execution_owner.id
            || launch.incarnation != binding.authority.incarnation_id
            || launch.generation != binding.authority.owner_generation
            || launch.guest_isa != self.isa
        {
            return Err(refused(
                "actual native peer differs from locally owned mixed target",
            ));
        }
        Ok(())
    }

    fn authenticate_enrolled_scope(&self) -> Result<(), EvidenceError> {
        match &self.native {
            NativeEnrollment::Live(peer) => peer
                .verify_kernel()
                .map_err(|error| evidence(&error.to_string())),
            NativeEnrollment::Reserved(reservation) => reservation
                .verify()
                .map_err(|error| evidence(&error.to_string())),
        }
    }

    fn check_world(&self, world: &HashRef) -> Result<(), EvidenceError> {
        if self.scenario.world.identity().map_err(contract_evidence)? != *world {
            return Err(evidence("mixed qualification names another complete world"));
        }
        self.authenticate_enrolled_scope()
    }
}

impl HostModelQualification for MixedEvidence {
    fn authenticate_model(
        &self,
        model: &HostModel,
        descriptor: &NodeDescriptor,
        binding: &NodeBinding,
    ) -> Result<(), OperationFailure> {
        let original = if descriptor.id.as_str() == "clock" {
            &self.clock
        } else {
            self.host_clocks
                .get(&descriptor.id)
                .ok_or_else(|| no_effect("additional Clock owner was not actually enrolled"))?
        };
        if self
            .descriptor(descriptor.id.as_str())
            .map_err(operation_error)?
            != descriptor
            || self
                .binding(descriptor.id.as_str())
                .map_err(operation_error)?
                != binding
            || !matches!(model, HostModel::Clock(_))
            || model.initialization_bytes(1024)? != *original
        {
            return Err(no_effect(
                "actual mixed clock differs from its enrolled original model",
            ));
        }
        self.authenticate_enrolled_scope()
            .map_err(|error| no_effect(&error.to_string()))
    }
}

/// Authenticates one actual unchanged peer after capsule-owned native preparation.
pub(super) struct MixedPreparedQualification {
    world: HashRef,
    binding: NodeBinding,
    descriptor: NodeDescriptor,
    installed: Rc<InstalledGem5ClosedProfile>,
    peer: LivePeer,
}

impl Gem5PreparationQualification for MixedPreparedQualification {
    fn authenticate_preparation(
        &self,
        native: &Gem5NativeProcess,
        graph: &AdmittedGraph,
        node: &Id,
    ) -> Result<(), OperationFailure> {
        if graph.world_binding_hash() != &self.world
            || graph.binding(node) != Some(&self.binding)
            || graph.descriptor(node) != Some(&self.descriptor)
        {
            return Err(no_effect(
                "actual native preparation names another admitted mixed graph",
            ));
        }
        self.peer
            .verify_unchanged(native)
            .map_err(operation_error)?;
        self.installed
            .verify_opaque_profile(
                native.launch(),
                &self
                    .installed
                    .artifact("auditor")
                    .map_err(operation_error)?,
            )
            .map_err(|error| no_effect(&error.to_string()))
    }
}

struct LivePeer {
    launch: Gem5Launch,
    pid: u32,
    start_ticks: String,
    executable: ContentRef,
    boundary: Gem5Boundary,
    authority: ContentRef,
}

impl LivePeer {
    fn measure(
        profile: &MixedProfile,
        native: &Gem5NativeProcess,
        authority: &Gem5ExactAuthority,
    ) -> Result<Self, NodeObservedError> {
        Self::measure_selected(&profile.installed, &profile.isa, native, authority)
    }

    fn measure_selected(
        installed: &InstalledGem5ClosedProfile,
        isa: &str,
        native: &Gem5NativeProcess,
        authority: &Gem5ExactAuthority,
    ) -> Result<Self, NodeObservedError> {
        if native.launch().guest_isa != isa
            || authority.maximum_microsteps() != installed.maximum_microsteps()
        {
            return Err(refused(
                "actual native ISA or sealed clock qualification differs",
            ));
        }
        installed
            .verify_opaque_profile(native.launch(), &installed.artifact("auditor")?)
            .map_err(|error| refused(&error.to_string()))?;
        native
            .next_publication_bound(authority)
            .map_err(|error| refused(&error.to_string()))?;
        let (proof, bytes) = authority.evidence();
        proof.verify(bytes)?;
        let pid = native
            .child_pid()
            .ok_or_else(|| refused("actual native child is absent"))?;
        let executable = measure_executable(Path::new(&format!("/proc/{pid}/exe")))?;
        let original = &native.launch().executable.content;
        let reconstructed = native
            .launch()
            .process_images
            .as_ref()
            .map(|tools| &tools.reconstruction_executable.content);
        if &executable != original && reconstructed != Some(&executable) {
            return Err(refused(
                "actual native kernel executable differs from installed engine/reconstruction",
            ));
        }
        Ok(Self {
            launch: native.launch().clone(),
            pid,
            start_ticks: start_ticks(pid)?,
            executable,
            boundary: native.boundary().clone(),
            authority: proof.clone(),
        })
    }

    fn commitment(&self) -> serde_json::Value {
        serde_json::json!({
            "pid":U64::new(u64::from(self.pid)),"start_ticks":self.start_ticks,
            "owner":self.launch.owner,"incarnation":self.launch.incarnation,"generation":self.launch.generation,
            "guest_isa":self.launch.guest_isa,"guest":self.launch.guest.content,
            "controller":self.launch.owner_script.content,"model":self.launch.model_script.content,
            "engine":self.launch.executable.content,"kernel_executable":self.executable,
            "native_boundary":self.boundary,"live_authority":self.authority,
        })
    }

    fn verify_unchanged(&self, native: &Gem5NativeProcess) -> Result<(), NodeObservedError> {
        self.verify_kernel()?;
        if native.child_pid() != Some(self.pid)
            || start_ticks(self.pid)? != self.start_ticks
            || native.boundary() != &self.boundary
            || native.launch().owner != self.launch.owner
            || native.launch().incarnation != self.launch.incarnation
            || native.launch().generation != self.launch.generation
            || native.launch().guest_isa != self.launch.guest_isa
            || native.launch().executable.content != self.launch.executable.content
            || native.launch().owner_script.content != self.launch.owner_script.content
            || native.launch().model_script.content != self.launch.model_script.content
            || native.launch().guest.content != self.launch.guest.content
            || measure_executable(Path::new(&format!("/proc/{}/exe", self.pid)))? != self.executable
        {
            return Err(refused(
                "enrolled native peer or original stopped boundary changed",
            ));
        }
        Ok(())
    }

    fn verify_kernel(&self) -> Result<(), NodeObservedError> {
        if start_ticks(self.pid)? != self.start_ticks
            || measure_executable(Path::new(&format!("/proc/{}/exe", self.pid)))? != self.executable
        {
            return Err(refused("original enrolled native kernel identity changed"));
        }
        Ok(())
    }
}

fn clock_bytes(profile: &MixedProfile, clock: &HostModel) -> Result<Vec<u8>, NodeObservedError> {
    if !matches!(clock, HostModel::Clock(_)) {
        return Err(refused("mixed host owner is not the actual integer clock"));
    }
    let bytes = clock
        .initialization_bytes(1024)
        .map_err(operation_observed)?;
    let descriptor = profile
        .scenario
        .descriptors
        .iter()
        .find(|node| node.id.as_str() == "clock")
        .ok_or_else(|| refused("mixed clock descriptor missing"))?;
    if profile
        .scenario
        .content_bytes(&descriptor.initialization_ref, 1024)
        .map_err(|error| refused(&error.to_string()))?
        != bytes
    {
        return Err(refused("actual mixed clock initialization differs"));
    }
    Ok(bytes)
}

fn host_clock_bytes(
    profile: &MixedProfile,
    models: &[(Id, HostModel)],
) -> Result<BTreeMap<Id, Vec<u8>>, NodeObservedError> {
    super::host_clocks::validate(&profile.host_clocks)?;
    if models.len() != profile.host_clocks.len() {
        return Err(refused(
            "actual Host clocks and selected source roster differ",
        ));
    }
    let mut retained = BTreeMap::new();
    for (selected, (node, model)) in profile.host_clocks.iter().zip(models) {
        if &selected.node != node || !matches!(model, HostModel::Clock(_)) {
            return Err(refused(
                "actual Host Clock has another selected node or codec",
            ));
        }
        let bytes = model
            .initialization_bytes(1024)
            .map_err(operation_observed)?;
        let descriptor = profile
            .scenario
            .descriptors
            .iter()
            .find(|descriptor| &descriptor.id == node)
            .ok_or_else(|| refused("selected Host Clock descriptor missing"))?;
        if profile
            .scenario
            .content_bytes(&descriptor.initialization_ref, 1024)
            .map_err(|error| refused(&error.to_string()))?
            != bytes
            || retained.insert(node.clone(), bytes).is_some()
        {
            return Err(refused(
                "actual Host Clock initialization differs or repeats",
            ));
        }
    }
    Ok(retained)
}

fn receipt(value: &serde_json::Value) -> Result<ScenarioContent, NodeObservedError> {
    let bytes = canonical::canonical_json(value)?;
    if bytes.len() > MAXIMUM_CONTENT_BYTES {
        return Err(refused(
            "mixed original enrollment receipt exceeds its ceiling",
        ));
    }
    Ok(ScenarioContent {
        reference: canonical::content_ref(&bytes, "application/json")?,
        bytes,
    })
}

fn start_ticks(pid: u32) -> Result<String, NodeObservedError> {
    let mut bytes = Vec::new();
    File::open(format!("/proc/{pid}/stat"))
        .map_err(io_error)?
        .take(16385)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() > 16384 {
        return Err(refused("actual native kernel identity exceeds its bound"));
    }
    let stat = std::str::from_utf8(&bytes)
        .map_err(|_| refused("actual native kernel identity is invalid"))?;
    stat.rsplit_once(')')
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .filter(|value| value.parse::<u64>().is_ok())
        .map(str::to_owned)
        .ok_or_else(|| refused("actual native kernel start identity is absent"))
}

fn evidence(reason: &str) -> EvidenceError {
    EvidenceError {
        message: reason.into(),
    }
}

fn no_effect(reason: &str) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::None,
        reason: reason.into(),
    }
}

fn contract_evidence(error: crucible_node_contract::ContractError) -> EvidenceError {
    evidence(&error.to_string())
}

fn operation_error(error: NodeObservedError) -> OperationFailure {
    no_effect(&error.to_string())
}

fn operation_observed(error: OperationFailure) -> NodeObservedError {
    refused(&error.reason)
}

fn io_error(error: std::io::Error) -> NodeObservedError {
    refused(&error.to_string())
}
