//! Constructs actual original source owners from the independently pinned package.

use super::super::{
    InstalledPacketCompleteCollectionAuthority, PacketCompleteCollectionRequest,
    PacketCompleteGraphOwner, PacketCompleteGraphRequest, PacketCompleteNativeLaunchInputs,
    PacketCompleteRoster,
};
use super::{manifest::*, *};
use crate::node_qualification::{
    PacketFixtureArtifact, PacketFixtureMeasurements, PacketWorldHostSupervisor,
    QualificationLimits,
};
use crucible::{
    node_adapters::cnp::{
        CnpSemanticRegistry, CnpSemanticSource, PacketCompleteAckHostRegistrationPlan,
        PacketCompleteCaptureBankLimits, PacketCompleteEffectReceiverGroup,
        PacketCompleteSemanticSource,
    },
    node_contract::{ActivationRecord, HostSchedulingOwner, RuntimeLimits, SavedRuntimeActivation},
};
use crucible_node_contract::{Bytes, Id, U64, canonical};
use crucible_node_provider::{
    client::CanonicalAckCodecMetadataExtent,
    reference_packet::{
        control::PacketNative5StorageSelection,
        coordinator::PacketNative5CoordinatorInstallation,
        service::{
            PacketConnectedSourceProgram, PacketNative5CaptureProfile,
            PacketNative5ConfirmationSelection, PacketNative5ProtocolMetadataLimits,
            PacketNative5SourceLaunch, ack_emitter::PacketNative5AckEmitterSelection,
            capture_allocation::PacketNative5CaptureAllocationSelection,
        },
    },
    reference_service::InstalledContent,
};
use std::{
    fs::{self, File},
    io::Read,
    os::unix::{
        fs::{DirBuilderExt, MetadataExt},
        net::{UnixDatagram, UnixStream},
    },
    time::Duration,
};

pub(super) fn install(
    selected: Manifest,
    directory: PathBuf,
) -> Result<InstalledCompleteScene, QualificationError> {
    if selected.schema == "crucible.complete-scene.installation/6" {
        // A suffix target must retain actual archive tickets and their restored
        // Host. The original-scene installer cannot issue that ancestry.
        return Err(refused());
    }
    // Bounded declarations, measured files and concrete source constructors
    // precede namespace creation. The independent full graph check follows.
    let measurements = selected.measurements.map(|one| PacketFixtureMeasurements {
        peer: artifact(one.peer),
        host: one.host,
        sources: one.sources.into_iter().map(artifact).collect(),
    });
    for measurement in &measurements {
        measurement.authenticate()?;
    }
    let content = super::manifest::content(selected.content)?;
    let host_owner = HostSchedulingOwner::new_complete_original_continuation(
        selected.host,
        selected.world.identity()?,
    )
    .map_err(|_| refused())?;
    let host = host_owner.source();
    let initial_bytes = encoded(&selected.coordinator)?;
    let initial = InstalledContent {
        reference: canonical::content_ref(&initial_bytes, "application/json")?,
        bytes: Bytes::new(initial_bytes),
    };
    let saved: SavedRuntimeActivation = serde_json::from_value(
        selected
            .coordinator
            .template
            .get("activation")
            .ok_or_else(refused)?
            .clone(),
    )
    .map_err(crucible_node_contract::ContractError::from)?;
    let activation = ActivationRecord {
        generation: saved.generation,
        activation_id: saved.activation_id,
        world_binding_hash: saved.world_binding_hash,
        owners: saved.owners,
        boundary: saved.boundary,
    };
    if activation.world_binding_hash != selected.world.identity()? {
        return Err(refused());
    }

    // The manifest validator has authenticated exact full outer14 DATA on both
    // immutable rosters and content before any Source bank or namespace effect.
    let restoration_observation = selected.schema == "crucible.complete-scene.installation/5";
    let restoration_activation =
        restoration_observation || selected.schema == "crucible.complete-scene.installation/4";
    let invocation_snapshot =
        restoration_activation || selected.schema == "crucible.complete-scene.installation/3";
    let (sources, declarations) = if selected.schema == "crucible.complete-scene.installation/7" {
        prepare_restored_settled_sources(
            selected.participants,
            &selected.coordinator,
            selected.maximum_native_rows,
            selected.maximum_initial_bytes,
            selected.mechanism,
            selected.maximum_coordinator_records.ok_or_else(refused)?,
            &content,
        )?
    } else {
        prepare_sources(
            selected.participants,
            &selected.coordinator,
            selected.maximum_native_rows,
            selected.maximum_initial_bytes,
            selected.mechanism,
            invocation_snapshot,
            restoration_activation,
            restoration_observation,
            false,
            &content,
        )?
    };
    let mut namespace = Namespace::create(directory)?;
    let directories = namespace.peer_directories()?;
    let paths: [PathBuf; 3] =
        std::array::from_fn(|member| namespace.path.join(format!("effect-{member}.sock")));
    let receivers = paths
        .each_ref()
        .map(|path| UnixDatagram::bind(path).map_err(|_| refused()));
    let [a, b, c] = receivers;
    let (group, reader) = PacketCompleteEffectReceiverGroup::from_original_receivers([a?, b?, c?]);
    let launches = launch_declarations(
        declarations,
        &selected.coordinator,
        &initial,
        &measurements,
        &paths,
    )?;
    let sources = ready_sources(
        sources,
        &launches,
        &group,
        &paths,
        selected.maximum_initial_bytes,
    )?;
    let roster = PacketCompleteRoster::new(sources.clone(), &selected.coordinator)?;
    let graph_owner = PacketCompleteGraphOwner::install(PacketCompleteGraphRequest {
        roster: roster.clone(),
        host: Rc::clone(&host),
        measurements: measurements.each_ref(),
        world: &selected.world,
        requirements: &selected.requirements,
        content: &content,
        coordinator: &selected.coordinator,
    })?;
    let authority =
        InstalledPacketCompleteCollectionAuthority::install(PacketCompleteCollectionRequest {
            roster,
            host,
            graph_policy: graph_owner.graph_policy()?,
            world: &selected.world,
            requirements: &selected.requirements,
            content: &content,
            coordinator: &selected.coordinator,
            launches,
            directories: directories.clone(),
            limits: QualificationLimits::default(),
            maximum_audit_bytes: 8 * 1024 * 1024,
        })?;
    let plan = Rc::new(authority.collection_plan().map_err(|_| refused())?);
    let mut registry = CnpSemanticRegistry::new(authority.clone(), 3).map_err(|_| refused())?;
    let mut installed_roles = Vec::with_capacity(3);
    for source in &sources {
        installed_roles.push(Some(
            registry
                .install_complete_packet_for_conformance(source.clone(), authority.clone(), &plan)
                .map_err(|_| refused())?,
        ));
    }
    let roles = installed_roles.try_into().map_err(|_| refused())?;
    let original = PacketCompleteReportStartupHolder::install_original_scene(
        graph_owner,
        authority,
        plan,
        selected.resources,
        group,
        reader,
    )?;
    original
        .try_borrow()
        .map_err(|_| refused())?
        .retain_installed_host_owner(host_owner)?;
    let content = Rc::new(content);
    let mut input_launches = Vec::with_capacity(3);
    for member in 0..3 {
        let (reader, writer) = UnixStream::pair().map_err(|_| refused())?;
        input_launches.push(Some(PacketCompleteNativeLaunchInputs {
            executable_path: measurements[member].peer.path.clone(),
            executable: measurements[member].peer.content.clone(),
            directory: directories[member].clone(),
            socket: directories[member].join("control.sock"),
            slot: None,
            bootstrap_reader: Some(reader),
            bootstrap_writer: Some(writer),
            write_watchdog: Duration::from_millis(selected.write_watchdog_ms),
        }));
    }
    let incoming = PacketCompleteOriginalSceneInputs {
        supervisor: PacketWorldHostSupervisor::new_complete_original()?.into(),
        activation,
        runtime_limits: RuntimeLimits {
            maximum_nodes: 4,
            maximum_owners: 4,
            maximum_operations: selected.maximum_operations,
            maximum_retained_outputs: selected.maximum_retained_outputs,
        },
        content: Some([Rc::clone(&content), Rc::clone(&content), content]),
        launches: input_launches.try_into().map_err(|_| refused())?,
        planned_query_ids: [
            Some(id("installed-complete-query-0")?),
            Some(id("installed-complete-query-1")?),
            Some(id("installed-complete-query-2")?),
        ],
        admit_ids: [
            id("installed-complete-admit-0")?,
            id("installed-complete-admit-1")?,
            id("installed-complete-admit-2")?,
        ],
        registry,
        roles,
    };
    // From here the actor owns all original inputs. It deliberately keeps the
    // private namespace and every surviving partial on refusal or shutdown.
    namespace.retained = true;
    Ok(InstalledCompleteScene {
        original,
        incoming: Some(incoming),
        attempted: false,
        retired: false,
        reclaimed: false,
        process: std::process::id(),
        thread: std::thread::current().id(),
    })
}

struct LaunchDeclaration {
    program: PacketConnectedSourceProgram,
    storage: PacketNative5StorageSelection,
    capture_profile: PacketNative5CaptureProfile,
    protocol_metadata: PacketNative5ProtocolMetadataLimits,
    mechanism: Option<CompleteMechanism>,
}

fn prepare_restored_settled_sources(
    participants: [Participant; 3],
    coordinator: &PacketNative5CoordinatorInstallation,
    maximum_native_rows: usize,
    maximum_initial_bytes: usize,
    mechanism: Option<CompleteMechanism>,
    maximum_coordinator_records: usize,
    content: &std::collections::BTreeMap<ContentRef, Vec<u8>>,
) -> Result<([PacketCompleteSemanticSource; 3], [LaunchDeclaration; 3]), QualificationError> {
    prepare_sources_with_capture_family(
        participants,
        coordinator,
        maximum_native_rows,
        maximum_initial_bytes,
        mechanism,
        true,
        true,
        true,
        true,
        true,
        Some(maximum_coordinator_records),
        content,
    )
}

fn prepare_sources(
    participants: [Participant; 3],
    coordinator: &PacketNative5CoordinatorInstallation,
    maximum_native_rows: usize,
    maximum_initial_bytes: usize,
    mechanism: Option<CompleteMechanism>,
    invocation_snapshot: bool,
    restoration_activation: bool,
    restoration_observation: bool,
    restored_suffix: bool,
    content: &std::collections::BTreeMap<ContentRef, Vec<u8>>,
) -> Result<([PacketCompleteSemanticSource; 3], [LaunchDeclaration; 3]), QualificationError> {
    prepare_sources_with_capture_family(
        participants,
        coordinator,
        maximum_native_rows,
        maximum_initial_bytes,
        mechanism,
        invocation_snapshot,
        restoration_activation,
        restoration_observation,
        restored_suffix,
        false,
        None,
        content,
    )
}

fn prepare_sources_with_capture_family(
    participants: [Participant; 3],
    coordinator: &PacketNative5CoordinatorInstallation,
    maximum_native_rows: usize,
    maximum_initial_bytes: usize,
    mechanism: Option<CompleteMechanism>,
    invocation_snapshot: bool,
    restoration_activation: bool,
    restoration_observation: bool,
    restored_suffix: bool,
    restored_settled: bool,
    maximum_coordinator_records: Option<usize>,
    content: &std::collections::BTreeMap<ContentRef, Vec<u8>>,
) -> Result<([PacketCompleteSemanticSource; 3], [LaunchDeclaration; 3]), QualificationError> {
    if restored_settled != maximum_coordinator_records.is_some() {
        return Err(refused());
    }
    let mut sources = Vec::with_capacity(3);
    let mut declarations = Vec::with_capacity(3);
    for (member, participant) in participants.into_iter().enumerate() {
        let installation = participant.installation.into_source_selection();
        let mut source = match &participant.program {
            PacketConnectedSourceProgram::Producer { program } => {
                PacketCompleteSemanticSource::new_producer_for_collecting_world(
                    installation,
                    program.clone(),
                    coordinator.clone(),
                    participant.storage.clone(),
                )
            }
            PacketConnectedSourceProgram::Reactive { program } => {
                PacketCompleteSemanticSource::new_reactive_for_collecting_world(
                    installation,
                    program.clone(),
                    coordinator.clone(),
                    participant.storage.clone(),
                )
            }
        }
        .map_err(|_| refused())?;
        source
            .bind_original_capture_profile(participant.capture_profile.clone())
            .map_err(|_| refused())?;
        source
            .bind_original_confirmation_selection(Some(
                PacketNative5ConfirmationSelection::AfterProtocolPoll5,
            ))
            .map_err(|_| refused())?;
        source
            .bind_original_ack_emitter_selection(Some(
                PacketNative5AckEmitterSelection::CanonicalSdkBlob5,
            ))
            .map_err(|_| refused())?;
        source
            .bind_original_ack_codec_metadata_extent(
                CanonicalAckCodecMetadataExtent::CanonicalAck512KiB,
            )
            .map_err(|_| refused())?;
        source
            .bind_original_native_ack_codec_metadata_extent(
                CanonicalAckCodecMetadataExtent::CanonicalAck512KiB,
            )
            .map_err(|_| refused())?;
        source
            .bind_original_protocol_metadata_limits(participant.protocol_metadata.clone())
            .map_err(|_| refused())?;
        source
            .bind_original_capture_allocation_selection(Some(
                PacketNative5CaptureAllocationSelection::OriginalObserve12,
            ))
            .map_err(|_| refused())?;
        if let Some(mechanism) = mechanism {
            mechanism.bind_source(&mut source)?;
        }
        if invocation_snapshot {
            if mechanism.is_none() {
                return Err(refused());
            }
            // This fixed-stack, allocation-free DATA binder belongs to the
            // ordinary operator-install phase, like the tuple binders above.
            // Later runtime/native grants do not authorize this earlier work.
            if restored_settled {
                source
                    .bind_original_restored_settled_capture_declaration()
                    .map_err(|_| refused())?;
                source
                    .bind_original_restored_settled_coordinator_policy17(
                        maximum_coordinator_records.ok_or_else(refused)?,
                    )
                    .map_err(|_| refused())?;
            } else if restored_suffix {
                source
                    .bind_original_restored_suffix_declaration()
                    .map_err(|_| refused())?;
            } else if restoration_observation {
                source
                    .bind_original_restoration_observation_declaration()
                    .map_err(|_| refused())?;
            } else if restoration_activation {
                source
                    .bind_original_restoration_activation_declaration()
                    .map_err(|_| refused())?;
            } else {
                source
                    .bind_original_invocation_snapshot_declaration()
                    .map_err(|_| refused())?;
            }
            super::super::records::validate_original_native_definition_data(
                &source, content, member,
            )?;
        }
        let host_protocol_bytes = match &participant.capture_profile {
            PacketNative5CaptureProfile::OwnedProtocol11 {
                host_protocol_bytes,
                ..
            } => usize::try_from(host_protocol_bytes.get()).map_err(|_| refused())?,
            _ => return Err(refused()),
        };
        let banks = PacketCompleteCaptureBankLimits {
            host_protocol_bytes,
            semantic_bytes: source.installation().maximum_semantic_bytes,
            ancestry_bytes: source.installation().maximum_result_bytes,
            journal_bytes: source.installation().maximum_authorization_bytes,
        };
        source
            .reserve_complete_capture_banks_owned11(
                banks,
                maximum_native_rows,
                maximum_initial_bytes,
            )
            .map_err(|_| refused())?;
        sources.push(source);
        declarations.push(LaunchDeclaration {
            program: participant.program,
            storage: participant.storage,
            capture_profile: participant.capture_profile,
            protocol_metadata: participant.protocol_metadata,
            mechanism,
        });
    }
    let sources: [PacketCompleteSemanticSource; 3] = sources.try_into().map_err(|_| refused())?;
    let declarations = declarations.try_into().map_err(|_| refused())?;
    Ok((sources, declarations))
}

fn launch_declarations(
    declarations: [LaunchDeclaration; 3],
    coordinator: &PacketNative5CoordinatorInstallation,
    initial: &InstalledContent,
    measurements: &[PacketFixtureMeasurements; 3],
    paths: &[PathBuf; 3],
) -> Result<[PacketNative5SourceLaunch; 3], QualificationError> {
    let mut entropy = File::open("/dev/urandom").map_err(|_| refused())?;
    let mut launches = Vec::with_capacity(3);
    for (
        member,
        LaunchDeclaration {
            program,
            storage,
            capture_profile,
            protocol_metadata,
            mechanism,
        },
    ) in declarations.into_iter().enumerate()
    {
        let mut secret = [0; 32];
        entropy.read_exact(&mut secret).map_err(|_| refused())?;
        launches.push(PacketNative5SourceLaunch {
            schema_version: 5,
            selection: coordinator
                .participants
                .get(member)
                .ok_or_else(refused)?
                .clone(),
            program,
            controller_pid: U64::new(u64::from(std::process::id())),
            controller_uid: U64::new(u64::from(rustix::process::geteuid().as_raw())),
            controller_executable: measurements[member].host.clone(),
            admission_token: Bytes::new(secret.to_vec()),
            initial_coordinator: initial.clone(),
            limits: storage.limits,
            storage: storage.storage,
            capture_profile,
            confirmation_selection: Some(PacketNative5ConfirmationSelection::AfterProtocolPoll5),
            ack_emitter_selection: Some(PacketNative5AckEmitterSelection::CanonicalSdkBlob5),
            native_codec_metadata_extent: Some(CanonicalAckCodecMetadataExtent::CanonicalAck512KiB),
            protocol_metadata_limits: Some(protocol_metadata),
            capture_allocation_selection: Some(
                PacketNative5CaptureAllocationSelection::OriginalObserve12,
            ),
            fresh_restore_allocation_selection: mechanism
                .map(|selected| selected.fresh_restore_allocation),
            complete_restore_selection: mechanism.map(|selected| selected.complete_restore),
            restore_input_emitter_selection: mechanism
                .map(|selected| selected.restore_input_emitter),
            effects: paths[member].clone(),
        });
    }
    drop(entropy);
    launches.try_into().map_err(|_| refused())
}

fn ready_sources(
    sources: [PacketCompleteSemanticSource; 3],
    launches: &[PacketNative5SourceLaunch; 3],
    group: &Rc<PacketCompleteEffectReceiverGroup>,
    paths: &[PathBuf; 3],
    maximum_initial_bytes: usize,
) -> Result<[Rc<PacketCompleteSemanticSource>; 3], QualificationError> {
    let mut ready_sources = Vec::with_capacity(3);
    for (member, mut source) in sources.into_iter().enumerate() {
        source
            .bind_original_effect_receiver(Rc::clone(group), member, paths[member].clone())
            .map_err(|_| refused())?;
        let mut features = source.installation().provider.extensions_supported.clone();
        features.extend([id("cnp.core/1")?, id("cnp.extension-negotiation/1")?]);
        features.sort();
        features.dedup();
        let mut envelope_extensions = vec![
            "cnp.extension-negotiation/1".into(),
            "source-owned.packet-canonical-ack-admission/5".into(),
            "source-owned.packet-input/4".into(),
            crucible_node_provider::reference_packet::service::confirmation::PACKET_NATIVE_AFTER_CONFIRMATION_EXTENSION.into(),
        ];
        if let Some(selection) = launches[member].complete_restore_selection {
            envelope_extensions.extend(
                crucible_node_provider::reference_packet::service::complete_restore::complete_restore_selected_envelope_extensions(selection)
                    .into_iter().map(str::to_owned),
            );
        }
        if launches[member]
            .fresh_restore_allocation_selection
            .is_some()
        {
            use crucible_node_provider::reference_packet::service::fresh_restore_allocation::{
                PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING,
                PACKET_FRESH_RESTORE_ALLOCATION_QUERY,
            };
            envelope_extensions.extend([
                PACKET_FRESH_RESTORE_ALLOCATION_QUERY.into(),
                PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING.into(),
            ]);
        }
        if source
            .is_original_restoration_activation_declaration_data()
            .map_err(|_| refused())?
        {
            use crucible_node_provider::reference_packet::service::complete_restore::activation::{
                PACKET_RESTORATION_ACTIVATION_FEATURE,
                upload::PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE,
            };
            envelope_extensions.extend([
                PACKET_RESTORATION_ACTIVATION_FEATURE.into(),
                PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE.into(),
            ]);
        }
        if source
            .is_original_restoration_observation_declaration_data()
            .map_err(|_| refused())?
        {
            envelope_extensions.push(crucible_node_provider::reference_packet::service::complete_restore::restoration_observe::PACKET_RESTORATION_OBSERVE_FEATURE.into());
        }
        envelope_extensions.sort();
        envelope_extensions.dedup();
        source
            .reserve_original_canonical_ack_peer_birth(
                &launches[member],
                id(&format!("installed-complete-boot-{member}"))?,
                PacketCompleteAckHostRegistrationPlan {
                    connection_id: id(&format!("installed-complete-connection-{member}"))?,
                    features,
                    extensions: Vec::new(),
                    envelope_extensions,
                },
                maximum_initial_bytes,
            )
            .map_err(|_| refused())?;
        ready_sources.push(Rc::new(source));
    }
    ready_sources.try_into().map_err(|_| refused())
}

fn artifact(one: FileSelection) -> PacketFixtureArtifact {
    PacketFixtureArtifact {
        role: one.role,
        path: one.path,
        content: one.content,
    }
}

fn id(value: &str) -> Result<Id, QualificationError> {
    Ok(Id::new(value)?)
}

fn encoded(value: &impl serde::Serialize) -> Result<Vec<u8>, QualificationError> {
    Ok(canonical::canonical_json(
        &serde_json::to_value(value).map_err(crucible_node_contract::ContractError::from)?,
    )?)
}

struct Namespace {
    path: PathBuf,
    identity: (u64, u64),
    retained: bool,
}

impl Namespace {
    fn create(path: PathBuf) -> Result<Self, QualificationError> {
        if !path.is_absolute() || path.file_name().is_none() {
            return Err(refused());
        }
        let parent = path.parent().ok_or_else(refused)?;
        let metadata = fs::symlink_metadata(parent).map_err(|_| refused())?;
        if !metadata.is_dir()
            || metadata.mode() & 0o777 != 0o700
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || fs::canonicalize(parent).map_err(|_| refused())? != parent
        {
            return Err(refused());
        }
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|_| refused())?;
        let metadata = fs::symlink_metadata(&path).map_err(|_| refused())?;
        Ok(Self {
            path,
            identity: (metadata.dev(), metadata.ino()),
            retained: false,
        })
    }

    fn peer_directories(&self) -> Result<[PathBuf; 3], QualificationError> {
        let paths = std::array::from_fn(|member| self.path.join(format!("peer-{member}")));
        for path in &paths {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(path)
                .map_err(|_| refused())?;
        }
        Ok(paths)
    }
}

impl Drop for Namespace {
    fn drop(&mut self) {
        if self.retained {
            return;
        }
        let Ok(current) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if !current.is_dir() || (current.dev(), current.ino()) != self.identity {
            return;
        }
        // Only this installer's fixed, newly created names are eligible. Never
        // recurse through operator data or release a namespace after native birth.
        for member in 0..3 {
            let _ = fs::remove_file(self.path.join(format!("effect-{member}.sock")));
            let _ = fs::remove_dir(self.path.join(format!("peer-{member}")));
        }
        let _ = fs::remove_dir(&self.path);
    }
}

#[path = "source/fresh_target.rs"]
mod fresh_target;
pub use fresh_target::{InstalledCompleteRestoration, PreparedCompleteRestoration};

#[cfg(test)]
#[path = "source/native_definition_tests.rs"]
mod native_definition_tests;
