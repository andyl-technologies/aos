//! Owns genuine child preparation and original supervisor cleanup.

use super::{content, encoded, id, setup, transport};
use crucible_engine::node_adapters::cnp::*;
use crucible_node_format::*;
use crucible_node_transport::{
    client::{
        ClientCustody, ClientPeer, ClientSession, CnpController, ControllerRoute, DeadlineStream,
        ExchangeDeadline, OriginalHelloJournal,
    },
    transport::{original_frames::OriginalFrameReservation, write_frame},
};
use std::{
    cell::RefCell,
    fs::{self, File},
    os::{
        fd::OwnedFd,
        unix::{fs::MetadataExt, net::UnixStream, process::CommandExt},
    },
    panic::{AssertUnwindSafe, catch_unwind},
    process::{Command, Stdio},
    rc::Rc,
    time::{Duration, Instant},
};

struct RetainedSlot {
    identity: U64,
    original: Rc<RefCell<Option<CnpSemanticProcessCustody>>>,
}

impl CnpSemanticProcessSlot for RetainedSlot {
    fn identity(&self) -> U64 {
        self.identity
    }

    fn retain(&mut self, custody: CnpSemanticProcessCustody) {
        let mut slot = self.original.borrow_mut();
        assert!(slot.is_none(), "original supervisor slot is consumed once");
        *slot = Some(custody);
    }
}

// Host time bounds supervisor reclamation only; it never enters model state.
#[allow(clippy::disallowed_methods)]
pub(super) fn run() {
    let installed = setup::install();
    assert_eq!(installed.scene.activation.owners.len(), 4);
    let plan = installed.authority.collection_plan().unwrap();
    let mut registry = CnpSemanticRegistry::new(installed.authority.clone(), 3).unwrap();
    let mut roles = std::array::from_fn::<_, 3, _>(|member| {
        Some(
            registry
                .install_complete_packet_for_conformance(
                    installed.sources[member].clone(),
                    installed.authority.clone(),
                    &plan,
                )
                .unwrap(),
        )
    });
    let slots: [Rc<RefCell<Option<CnpSemanticProcessCustody>>>; 3] =
        std::array::from_fn(|_| Rc::new(RefCell::new(None)));
    let mut reservations = std::array::from_fn::<_, 3, _>(|member| {
        Some(
            installed.sources[member]
                .reserve_original_complete_bytes_launch(
                    installed.directories[member].clone(),
                    installed.measurements[member].peer.content.clone(),
                    Box::new(RetainedSlot {
                        identity: U64::new(member as u64 + 1),
                        original: slots[member].clone(),
                    }),
                )
                .unwrap(),
        )
    });
    let mut preparations: [Option<CnpSemanticPreparation>; 3] = std::array::from_fn(|_| None);
    let mut guards: [Option<CnpSemanticLaunchGuard>; 3] = std::array::from_fn(|_| None);
    // Every literal bank and initial promised-body custody precedes all Child effects.
    let mut clients = std::array::from_fn::<_, 3, _>(|member| {
        Some(ClientCustody::new(64, content::selected(&installed, member)).unwrap())
    });
    let mut banks = std::array::from_fn::<_, 3, _>(|member| {
        Some(
            OriginalFrameReservation::reserve(
                installed.launches[member].storage.frame_bank_bytes.get() as usize,
                installed.launches[member]
                    .storage
                    .frames_per_direction
                    .get() as usize,
            )
            .unwrap(),
        )
    });
    let mut handshakes = std::array::from_fn::<_, 3, _>(|member| {
        let launch = &installed.launches[member];
        let token: [u8; 32] = launch.admission_token.as_slice().try_into().unwrap();
        Some(transport::handshake(
            member,
            &launch.selection,
            launch.limits,
            token,
        ))
    });
    let mut hellos = std::array::from_fn::<_, 3, _>(|member| {
        Some(
            OriginalHelloJournal::reserve_native5(
                &handshakes[member].as_ref().unwrap().2,
                65_536,
                64,
            )
            .unwrap(),
        )
    });
    let mut bootstraps = std::array::from_fn::<_, 3, _>(|_| Some(UnixStream::pair().unwrap()));
    let incidents: [Rc<transport::Incidents>; 3] =
        std::array::from_fn(|_| transport::Incidents::new());
    let journal_slots: [Rc<RefCell<Option<OriginalHelloJournal>>>; 3] =
        std::array::from_fn(|_| Rc::new(RefCell::new(None)));
    for (member, slot) in journal_slots.iter().enumerate() {
        installed
            .authority
            .bind_original_ack_hello_slot(member, slot.clone())
            .unwrap();
    }
    let mut boot_materials = installed
        .sources
        .each_ref()
        .map(|source| Some(source.begin_original_canonical_ack_private_boot().unwrap()));
    let mut private_frames = std::array::from_fn::<_, 3, _>(|_| None);
    for member in 0..3 {
        boot_materials[member]
            .as_ref()
            .unwrap()
            .prepare_private_boot_frame_into(&mut private_frames[member])
            .unwrap();
    }
    // The same holders survive every original peer or trusted callback failure.
    let mut original_writers: [Option<DeadlineStream>; 3] = std::array::from_fn(|_| None);
    let mut original_controllers: [Option<CnpController>; 3] = std::array::from_fn(|_| None);
    let mut original_plain_handshakes: [Option<crucible_node_transport::handshake::Handshake>; 3] =
        std::array::from_fn(|_| None);
    let mut original_typed_handshakes: [Option<
        crucible_node_transport::handshake::ExtensionHandshake,
    >; 3] = std::array::from_fn(|_| None);
    let mut admit_results = std::array::from_fn::<_, 3, _>(|_| None);
    let deadline = ExchangeDeadline::start(Duration::from_secs(60)).unwrap();
    let result = catch_unwind(AssertUnwindSafe(|| {
        for member in 0..3 {
            deadline.remaining().unwrap();
            let launch = &installed.launches[member];
            let directory = &installed.directories[member];
            installed
                .authority
                .authenticate_private_peer(launch, &installed.peer, directory)
                .unwrap();
            let (reader, writer) = bootstraps[member].take().unwrap();
            let socket = directory.join("control.sock");
            let mut command = Command::new(&installed.peer);
            command
                .arg(&socket)
                .arg("--original-canonical-ack-boot")
                .stdin(Stdio::from(File::from(OwnedFd::from(reader))))
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .process_group(0);
            reservations[member]
                .as_mut()
                .unwrap()
                .launch(&mut command)
                .unwrap();
            let reservation = reservations[member].take().unwrap();
            guards[member] = Some(match reservation.into_guard() {
                Ok(guard) => guard,
                Err(failure) => {
                    reservations[member] = Some(failure.original);
                    panic!("original Native5 guard transfer: {}", failure.error);
                }
            });
            let pid = guards[member]
                .as_ref()
                .unwrap()
                .custody()
                .unwrap()
                .provider_pid();
            original_writers[member] =
                Some(DeadlineStream::with_deadline(writer, deadline.clone()).unwrap());
            write_frame(
                original_writers[member].as_mut().unwrap(),
                &serde_json::to_value(launch).unwrap(),
                1024 * 1024,
            )
            .unwrap();
            private_frames[member]
                .as_mut()
                .unwrap()
                .write_original(
                    boot_materials[member].as_ref().unwrap(),
                    original_writers[member].as_mut().unwrap(),
                )
                .unwrap();
            drop(boot_materials[member].take());
            // Both complete private frames have been sent. Closing this writer
            // prevents an unrecorded private suffix after selected native birth.
            drop(original_writers[member].take());
            let stream = loop {
                match UnixStream::connect(&socket) {
                    Ok(stream) => break stream,
                    Err(error)
                        if deadline.remaining().is_ok()
                            && matches!(
                                error.kind(),
                                std::io::ErrorKind::NotFound
                                    | std::io::ErrorKind::ConnectionRefused
                            ) =>
                    {
                        std::thread::yield_now();
                    }
                    Err(error) => panic!("original Native5 connection: {error}"),
                }
            };
            let (handshake, mut verifier, hello) = handshakes[member].take().unwrap();
            original_plain_handshakes[member] = Some(handshake);
            original_typed_handshakes[member] = Some(
                crucible_node_transport::handshake::ExtensionHandshake::from_original_empty_registry_retained(
                    &mut original_plain_handshakes[member],
                )
                .unwrap(),
            );
            let session = ClientSession::negotiate_extensions_recorded_before(
                stream,
                &ClientPeer {
                    pid,
                    uid: fs::metadata("/proc/self").unwrap().uid(),
                    executable: installed.measurements[member].peer.content.clone(),
                },
                &hello,
                id(&format!("complete-original-connection-{member}")),
                original_typed_handshakes[member].as_mut().unwrap(),
                &mut verifier,
                incidents[member].clone(),
                Rc::new(transport::HelloSchema),
                deadline.clone(),
                65_536,
                64,
                hellos[member].as_mut().unwrap(),
            )
            .unwrap();
            assert_eq!(session.authority().limits(), launch.limits);
            original_controllers[member] = Some(
                CnpController::new(
                    session,
                    clients[member].take().unwrap(),
                    ControllerRoute {
                        node: launch.selection.realization.descriptors[0].id.clone(),
                        execution_owner: launch.selection.realization.owner_bindings[0]
                            .owner
                            .id
                            .clone(),
                    },
                    Duration::from_secs(60),
                )
                .unwrap(),
            );
            original_controllers[member].as_mut().unwrap()
                .install_native5_source_ack_emitter_codec_with_metadata_extent(
                    &mut banks[member],
                    launch.selection.clone(),
                    launch.initial_coordinator.clone(),
                    launch.capture_profile.clone(),
                    crucible_node_transport::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB,
                )
                .unwrap();
            *journal_slots[member].borrow_mut() = hellos[member].take();
            guards[member]
                .as_mut()
                .unwrap()
                .attach_extensions_owned(
                    &mut original_controllers[member],
                    &mut original_typed_handshakes[member],
                )
                .unwrap();
            assert!(original_controllers[member].is_none());
            assert!(original_typed_handshakes[member].is_none());
            let guard = guards[member].take().unwrap();
            preparations[member] = Some(
                match CnpSemanticPreparation::prepare_for_conformance(
                    guard,
                    roles[member].take().unwrap(),
                ) {
                    Ok(preparation) => preparation,
                    Err(failure) => {
                        let reason = failure.error.reason.clone();
                        guards[member] = Some(failure.guard);
                        panic!("original complete preparation {member}: {reason}");
                    }
                },
            );
            assert!(
                journal_slots[member].borrow().is_none(),
                "real callback transferred the same original Hello once"
            );
            preparations[member]
                .as_mut()
                .unwrap()
                .call_original_canonical_ack_admit_into(
                    &installed.sources[member],
                    id(&format!("original-keyed-admit-{member}")),
                    &mut admit_results[member],
                )
                .unwrap();
            assert!(admit_results[member].is_some());
            deadline.remaining().unwrap();
            let prepared = preparations[member].as_ref().unwrap();
            assert_eq!(
                prepared.descriptor(),
                &launch.selection.realization.descriptors[0]
            );
            assert_eq!(
                prepared.binding(),
                &launch.selection.realization.bindings[0]
            );
            assert_eq!(
                prepared.owner_binding(),
                &launch.selection.realization.owner_bindings[0]
            );
            installed.sources[member]
                .authenticate_current_native()
                .unwrap();
            installed.sources[member]
                .authenticate_original_preconstruction()
                .unwrap();
            let facts = installed.sources[member]
                .original_capture_bank_facts()
                .unwrap();
            fs::write(
                installed.directories[member].join("original-preconstruction-bank-facts.json"),
                encoded(&serde_json::json!({
                    "scope": "original preparation allocation association only",
                    "semantic_bytes": facts.semantic_bytes,
                    "ancestry_bytes": facts.ancestry_bytes,
                    "journal_bytes": facts.journal_bytes,
                    "protocol_bytes": facts.protocol_bytes,
                    "native_snapshot_bytes": facts.native_snapshot_bytes,
                    "native_control_bytes": facts.native_control_bytes,
                    "native_anchor_bytes": facts.native_anchor_bytes,
                    "total_bytes": facts.total_bytes,
                })),
            )
            .unwrap();

            eprintln!(
                "complete original member {member}: genuine source registration/typed Hello/Discover/Realize and once keyed protocol Admit verified; no semantic Arm/Capture"
            );
        }
        installed.authority.current().unwrap();
        installed
            .receiver_reader
            .authenticate_original_group(&installed.receiver_group)
            .unwrap();
        installed.receiver_group.authenticate_empty().unwrap();
        for member in 0..3 {
            installed.sources[member]
                .authenticate_original_effect_receiver_binding(
                    &installed.receiver_group,
                    member,
                    &installed.launches[member].effects,
                )
                .unwrap();
        }
        assert!(incidents.iter().all(|original| original.is_empty()));
        fs::write(
            installed.directory.join("prepared-coordinator.json"),
            encoded(&installed.scene.coordinator),
        )
        .unwrap();
    }));
    // Retire the same complete native owners even if the original preparation failed.
    drop(preparations);
    drop(guards);
    drop(reservations);
    let cleanup = Instant::now() + Duration::from_secs(10);
    for (member, original) in slots.iter().enumerate() {
        let mut holder = original.borrow_mut();
        let Some(custody) = holder.as_mut() else {
            // A later member may remain unlaunched after an earlier failure.
            continue;
        };
        if let Some(controller) = custody.controller() {
            let originals: Vec<_> = controller.originals().collect();
            fs::write(
                installed.directories[member].join("original-controller-journal.json"),
                encoded(&originals),
            )
            .unwrap();
        }
        if custody.provider_pid() == 0 {
            continue;
        }
        while !custody.poll_reclamation().unwrap() {
            assert!(
                Instant::now() < cleanup,
                "original native process group cleanup"
            );
            std::thread::yield_now();
        }
        eprintln!(
            "complete original child {} reaped with its private group",
            custody.provider_pid()
        );
        assert!(
            installed.sources[member]
                .authenticate_original_preconstruction()
                .is_err(),
            "the same original source association refuses after authentic child reap"
        );
    }
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}
