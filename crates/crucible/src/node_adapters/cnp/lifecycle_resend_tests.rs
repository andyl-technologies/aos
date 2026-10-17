//! Actual original owner-ready adoption and mechanical duplicate uncertainty.
//!
//! The policy faults are explicit test interception. This fixture authenticates
//! actual source-built preparation custody but grants no SourceAuthority class.

use super::*;
use crate::node_contract::EffectKnowledge;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    Refusal,
    Unwind,
    NativeDeath,
}

struct ProbeFault {
    mode: Fault,
    calls: Rc<RefCell<usize>>,
    observations: ObservationHandle,
    provider: u32,
    source_binding: HashRef,
}

impl CnpCompletedLifecycleQualification for ProbeFault {
    fn authenticate(
        &self,
        guard: &CnpLaunchGuard,
        scope: &CnpCompletedLifecycleScope,
    ) -> Result<bool, OperationFailure> {
        *self.calls.borrow_mut() += 1;
        assert_eq!(guard.provider_pid(), Some(self.provider));
        assert_eq!(scope.phase, CnpCompletedLifecyclePhase::Prepared);
        assert_eq!(scope.method, Method::Activate);
        assert_eq!(scope.binding_hash, self.source_binding);
        assert_eq!(
            scope.native_status,
            crucible_node_provider::reference_device::DeviceStatus::Parked
        );
        assert!(scope.grant.is_none());
        let keys = self.observations.request_keys().unwrap();
        let refs = self.observations.content_references().unwrap();
        let snapshot = self
            .observations
            .snapshot(
                &keys,
                &refs,
                ObservationLimits {
                    maximum_requests: 64,
                    maximum_objects: 256,
                    maximum_bytes: 16 * 1024 * 1024,
                },
            )
            .unwrap();
        let original = snapshot
            .evidence
            .requests
            .iter()
            .find(|original| {
                original.key.origin == RequestOrigin::Controller
                    && original.key.request_id == scope.request_id
            })
            .unwrap();
        let request = Envelope::decode(original.request.bytes.as_slice(), 1_048_576).unwrap();
        assert_eq!(
            request.request_hash(RequestOrigin::Controller).unwrap(),
            original.identity
        );
        assert_eq!(request.method, Method::Activate);
        assert!(original.response.0.is_some());
        assert!(scope.evidence_roots.iter().all(|root| {
            snapshot
                .evidence
                .objects
                .iter()
                .any(|object| object.reference == *root)
        }));
        match self.mode {
            Fault::None => Ok(true),
            Fault::Refusal => Err(super::super::readiness::refused(
                "injected after native ready adoption",
            )),
            Fault::Unwind => panic!("injected after native ready adoption"),
            Fault::NativeDeath => {
                let pid =
                    rustix::process::Pid::from_raw(i32::try_from(self.provider).unwrap()).unwrap();
                assert_eq!(rustix::process::getpgid(Some(pid)).unwrap(), pid);
                rustix::process::kill_process_group(pid, rustix::process::Signal::KILL).unwrap();
                Ok(true)
            }
        }
    }
}

#[test]
#[ignore = "requires source-built CRUCIBLE_REFERENCE_PROVIDER_EXECUTABLE and CRUCIBLE_REFERENCE_DEVICE_EXECUTABLE"]
fn actual_ready_duplicate_and_post_adoption_faults_preserve_original_custody() {
    for mode in [
        Fault::None,
        Fault::Refusal,
        Fault::Unwind,
        Fault::NativeDeath,
    ] {
        run_original(mode);
    }
}

fn run_original(mode: Fault) {
    let provider = PathBuf::from(
        std::env::var_os("CRUCIBLE_REFERENCE_PROVIDER_EXECUTABLE")
            .expect("set source-built public provider"),
    );
    let device = PathBuf::from(
        std::env::var_os("CRUCIBLE_REFERENCE_DEVICE_EXECUTABLE")
            .expect("set source-built companion"),
    );
    let mut installed = installation(&provider, &device);
    let directory = std::env::temp_dir().join(format!(
        "cnp-lifecycle-probe-{}-{}",
        std::process::id(),
        installed.bootstrap.admission_token.as_slice()[0]
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let socket = directory.join("control.sock");
    let retained = Rc::new(RefCell::new(Vec::with_capacity(1)));
    // Reserve the finite slot before creating an actual process.
    let slot = Box::new(Slot(Rc::clone(&retained)));
    let mut child = Command::new(&provider)
        .arg(&socket)
        .arg(&device)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .process_group(0)
        .spawn()
        .unwrap();
    let stdin = child.stdin.take();
    let mut guard = CnpLaunchGuard::new(child, directory.clone(), slot)
        .ok()
        .unwrap();
    let mut stdin = stdin.unwrap();
    crucible_node_provider::transport::write_frame(
        &mut stdin,
        &serde_json::to_value(ReferenceServiceInstalledLaunchBootstrap {
            schema_version: 3,
            profile: PublicReferenceProfile::ByteLinkedV1 {
                closed_ingress: true,
            },
            bootstrap: installed.bootstrap.clone(),
            qualification_refs: installed.qualifications.clone(),
        })
        .unwrap(),
        16 * 1024 * 1024,
    )
    .unwrap();
    drop(stdin);
    for _ in 0..300 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        socket.exists(),
        "actual private provider did not become available"
    );
    connect(&mut guard, &socket, &mut installed);
    let controller = guard.custody.as_mut().unwrap().controller.as_mut().unwrap();
    let observations = controller
        .observe(ObservationLimits {
            maximum_requests: 64,
            maximum_objects: 256,
            maximum_bytes: 16 * 1024 * 1024,
        })
        .unwrap();
    let transmissions = controller
        .observe_resends(TransmissionLimits {
            maximum_transmissions: 1,
            maximum_bytes: 4 * 1024 * 1024,
        })
        .unwrap();
    let calls = Rc::new(RefCell::new(0usize));
    let source_binding = controller.binding().unwrap().0.identity().unwrap();
    guard
        .install_completed_lifecycle_qualification(
            Rc::new(ProbeFault {
                mode,
                calls: calls.clone(),
                observations: observations.clone(),
                provider: guard.provider_pid().unwrap(),
                source_binding,
            }),
            1,
        )
        .unwrap();
    let prepared = match CnpReferencePreparation::prepare(guard, &installed) {
        Ok(prepared) => prepared,
        Err(failure) => panic!("actual public preparation failed: {:?}", failure.error),
    };
    let companion = prepared.companion_pid;
    let mut controlled = super::control::CnpControlledReference::new(prepared, 8);
    let record = ActivationRecord {
        generation: installed.bootstrap.world_generation,
        activation_id: installed.bootstrap.activation_id.clone(),
        world_binding_hash: installed.bootstrap.world_binding_hash.clone(),
        owners: vec![crate::node_contract::OwnerIdentity {
            owner: installed.bootstrap.owner_id.clone(),
            incarnation: installed.bootstrap.authority.incarnation_id.clone(),
            generation: installed.bootstrap.authority.owner_generation,
        }],
        boundary: Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl),
    };
    let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        controlled.prepare_activation(&record)
    }));
    assert_eq!(*calls.borrow(), 1);
    assert!(controlled.prepared.as_ref().unwrap().registry_complete);
    let original_ready = controlled.prepared.as_ref().unwrap().ready.clone();
    let keys = observations.request_keys().unwrap();
    let wire = serde_json::to_value(transmissions.snapshot(4 * 1024 * 1024).unwrap()).unwrap();
    if mode == Fault::None {
        assert_eq!(first.unwrap().unwrap(), original_ready);
        assert_eq!(
            controlled.prepare_activation(&record).unwrap(),
            original_ready
        );
        assert_eq!(wire["incomplete"], false);
        assert_eq!(wire["rows"].as_array().unwrap().len(), 1);
        assert_eq!(wire["rows"][0]["semantic_response_verified"], true);
    } else {
        if mode == Fault::Unwind {
            assert!(first.is_err());
        } else {
            assert_eq!(
                first.unwrap().unwrap_err().effects,
                EffectKnowledge::Unknown
            );
        }
        let failed = controlled.prepare_activation(&record).unwrap_err();
        assert_eq!(failed.effects, EffectKnowledge::Unknown);
        assert_eq!(*calls.borrow(), 1);
        assert_eq!(controlled.prepared.as_ref().unwrap().ready, original_ready);
        let probes = controlled
            .guard
            .custody
            .as_ref()
            .unwrap()
            .lifecycle_probes
            .as_ref()
            .unwrap();
        assert!(probes.unresolved);
        assert_eq!(probes.current.as_ref().unwrap().activation, record);
        if mode == Fault::NativeDeath {
            assert_eq!(wire["incomplete"], true);
            assert_eq!(wire["rows"].as_array().unwrap().len(), 1);
        } else {
            assert_eq!(wire["rows"].as_array().unwrap().len(), 0);
        }
    }
    assert_eq!(observations.request_keys().unwrap(), keys);
    assert_eq!(
        serde_json::to_value(transmissions.snapshot(4 * 1024 * 1024).unwrap()).unwrap(),
        wire
    );
    for _ in 0..300 {
        if controlled.quarantine_public().unwrap() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        controlled.status,
        crucible_node_provider::reference_device::DeviceStatus::Reaped
    );
    assert!(!std::path::Path::new(&format!("/proc/{companion}")).exists());
    drop(controlled);
    assert_eq!(retained.borrow().len(), 1);
    let mut retained = retained.borrow_mut();
    let peer = &mut retained[0];
    let probes = peer.lifecycle_probes.as_ref().unwrap();
    assert_eq!(probes.unresolved, mode != Fault::None);
    if mode == Fault::None {
        assert_eq!(probes.attempts.len(), 1);
    } else {
        assert_eq!(probes.current.as_ref().unwrap().activation, record);
    }
    assert!(
        peer.runtime
            .as_ref()
            .unwrap()
            .prepared
            .as_ref()
            .unwrap()
            .ready
            == original_ready
    );
    assert!(peer.poll_reclamation().unwrap());
    std::fs::remove_dir_all(directory).unwrap();
}
