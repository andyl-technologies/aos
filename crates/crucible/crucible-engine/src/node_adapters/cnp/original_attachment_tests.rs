//! Exercises borrowed attachment against one actual source-built public peer.
//!
//! This is process/transport custody coverage, not normal behavioral acceptance,
//! world readiness, state preservation or a native class certificate.

use super::*;

struct ActualOriginal {
    capsule: Option<Box<Capsule>>,
}

struct Capsule {
    guard: Option<CnpLaunchGuard>,
    retained: Rc<RefCell<Vec<CnpPeerCustody>>>,
    controller: Option<ReferenceController>,
    handshake: Option<Handshake>,
    withheld_handshake: Option<Handshake>,
    directory: PathBuf,
}

impl ActualOriginal {
    fn launch() -> Self {
        let provider = PathBuf::from(
            std::env::var_os("CRUCIBLE_REFERENCE_PROVIDER_EXECUTABLE")
                .expect("source-built provider is required"),
        );
        let device = PathBuf::from(
            std::env::var_os("CRUCIBLE_REFERENCE_DEVICE_EXECUTABLE")
                .expect("source-built companion is required"),
        );
        let mut installed = installation(&provider, &device);
        let directory = std::env::temp_dir().join(format!(
            "cnp-original-attachment-{}-{}",
            std::process::id(),
            installed.bootstrap.admission_token.as_slice()[0],
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let socket = directory.join("control.sock");
        let retained = Rc::new(RefCell::new(Vec::with_capacity(1)));
        let slot = Box::new(Slot(Rc::clone(&retained)));
        let mut child = Command::new(provider)
            .arg(&socket)
            .arg(device)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let guard = CnpLaunchGuard::new(child, directory.clone(), slot)
            .ok()
            .unwrap();
        let mut original = Self {
            capsule: Some(Box::new(Capsule {
                guard: Some(guard),
                retained,
                controller: None,
                handshake: None,
                withheld_handshake: None,
                directory,
            })),
        };
        let mut stdin = stdin.unwrap();
        crucible_node_transport::transport::write_frame(
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

        let deadline = ExchangeDeadline::start(Duration::from_secs(3)).unwrap();
        while !socket.exists() {
            let remaining = deadline
                .remaining()
                .expect("actual provider socket deadline");
            std::thread::park_timeout(remaining.min(Duration::from_millis(1)));
        }
        let capsule = original.capsule.as_mut().unwrap();
        let (controller, handshake) = original_control(
            capsule.guard.as_ref().unwrap(),
            &socket,
            &mut installed,
            Rc::new(Schemas),
        );
        capsule.controller = Some(controller);
        capsule.handshake = Some(handshake);
        original
    }
}

impl Drop for ActualOriginal {
    fn drop(&mut self) {
        let Some(mut original) = self.capsule.take() else {
            return;
        };
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            retire_original(&mut original)
        }));
        if !matches!(outcome, Ok(true)) {
            // Retain the complete same capsule on refusal, timeout or unwind.
            // An unresolved assertion never becomes a native cleanup verdict.
            std::mem::forget(original);
        }
    }
}

fn retire_original(original: &mut Capsule) -> bool {
    if original.handshake.is_none() {
        original.handshake = original.withheld_handshake.take();
    }
    if let Some(guard) = original.guard.as_mut()
        && original.controller.is_some()
        && guard
            .attach_original(&mut original.controller, &mut original.handshake)
            .is_err()
    {
        return false;
    }
    drop(original.guard.take());
    let Ok(deadline) = ExchangeDeadline::start(Duration::from_secs(3)) else {
        return false;
    };
    loop {
        let Ok(mut retained) = original.retained.try_borrow_mut() else {
            return false;
        };
        let reclaimed = retained.first_mut().map(|peer| peer.poll_reclamation());
        drop(retained);
        if matches!(reclaimed, Some(Ok(true))) {
            // This isolated transport fixture never entered an ordinary world.
            // The original native proof precedes removal of its socket directory.
            return std::fs::remove_dir_all(&original.directory).is_ok();
        }
        let Ok(remaining) = deadline.remaining() else {
            return false;
        };
        std::thread::park_timeout(remaining.min(Duration::from_millis(1)));
    }
}

#[test]
#[ignore = "requires source-built CRUCIBLE_REFERENCE_PROVIDER_EXECUTABLE and CRUCIBLE_REFERENCE_DEVICE_EXECUTABLE"]
fn actual_original_attachment_keeps_rejected_inputs_then_adopts_same_child() {
    let mut original = ActualOriginal::launch();
    let capsule = original.capsule.as_mut().unwrap();
    let pid = capsule.guard.as_ref().unwrap().provider_pid().unwrap();
    capsule.withheld_handshake = capsule.handshake.take();

    assert!(
        capsule
            .guard
            .as_mut()
            .unwrap()
            .attach_original(&mut capsule.controller, &mut capsule.handshake)
            .is_err()
    );
    assert_eq!(capsule.controller.as_ref().unwrap().peer_pid(), pid);
    assert!(capsule.withheld_handshake.is_some());
    assert!(capsule.retained.borrow().is_empty());
    assert!(
        capsule
            .guard
            .as_ref()
            .unwrap()
            .custody
            .as_ref()
            .unwrap()
            .controller
            .is_none()
    );

    capsule.handshake = capsule.withheld_handshake.take();
    capsule
        .guard
        .as_mut()
        .unwrap()
        .attach_original(&mut capsule.controller, &mut capsule.handshake)
        .unwrap();
    assert!(capsule.controller.is_none());
    assert!(capsule.handshake.is_none());
    assert_eq!(capsule.guard.as_ref().unwrap().provider_pid(), Some(pid));
    assert_eq!(
        capsule
            .guard
            .as_ref()
            .unwrap()
            .custody
            .as_ref()
            .unwrap()
            .controller
            .as_ref()
            .unwrap()
            .peer_pid(),
        pid
    );

    drop(capsule.guard.take());
    assert_eq!(capsule.retained.borrow().len(), 1);
    assert_eq!(capsule.retained.borrow()[0].provider_pid(), pid);
    assert!(capsule.retained.borrow()[0].controller.is_some());
}
