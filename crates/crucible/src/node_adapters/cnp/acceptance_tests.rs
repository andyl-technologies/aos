//! Exercises real process ordering and original custody, not native class qualification.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- Native fixture assertions fail immediately when original custody or ordering changes.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::cell::Cell;

use super::*;

struct Calls(RefCell<Vec<(MessageKind, Method)>>);

impl BodySchemaVerifier for Calls {
    fn verify(
        &self,
        authority: &ConnectionAuthority,
        envelope: &Envelope,
        body: &ReceivedBody,
    ) -> Result<(), ProviderError> {
        Schemas.verify(authority, envelope, body)?;
        self.0
            .borrow_mut()
            .push((envelope.message, envelope.method));
        Ok(())
    }
}

struct Acceptance<'a> {
    installed: &'a Installed,
    calls: &'a Calls,
    accepted: Cell<bool>,
    evaluations: Cell<usize>,
}

impl CnpRealizationAcceptance for Acceptance<'_> {
    fn authenticate(&self, scope: CnpAcceptanceScope<'_>) -> Result<(), OperationFailure> {
        let CnpAcceptanceScope {
            guard,
            profile,
            realization,
            binding,
            owner,
            resources,
            gate,
        } = scope;
        assert!(guard.provider_pid().is_some());
        assert_eq!(resources, &self.installed.bootstrap.resource_limits);
        assert!(gate.gate_closed);
        assert_eq!(
            profile.implementation,
            self.installed.profile.implementation
        );
        assert_eq!(
            realization.realization_manifest.bindings.as_slice(),
            std::slice::from_ref(binding)
        );
        assert_eq!(
            realization.realization_manifest.owner_bindings.as_slice(),
            std::slice::from_ref(owner)
        );
        assert_eq!(
            realization.prepared_token,
            self.installed.bootstrap.prepared_token
        );
        assert!(
            self.calls
                .0
                .borrow()
                .contains(&(MessageKind::Response, Method::Realize))
        );
        self.evaluations.set(self.evaluations.get() + 1);
        if !self.accepted.get() {
            return Err(OperationFailure {
                effects: crate::node_contract::EffectKnowledge::Unknown,
                reason: "fixture current behavioral evidence absent".into(),
            });
        }
        Ok(())
    }
}

// Reuse the public transport's opaque host budget. The local pair owns its
// lifetime, and tightening never renews the original three-second allowance.
// No host clock coordinate or synthetic provider response enters the fixture.
fn wait_for_process(mut complete: impl FnMut() -> bool) {
    let (stream, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
    let (_transport, deadline) =
        crucible_node_provider::client::DeadlineStream::new(stream, Duration::from_secs(3))
            .unwrap();
    while !complete() {
        deadline.tighten(Duration::from_secs(3)).unwrap();
        std::thread::yield_now();
    }
}

#[test]
#[ignore = "requires source-built CRUCIBLE_REFERENCE_PROVIDER_EXECUTABLE and CRUCIBLE_REFERENCE_DEVICE_EXECUTABLE"]
fn actual_current_acceptance_precedes_admit_and_retains_original_realize_on_refusal() {
    let provider =
        PathBuf::from(std::env::var_os("CRUCIBLE_REFERENCE_PROVIDER_EXECUTABLE").unwrap());
    let device = PathBuf::from(std::env::var_os("CRUCIBLE_REFERENCE_DEVICE_EXECUTABLE").unwrap());
    for accepted in [false, true] {
        let mut installed = installation(&provider, &device);
        let directory = std::env::temp_dir().join(format!(
            "cnp-core-acceptance-{}-{accepted}",
            std::process::id()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let socket = directory.join("control.sock");
        let retained = Rc::new(RefCell::new(Vec::new()));
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
        let mut stdin = child.stdin.take().unwrap();
        let mut guard = CnpLaunchGuard::new(child, directory.clone(), slot)
            .ok()
            .unwrap();
        let original_pid = guard.provider_pid().unwrap();
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
        wait_for_process(|| socket.exists());
        assert!(socket.exists());
        let calls = Rc::new(Calls(RefCell::new(Vec::new())));
        connect_with_schema(&mut guard, &socket, &mut installed, calls.clone());
        let acceptance = Acceptance {
            installed: &installed,
            calls: &calls,
            accepted: Cell::new(accepted),
            evaluations: Cell::new(0),
        };
        let result = CnpAcceptedPreparation::prepare(guard, &installed, &acceptance);
        assert_eq!(acceptance.evaluations.get(), 1);
        let admitted = calls
            .0
            .borrow()
            .iter()
            .filter(|(kind, method)| *kind == MessageKind::Request && *method == Method::Admit)
            .count();
        assert_eq!(admitted, usize::from(accepted));
        if accepted {
            let prepared = result.ok().unwrap();
            let before = calls.0.borrow().len();
            acceptance.accepted.set(false);
            assert!(prepared.reauthenticate(&installed, &acceptance).is_err());
            assert_eq!(acceptance.evaluations.get(), 2);
            assert_eq!(
                calls.0.borrow().len(),
                before,
                "fresh check did not redispatch"
            );
            drop(prepared);
        } else {
            let failure = result.err().unwrap();
            assert_eq!(failure.guard.provider_pid(), Some(original_pid));
            let controller = failure
                .guard
                .custody
                .as_ref()
                .unwrap()
                .controller
                .as_ref()
                .unwrap();
            let original = controller
                .observation_snapshot(
                    &[ObservedRequestKey {
                        origin: RequestOrigin::Controller,
                        request_id: id(&format!(
                            "prepare-realize-{}",
                            installed.bootstrap.authority.realization_id
                        )),
                    }],
                    &[],
                    ObservationLimits {
                        maximum_requests: 4,
                        maximum_objects: 16,
                        maximum_bytes: 1024 * 1024,
                    },
                )
                .unwrap();
            assert_eq!(original.requests.len(), 1);
            assert!(original.requests[0].response.0.is_some());
            drop(failure);
        }
        assert_eq!(retained.borrow().len(), 1);
        wait_for_process(|| retained.borrow_mut()[0].poll_reclamation().unwrap());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
