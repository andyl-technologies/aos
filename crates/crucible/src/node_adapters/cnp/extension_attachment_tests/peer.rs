//! Source-built test subprocess and finite original supervisor for attachment controls.

#![cfg(test)]

// crucible-lint: allow host-monotonic-time -- the finite test supervisor clock bounds only original socket startup or authentic child cleanup, never modeled state.
use std::{os::unix::net::UnixListener, time::Instant};

use super::super::*;
use crucible_node_provider::transport::{FrameReader, write_frame};

const CHILD_ENV: &str = "CRUCIBLE_TYPED_ATTACHMENT_MODEL_DIRECTORY";
const CHILD_TEST: &str = "node_adapters::cnp::tests::extension_attachment::peer::framed_peer_child";

struct ExtensionsPolicy(Vec<ExtensionSelection>);

impl InstalledExtensionNegotiationVerifier for ExtensionsPolicy {
    fn supported(&self) -> &[ExtensionSelection] {
        &self.0
    }
    fn required(&self) -> &[ExtensionSelection] {
        &self.0
    }
    fn verify_selection(
        &self,
        selected: &[ExtensionSelection],
        _: &IdSet,
    ) -> Result<(), ProviderError> {
        if selected == self.0 {
            Ok(())
        } else {
            Err(ProviderError::Correlation("model exact tuple changed"))
        }
    }
}

fn selection() -> ExtensionSelection {
    ExtensionSelection {
        declaration: canonical::content_ref(b"test-only typed attachment tuple", "text/plain")
            .unwrap(),
        identifier: id("test.example/typed-attachment"),
        semantic_version: SemanticVersion {
            major: U64::new(1),
            minor: U64::new(0),
            patch: U64::new(0),
            prerelease: None,
            build: None,
        },
        schema_digest: canonical::content_ref(b"test-only schema", "text/plain")
            .unwrap()
            .hash,
    }
}

pub(super) struct Peer {
    directory: PathBuf,
    retained: Rc<RefCell<Vec<CnpPeerCustody>>>,
    pub(super) guard: Option<CnpLaunchGuard>,
    pub(super) controller: Option<ReferenceController>,
    pub(super) registrar: Option<ExtensionHandshake>,
    pub(super) installed: Installed,
    reclaimed: bool,
}

impl Peer {
    // crucible-lint: allow rust-allow -- test-only operational deadlines never enter modeled state.
    // crucible-lint: allow clippy-disallowed-method -- the finite socket startup deadline bounds only this test supervisor.
    #[allow(clippy::disallowed_methods)]
    pub(super) fn launch() -> Self {
        static NEXT_DIRECTORY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let serial = NEXT_DIRECTORY.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let directory =
            std::env::temp_dir().join(format!("typed-attachment-{}-{serial}", std::process::id()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let executable = std::env::current_exe().unwrap();
        let installed = installation(&executable, &executable);
        let retained = Rc::new(RefCell::new(Vec::new()));
        let child = Command::new(&executable)
            .args(["--exact", CHILD_TEST, "--nocapture"])
            .env(CHILD_ENV, directory.as_path())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .process_group(0)
            .spawn()
            .unwrap();
        let (guard, launch_error) = match CnpLaunchGuard::new(
            child,
            directory.as_path().to_path_buf(),
            Box::new(Slot(retained.clone())),
        ) {
            Ok(guard) => (guard, None),
            Err(failure) => (failure.guard, Some(failure.error)),
        };
        // Establish the cleanup owner before any further assertion or fallible
        // Hello step, including a failed original process-group validation.
        let mut owner = Self {
            directory,
            retained,
            guard: Some(guard),
            controller: None,
            registrar: None,
            installed,
            reclaimed: false,
        };
        assert!(
            launch_error.is_none(),
            "model launch refused: {launch_error:?}"
        );
        let socket = owner.directory.as_path().join("peer.sock");
        let guard = owner.guard.as_mut().unwrap();
        let installed = &mut owner.installed;
        // crucible-lint: allow host-monotonic-time -- the finite test supervisor clock bounds only original socket startup or authentic child cleanup, never modeled state.
        let deadline = Instant::now() + Duration::from_secs(3);
        // crucible-lint: allow host-monotonic-time -- the finite test supervisor clock bounds only original socket startup or authentic child cleanup, never modeled state.
        while !socket.exists() && Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert!(socket.exists(), "model original peer endpoint unavailable");

        let bootstrap = installed.bootstrap.clone();
        let feature = id(EXTENSION_NEGOTIATION_V1);
        let features = vec![
            id("cnp.control-evidence/1"),
            id("cnp.core/1"),
            feature.clone(),
        ];
        let mut token = [0; 32];
        token.copy_from_slice(bootstrap.admission_token.as_slice());
        let mut registrar = ExtensionHandshake::new(
            Handshake::new(
                TrustedInstallation {
                    session_id: bootstrap.authority.session_id.clone(),
                    incarnation_id: bootstrap.authority.incarnation_id.clone(),
                    measured_implementation: installed.profile.implementation.clone(),
                    launch_receipt: bootstrap.admission_receipt.clone(),
                    admission_token: token,
                },
                NegotiationPolicy {
                    supported_features: features.clone(),
                    required_features: features.clone(),
                    provider_limits: bootstrap.limits,
                    required_schemas: Vec::new(),
                    required_guarantees: installed
                        .profile
                        .bind_qualified(bootstrap.authority.clone(), &installed.qualifications)
                        .unwrap()
                        .0
                        .compatibility
                        .guarantees_ref,
                    envelope_extension_features: BTreeMap::from([(
                        EXTENSION_NEGOTIATION_V1.into(),
                        feature,
                    )]),
                },
            )
            .unwrap(),
            Rc::new(ExtensionsPolicy(vec![selection()])),
        )
        .unwrap();
        let hello = HelloRequest {
            versions: vec!["CNP/1".into()],
            session_id: bootstrap.authority.session_id.clone(),
            controller_nonce: entropy(),
            required_features: features,
            optional_features: Vec::new(),
            limits: bootstrap.limits,
            admission_token: bootstrap.admission_token.clone(),
            resume_session: None,
            extensions: Extensions::new(),
        };
        let envelope = Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(None),
            incarnation_id: Nullable(None),
            node_id: Nullable(None),
            execution_owner_id: Nullable(None),
            capture_owner_id: Nullable(None),
            operation_id: Nullable(None),
            request_id: Nullable(Some(id("typed-model-hello"))),
            sequence: U64::new(1),
            method: Method::Hello,
            body: serde_json::to_value(hello)
                .unwrap()
                .as_object()
                .unwrap()
                .clone(),
            extensions: BTreeMap::from([(
                EXTENSION_NEGOTIATION_V1.into(),
                serde_json::to_value(ExtensionOfferV1 {
                    format: U64::new(1),
                    required: vec![selection()],
                    optional: Vec::new(),
                })
                .unwrap(),
            )]),
        };
        let result = HelloResult {
            version: "CNP/1".into(),
            session_id: bootstrap.authority.session_id.clone(),
            incarnation_id: bootstrap.authority.incarnation_id.clone(),
            controller_nonce: Bytes::new(vec![0; 32]),
            provider_nonce: entropy(),
            selected_features: envelope.body["required_features"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| serde_json::from_value(v.clone()).unwrap())
                .collect(),
            limits: bootstrap.limits,
            resume_token: Nullable(None),
            provider_identity: installed.profile.provider_manifest.clone(),
            resumed_operations: Vec::new(),
        };
        write_frame(
            guard
                .custody
                .as_mut()
                .unwrap()
                .child
                .stdin
                .as_mut()
                .unwrap(),
            &serde_json::to_value(result).unwrap(),
            1_048_576,
        )
        .unwrap();
        drop(guard.custody.as_mut().unwrap().child.stdin.take());
        let peer = ClientPeer {
            pid: guard.provider_pid().unwrap(),
            uid: rustix::process::geteuid().as_raw(),
            executable: crucible_node_provider::conformance::measure_executable(&executable)
                .unwrap(),
        };
        let session = ClientSession::negotiate_extensions(
            UnixStream::connect(socket).unwrap(),
            &peer,
            &envelope,
            id("typed-model-connection"),
            &mut registrar,
            installed,
            Rc::new(Supervisor::default()),
            Rc::new(Schemas),
            Duration::from_secs(3),
            1_048_576,
            64,
        )
        .unwrap();
        let controller = ReferenceController::new_qualified(
            installed.profile.clone(),
            bootstrap,
            session,
            ClientCustody::new(
                256,
                ClientContent::new(16 * 1024 * 1024, 256, 16_384).unwrap(),
            )
            .unwrap(),
            Duration::from_secs(3),
            installed.qualifications.clone(),
        )
        .unwrap();
        owner.controller = Some(controller);
        owner.registrar = Some(registrar);
        owner
    }

    pub(super) fn path(&self) -> &std::path::Path {
        self.directory.as_path()
    }

    pub(super) fn finish(&mut self) {
        self.retire();
        assert!(
            self.reclaimed,
            "actual original framed child remains supervised"
        );
    }

    // crucible-lint: allow rust-allow -- test-only operational deadlines never enter modeled state.
    // crucible-lint: allow clippy-disallowed-method -- the finite original child reclamation deadline bounds only this test supervisor.
    #[allow(clippy::disallowed_methods)]
    fn retire(&mut self) {
        // Drop transfers the original Child to its reserved slot. No test
        // result or transport closure substitutes for actual kernel cleanup.
        drop(self.guard.take());
        drop(self.controller.take());
        drop(self.registrar.take());
        // crucible-lint: allow host-monotonic-time -- the finite test supervisor clock bounds only original socket startup or authentic child cleanup, never modeled state.
        let deadline = Instant::now() + Duration::from_secs(3);
        // crucible-lint: allow host-monotonic-time -- the finite test supervisor clock bounds only original socket startup or authentic child cleanup, never modeled state.
        while Instant::now() < deadline {
            let mut retained = self.retained.borrow_mut();
            if retained.len() == 1 && retained[0].poll_reclamation().unwrap_or(false) {
                self.reclaimed = true;
                return;
            }
            drop(retained);
            std::thread::yield_now();
        }
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        if !self.reclaimed {
            self.retire();
        }
        if self.reclaimed {
            std::fs::remove_dir_all(&self.directory).unwrap();
        } else {
            // A fixture failure cannot release a still-effectful original Child
            // or its namespace. Keep the same finite supervisor allocation for
            // process lifetime, with the private path available for inspection.
            std::mem::forget(self.retained.clone());
            eprintln!(
                "original model custody retained at {}",
                self.directory.display()
            );
        }
    }
}

#[test]
fn framed_peer_child() {
    let Some(directory) = std::env::var_os(CHILD_ENV).map(PathBuf::from) else {
        return;
    };
    let listener = UnixListener::bind(directory.join("peer.sock")).unwrap();
    let mut stdin = FrameReader::new(std::io::stdin(), 1_048_576).unwrap();
    let mut result: HelloResult = serde_json::from_value(stdin.read().unwrap().unwrap()).unwrap();
    let (mut stream, _) = listener.accept().unwrap();
    let mut reader = FrameReader::new(stream.try_clone().unwrap(), 1_048_576).unwrap();
    let request: Envelope = serde_json::from_value(reader.read().unwrap().unwrap()).unwrap();
    let hello: HelloRequest =
        serde_json::from_value(serde_json::Value::Object(request.body.clone())).unwrap();
    result.controller_nonce = hello.controller_nonce;
    let mut response = request.clone();
    response.message = MessageKind::Response;
    response.incarnation_id = Nullable(Some(result.incarnation_id.clone()));
    response.body = serde_json::json!({
        "status": "completed",
        "operation_state": "completed",
        "result": result,
        "extensions": {}
    })
    .as_object()
    .unwrap()
    .clone();
    response.extensions = BTreeMap::from([(
        EXTENSION_NEGOTIATION_V1.into(),
        serde_json::to_value(ExtensionSelectionV1 {
            format: U64::new(1),
            selected: vec![selection()],
        })
        .unwrap(),
    )]);
    write_frame(
        &mut stream,
        &serde_json::to_value(response).unwrap(),
        1_048_576,
    )
    .unwrap();
    if let Some(value) = reader.read().unwrap() {
        std::fs::write(
            directory.join("unexpected-control.json"),
            canonical::canonical_json(&value).unwrap(),
        )
        .unwrap();
        panic!("typed metadata caused an unauthorized post-Hello control");
    }
}
