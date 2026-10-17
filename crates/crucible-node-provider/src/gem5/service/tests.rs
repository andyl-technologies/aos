//! Exercises measured discovery, sealed registration and retained refusal custody.

// crucible-lint: allow panic-shortcut -- These service tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{cell::RefCell, path::PathBuf, rc::Rc, time::Duration};

use crucible_node_contract::*;
use serde_json::{Value, json};

use super::*;
use crate::{
    ProviderError,
    envelope::{Envelope, Nullable, RequestOrigin},
    gem5::{
        Gem5CustodySlot, Gem5Launch, Gem5LaunchArtifact, Gem5NativeCustody, Gem5OwnerResources,
    },
    handshake::*,
    journal::{JournalLimits, RequestKey},
    native_journal::{
        NativeCustody, NativeJournalLimits, NativeJournalSupervisor, NativeSupervision,
    },
};

struct Fixture {
    root: PathBuf,
    artifact: Gem5LaunchArtifact,
    launch: Gem5Launch,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let root = std::env::temp_dir().join(format!(
            "gem5-service-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let bytes = b"installed test artifact, not a native qualification";
        let path = root.join("artifact");
        std::fs::write(&path, bytes).unwrap();
        let artifact = Gem5LaunchArtifact {
            path,
            content: canonical::content_ref(bytes, "application/octet-stream").unwrap(),
        };
        let launch = Gem5Launch {
            executable: artifact.clone(),
            owner_script: artifact.clone(),
            model_script: artifact.clone(),
            guest: artifact.clone(),
            guest_isa: "x86_64".into(),
            owner: id("owner"),
            incarnation: id("incarnation"),
            generation: U64::new(1),
            resource_root: root.clone(),
            timeout: Duration::from_secs(1),
            process_images: None,
        };
        Self {
            root,
            artifact,
            launch,
        }
    }

    fn bootstrap(&self) -> Gem5ServiceBootstrap {
        Gem5ServiceBootstrap::authenticate(
            &self.artifact,
            self.launch.clone(),
            id("session"),
            canonical::content_ref(b"actual test host receipt", "application/json").unwrap(),
            [7; 32],
            limits(),
            &Installation,
        )
        .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}

fn id(name: &str) -> Id {
    Id::new(name).unwrap()
}

fn limits() -> Limits {
    Limits {
        frame_bytes: U64::new(65536),
        nesting: U64::new(64),
        requests: U64::new(16),
        journal_entries: U64::new(64),
        blob_chunk_bytes: U64::new(4096),
    }
}

struct Installation;
impl Gem5InstallationVerifier for Installation {
    fn authenticate_installation(
        &self,
        _: &Gem5Launch,
        _: &Gem5Catalog,
        _: &ContentRef,
        _: &Id,
    ) -> Result<(), ProviderError> {
        Ok(())
    }
}

struct NativeSlot;
impl Gem5CustodySlot for NativeSlot {
    fn retain(self: Box<Self>, _: Gem5NativeCustody) {
        panic!("discovery must not spawn a native owner");
    }
}

#[derive(Clone, Default)]
struct Supervisor(Rc<RefCell<Option<NativeCustody<Gem5OwnerResources>>>>);
impl NativeJournalSupervisor<Gem5OwnerResources> for Supervisor {
    fn reserve(&self) -> Result<Box<dyn NativeSupervision<Gem5OwnerResources>>, ProviderError> {
        Ok(Box::new(self.clone()))
    }
}
impl NativeSupervision<Gem5OwnerResources> for Supervisor {
    fn retain(&mut self, custody: NativeCustody<Gem5OwnerResources>) {
        *self.0.borrow_mut() = Some(custody);
    }
}

fn service(fixture: &Fixture, supervisor: &Supervisor) -> Gem5DiscoveryService {
    Gem5DiscoveryService::new(
        fixture.bootstrap(),
        Box::new(NativeSlot),
        JournalLimits {
            entries_per_origin: 64,
            outcome_bytes: 65536,
            tombstones_per_origin: 64,
        },
        NativeJournalLimits {
            operations: 16,
            operation_tombstones: 64,
            input_batches: 16,
            observation_batches: 16,
            retained_bytes: 65536,
        },
        supervisor,
    )
    .unwrap()
}

struct Exchange;
impl TrustedHandshakeVerifier for Exchange {
    fn authenticate_exchange(
        &mut self,
        _: &Id,
        _: &TrustedInstallation,
        _: &HelloRequest,
        _: &HelloResult,
    ) -> Result<(), ProviderError> {
        Ok(())
    }
    fn verify_contract_selection(
        &mut self,
        _: &ProviderManifest,
        _: &IdSet,
        _: &[SchemaRef],
        _: &ContentRef,
    ) -> Result<(), ProviderError> {
        Ok(())
    }
    fn resume_custody(
        &mut self,
        _: &Id,
        _: &Id,
        _: &IdSet,
    ) -> Result<Vec<ResumedOperation>, ProviderError> {
        Ok(Vec::new())
    }
    fn fence_connection(&mut self, _: &Id) -> Result<(), ProviderError> {
        Ok(())
    }
}

fn envelope(method: &str, request: &str, body: Value) -> Envelope {
    serde_json::from_value(json!({"protocol":"CNP/1", "message":"request",
        "session_id":"session", "incarnation_id":"incarnation", "node_id":null,
        "execution_owner_id":null, "capture_owner_id":null, "request_id":request,
        "operation_id":null, "sequence":"2", "method":method, "body":body,
        "extensions":{}}))
    .unwrap()
}

fn admit(service: &mut Gem5DiscoveryService) -> ConnectionAuthority {
    let hello = HelloRequest {
        versions: vec!["CNP/1".into()],
        session_id: id("session"),
        controller_nonce: Bytes::new(vec![3; 32]),
        required_features: vec![id("cnp.core/1")],
        optional_features: Vec::new(),
        limits: limits(),
        admission_token: Bytes::new(vec![7; 32]),
        resume_session: None,
        extensions: Extensions::new(),
    };
    let result = HelloResult {
        version: "CNP/1".into(),
        session_id: id("session"),
        incarnation_id: id("incarnation"),
        controller_nonce: hello.controller_nonce.clone(),
        provider_nonce: Bytes::new(vec![5; 32]),
        selected_features: hello.required_features.clone(),
        limits: limits(),
        resume_token: Nullable(None),
        provider_identity: service.catalog().manifest().clone(),
        resumed_operations: Vec::new(),
    };
    let mut request = envelope("hello", "hello", serde_json::to_value(hello).unwrap());
    request.sequence = U64::new(1);
    request.session_id = Nullable(None);
    request.incarnation_id = Nullable(None);
    let mut response = request.clone();
    response.message = crate::envelope::MessageKind::Response;
    response.incarnation_id = Nullable(Some(id("incarnation")));
    response.body = json!({"status":"completed", "operation_state":"completed", "result":result,
        "extensions":{}})
    .as_object()
    .unwrap()
    .clone();
    service
        .admit_connection(&request, &response, id("connection"), &mut Exchange)
        .unwrap()
}

#[test]
fn catalog_does_not_promote_artifact_hashes_to_profiles() {
    let fixture = Fixture::new();
    let catalog = Gem5Catalog::measure(&fixture.artifact, &fixture.launch).unwrap();
    assert_eq!(catalog.manifest().implementation.artifacts.len(), 5);
    assert!(catalog.manifest().supported_profiles.is_empty());
    assert!(catalog.manifest().qualification_refs.is_empty());
    assert_eq!(
        catalog.guarantees().repeatability,
        Repeatability::Unqualified
    );
    assert_eq!(catalog.guarantees().capture_scope, CaptureScope::None);
    for (reference, bytes) in catalog.content_objects() {
        reference.verify(bytes).unwrap();
    }
}

#[test]
fn changed_artifact_and_denied_installation_fail_before_launch() {
    let fixture = Fixture::new();
    struct Denied;
    impl Gem5InstallationVerifier for Denied {
        fn authenticate_installation(
            &self,
            _: &Gem5Launch,
            _: &Gem5Catalog,
            _: &ContentRef,
            _: &Id,
        ) -> Result<(), ProviderError> {
            Err(ProviderError::Correlation("actual installation denied"))
        }
    }
    assert!(
        Gem5ServiceBootstrap::authenticate(
            &fixture.artifact,
            fixture.launch.clone(),
            id("session"),
            canonical::content_ref(b"receipt", "application/json").unwrap(),
            [7; 32],
            limits(),
            &Denied
        )
        .is_err()
    );
    std::fs::write(&fixture.artifact.path, b"changed artifact").unwrap();
    assert!(Gem5Catalog::measure(&fixture.artifact, &fixture.launch).is_err());
}

#[test]
fn original_discovery_is_retained_on_retry_and_drop() {
    let fixture = Fixture::new();
    let supervisor = Supervisor::default();
    let mut service = service(&fixture, &supervisor);
    let authority = admit(&mut service);
    let request = envelope(
        "discover",
        "discovery",
        json!({"profile_ids":[], "extensions":{}}),
    );
    let outcome = service.dispatch(&authority, &request).unwrap();
    assert_eq!(service.dispatch(&authority, &request).unwrap(), outcome);
    let mut changed = request.clone();
    changed
        .body
        .insert("profile_ids".into(), json!(["forged/exact"]));
    assert!(service.dispatch(&authority, &changed).is_err());

    drop(service);
    assert!(authority.ensure_live().is_err());
    let retained = supervisor.0.borrow();
    let custody = retained.as_ref().unwrap();
    assert!(custody.resources.boundary().is_none());
    assert!(
        custody
            .requests
            .get(&RequestKey {
                origin: RequestOrigin::Controller,
                id: id("discovery")
            })
            .unwrap()
            .outcome()
            .is_some()
    );
}

#[test]
fn same_wire_ids_from_foreign_handshake_do_not_authorize_dispatch() {
    let fixture = Fixture::new();
    let mut original = service(&fixture, &Supervisor::default());
    let own = admit(&mut original);
    let mut foreign = service(&fixture, &Supervisor::default());
    let foreign_lease = admit(&mut foreign);
    assert_eq!(own.session_id(), foreign_lease.session_id());
    assert_eq!(own.connection_id(), foreign_lease.connection_id());
    assert_eq!(own.epoch(), foreign_lease.epoch());
    assert!(own.same_registration(&own.clone()));
    assert!(!own.same_registration(&foreign_lease));
    let request = envelope(
        "discover",
        "foreign",
        json!({"profile_ids":[], "extensions":{}}),
    );
    assert!(original.dispatch(&foreign_lease, &request).is_err());
}

#[test]
fn unsupported_native_requests_remain_original_no_effect_refusals() {
    let fixture = Fixture::new();
    let mut service = service(&fixture, &Supervisor::default());
    let authority = admit(&mut service);
    let request = envelope(
        "discover",
        "unknown-page",
        json!({"profile_ids":[], "cursor":"forged", "extensions":{}}),
    );
    let response = service.dispatch(&authority, &request).unwrap();
    assert_eq!(response["operation_state"], "not_started");
    assert_eq!(response["error"]["effect"], "not_started");
    assert_eq!(service.dispatch(&authority, &request).unwrap(), response);
    assert!(service.journal().resources().boundary().is_none());
}

#[test]
fn actual_unix_stream_discovery_retains_journal_after_eof() {
    use crate::{
        connection::{BodySchemaVerifier, ConnectionIncident, ConnectionSupervisor, ReceivedBody},
        transport::{FrameReader, write_frame},
    };

    struct Schemas;
    impl BodySchemaVerifier for Schemas {
        fn verify(
            &self,
            _: &ConnectionAuthority,
            _: &Envelope,
            _: &ReceivedBody,
        ) -> Result<(), ProviderError> {
            // This witness selects only closed baseline discovery bodies; it
            // does not install or qualify a vendor execution/payload schema.
            Ok(())
        }
    }
    #[derive(Default)]
    struct Incidents(RefCell<Vec<ConnectionIncident>>);
    impl ConnectionSupervisor for Incidents {
        fn quarantine(&self, incident: ConnectionIncident) {
            self.0.borrow_mut().push(incident);
        }
    }

    let fixture = Fixture::new();
    let mut service = service(&fixture, &Supervisor::default());
    let authority = admit(&mut service);
    let incidents = Rc::new(Incidents::default());
    let (provider, mut controller) = std::os::unix::net::UnixStream::pair().unwrap();
    provider
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    provider
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    controller
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    controller
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let request = envelope(
        "discover",
        "native-stream",
        json!({"profile_ids":[], "extensions":{}}),
    );
    let original = request.clone();
    let peer = std::thread::spawn(move || {
        write_frame(
            &mut controller,
            &serde_json::to_value(request).unwrap(),
            65536,
        )
        .unwrap();
        let mut reader = FrameReader::new(controller, 65536).unwrap();
        reader.read().unwrap().unwrap()
    });

    service
        .serve_connection(
            provider,
            authority.clone(),
            incidents.clone(),
            Rc::new(Schemas),
        )
        .unwrap();
    let response = peer.join().unwrap();
    assert_eq!(response["body"]["status"], "completed");
    assert!(
        response["body"]["result"]["profiles"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(authority.ensure_live().is_err());
    assert!(service.dispatch(&authority, &original).is_err());
    let entry = service
        .journal()
        .snapshot()
        .requests
        .get(&RequestKey {
            origin: RequestOrigin::Controller,
            id: id("native-stream"),
        })
        .unwrap();
    assert_eq!(
        canonical::parse_json(entry.outcome().unwrap(), 65536).unwrap(),
        response["body"]
    );
    let retained = incidents.0.borrow();
    assert_eq!(retained.len(), 1);
    assert!(retained[0].transport_fenced);
    assert!(service.journal().resources().boundary().is_none());
}
