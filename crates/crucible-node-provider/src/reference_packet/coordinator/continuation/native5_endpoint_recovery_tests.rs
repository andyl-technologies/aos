//! Uses actual paired Unix streams and local producer ownership for refusal recovery.
//!
//! The Hello registrar and source selection are explicitly modeled. Literal
//! received/emitted Hello bytes and the native model are real owning values;
//! this fixture supplies no child, complete Capture or restoration authority.

use super::*;
use crate::blob::{BlobQuarantine, BlobSupervisor};
use crate::native_hello::OriginalNativeHelloJournal;
use crate::reference_packet::service::PacketNative5StorageLimits;
use crate::reference_packet::{PacketEvent, PacketProgram, control::PacketControl};
use std::io::Write;
use std::os::unix::net::UnixDatagram;

struct BlobCustodian;
impl BlobSupervisor for BlobCustodian {
    fn quarantine(&self, _: BlobQuarantine) {}
}

pub(super) fn retained_endpoint_fixture() -> (
    Handshake,
    Connection<UnixStream>,
    PacketControl,
    Rc<crate::reference_packet::Native5Policy>,
    PacketNative5StorageLimits,
    OriginalNativeHelloJournal,
    UnixStream,
) {
    retained_endpoint_fixture_with_hello_limit(65536)
}

fn retained_endpoint_fixture_with_hello_limit(
    maximum_hello_frame: usize,
) -> (
    Handshake,
    Connection<UnixStream>,
    PacketControl,
    Rc<crate::reference_packet::Native5Policy>,
    PacketNative5StorageLimits,
    OriginalNativeHelloJournal,
    UnixStream,
) {
    retained_endpoint_fixture_with_supervisor(maximum_hello_frame, Rc::new(Supervisor))
}

fn retained_endpoint_fixture_with_supervisor(
    maximum_hello_frame: usize,
    supervisor: Rc<dyn ConnectionSupervisor>,
) -> (
    Handshake,
    Connection<UnixStream>,
    PacketControl,
    Rc<crate::reference_packet::Native5Policy>,
    PacketNative5StorageLimits,
    OriginalNativeHelloJournal,
    UnixStream,
) {
    retained_endpoint_fixture_with_bank(maximum_hello_frame, supervisor, 1024 * 1024, 64)
}

fn retained_endpoint_fixture_with_bank(
    maximum_hello_frame: usize,
    supervisor: Rc<dyn ConnectionSupervisor>,
    history_bytes: usize,
    direction_slots: usize,
) -> (
    Handshake,
    Connection<UnixStream>,
    PacketControl,
    Rc<crate::reference_packet::Native5Policy>,
    PacketNative5StorageLimits,
    OriginalNativeHelloJournal,
    UnixStream,
) {
    let (handshake, authority, selection, coordinator) = scope(true);
    let policy = crate::reference_packet::service::controlled_native5_policy(
        selection.clone(),
        coordinator.clone(),
    )
    .unwrap();
    let (mut host, native) = UnixStream::pair().unwrap();
    let mut hello = OriginalNativeHelloJournal::reserve(maximum_hello_frame, 64)
        .unwrap()
        .bind(native)
        .unwrap();
    let request = crate::handshake::HelloRequest {
        versions: vec!["CNP/1".into()],
        session_id: authority.session_id().clone(),
        controller_nonce: Bytes::new(vec![3; 32]),
        required_features: authority.selected_features().clone(),
        optional_features: Vec::new(),
        limits: authority.limits(),
        admission_token: Bytes::new(vec![7; 32]),
        resume_session: None,
        extensions: Extensions::new(),
    };
    let result = crate::handshake::HelloResult {
        version: "CNP/1".into(),
        session_id: authority.session_id().clone(),
        incarnation_id: authority.incarnation_id().clone(),
        controller_nonce: request.controller_nonce.clone(),
        provider_nonce: Bytes::new(vec![5; 32]),
        selected_features: authority.selected_features().clone(),
        limits: authority.limits(),
        resume_token: Nullable(None),
        provider_identity: selection.provider.clone(),
        resumed_operations: Vec::new(),
    };
    let mut request_frame = crate::envelope::tests::request();
    request_frame.method = Method::Hello;
    request_frame.sequence = U64::new(1);
    request_frame.session_id = Nullable(Some(authority.session_id().clone()));
    request_frame.incarnation_id = Nullable(None);
    request_frame.node_id = Nullable(None);
    request_frame.execution_owner_id = Nullable(None);
    request_frame.capture_owner_id = Nullable(None);
    request_frame.operation_id = Nullable(None);
    request_frame.body = serde_json::to_value(request)
        .unwrap()
        .as_object()
        .unwrap()
        .clone();
    let mut response_frame = request_frame.clone();
    response_frame.message = MessageKind::Response;
    response_frame.incarnation_id = Nullable(Some(authority.incarnation_id().clone()));
    response_frame.body = serde_json::to_value(crate::bodies::ResponseShape::Completed {
        operation_state: crate::bodies::OperationState::Completed,
        result: serde_json::to_value(result)
            .unwrap()
            .as_object()
            .unwrap()
            .clone(),
        extensions: Extensions::new(),
    })
    .unwrap()
    .as_object()
    .unwrap()
    .clone();
    let request_value = serde_json::to_value(request_frame).unwrap();
    let mut raw = serde_json::to_vec(&request_value).unwrap();
    raw.extend_from_slice(b" \n");
    host.write_all(&(raw.len() as u32).to_be_bytes()).unwrap();
    host.write_all(&raw).unwrap();
    assert_eq!(hello.receive().unwrap().unwrap(), request_value);
    hello
        .publish(&serde_json::to_value(response_frame).unwrap())
        .unwrap();
    let (native, hello) = hello.into_parts();
    assert_eq!(hello.original_frames().frames().count(), 2);

    let storage = PacketNative5StorageLimits {
        snapshot_bytes: U64::new(65536),
        control_snapshot_bytes: U64::new(65536),
        protocol_snapshot_bytes: U64::new(1024 * 1024),
        frame_bank_bytes: U64::new(1024 * 1024),
        frames_per_direction: U64::new(64),
        hello_bytes: U64::new(1024 * 1024),
        settlement_bytes: U64::new(1024 * 1024),
    };
    storage.validate(&authority.limits()).unwrap();
    let mut connection = Connection::new(
        native,
        authority.clone(),
        supervisor,
        Rc::new(Uninstalled),
        EndpointRole::Provider,
    )
    .unwrap();
    let mut bank = Some(OriginalFrameReservation::reserve(history_bytes, direction_slots).unwrap());
    connection
        .install_native5_native_codec(&mut bank, policy.clone())
        .unwrap();
    let installed =
        PacketNative5CoordinatorInstallation::decode(coordinator.bytes.as_slice(), &selection)
            .unwrap();
    let (effects, _effect_peer) = UnixDatagram::pair().unwrap();
    let program = PacketProgram::new(
        vec![
            PacketEvent {
                id: id("private-callback-0"),
                evaluation: Position::new(U64::new(4), U64::new(0), Phase::Reaction),
                completion: Position::new(U64::new(4), U64::new(0), Phase::Reaction),
                payload: None,
            },
            PacketEvent {
                id: id("packet-callback-0"),
                evaluation: Position::new(U64::new(5), U64::new(0), Phase::Reaction),
                completion: Position::new(U64::new(5), U64::new(1), Phase::Publication),
                payload: Some(Bytes::new(b"original-producer".to_vec())),
            },
        ],
        effects,
    )
    .unwrap();
    let mut native = PacketControl::new_complete_producer(selection, program, installed).unwrap();
    native
        .bind_complete_original_storage(storage.clone(), authority.limits())
        .unwrap();
    (handshake, connection, native, policy, storage, hello, host)
}

#[test]
fn native5_original_complete_endpoint_refusal_recovers_same_literal_hello_and_tuple() {
    use crate::reference_packet::endpoint::PacketEndpoint;

    let (_handshake, mut connection, native, policy, storage, hello, _host) =
        retained_endpoint_fixture();
    let same_hello = hello.original_test_identity();
    let original_hello = serde_json::to_value(hello.protocol_view()).unwrap();
    let original_scope_storage = native
        .endpoint_scope()
        .unwrap()
        .realization
        .descriptors
        .as_ptr();
    let limits = connection.provider_authority().unwrap().limits();
    let mut wrong = storage.clone();
    wrong.protocol_snapshot_bytes = U64::new(storage.protocol_snapshot_bytes.get() + 1);
    wrong.validate(&limits).unwrap();

    let refusal = match PacketEndpoint::new_complete(
        connection,
        native,
        policy,
        Rc::new(BlobCustodian),
        wrong,
        hello,
    ) {
        Err(refusal) => refusal,
        Ok(_) => panic!("different compatible storage must refuse"),
    };
    assert!(matches!(refusal.error(), ProviderError::Correlation(_)));
    let original = (*refusal).into_original();
    assert!(same_hello(original.hello()));
    assert_eq!(
        serde_json::to_value(original.hello().protocol_view()).unwrap(),
        original_hello
    );
    assert_eq!(original.snapshot_allocations(), (None, None));

    let mut second_wrong = storage.clone();
    second_wrong.settlement_bytes = U64::new(storage.settlement_bytes.get() + 1);
    second_wrong.validate(&limits).unwrap();
    let refusal = match original.retry(second_wrong) {
        Err(refusal) => refusal,
        Ok(_) => panic!("recovered original cannot select different compatible storage"),
    };
    let original = (*refusal).into_original();
    assert!(same_hello(original.hello()));
    assert_eq!(
        serde_json::to_value(original.hello().protocol_view()).unwrap(),
        original_hello
    );
    assert_eq!(original.snapshot_allocations(), (None, None));

    let endpoint = match original.retry(storage) {
        Ok(endpoint) => endpoint,
        Err(refusal) => panic!("exact original storage must continue: {}", refusal.error()),
    };
    assert_eq!(
        endpoint
            .native()
            .endpoint_scope()
            .unwrap()
            .realization
            .descriptors
            .as_ptr(),
        original_scope_storage
    );
    assert!(!endpoint.is_held());
    assert!(endpoint.exchanges().is_empty());
}

#[test]
fn native5_original_late_hello_credit_refusal_retains_prepared_banks_and_same_hello() {
    use crate::reference_packet::endpoint::PacketEndpoint;

    let (_handshake, connection, native, policy, storage, hello, _host) =
        retained_endpoint_fixture_with_hello_limit(524288);
    assert!(hello.allocated_bytes() > storage.hello_bytes.get() as usize);
    let same_hello = hello.original_test_identity();
    let original_hello = serde_json::to_value(hello.protocol_view()).unwrap();
    let refusal = match PacketEndpoint::new_complete(
        connection,
        native,
        policy,
        Rc::new(BlobCustodian),
        storage.clone(),
        hello,
    ) {
        Err(refusal) => refusal,
        Ok(_) => panic!("original Hello exceeding selected actual credit must refuse"),
    };
    assert!(matches!(
        refusal.error(),
        ProviderError::ResourceExhausted(_)
    ));
    let original = (*refusal).into_original();
    let allocations = original.snapshot_allocations();
    assert!(allocations.0.is_some_and(|bytes| bytes > 1024 * 1024));
    assert_eq!(allocations.0, allocations.1);
    assert!(same_hello(original.hello()));
    assert_eq!(
        serde_json::to_value(original.hello().protocol_view()).unwrap(),
        original_hello
    );
    let refusal = match original.retry(storage) {
        Err(refusal) => refusal,
        Ok(_) => panic!("retry must not replace oversized original Hello"),
    };
    let original = (*refusal).into_original();
    assert!(same_hello(original.hello()));
    assert_eq!(original.snapshot_allocations(), allocations);
    assert_eq!(
        serde_json::to_value(original.hello().protocol_view()).unwrap(),
        original_hello
    );
}

struct RefuseSourceAfterBanks {
    panic_source: bool,
    payload_drops: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
    policy: Rc<crate::reference_packet::Native5Policy>,
    calls: Rc<std::cell::Cell<usize>>,
}

impl crate::blob::BlobSchemaVerifier for RefuseSourceAfterBanks {
    fn verify_schema(
        &self,
        schema: &ContentRef,
        content: &ContentRef,
        bytes: &[u8],
    ) -> Result<(), ProviderError> {
        crate::blob::BlobSchemaVerifier::verify_schema(&*self.policy, schema, content, bytes)
    }
}

impl crate::reference_packet::endpoint::PacketEndpointPolicy for RefuseSourceAfterBanks {
    fn authenticate_source(
        &self,
        _: &ConnectionAuthority,
        _: &PacketControlSelection,
    ) -> Result<(), ProviderError> {
        self.calls.set(self.calls.get() + 1);
        if self.panic_source {
            if let Some(drops) = &self.payload_drops {
                std::panic::panic_any(RetainedPanicPayload(drops.clone()));
            }
            panic!("intentional modeled endpoint policy unwind");
        }
        Err(ProviderError::Correlation(
            "modeled endpoint source refusal after reservation",
        ))
    }
    fn consuming_schema(
        &self,
        content: &ContentRef,
        original: &Envelope,
    ) -> Result<ContentRef, ProviderError> {
        crate::reference_packet::endpoint::PacketEndpointPolicy::consuming_schema(
            &*self.policy,
            content,
            original,
        )
    }
}

#[test]
fn native5_original_late_source_refusal_retains_banks_and_changed_retry_skips_callback() {
    use crate::reference_packet::endpoint::PacketEndpoint;

    let (_handshake, connection, native, policy, storage, hello, _host) =
        retained_endpoint_fixture();
    let same_hello = hello.original_test_identity();
    let original_hello = serde_json::to_value(hello.protocol_view()).unwrap();
    let calls = Rc::new(std::cell::Cell::new(0));
    let policy = Rc::new(RefuseSourceAfterBanks {
        panic_source: false,
        payload_drops: None,
        policy,
        calls: calls.clone(),
    });
    let refusal = match PacketEndpoint::new_complete(
        connection,
        native,
        policy,
        Rc::new(BlobCustodian),
        storage.clone(),
        hello,
    ) {
        Err(refusal) => refusal,
        Ok(_) => panic!("modeled source policy must refuse after banks are prepared"),
    };
    assert_eq!(calls.get(), 1);
    let original = (*refusal).into_original();
    let allocations = original.snapshot_allocations();
    assert!(allocations.0.is_some_and(|bytes| bytes > 1024 * 1024));
    assert_eq!(allocations.0, allocations.1);
    assert!(same_hello(original.hello()));
    let mut wrong = storage.clone();
    wrong.settlement_bytes = U64::new(storage.settlement_bytes.get() + 1);
    let refusal = match original.retry(wrong) {
        Err(refusal) => refusal,
        Ok(_) => panic!("wrong retry tuple must refuse before source callback"),
    };
    assert_eq!(calls.get(), 1);
    let original = (*refusal).into_original();
    assert_eq!(original.snapshot_allocations(), allocations);
    assert!(same_hello(original.hello()));
    let refusal = match original.retry(storage) {
        Err(refusal) => refusal,
        Ok(_) => panic!("retry must retain the same refusing source policy"),
    };
    assert_eq!(calls.get(), 2);
    let original = (*refusal).into_original();
    assert_eq!(original.snapshot_allocations(), allocations);
    assert!(same_hello(original.hello()));
    assert_eq!(
        serde_json::to_value(original.hello().protocol_view()).unwrap(),
        original_hello
    );
}

#[test]
fn native5_original_policy_unwind_keeps_owner_and_poisoned_retry_never_calls_again() {
    use crate::reference_packet::endpoint::PacketEndpoint;

    let (_handshake, connection, native, policy, storage, hello, _host) =
        retained_endpoint_fixture();
    let same_hello = hello.original_test_identity();
    let original_hello = serde_json::to_value(hello.protocol_view()).unwrap();
    let calls = Rc::new(std::cell::Cell::new(0));
    let policy = Rc::new(RefuseSourceAfterBanks {
        panic_source: true,
        payload_drops: None,
        policy,
        calls: calls.clone(),
    });
    let mut refusal = match PacketEndpoint::new_complete(
        connection,
        native,
        policy,
        Rc::new(BlobCustodian),
        storage.clone(),
        hello,
    ) {
        Err(refusal) => refusal,
        Ok(_) => panic!("policy unwind must return original poisoned custody"),
    };
    assert_eq!(calls.get(), 1);
    refusal.contain_original().unwrap();
    let original = (*refusal).into_original();
    let allocations = original.snapshot_allocations();
    assert!(allocations.0.is_some());
    assert!(same_hello(original.hello()));
    let refusal = match original.retry(storage) {
        Err(refusal) => refusal,
        Ok(_) => panic!("poisoned source must not retry native work"),
    };
    assert_eq!(calls.get(), 1);
    let original = (*refusal).into_original();
    assert_eq!(original.snapshot_allocations(), allocations);
    assert!(same_hello(original.hello()));
    assert_eq!(
        serde_json::to_value(original.hello().protocol_view()).unwrap(),
        original_hello
    );
}

struct PanicNativeSupervisor(Rc<std::cell::Cell<usize>>);
impl ConnectionSupervisor for PanicNativeSupervisor {
    fn quarantine(&self, _: ConnectionIncident) {
        self.0.set(self.0.get() + 1);
        panic!("intentional original quarantine supervisor unwind");
    }
}

#[test]
fn native5_original_authority_quarantine_unwind_keeps_hello_and_terminal_owner() {
    use crate::reference_packet::endpoint::PacketEndpoint;

    let calls = Rc::new(std::cell::Cell::new(0));
    let (mut handshake, connection, native, policy, storage, hello, _host) =
        retained_endpoint_fixture_with_supervisor(
            65536,
            Rc::new(PanicNativeSupervisor(calls.clone())),
        );
    let same_hello = hello.original_test_identity();
    let original_hello = serde_json::to_value(hello.protocol_view()).unwrap();
    handshake.contain();
    let mut refusal = match PacketEndpoint::new_complete(
        connection,
        native,
        policy,
        Rc::new(BlobCustodian),
        storage.clone(),
        hello,
    ) {
        Err(refusal) => refusal,
        Ok(_) => panic!("revoked registration supervisor unwind must retain the whole original"),
    };
    assert_eq!(calls.get(), 1);
    refusal.contain_original().unwrap();
    let original = (*refusal).into_original();
    assert_eq!(original.snapshot_allocations(), (None, None));
    assert!(same_hello(original.hello()));
    let refusal = match original.retry(storage) {
        Err(refusal) => refusal,
        Ok(_) => panic!("poisoned authority must not call supervisor again"),
    };
    assert_eq!(calls.get(), 1);
    let original = (*refusal).into_original();
    assert!(same_hello(original.hello()));
    assert_eq!(original.snapshot_allocations(), (None, None));
    assert_eq!(
        serde_json::to_value(original.hello().protocol_view()).unwrap(),
        original_hello
    );
}

struct RetainedPanicPayload(std::sync::Arc<std::sync::atomic::AtomicUsize>);
impl Drop for RetainedPanicPayload {
    fn drop(&mut self) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[test]
fn native5_original_unwind_payload_stays_owned_through_refusal_and_poisoned_retry() {
    use crate::reference_packet::endpoint::PacketEndpoint;
    use std::sync::atomic::Ordering;

    let (_handshake, connection, native, policy, storage, hello, _host) =
        retained_endpoint_fixture();
    let same_hello = hello.original_test_identity();
    let drops = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let calls = Rc::new(std::cell::Cell::new(0));
    let policy = Rc::new(RefuseSourceAfterBanks {
        panic_source: true,
        payload_drops: Some(drops.clone()),
        policy,
        calls: calls.clone(),
    });
    let mut refusal = match PacketEndpoint::new_complete(
        connection,
        native,
        policy,
        Rc::new(BlobCustodian),
        storage.clone(),
        hello,
    ) {
        Err(refusal) => refusal,
        Ok(_) => panic!("owned panic payload must return original custody"),
    };
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    refusal.contain_original().unwrap();
    let original = (*refusal).into_original();
    assert!(same_hello(original.hello()));
    let refusal = match original.retry(storage) {
        Err(refusal) => refusal,
        Ok(_) => panic!("poisoned retry must remain held"),
    };
    assert_eq!(calls.get(), 1);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    let original = (*refusal).into_original();
    assert!(same_hello(original.hello()));
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    // This explicit end of a closed-gate component fixture is not native
    // reclamation or journal release evidence. It verifies destructor timing.
    drop(original);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn native5_original_complete_endpoint_refuses_different_actual_bank_before_snapshot_reservation() {
    use crate::reference_packet::endpoint::PacketEndpoint;

    for (history, slots) in [(2 * 1024 * 1024, 64), (1024 * 1024, 128)] {
        let (_handshake, connection, native, policy, storage, hello, _host) =
            retained_endpoint_fixture_with_bank(65536, Rc::new(Supervisor), history, slots);
        let same_hello = hello.original_test_identity();
        let original_hello = serde_json::to_value(hello.protocol_view()).unwrap();
        let refusal = match PacketEndpoint::new_complete(
            connection,
            native,
            policy,
            Rc::new(BlobCustodian),
            storage.clone(),
            hello,
        ) {
            Err(refusal) => refusal,
            Ok(_) => panic!("actual allocated geometry must match original native storage"),
        };
        assert!(matches!(
            refusal.error(),
            ProviderError::Correlation("native5 original bank differs from selected birth storage")
        ));
        let original = (*refusal).into_original();
        assert!(same_hello(original.hello()));
        assert_eq!(original.snapshot_allocations(), (None, None));
        let refusal = match original.retry(storage) {
            Err(refusal) => refusal,
            Ok(_) => panic!("same incompatible actual bank must not become a replacement"),
        };
        let original = (*refusal).into_original();
        assert_eq!(original.snapshot_allocations(), (None, None));
        assert!(same_hello(original.hello()));
        assert_eq!(
            serde_json::to_value(original.hello().protocol_view()).unwrap(),
            original_hello
        );
    }
}

#[test]
fn native5_original_immutable_bank_facts_read_same_retained_connection() {
    let (mut handshake, connection, _native, _policy, storage, hello, _peer) =
        retained_endpoint_fixture();
    let original_hello = hello.original_test_identity();
    let borrowed = &connection;
    let facts = borrowed.original_native5_storage_facts().unwrap();
    assert_eq!(
        facts.maximum_history_bytes,
        storage.frame_bank_bytes.get() as usize
    );
    assert_eq!(facts.byte_capacity, storage.frame_bank_bytes.get() as usize);
    assert_eq!(
        facts.maximum_frames_per_direction,
        storage.frames_per_direction.get() as usize
    );
    assert_eq!(
        facts.descriptor_capacity,
        2 * storage.frames_per_direction.get() as usize
    );
    assert_eq!(facts.maximum_frame_bytes, 65_536);
    assert!(facts.all_io_complete);
    assert_eq!(borrowed.original_native5_storage_facts().unwrap(), facts);
    assert!(original_hello(&hello));

    handshake.contain();
    assert!(borrowed.original_native5_storage_facts().is_err());
    assert!(original_hello(&hello));
}

#[test]
fn native_control_admit_handoff_requires_actual_installed_token() {
    let (_handshake, connection, _control, _policy, _storage, _hello, _host) =
        retained_endpoint_fixture();
    let mut original = crate::envelope::tests::request();
    original.method = Method::Admit;
    assert!(
        connection
            .retain_original_canonical_ack_control_admit(&original)
            .is_err()
    );
    assert!(
        connection
            .original_canonical_blob_ack_framed_bytes()
            .is_err()
    );
}
