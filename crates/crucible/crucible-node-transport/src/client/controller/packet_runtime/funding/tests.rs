//! Checks the full future row against actual original owners and socket history.
//!
//! Fixture registration and numeric rows grant no Source action or native effect.

use super::*;
use crate::{
    bodies::*,
    client::{ClientContent, ClientCustody, ControllerRoute},
    connection::{BodySchemaVerifier, ReceivedBody},
    envelope::{Envelope, MessageKind, Method, Nullable, RequestOrigin},
    handshake::{ConnectionAuthority, Handshake},
    transport::{FrameReader, write_frame},
};
use crucible_node_format::{Bytes, ContentRef, Id, U64};
use serde_json::Value;
use std::{cell::Cell, io::Read, os::unix::net::UnixStream, rc::Rc, time::Duration};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Fixture {
    handshake: Handshake,
    original: Option<CnpController>,
    owner: OriginalRetainedSupervisor,
    witness: OriginalProtocolSupervisor,
    peer: UnixStream,
    content: ContentRef,
}

fn fixture(requests: usize, bytes: usize, objects: usize) -> Fixture {
    let (handshake, session, owner, witness, peer) = ClientSession::restoration_retained_fixture();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    peer.set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut content = ClientContent::new(bytes, objects, 4096).unwrap();
    let reference =
        crucible_node_format::canonical::content_ref(b"original", "application/octet-stream")
            .unwrap();
    content
        .install(reference.clone(), b"original".to_vec())
        .unwrap();
    let original = CnpController::new(
        session,
        ClientCustody::new(requests, content).unwrap(),
        ControllerRoute {
            node: id("node"),
            execution_owner: id("owner"),
        },
        Duration::from_secs(2),
    )
    .unwrap();
    Fixture {
        handshake,
        original: Some(original),
        owner,
        witness,
        peer,
        content: reference,
    }
}

fn id(text: &str) -> Id {
    Id::new(text).unwrap()
}

fn quote(fixture: &Fixture) -> Result<PacketRuntimeFutureStorageData, ProviderError> {
    fixture
        .original
        .as_ref()
        .unwrap()
        .original_packet_runtime_future_storage_data(
            &fixture.owner,
            Some(&fixture.witness),
            &RetainedProtocolMetadataFacts::default(),
            usize::MAX,
        )
}

fn history(controller: &CnpController) -> Vec<u8> {
    serde_json::to_vec(&controller.custody.originals().collect::<Vec<_>>()).unwrap()
}

#[test]
fn exact_full_row_and_one_byte_short_preserve_original_credit_and_content() -> TestResult {
    let mut fixture = fixture(8, 262_144, 8);
    let controller = fixture.original.as_ref().unwrap();
    let before = history(controller);
    let debit = controller.custody.runtime_journal_bytes_data();
    let content = controller.content(&fixture.content)?.as_ptr();
    let row = quote(&fixture)?;
    let total = row.total_requested_bytes_data()?;

    assert!(row.retained_requested_bytes_data() > 0);
    assert!(row.maximum_simultaneous_transient_bytes_data() > 0);
    assert_eq!(
        row.counter_scratch_bytes_data(),
        controller.original_packet_runtime_future_counter_scratch_data()
    );
    assert!(row.metadata_capacity_rows_data() > 131_072);
    assert_eq!(
        controller.original_packet_runtime_future_storage_data(
            &fixture.owner,
            Some(&fixture.witness),
            &Default::default(),
            total
        )?,
        row
    );
    assert!(
        controller
            .original_packet_runtime_future_storage_data(
                &fixture.owner,
                Some(&fixture.witness),
                &Default::default(),
                total - 1
            )
            .is_err()
    );

    assert_eq!(history(controller), before);
    assert_eq!(controller.custody.runtime_journal_bytes_data(), debit);
    assert_eq!(controller.content(&fixture.content)?.as_ptr(), content);
    assert!(!controller.fenced);
    assert!(fixture.owner.is_empty_data()?);
    fixture.peer.set_nonblocking(true)?;
    assert_eq!(
        fixture.peer.read(&mut [0]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );

    let mut output = None;
    PacketRuntimeController::retain_into(&mut fixture.original, &mut output)?;
    let runtime = output.as_ref().unwrap();
    assert!(fixture.original.is_none());
    assert_eq!(
        runtime.journal_byte_reservations_data(),
        [debit[0], debit[1], 0]
    );
    assert_eq!(runtime.content(&fixture.content)?.as_ptr(), content);
    runtime
        .retained_metadata_facts_with_retained_supervisor(&fixture.owner, Some(&fixture.witness))?;
    Ok(())
}

#[test]
fn widest_source_layout_and_complete_record_bank_have_independent_funding() -> TestResult {
    let fixture = fixture(8, 262_144, 8);
    let controller = fixture.original.as_ref().unwrap();
    let empty = quote(&fixture)?;
    let source = RetainedProtocolMetadataFacts {
        tree_containers: 3,
        tree_entries: 7,
        maximum_tree_key_value_bytes: 8192,
        maximum_tree_entry_alignment: 64,
        capacity_records: 11,
        ..Default::default()
    };

    let wider = controller.original_packet_runtime_future_storage_data(
        &fixture.owner,
        Some(&fixture.witness),
        &source,
        usize::MAX,
    )?;

    assert!(wider.retained_requested_bytes_data() > empty.retained_requested_bytes_data());
    assert_eq!(
        wider.metadata_capacity_rows_data(),
        empty.metadata_capacity_rows_data() + 11
    );
    assert_eq!(
        wider.maximum_simultaneous_transient_bytes_data(),
        empty.maximum_simultaneous_transient_bytes_data()
    );
    assert_eq!(
        wider.counter_scratch_bytes_data(),
        empty.counter_scratch_bytes_data()
    );
    for invalid in [
        RetainedProtocolMetadataFacts {
            maximum_tree_entry_alignment: 3,
            ..source
        },
        RetainedProtocolMetadataFacts {
            tree_entries: usize::MAX,
            ..source
        },
        RetainedProtocolMetadataFacts {
            capacity_records: usize::MAX,
            ..source
        },
    ] {
        assert!(
            controller
                .original_packet_runtime_future_storage_data(
                    &fixture.owner,
                    Some(&fixture.witness),
                    &invalid,
                    usize::MAX
                )
                .is_err()
        );
    }
    assert!(fixture.owner.is_empty_data()?);
    assert!(!controller.fenced);
    Ok(())
}

#[test]
fn actual_request_content_and_object_caps_change_the_defining_axes() -> TestResult {
    let base = fixture(8, 262_144, 8);
    let requests = fixture(9, 262_144, 8);
    let bytes = fixture(8, 262_145, 8);
    let objects = fixture(8, 262_144, 9);
    let base = quote(&base)?;
    let requests = quote(&requests)?;
    let bytes = quote(&bytes)?;
    let objects = quote(&objects)?;

    assert!(requests.retained_requested_bytes_data() > base.retained_requested_bytes_data());
    assert_eq!(
        requests.maximum_simultaneous_transient_bytes_data(),
        base.maximum_simultaneous_transient_bytes_data()
    );
    assert!(requests.metadata_capacity_rows_data() > base.metadata_capacity_rows_data());
    assert!(bytes.retained_requested_bytes_data() > base.retained_requested_bytes_data());
    assert!(
        bytes.maximum_simultaneous_transient_bytes_data()
            > base.maximum_simultaneous_transient_bytes_data()
    );
    assert_eq!(
        bytes.metadata_capacity_rows_data(),
        base.metadata_capacity_rows_data()
    );
    assert!(objects.retained_requested_bytes_data() > base.retained_requested_bytes_data());
    assert!(
        objects.maximum_simultaneous_transient_bytes_data()
            > base.maximum_simultaneous_transient_bytes_data()
    );
    assert!(objects.metadata_capacity_rows_data() > base.metadata_capacity_rows_data());
    Ok(())
}

#[test]
fn revoked_and_foreign_owners_cannot_invoke_containment_or_change_the_original() -> TestResult {
    let mut fixture = fixture(8, 262_144, 8);
    let foreign = super::tests::fixture(8, 262_144, 8);
    let controller = fixture.original.as_ref().unwrap();
    let before = history(controller);
    let debit = controller.custody.runtime_journal_bytes_data();
    quote(&fixture)?;

    assert!(
        controller
            .original_packet_runtime_future_storage_data(
                &foreign.owner,
                Some(&fixture.witness),
                &Default::default(),
                usize::MAX
            )
            .is_err()
    );
    assert!(
        controller
            .original_packet_runtime_future_storage_data(
                &fixture.owner,
                Some(&foreign.witness),
                &Default::default(),
                usize::MAX
            )
            .is_err()
    );
    fixture.handshake.contain();
    assert!(quote(&fixture).is_err());

    let controller = fixture.original.as_ref().unwrap();
    assert_eq!(history(controller), before);
    assert_eq!(controller.custody.runtime_journal_bytes_data(), debit);
    assert!(!controller.fenced);
    assert!(fixture.owner.is_empty_data()?);
    assert!(foreign.owner.is_empty_data()?);
    Ok(())
}

#[test]
fn frame_construction_population_is_independent_of_journal_credit() -> TestResult {
    let smaller = operation::storage_data(4096)?;
    let larger = operation::storage_data(65_536)?;

    assert!(larger[0] > smaller[0]);
    assert!(larger[1] > smaller[1]);
    assert!(operation::storage_data(0).is_err());
    assert!(operation::storage_data(65_537).is_err());
    Ok(())
}

#[test]
fn actual_provider_replay_is_added_without_spending_remaining_suffix_credit() -> TestResult {
    let mut fixture = fixture(8, 262_144, 8);
    let before = quote(&fixture)?;
    let mut peer = fixture.peer.try_clone()?;
    let reference = fixture.content.clone();
    let server = std::thread::spawn(move || {
        let mut reader = FrameReader::new(peer.try_clone().unwrap(), 65_536).unwrap();
        let request: Envelope = serde_json::from_value(reader.read().unwrap().unwrap()).unwrap();
        for index in 0..3 {
            let mut incoming = request.clone();
            incoming.sequence = U64::new(index + 2);
            incoming.request_id = Nullable(Some(id([
                "provider-begin",
                "provider-chunk",
                "provider-finish",
            ][index as usize])));
            incoming.method =
                [Method::BlobBegin, Method::BlobChunk, Method::BlobFinish][index as usize];
            incoming.body = object(match index {
                0 => serde_json::to_value(BlobBeginRequest {
                    transfer_id: id("transfer"),
                    content: reference.clone(),
                    extensions: Default::default(),
                })
                .unwrap(),
                1 => serde_json::to_value(BlobChunkRequest {
                    transfer_id: id("transfer"),
                    offset: U64::new(0),
                    bytes: Bytes::new(b"original".to_vec()),
                    extensions: Default::default(),
                })
                .unwrap(),
                _ => serde_json::to_value(BlobFinishRequest {
                    transfer_id: id("transfer"),
                    extensions: Default::default(),
                })
                .unwrap(),
            });
            write_frame(&mut peer, &serde_json::to_value(&incoming).unwrap(), 65_536).unwrap();
            let ack: Envelope = serde_json::from_value(reader.read().unwrap().unwrap()).unwrap();
            incoming.matches_response(&ack).unwrap();
        }
        let mut response = request;
        response.message = MessageKind::Response;
        response.sequence = U64::new(5);
        response.body = object(
            serde_json::to_value(ResponseShape::Error {
                operation_state: OperationState::NotStarted,
                error: ErrorRecord {
                    code: "UNSUPPORTED_FEATURE".into(),
                    message: "modeled refusal".into(),
                    effect: EffectCertainty::NotStarted,
                    retryable: false,
                    details: Default::default(),
                },
                extensions: Default::default(),
            })
            .unwrap(),
        );
        write_frame(&mut peer, &serde_json::to_value(&response).unwrap(), 65_536).unwrap();
    });
    fixture.original.as_mut().unwrap().call(
        id("legacy"),
        None,
        Method::Discover,
        false,
        DiscoverRequest {
            profile_ids: vec![id("cnp.reference-packet/1")],
            cursor: None,
            extensions: Default::default(),
        },
    )?;
    server.join().unwrap();
    let controller = fixture.original.as_ref().unwrap();
    let history = history(controller);
    let debit = controller.custody.runtime_journal_bytes_data();
    let clone = controller.original_packet_runtime_provider_replay_storage_data(usize::MAX)?[1];

    let after = quote(&fixture)?;

    assert!(clone > 0);
    assert_eq!(
        after.maximum_simultaneous_transient_bytes_data(),
        before.maximum_simultaneous_transient_bytes_data() + clone
    );
    assert_eq!(
        controller
            .custody
            .originals_by_origin(RequestOrigin::Provider)
            .count(),
        3
    );
    assert!(debit[1] > 0);
    assert_eq!(controller.custody.runtime_journal_bytes_data(), debit);
    assert_eq!(self::history(controller), history);
    assert!(fixture.owner.is_empty_data()?);
    Ok(())
}

fn object(value: Value) -> serde_json::Map<String, Value> {
    let Value::Object(object) = value else {
        panic!("test object")
    };
    object
}

#[test]
fn full_row_covers_actual_retained_fault_under_a_wider_enclosing_source() -> TestResult {
    use crate::retained_metadata::requested_metadata_backing_storage_data;

    let mut fixture = fixture(8, 262_144, 8);
    let source = RetainedProtocolMetadataFacts {
        tree_containers: 3,
        tree_entries: 7,
        maximum_tree_key_value_bytes: 8192,
        maximum_tree_entry_alignment: 64,
        capacity_records: 11,
        ..Default::default()
    };
    let controller = fixture.original.as_ref().unwrap();
    let current = controller.original_restoration_host_metadata_facts_with_retained_supervisor(
        &fixture.owner,
        Some(&fixture.witness),
    )?;
    let row = controller.original_packet_runtime_future_storage_data(
        &fixture.owner,
        Some(&fixture.witness),
        &source,
        usize::MAX,
    )?;
    let mut records =
        crate::retained_metadata::records::PacketRuntimeMetadataRecordBank::unallocated(&row)?;
    assert_eq!(
        crate::retained_metadata::records::PacketRuntimeMetadataRecordBank::reservation_requested_bytes_data(&row)?,
        row.metadata_capacity_rows_data() * std::mem::size_of::<MetadataCapacityRecord>()
    );
    records.reserve_retained_data()?;
    let mut peer = fixture.peer.try_clone()?;
    let server = std::thread::spawn(move || {
        let mut reader = FrameReader::new(peer.try_clone().unwrap(), 65_536).unwrap();
        let mut event: Envelope = serde_json::from_value(reader.read().unwrap().unwrap()).unwrap();
        event.message = MessageKind::Event;
        event.method = Method::ProviderFault;
        event.request_id = Nullable(None);
        event.sequence = U64::new(2);
        event.body = object(
            serde_json::to_value(NotificationBody {
                operation_state: OperationState::NotStarted,
                last_observation_sequence: U64::new(0),
                details: object(serde_json::json!({"maps": vec![serde_json::json!({}); 20_000]})),
                extensions: Default::default(),
            })
            .unwrap(),
        );
        write_frame(&mut peer, &serde_json::to_value(&event).unwrap(), 65_536).unwrap();
        event
    });
    let mut output = None;
    PacketRuntimeController::retain_into(&mut fixture.original, &mut output)?;
    let runtime = output.as_mut().unwrap();
    let request = BlobFinishRequest {
        transfer_id: id("unfinished"),
        extensions: Default::default(),
    };

    assert!(
        runtime
            .call(
                id("runtime"),
                None,
                None,
                PacketRuntimeRequest::BlobFinish(&request),
                &Default::default()
            )
            .is_err()
    );
    let event = server.join().unwrap();
    fixture.handshake.contain();
    let mut after = runtime
        .retained_metadata_facts_with_retained_supervisor(&fixture.owner, Some(&fixture.witness))?;

    let recorded = runtime.retained_metadata_records_with_retained_supervisor(
        &fixture.owner,
        Some(&fixture.witness),
        &mut records,
    )?;
    assert_eq!(recorded, after);
    assert_eq!(records.rows().len(), after.capacity_records);
    let encoded = serde_json::to_vec(&records)?;
    let decoded =
        crate::retained_metadata::records::ValidatedPacketRuntimeMetadataRecords::validate(
            &encoded,
            row.metadata_capacity_rows_data(),
            records.allocated_bytes(),
            after.string_capacity_bytes + after.vector_capacity_bytes,
        )?;
    assert_eq!(
        decoded.rows().collect::<Result<Vec<_>, _>>()?,
        records.rows()
    );
    assert_eq!(
        decoded.observed_backing_capacity_bytes_data(),
        after.string_capacity_bytes + after.vector_capacity_bytes
    );

    assert_eq!(runtime.unexpected_frame().unwrap().envelope, event);
    assert!(after.tree_containers > current.tree_containers + 40_000);
    assert!(after.capacity_records + source.capacity_records <= row.metadata_capacity_rows_data());
    after.tree_containers += source.tree_containers;
    after.tree_entries += source.tree_entries;
    after.maximum_tree_key_value_bytes = after
        .maximum_tree_key_value_bytes
        .max(source.maximum_tree_key_value_bytes);
    after.maximum_tree_entry_alignment = after
        .maximum_tree_entry_alignment
        .max(source.maximum_tree_entry_alignment);
    let actual_report = requested_metadata_backing_storage_data(&after)?;
    let original_report = requested_metadata_backing_storage_data(&current)?;

    assert!(actual_report > original_report + 1024 * 1024 * 1024);
    assert!(actual_report <= original_report + row.retained_requested_bytes_data());
    assert!(runtime.authority().ensure_live().is_err());
    Ok(())
}

#[test]
fn erased_schema_callback_cannot_supply_an_installed_codec_funding_row() -> TestResult {
    struct Callback(Rc<Cell<usize>>);

    impl BodySchemaVerifier for Callback {
        fn verify(
            &self,
            _: &ConnectionAuthority,
            _: &Envelope,
            _: &ReceivedBody,
        ) -> Result<(), ProviderError> {
            self.0.set(self.0.get() + 1);
            Ok(())
        }
    }

    let (_handshake, authority) = crate::handshake::tests::controller_authority(true)?;
    let (operational, owner) = OriginalRetainedSupervisor::reserve()?;
    let calls = Rc::new(Cell::new(0));
    let (session, _peer) = ClientSession::controller_fixture(
        authority,
        operational,
        Rc::new(Callback(calls.clone())),
    )?;
    let controller = CnpController::new(
        session,
        ClientCustody::new(8, ClientContent::new(262_144, 8, 4096)?)?,
        ControllerRoute {
            node: id("node"),
            execution_owner: id("owner"),
        },
        Duration::from_secs(2),
    )?;

    assert!(
        controller
            .original_packet_runtime_future_storage_data(
                &owner,
                None,
                &Default::default(),
                usize::MAX
            )
            .is_err()
    );
    assert_eq!(calls.get(), 0);
    assert!(owner.is_empty_data()?);
    assert!(!controller.fenced);
    Ok(())
}

#[test]
fn physical_recording_checks_original_supervisors_before_clearing_history() -> TestResult {
    use crate::retained_metadata::records::PacketRuntimeMetadataRecordBank;

    let mut fixture = fixture(8, 262_144, 8);
    let row = quote(&fixture)?;
    let mut records = PacketRuntimeMetadataRecordBank::unallocated(&row)?;
    let mut output = None;
    PacketRuntimeController::retain_into(&mut fixture.original, &mut output)?;
    let runtime = output.as_ref().unwrap();
    assert!(
        runtime
            .retained_metadata_records_with_retained_supervisor(
                &fixture.owner,
                Some(&fixture.witness),
                &mut records,
            )
            .is_err()
    );
    assert_eq!(records.capacity_rows(), 0);

    records.reserve_retained_data()?;
    let facts = runtime.retained_metadata_records_with_retained_supervisor(
        &fixture.owner,
        Some(&fixture.witness),
        &mut records,
    )?;
    assert_eq!(facts.capacity_records, records.rows().len());
    assert!(!records.rows().is_empty());
    let before = serde_json::to_vec(&records)?;
    let (_handshake, _session, foreign_owner, foreign_witness, _peer) =
        ClientSession::restoration_retained_fixture();

    assert!(
        runtime
            .retained_metadata_records_with_retained_supervisor(
                &foreign_owner,
                Some(&fixture.witness),
                &mut records,
            )
            .is_err()
    );
    assert_eq!(serde_json::to_vec(&records)?, before);
    assert!(
        runtime
            .retained_metadata_records_with_retained_supervisor(
                &fixture.owner,
                Some(&foreign_witness),
                &mut records,
            )
            .is_err()
    );
    assert_eq!(serde_json::to_vec(&records)?, before);
    assert_eq!(
        runtime.retained_metadata_records_with_retained_supervisor(
            &fixture.owner,
            Some(&fixture.witness),
            &mut records,
        )?,
        facts
    );
    assert_eq!(serde_json::to_vec(&records)?, before);
    Ok(())
}

mod registrar;
