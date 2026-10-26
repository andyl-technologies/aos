//! Checks original SDK custody as mapping DATA under a modeled Hello exchange.
//!
//! These private fixtures retain a real registrar and immutable source codec.
//! Their unverified archive commitments grant no native installation, Core
//! ticket, private Source or completed-restoration authority.

use super::*;
use crate::retained_metadata::{
    RetainedCaptureProtocolData,
    records::{MetadataCapacityRecord, MetadataRecordBank, MetadataRecordKind},
};

#[derive(Default)]
struct NoOperations {
    incidents: std::cell::RefCell<Vec<crate::connection::ConnectionIncident>>,
}

impl crate::connection::ConnectionSupervisor for NoOperations {
    fn quarantine(&self, incident: crate::connection::ConnectionIncident) {
        // Connection teardown contains its unused stream after these controls.
        self.incidents.borrow_mut().push(incident);
    }
}

impl crate::connection::BodySchemaVerifier for NoOperations {
    fn verify(
        &self,
        _: &ConnectionAuthority,
        _: &crate::envelope::Envelope,
        _: &crate::connection::ReceivedBody,
    ) -> Result<(), ProviderError> {
        Err(ProviderError::Correlation(
            "capacity fixture forbids protocol operations",
        ))
    }
}

struct MappingFixture {
    handshake: crate::handshake::Handshake,
    mapping: PreparedArchivedProtocolMapping,
    _connection: crate::connection::Connection<std::os::unix::net::UnixStream>,
    peer: std::os::unix::net::UnixStream,
    supervisor: Rc<NoOperations>,
}

impl MappingFixture {
    fn assert_quiet(&mut self) {
        use std::io::Read;
        assert!(self.supervisor.incidents.borrow().is_empty());
        self.peer.set_nonblocking(true).unwrap();
        let mut byte = [0];
        assert!(
            matches!(self.peer.read(&mut byte), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
        self.peer.set_nonblocking(false).unwrap();
    }
}

fn mapping(class: RestorationMappingClass) -> MappingFixture {
    let (handshake, fresh, selection, coordinator) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    let (stream, peer) = std::os::unix::net::UnixStream::pair().unwrap();
    let supervisor = Rc::new(NoOperations::default());
    let mut connection = crate::connection::Connection::new(
        stream,
        fresh.clone(),
        supervisor.clone(),
        supervisor.clone(),
        crate::connection::EndpointRole::Controller,
    )
    .unwrap();
    let mut frames = Some(
        crate::transport::original_frames::OriginalFrameReservation::reserve(262144, 64).unwrap(),
    );
    connection
        .install_native5_controller_ack_emitter_codec_with_metadata_extent(
            &mut frames,
            selection,
            coordinator,
            crate::reference_packet::service::PacketNative5CaptureProfile::OriginalArrays6,
            crate::connection::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB,
        )
        .unwrap();
    let codec = connection.retained_native5_codec_owner().unwrap().clone();
    let owner = Rc::new(ProtocolCaptureOwner::new());
    let archive_protocol = crucible_node_format::canonical::content_ref(
        b"unverified archive DATA",
        "application/json",
    )
    .unwrap();
    let native_protocol =
        crucible_node_format::canonical::content_ref(b"unverified native DATA", "application/json")
            .unwrap();
    let cut =
        crate::operational_time::OperationalDeadline::after(std::time::Duration::from_secs(2))
            .unwrap();
    MappingFixture {
        handshake,
        mapping: PreparedArchivedProtocolMapping {
            identity: Rc::new(ArchivedProtocolMappingIdentity),
            class,
            archive_protocol,
            native_protocol,
            nonce: [7; 32],
            fresh,
            controller_owner: owner.clone(),
            connection_owner: owner,
            codec,
            cut,
        },
        _connection: connection,
        peer,
        supervisor,
    }
}

fn prefix() -> MetadataCapacityRecord {
    MetadataCapacityRecord {
        kind: MetadataRecordKind::String,
        extent: 263,
        element_bytes: 1,
        alignment: 1,
    }
}

#[test]
fn archived_mapping_capacity_keeps_all_classes_with_revoked_and_gate_held_custody() {
    for class in [
        RestorationMappingClass::Legacy11,
        RestorationMappingClass::StartupCapture14,
        RestorationMappingClass::InvocationCapture15,
    ] {
        let mut fixture = mapping(class);
        let mapping = &fixture.mapping;
        let expected = mapping.original_retained_metadata_facts().unwrap();
        let component = RetainedCaptureProtocolData::ArchivedMapping(mapping);
        assert_eq!(component.observe_retained_metadata().unwrap(), expected);
        assert!(expected.shared_backing_views >= 6);
        let views = (
            Rc::strong_count(&mapping.identity),
            Rc::strong_count(&mapping.controller_owner),
            Rc::strong_count(&mapping.codec),
        );

        mapping
            .fresh
            .with_live(|| {
                assert_eq!(component.observe_retained_metadata()?, expected);
                Ok(())
            })
            .unwrap();
        fixture.handshake.contain();

        assert!(mapping.original_retained_metadata_facts().is_err());
        assert!(mapping.fresh.ensure_live().is_err());
        assert_eq!(component.observe_retained_metadata().unwrap(), expected);
        assert_eq!(
            views,
            (
                Rc::strong_count(&mapping.identity),
                Rc::strong_count(&mapping.controller_owner),
                Rc::strong_count(&mapping.codec)
            )
        );
        assert!(PreparedArchivedProtocolMapping::capacity_counter_scratch_data() > 0);
        fixture.assert_quiet();
    }
}

#[test]
fn archived_mapping_capacity_appends_repeated_views_and_preserves_short_prefixes() {
    let mut fixture = mapping(RestorationMappingClass::Legacy11);
    let mapping = &fixture.mapping;
    let expected = RetainedCaptureProtocolData::ArchivedMapping(mapping)
        .observe_retained_metadata()
        .unwrap();
    let mut bank = MetadataRecordBank::reserve(1 + 2 * expected.capacity_records).unwrap();
    bank.append(prefix()).unwrap();
    let backing = bank.allocated_bytes();
    for _ in 0..2 {
        let mut observer = MetadataObserver::appending(&mut bank);
        mapping.observe_capacity_data(&mut observer).unwrap();
        assert_eq!(observer.finish(), expected);
    }
    assert_eq!(bank.rows()[0], prefix());
    assert_eq!(
        &bank.rows()[1..1 + expected.capacity_records],
        &bank.rows()[1 + expected.capacity_records..]
    );
    assert_eq!(bank.allocated_bytes(), backing);

    let mut short = MetadataRecordBank::reserve(2).unwrap();
    short.append(prefix()).unwrap();
    let mut observer = MetadataObserver::appending(&mut short);
    assert!(mapping.observe_capacity_data(&mut observer).is_err());
    let _partial = observer.finish();
    assert_eq!(short.rows()[0], prefix());
    assert_eq!(short.rows().len(), 2);
    assert_eq!(short.rows()[1].kind, MetadataRecordKind::Shared);
    assert_eq!(
        short.rows()[1].extent,
        size_of::<ArchivedProtocolMappingIdentity>()
    );
    assert!(mapping.fresh.ensure_live().is_ok());
    fixture.assert_quiet();
}

#[test]
fn archived_mapping_capacity_foreign_either_creator_refuses_before_any_row() {
    for controller in [true, false] {
        let mut fixture = mapping(RestorationMappingClass::Legacy11);
        let mapping = &mut fixture.mapping;
        let foreign = Rc::new(ProtocolCaptureOwner {
            pid: std::process::id().wrapping_add(1),
            thread: std::thread::current().id(),
        });
        if controller {
            mapping.controller_owner = foreign;
        } else {
            mapping.connection_owner = foreign;
        }
        assert!(
            RetainedCaptureProtocolData::ArchivedMapping(mapping)
                .check_original_creator()
                .is_err()
        );
        let mut records = MetadataRecordBank::reserve(4).unwrap();
        records.append(prefix()).unwrap();
        let mut observer = MetadataObserver::appending(&mut records);

        assert!(mapping.observe_capacity_data(&mut observer).is_err());

        assert_eq!(observer.finish().capacity_records, 0);
        assert_eq!(records.rows(), &[prefix()]);
        fixture.assert_quiet();
    }
}
