//! Checks the actual enclosing allocations without inferring nested ownership.

use super::super::super::tests::{
    coordinator, installation, producer, reactive, storage_selection,
};
use super::*;
use std::{
    os::unix::net::UnixDatagram,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

fn source(member: usize) -> PacketCompleteSemanticSource {
    let coordinator = coordinator();
    let installation = installation(&coordinator, member);
    if member == 0 {
        PacketCompleteSemanticSource::new_producer_for_collecting_world(
            installation,
            producer(),
            coordinator,
            storage_selection(),
        )
        .unwrap()
    } else {
        let definition = reactive(&coordinator, member);
        PacketCompleteSemanticSource::new_reactive_for_collecting_world(
            installation,
            definition,
            coordinator,
            storage_selection(),
        )
        .unwrap()
    }
}

fn original_holder_cost(source: &Rc<PacketCompleteSemanticSource>) -> usize {
    let nested = source
        .original_complete_nested_holder_storage_data_with_error::<RuntimeError>(usize::MAX)
        .unwrap();
    let header = NodeRuntime::capture_protocol_shared_header_storage(
        1,
        align_of::<PacketCompleteSemanticSource>(),
        usize::MAX,
    )
    .unwrap();
    size_of::<PacketCompleteSemanticSource>() + header + nested
}

#[test]
fn all_three_actual_holders_match_independent_original_byte_accounting() {
    for member in 0..3 {
        let source = Rc::new(source(member));
        let facts = source.original_complete_holder_capacity_data(None).unwrap();
        let total = original_holder_cost(&source);
        let underlying = match &source.original {
            CompletePacketOriginal::Producer(value) => size_of_val(value.as_ref()),
            CompletePacketOriginal::Reactive(value) => size_of_val(value.as_ref()),
        };

        assert_eq!(facts.capacity_records, 2);
        assert_eq!(facts.shared_backing_views, 1);
        assert_eq!(
            facts.shared_value_bytes,
            size_of::<PacketCompleteSemanticSource>()
        );
        assert_eq!(
            facts.maximum_shared_value_alignment,
            align_of::<PacketCompleteSemanticSource>()
        );
        assert_eq!(facts.boxed_value_bytes, underlying);
        assert_eq!(facts.vector_banks, 0);
        assert_eq!(facts.tree_containers, 0);
        assert_eq!(facts.observed_nodes, 0);
        assert_eq!(
            source.original_complete_holder_storage_data_with_error::<RuntimeError>(total),
            Ok(total)
        );
        assert_eq!(
            source.original_complete_holder_storage_data_with_error::<RuntimeError>(total - 1),
            Err(RuntimeError::ResourceLimit)
        );
        assert!(source.ack_peer_birth.borrow().is_none());
        assert!(source.capture_banks.borrow().is_none());
    }
}

#[test]
fn repeated_actual_rc_views_receive_no_alias_discount_or_new_ownership() {
    let source = Rc::new(source(0));
    let before = source.original_complete_holder_capacity_data(None).unwrap();
    let alias = Rc::clone(&source);
    let after = alias.original_complete_holder_capacity_data(None).unwrap();

    assert_eq!(before, after);
    assert_eq!(after.shared_backing_views, 1);
    assert_eq!(Rc::strong_count(&source), 2);
    assert_eq!(original_holder_cost(&source), original_holder_cost(&alias));
}

#[test]
fn foreign_source_refuses_before_holder_metadata_is_observed() {
    let mut source = Rc::new(source(0));
    let before = source.original_complete_holder_capacity_data(None).unwrap();
    let process = source.process;
    Rc::get_mut(&mut source).unwrap().process = process.wrapping_add(1);

    assert_eq!(
        source.original_complete_holder_capacity_data(None),
        Err(RuntimeError::ForeignAuthority)
    );
    Rc::get_mut(&mut source).unwrap().process = process;
    assert_eq!(
        source.original_complete_holder_capacity_data(None).unwrap(),
        before
    );
}

struct ReceiverFixture {
    _directory: ReceiverDirectory,
    paths: [PathBuf; 3],
    group: Rc<effects::PacketCompleteEffectReceiverGroup>,
    _reader: effects::PacketCompleteEffectReceiverReader,
}

impl ReceiverFixture {
    fn new() -> Self {
        let directory = ReceiverDirectory::new();
        let paths = std::array::from_fn(|member| directory.path.join(format!("receiver-{member}")));
        let receivers = paths
            .each_ref()
            .map(|path| UnixDatagram::bind(path).unwrap());
        let (group, reader) =
            effects::PacketCompleteEffectReceiverGroup::from_original_receivers(receivers);
        Self {
            _directory: directory,
            paths,
            group,
            _reader: reader,
        }
    }
}

struct ReceiverDirectory {
    path: PathBuf,
}

impl ReceiverDirectory {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let directory = std::env::temp_dir().join(format!(
            "aos-rfc25-holder-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&directory).unwrap();
        Self { path: directory }
    }
}

impl Drop for ReceiverDirectory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.path).unwrap();
    }
}

#[test]
fn actual_bound_path_keeps_spare_capacity_without_reopening_kernel_custody() {
    let fixture = ReceiverFixture::new();
    let mut source = source(0);
    let mut path = fixture.paths[0].clone();
    path.reserve(211);
    let capacity = path.capacity();
    assert!(capacity > path.as_os_str().len());
    source
        .bind_original_effect_receiver(Rc::clone(&fixture.group), 0, path)
        .unwrap();
    let source = Rc::new(source);

    // Retained DATA survives unlinking the old kernel address. Current receiver
    // authentication remains a separate operation with its own kernel checks.
    std::fs::remove_file(&fixture.paths[0]).unwrap();
    let facts = source.original_complete_holder_capacity_data(None).unwrap();
    let expected = original_holder_cost(&source);

    assert_eq!(facts.vector_banks, 1);
    assert_eq!(facts.vector_capacity_bytes, capacity);
    assert_eq!(facts.capacity_records, 3);
    assert_eq!(facts.shared_backing_views, 1);
    assert_eq!(Rc::strong_count(&fixture.group), 3);
    assert_eq!(
        source.original_complete_holder_storage_data_with_error::<RuntimeError>(expected),
        Ok(expected)
    );
    assert_eq!(
        source.original_complete_holder_storage_data_with_error::<RuntimeError>(expected - 1),
        Err(RuntimeError::ResourceLimit)
    );
}
