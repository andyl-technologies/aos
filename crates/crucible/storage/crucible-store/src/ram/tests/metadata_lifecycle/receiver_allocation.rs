//! Receiver assembly refusal keeps the actual allocator cause and original.
//!
//! The peer advertises a bounded, incomplete first object. Exact-layout
//! injection reaches the existing fallible assembly reservation, after a
//! separately observed prefix. These RAM-only controls admit no whole world.

use super::*;
use crucible_host_resources::test_support::TestAllocationObserver;
use crucible_qemu_protocol::ram_transfer::{RamTransferControl, RamTransferMessage};
use std::alloc::Layout;
use std::collections::TryReserveError;

const ASSEMBLY_BYTES: usize = 60_013;

fn allocator_source<'error>(mut error: &'error (dyn Error + 'static)) -> &'error TryReserveError {
    loop {
        if let Some(source) = error.downcast_ref::<TryReserveError>() {
            return source;
        }
        error = error.source().expect("actual allocation cause");
    }
}

fn exercise_receiver(prefix_only: bool, inject: bool) {
    let source_directory = tempfile::tempdir().unwrap();
    let destination_directory = tempfile::tempdir().unwrap();
    let source_quota = ObservedQuota::with_limit(32 << 20);
    let destination_quota = ObservedQuota::with_limit(32 << 20);
    let source = directory_store(source_directory.path(), &source_quota);
    let destination = directory_store(destination_directory.path(), &destination_quota);
    let source_original = fixture_original(&source);
    let root = source
        .capture(
            topology(17),
            Scope::Exact,
            &mut patterned,
            &Retention::default(),
            &source_original,
            &mut || Ok(()),
        )
        .unwrap();
    let root_id = root.object_id();
    let offer = archive_offer(&root, 64);
    let mut sender = RamTransferSender::new(
        source,
        root,
        [94; 32],
        ContentId::parse(&offer.whole_world_root).unwrap(),
        &offer.destination,
        offer.durable_placements,
        offer.limits,
        &source_original,
    )
    .unwrap();
    let caller_quota = ObservedQuota::with_limit(128 << 20);
    let original = DecodeBudget::for_store(caller_quota.clone()).unwrap();
    original
        .charge_bytes(crate::ram::maximum_ram_root_decoding_bytes().unwrap())
        .unwrap();
    let offered =
        crate::ram::response::decode_local(&sender.offer().unwrap(), &source_original, &original)
            .unwrap();
    let retention = Retention::default();
    let mut receiver = RamTransferReceiver::new(destination.clone(), &retention, offered).unwrap();
    let layout = Layout::array::<u8>(ASSEMBLY_BYTES).unwrap();
    let mut chunks = 0;
    let mut cancellations = 0;
    let mut acknowledgments = 0;
    let mut exchange = |message: RamTransferMessage| {
        if matches!(message.control, RamTransferControl::Cancel) {
            cancellations += 1;
        }
        if matches!(message.control, RamTransferControl::ClosureStored { .. }) {
            acknowledgments += 1;
        }
        let mut response = sender.respond(message, &mut || Ok(()))?;
        if matches!(
            response.message().control,
            RamTransferControl::ObjectChunk { .. }
        ) {
            chunks += 1;
            if prefix_only || inject {
                response.alter_for_test(|message| {
                    let RamTransferControl::ObjectChunk { length, last, .. } = &mut message.control
                    else {
                        panic!("first object chunk");
                    };
                    *length = ASSEMBLY_BYTES as u64;
                    *last = false;
                });
                // Include real response encoding in the observed prefix. The
                // advertised assembly extent is distinct from frame storage.
                response.with_encoded(&original, |_| Ok(()))?;
                if prefix_only {
                    return Err(RamStoreError::Canceled);
                }
            }
        }
        Ok(response)
    };
    let mut receive = || receiver.receive(&mut exchange, &original, &mut || Ok(()));

    if prefix_only {
        let (result, earlier, counts) =
            TestAllocationObserver::capture_layout_and_count(layout, receive);
        assert!(matches!(result, Err(RamStoreError::Canceled)));
        assert!(
            earlier.is_none(),
            "assembly extent overlaps the real prefix"
        );
        assert!(!counts.overflow);
        assert_eq!((chunks, cancellations, acknowledgments), (1, 1, 0));
        assert!(!destination.backend.contains(root_id).unwrap());
    } else if inject {
        let (expected, reached) = TestAllocationObserver::refuse_one_allocation(layout, || {
            Vec::<u8>::new()
                .try_reserve_exact(ASSEMBLY_BYTES)
                .unwrap_err()
        })
        .unwrap();
        assert!(reached);
        let (result, reached) =
            TestAllocationObserver::refuse_one_allocation(layout, receive).unwrap();
        assert!(reached, "the actual fallible assembly was not reached");
        let error = result.unwrap_err();
        assert_eq!(allocator_source(&error), &expected);
        let funded_error = matches!(
            &error,
            RamStoreError::Store(StoreError::DecodeAdmission { .. })
        );
        assert_eq!((chunks, cancellations, acknowledgments), (1, 1, 0));
        assert!(!destination.backend.contains(root_id).unwrap());

        drop(receiver);
        drop(original);
        let retained = caller_quota.used();
        drop(error);
        assert_eq!(caller_quota.used(), 0);
        assert!(
            funded_error && retained > 0,
            "allocator diagnostic must retain its actual original: funded={funded_error}, retained={retained}"
        );
        return;
    } else {
        let RamTransferStep::ClosureStored(stored) = receive().unwrap() else {
            panic!("complete RAM closure");
        };
        assert_eq!(stored.root().object_id(), root_id);
        assert_eq!(stored.report().copied_objects, 3);
        assert_eq!(acknowledgments, 1);
        assert_eq!(cancellations, 0);
        let verified = destination
            .verify(stored.root(), &original, &mut || Ok(()))
            .unwrap();
        assert_eq!((verified.pages, verified.logical_bytes), (1, 17));
        drop(stored);
    }

    drop(receiver);
    drop(original);
    assert_eq!(caller_quota.used(), 0);
}

#[test]
fn receiver_assembly_prefix_avoids_the_injected_allocation_extent() {
    exercise_receiver(true, false);
}

#[test]
fn receiver_assembly_keeps_healthy_complete_ram_transfer() {
    exercise_receiver(false, false);
}

#[test]
fn receiver_assembly_allocator_refusal_retains_actual_original_custody() {
    exercise_receiver(false, true);
}
