//! Checks native no-reply forget records, original handles and pending pins.

#![allow(clippy::unwrap_used)]

use super::*;

fn id(value: u64) -> NonZeroU64 {
    NonZeroU64::new(value).unwrap()
}

fn table(nodes: u32, handles: u32) -> Table {
    Table::new(Limits {
        nodes,
        handles,
        bytes: 65536,
    })
    .unwrap()
}

fn request(opcode: u32, node: u64, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 40 + body.len()];
    let length = bytes.len() as u32;
    bytes[..4].copy_from_slice(&length.to_ne_bytes());
    bytes[4..8].copy_from_slice(&opcode.to_ne_bytes());
    bytes[8..16].copy_from_slice(&99u64.to_ne_bytes());
    bytes[16..24].copy_from_slice(&node.to_ne_bytes());
    bytes[40..].copy_from_slice(body);
    bytes
}

fn forget(table: &mut Table, node: u64, count: u64) -> Result<(), Error> {
    let bytes = request(2, node, &count.to_ne_bytes());
    table.forget(Request::parse(&bytes, 65536).unwrap(), 1)
}

fn batch(records: &[(u64, u64)]) -> Vec<u8> {
    let mut body = vec![0; 8];
    body[..4].copy_from_slice(&(records.len() as u32).to_ne_bytes());
    for (node, count) in records {
        body.extend_from_slice(&node.to_ne_bytes());
        body.extend_from_slice(&count.to_ne_bytes());
    }
    request(42, 0, &body)
}

#[test]
fn forget_waits_for_every_original_handle_and_pending_work_pin() {
    let mut state = table(2, 2);
    state.lookup(id(19)).unwrap();
    state.lookup(id(19)).unwrap();
    state.pin(id(19)).unwrap();
    let first = state.open(id(19), Kind::File).unwrap();
    let second = state.open(id(19), Kind::File).unwrap();
    assert_ne!(first, second);

    forget(&mut state, 19, 2).unwrap();
    assert_eq!(state.next_unreferenced(), None);
    state.close(first, id(19), Kind::File).unwrap();
    assert_eq!(state.next_unreferenced(), None);
    state.close(second, id(19), Kind::File).unwrap();
    assert_eq!(state.next_unreferenced(), None);
    state.unpin(id(19)).unwrap();
    assert_eq!(state.next_unreferenced(), Some(id(19)));
    assert_eq!(state.next_unreferenced(), None);
}

#[test]
fn released_handles_never_alias_reopened_nodes_or_directory_handles() {
    let mut state = table(2, 2);
    state.lookup(id(19)).unwrap();
    let original = state.open(id(19), Kind::File).unwrap();
    assert_eq!(
        state.check(original, id(20), Kind::File),
        Err(Error::Handle)
    );
    assert_eq!(
        state.close(original, id(19), Kind::Directory),
        Err(Error::Handle)
    );
    state.close(original, id(19), Kind::File).unwrap();
    let reopened = state.open(id(19), Kind::File).unwrap();
    assert_ne!(original, reopened);
    assert_eq!(
        state.close(original, id(19), Kind::File),
        Err(Error::Handle)
    );
    state.check(reopened, id(19), Kind::File).unwrap();

    let root = state.open(id(1), Kind::Directory).unwrap();
    state.close(root, id(1), Kind::Directory).unwrap();
    assert_eq!(state.next_unreferenced(), None);
    assert_eq!(
        state.check(root, id(1), Kind::Directory),
        Err(Error::Handle)
    );
}

#[test]
fn batch_duplicates_are_summed_before_any_forget_changes_state() {
    let mut state = table(2, 2);
    for node in [19, 19, 20] {
        state.lookup(id(node)).unwrap();
    }
    let excessive = batch(&[(20, 1), (19, 1), (19, 2)]);
    assert_eq!(
        state.forget(Request::parse(&excessive, 65536).unwrap(), 3),
        Err(Error::References)
    );
    assert_eq!(state.next_unreferenced(), None);
    let overflow = batch(&[(19, u64::MAX), (19, 1)]);
    assert_eq!(
        state.forget(Request::parse(&overflow, 65536).unwrap(), 3),
        Err(Error::Overflow)
    );
    assert_eq!(state.next_unreferenced(), None);

    let valid = batch(&[(20, 1), (19, 1), (19, 1)]);
    state
        .forget(Request::parse(&valid, 65536).unwrap(), 3)
        .unwrap();
    let mut retired = [
        state.next_unreferenced().unwrap(),
        state.next_unreferenced().unwrap(),
    ];
    retired.sort_unstable();
    assert_eq!(retired, [id(19), id(20)]);
}

#[test]
fn malformed_forgets_and_over_forgets_preserve_all_references() {
    let mut state = table(1, 1);
    state.lookup(id(19)).unwrap();
    assert_eq!(forget(&mut state, 19, 2), Err(Error::References));
    assert_eq!(forget(&mut state, 20, 1), Err(Error::References));
    assert_eq!(forget(&mut state, 19, 0), Err(Error::Protocol));
    for bytes in [
        request(2, 0, &1u64.to_ne_bytes()),
        request(2, 19, &[1; 7]),
        batch(&[(0, 1)]),
        batch(&[(19, 0)]),
        request(3, 19, &[1; 8]),
    ] {
        assert_eq!(
            state.forget(Request::parse(&bytes, 65536).unwrap(), 2),
            Err(Error::Protocol)
        );
    }
    let mut padded = batch(&[(19, 1)]);
    padded[44] = 1;
    assert_eq!(
        state.forget(Request::parse(&padded, 65536).unwrap(), 2),
        Err(Error::Protocol)
    );
    let valid = batch(&[(19, 1)]);
    assert_eq!(
        state.forget(Request::parse(&valid, 65536).unwrap(), 0),
        Err(Error::Protocol)
    );
    assert_eq!(state.next_unreferenced(), None);
    forget(&mut state, 19, 1).unwrap();
    assert_eq!(state.next_unreferenced(), Some(id(19)));
    let empty = batch(&[]);
    state
        .forget(Request::parse(&empty, 65536).unwrap(), 0)
        .unwrap();
}

#[test]
fn node_handle_and_counter_exhaustion_refuse_before_mutating_original_state() {
    assert!(matches!(
        Table::new(Limits {
            nodes: 0,
            handles: 1,
            bytes: 65536
        }),
        Err(Error::Budget)
    ));
    assert!(matches!(
        Table::new(Limits {
            nodes: 1,
            handles: 1,
            bytes: 1
        }),
        Err(Error::Budget)
    ));
    let mut state = table(1, 1);
    assert_eq!(state.open(id(19), Kind::File), Err(Error::References));
    state.lookup(id(19)).unwrap();
    assert_eq!(state.lookup(id(20)), Err(Error::Capacity));
    let first = state.open(id(19), Kind::File).unwrap();
    assert_eq!(state.open(id(19), Kind::File), Err(Error::Capacity));
    state.close(first, id(19), Kind::File).unwrap();
    let second = state.open(id(19), Kind::File).unwrap();
    assert_eq!(second.get(), first.get() + 1);
    state.close(second, id(19), Kind::File).unwrap();

    state.node_mut(id(19)).unwrap().lookups = u64::MAX;
    assert_eq!(state.lookup(id(19)), Err(Error::Overflow));
    assert_eq!(state.node_mut(id(19)).unwrap().lookups, u64::MAX);
    state.node_mut(id(19)).unwrap().pins = u64::MAX;
    assert_eq!(state.pin(id(19)), Err(Error::Overflow));
    assert_eq!(state.node_mut(id(19)).unwrap().pins, u64::MAX);
    state.next_handle = u64::MAX;
    assert_eq!(state.open(id(19), Kind::File), Err(Error::Overflow));
    assert!(state.handles.is_empty());
}

#[test]
fn expired_waiter_does_not_retire_a_still_pinned_shared_fetch() {
    let mut state = table(1, 1);
    state.lookup(id(19)).unwrap();
    state.pin(id(19)).unwrap(); // The original shared fetch.
    state.pin(id(19)).unwrap(); // One outstanding kernel response.
    forget(&mut state, 19, 1).unwrap();
    state.unpin(id(19)).unwrap(); // The response expires independently.
    assert_eq!(state.next_unreferenced(), None);
    state.pin(id(19)).unwrap(); // A new waiter joins the same fetch.
    state.unpin(id(19)).unwrap(); // The original fetch completes.
    let handle = state.open(id(19), Kind::File).unwrap();
    state.unpin(id(19)).unwrap(); // The successful waiter now owns a handle.
    assert_eq!(state.next_unreferenced(), None);
    state.close(handle, id(19), Kind::File).unwrap();
    assert_eq!(state.next_unreferenced(), Some(id(19)));
    assert_eq!(state.unpin(id(19)), Err(Error::References));
}
