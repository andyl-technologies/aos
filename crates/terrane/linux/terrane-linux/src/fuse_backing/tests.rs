//! Exercises shared resources through original queue and lifetime transitions.

#![allow(clippy::unwrap_used)]

use super::*;
use crate::{fuse_lifetime, fuse_open};
use std::{cell::Cell, rc::Rc, time::Duration};

fn id(value: u64) -> NonZeroU64 {
    NonZeroU64::new(value).unwrap()
}

#[allow(
    clippy::disallowed_methods,
    reason = "A fixed origin anchors pure queue transitions without native IO or repository state."
)]
fn clock() -> std::time::Instant {
    std::time::Instant::now()
}

fn queue() -> fuse_open::Queue {
    fuse_open::Queue::new(fuse_open::Limits {
        nodes: 4,
        waiters: 8,
        bytes: 4096,
    })
    .unwrap()
}

fn start(queue: &mut fuse_open::Queue, node: u64, unique: u64) -> Ticket {
    match queue
        .enqueue(id(node), id(unique), clock(), Duration::from_secs(1))
        .unwrap()
    {
        fuse_open::Enqueued::Start(ticket) => ticket,
        other => panic!("expected original fetch, got {other:?}"),
    }
}

fn table<B>(nodes: u32) -> Table<B> {
    Table::new(Limits { nodes, bytes: 4096 }).unwrap()
}

#[test]
fn distinct_nodes_install_independently_and_never_replace_original_resources() {
    let mut queue = queue();
    let first = start(&mut queue, 19, 1);
    let second = start(&mut queue, 20, 2);
    let mut table = table(2);

    table.reserve(first).unwrap();
    table.reserve(second).unwrap();
    assert_eq!(table.get(id(19)), None);
    assert_eq!(table.retire(id(19)), Err(Error::Pending));
    let unstarted = table.install(first, 999).unwrap_err();
    assert_eq!((unstarted.error, unstarted.backing), (Error::Stale, 999));
    assert_eq!(table.next_fetch(), Some(first));
    assert_eq!(table.next_fetch(), Some(second));
    assert_eq!(table.next_fetch(), None);
    table.install(second, 200).unwrap();
    table.install(first, 100).unwrap();

    let rejected = table.install(first, 999).unwrap_err();
    assert_eq!((rejected.error, rejected.backing), (Error::Stale, 999));
    assert_eq!(table.reserve(first), Err(Error::Duplicate));
    assert_eq!(table.fail(first), Err(Error::Stale));
    assert_eq!(table.get(id(19)), Some(&100));
    assert_eq!(table.get(id(20)), Some(&200));
    assert_eq!(table.retire(id(19)), Ok(Some(100)));
    assert_eq!(table.get(id(20)), Some(&200));
    assert_eq!(table.retire(id(19)), Ok(None));
}

#[test]
fn exhausted_reservations_and_old_completions_preserve_retry_ownership() {
    let mut queue = queue();
    let first = start(&mut queue, 19, 1);
    let other = start(&mut queue, 20, 2);
    let mut table = table(1);
    table.reserve(first).unwrap();

    assert_eq!(table.reserve(other), Err(Error::Capacity));
    assert_eq!(table.reserve(first), Err(Error::Duplicate));
    table.fail(first).unwrap();
    queue.complete(first, fuse_open::Outcome::IoError).unwrap();
    let retry = start(&mut queue, 19, 3);
    assert_ne!(retry, first);
    table.reserve(retry).unwrap();

    assert_eq!(table.fail(first), Err(Error::Stale));
    let rejected = table.install(first, 999).unwrap_err();
    assert_eq!((rejected.error, rejected.backing), (Error::Stale, 999));
    assert_eq!(table.get(id(19)), None);
    assert_eq!(table.next_fetch(), Some(retry));
    table.install(retry, 100).unwrap();
    assert_eq!(table.get(id(19)), Some(&100));
}

#[derive(Debug)]
struct Resource(Rc<Cell<u32>>);

impl Drop for Resource {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}

#[test]
fn expired_waiter_and_peer_release_keep_the_original_backing_until_retirement() {
    let mut queue = queue();
    let ticket = start(&mut queue, 19, 1);
    let mut table = table(1);
    let mut lifetime = fuse_lifetime::Table::new(fuse_lifetime::Limits {
        nodes: 2,
        handles: 2,
        bytes: 4096,
    })
    .unwrap();
    let drops = Rc::new(Cell::new(0));
    table.reserve(ticket).unwrap();
    lifetime.pin(ticket.node()).unwrap();

    let expired = queue.next_reply(clock() + Duration::from_secs(2)).unwrap();
    assert_eq!(expired.outcome, fuse_open::Outcome::IoError);
    assert_eq!(lifetime.next_unreferenced(), None);
    assert_eq!(table.retire(ticket.node()).unwrap_err(), Error::Pending);
    assert_eq!(table.next_fetch(), Some(ticket));
    table.install(ticket, Resource(drops.clone())).unwrap();
    queue.complete(ticket, fuse_open::Outcome::Ready).unwrap();

    let first = lifetime
        .open(ticket.node(), fuse_lifetime::Kind::File)
        .unwrap();
    let peer = lifetime
        .open(ticket.node(), fuse_lifetime::Kind::File)
        .unwrap();
    lifetime.unpin(ticket.node()).unwrap();
    lifetime
        .close(peer, ticket.node(), fuse_lifetime::Kind::File)
        .unwrap();
    assert_eq!(lifetime.next_unreferenced(), None);
    assert!(table.get(ticket.node()).is_some());
    assert_eq!(drops.get(), 0);

    lifetime
        .close(first, ticket.node(), fuse_lifetime::Kind::File)
        .unwrap();
    let unreferenced = lifetime.next_unreferenced().unwrap();
    let resource = table.retire(unreferenced).unwrap().unwrap();
    assert!(table.get(ticket.node()).is_none());
    assert_eq!(drops.get(), 0);
    drop(resource);
    assert_eq!(drops.get(), 1);
}

#[test]
fn startup_bounds_include_pending_records_and_the_actual_resource_layout() {
    assert!(matches!(
        Table::<u64>::new(Limits {
            nodes: 0,
            bytes: 4096
        }),
        Err(Error::Budget)
    ));
    assert!(matches!(
        Table::<[u8; 256]>::new(Limits {
            nodes: 2,
            bytes: 256
        }),
        Err(Error::Budget)
    ));
    let mut table = table::<u64>(2);
    let mut queue = queue();
    let first = start(&mut queue, 19, 1);
    let second = start(&mut queue, 20, 2);
    let capacity = table.entries.capacity();

    table.reserve(first).unwrap();
    table.reserve(second).unwrap();
    assert_eq!(table.next_fetch(), Some(first));
    table.install(first, 100).unwrap();
    table.fail(second).unwrap();
    table.retire(first.node()).unwrap();
    assert_eq!(table.entries.capacity(), capacity);
    assert!(capacity * size_of::<Entry<u64>>() <= 4096);
}
