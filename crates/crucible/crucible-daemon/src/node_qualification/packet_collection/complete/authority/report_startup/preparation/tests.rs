//! Exercises real known-family reservation without creating native processes.
//!
//! The scene performs real file/ELF measurements, entropy and local socket binds.
//! Native currentness, host query publication and semantic qualification remain
//! unavailable; these controls never construct a synthetic completed preparation.

#![allow(clippy::unwrap_used)]
// crucible-lint: allow panic-shortcut -- Control assertions are intended verdicts.

use super::*;
use crate::node_qualification::packet_collection::complete::tests::POSITIVE_STARTUP_SETUP_MEMORY_BYTES;

fn fixture() -> (
    crate::node_qualification::packet_collection::complete::tests::Scene,
    Rc<RefCell<PacketCompleteReportStartupHolder>>,
) {
    crate::node_qualification::packet_collection::complete::tests::report_startup_fixture()
}

#[test]
fn actual_preparation_supervisors_retain_same_operational_owners_and_once_reservation() {
    let (_scene, original) = fixture();
    PacketCompleteReportStartupHolder::reserve_original_preparation_supervisors(&original).unwrap();

    let first =
        PacketCompleteReportStartupHolder::original_preparation_supervisor(&original, 0).unwrap();
    let same =
        PacketCompleteReportStartupHolder::original_preparation_supervisor(&original, 0).unwrap();
    let different =
        PacketCompleteReportStartupHolder::original_preparation_supervisor(&original, 1).unwrap();
    assert!(Rc::ptr_eq(&first, &same));
    assert!(!Rc::ptr_eq(&first, &different));
    assert!(
        PacketCompleteReportStartupHolder::reserve_original_preparation_supervisors(&original)
            .is_err()
    );

    let held = original.borrow();
    let owners = held.preparations.borrow();
    let registered = held.authority.original_ack_hello.borrow();
    for (member, peer) in owners.peers.iter().enumerate() {
        let actual_hello_slot = peer.hello_slot.as_ref().unwrap();
        assert!(Rc::ptr_eq(
            actual_hello_slot,
            registered[member].as_ref().unwrap()
        ));
        assert!(actual_hello_slot.borrow().is_none());
        assert!(peer.connection.is_none());
        assert!(peer.admit_response.is_none());
        assert!(!peer.connection_attempted);
        assert!(peer.supervisor.as_ref().unwrap().is_empty_data().unwrap());
        assert!(peer.preparation.is_none());
        assert!(peer.ticket.get().is_none());
        assert!(!peer.host_attempted);
    }
    assert!(held.authority.roster.current_native().is_err());
}

#[test]
fn actual_preparation_supervisor_quote_exact_policy_and_one_short_keep_original_births() {
    let (_scene, exact) = fixture();
    let peak = {
        let held = exact.borrow();
        let (retained, scratch, future) =
            PacketCompleteReportStartupHolder::preparation_supervisor_reservation_data(
                &exact, &held,
            )
            .unwrap();
        retained
            .checked_add(scratch)
            .unwrap()
            .checked_add(future)
            .unwrap()
    };
    exact.borrow_mut().resources.memory_bytes = crucible_node_format::U64::new(peak as u64);
    PacketCompleteReportStartupHolder::reserve_original_preparation_supervisors(&exact).unwrap();
    assert!(
        exact
            .borrow()
            .preparations
            .borrow()
            .peers
            .iter()
            .all(|peer| peer.supervisor.is_some())
    );

    let (_short_scene, short) = fixture();
    let short_peak = {
        let held = short.borrow();
        let (retained, scratch, future) =
            PacketCompleteReportStartupHolder::preparation_supervisor_reservation_data(
                &short, &held,
            )
            .unwrap();
        retained
            .checked_add(scratch)
            .unwrap()
            .checked_add(future)
            .unwrap()
    };
    let before = std::array::from_fn::<_, 3, _>(|member| {
        short.borrow().authority.roster.sources[member]
            .original_report_startup_audit_data()
            .unwrap()
    });
    short.borrow_mut().resources.memory_bytes =
        crucible_node_format::U64::new((short_peak - 1) as u64);
    assert!(
        PacketCompleteReportStartupHolder::reserve_original_preparation_supervisors(&short)
            .is_err()
    );
    let held = short.borrow();
    let owners = held.preparations.borrow();
    assert!(!owners.attempted);
    assert!(owners.peers.iter().all(|peer| peer.supervisor.is_none()));
    for (source, before) in held.authority.roster.sources.iter().zip(before) {
        assert_eq!(source.original_report_startup_audit_data().unwrap(), before);
        assert!(source.authenticate_current_native().is_err());
    }
}

#[test]
fn actual_preparation_supervisor_short_policy_refuses_before_any_owner_construction() {
    let (_scene, original) = fixture();
    original.borrow_mut().resources.memory_bytes = crucible_node_format::U64::new(1);

    assert!(
        PacketCompleteReportStartupHolder::reserve_original_preparation_supervisors(&original)
            .is_err()
    );

    let held = original.borrow();
    let owners = held.preparations.borrow();
    assert!(!owners.attempted);
    assert!(owners.scratch.is_none());
    assert!(
        owners
            .peers
            .iter()
            .all(|peer| peer.supervisor.is_none() && peer.operational.is_none())
    );
    assert!(held.authority.roster.current_native().is_err());
}

#[test]
fn original_host_query_keeps_missing_real_preparation_refused_without_native_dispatch() {
    let (_scene, original) = fixture();
    // Use positive setup policy while retaining the missing-preparation refusal.
    original.borrow_mut().resources.memory_bytes =
        crucible_node_format::U64::new(POSITIVE_STARTUP_SETUP_MEMORY_BYTES);
    PacketCompleteReportStartupHolder::reserve_original_preparation_supervisors(&original).unwrap();
    PacketCompleteReportStartupHolder::finalize_original_report_startup(&original).unwrap();
    let before =
        PacketCompleteReportStartupHolder::original_preparation_supervisor(&original, 0).unwrap();

    assert_eq!(
        PacketCompleteReportStartupHolder::call_original_fresh_restore_query(&original, 0),
        Err(RuntimeError::OwnerUnavailable),
    );

    let after =
        PacketCompleteReportStartupHolder::original_preparation_supervisor(&original, 0).unwrap();
    assert!(Rc::ptr_eq(&before, &after));
    let held = original.borrow();
    let owners = held.preparations.borrow();
    assert!(owners.peers[0].host_attempted);
    assert!(owners.peers[0].ticket.get().is_none());
    assert!(owners.peers[0].preparation.is_none());
    assert!(
        owners.peers[0]
            .supervisor
            .as_ref()
            .unwrap()
            .is_empty_data()
            .unwrap()
    );
    assert!(held.authority.roster.current_native().is_err());
}

#[test]
fn preparation_holder_foreign_origin_refuses_before_busy_owner_bank() {
    let (_scene, original) = fixture();
    let process = original.borrow().process;
    original.borrow_mut().process = process.wrapping_add(1);
    let held = original.borrow();
    let owners = held.preparations.borrow_mut();

    assert_eq!(
        PacketCompleteReportStartupHolder::original_preparation_supervisor(&original, 0).err(),
        Some(RuntimeError::ForeignAuthority),
    );
    assert!(!owners.attempted);
    assert!(owners.peers.iter().all(|peer| peer.supervisor.is_none()));

    drop(owners);
    drop(held);
    original.borrow_mut().process = process;
}
