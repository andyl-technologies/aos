//! Tests exact six-ring barriers and actual kernel exclusion without native authority.

// crucible-lint: allow panic-shortcut -- Assertion panics are the control verdict.
#![allow(clippy::unwrap_used)]

use super::super::super::tests::original_aliases;
use super::*;
use std::os::unix::fs::FileExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn pairs(node: u32) -> [(u32, u32); RING_COUNT] {
    [
        (node, crate::SLOT_NET_ROUTER as u32),
        (crate::SLOT_NET_ROUTER as u32, node),
        (node, crate::SLOT_BLK_IO as u32),
        (crate::SLOT_BLK_IO as u32, node),
        (node, crate::SLOT_9P_IO as u32),
        (crate::SLOT_9P_IO as u32, node),
    ]
}

fn prepared(owner: &SharedOwnedSetupMapping) -> TestResult<PreparedDirectedRingRoster> {
    owner.prepare_whole_intent_retention()?;
    Ok(owner
        .with_ordinary_preparation(|view| view.prepare_directed_ring_hold_roster(0, pairs(0)))??)
}

#[test]
fn six_exact_headers_hold_while_other_families_remain_unheld() -> TestResult {
    let (_file, mapping, mut alias) = original_aliases()?;
    let mut owner = SharedOwnedSetupMapping::new(mapping);
    let mut roster = prepared(&owner)?;
    let allocation = std::ptr::from_ref::<MappedSetupRegion>(&*owner.mapping()?) as usize;
    assert_eq!(allocation, roster.mapping_object);
    let frame = crate::FrameEntry::new(4, 0, 19, b"same original six rings")?;
    {
        let pair = alias.node_directed_ring_pair_mut(
            0,
            0,
            crate::SLOT_NET_ROUTER as u32,
            crate::SLOT_NET_ROUTER as u32,
            0,
        )?;
        pair.first.header.enqueue(pair.first.entries, &frame)?;
        assert_eq!(
            pair.first.header.dequeue(pair.first.entries)?.unwrap().seq,
            19
        );
    }
    let snapshot = owner.hold_prepared_directed_rings(&mut roster)?;
    assert_eq!(snapshot.ring_count(), 6);
    assert_eq!(snapshot.held_rings(), 6);
    assert!(snapshot.quiescent() && snapshot.mapping_excluded());
    assert_eq!(owner.prepared_directed_ring_snapshot(&roster)?, snapshot);
    let full = alias.hot_fork_ring_io_snapshot()?;
    assert!(full.ring_count() > 6);
    assert_eq!(full.held_rings(), 6);
    assert!(!full.quiescent());
    assert!(alias.release_hot_fork_ring_io().is_err());
    assert!(alias.restore_hot_fork_parent_inheritance().is_err());
    assert!(
        alias
            .node_directed_ring_pair_mut(
                1,
                1,
                crate::SLOT_NET_ROUTER as u32,
                crate::SLOT_NET_ROUTER as u32,
                1
            )
            .is_err()
    );
    assert!(owner.ordinary_mapping_mut().is_err());
    Ok(())
}

#[test]
fn admitted_producer_leaves_all_six_held_and_same_arc_quarantined() -> TestResult {
    let (_file, mapping, mut alias) = original_aliases()?;
    let owner = SharedOwnedSetupMapping::new(mapping);
    let mut roster = prepared(&owner)?;
    let allocation = roster.mapping_object;
    let pair = alias.node_directed_ring_pair_mut(
        0,
        0,
        crate::SLOT_NET_ROUTER as u32,
        crate::SLOT_NET_ROUTER as u32,
        0,
    )?;
    let admission = pair
        .first
        .header
        .enter_producer()
        .ok_or("ordinary admission missing")?;
    let error = owner.hold_prepared_directed_rings(&mut roster).unwrap_err();
    let PreparedDirectedRingHoldError::NotQuiescent { snapshot } = error else {
        return Err("wrong original hold refusal".into());
    };
    assert_eq!(snapshot.held_rings(), 6);
    assert_eq!(snapshot.producers_in_flight(), 1);
    assert!(!snapshot.quiescent());
    drop(admission);
    assert!(owner.hold_prepared_directed_rings(&mut roster).is_err());
    assert!(owner.prepared_directed_ring_snapshot(&roster).is_err());
    assert!(alias.release_hot_fork_ring_io().is_err());
    drop(owner);
    let quarantine = super::super::super::quarantine().lock().unwrap();
    assert!(
        quarantine
            .owners
            .iter()
            .any(|mapping| std::ptr::from_ref(mapping.as_ref()) as usize == allocation)
    );
    Ok(())
}

#[test]
fn changed_header_before_hold_refuses_without_barrier_effects() -> TestResult {
    let (file, mapping, alias) = original_aliases()?;
    let owner = SharedOwnedSetupMapping::new(mapping);
    let mut roster = prepared(&owner)?;
    let magic = crate::REGION_HEADER_MAGIC_OFFSET as u64;
    let mut original = [0_u8; 8];
    file.read_exact_at(&mut original, magic)?;
    file.write_all_at(&0_u64.to_le_bytes(), magic)?;
    assert!(owner.hold_prepared_directed_rings(&mut roster).is_err());
    file.write_all_at(&original, magic)?;
    assert_eq!(alias.hot_fork_ring_io_snapshot()?.held_rings(), 0);
    assert!(owner.hold_prepared_directed_rings(&mut roster).is_err());
    assert!(alias.release_hot_fork_ring_io().is_err());
    Ok(())
}

#[test]
fn foreign_original_roster_and_repeated_attempt_never_release() -> TestResult {
    let (_file, mapping, alias) = original_aliases()?;
    let original = SharedOwnedSetupMapping::new(mapping);
    let mut roster = prepared(&original)?;
    let foreign = SharedOwnedSetupMapping::new(alias);
    foreign.prepare_whole_intent_retention()?;
    assert!(foreign.hold_prepared_directed_rings(&mut roster).is_err());
    assert!(original.hold_prepared_directed_rings(&mut roster).is_err());

    let (_file, mapping, alias) = original_aliases()?;
    let owner = SharedOwnedSetupMapping::new(mapping);
    let mut roster = prepared(&owner)?;
    owner.hold_prepared_directed_rings(&mut roster)?;
    assert!(owner.hold_prepared_directed_rings(&mut roster).is_err());
    assert_eq!(alias.hot_fork_ring_io_snapshot()?.held_rings(), 6);
    assert!(alias.release_hot_fork_ring_io().is_err());
    Ok(())
}

#[test]
fn invalid_roster_and_missing_ticket_stop_before_effects() -> TestResult {
    let (_file, mapping, alias) = original_aliases()?;
    let owner = SharedOwnedSetupMapping::new(mapping);
    owner.prepare_whole_intent_retention()?;
    let mut duplicate = pairs(0);
    duplicate[5] = duplicate[0];
    assert!(
        owner
            .with_ordinary_preparation(|view| view.prepare_directed_ring_hold_roster(0, duplicate))?
            .is_err()
    );
    assert_eq!(alias.hot_fork_ring_io_snapshot()?.held_rings(), 0);
    let (_file, mapping, _alias) = original_aliases()?;
    let owner = SharedOwnedSetupMapping::new(mapping);
    let called = std::cell::Cell::new(false);
    assert!(
        owner
            .with_ordinary_preparation(|_| {
                called.set(true);
                Ok::<_, ()>(())
            })
            .is_err()
    );
    assert!(!called.get());
    Ok(())
}

// This bounded kernel child watchdog never enters modeled simulation time.
#[allow(clippy::disallowed_types, clippy::disallowed_methods)]
#[test]
fn dontfork_and_foreign_pid_refuse_before_inherited_owner_lock() -> TestResult {
    let (_file, mapping, alias) = original_aliases()?;
    let owner = SharedOwnedSetupMapping::new(mapping);
    let mut roster = prepared(&owner)?;
    // Clear the earlier exclusion through a real alias. HOLD must perform the
    // actual kernel exclusion again after fencing aliases.
    alias.restore_hot_fork_parent_inheritance()?;
    owner.hold_prepared_directed_rings(&mut roster)?;
    let held = owner.mapping()?;
    let address = held.mapping_start();
    // SAFETY: this isolated control retains the original owner mutex across
    // fork. Child performs only raw kernel observation, the PID-first helper,
    // static verdict and _exit; it never formats, allocates or drops custody.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if child == 0 {
        let mut residency = 0_u8;
        let absent = unsafe {
            // SAFETY: mincore only queries this original page-aligned mapping
            // address; the kernel may reject its absent child VMA. The writable
            // residency byte covers this fixture's single queried page.
            libc::mincore(address as *mut libc::c_void, 4096, &mut residency)
        } < 0;
        let refused = matches!(
            owner.hold_prepared_directed_rings(&mut roster),
            Err(PreparedDirectedRingHoldError::Custody {
                source: WholeMappingCustodyError::Unregistered
            })
        );
        // SAFETY: this literal verdict terminates the copied child with no cleanup.
        unsafe {
            libc::_exit(if absent && refused { 78 } else { 79 });
        }
    }
    drop(held);
    let mut status = 0;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        // SAFETY: the original parent checks only its own child, without blocking.
        let reaped = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
        if reaped == child {
            break;
        }
        if reaped < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if std::time::Instant::now() >= deadline {
            // SAFETY: this exact unreaped child came from our fork; containment
            // targets only that child and reaps it before reporting failure.
            unsafe {
                libc::kill(child, libc::SIGKILL);
                libc::waitpid(child, &mut status, 0);
            }
            return Err("copied owner entered an inherited lock".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 78);
    assert!(owner.prepared_directed_ring_snapshot(&roster)?.quiescent());
    Ok(())
}

#[test]
fn busy_owner_before_hold_fences_without_touching_headers() -> TestResult {
    let (_file, mapping, alias) = original_aliases()?;
    let owner = SharedOwnedSetupMapping::new(mapping);
    let mut roster = prepared(&owner)?;
    let held = owner.mapping()?;
    assert!(matches!(
        owner.hold_prepared_directed_rings(&mut roster),
        Err(PreparedDirectedRingHoldError::Custody {
            source: WholeMappingCustodyError::Busy
        })
    ));
    drop(held);
    assert_eq!(alias.hot_fork_ring_io_snapshot()?.held_rings(), 0);
    assert!(alias.release_hot_fork_ring_io().is_err());
    assert!(owner.hold_prepared_directed_rings(&mut roster).is_err());
    Ok(())
}
