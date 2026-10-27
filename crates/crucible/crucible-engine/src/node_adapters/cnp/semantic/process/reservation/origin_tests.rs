//! Exercises seeded creator drift before source bookkeeping and callbacks.
//!
//! These safe model controls qualify guard ordering only. Actual inherited
//! custody and original parent cleanup are exercised by a separate kernel fork.

use std::{cell::Cell, path::PathBuf, process::Command, rc::Rc};

use crucible_node_format::{U64, canonical};

use super::super::ReadCall;
use super::*;

struct Slot {
    retained: Rc<Cell<usize>>,
    dropped: Rc<Cell<usize>>,
}

impl CnpSemanticProcessSlot for Slot {
    fn identity(&self) -> U64 {
        U64::new(91)
    }

    fn retain(&mut self, _custody: CnpSemanticProcessCustody) {
        self.retained.set(self.retained.get() + 1);
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.dropped.set(self.dropped.get() + 1);
    }
}

type FixtureReservation = (
    CnpSemanticLaunchReservation,
    Rc<Cell<usize>>,
    Rc<Cell<usize>>,
);

fn reservation() -> Result<FixtureReservation, ProviderError> {
    let retained = Rc::new(Cell::new(0));
    let dropped = Rc::new(Cell::new(0));
    let executable = canonical::content_ref(b"unlaunched origin fixture", "text/plain")?;
    let original = CnpSemanticLaunchReservation::reserve(
        PathBuf::from("unlaunched-origin-fixture"),
        executable,
        Box::new(Slot {
            retained: Rc::clone(&retained),
            dropped: Rc::clone(&dropped),
        }),
    );
    Ok((original, retained, dropped))
}

#[test]
fn cached_foreign_launch_origin_refuses_before_spawn_or_attempt_bookkeeping()
-> Result<(), ProviderError> {
    let (mut original, retained, dropped) = reservation()?;
    original.guard.creator_process = 0;
    let mut command = Command::new("nonexistent-origin-control-must-not-spawn");

    assert!(matches!(
        original.launch(&mut command),
        Err(ProviderError::Correlation(
            "generic original launch guard belongs to another process"
        ))
    ));
    assert!(!original.attempted);
    assert!(
        original
            .guard
            .custody
            .as_ref()
            .is_some_and(|custody| custody.child.is_none())
    );
    drop(original);

    assert_eq!(retained.get(), 0);
    assert_eq!(dropped.get(), 0);
    Ok(())
}

#[test]
fn cached_foreign_custody_poll_preserves_read_owner_and_native_bookkeeping()
-> Result<(), ProviderError> {
    let (mut original, retained, dropped) = reservation()?;
    let custody = original
        .guard
        .custody
        .as_mut()
        .ok_or(ProviderError::Correlation("fixture custody absent"))?;
    custody.creator_process = 0;

    assert!(matches!(
        custody.poll_reclamation(),
        Err(ProviderError::Correlation(
            "generic original custody belongs to another process"
        ))
    ));
    ReadCall::begin(Rc::clone(&custody.read_owner))?.finish(true);
    assert!(!custody.killed);
    assert!(custody.reaped.is_none());
    assert!(custody.child.is_none());
    assert!(matches!(
        custody.kernel_resources_reclaimed(),
        Err(ProviderError::Correlation(
            "generic original custody belongs to another process"
        ))
    ));
    drop(original);

    assert_eq!(retained.get(), 0);
    assert_eq!(dropped.get(), 1);
    Ok(())
}

#[test]
fn current_unlaunched_owner_drops_only_its_original_supervisor_slot() -> Result<(), ProviderError> {
    let (original, retained, dropped) = reservation()?;

    drop(original);

    assert_eq!(retained.get(), 0);
    assert_eq!(dropped.get(), 1);
    Ok(())
}
