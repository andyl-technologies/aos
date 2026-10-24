//! Checks actual precredit owner guards without creating a native process.

use std::{cell::Cell, rc::Rc};

use crucible_node_format::U64;

use super::super::{
    CnpSemanticProcessSlot,
    current::{ReadCall, ReadOwner},
};
use super::*;

struct Slot {
    observations: Rc<Cell<usize>>,
}

impl CnpSemanticProcessSlot for Slot {
    fn identity(&self) -> U64 {
        U64::new(1)
    }

    fn retained_requested_storage_precredit_data(
        &self,
        _: usize,
    ) -> Result<Option<usize>, RuntimeError> {
        self.observations.set(self.observations.get() + 1);
        Ok(None)
    }

    fn retain(&mut self, _: CnpSemanticProcessCustody) {
        panic!("unlaunched guard test must not transfer native custody");
    }
}

#[test]
fn foreign_guard_refuses_before_slot_callback_or_counter_mutation() -> Result<(), RuntimeError> {
    let observations = Rc::new(Cell::new(0));
    let mut guard = CnpSemanticLaunchGuard {
        creator_process: std::process::id().wrapping_add(1),
        custody: None,
        slot: Some(Box::new(Slot {
            observations: Rc::clone(&observations),
        })),
        supervision_id: U64::new(1),
    };
    let mut counter = PreparationCounter::new(usize::MAX);
    counter.add(13)?;

    let result = guard.charge_retained_storage_precredit_data(None, None, &mut counter);
    // The deliberate test-only origin substitution must not cause foreign Drop
    // to leak the fixture's own slot. This constructs no Child or live authority.
    guard.creator_process = std::process::id();

    assert_eq!(result, Err(RuntimeError::ForeignAuthority));
    assert_eq!(observations.get(), 0);
    assert_eq!(counter.finish().known_requested_bytes(), 13);
    Ok(())
}

#[test]
fn actual_read_owner_busy_loan_refuses_without_reviving_currentness()
-> Result<(), Box<dyn std::error::Error>> {
    let owner = Rc::new(ReadOwner::new(U64::new(7)));
    let loan = ReadCall::begin(Rc::clone(&owner))?;
    assert_eq!(owner.storage_precredit_data(), Err(RuntimeError::OwnerBusy));
    loan.finish(false);

    // Revocation does not destroy backing. Observation neither clears that
    // revocation nor obtains another read operation or native permission.
    owner.storage_precredit_data()?;
    assert!(ReadCall::begin(Rc::clone(&owner)).is_err());
    Ok(())
}
