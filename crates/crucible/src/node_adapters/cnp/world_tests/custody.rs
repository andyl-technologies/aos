//! Finite whole-world custody reserved before either actual provider is launched.

use super::*;
use crate::node_contract::{RuntimeCustodySlot, RuntimeError, WholeRuntimeCustody};

pub(super) struct WorldSupervisor {
    retained: Rc<RefCell<Vec<WholeRuntimeCustody>>>,
    original: Rc<RefCell<Option<ActivationRecord>>>,
    limits: RuntimeLimits,
}

struct WorldSlot {
    retained: Rc<RefCell<Vec<WholeRuntimeCustody>>>,
    original: Rc<RefCell<Option<ActivationRecord>>>,
    limits: RuntimeLimits,
}

impl RuntimeCustodySlot for WorldSlot {
    fn validate_world(
        &self,
        record: &ActivationRecord,
        limits: RuntimeLimits,
    ) -> Result<(), RuntimeError> {
        if self.original.borrow().as_ref() != Some(record) || limits != self.limits {
            return Err(RuntimeError::InvalidReceipt);
        }
        Ok(())
    }

    fn retain(self: Box<Self>, custody: WholeRuntimeCustody) {
        let mut retained = self.retained.borrow_mut();
        assert!(
            retained.is_empty(),
            "the finite world slot was reserved once"
        );
        assert_eq!(
            custody.activation(),
            self.original.borrow().as_ref().unwrap()
        );
        assert_eq!(custody.limits(), self.limits);
        assert_eq!(retained.capacity(), 1);
        retained.push(custody);
    }
}

impl WorldSupervisor {
    pub(super) fn reserve(limits: RuntimeLimits) -> (Self, Box<dyn RuntimeCustodySlot>) {
        let retained = Rc::new(RefCell::new(Vec::with_capacity(1)));
        let original = Rc::new(RefCell::new(None));
        let slot = WorldSlot {
            retained: Rc::clone(&retained),
            original: Rc::clone(&original),
            limits,
        };
        (
            Self {
                retained,
                original,
                limits,
            },
            Box::new(slot),
        )
    }

    pub(super) fn install_original(&self, record: &ActivationRecord) {
        assert!(self.original.borrow().is_none());
        *self.original.borrow_mut() = Some(record.clone());
    }

    pub(super) fn take(&self) -> WholeRuntimeCustody {
        let mut retained = self.retained.borrow_mut();
        assert_eq!(retained.len(), 1);
        let custody = retained.pop().unwrap();
        assert_eq!(
            custody.activation(),
            self.original.borrow().as_ref().unwrap()
        );
        assert_eq!(custody.limits(), self.limits);
        custody
    }
}
