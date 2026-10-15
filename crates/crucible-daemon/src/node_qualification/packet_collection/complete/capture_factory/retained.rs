//! Holds one synchronous, original actor loan for requested-storage admission.
//!
//! The loan carries data, not input/native permission. Its guard cannot outlive
//! the factory, and the actor retains immutable scene/grant borrows until the
//! original Core call returns or unwinds. No public byte setter exists.

use super::*;
use crate::node_qualification::packet_collection::complete::{
    execution::PacketCompleteExecutionScene, retained::Counter,
};

pub(super) struct ActorStorageLoanState {
    actor: *const (),
    scene: *const (),
    retained: usize,
    entered: bool,
}

impl ActorStorageLoanState {
    fn enter(&mut self) -> Result<(), StateError> {
        if self.entered {
            return Err(refused("complete actor storage loan was already consumed"));
        }
        self.entered = true;
        Ok(())
    }
}

fn retained_loan_data(
    held: Option<&ActorStorageLoanState>,
    scene: *const (),
) -> Result<usize, StateError> {
    let loan = held
        .filter(|loan| loan.entered && !loan.actor.is_null() && loan.scene == scene)
        .ok_or_else(|| refused("complete actor storage loan is stale or foreign"))?;
    Ok(loan.retained)
}

pub(in crate::node_qualification::packet_collection::complete) struct ActorStorageLoan<'a> {
    factory: &'a PacketCompleteCaptureFactory,
    actor: *const (),
}

impl Drop for ActorStorageLoan<'_> {
    fn drop(&mut self) {
        if self.factory.authenticate_storage_origin().is_err() {
            return;
        }
        if let Ok(mut held) = self.factory.actor_storage_loan.try_borrow_mut()
            && held.as_ref().is_some_and(|loan| loan.actor == self.actor)
        {
            *held = None;
        }
    }
}

impl PacketCompleteCaptureFactory {
    pub(in crate::node_qualification::packet_collection::complete) fn daemon_storage_limit(
        &self,
    ) -> usize {
        self.limits.state.maximum_total_content_bytes
    }

    pub(super) fn authenticate_storage_origin(&self) -> Result<(), StateError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(refused(
                "complete factory storage belongs to another creator",
            ));
        }
        Ok(())
    }

    pub(in crate::node_qualification::packet_collection::complete) fn loan_actor_storage(
        &self,
        scene: &Rc<PacketCompleteExecutionScene>,
        actor: *const (),
        retained: usize,
    ) -> Result<ActorStorageLoan<'_>, StateError> {
        self.current()?;
        let original = self.authority.original_execution_scene().map_err(error)?;
        if actor.is_null() || !Rc::ptr_eq(&original, scene) {
            return Err(refused(
                "complete storage loan is not the original actor scene",
            ));
        }
        let mut held = self.actor_storage_loan.try_borrow_mut().map_err(error)?;
        if held.is_some() {
            return Err(refused(
                "complete actor storage loan is already outstanding",
            ));
        }
        *held = Some(ActorStorageLoanState {
            actor,
            scene: Rc::as_ptr(scene).cast(),
            retained,
            entered: false,
        });
        Ok(ActorStorageLoan {
            factory: self,
            actor,
        })
    }

    pub(super) fn enter_actor_storage_loan(&self) -> Result<(), StateError> {
        self.authenticate_storage_origin()?;
        let mut held = self.actor_storage_loan.try_borrow_mut().map_err(error)?;
        let loan = held
            .as_mut()
            .ok_or_else(|| refused("complete capture has no original actor storage loan"))?;
        loan.enter()
    }

    pub(super) fn actual_daemon_requested_storage(
        &self,
        maximum: usize,
    ) -> Result<usize, StateError> {
        self.current()?;
        let bytes = self.actual_archive_daemon_requested_storage(maximum, true)?;
        self.current()?;
        Ok(bytes)
    }

    // The origin flag comes only from Core's authenticated private validation
    // purpose. Cold loads have no original actor requirement or kernel callbacks.
    pub(super) fn actual_archive_daemon_requested_storage(
        &self,
        maximum: usize,
        original_write: bool,
    ) -> Result<usize, StateError> {
        self.authenticate_storage_origin()?;
        let scene = self
            .authority
            .original_execution_scene_storage_data()
            .map_err(error)?;
        let held = self.actor_storage_loan.try_borrow().map_err(error)?;
        let actor = match (held.as_ref(), scene.as_ref()) {
            (Some(loan), Some(scene)) => {
                Some(retained_loan_data(Some(loan), Rc::as_ptr(scene).cast())?)
            }
            (None, _) if !original_write => None,
            _ => {
                return Err(refused(
                    "original archive actor storage loan is absent or foreign",
                ));
            }
        };
        let mut counter = Counter::new(maximum);
        counter
            .shared_header(
                (self as *const Self).cast(),
                size_of::<Self>(),
                std::mem::align_of::<Self>(),
            )
            .map_err(error)?;
        if let Some(actor) = actor {
            counter.add(actor).map_err(error)?;
        }
        if counter.rc(&self.authority).map_err(error)? {
            self.authority
                .charge_retained_storage(&mut counter)
                .map_err(error)?;
        }
        if counter.rc(&self.plan).map_err(error)? {
            counter
                .add(
                    self.plan
                        .retained_allocation_bytes_excluding_authority()
                        .map_err(error)?,
                )
                .map_err(error)?;
        }
        if let Some(scene) = scene.as_ref()
            && counter.rc(scene).map_err(error)?
        {
            scene.charge_retained_storage(&mut counter).map_err(error)?;
        }
        // Actual cache rows are counted by the caller; native/source and Host
        // backings remain distinct rows in the same full requested-storage sum.
        self.authenticate_storage_origin()?;
        Ok(counter.bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_loan_requires_original_entry_and_scene_and_cannot_reenter() -> Result<(), StateError>
    {
        // Real independent allocations exercise the private data occurrence.
        // No source, actor runtime, native effect or Capture right is mocked.
        let actor = Box::new(7u8);
        let scene = Rc::new(());
        let foreign = Rc::new(());
        let mut loan = ActorStorageLoanState {
            actor: std::ptr::from_ref(actor.as_ref()).cast(),
            scene: Rc::as_ptr(&scene).cast(),
            retained: 123,
            entered: false,
        };
        assert!(retained_loan_data(None, Rc::as_ptr(&scene).cast()).is_err());
        assert!(retained_loan_data(Some(&loan), Rc::as_ptr(&scene).cast()).is_err());
        loan.enter()?;
        assert_eq!(
            retained_loan_data(Some(&loan), Rc::as_ptr(&scene).cast())?,
            123
        );
        assert!(retained_loan_data(Some(&loan), Rc::as_ptr(&foreign).cast()).is_err());
        assert!(loan.enter().is_err());
        Ok(())
    }
}
