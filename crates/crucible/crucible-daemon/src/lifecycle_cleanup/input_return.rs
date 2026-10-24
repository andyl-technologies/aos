//! Reserves one existing receiving-input destination before aliases escape.
//!
//! The witness consumes the actual registered output receiver and keeps the
//! existing queue alive. Its singleton latch excludes every other publisher.
//! Delivery constructs the actual input outside the short control lock, then
//! moves it into that exact epoch without a fallible ownership handoff.

use super::*;
use crate::imported_checkpoint::{ImportedCheckpointBasis, ImportedCheckpointMaintenance};
use crate::packaged_qemu_executor::ServiceRetirementInput;

/// Keeps the existing singleton input destination for one actual receiver.
///
/// This move-only witness creates no receiver count, allocation or authority.
/// It must either publish its actual aliases or be canceled before they exist.
/// Dropping it alone cannot certify destruction or acknowledge the receiver.
#[must_use = "publish the actual aliases or cancel before alias creation"]
pub struct ServiceInputReturn {
    pub(super) queue: Arc<LifecycleCleanupQueue>,
    pub(super) index: usize,
    pub(super) epoch: u64,
    receiver: ServiceMainReceiver,
}

impl ServiceMainReceiver {
    /// Reserves its same Main input singleton before taking any live aliases.
    ///
    /// # Errors
    /// Returns this same receiver on unavailable, stale, retiring, borrowed,
    /// poisoned or occupied storage. No input or native effect occurs first.
    pub(crate) fn prepare_input_return(
        self,
    ) -> Result<ServiceInputReturn, (Self, ServiceMainPreclaimError)> {
        let Some(queue) = self.key.queue.upgrade() else {
            return Err((self, refusal("input return containing Main is unavailable")));
        };
        let Some(slot) = queue.slots.get(self.key.index) else {
            return Err((self, refusal("input return role is absent")));
        };
        let mut cell = match slot.cell.try_lock() {
            Ok(cell) => cell,
            Err(_) => {
                return Err((
                    self,
                    refusal("input return storage is borrowed or poisoned"),
                ));
            }
        };
        if !self.can_reserve_input_return()
            || slot.epoch.load(Ordering::Acquire) != self.key.epoch
            || cell.epoch != self.key.epoch
            || !slot.is(CleanupPhase::Reserved)
            || !slot.work_is_open()
            || slot.external_receivers.load(Ordering::Acquire) == 0
            || cell.retirement_input.is_some()
            || cell.retirement_input_reserved
        {
            return Err((
                self,
                refusal("same input return singleton is stale or occupied"),
            ));
        }
        cell.retirement_input_reserved = true;
        let index = self.key.index;
        let epoch = self.key.epoch;
        drop(cell);
        Ok(ServiceInputReturn {
            queue,
            index,
            epoch,
            receiver: self,
        })
    }
}

impl ServiceInputReturn {
    /// Returns the same receiver before any receiving aliases were constructed.
    ///
    /// This cancels only fixed metadata. It acknowledges no alias destruction,
    /// reopens no work and preserves quarantine if the control mutex is poisoned.
    pub(crate) fn cancel_before_aliases(self) -> ServiceMainReceiver {
        let Self {
            queue,
            index,
            epoch: _,
            receiver,
        } = self;
        let slot = &queue.slots[index];
        let (mut cell, poisoned) = match slot.cell.lock() {
            Ok(cell) => (cell, false),
            Err(poison) => (poison.into_inner(), true),
        };
        cell.retirement_input_reserved = false;
        if poisoned {
            slot.publish(CleanupPhase::DestructionRefused);
        }
        drop(cell);
        drop(queue);
        receiver
    }

    /// Publishes the actual maintenance aliases into their reserved Main cell.
    ///
    /// The private pre-exposure constructor retained this exact queue, epoch,
    /// receiver and exclusive singleton. The receiver's outstanding debt bars
    /// role reuse. Conversion below moves existing owners without native work;
    /// no callback or destructor executes under the control mutex. Matching
    /// poison retains input and quarantine together. Body publication follows.
    pub(crate) fn return_maintenance(
        self,
        basis: ImportedCheckpointBasis,
        maintenance: ImportedCheckpointMaintenance<'_>,
        semantic_shutdown: Option<crucible_engine::SchedulerError>,
    ) {
        let Self {
            queue,
            index,
            epoch: _,
            receiver,
        } = self;
        let input = ServiceRetirementInput::from_maintenance(
            basis,
            maintenance,
            receiver,
            semantic_shutdown,
        );
        let slot = &queue.slots[index];
        let (mut cell, poisoned) = match slot.cell.lock() {
            Ok(cell) => (cell, false),
            Err(poison) => (poison.into_inner(), true),
        };
        // Only this witness can publish after reserving the singleton. Other
        // adoption paths reject the latch, and the receiver prevents reuse.
        cell.retirement_input = Some(input);
        cell.retirement_input_reserved = false;
        if poisoned {
            slot.publish(CleanupPhase::DestructionRefused);
        }
        drop(cell);
        // Main now owns the actual input; it must not own a strong queue cycle.
        drop(queue);
    }
}

impl std::fmt::Debug for ServiceInputReturn {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServiceInputReturn")
            .field("index", &self.index)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

fn refusal(message: &'static str) -> ServiceMainPreclaimError {
    ServiceMainPreclaimError::Role(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_input_return_keeps_the_same_unacknowledged_receiver() {
        let receiver = ServiceMainReceiver::new_registered(ServiceMainPreclaim {
            queue: Weak::new(),
            index: 3,
            epoch: 7,
        });
        let Err((receiver, error)) = receiver.prepare_input_return() else {
            panic!("an unavailable negative-only selector cannot reserve input");
        };

        assert_eq!(receiver.key.index, 3);
        assert_eq!(receiver.key.epoch, 7);
        assert!(receiver.key.queue.upgrade().is_none());
        assert!(receiver.can_reserve_input_return());
        assert!(matches!(
            error,
            ServiceMainPreclaimError::Role("input return containing Main is unavailable")
        ));
        drop(receiver);
    }
}
