//! Preserves actual failed-World ownership and independent refusal history.

use super::*;

impl NativePoolRefusal {
    /// Moves only the actual committed World retained by this refusal.
    ///
    /// The original first cause and independent postcut remain in this report.
    /// This neither reclaims an assignment nor creates a loan or new authority.
    pub fn take_retained_world(&mut self) -> Option<AuthenticatedNativeWorldClaim> {
        self._retained.as_mut()?._world.take()
    }

    /// Borrows a later failure to deliver this World's genuine cleanup custody.
    #[must_use]
    pub fn world_delivery_error(&self) -> Option<&ServiceBirthError> {
        self._retained.as_ref()?.delivery.as_ref()
    }

    /// Retains the first custody-delivery refusal beside the initiating report.
    ///
    /// This changes diagnostics only; it issues no World or cleanup permission.
    pub fn retain_world_delivery_error(&mut self, error: ServiceBirthError) {
        let retained = self._retained.get_or_insert_with(|| RetainedClaim {
            _pool: None,
            _source: None,
            _dispatcher: None,
            _world: None,
            _window: None,
            delivery: None,
            receiver: None,
        });
        retained.delivery.get_or_insert(error);
    }

    /// Borrows the fixed receiving-stage refusal independently of first/post.
    #[must_use]
    pub fn world_receiver_refusal(&self) -> Option<&'static str> {
        self._retained.as_ref()?.receiver
    }

    /// Retains the first receiving-stage refusal without allocating a carrier.
    pub fn retain_world_receiver_refusal(&mut self, operation: &'static str) {
        let retained = self._retained.get_or_insert_with(|| RetainedClaim {
            _pool: None,
            _source: None,
            _dispatcher: None,
            _world: None,
            _window: None,
            delivery: None,
            receiver: None,
        });
        retained.receiver.get_or_insert(operation);
    }

    /// Reports a proven World admission refusal before any assignment published.
    ///
    /// This factual classification grants no retry authority. Callback refusal,
    /// poisoned synchronization, descriptor effects and negative postcuts never
    /// acquire it, even when no issued holder is present in this error.
    #[must_use]
    pub fn world_assignment_was_refused(&self) -> bool {
        self.world_assignment_refused && self.after.is_none() && self._retained.is_none()
    }
}
