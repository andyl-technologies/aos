//! Preserves actual failed-World ownership and independent refusal history.

use super::*;

#[derive(Debug)]
pub(super) struct RetainedClaim {
    owner: RetainedOwner,
    delivery: Option<ServiceBirthError>,
    receiver: Option<&'static str>,
}

// Each issuer can transfer exactly one actual owner into its refusal. Keep the
// alternatives inline so exhaustion cannot require another allocation, without
// reserving simultaneous storage for owners that no issuer can produce together.
#[derive(Debug)]
enum RetainedOwner {
    None,
    Pool {
        _pool: AuthenticatedNativePoolPurpose,
    },
    Source {
        _source: AuthenticatedSourceHostPurpose,
    },
    Dispatcher {
        _dispatcher: super::super::AuthenticatedTargetDispatcherPurpose,
    },
    World {
        world: Option<AuthenticatedNativeWorldClaim>,
    },
    Window {
        _window: AuthenticatedNativeNodeHostWindow,
    },
}

impl RetainedClaim {
    fn new(owner: RetainedOwner) -> Self {
        Self {
            owner,
            delivery: None,
            receiver: None,
        }
    }

    pub(super) fn source(source: AuthenticatedSourceHostPurpose) -> Self {
        Self::new(RetainedOwner::Source { _source: source })
    }

    pub(super) fn pool(pool: AuthenticatedNativePoolPurpose) -> Self {
        Self::new(RetainedOwner::Pool { _pool: pool })
    }

    pub(super) fn dispatcher(
        dispatcher: super::super::AuthenticatedTargetDispatcherPurpose,
    ) -> Self {
        Self::new(RetainedOwner::Dispatcher {
            _dispatcher: dispatcher,
        })
    }

    pub(super) fn world(world: AuthenticatedNativeWorldClaim) -> Self {
        Self::new(RetainedOwner::World { world: Some(world) })
    }

    pub(super) fn window(window: AuthenticatedNativeNodeHostWindow) -> Self {
        Self::new(RetainedOwner::Window { _window: window })
    }
}

impl NativePoolRefusal {
    /// Moves only the actual committed World retained by this refusal.
    ///
    /// The original first cause and independent postcut remain in this report.
    /// This neither reclaims an assignment nor creates a loan or new authority.
    pub fn take_retained_world(&mut self) -> Option<AuthenticatedNativeWorldClaim> {
        match &mut self._retained.as_mut()?.owner {
            RetainedOwner::World { world } => world.take(),
            _ => None,
        }
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
        let retained = self
            ._retained
            .get_or_insert_with(|| RetainedClaim::new(RetainedOwner::None));
        retained.delivery.get_or_insert(error);
    }

    /// Borrows the fixed receiving-stage refusal independently of first/post.
    #[must_use]
    pub fn world_receiver_refusal(&self) -> Option<&'static str> {
        self._retained.as_ref()?.receiver
    }

    /// Retains the first receiving-stage refusal without allocating a carrier.
    pub fn retain_world_receiver_refusal(&mut self, operation: &'static str) {
        let retained = self
            ._retained
            .get_or_insert_with(|| RetainedClaim::new(RetainedOwner::None));
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
