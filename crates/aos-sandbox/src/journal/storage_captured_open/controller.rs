//! Captures only a genuine Controller Session's fixed protected journal.
//!
//! Initial boot and fresh Start Network keep distinct opaque lenders. Their
//! private adapters enter the same native opener, replay and one-way handoff;
//! neither path can adopt the other's operation, scope, UID or receiving grant.

use super::*;
use crate::controller_resource_reservation::ControllerInitialBrokerSessionOwnerLinkV1;
use crate::{
    ControllerInitialBrokerSessionClosedV1, ControllerInitialBrokerSessionReceivingLoanV1,
    ControllerInitialBrokerSessionRoleV1, ResourceReservationErrorV1,
    StartResourceSessionOpeningLoanV2, StartResourceSessionOpeningOwnerLinkV2,
};

pub(super) const fn directory(role: ControllerInitialBrokerSessionRoleV1) -> &'static str {
    match role {
        ControllerInitialBrokerSessionRoleV1::Host => "/var/lib/aos/sandboxd/broker-session/host",
        ControllerInitialBrokerSessionRoleV1::Mount => "/var/lib/aos/sandboxd/broker-session/mount",
        ControllerInitialBrokerSessionRoleV1::Storage => "/var/lib/aos/sandboxd/broker-session/storage",
        ControllerInitialBrokerSessionRoleV1::Network => "/var/lib/aos/sandboxd/broker-session/network",
    }
}

// Only these two actual loan types can enter this adapter. Geometry and role
// selectors remain DATA; each native stage still calls its genuine lender.
trait ControllerCaptureReceivingV4 {
    type Link;
    type Failure: Error + 'static;

    fn role(&self) -> ControllerInitialBrokerSessionRoleV1;
    fn recipe(role: ControllerInitialBrokerSessionRoleV1, uid: u32) -> ProtectedCapturedJournalRecipeV1;
    fn owner_link(&self) -> Self::Link;
    fn same_owner(left: &Self::Link, right: &Self::Link) -> bool;
    fn controller_uid(&self) -> Result<u32, Self::Failure>;
    fn enter_preparation(&mut self, role: ControllerInitialBrokerSessionRoleV1) -> Result<(), Self::Failure>;
    fn enter_replay(&mut self, role: ControllerInitialBrokerSessionRoleV1) -> Result<(), Self::Failure>;
    fn enter_take(&mut self, role: ControllerInitialBrokerSessionRoleV1, opening: &StorageNativeOpeningOwnerLinkV1) -> Result<(), Self::Failure>;
}

impl ControllerCaptureReceivingV4 for ControllerInitialBrokerSessionReceivingLoanV1<'_> {
    type Link = ControllerInitialBrokerSessionOwnerLinkV1;
    type Failure = ControllerInitialBrokerSessionClosedV1;

    fn role(&self) -> ControllerInitialBrokerSessionRoleV1 { self.actual_role_v1() }
    fn recipe(role: ControllerInitialBrokerSessionRoleV1, uid: u32) -> ProtectedCapturedJournalRecipeV1 {
        ProtectedCapturedJournalRecipeV1::JoinedControllerSession(Some((role, uid)))
    }
    fn owner_link(&self) -> Self::Link { self.owner_link_v1() }
    fn same_owner(left: &Self::Link, right: &Self::Link) -> bool { left.same_owner_v1(right) }
    fn controller_uid(&self) -> Result<u32, Self::Failure> { self.controller_uid_v1() }
    fn enter_preparation(&mut self, role: ControllerInitialBrokerSessionRoleV1) -> Result<(), Self::Failure> { self.enter_journal_preparation_once_v1(role) }
    fn enter_replay(&mut self, role: ControllerInitialBrokerSessionRoleV1) -> Result<(), Self::Failure> { self.enter_journal_replay_once_v1(role) }
    fn enter_take(&mut self, role: ControllerInitialBrokerSessionRoleV1, opening: &StorageNativeOpeningOwnerLinkV1) -> Result<(), Self::Failure> { self.enter_journal_take_once_v1(role, opening) }
}

impl ControllerCaptureReceivingV4 for StartResourceSessionOpeningLoanV2<'_> {
    type Link = StartResourceSessionOpeningOwnerLinkV2;
    type Failure = ResourceReservationErrorV1;

    fn role(&self) -> ControllerInitialBrokerSessionRoleV1 { self.actual_role_v2() }
    fn recipe(role: ControllerInitialBrokerSessionRoleV1, uid: u32) -> ProtectedCapturedJournalRecipeV1 {
        ProtectedCapturedJournalRecipeV1::JoinedStartResourceSession(Some((role, uid)))
    }
    fn owner_link(&self) -> Self::Link { self.owner_link_v2() }
    fn same_owner(left: &Self::Link, right: &Self::Link) -> bool { left.same_owner_v2(right) }
    fn controller_uid(&self) -> Result<u32, Self::Failure> { self.controller_uid_v2() }
    fn enter_preparation(&mut self, role: ControllerInitialBrokerSessionRoleV1) -> Result<(), Self::Failure> {
        if role != self.role() { return Err(ResourceReservationErrorV1::Conflict); }
        self.enter_journal_preparation_once_v2()
    }
    fn enter_replay(&mut self, role: ControllerInitialBrokerSessionRoleV1) -> Result<(), Self::Failure> {
        if role != self.role() { return Err(ResourceReservationErrorV1::Conflict); }
        self.enter_journal_replay_once_v2()
    }
    fn enter_take(&mut self, role: ControllerInitialBrokerSessionRoleV1, opening: &StorageNativeOpeningOwnerLinkV1) -> Result<(), Self::Failure> {
        if role != self.role() { return Err(ResourceReservationErrorV1::Conflict); }
        self.enter_journal_take_once_v2(opening)
    }
}

struct ControllerCapturedJournalOriginalV4<L, E> {
    inner: FixedProtectedCapturedJournalOpenV1,
    attempted: bool,
    prepared_role: Option<ControllerInitialBrokerSessionRoleV1>,
    owner: Option<L>,
    replay_binding: Option<Result<(), JournalError>>,
    take_binding: Option<Result<(), JournalError>>,
    entry: Option<Result<(), E>>,
    coordinates: Option<Result<(), E>>,
    replay_entry: Option<Result<(), E>>,
    take_entry: Option<Result<(), E>>,
}

impl<L, E: Error + 'static> ControllerCapturedJournalOriginalV4<L, E> {
    const fn new() -> Self {
        Self {
            inner: FixedProtectedCapturedJournalOpenV1::with_recipe(
                ProtectedCapturedJournalRecipeV1::JoinedControllerSession(None),
            ),
            attempted: false, prepared_role: None, owner: None, replay_binding: None, take_binding: None,
            entry: None, coordinates: None, replay_entry: None, take_entry: None,
        }
    }

    fn prepare_once<T: ControllerCaptureReceivingV4<Link = L, Failure = E>>(
        &mut self, limits: JournalLimits, mode: CapturedJournalOpenModeV1, receiving: &mut T,
    ) {
        if self.attempted { self.inner.closed.get_or_insert(JournalError::ProtectedBoundary); return; }
        self.attempted = true;
        let role = receiving.role();
        self.prepared_role = Some(role);
        self.owner = Some(receiving.owner_link());
        self.entry = Some(receiving.enter_preparation(role));
        if !matches!(self.entry, Some(Ok(()))) { return; }
        self.coordinates = Some(receiving.controller_uid().map(|uid| {
            self.inner.recipe = T::recipe(role, uid);
        }));
        if matches!(self.coordinates, Some(Ok(()))) { self.inner.prepare_once(limits, mode); }
    }

    fn replay_once<T: ControllerCaptureReceivingV4<Link = L, Failure = E>>(&mut self, receiving: &mut T) {
        if self.replay_binding.is_some() || self.replay_entry.is_some() || self.failure().is_some() {
            self.inner.closed.get_or_insert(JournalError::ProtectedBoundary); return;
        }
        let Some(role) = self.prepared_role else {
            self.inner.closed.get_or_insert(JournalError::ProtectedBoundary); return;
        };
        self.replay_binding = Some(self.owner.as_ref()
            .filter(|owner| T::same_owner(owner, &receiving.owner_link()))
            .map(|_| ()).ok_or(JournalError::ProtectedBoundary));
        if !matches!(self.replay_binding, Some(Ok(()))) { return; }
        self.replay_entry = Some(receiving.enter_replay(role));
        if matches!(self.replay_entry, Some(Ok(()))) { self.inner.replay_once(); }
    }

    fn replay_ready(&self) -> bool { self.failure().is_none() && self.inner.replay_ready() }

    fn take_opened<T: ControllerCaptureReceivingV4<Link = L, Failure = E>>(&mut self, receiving: &mut T) -> Option<(Journal, RecoveryReport)> {
        if self.take_entry.is_some() || !self.replay_ready() { return None; }
        let Some(role) = self.prepared_role else { return None; };
        self.take_binding = Some(self.owner.as_ref()
            .filter(|owner| T::same_owner(owner, &receiving.owner_link()))
            .map(|_| ()).ok_or(JournalError::ProtectedBoundary));
        if !matches!(self.take_binding, Some(Ok(()))) { return None; }
        self.take_entry = Some(receiving.enter_take(role, self.inner.owner_link.as_ref()?));
        if !matches!(self.take_entry, Some(Ok(()))) { return None; }
        self.inner.take_opened()
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        fn original<E: Error + 'static>(slot: &Option<Result<(), E>>) -> Option<&(dyn Error + 'static)> {
            slot.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn Error)
        }
        original(&self.entry).or_else(|| original(&self.coordinates))
            .or_else(|| original(&self.replay_binding)).or_else(|| original(&self.replay_entry))
            .or_else(|| original(&self.take_binding)).or_else(|| original(&self.take_entry))
            .or_else(|| self.inner.failure())
    }
}

fn fixed_preparation_demand<T>(role: ControllerInitialBrokerSessionRoleV1, retained_append: bool) -> Result<aos_sandbox_core::ResourceVector, aos_sandbox_core::AccountingError> {
    let demand = ProtectedWriterOpenOriginalsV1::fixed_writable_preparation_demand_v1::<T>(
        7, (directory(role).len() + "session.journal".len()) as u16,
    )?;
    if !retained_append { return Ok(demand); }
    demand.checked_add(
        crate::journal::native_interval::captured::CapturedAppendOwnerV1::construction_demand_v1()
            .ok_or(aos_sandbox_core::AccountingError::ArithmeticOverflow {
                dimension: aos_sandbox_core::ResourceDimension::MemoryBytes,
            })?,
    )
}

macro_rules! controller_captured_facade {
    ($name:ident, $loan:ident, $link:ident, $failure:ident, $taken:ident, $receiving_link:ident, $opening_link:ident) => {
        impl $name {
            /// Creates inert destinations without allocation or native admission.
            #[must_use]
            pub const fn new() -> Self { Self(ControllerCapturedJournalOriginalV4::new()) }

            /// Enters this actual lender's paid fixed preparation before native IO.
            pub fn prepare_once(&mut self, limits: JournalLimits, mode: CapturedJournalOpenModeV1, receiving: &mut $loan<'_>) {
                self.0.prepare_once(limits, mode, receiving);
            }

            /// Borrows the same held extent without granting replay.
            #[must_use]
            pub fn captured_extent(&self) -> Option<&ProtectedJournalPreopenReplayExtentV1> {
                if self.failure().is_some() { None } else { self.0.inner.captured_extent() }
            }

            /// Enters the same lender's separately prepaid canonical replay.
            pub fn replay_once(&mut self, receiving: &mut $loan<'_>) { self.0.replay_once(receiving); }

            /// Reports completed mechanical replay without an authority grant.
            #[must_use]
            pub fn replay_ready(&self) -> bool { self.0.replay_ready() }

            /// Moves the actual Journal only after same-owner gates and native posts.
            #[must_use]
            pub fn take_opened(&mut self, receiving: &mut $loan<'_>) -> Option<(Journal, RecoveryReport)> { self.0.take_opened(receiving) }

            /// Reports the actual positive one-way native handoff.
            #[must_use]
            pub fn $taken(&self) -> bool { self.failure().is_none() && self.0.inner.was_taken_positive() }

            /// Borrows the earliest native or actual original-lender refusal.
            #[must_use]
            pub fn failure(&self) -> Option<&(dyn Error + 'static)> { self.0.failure() }

            pub(crate) fn $receiving_link(&self) -> Option<&$link> { self.0.owner.as_ref() }
            pub(crate) fn $opening_link(&self) -> Option<&StorageNativeOpeningOwnerLinkV1> { self.0.inner.owner_link.as_ref() }
        }

        impl Default for $name { fn default() -> Self { Self::new() } }
    };
}

/// Retains a genuine initial boot Session's fixed native opening and failed prefixes.
#[must_use = "retain the actual opening through all independently owed posts"]
pub struct ControllerBrokerSessionCapturedJournalOpenV1(ControllerCapturedJournalOriginalV4<ControllerInitialBrokerSessionOwnerLinkV1, ControllerInitialBrokerSessionClosedV1>);

controller_captured_facade!(ControllerBrokerSessionCapturedJournalOpenV1,
    ControllerInitialBrokerSessionReceivingLoanV1, ControllerInitialBrokerSessionOwnerLinkV1,
    ControllerInitialBrokerSessionClosedV1, was_taken_positive_v1, receiving_owner_link_v1, opening_owner_link_v1);

impl ControllerBrokerSessionCapturedJournalOpenV1 {
    /// Prices one compiled Controller Session path before actual role admission.
    ///
    /// # Errors
    /// Refuses unrepresentable native or writable construction geometry.
    #[must_use]
    pub fn fixed_preparation_demand(role: ControllerInitialBrokerSessionRoleV1) -> Result<aos_sandbox_core::ResourceVector, aos_sandbox_core::AccountingError> {
        fixed_preparation_demand::<Self>(role, matches!(role, ControllerInitialBrokerSessionRoleV1::Host | ControllerInitialBrokerSessionRoleV1::Storage))
    }
}

/// Retains only the fresh Start Network lender's fixed native Session opening.
#[must_use = "retain the actual Start opening through all independently owed posts"]
pub struct ControllerStartResourceSessionCapturedJournalOpenV4(ControllerCapturedJournalOriginalV4<StartResourceSessionOpeningOwnerLinkV2, ResourceReservationErrorV1>);

controller_captured_facade!(ControllerStartResourceSessionCapturedJournalOpenV4,
    StartResourceSessionOpeningLoanV2, StartResourceSessionOpeningOwnerLinkV2,
    ResourceReservationErrorV1, was_taken_positive_v4, receiving_owner_link_v2, opening_owner_link_v2);

impl ControllerStartResourceSessionCapturedJournalOpenV4 {
    /// Prices the sole fixed Network path without constructing a Start lender.
    ///
    /// # Errors
    /// Refuses unrepresentable native or writable construction geometry.
    #[must_use]
    pub fn fixed_preparation_demand(role: ControllerInitialBrokerSessionRoleV1) -> Result<aos_sandbox_core::ResourceVector, aos_sandbox_core::AccountingError> {
        fixed_preparation_demand::<Self>(role, true)
    }
}
