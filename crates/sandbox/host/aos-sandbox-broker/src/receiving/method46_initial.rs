//! Retains either separately funded manual METHOD46 initial-floor service.
//!
//! The closed purpose selects custody destinations only. The same real PID1
//! channel, Parent06 M/F partition, four-entry initial table, exact profile,
//! process and cgroup observations must authenticate before any debit. The
//! Controller and Storage services retain separate originals and MAC domains.
//! No request, signature, decoded vector or role enum constructs a paid source.

use std::error::Error;
use std::fmt;
use std::os::fd::OwnedFd;

use aos_linux_descriptors::pidfd::PidFd;
use aos_sandbox_linux::cgroup::{
    CgroupPopulationMonitorOriginalV3, ExactCgroupMembershipReadbackV1,
    Method46StoppedOwnerCgroupOriginalV1, Method46StoppedOwnerCgroupV1,
};
use aos_sandbox_model::ResourceVector;

use super::fixed_service_operation::FixedServiceOperationClosedV4;
use super::fixed_service_receiving::{FixedServiceReceivingCaptureV1, FixedServiceRoleV1};

/// Selects one immutable manual service without authenticating its original.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Method46InitialServiceRoleV1 {
    /// Selects only the Controller Storage-client initial-floor service.
    ControllerStorageClient,
    /// Selects only the Storage broker initial-floor service.
    StorageBroker,
}

/// Reports a refused manual METHOD46 initial-floor receiver while its owner keeps cause.
#[derive(Clone, Copy, Debug, Default)]
pub struct Method46InitialReceivingClosedV1;

impl fmt::Display for Method46InitialReceivingClosedV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("original METHOD46 initial-floor receiving scope is closed")
    }
}

impl Error for Method46InitialReceivingClosedV1 {}

// The same receiver owns the actual fields. Only these finite manual-purpose adapters
// move its complete startup roles or project its authenticated comparison DATA.
impl<E: Copy + Default + Error + 'static> FixedServiceReceivingCaptureV1<E> {
    pub(super) fn take_method46_initial_roles_once_v1(
        &mut self,
    ) -> Option<Method46InitialStartupRolesV1> {
        if !matches!(
            self.role,
            FixedServiceRoleV1::Method46ControllerInitial
                | FixedServiceRoleV1::Method46StorageInitial
        ) || self.require_permanent_fd_coverage_v1().is_err()
        {
            return None;
        }
        let names = self.names.as_ref()?.as_ref().ok()?;
        let listener_index = names
            .iter()
            .position(|name| name == "aos-method46-initial-approval")?;
        let pid1_index = names
            .iter()
            .position(|name| name == "aos-method46-initial-pid1-image")?;
        let entries = self.entries.as_mut()?;
        if listener_index == pid1_index
            || entries[listener_index].is_none()
            || entries[pid1_index].is_none()
            || self.root_profile.is_none()
        {
            return None;
        }
        let listener = entries[listener_index].take();
        let pid1 = entries[pid1_index].take();
        let profile = self.root_profile.take();
        match (listener, pid1, profile) {
            (Some(listener), Some(pid1), Some(profile)) => Some(Method46InitialStartupRolesV1 {
                listener,
                pid1,
                profile: profile.into(),
            }),
            (listener, pid1, profile) => {
                // Preserve even an impossible partial handoff on this original.
                entries[listener_index] = listener;
                entries[pid1_index] = pid1;
                self.root_profile = profile;
                None
            }
        }
    }

    pub(super) fn method46_initial_origin_data_v1(
        &self,
    ) -> Result<Method46InitialOriginComparisonDataV1, E> {
        if !matches!(
            self.role,
            FixedServiceRoleV1::Method46ControllerInitial
                | FixedServiceRoleV1::Method46StorageInitial
        ) || self.require_permanent_fd_coverage_v1().is_err()
        {
            return Err(E::default());
        }
        let enrollment = self.enrollment.as_ref().ok_or(E::default())?;
        let packet = &self.parts[0].as_ref().ok_or(E::default())?.payload;
        let (node, resource_epoch) = enrollment.policy.image_identity_data_v1();
        let native = enrollment.identity.native_fields();
        let role = match self.role {
            FixedServiceRoleV1::Method46ControllerInitial => {
                Method46InitialServiceRoleV1::ControllerStorageClient
            }
            FixedServiceRoleV1::Method46StorageInitial => {
                Method46InitialServiceRoleV1::StorageBroker
            }
            _ => return Err(E::default()),
        };
        Ok(Method46InitialOriginComparisonDataV1 {
            role,
            node,
            resource_epoch,
            boot: native.boot,
            producer_invocation: native.invocation,
            recipient_invocation: enrollment.recipient_invocation,
            policy_digest: self.pair.policy_commitment().ok_or(E::default())?,
            parent_digest: packet[56..88].try_into().map_err(|_| E::default())?,
            unit_fragment_digest: packet[88..120].try_into().map_err(|_| E::default())?,
        })
    }
}

/// Owns the three startup roles from one completed original four-entry capture.
///
/// Fields and construction remain private. Moving the actual roles grants no
/// journal, key, floor, signature, readiness or publication authority.
#[must_use = "retain the original startup roles with their source receiver"]
pub struct Method46InitialStartupRolesV1 {
    pub(super) listener: OwnedFd,
    pub(super) pid1: OwnedFd,
    pub(super) profile: OwnedFd,
}

impl Method46InitialStartupRolesV1 {
    /// Moves the actual listener, PID1 image and profile originals without IO.
    ///
    /// The purpose-specific Domain startup constructor must independently
    /// authenticate these same originals while retaining the source receiver.
    #[must_use]
    pub fn into_parts_v1(self) -> (OwnedFd, OwnedFd, OwnedFd) {
        (self.listener, self.pid1, self.profile)
    }
}

/// Copies authenticated source comparison DATA without issuing a native scope.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Method46InitialOriginComparisonDataV1 {
    /// Selects the actual original manual service, never a caller-built grant.
    pub role: Method46InitialServiceRoleV1,
    /// Identifies the actual immutable policy's Node.
    pub node: [u8; 16],
    /// Identifies that same resource-policy epoch.
    pub resource_epoch: [u8; 16],
    /// Identifies the actual kernel boot joined by the retained pair.
    pub boot: [u8; 16],
    /// Identifies the actual PID1 producer invocation.
    pub producer_invocation: [u8; 16],
    /// Identifies the actual manual service recipient invocation.
    pub recipient_invocation: [u8; 16],
    /// Commits to the complete original image policy.
    pub policy_digest: [u8; 32],
    /// Commits to the complete original Parent06 partition and unit roster.
    pub parent_digest: [u8; 32],
    /// Commits to the original materialized manual service unit fragment.
    pub unit_fragment_digest: [u8; 32],
}

#[derive(Clone, Copy)]
enum First {
    Capture,
    Funding,
    Before,
    After,
    Helper,
    Population,
    StoppedOwner,
    Order,
}

/// Retains the genuine manual METHOD46 initial-floor source and receiving interval.
///
/// Construction is inert. Successful initial capture, complete native transfer,
/// Parent06 partition, same-process containment and real before/after owners
/// remain necessary. Failed originals and spent traffic are never reset.
///
/// The initial table is process-lifetime custody even before observation. The
/// caller retains this owner until process exit; dropping it aborts the process.
#[must_use = "retain original custody until process exit, including after owed posts"]
pub struct Method46InitialSourceCaptureV1 {
    original: FixedServiceReceivingCaptureV1<FixedServiceOperationClosedV4>,
    first: Option<First>,
    roles_taken: bool,
    before_attempted: bool,
    after_attempted: bool,
    origin: Option<Method46InitialOriginComparisonDataV1>,
    closed: Method46InitialReceivingClosedV1,
}

impl Method46InitialSourceCaptureV1 {
    /// Creates empty custody with the actual upper inline layout contribution.
    ///
    /// This performs no IO or allocation and supplies no receiving authority.
    #[must_use]
    pub fn new(role: Method46InitialServiceRoleV1, upper_inline_bytes: usize) -> Self {
        let original = match role {
            Method46InitialServiceRoleV1::ControllerStorageClient => {
                FixedServiceReceivingCaptureV1::new_method46_controller_initial_v1(
                    upper_inline_bytes,
                )
            }
            Method46InitialServiceRoleV1::StorageBroker => {
                FixedServiceReceivingCaptureV1::new_method46_storage_initial_v1(upper_inline_bytes)
            }
        };
        Self {
            original,
            first: None,
            roles_taken: false,
            before_attempted: false,
            after_attempted: false,
            origin: None,
            closed: Method46InitialReceivingClosedV1,
        }
    }

    /// Captures the sole original table and authenticates its complete source.
    ///
    /// # Errors
    /// Retains every reached table, descriptor, pair, profile and native result.
    /// Failed or repeated entry cannot probe another initial table or mode.
    pub fn capture_once_v1(&mut self) -> Result<(), Method46InitialReceivingClosedV1> {
        if self.first.is_some() {
            return Err(self.closed);
        }

        if self.original.capture_once().is_err() {
            self.first.get_or_insert(First::Capture);
            return Err(self.closed);
        }
        match self.original.method46_initial_origin_data_v1() {
            Ok(origin) => self.origin = Some(origin),
            Err(_) => {
                self.first.get_or_insert(First::Capture);
                return Err(self.closed);
            }
        }
        Ok(())
    }

    /// Moves only the three roles from this completed exact original table.
    ///
    /// No caller-supplied descriptor or role can enter this handoff.
    #[must_use]
    pub fn take_completed_startup_roles_once_v1(
        &mut self,
    ) -> Option<Method46InitialStartupRolesV1> {
        if self.first.is_some() || self.roles_taken {
            self.first.get_or_insert(First::Order);
            return None;
        }
        let roles = self.original.take_method46_initial_roles_once_v1();
        if roles.is_some() {
            self.roles_taken = true;
        } else {
            self.first.get_or_insert(First::Order);
        }
        roles
    }

    /// Prepays the complete cumulative upper shape on the same sole ledger.
    ///
    /// # Errors
    /// Retains the earliest same-ledger or arithmetic refusal before any growth.
    /// A supplied shape cannot establish a source, role or native permission.
    pub fn require_complete_v1(
        &mut self,
        cumulative: ResourceVector,
    ) -> Result<(), Method46InitialReceivingClosedV1> {
        if self.first.is_some()
            || self
                .original
                .require_startup_representation_v4(cumulative)
                .is_err()
        {
            self.first.get_or_insert(First::Funding);
            return Err(self.closed);
        }
        Ok(())
    }

    /// Observes the actual entered interval's before destination once.
    ///
    /// # Errors
    /// Refuses missing payment or repeated entry and retains the native cause.
    pub fn observe_native_before_once_v1(
        &mut self,
    ) -> Result<(), Method46InitialReceivingClosedV1> {
        if self.first.is_some() || self.before_attempted {
            self.first.get_or_insert(First::Order);
            return Err(self.closed);
        }
        self.before_attempted = true;
        if self.original.begin_startup_native_once_v4().is_err() {
            self.first.get_or_insert(First::Before);
            return Err(self.closed);
        }
        Ok(())
    }

    /// Rejoins this actual healthy, unfinished source interval without new IO.
    ///
    /// # Errors
    /// Refuses poison, a missing native before, changed role or a completed turn.
    pub fn require_current_v1(&self) -> Result<(), Method46InitialReceivingClosedV1> {
        if self.first.is_some() {
            return Err(self.closed);
        }

        let current = match self.original.role {
            FixedServiceRoleV1::Method46ControllerInitial => self
                .original
                .require_method46_controller_initial_current_v1(),
            FixedServiceRoleV1::Method46StorageInitial => {
                self.original.require_method46_storage_initial_current_v1()
            }
            _ => return Err(self.closed),
        };
        if current.is_err() {
            return Err(self.closed);
        }
        Ok(())
    }

    /// Performs the independently owed native after despite prior refusal.
    ///
    /// The existing prepaid engine attempts missing reached before and after
    /// destinations independently. No healthy guard, new debit or body success
    /// assertion controls the owed observation. Upper semantic outcomes remain
    /// with the actual provisioning owner and must be selected before calling this.
    ///
    /// # Errors
    /// Retains missing-entry, repeated-use or actual native-after refusal.
    pub fn observe_native_after_owed_once_v1(
        &mut self,
    ) -> Result<(), Method46InitialReceivingClosedV1> {
        if self.after_attempted {
            self.first.get_or_insert(First::Order);
            return Err(self.closed);
        }
        self.after_attempted = true;
        // This closes only the actual native observation interval. It issues
        // no completed preparation, signature, floor or publication token.
        if self
            .original
            .finish_startup_native_once_v4(Ok::<(), FixedServiceOperationClosedV4>(()))
            .is_err()
        {
            self.first.get_or_insert(First::After);
            return Err(self.closed);
        }
        if self.first.is_some() {
            Err(self.closed)
        } else {
            Ok(())
        }
    }

    /// Borrows actual authenticated comparison DATA inside the healthy interval.
    ///
    /// # Errors
    /// Refuses absent initial capture or a missing/closed native interval.
    pub fn origin_comparison_data_v1(
        &self,
    ) -> Result<&Method46InitialOriginComparisonDataV1, Method46InitialReceivingClosedV1> {
        self.require_current_v1()?;
        self.origin.as_ref().ok_or(self.closed)
    }

    /// Checks the saved comparison DATA against this same current original.
    ///
    /// The input can only reject affinity. It cannot construct a scope,
    /// replace an owner, reopen a finished interval or perform native IO.
    ///
    /// # Errors
    /// Refuses absent or poisoned source custody, a closed interval, or any
    /// foreign boot, invocation, image, Parent or materialized-unit coordinate.
    pub fn require_same_origin_current_v1(
        &self,
        expected: &Method46InitialOriginComparisonDataV1,
    ) -> Result<(), Method46InitialReceivingClosedV1> {
        self.require_current_v1()?;
        if self.origin.as_ref() != Some(expected) {
            return Err(self.closed);
        }
        Ok(())
    }

    /// Returns the genuine final transfer's conservative helper-table bound.
    ///
    /// The signed Source flight already joins the inherited descriptor high
    /// watermark and both installed finite NOFILE limits. Its permanent peak
    /// bounds the initial table and all subsequent parent growth, including
    /// CLOEXEC positions. This DATA does not pay for a second copied table or
    /// authorize spawning; the actual manual receiver must separately admit it.
    ///
    /// # Errors
    /// Refuses a closed Source interval or incomplete original final transfer.
    pub fn helper_table_bound_data_v1(&self) -> Result<u64, Method46InitialReceivingClosedV1> {
        self.require_current_v1()?;
        self.original
            .permanent_open_files()
            .map_err(|_| self.closed)
    }

    /// Observes a child's exact membership under this Source's original anchor.
    ///
    /// The caller prepays and retains the supplied observation destination; it
    /// cannot supply an anchor, parent identity or membership value. This unit
    /// comparison grants no helper image, session, secret, NV or floor authority.
    /// The same original Source must remain alive through the independent posts.
    ///
    /// # Errors
    /// Refuses a closed interval, unavailable original anchor, failed membership
    /// observation or a child belonging to a different parent. The destination
    /// retains every reached native result, including its own required posts.
    pub fn observe_helper_membership_once_v1(
        &mut self,
        child: &PidFd,
        destination: &mut ExactCgroupMembershipReadbackV1,
    ) -> Result<(), Method46InitialReceivingClosedV1> {
        self.require_current_v1()?;
        self.observe_helper_membership_destination(child, destination)
    }

    /// Runs an independently prepaid helper-membership post after body refusal.
    ///
    /// The genuine initial capture and entered Source interval remain required.
    /// This method performs no debit and deliberately has no healthy-body guard;
    /// the upper owner must have parked and prepaid this destination before its
    /// corresponding native frontier. Source's final native after remains owed.
    ///
    /// # Errors
    /// Refuses a missing or already finished interval, unavailable original
    /// anchor, foreign child, failed native observation or destination reentry.
    pub fn observe_helper_membership_owed_once_v1(
        &mut self,
        child: &PidFd,
        destination: &mut ExactCgroupMembershipReadbackV1,
    ) -> Result<(), Method46InitialReceivingClosedV1> {
        if !self.before_attempted || self.after_attempted || self.origin.is_none() {
            self.first.get_or_insert(First::Order);
            return Err(self.closed);
        }
        self.observe_helper_membership_destination(child, destination)
    }

    fn observe_helper_membership_destination(
        &mut self,
        child: &PidFd,
        destination: &mut ExactCgroupMembershipReadbackV1,
    ) -> Result<(), Method46InitialReceivingClosedV1> {
        let result = (|| {
            let anchor = self.original.cgroup.as_ref().ok_or(self.closed)?;
            destination
                .capture_once(anchor, child)
                .map_err(|_| self.closed)?;
            let parent = self
                .original
                .membership
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(self.closed)?;
            let observed = destination
                .result()
                .and_then(|result| result.as_ref().ok())
                .ok_or(self.closed)?;
            if parent.pid() != std::process::id() || observed.parent_pid() != parent.pid() {
                return Err(self.closed);
            }
            Ok(())
        })();
        if result.is_err() {
            self.first.get_or_insert(First::Helper);
        }
        result
    }

    /// Retains a population monitor acquired from this Source's original anchor.
    ///
    /// The caller pays the complete destination before entering this finite
    /// recipe and retains it even on refusal. No path or caller anchor enters;
    /// a completed monitor remains observation custody rather than readiness,
    /// drain, restart or release authority.
    ///
    /// # Errors
    /// Refuses a closed interval or unavailable anchor, failed native acquisition,
    /// changed anchor identity or reentry. Partial files remain in destination.
    pub fn capture_population_once_v1(
        &mut self,
        destination: &mut CgroupPopulationMonitorOriginalV3,
    ) -> Result<(), Method46InitialReceivingClosedV1> {
        self.require_current_v1()?;
        let result = (|| {
            let anchor = self.original.cgroup.as_ref().ok_or(self.closed)?;
            destination
                .capture_once_v3(anchor)
                .map_err(|_| self.closed)?;
            self.require_current_v1()
        })();
        if result.is_err() {
            self.first.get_or_insert(First::Population);
        }
        result
    }

    /// Observes a fixed stopped owner beneath this Source's actual hierarchy.
    ///
    /// The enclosing owner prepays the complete destination and native recipe
    /// before entry. The coordinate is DATA; no caller root, path, descriptor
    /// or copied identity can replace the original validated hierarchy.
    ///
    /// # Errors
    /// Refuses an unavailable Source or native acquisition/population failure.
    /// All reached originals and the actual cause remain in the destination.
    pub fn observe_stopped_owner_cgroup_once_v1(
        &mut self,
        owner: Method46StoppedOwnerCgroupV1,
        destination: &mut Method46StoppedOwnerCgroupOriginalV1,
    ) -> Result<(), Method46InitialReceivingClosedV1> {
        self.require_current_v1()?;
        self.observe_stopped_owner_cgroup_destination(owner, destination)
    }

    /// Performs an independently prepaid stopped-owner post after body refusal.
    ///
    /// This performs no new debit. The same captured, entered interval must
    /// remain held; its final Source after is still independently owed.
    ///
    /// # Errors
    /// Refuses an unentered or ended Source, missing original hierarchy,
    /// destination reentry or the actual retained native failure.
    pub fn observe_stopped_owner_cgroup_owed_once_v1(
        &mut self,
        owner: Method46StoppedOwnerCgroupV1,
        destination: &mut Method46StoppedOwnerCgroupOriginalV1,
    ) -> Result<(), Method46InitialReceivingClosedV1> {
        if !self.before_attempted || self.after_attempted || self.origin.is_none() {
            self.first.get_or_insert(First::Order);
            return Err(self.closed);
        }
        self.observe_stopped_owner_cgroup_destination(owner, destination)
    }

    fn observe_stopped_owner_cgroup_destination(
        &mut self,
        owner: Method46StoppedOwnerCgroupV1,
        destination: &mut Method46StoppedOwnerCgroupOriginalV1,
    ) -> Result<(), Method46InitialReceivingClosedV1> {
        let result = (|| {
            let hierarchy = self.original.hierarchy.as_ref().ok_or(self.closed)?;
            destination
                .observe_once_v1(hierarchy, owner)
                .map_err(|_| self.closed)
        })();
        if result.is_err() {
            self.first.get_or_insert(First::StoppedOwner);
        }
        result
    }

    /// Borrows the earliest retained source-specific cause without another IO.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Capture => self.original.failure(),
            First::Funding | First::Before | First::After => {
                self.original.service_startup_failure_v4()
            }
            First::Helper | First::Population | First::StoppedOwner | First::Order => None,
        }
        .or(Some(&self.closed as &(dyn Error + 'static)))
    }
}

#[cfg(test)]
mod tests {
    use super::{Method46InitialServiceRoleV1, Method46InitialSourceCaptureV1};

    #[test]
    fn method46_initial_stopped_cgroups_cannot_borrow_a_missing_source_hierarchy() {
        use aos_sandbox_linux::cgroup::{
            Method46StoppedOwnerCgroupOriginalV1, Method46StoppedOwnerCgroupV1,
        };

        for role in [
            Method46InitialServiceRoleV1::ControllerStorageClient,
            Method46InitialServiceRoleV1::StorageBroker,
        ] {
            let mut source =
                std::mem::ManuallyDrop::new(Method46InitialSourceCaptureV1::new(role, 0));
            let mut destination = Method46StoppedOwnerCgroupOriginalV1::new();

            assert!(
                source
                    .observe_stopped_owner_cgroup_once_v1(
                        Method46StoppedOwnerCgroupV1::Controller,
                        &mut destination,
                    )
                    .is_err()
            );
            assert!(
                source
                    .observe_stopped_owner_cgroup_owed_once_v1(
                        Method46StoppedOwnerCgroupV1::Controller,
                        &mut destination,
                    )
                    .is_err()
            );

            assert!(source.original.hierarchy.is_none());
            assert!(destination.failure_v1().is_none());
            assert!(!destination.is_empty_or_absent_data_v1());
            assert!(source.failure_v1().is_some());
        }
    }

    #[test]
    fn manual_role_selection_cannot_supply_a_source_or_startup_descriptors() {
        for role in [
            Method46InitialServiceRoleV1::ControllerStorageClient,
            Method46InitialServiceRoleV1::StorageBroker,
        ] {
            // Initial-table custody is process-lifetime even before capture.
            // This negative never observes or acquires any descriptor.
            let mut source =
                std::mem::ManuallyDrop::new(Method46InitialSourceCaptureV1::new(role, 0));

            assert!(source.require_current_v1().is_err());
            assert!(source.origin_comparison_data_v1().is_err());
            assert!(source.helper_table_bound_data_v1().is_err());
            assert!(source.take_completed_startup_roles_once_v1().is_none());

            // An early handoff refusal permanently fences this owner. Neither
            // purpose may retry into native IO or manufacture the missing roles.
            assert!(source.failure_v1().is_some());
            assert!(source.capture_once_v1().is_err());
            assert!(source.take_completed_startup_roles_once_v1().is_none());
            assert!(source.observe_native_before_once_v1().is_err());
            assert!(source.require_current_v1().is_err());
        }
    }
}
