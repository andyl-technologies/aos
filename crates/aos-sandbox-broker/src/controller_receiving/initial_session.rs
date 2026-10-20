//! Keeps the four initial Client role claims on the actual sole Controller C.
//!
//! The trusted Native Bank retains the real Journal/schema/HELLO receiver above.
//! These private state transitions debit only representation on the same ledger;
//! their Results grant no IO, Native receiver, account or semantic completion.

use std::error::Error;
use std::sync::Arc;

use aos_sandbox_core::ResourceVector;
use super::{ControllerReceivingErrorV1, ControllerReceivingOriginalV1};
use super::profile::{ControllerProfileErrorV1, ControllerSelfProfileOriginalV1,
    ControllerProfileFailureViewV1};

/// Identifies one of the four existing fixed boot Client endpoints.
///
/// This passive selector carries no path, process identity or receiving grant.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerInitialBrokerSessionRoleV1 {
    /// The existing Controller-to-Host endpoint.
    Host,
    /// The existing Controller-to-Mount endpoint.
    Mount,
    /// The existing Controller-to-Storage endpoint.
    Storage,
    /// The existing Controller-to-Network endpoint.
    Network,
}

impl ControllerInitialBrokerSessionRoleV1 {
    /// Number of fixed initial Client roles.
    pub const COUNT: usize = 4;

    /// Returns this existing fixed role's custody pathname as comparison DATA.
    pub const fn endpoint_custody_path_v1(self) -> &'static str {
        match self {
            Self::Host => "/var/lib/aos/sandboxd/broker-session/host/custody",
            Self::Mount => "/var/lib/aos/sandboxd/broker-session/mount/custody",
            Self::Storage => "/var/lib/aos/sandboxd/broker-session/storage/custody",
            Self::Network => "/var/lib/aos/sandboxd/broker-session/network/custody",
        }
    }


    /// Returns this fixed role's stable receiving-array index.
    pub const fn index(self) -> usize {
        match self {
            Self::Host => 0,
            Self::Mount => 1,
            Self::Storage => 2,
            Self::Network => 3,
        }
    }

    pub(in crate::controller_receiving) const fn recovered_owner_v2(self) -> super::budget::BaselineOwner {
        match self {
            Self::Host => super::budget::BaselineOwner::RecoveredHostSession,
            Self::Mount => super::budget::BaselineOwner::RecoveredMountSession,
            Self::Storage => super::budget::BaselineOwner::RecoveredStorageSession,
            Self::Network => super::budget::BaselineOwner::RecoveredNetworkSession,
        }
    }

    pub(in crate::controller_receiving) const fn owner(self) -> super::budget::BaselineOwner {
        match self {
            Self::Host => super::budget::BaselineOwner::InitialHostSession,
            Self::Mount => super::budget::BaselineOwner::InitialMountSession,
            Self::Storage => super::budget::BaselineOwner::InitialStorageSession,
            Self::Network => super::budget::BaselineOwner::InitialNetworkSession,
        }
    }
}


#[derive(Clone, Copy)]
enum FirstV1 { Execution, EndpointCustody, EndpointNative, Claim, Representation, FloorRepresentation, PhysicalRepresentation, Before, After, Reentry }

/// Retains the actual once-role C claim and nonauthorizing representation debt.
///
/// Only a genuine original and its same privately admitted profile can enter.
/// The upper Native Bank alone constructs the actual boot Session receiver;
/// this type provides no Native open/replay/take or protected authority API.
#[must_use = "keep this same original with the actual Native Session receiver"]
pub struct ControllerInitialSessionReceivingOriginalV1 {
    original: Arc<ControllerReceivingOriginalV1>,
    recover: Option<Arc<super::bank_launch::ControllerSessionRepresentationV3>>,
    role: ControllerInitialBrokerSessionRoleV1,
    claim: Result<(), ControllerReceivingErrorV1>,
    representation: Option<Result<(), ControllerReceivingErrorV1>>,
    fixed_paid: bool,
    endpoint_entry: Option<Result<(), ControllerReceivingErrorV1>>,
    execution_capture: Option<Result<crate::endpoint_native_files::ControllerEndpointExecutionOriginalV1,
        crate::endpoint_native_files::ControllerEndpointExecutionCaptureErrorV1>>,
    endpoint_completion: Option<Result<(), ControllerReceivingErrorV1>>,
    endpoint_custody: Option<Arc<crate::endpoint_native_files::ControllerEndpointNativeCustodyV1>>,
    endpoint_origin: Option<Arc<crate::endpoint_native_files::EndpointNativeSelectedOriginV1>>,
    fence: Option<Result<(), ControllerReceivingErrorV1>>,
    floor_representation: Option<Result<(), ControllerReceivingErrorV1>>,
    floor_complete: Option<ResourceVector>,
    physical_preparation: Option<Result<ResourceVector, ControllerReceivingErrorV1>>,
    physical_taken: bool,
    floor_helper_delivered: bool,
    before: Option<Result<([u8; 16], [u8; 16]), ControllerProfileErrorV1>>,
    after: Option<Result<([u8; 16], [u8; 16]), ControllerProfileErrorV1>>,
    first: Option<FirstV1>,
    reentry: Option<ControllerReceivingErrorV1>,
}

impl ControllerInitialSessionReceivingOriginalV1 {
    /// Reports only the reconciliation role of this actual private receiver.
    ///
    /// Initial and Storage-Recover receivers return `None`. This comparison
    /// DATA grants no currentness, query, effect, capacity or normal enrollment.
    #[doc(hidden)]
    #[must_use]
    pub fn reconciliation_role_data_v2(&self)
        -> Option<super::bank_launch::ControllerReconciliationInventoryRoleV2>
    {
        use super::bank_launch::ControllerReconciliationInventoryRoleV2 as Role;

        if self.claim.is_err() { return None; }
        let source = self.recover.as_ref()?;
        if !source.is_reconciliation_v2() { return None; }
        let actual = source.role_data_v2();
        if actual != self.role { return None; }
        match actual {
            ControllerInitialBrokerSessionRoleV1::Host => Some(Role::Host),
            ControllerInitialBrokerSessionRoleV1::Mount => Some(Role::Mount),
            ControllerInitialBrokerSessionRoleV1::Network => Some(Role::Network),
            ControllerInitialBrokerSessionRoleV1::Storage => None,
        }
    }

    /// Selects the installed maintenance client grammar from actual bank funding.
    ///
    /// Initial and recovered ordinary receivers keep their genuine role.
    /// OperatorRecover and readonly reconciliation receivers return `None`.
    /// This comparison DATA supplies no request or effect authority.
    ///
    /// # Errors
    /// Refuses an unclaimed, failed or no-longer-current actual receiver.
    #[doc(hidden)]
    pub fn selected_maintenance_client_role_v2(&self)
        -> Result<Option<ControllerInitialBrokerSessionRoleV1>, ControllerReceivingErrorV1>
    {
        self.require_claimed_v1()?;
        if self.recover.as_ref().is_some_and(|source|
            source.is_reconciliation_v2() || source.is_execution_cold_v2() || source.is_stop_cleanup_v1()) {
            return Ok(None);
        }
        Ok(Some(self.role))
    }

    /// Reports only the actual finite Recover-funded Stop cold purpose.
    #[doc(hidden)]
    #[must_use]
    pub fn is_host_stop_cleanup_data_v1(&self) -> bool {
        self.claim.is_ok() && self.recover.as_ref().is_some_and(|source| source.is_stop_cleanup_v1())
    }

    /// Reports the actual finite Source/C18 cold financial branch as DATA.
    #[doc(hidden)]
    #[must_use]
    pub fn is_execution_cleanup_cold_data_v2(&self) -> bool {
        self.claim.is_ok() && self.recover.as_ref()
            .is_some_and(|source| source.is_execution_cold_v2())
    }

    /// Retains the genuine financial identity for the final native Session.
    ///
    /// # Errors
    /// Refuses an unclaimed, failed or no-longer-current native receiver.
    #[doc(hidden)]
    pub fn retain_execution_cold_native_v2(&self)
        -> Result<Option<super::bank_launch::ControllerExecutionColdSessionRetentionV2>, ControllerReceivingErrorV1>
    {
        self.require_claimed_v1()?;
        match &self.recover {
            Some(source) => source.retain_execution_native_v2(),
            None => Ok(None),
        }
    }

    /// Retains the same fresh Stop22 payer after the final native Session fields.
    ///
    /// # Errors
    /// Refuses an unclaimed, failed or already fenced actual receiver.
    #[doc(hidden)]
    pub fn retain_stop_cleanup_session_native_v1(&self)
        -> Result<Option<super::bank_launch::ControllerStopCleanupSessionRetentionV1>, ControllerReceivingErrorV1>
    {
        self.require_claimed_v1()?;
        match &self.recover {
            Some(source) => super::bank_launch::ControllerSessionRepresentationV3::retain_stop_cleanup_native_v1(source),
            None => Ok(None),
        }
    }

    /// Retains the same Recover identity through physical Session disposal.
    ///
    /// # Errors
    /// Refuses an unclaimed, failed or already fenced initial receiver.
    #[doc(hidden)]
    pub fn retain_recovery_session_native_v1(&self)
        -> Result<Option<super::bank_launch::ControllerRecoverySessionRetentionV1>, ControllerReceivingErrorV1>
    {
        self.require_claimed_v1()?;
        self.recover.as_ref().map_or(Ok(None), |source|
            super::bank_launch::ControllerSessionRepresentationV3::retain_recovery_native_v1(source))
    }

    pub(crate) fn matches_execution_cold_v2(&self,
        expected: &Arc<super::bank_launch::ControllerExecutionColdSessionBudgetV2>,
    ) -> bool {
        self.role == ControllerInitialBrokerSessionRoleV1::Host && self.claim.is_ok()
            && self.recover.as_ref().is_some_and(|source| source.matches_execution_cold_v2(expected))
    }

    /// Parks the same original role claim before any upper geometry derivation.
    ///
    /// Failed claims stay owned. Constructing this DATA owner alone grants no
    /// Native receiver and cannot replace the Bank's writer/launch conjunction.
    #[doc(hidden)]
    pub fn from_actual_profile_v1(
        original: Arc<ControllerReceivingOriginalV1>,
        profile: &ControllerSelfProfileOriginalV1,
        role: ControllerInitialBrokerSessionRoleV1,
    ) -> Self {
        let claim = original.claim_initial_session_role_v1(profile, role);
        Self::from_claim_v1(original, profile, role, claim, None)
    }

    pub(in crate::controller_receiving) fn from_recover_v1(
        original: Arc<ControllerReceivingOriginalV1>,
        profile: &ControllerSelfProfileOriginalV1,
        recover: Arc<super::bank_launch::ControllerSessionRepresentationV3>,
    ) -> Self {
        let claim = recover.require_current_v1();
        Self::from_claim_v1(original, profile, recover.role_data_v2(),
            claim, Some(recover))
    }

    pub(in crate::controller_receiving) fn from_recovered_ordinary_v2(
        original: Arc<ControllerReceivingOriginalV1>,
        profile: &ControllerSelfProfileOriginalV1,
        representation: Arc<super::bank_launch::ControllerSessionRepresentationV3>,
    ) -> Self {
        let claim = representation.require_current_v1();
        Self::from_claim_v1(original, profile, representation.role_data_v2(), claim, Some(representation))
    }

    fn from_claim_v1(original: Arc<ControllerReceivingOriginalV1>,
        profile: &ControllerSelfProfileOriginalV1, role: ControllerInitialBrokerSessionRoleV1,
        claim: Result<(), ControllerReceivingErrorV1>,
        recover: Option<Arc<super::bank_launch::ControllerSessionRepresentationV3>>,
    ) -> Self {
        let first = claim.is_err().then_some(FirstV1::Claim);
        Self {
            original, recover, role, claim, representation: None, fixed_paid: false, endpoint_entry: None, execution_capture: None, endpoint_completion: None, endpoint_custody: None, endpoint_origin: None, fence: None, floor_representation: None,
            floor_complete: None, physical_preparation: None, physical_taken: false,
            floor_helper_delivered: profile.has_tpm_image_delivery(),
            before: None, after: None, first, reentry: None,
        }
    }

    /// Captures the same C self guard at the original fixed endpoint frontier.
    ///
    /// Required roles reuse the actual first native guard, never its snapshot
    /// as a fresh observation. The caller still owns every fresh role post.
    ///
    /// # Errors
    /// Retains the actual first native capture or same-original refusal.
    #[doc(hidden)]
    pub fn capture_endpoint_execution_once_v1(&mut self)
        -> Result<crate::endpoint_native_files::ControllerEndpointExecutionOriginalV1,
            crate::endpoint_native_files::ControllerEndpointExecutionCaptureErrorV1>
    {
        use crate::endpoint_native_files::ControllerEndpointExecutionCaptureErrorV1 as Failure;
        if self.execution_capture.is_some() || !self.fixed_paid
            || !matches!(self.before, Some(Ok(_))) || self.after.is_some()
            || self.endpoint_entry.is_some() || self.require_claimed_v1().is_err()
        {
            self.first.get_or_insert(FirstV1::Execution);
            return Err(Failure::Unavailable);
        }
        self.execution_capture = Some(match self.recover.as_ref() {
            Some(recover) => recover.require_current_v1().map_err(|_| Failure::Unavailable)
                .and_then(|()| self.original.capture_fixed_session_execution_v1(self.role)),
            None => self.original.capture_initial_execution_v1(self.role),
        });
        match self.execution_capture.as_ref() {
            Some(Ok(guard)) => Ok(guard.share_v1()),
            Some(Err(cause)) => { self.first.get_or_insert(FirstV1::Execution); Err(cause.clone()) }
            None => Err(Failure::Unavailable),
        }
    }

    /// Captures the actual fixed directory under this paid once-role C.
    ///
    /// The destination retains the whole native open result. The private
    /// provenance contains only this same original and role; callers supply
    /// no path, UID, descriptor, account or completion assertion.
    ///
    /// # Errors
    /// Retains missing paid/before entry, reentry or same-original refusal.
    #[doc(hidden)]
    pub fn capture_endpoint_directory_once_v1(
        &mut self,
        destination: &mut crate::endpoint_native_files::EndpointNativeFileOpenOriginalV1,
    ) -> Result<(), ControllerReceivingErrorV1> {
        if self.endpoint_entry.is_some() {
            self.reentry.get_or_insert(ControllerReceivingErrorV1::Conflict);
            self.first.get_or_insert(FirstV1::Reentry);
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        self.endpoint_entry = Some((|| {
            if !self.fixed_paid || !matches!(self.before, Some(Ok(_)))
                || self.after.is_some() || destination.entered()
            {
                return Err(ControllerReceivingErrorV1::Conflict);
            }
            self.require_claimed_v1()
        })());
        if !matches!(self.endpoint_entry, Some(Ok(()))) {
            self.first.get_or_insert(FirstV1::EndpointNative);
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        self.endpoint_origin = Some(crate::endpoint_native_files::EndpointNativeSelectedOriginV1::new(
            &self.original, self.role,
        ));
        if let Some(origin) = &self.endpoint_origin {
            destination.selected_directory_once(origin);
        }
        Ok(())
    }

    /// Retains the actual same-role native endpoint anchors after their posts.
    ///
    /// This consumes the real Linux execution guard into the lower owning
    /// capture and shares only the already-held native descriptor objects.
    /// It accepts no completion flag, resource vector or semantic endpoint.
    ///
    /// # Errors
    /// Retains reentry, same-C/role/process refusal or actual partial custody.
    #[doc(hidden)]
    pub fn capture_endpoint_custody_once_v1(
        &mut self,
        destination: &mut crate::endpoint_native_files::ControllerEndpointNativeCustodyCaptureV1,
        execution: &mut Option<crate::endpoint_native_files::ControllerEndpointExecutionOriginalV1>,
        post: &mut Option<aos_sandbox_linux::self_execution::SelfExecutionObservationV1>,
        files: [&crate::endpoint_native_files::EndpointNativeFileV1; 4],
    ) -> Result<(), ControllerReceivingErrorV1> {
        if self.endpoint_completion.is_some() {
            self.reentry.get_or_insert(ControllerReceivingErrorV1::Conflict);
            self.first.get_or_insert(FirstV1::Reentry);
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        self.endpoint_completion = Some((|| {
            self.require_claimed_v1()?;
            if !matches!(self.endpoint_entry, Some(Ok(()))) || self.after.is_some() {
                return Err(ControllerReceivingErrorV1::Conflict);
            }
            let origin = self.endpoint_origin.as_ref().ok_or(ControllerReceivingErrorV1::Conflict)?;
            destination.capture_once(execution, post, files, origin, &self.original, self.role)?;
            let custody = destination.completed().ok_or(ControllerReceivingErrorV1::Conflict)?;
            if custody.retained_open_file_count_v1() != Some(6) {
                return Err(ControllerReceivingErrorV1::Conflict);
            }
            self.endpoint_custody = Some(Arc::clone(custody));
            Ok(())
        })());
        if matches!(self.endpoint_completion, Some(Ok(()))) { Ok(()) }
        else {
            self.first.get_or_insert(FirstV1::EndpointCustody);
            Err(ControllerReceivingErrorV1::Conflict)
        }
    }

    /// Supplies actual additional owner, argument and lock geometry DATA.
    ///
    /// The enclosing Native sizeof already includes the resident owner slot;
    /// this conservative addition covers complete construction overlap too.
    /// No resource bound, payment or Native permission is returned.
    #[must_use]
    pub fn receiving_demand_v1() -> Option<ResourceVector> {
        use aos_sandbox_core::ResourceDimension as D;
        type Producer = Result<([u8; 16], [u8; 16]), ControllerProfileErrorV1>;
        let (lock_bytes, _) = Self::current_temporary_shape_v1();
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(std::mem::size_of::<Producer>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<ResourceVector>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<Result<(), ControllerReceivingErrorV1>>())?
            .checked_add(lock_bytes)?;
        // Owner fields and temporary control values occupy memory; they do
        // not create resident namespace entries.
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?))
    }

    /// Fences the same claimed original after an upper fixed-geometry refusal.
    ///
    /// The actual upper arithmetic error remains its owner's first cause. This
    /// fixed argument-free close cannot reserve, reopen or authorize anything.
    /// A failed same-profile claim cannot close another unmatched original.
    #[doc(hidden)]
    pub fn fence_after_upper_representation_refusal_v1(&mut self) {
        if self.claim.is_ok() && self.fence.is_none() {
            self.fence = Some(match &self.recover {
                Some(recover) => recover.fence_primary_v1(),
                None => self.original.fence_initial_session_representation_v1(),
            });
        }
    }

    /// Requires this actual once-role claim without issuing Native authority.
    ///
    /// # Errors
    /// Refuses an original claim failure or a closed/foreign current process.
    pub fn require_claimed_v1(&self) -> Result<(), ControllerReceivingErrorV1> {
        if self.claim.is_err() || self.first.is_some() {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        match &self.recover {
            Some(recover) => recover.require_current_v1(),
            None => self.original.require_initial_session_current_v1(self.role),
        }
    }

    fn debit_complete_v1(&self, complete: ResourceVector) -> Result<(), ControllerReceivingErrorV1> {
        match &self.recover {
            Some(recover) => recover.raise_session_v1(complete),
            None => self.original.debit_initial_session_complete_v1(self.role, complete),
        }
    }

    /// Monotonically debits this role's actual complete Native representation.
    ///
    /// This is DATA from the trusted Native fixed/schema/captured-prefix
    /// producer. It returns no capacity, IO permit, receiver or positive take;
    /// only the actual upper private Bank receiver can reach those operations.
    ///
    /// # Errors
    /// Retains same-original/Serving/role/process or capacity refusal before
    /// growth. Earlier successful bounds stay charged without refund/rearm.
    #[doc(hidden)]
    pub fn debit_initial_session_representation_v1(&mut self, complete: ResourceVector)
        -> Result<(), ControllerReceivingErrorV1>
    {
        if self.first.is_some() { return Err(ControllerReceivingErrorV1::Conflict); }
        self.representation = Some(self.debit_complete_v1(complete));
        if matches!(self.representation, Some(Ok(()))) { self.fixed_paid = true; Ok(()) }
        else { self.first = Some(FirstV1::Representation); Err(ControllerReceivingErrorV1::Conflict) }
    }

    /// Requires the same original claimed Storage role in its Serving phase.
    ///
    /// # Errors
    /// Refuses another role, closed original, active scope or changed process.
    pub fn require_storage_floor_current_v1(&self) -> Result<(), ControllerReceivingErrorV1> {
        if self.role != ControllerInitialBrokerSessionRoleV1::Storage {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        self.require_claimed_v1()
    }

    /// Debits cumulative main plus actual distinct Storage sidecar representation.
    ///
    /// Actual main/facade/sidecar identity, extent/limits/schema and once phases
    /// remain in the same Native receiver. This debit supplies none of them.
    ///
    /// # Errors
    /// Retains wrong Storage role, Serving/recipient/ledger closure or capacity
    /// failure before native or typed growth. No previous charge is refunded.
    #[doc(hidden)]
    pub fn debit_storage_floor_representation_v1(&mut self, complete: ResourceVector)
        -> Result<(), ControllerReceivingErrorV1>
    {
        self.require_storage_floor_current_v1()?;
        self.floor_representation = Some(self.debit_complete_v1(complete));
        if matches!(self.floor_representation, Some(Ok(()))) {
            self.floor_complete = Some(complete);
            Ok(())
        } else {
            self.first = Some(FirstV1::FloorRepresentation);
            Err(ControllerReceivingErrorV1::Conflict)
        }
    }

    /// Transfers once the same Storage representation bookkeeping original.
    ///
    /// The trusted Native receiver has separately joined its actual taken main
    /// and sidecar. Its compiled construction width is representation DATA;
    /// this method supplies no Journal, native constructor or IO permission.
    /// The complete earlier main/sidecar bound remains permanently charged.
    ///
    /// A refused whole debit stays resident here. Successful transfer creates
    /// only another owning reference to this SAME C, without a new account.
    #[doc(hidden)]
    pub fn take_storage_floor_representation_once_v1(
        &mut self,
        native_construction: ResourceVector,
    ) -> Option<ControllerStorageFloorRepresentationV1> {
        if self.first.is_some() || self.physical_preparation.is_some() || self.physical_taken {
            self.reentry.get_or_insert(ControllerReceivingErrorV1::Conflict);
            self.first.get_or_insert(FirstV1::Reentry);
            return None;
        }
        self.physical_preparation = Some((|| {
            self.require_storage_floor_current_v1()?;
            if !self.fixed_paid || !self.floor_helper_delivered
                || !matches!(self.floor_representation, Some(Ok(())))
            {
                return Err(ControllerReceivingErrorV1::Conflict);
            }
            let base = self.floor_complete.ok_or(ControllerReceivingErrorV1::Conflict)?;
            let own = ControllerStorageFloorRepresentationV1::receiving_demand_v1()
                .ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)?;
            let complete = base.checked_add(own)?.checked_add(native_construction)?;
            self.debit_complete_v1(complete)?;
            Ok(complete)
        })());
        let base = match self.physical_preparation.as_ref() {
            Some(Ok(base)) => *base,
            _ => {
                self.first = Some(FirstV1::PhysicalRepresentation);
                return None;
            }
        };
        self.physical_taken = true;
        Some(ControllerStorageFloorRepresentationV1::new(Arc::clone(&self.original), base, self.recover.as_ref().map(Arc::clone)))
    }

    /// Supplies temporary bytes and zero additional resident namespace entries.
    #[must_use]
    pub fn current_temporary_shape_v1() -> (usize, usize) {
        ControllerReceivingOriginalV1::initial_session_current_temporary_shape_v1()
    }

    /// Reads the node from this same genuine claimed original.
    ///
    /// # Errors
    /// Refuses a closed, missing or unclaimed original.
    pub fn expected_node_v1(&self) -> Result<[u8; 16], ControllerReceivingErrorV1> {
        match &self.recover {
            Some(recover) => recover.node_data_v1(),
            None => self.original.initial_session_node_v1(self.role),
        }
    }

    /// Compares only the same actual original recipient/producer pair.
    ///
    /// # Errors
    /// Refuses another original pair without creating any scope or permission.
    pub fn require_recipient_v1(&self, recipient: [u8; 16], producer: [u8; 16])
        -> Result<(), ControllerReceivingErrorV1>
    {
        self.original.require_runtime_recipient(recipient, producer)
    }

    /// Runs the existing complete private producer recipe for actual entry.
    ///
    /// # Errors
    /// Retains reentry, foreign profile or the actual original profile result.
    pub fn observe_profile_before_once_v1(&mut self, profile: &ControllerSelfProfileOriginalV1)
        -> Result<([u8; 16], [u8; 16]), ControllerProfileErrorV1>
    {
        if self.before.is_some() || self.first.is_some()
            || !self.fixed_paid
            || !profile.has_same_baseline_original(&self.original)
        {
            self.reentry.get_or_insert(ControllerReceivingErrorV1::Conflict);
            self.first.get_or_insert(FirstV1::Reentry);
            return Err(ControllerProfileErrorV1::Service);
        }
        self.before = Some(match &self.recover {
            Some(recover) => recover.pair_data_v1().map_err(|_| ControllerProfileErrorV1::Service),
            None => profile.require_resource_producer(),
        });
        match self.before {
            Some(Ok(pair)) => Ok(pair),
            Some(Err(cause)) => { self.first = Some(FirstV1::Before); Err(cause) }
            None => Err(ControllerProfileErrorV1::Service),
        }
    }

    /// Runs the same independently owed private producer post after entry.
    ///
    /// This creates no fresh role/payment and never heals earlier refusal.
    ///
    /// # Errors
    /// Retains repeated/missing entry, foreign profile and actual post refusal.
    pub fn observe_profile_after_once_v1(&mut self, profile: &ControllerSelfProfileOriginalV1)
        -> Result<([u8; 16], [u8; 16]), ControllerProfileErrorV1>
    {
        if self.after.is_some() || self.before.is_none()
            || !self.fixed_paid
            || !profile.has_same_baseline_original(&self.original)
        {
            self.reentry.get_or_insert(ControllerReceivingErrorV1::Conflict);
            self.first.get_or_insert(FirstV1::Reentry);
            return Err(ControllerProfileErrorV1::Service);
        }
        // Recover retains the enclosing native Producer before/owed-after
        // across the whole cold Session and Inventory. This local comparison
        // neither consumes a boot Producer nor claims that outer post complete.
        self.after = Some(match &self.recover {
            Some(recover) => recover.pair_data_v1().map_err(|_| ControllerProfileErrorV1::Service),
            None => profile.require_resource_producer(),
        });
        match self.after {
            Some(Ok(pair)) => Ok(pair),
            Some(Err(cause)) => { self.first.get_or_insert(FirstV1::After); Err(cause) }
            None => Err(ControllerProfileErrorV1::Service),
        }
    }

    /// Borrows the real guarded profile error only at its selected first site.
    #[must_use]
    pub fn profile_failure_view_v1<'profile>(&self, profile: &'profile ControllerSelfProfileOriginalV1)
        -> Option<ControllerProfileFailureViewV1<'profile>>
    {
        if !matches!(self.first, Some(FirstV1::Before | FirstV1::After))
            || !profile.has_same_baseline_original(&self.original) {
            return None;
        }
        profile.failure_view_v1()
    }

    /// Borrows the first actual stored error without cloning native causes.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            FirstV1::Execution => self.execution_capture.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static))
                .or(Some(&INITIAL_EXECUTION_CLOSED)),
            FirstV1::EndpointCustody => failure(&self.endpoint_completion),
            FirstV1::EndpointNative => failure(&self.endpoint_entry),
            FirstV1::Claim => self.claim.as_ref().err().map(|cause| cause as _),
            FirstV1::Representation => failure(&self.representation),
            FirstV1::FloorRepresentation => failure(&self.floor_representation),
            FirstV1::PhysicalRepresentation => failure(&self.physical_preparation),
            FirstV1::Before => failure(&self.before),
            FirstV1::After => failure(&self.after),
            FirstV1::Reentry => self.reentry.as_ref().map(|cause| cause as _),
        }
    }
}


/// Keeps persistent physical representation on the same claimed Storage C.
///
/// This opaque mechanical owner has no public constructor or role/native
/// completion API. Its sole producer is the once-role receiver above. Actual
/// Journal pair custody and fixed physical primitives stay in the trusted
/// Native and Security owners; identity DATA cannot replace their files.
#[doc(hidden)]
#[must_use = "retain failed physical representation with its actual Session"]
pub struct ControllerStorageFloorRepresentationV1 {
    original: Arc<ControllerReceivingOriginalV1>,
    recover: Option<Arc<super::bank_launch::ControllerSessionRepresentationV3>>,
    base: ResourceVector,
    complete: Option<Result<ResourceVector, ControllerReceivingErrorV1>>,
    debit: Option<Result<(), ControllerReceivingErrorV1>>,
    profile: Option<Result<(), ControllerReceivingErrorV1>>,
    first: Option<PhysicalFirstV1>,
    current: Option<Result<(), ControllerReceivingErrorV1>>,
    fixed_operation: Option<crate::receiving::ComponentReceivingOwnedOperationV1>,
    request_operation: Option<crate::receiving::ComponentReceivingOwnedOperationV1>,
    operation_result: Option<Result<(), ControllerReceivingErrorV1>>,
    disposal: Option<Result<(), ControllerReceivingErrorV1>>,
}

#[derive(Clone, Copy)]
enum PhysicalFirstV1 { Profile, Current, Complete, Debit, Operation, Disposal }

impl ControllerStorageFloorRepresentationV1 {
    fn new(original: Arc<ControllerReceivingOriginalV1>, base: ResourceVector,
        recover: Option<Arc<super::bank_launch::ControllerSessionRepresentationV3>>,
    ) -> Self {
        Self { original, recover, base, complete: None, debit: None, profile: None, first: None,
            current: None, fixed_operation: None, request_operation: None, operation_result: None, disposal: None }
    }

    /// Supplies compiled carriers and actual same-owner lock temporaries only.
    #[must_use]
    pub fn receiving_demand_v1() -> Option<ResourceVector> {
        use aos_sandbox_core::ResourceDimension as D;

        let (lock, _) = ControllerReceivingOriginalV1::initial_session_current_temporary_shape_v1();
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(std::mem::size_of::<ResourceVector>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<Result<ResourceVector, ControllerReceivingErrorV1>>())?
            .checked_add(lock)?
            .checked_add(std::mem::size_of::<crate::receiving::ComponentReceivingOwnedOperationV1>())?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?))
    }

    /// Compares the actual launch profile with this same original C.
    ///
    /// The trusted Native/Security adapter supplies only the existing opaque
    /// admitted profile. This comparison creates no role, payment or effect.
    ///
    /// # Errors
    /// Retains a foreign original, absent measured helper mode or prior failure.
    pub fn require_same_profile_v1(&mut self, profile: &ControllerSelfProfileOriginalV1)
        -> Result<(), ControllerReceivingErrorV1>
    {
        if self.first.is_some() {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        self.profile = Some(if profile.has_same_baseline_original(&self.original)
            && profile.has_tpm_image_delivery()
        {
            Ok(())
        } else {
            Err(ControllerReceivingErrorV1::Conflict)
        });
        if matches!(self.profile, Some(Ok(()))) {
            Ok(())
        } else {
            self.first = Some(PhysicalFirstV1::Profile);
            Err(ControllerReceivingErrorV1::Conflict)
        }
    }

    /// Checks the same claimed Storage original before fresh physical work.
    ///
    /// # Errors
    /// Keeps a closed, foreign-process or non-Serving original refusal. The
    /// already-paid negative continuation does not call this healthy gate.
    #[doc(hidden)]
    pub fn require_persistent_current_v1(&mut self) -> Result<(), ControllerReceivingErrorV1> {
        if self.first.is_some() { return Err(ControllerReceivingErrorV1::Conflict); }
        self.current = Some(match &self.recover {
            Some(recover) => recover.require_current_v1(),
            None => self.original.require_initial_session_current_v1(
                ControllerInitialBrokerSessionRoleV1::Storage),
        });
        if matches!(self.current, Some(Ok(()))) { Ok(()) } else {
            self.first = Some(PhysicalFirstV1::Current);
            Err(ControllerReceivingErrorV1::Conflict)
        }
    }

    /// Debits cumulative actual physical representation above its retained base.
    ///
    /// DATA comes from the trusted fixed Native/Security producer before its
    /// reached growth. No capacity, account, constructor, callback, IO permit,
    /// healthy phase or semantic/native completion is returned. Earlier bounds
    /// remain on the sole monotone Storage owner with no refund or rearm.
    ///
    /// # Errors
    /// Retains arithmetic or same-C/Serving/Storage/process/ledger refusal.
    /// Failed owners reject fresh primary debits; already prepaid owed native
    /// observations are held and consumed by the real upper physical owner.
    pub fn debit_physical_representation_v1(&mut self, physical: ResourceVector)
        -> Result<(), ControllerReceivingErrorV1>
    {
        if self.first.is_some() {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        if !matches!(self.profile, Some(Ok(()))) {
            self.profile = Some(Err(ControllerReceivingErrorV1::Conflict));
            self.first = Some(PhysicalFirstV1::Profile);
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        self.complete = Some(self.base.checked_add(physical)
            .map_err(ControllerReceivingErrorV1::Accounting));
        let complete = match self.complete.as_ref() {
            Some(Ok(complete)) => *complete,
            _ => {
                self.first = Some(PhysicalFirstV1::Complete);
                return Err(ControllerReceivingErrorV1::Conflict);
            }
        };
        self.debit = Some(match &self.recover {
            Some(recover) => recover.raise_physical_session_v1(complete, physical),
            None => self.original.debit_initial_session_complete_v1(
                ControllerInitialBrokerSessionRoleV1::Storage, complete),
        });
        if !matches!(self.debit, Some(Ok(()))) {
            self.first = Some(PhysicalFirstV1::Debit);
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        let destination = if self.fixed_operation.is_none() {
            &mut self.fixed_operation
        } else {
            &mut self.request_operation
        };
        self.operation_result = Some(match &self.recover {
            Some(recover) => recover.prepare_physical_operation_v1(physical, destination),
            None => self.original.prepare_storage_physical_operation_v1(physical, destination),
        });
        if matches!(self.operation_result, Some(Ok(()))) {
            Ok(())
        } else {
            self.first = Some(PhysicalFirstV1::Operation);
            Err(ControllerReceivingErrorV1::Conflict)
        }
    }

    /// Disposes only consumed request arithmetic after the real Native stage.
    ///
    /// The trusted private Native consumer first completes every physical and
    /// independently owed post and drops its actual positive request carriers.
    /// This argument-free bookkeeping stage accepts no caller success value,
    /// grants no IO, and cannot complete the persistent helper's fixed phase.
    ///
    /// # Errors
    /// Retains an unconsumed or failed request instead of disposing it.
    #[doc(hidden)]
    pub fn retire_physical_request_after_native_disposal_v1(&mut self)
        -> Result<(), ControllerReceivingErrorV1>
    {
        if self.first.is_some() { return Err(ControllerReceivingErrorV1::Conflict); }
        self.disposal = Some(if self.request_operation.as_ref()
            .is_none_or(|operation| operation.is_consumed_current())
            && self.fixed_operation.as_ref().is_some_and(|operation| operation.is_consumed_current())
        { Ok(()) } else { Err(ControllerReceivingErrorV1::Conflict) });
        if !matches!(self.disposal, Some(Ok(()))) {
            self.first = Some(PhysicalFirstV1::Disposal);
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        if let Some(operation) = self.request_operation.take() {
            operation.complete_after_disposal();
        }
        Ok(())
    }

    /// Borrows the first actual stored representation failure without IO.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            PhysicalFirstV1::Profile => failure(&self.profile),
            PhysicalFirstV1::Current => failure(&self.current),
            PhysicalFirstV1::Complete => failure(&self.complete),
            PhysicalFirstV1::Debit => failure(&self.debit),
            PhysicalFirstV1::Operation => self.request_operation.as_ref()
                .and_then(|operation| operation.failure()).map(|cause| cause as _)
                .or_else(|| self.fixed_operation.as_ref().and_then(|operation| operation.failure())
                    .map(|cause| cause as _)).or_else(|| failure(&self.operation_result)),
            PhysicalFirstV1::Disposal => failure(&self.disposal),
        }
    }
}

fn failure<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::budget::{BaselineDemand, BaselineOwner};
    use aos_sandbox_core::ResourceDimension as D;

    #[test]
    fn initial_roles_follow_existing_fixed_order_and_distinct_ledger_owners() {
        let roles = [ControllerInitialBrokerSessionRoleV1::Host,
            ControllerInitialBrokerSessionRoleV1::Mount,
            ControllerInitialBrokerSessionRoleV1::Storage,
            ControllerInitialBrokerSessionRoleV1::Network];
        for (index, role) in roles.into_iter().enumerate() {
            assert_eq!(role.index(), index);
            assert_eq!(role.owner() as usize, BaselineOwner::InitialHostSession as usize + index);
        }
    }

    #[test]
    fn initial_session_representation_uses_the_same_monotone_aggregate() {
        let capacity = ResourceVector::ZERO.with(D::MemoryBytes, 10).with(D::MetadataEntries, 10);
        let mut ledger = BaselineDemand::new();
        ledger.begin().unwrap();
        ledger.raise(BaselineOwner::InitialHostSession,
            ResourceVector::ZERO.with(D::MemoryBytes, 8), capacity).unwrap();
        ledger.begin().unwrap();
        ledger.raise(BaselineOwner::InitialStorageSession,
            ResourceVector::ZERO.with(D::MemoryBytes, 2), capacity).unwrap();

        // A lower repeated Host requirement does not refund its prior eight
        // bytes or any distinct Storage charge on the SAME bookkeeping owner.
        ledger.begin().unwrap();
        ledger.raise(BaselineOwner::InitialHostSession,
            ResourceVector::ZERO.with(D::MemoryBytes, 1).with(D::MetadataEntries, 10), capacity).unwrap();
        ledger.begin().unwrap();
        assert!(ledger.raise(BaselineOwner::InitialNetworkSession,
            ResourceVector::ZERO.with(D::MemoryBytes, 1), capacity).is_err());
        assert!(ledger.is_closed());
        assert!(ledger.begin().is_err());
    }
}

impl ControllerInitialSessionReceivingOriginalV1 {
    /// Joins the actual completed endpoint aggregate to this same claimed C.
    ///
    /// This readonly custody check grants no IO, admission or semantic result.
    ///
    /// # Errors
    /// Refuses a failed/unfinished interval, foreign aggregate or live probe.
    #[doc(hidden)]
    pub fn require_completed_endpoint_native_v1(
        &self,
        actual: &Arc<crate::endpoint_native_files::ControllerEndpointNativeCustodyV1>,
    ) -> Result<(), ControllerReceivingErrorV1> {
        if self.first.is_some() || !matches!(self.before, Some(Ok(_)))
            || !matches!(self.after, Some(Ok(_)))
            || !self.endpoint_custody.as_ref().is_some_and(|held| Arc::ptr_eq(held, actual))
            || actual.retained_open_file_count_v1() != Some(6)
        {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        self.require_claimed_v1()
    }
}

impl ControllerStorageFloorRepresentationV1 {
    /// Compares the persistent Storage representation with its actual initial C.
    ///
    /// # Errors
    /// Refuses another original, role or a closed financial owner.
    #[doc(hidden)]
    pub fn require_initial_original_v1(
        &mut self,
        initial: &ControllerInitialSessionReceivingOriginalV1,
    ) -> Result<(), ControllerReceivingErrorV1> {
        if initial.role != ControllerInitialBrokerSessionRoleV1::Storage
            || !Arc::ptr_eq(&self.original, &initial.original)
        {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        match (&self.recover, &initial.recover) {
            (Some(held), Some(actual)) if Arc::ptr_eq(held, actual) => {},
            (None, None) => {},
            _ => return Err(ControllerReceivingErrorV1::Conflict),
        }
        self.require_persistent_current_v1()
    }
}

static INITIAL_EXECUTION_CLOSED: super::ControllerReceivingErrorV1 = super::ControllerReceivingErrorV1::Conflict;

impl ControllerInitialSessionReceivingOriginalV1 {
    pub(in crate::controller_receiving) fn matches_recover_storage_original_v1(
        &self,
        expected: &Arc<super::bank_launch::ControllerSessionRepresentationV3>,
        original: &Arc<ControllerReceivingOriginalV1>,
    ) -> bool {
        self.matches_recovery_session_original_v2(expected, original,
            ControllerInitialBrokerSessionRoleV1::Storage)
    }

    pub(in crate::controller_receiving) fn matches_recovery_session_original_v2(
        &self, expected: &Arc<super::bank_launch::ControllerSessionRepresentationV3>,
        original: &Arc<ControllerReceivingOriginalV1>, role: ControllerInitialBrokerSessionRoleV1,
    ) -> bool {
        self.role == role && expected.role_data_v2() == role
            && Arc::ptr_eq(&self.original, original)
            && self.recover.as_ref().is_some_and(|actual| Arc::ptr_eq(actual, expected))
    }
}


impl ControllerInitialSessionReceivingOriginalV1 {
    pub(in crate::controller_receiving) fn require_completed_recovered_ordinary_v2(&self,
        expected: &Arc<super::bank_launch::ControllerSessionRepresentationV3>,
        original: &Arc<ControllerReceivingOriginalV1>, role: ControllerInitialBrokerSessionRoleV1,
    ) -> Result<(), ControllerReceivingErrorV1> {
        if !self.matches_recovered_ordinary_original_v2(expected, original, role) {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        self.require_completed_ordinary_endpoint_v2()
    }

    fn require_completed_ordinary_endpoint_v2(&self)
        -> Result<(), ControllerReceivingErrorV1> {
        if self.first.is_some() || !matches!(self.before, Some(Ok(_)))
            || !matches!(self.after, Some(Ok(_)))
            || !matches!(self.endpoint_completion, Some(Ok(())))
            || self.endpoint_custody.as_ref().and_then(|custody| custody.retained_open_file_count_v1()) != Some(6)
        {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        self.require_claimed_v1()
    }

    // Only the actual current maintenance native original calls this private
    // comparison. No saved generation, receiver or context DATA is adopted.
    pub(in crate::controller_receiving) fn require_completed_maintenance_original_v2(&self,
        original: &Arc<ControllerReceivingOriginalV1>, role: ControllerInitialBrokerSessionRoleV1,
    ) -> Result<(), ControllerReceivingErrorV1> {
        if self.role != role || !Arc::ptr_eq(&self.original, original) {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        original.require_catalog_maintenance_context_v2()?;
        match (original.writer_enrollment()?.controller_generation_v1, self.recover.as_ref()) {
            (Some(0), None) => self.require_completed_ordinary_endpoint_v2(),
            (Some(ordinal), Some(actual)) if ordinal > 0 && !actual.is_reconciliation_v2() => {
                self.require_completed_recovered_ordinary_v2(actual, original, role)
            }
            _ => Err(ControllerReceivingErrorV1::Conflict),
        }
    }

    pub(in crate::controller_receiving) fn matches_recovered_ordinary_original_v2(&self,
        expected: &Arc<super::bank_launch::ControllerSessionRepresentationV3>,
        original: &Arc<ControllerReceivingOriginalV1>, role: ControllerInitialBrokerSessionRoleV1,
    ) -> bool {
        !expected.is_reconciliation_v2() && self.role == role && expected.role_data_v2() == role
            && Arc::ptr_eq(&self.original, original)
            && self.recover.as_ref().is_some_and(|actual| Arc::ptr_eq(actual, expected))
    }
}
