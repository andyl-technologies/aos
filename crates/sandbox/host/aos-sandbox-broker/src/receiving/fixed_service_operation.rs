//! Finite Mount and Network intervals on their genuine image-enrolled owner.
//!
//! Cost DATA restricts the same retained F ledger. It never authenticates a
//! request or permits a semantic effect. The fixed role and native originals
//! come only from the actual PID1 flight; no role or account can be adopted.

mod clock;
mod host_cold_clock;
pub use host_cold_clock::HostControlColdClockOriginalV1;
mod network_worker_birth;
pub use network_worker_birth::{NetworkWorkerBirthOriginalV2, NetworkWorkerBirthPurposeV2, NetworkWorkerBirthReservationV2};
mod fd_store_empty;
pub use fd_store_empty::FixedServiceInventoryFdStoreEmptyOriginalV2;
mod network_worker_inventory;
pub use network_worker_inventory::NetworkWorkerInventoryObservationOriginalV4;

use std::error::Error;

use aos_sandbox_model::{AccountingError, RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_model::component_receiving::complete_bound_delta_v1;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;

use super::fixed_service_currentness::FixedServiceCurrentnessSampleV1;
use super::fixed_service_receiving::{FixedServiceReceivingCaptureV1, FixedServiceRoleV1};
use super::representation::RepresentationDemandDebitV1;

/// Reports a closed interval while its owner retains the original cause.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, thiserror::Error)]
#[error("fixed-service operation is closed")]
pub struct FixedServiceOperationClosedV4;

#[derive(Clone, Copy)]
enum Failure { Entry, Geometry, Accounting, Before, Method, Body, After, Clock, Order }

#[derive(Clone, Copy)]
enum Purpose { NetworkRequestReceiving, NetworkPrepare, NetworkDestroy, NetworkInventory, MountAttachmentAnchor, MountInventory,
    MountSessionOpening, NetworkSessionOpening }

impl Purpose {
    fn role(self) -> FixedServiceRoleV1 {
        match self {
            Self::NetworkRequestReceiving | Self::NetworkPrepare | Self::NetworkDestroy | Self::NetworkInventory | Self::NetworkSessionOpening => FixedServiceRoleV1::Network,
            Self::MountAttachmentAnchor | Self::MountInventory | Self::MountSessionOpening => FixedServiceRoleV1::Mount,
        }
    }

    fn method(self) -> Option<u32> {
        match self {
            Self::NetworkPrepare => Some(63),
            Self::NetworkDestroy => Some(9),
            Self::NetworkInventory => Some(19),
            Self::MountAttachmentAnchor => Some(62),
            Self::MountInventory => Some(16),
            Self::NetworkRequestReceiving | Self::MountSessionOpening | Self::NetworkSessionOpening => None,
        }
    }

    fn primary_clocks(self) -> usize {
        match self {
            // The shared finite worker programme separately gates each P/O
            // frontier; this is the parent domain/Session/send upper bound.
            Self::NetworkRequestReceiving | Self::NetworkPrepare | Self::NetworkDestroy => 14,
            // Admission, twelve domain mutations, Session terminal CAS, send.
            Self::MountAttachmentAnchor => 15,
            // Admission, Session terminal CAS, send.
            Self::NetworkInventory | Self::MountInventory => 3,
            // Opening + installer 26 + endpoint publication + BrokerHello.
            Self::MountSessionOpening | Self::NetworkSessionOpening => 29,
        }
    }
}

// Only the existing authenticated Session receipt supplies these coordinates.
// Keeping them on the same interval denies a later foreign request of the same
// method; they provide neither signed domain authority nor another Source.
#[derive(Clone, Copy, PartialEq, Eq)]
struct NetworkRequestBindingV5 {
    request: [u8; 16],
    session: [u8; 32],
    signed_packet: [u8; 32],
    method: u32,
}

impl NetworkRequestBindingV5 {
    fn from_authenticated(request: &AuthenticatedBrokerMethodRequestV1) -> Self {
        Self {
            request: request.request_id(),
            session: request.session_binding(),
            signed_packet: request.signed_request_digest(),
            method: request.method() as u32,
        }
    }
}

/// Identifies which retained owner supplies a Network aggregate refusal.
///
/// The actual worker keeps its lower native original and the same operation
/// through all owed posts. These markers neither contain a grant nor replace
/// the original financial/native cause.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NetworkWorkerAggregateInitializationRefusalV4 {
    /// The same operation's entry, geometry or financial gate refused first.
    #[error("the original Network receiving gate refused aggregate initialization")]
    Original,
    /// The lower aggregate capture entered and retained its native refusal.
    #[error("the retained Network aggregate native capture refused")]
    Native,
}

/// Retains one fixed-purpose interval, including both independent native posts.
///
/// Construction is inert. Entered destinations cannot be replaced or rearmed.
/// The owning service retains completed and failed intervals for their actual
/// model/native lifetime; the ledger never refunds their committed liability.
#[must_use]
pub struct FixedServiceOperationOriginalV4 {
    entered: bool,
    armed: bool,
    finished: bool,
    purpose: Option<Purpose>,
    invocation: Option<[u8; 16]>,
    first: Option<Failure>,
    closed: FixedServiceOperationClosedV4,
    geometry: Option<Result<ResourceVector, AccountingError>>,
    committed: ResourceVector,
    clock: clock::OperationClockV4,
    installer_clocks: usize,
    worker_cleanup_prearmed: bool,
    worker_birth_mask: u8,
    worker_terminal_mask: u8,
    worker_success_mask: u8,
    operation_ordinal: Option<u64>,
    worker_aggregate_entered: bool,
    worker_aggregate_result: Option<Result<(), aos_linux_descriptors::Error>>,
    before: FixedServiceCurrentnessSampleV1<FixedServiceOperationClosedV4>,
    before_result: Option<Result<(), FixedServiceOperationClosedV4>>,
    method: Option<Result<(), FixedServiceOperationClosedV4>>,
    network_request: Option<NetworkRequestBindingV5>,
    body: Option<Result<(), FixedServiceOperationClosedV4>>,
    after: FixedServiceCurrentnessSampleV1<FixedServiceOperationClosedV4>,
    after_result: Option<Result<(), FixedServiceOperationClosedV4>>,
}

impl Default for FixedServiceOperationOriginalV4 {
    fn default() -> Self { Self::new() }
}

impl FixedServiceOperationOriginalV4 {
    /// Creates empty destinations without inspecting a role, request or file.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entered: false, armed: false, finished: false, purpose: None,
            invocation: None, first: None, closed: FixedServiceOperationClosedV4,
            geometry: None, committed: ResourceVector::ZERO, clock: Default::default(), installer_clocks: 0, worker_cleanup_prearmed: false, worker_birth_mask: 0, worker_terminal_mask: 0, worker_success_mask: 0, operation_ordinal: None, worker_aggregate_entered: false, worker_aggregate_result: None,
            before: Default::default(), before_result: None, method: None,
            network_request: None, body: None, after: Default::default(), after_result: None,
        }
    }

    /// Borrows the interval's first native, geometry or closed cause.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            Failure::Geometry => self.geometry.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)),
            Failure::Before => self.before.failure(),
            Failure::After => self.after.failure(),
            Failure::Clock => self.clock.failure(),
            _ => None,
        }.or(Some(&self.closed))
    }

    /// Borrows the actual financial cause only for this same original's debit.
    ///
    /// A late post cannot replace an earlier native/body cause, and another
    /// service's ledger cannot supply this operation's diagnostic origin.
    pub fn failure_with_common_v4<'held>(
        &'held self, common: &'held FixedServiceReceivingCaptureV1<FixedServiceOperationClosedV4>,
    ) -> Option<&'held (dyn Error + 'static)> {
        if matches!(self.first, Some(Failure::Accounting))
            && self.invocation == common.enrollment.map(|value| value.recipient_invocation)
            && self.purpose.is_some_and(|purpose| purpose.role() == common.role)
        {
            common.representation.as_ref().and_then(|ledger| ledger.failure()).map(|cause| cause as _)
                .or_else(|| self.failure())
        } else { self.failure() }
    }

    fn fail(&mut self, site: Failure) -> FixedServiceOperationClosedV4 {
        self.first.get_or_insert(site);
        self.closed
    }

    fn native_demand(purpose: Option<Purpose>) -> Result<ResourceVector, AccountingError> {
        let sample = FixedServiceCurrentnessSampleV1::<FixedServiceOperationClosedV4>::dynamic_demand()?;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|value| u64::try_from(value).ok())
            .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
        let native = sample.checked_add(sample)?.checked_add(clock::OperationClockV4::dynamic_demand()?)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))?;
        if purpose.is_some_and(|purpose| purpose.role() == FixedServiceRoleV1::Network) {
            let aggregate = FixedServiceCurrentnessSampleV1::<FixedServiceOperationClosedV4>::
                network_aggregate_dynamic_demand_v4()?;
            native.checked_add(aggregate)?.checked_add(aggregate)
        } else { Ok(native) }
    }
}

/// Borrows one genuine Network purpose and its original native destinations.
pub type NetworkServiceReceivingLoanV4<'held> = FixedServiceOperationLoanV4<'held>;

/// Borrows only the genuine Mount attachment-anchor purpose.
pub type MountAttachmentAnchorReceivingLoanV4<'held> = FixedServiceOperationLoanV4<'held>;

/// Borrows the actual Mount service's distinct protected Session opening.
pub type MountServiceSessionOpeningLoanV4<'held> = FixedServiceOperationLoanV4<'held>;

/// Borrows the actual Network service's distinct protected Session opening.
pub type NetworkServiceSessionOpeningLoanV4<'held> = FixedServiceOperationLoanV4<'held>;

/// Retains the two prearmed clock destinations for one Network worker cleanup.
///
/// This opaque scope binds the same live Prepare63 or Destroy9 operation and the actual
/// service's checked, nonreusable operation ordinal. Recycled storage cannot
/// associate a prior unused scope with a later operation. It supplies no
/// native child identity or permission to signal a process; the worker must
/// separately retain its validated READY child and disabling-only scope.
#[must_use]
pub struct NetworkWorkerCleanupClockScopeV4 {
    operation_address: usize,
    operation_ordinal: u64,
    invocation: [u8; 16],
    used: usize,
}

/// Restricts one closed role interval without exposing a ledger or native file.
pub struct FixedServiceOperationLoanV4<'held> {
    common: &'held mut FixedServiceReceivingCaptureV1<FixedServiceOperationClosedV4>,
    operation: &'held mut FixedServiceOperationOriginalV4,
}

impl FixedServiceReceivingCaptureV1<FixedServiceOperationClosedV4> {
    /// Enters only Network's paid request-receiving phase on its actual F.
    ///
    /// The same ordinal, native originals and clock survive authentication.
    /// No effect purpose exists until the SDK consumes an authenticated request.
    ///
    /// # Errors
    /// Refuses wrong roles, incomplete startup, previous debt or repeated entry.
    pub fn begin_network_request_receiving_once_v5<'held>(
        &'held mut self, operation: &'held mut FixedServiceOperationOriginalV4,
        fixed: ResourceVector,
    ) -> Result<NetworkServiceReceivingLoanV4<'held>, FixedServiceOperationClosedV4> {
        self.begin_operation(operation, fixed, Purpose::NetworkRequestReceiving)
    }

    /// Admits Mount's cold Session opening after completed native startup.
    ///
    /// This purpose accepts no broker method and supplies no effect authority.
    /// The actual SDK must retain and verify its fixed endpoint/HELLO owners.
    ///
    /// # Errors
    /// Refuses wrong roles, incomplete startup or an occupied/closed interval.
    pub fn begin_mount_session_opening_once_v4<'held>(
        &'held mut self, operation: &'held mut FixedServiceOperationOriginalV4,
        fixed: ResourceVector,
    ) -> Result<MountServiceSessionOpeningLoanV4<'held>, FixedServiceOperationClosedV4> {
        self.begin_operation(operation, fixed, Purpose::MountSessionOpening)
    }

    /// Admits Network's cold Session opening on its actual service owner.
    ///
    /// # Errors
    /// Refuses wrong roles, incomplete startup or an occupied/closed interval.
    pub fn begin_network_session_opening_once_v4<'held>(
        &'held mut self, operation: &'held mut FixedServiceOperationOriginalV4,
        fixed: ResourceVector,
    ) -> Result<NetworkServiceSessionOpeningLoanV4<'held>, FixedServiceOperationClosedV4> {
        self.begin_operation(operation, fixed, Purpose::NetworkSessionOpening)
    }

    /// Admits the fixed Network Prepare63 receiving interval before decoding.
    ///
    /// # Errors
    /// Retains refusal without entering native IO when the first debit fails.
    pub fn begin_network_prepare_once_v4<'held>(
        &'held mut self, operation: &'held mut FixedServiceOperationOriginalV4, fixed: ResourceVector,
    ) -> Result<NetworkServiceReceivingLoanV4<'held>, FixedServiceOperationClosedV4> {
        self.begin_operation(operation, fixed, Purpose::NetworkPrepare)
    }

    /// Admits the distinct Destroy9 interval on the genuine enrolled Netd owner.
    ///
    /// This reserves the same native/financial engine before hostile decoding.
    /// The actual authenticated Destroy request and signed domain admission
    /// remain required before the worker can enter its physical programme.
    ///
    /// # Errors
    /// Refuses another role, incomplete startup, reentry or original F failure.
    pub fn begin_network_destroy_once_v4<'held>(
        &'held mut self, operation: &'held mut FixedServiceOperationOriginalV4,
        fixed: ResourceVector,
    ) -> Result<NetworkServiceReceivingLoanV4<'held>, FixedServiceOperationClosedV4> {
        self.begin_operation(operation, fixed, Purpose::NetworkDestroy)
    }

    /// Admits the separate Network Inventory19 interval on the same original.
    ///
    /// # Errors
    /// Refuses wrong roles, unfinished intervals or sticky native/debit failure.
    pub fn begin_network_inventory_once_v4<'held>(
        &'held mut self, operation: &'held mut FixedServiceOperationOriginalV4, fixed: ResourceVector,
    ) -> Result<NetworkServiceReceivingLoanV4<'held>, FixedServiceOperationClosedV4> {
        self.begin_operation(operation, fixed, Purpose::NetworkInventory)
    }

    /// Admits only Mount's AttachmentAnchor62 receiving interval.
    ///
    /// # Errors
    /// Refuses provider-Acquire and every original not captured as Mount.
    pub fn begin_mount_attachment_anchor_once_v4<'held>(
        &'held mut self, operation: &'held mut FixedServiceOperationOriginalV4, fixed: ResourceVector,
    ) -> Result<MountAttachmentAnchorReceivingLoanV4<'held>, FixedServiceOperationClosedV4> {
        self.begin_operation(operation, fixed, Purpose::MountAttachmentAnchor)
    }

    /// Admits Mount's separate fresh destination inventory16 interval.
    ///
    /// # Errors
    /// Refuses another role or an outstanding/failed interval before native IO.
    pub fn begin_mount_attachment_anchor_inventory_once_v4<'held>(
        &'held mut self, operation: &'held mut FixedServiceOperationOriginalV4, fixed: ResourceVector,
    ) -> Result<MountAttachmentAnchorReceivingLoanV4<'held>, FixedServiceOperationClosedV4> {
        self.begin_operation(operation, fixed, Purpose::MountInventory)
    }

    fn begin_operation<'held>(
        &'held mut self, operation: &'held mut FixedServiceOperationOriginalV4,
        fixed: ResourceVector, purpose: Purpose,
    ) -> Result<FixedServiceOperationLoanV4<'held>, FixedServiceOperationClosedV4> {
        if operation.entered || self.operation_active || self.operation_closed
            || self.inventory_disposal_pending.is_some()
            || self.role != purpose.role() || self.require_permanent_fd_coverage_v1().is_err()
            || !self.service_startup.as_ref().is_some_and(|owner| owner.complete())
        {
            self.operation_closed = true;
            return Err(operation.fail(Failure::Entry));
        }
        let Some(ordinal) = self.operation_ordinal.checked_add(1) else {
            self.operation_closed = true;
            return Err(operation.fail(Failure::Order));
        };
        self.operation_ordinal = ordinal;
        operation.operation_ordinal = Some(ordinal);
        operation.entered = true;
        operation.purpose = Some(purpose);
        operation.invocation = self.enrollment.map(|original| original.recipient_invocation);
        self.operation_active = true;
        let mut loan = FixedServiceOperationLoanV4 { common: self, operation };
        loan.require_representation_v4(fixed)?;
        loan.operation.armed = true;
        Ok(loan)
    }
}

impl FixedServiceOperationLoanV4<'_> {
    /// Samples before one of the fixed installer's 26 actual native frontiers.
    ///
    /// The closed recipe has two mkdir attempts and their parent syncs,
    /// one writable-directory mode,
    /// six mutations for each of three files, final mode+sync and a final
    /// boundary. Opening, endpoint publication and BrokerHello keep distinct
    /// slots.
    /// Every successful primary reader is physically disposed by the same
    /// clock engine before its next observation; failed prefixes stay held.
    ///
    /// # Errors
    /// Refuses a request purpose, expired unchanged cutoff, prior failure or
    /// exhausted finite installer roster. No new baseline/window is created.
    pub fn observe_session_install_frontier_clock_v4(&mut self)
        -> Result<RawPairedClockSample, FixedServiceOperationClosedV4>
    {
        self.require_session_opening_current_v4()?;
        if self.operation.installer_clocks >= 26 {
            self.common.operation_closed = true;
            return Err(self.operation.fail(Failure::Clock));
        }
        self.operation.installer_clocks += 1;
        // At most the original opening plus 26 installer pairs can enter here.
        // Slots 28 and 29 remain for endpoint publication and BrokerHello.
        self.operation.clock.observe_primary(27).map_err(|_| {
            self.common.operation_closed = true;
            self.operation.fail(Failure::Clock)
        })
    }

    /// Requires the actual Mount cold-opening purpose before fixed Mount IO.
    ///
    /// # Errors
    /// Refuses Network opening, every request purpose or failed currentness.
    pub fn require_mount_session_opening_current_v4(&mut self)
        -> Result<(), FixedServiceOperationClosedV4>
    {
        self.require_exact_session_opening(Purpose::MountSessionOpening)
    }

    /// Requires the actual Network cold-opening purpose before fixed Network IO.
    ///
    /// # Errors
    /// Refuses Mount opening, every request purpose or failed currentness.
    pub fn require_network_session_opening_current_v4(&mut self)
        -> Result<(), FixedServiceOperationClosedV4>
    {
        self.require_exact_session_opening(Purpose::NetworkSessionOpening)
    }

    fn require_exact_session_opening(&mut self, expected: Purpose)
        -> Result<(), FixedServiceOperationClosedV4>
    {
        self.require_bound()?;
        let actual_matches = matches!((self.operation.purpose, expected),
            (Some(Purpose::MountSessionOpening), Purpose::MountSessionOpening)
            | (Some(Purpose::NetworkSessionOpening), Purpose::NetworkSessionOpening));
        if !actual_matches {
            self.common.operation_closed = true;
            return Err(self.operation.fail(Failure::Method));
        }
        self.require_session_opening_current_v4()
    }

    /// Requires only the entered fixed-role Session-opening native interval.
    ///
    /// Its actual transport cutoff must already have been narrowed around the
    /// retained opening sample. No opcode or request DATA can select it.
    ///
    /// # Errors
    /// Refuses every request purpose, method adoption, failed native prefix or
    /// expired unchanged transport cutoff. This is not effect admission.
    pub fn require_session_opening_current_v4(&mut self)
        -> Result<(), FixedServiceOperationClosedV4>
    {
        self.require_bound()?;
        if !matches!(self.operation.purpose,
            Some(Purpose::MountSessionOpening | Purpose::NetworkSessionOpening))
            || self.operation.method.is_some()
        {
            self.common.operation_closed = true;
            return Err(self.operation.fail(Failure::Method));
        }
        self.operation.clock.require_current().map_err(|_| {
            self.common.operation_closed = true;
            self.operation.fail(Failure::Clock)
        })
    }

    /// Admits another co-live representation plane on this same interval.
    ///
    /// This adds the contribution to this original's previously committed
    /// external representation and delegates the sole cumulative debit engine.
    /// It cannot replace an earlier request, Session or model liability.
    ///
    /// # Errors
    /// Retains checked arithmetic, original capacity or prior interval refusal.
    pub fn require_additional_representation_v4(
        &mut self, additional: ResourceVector,
    ) -> Result<(), FixedServiceOperationClosedV4> {
        if self.operation.first.is_some() || self.operation.finished {
            return Err(self.operation.fail(Failure::Order));
        }
        self.operation.geometry = Some((|| {
            let native = FixedServiceOperationOriginalV4::native_demand(self.operation.purpose)?;
            self.operation.committed.checked_sub(native)?.checked_add(additional)
        })());
        let shape = match self.operation.geometry.as_ref().and_then(|value| value.as_ref().ok()).copied() {
            Some(shape) => shape,
            None => {
                self.common.operation_closed = true;
                return Err(self.operation.fail(Failure::Geometry));
            }
        };
        self.require_representation_v4(shape)
    }

    /// Returns the actual enrolled invocation of this same held operation.
    ///
    /// This comparison DATA is not a native observation or admission grant.
    ///
    /// # Errors
    /// Refuses a foreign, failed, unentered or completed operation.
    pub fn actual_invocation_data_v4(&mut self) -> Result<[u8; 16], FixedServiceOperationClosedV4> {
        self.require_bound()?;
        self.operation.invocation.ok_or(self.operation.closed)
    }

    /// Admits the complete cumulative interval shape before corresponding growth.
    ///
    /// Cost DATA supplies no request/effect authority. FD liabilities stay in
    /// the SAME precharged F3 bound, including all earlier retained intervals.
    ///
    /// # Errors
    /// Preserves the first checked arithmetic or original ledger refusal.
    pub fn require_representation_v4(&mut self, shape: ResourceVector) -> Result<(), FixedServiceOperationClosedV4> {
        if self.operation.first.is_some() || self.operation.finished {
            return Err(self.operation.fail(Failure::Order));
        }
        self.operation.geometry = Some((|| {
            let requirement = FixedServiceOperationOriginalV4::native_demand(self.operation.purpose)?.checked_add(shape)?;
            let (high, delta) = complete_bound_delta_v1(self.operation.committed, requirement)?;
            let files = self.common.operation_files.checked_add(delta.get(D::OpenFiles))
                .ok_or(AccountingError::ArithmeticOverflow { dimension: D::OpenFiles })?;
            let startup = self.common.fixed_startup_demand()?;
            let attempted = startup.get(D::OpenFiles)
                .checked_add(self.common.service_startup.as_ref().map_or(0, |owner| owner.committed_files()))
                .and_then(|base| base.checked_add(files))
                .ok_or(AccountingError::ArithmeticOverflow { dimension: D::OpenFiles })?;
            let limit = self.common.permanent_open_files().map_err(|_| AccountingError::ArithmeticOverflow { dimension: D::OpenFiles })?;
            if attempted > limit {
                return Err(AccountingError::LimitExceeded { dimension: D::OpenFiles, limit, attempted });
            }
            Ok(high)
        })());
        let high = match self.operation.geometry.as_ref().and_then(|value| value.as_ref().ok()).copied() {
            Some(high) => high,
            None => {
                self.common.operation_closed = true;
                return Err(self.operation.fail(Failure::Geometry));
            }
        };
        let delta = high.checked_sub(self.operation.committed).map_err(|_| self.operation.fail(Failure::Geometry))?;
        let admitted = self.common.representation.as_mut()
            .is_some_and(|ledger| ledger.reserve(delta.with(D::OpenFiles, 0)).is_ok());
        if !admitted {
            self.common.operation_closed = true;
            return Err(self.operation.fail(Failure::Accounting));
        }
        self.common.operation_files += delta.get(D::OpenFiles);
        self.operation.committed = high;
        Ok(())
    }

    /// Checks the authenticated method against the actual private begin purpose.
    ///
    /// # Errors
    /// A mismatch is sticky; Prepare63 cannot become Inventory19 or Mount62.
    pub fn require_method_data_v4(&mut self, method: u32) -> Result<(), FixedServiceOperationClosedV4> {
        if self.operation.method.is_some() || self.operation.first.is_some() {
            return Err(self.operation.fail(Failure::Order));
        }
        self.operation.method = Some(if self.operation.purpose.is_some_and(|purpose| purpose.method() == Some(method)) {
            Ok(())
        } else { Err(self.operation.closed) });
        if matches!(self.operation.method, Some(Ok(()))) { Ok(()) }
        else {
            self.common.operation_closed = true;
            Err(self.operation.fail(Failure::Method))
        }
    }

    /// Consumes neutral receiving with the SDK's actual authenticated request.
    ///
    /// This selects only 19, 63 or 9 on the same original. It does not resample
    /// the opening pair or create a new deadline, ordinal or financial owner.
    /// The caller must next narrow the clock to this same signed request D.
    ///
    /// # Errors
    /// Retains unknown methods, substituted requests or repeated selection.
    pub fn select_authenticated_network_request_once_v5(
        &mut self, request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), FixedServiceOperationClosedV4> {
        self.require_bound()?;
        if !matches!(self.operation.purpose, Some(Purpose::NetworkRequestReceiving))
            || self.operation.method.is_some() || self.operation.network_request.is_some()
        {
            self.common.operation_closed = true;
            return Err(self.operation.fail(Failure::Method));
        }
        let purpose = match request.method() as u32 {
            19 => Purpose::NetworkInventory,
            63 => Purpose::NetworkPrepare,
            9 => Purpose::NetworkDestroy,
            _ => {
                self.common.operation_closed = true;
                return Err(self.operation.fail(Failure::Method));
            }
        };
        self.operation.purpose = Some(purpose);
        self.operation.network_request = Some(NetworkRequestBindingV5::from_authenticated(request));
        self.require_method_data_v4(request.method() as u32)
    }

    /// Rejoins the same selected authenticated request before a domain branch.
    ///
    /// # Errors
    /// Refuses unselected, changed, poisoned or expired original custody.
    pub fn require_selected_network_request_v5(
        &mut self, request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), FixedServiceOperationClosedV4> {
        if self.operation.network_request != Some(NetworkRequestBindingV5::from_authenticated(request)) {
            self.common.operation_closed = true;
            return Err(self.operation.fail(Failure::Method));
        }
        self.require_network_current_v4()
    }

    /// Runs the already paid independent native entry sample once.
    ///
    /// # Errors
    /// Retains actual native failure and permanently closes positive entry.
    pub fn observe_before_once_v4(&mut self) -> Result<(), FixedServiceOperationClosedV4> {
        if !self.operation.armed || self.operation.before_result.is_some() || self.operation.first.is_some() {
            return Err(self.operation.fail(Failure::Order));
        }
        self.operation.before_result = Some(observe(self.common, &mut self.operation.before));
        if matches!(self.operation.before_result, Some(Ok(()))) { Ok(()) }
        else {
            self.common.operation_closed = true;
            Err(self.operation.fail(Failure::Before))
        }
    }

    /// Returns the retained actual opening kernel pair for signed admission.
    ///
    /// # Errors
    /// Refuses reentry, a failed native prefix or a different held invocation.
    pub fn actual_before_clock_v4(&mut self) -> Result<RawPairedClockSample, FixedServiceOperationClosedV4> {
        self.require_bound()?;
        self.operation.clock.observe_primary(1).map_err(|_| {
            self.common.operation_closed = true;
            self.operation.fail(Failure::Clock)
        })
    }

    /// Reborrows the actual already-sampled opening pair as comparison DATA.
    ///
    /// The protected Session receipt and domain admission use the same pair;
    /// this performs no observation, schedule advance or deadline renewal.
    ///
    /// # Errors
    /// Refuses a missing, failed, completed or foreign opening interval.
    pub fn retained_opening_clock_data_v4(&mut self)
        -> Result<RawPairedClockSample, FixedServiceOperationClosedV4>
    {
        self.require_bound()?;
        self.operation.clock.opening_data()
    }

    /// Samples the same prepaid finite kernel gate before the next frontier.
    ///
    /// # Errors
    /// Preserves native/time failure and refuses the closed purpose's finite
    /// schedule exhaustion. No sample creates an effect or renews a deadline.
    pub fn observe_frontier_clock_v4(&mut self) -> Result<RawPairedClockSample, FixedServiceOperationClosedV4> {
        self.require_bound()?;
        let maximum = self.operation.purpose.ok_or(self.operation.closed)?.primary_clocks();
        self.operation.clock.observe_primary(maximum).map_err(|_| {
            self.common.operation_closed = true;
            self.operation.fail(Failure::Clock)
        })
    }

    /// Returns the same fresh fixed-purpose pre-effect kernel observation.
    ///
    /// # Errors
    /// Preserves the exact shared gate refusal without a second clock engine.
    pub fn fresh_before_effect_clock_v4(&mut self) -> Result<RawPairedClockSample, FixedServiceOperationClosedV4> {
        self.observe_frontier_clock_v4()
    }

    /// Samples the finite worker lane of the actual Prepare63 or Destroy9 owner.
    ///
    /// The same original kernel reader, sequencing baseline, request/lease
    /// ceilings and independently owed after are reused. Ordinary domain,
    /// Session CAS and response-send slots are not consumed by these bounded
    /// worker/FDStore mutation attempts; readonly D-Bus packets use no slot.
    ///
    /// # Errors
    /// Refuses another purpose, poison, native/clock failure, or the exact
    /// finite source ceiling for the actual worker programme. No retry is authorized.
    pub fn observe_network_worker_effect_clock_v4(&mut self)
        -> Result<RawPairedClockSample, FixedServiceOperationClosedV4> {
        if !matches!(self.operation.purpose, Some(Purpose::NetworkPrepare | Purpose::NetworkDestroy)) {
            self.common.operation_closed = true;
            return Err(self.operation.fail(Failure::Method));
        }
        self.require_current_interval()?;
        self.operation.clock.observe_worker_primary_v4().map_err(|_| {
            self.common.operation_closed = true;
            self.operation.fail(Failure::Clock)
        })
    }

    /// Initializes a worker's native association from this actual private aggregate.
    ///
    /// The same full lower supplier is admitted before its first native entry.
    /// No cgroup pathname, descriptor, account or caller-selected limit is lent.
    /// Actual child construction/receiving remains separately prepaid by the
    /// worker; this native comparison creates no financial or effect authority.
    ///
    /// # Errors
    /// Distinguishes the actual prior receiving gate from an entered lower
    /// native refusal. Reentry neither replaces the owner nor repeats IO.
    pub fn initialize_network_worker_aggregate_once_v4(&mut self,
        original: &mut aos_sandbox_linux::cgroup::NetworkWorkerAggregateAssociationOriginalV4,
    ) -> Result<(), NetworkWorkerAggregateInitializationRefusalV4> {
        use NetworkWorkerAggregateInitializationRefusalV4 as Refusal;
        if self.operation.worker_aggregate_entered {
            self.common.operation_closed = true;
            self.operation.fail(Failure::Order);
            return Err(if matches!(self.operation.worker_aggregate_result, Some(Err(_))) {
                Refusal::Native
            } else { Refusal::Original });
        }
        self.require_network_worker_current_v4().map_err(|_| Refusal::Original)?;
        self.operation.worker_aggregate_entered = true;
        let demand = (|| {
            let overflow = AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes };
            let (bytes, files, names) = aos_sandbox_linux::cgroup::
                NetworkWorkerAggregateAssociationOriginalV4::receiving_obligations_v4().ok_or(overflow)?;
            Ok(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| overflow)?)
                .with(D::OpenFiles, u64::try_from(files).map_err(|_| overflow)?)
                .with(D::MetadataEntries, u64::try_from(names).map_err(|_| overflow)?))
        })();
        let demand = match demand {
            Ok(demand) => demand,
            Err(cause) => {
                self.operation.geometry = Some(Err(cause));
                self.common.operation_closed = true;
                self.operation.fail(Failure::Geometry);
                return Err(Refusal::Original);
            }
        };
        self.require_additional_representation_v4(demand).map_err(|_| Refusal::Original)?;
        let aggregate = self.common.network_aggregate.as_ref()
            .and_then(|owner| owner.anchor_v4().ok()).ok_or(Refusal::Original)?;
        self.operation.worker_aggregate_result = Some(original.capture_once_v4(aggregate));
        if !matches!(self.operation.worker_aggregate_result, Some(Ok(()))) {
            self.common.operation_closed = true;
            self.operation.fail(Failure::Body);
            return Err(Refusal::Native);
        }
        Ok(())
    }

    /// Prearms the same operation's two disabling-cleanup clock destinations.
    ///
    /// The actual worker retains this scope before its first request issue.
    /// Mutation and its mandatory observation share this single scope; their
    /// failure cleanups are mutually exclusive in the closed P/O programme.
    /// Construction allocates no backing and does not sample another clock.
    ///
    /// # Errors
    /// Refuses another purpose, poison, incomplete admission or repeated prearm.
    pub fn prearm_network_worker_cleanup_once_v4(&mut self)
        -> Result<NetworkWorkerCleanupClockScopeV4, FixedServiceOperationClosedV4>
    {
        self.require_network_worker_current_v4()?;
        if self.operation.worker_cleanup_prearmed {
            self.common.operation_closed = true;
            return Err(self.operation.fail(Failure::Order));
        }
        let invocation = self.operation.invocation.ok_or(self.operation.closed)?;
        let ordinal = self.operation.operation_ordinal.ok_or(self.operation.closed)?;
        self.operation.worker_cleanup_prearmed = true;
        Ok(NetworkWorkerCleanupClockScopeV4 {
            operation_address: std::ptr::from_ref(&*self.operation).addr(),
            operation_ordinal: ordinal,
            invocation,
            used: 0,
        })
    }

    /// Samples one prearmed disabling-cleanup frontier after primary poison.
    ///
    /// Financial or body failure cannot suppress this owed destination. The
    /// same clock still rejects its own failed native prefix, discontinuity,
    /// expired original BOOTTIME/WALL bounds and completed after observation.
    /// This port cannot enter the positive worker/FDSTORE lane or renew bounds.
    ///
    /// # Errors
    /// Refuses a foreign scope, wrong purpose, missing original native entry,
    /// more than two attempts, completion, or the clock's own currentness error.
    pub fn observe_owed_network_worker_cleanup_clock_v4(
        &mut self, scope: &mut NetworkWorkerCleanupClockScopeV4,
    ) -> Result<RawPairedClockSample, FixedServiceOperationClosedV4> {
        if Some(scope.operation_ordinal) != self.operation.operation_ordinal
            || scope.operation_ordinal != self.common.operation_ordinal
            || scope.operation_address != std::ptr::from_ref(&*self.operation).addr()
            || Some(scope.invocation) != self.operation.invocation
            || self.operation.invocation != self.common.enrollment.map(|value| value.recipient_invocation)
            || !matches!(self.operation.purpose, Some(Purpose::NetworkPrepare | Purpose::NetworkDestroy))
            || !matches!(self.common.role, FixedServiceRoleV1::Network)
            || !self.operation.worker_cleanup_prearmed || scope.used >= 2
            || !self.operation.armed || self.operation.finished || !self.common.operation_active
            || !matches!(self.operation.before_result, Some(Ok(())))
            || !matches!(self.operation.method, Some(Ok(())))
        {
            self.common.operation_closed = true;
            return Err(self.operation.fail(Failure::Order));
        }
        // This lane deliberately bypasses only the financial/body healthy gate.
        // The unchanged original clock remains fail-stop and owns every sample.
        scope.used += 1;
        self.operation.clock.require_current().and_then(|()| {
            self.operation.clock.observe_worker_cleanup_primary_v4()
        }).map_err(|_| {
            self.common.operation_closed = true;
            self.operation.fail(Failure::Clock)
        })
    }

    /// Tightens only the actual request/signed-wall DATA ceilings.
    ///
    /// # Errors
    /// Rejects zero/expired or backward clock bounds. This comparison neither
    /// verifies a signature nor adopts supplied DATA as effect authority.
    pub fn narrow_deadline_data_v4(&mut self, deadline: u64, wall_expiry: Option<i64>) -> Result<(), FixedServiceOperationClosedV4> {
        self.require_bound()?;
        self.operation.clock.narrow(deadline, wall_expiry).map_err(|_| {
            self.common.operation_closed = true;
            self.operation.fail(Failure::Clock)
        })
    }

    /// Requires the actual bound Mount62 interval at a physical frontier.
    ///
    /// # Errors
    /// Rejects Network/inventory purposes, failed native entry, poison, and
    /// missing or expired previously observed signed/request clock ceilings.
    pub fn require_current_v4(&mut self) -> Result<(), FixedServiceOperationClosedV4> {
        if !matches!(self.operation.purpose, Some(Purpose::MountAttachmentAnchor)) {
            self.common.operation_closed = true;
            return Err(self.operation.fail(Failure::Method));
        }
        self.require_current_interval()
    }

    /// Requires the actual bound Network63, Destroy9 or Inventory19 interval.
    ///
    /// # Errors
    /// Refuses another purpose, incomplete entry, poison or clock failure.
    pub fn require_network_current_v4(&mut self) -> Result<(), FixedServiceOperationClosedV4> {
        if !matches!(self.operation.purpose, Some(Purpose::NetworkPrepare | Purpose::NetworkDestroy | Purpose::NetworkInventory)) {
            self.common.operation_closed = true;
            return Err(self.operation.fail(Failure::Method));
        }
        self.require_current_interval()
    }

    /// Requires only the actual bound Network Prepare63 interval.
    ///
    /// # Errors
    /// Refuses Inventory19, another purpose, incomplete entry or currentness failure.
    pub fn require_network_prepare_current_v4(&mut self) -> Result<(), FixedServiceOperationClosedV4> {
        if !matches!(self.operation.purpose, Some(Purpose::NetworkPrepare)) {
            self.common.operation_closed = true;
            return Err(self.operation.fail(Failure::Method));
        }
        self.require_current_interval()
    }

    /// Requires only the actual bound Network Destroy9 interval.
    ///
    /// # Errors
    /// Refuses Prepare63, Inventory19, poison or stale original BOOT/WALL bounds.
    pub fn require_network_destroy_current_v4(&mut self) -> Result<(), FixedServiceOperationClosedV4> {
        if !matches!(self.operation.purpose, Some(Purpose::NetworkDestroy)) {
            self.common.operation_closed = true;
            return Err(self.operation.fail(Failure::Method));
        }
        self.require_current_interval()
    }

    // Private physical mechanics accept only these two actual entered owners.
    // No request DATA, ordinal or public generic purpose can select this gate.
    fn require_network_worker_current_v4(&mut self) -> Result<(), FixedServiceOperationClosedV4> {
        if !matches!(self.operation.purpose, Some(Purpose::NetworkPrepare | Purpose::NetworkDestroy)) {
            self.common.operation_closed = true;
            return Err(self.operation.fail(Failure::Method));
        }
        self.require_current_interval()
    }

    fn network_worker_request_matches_v4(
        &self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> bool {
        match self.operation.purpose {
            Some(Purpose::NetworkPrepare) => request.network_preparation_data_v2().is_some(),
            Some(Purpose::NetworkDestroy) => request.network_destroy_data_v4().is_some(),
            _ => false,
        }
    }

    /// Requires only the actual bound Network Inventory19 interval.
    ///
    /// # Errors
    /// Refuses Prepare63, another purpose, incomplete entry or currentness failure.
    pub fn require_network_inventory_current_v4(&mut self) -> Result<(), FixedServiceOperationClosedV4> {
        if !matches!(self.operation.purpose, Some(Purpose::NetworkInventory)) {
            self.common.operation_closed = true;
            return Err(self.operation.fail(Failure::Method));
        }
        self.require_current_interval()
    }

    /// Borrows the already narrowed absolute wall ceiling of this Network request.
    ///
    /// This comparison DATA neither samples a clock nor renews the interval.
    /// Raw worker transports still check the same original absolute ceilings.
    ///
    /// # Errors
    /// Refuses another purpose, an unbound request, poison or currentness failure.
    pub fn retained_network_wall_ceiling_data_v4(&mut self)
        -> Result<Option<i64>, FixedServiceOperationClosedV4> {
        self.require_network_current_v4()?;
        self.operation.clock.retained_wall_ceiling_data_v4()
    }

    /// Borrows this bound Network request's unchanged cutoff and latest pair.
    ///
    /// Native worker/FDStore transports use these comparison DATA to clamp
    /// their mechanical waits. This performs no sample, schedule advance,
    /// deadline renewal or request/effect admission. Actual effect frontiers
    /// still require the separately prepaid fresh clock gate.
    ///
    /// # Errors
    /// Refuses another purpose, an unbound request, poison or clock failure.
    pub fn retained_network_horizon_data_v4(&mut self)
        -> Result<(RawPairedClockSample, u64), FixedServiceOperationClosedV4> {
        self.require_network_current_v4()?;
        self.operation.clock.retained_interval_data_v4()
    }

    /// Requires Mount's actual separately admitted inventory16 interval.
    ///
    /// # Errors
    /// Refuses Mount62/Network, incomplete entry, poison or expired ceilings.
    pub fn require_inventory_current_v4(&mut self) -> Result<(), FixedServiceOperationClosedV4> {
        if !matches!(self.operation.purpose, Some(Purpose::MountInventory)) {
            self.common.operation_closed = true;
            return Err(self.operation.fail(Failure::Method));
        }
        self.require_current_interval()
    }

    fn require_current_interval(&mut self) -> Result<(), FixedServiceOperationClosedV4> {
        self.require_bound()?;
        if !matches!(self.operation.method, Some(Ok(()))) {
            return Err(self.operation.fail(Failure::Method));
        }
        self.operation.clock.require_current().map_err(|_| {
            self.common.operation_closed = true;
            self.operation.fail(Failure::Clock)
        })
    }

    fn require_bound(&mut self) -> Result<(), FixedServiceOperationClosedV4> {
        if !self.operation.armed || self.operation.finished || self.operation.first.is_some()
            || self.common.operation_closed || !self.common.operation_active
            || self.operation.invocation != self.common.enrollment.map(|value| value.recipient_invocation)
            || !self.operation.purpose.is_some_and(|purpose| purpose.role() == self.common.role)
            || !matches!(self.operation.before_result, Some(Ok(())))
            || self.common.representation.as_ref().is_none_or(|ledger| ledger.failure().is_some())
        {
            self.common.operation_closed = true;
            return Err(self.operation.fail(Failure::Order));
        }
        Ok(())
    }

    /// Parks the actual caller's whole semantic/body completion marker once.
    ///
    /// This marker grants no permission and creates no native disposal credit.
    ///
    /// # Errors
    /// Retains negative or repeated completion without masking earlier causes.
    pub fn record_body_result_v4(&mut self, result: Result<(), FixedServiceOperationClosedV4>) -> Result<(), FixedServiceOperationClosedV4> {
        if self.operation.body.is_some() { return Err(self.operation.fail(Failure::Order)); }
        self.operation.body = Some(result);
        if result.is_err() {
            self.common.operation_closed = true;
            return Err(self.operation.fail(Failure::Body));
        }
        Ok(())
    }

    /// Always runs the armed independent owed native sample, including poison.
    ///
    /// # Errors
    /// Preserves the first body/debit/native cause; missing body or entry proof
    /// cannot become successful completion. Native results remain resident.
    pub fn finish_native_once_v4(&mut self) -> Result<(), FixedServiceOperationClosedV4> {
        if !self.operation.armed || self.operation.finished {
            return Err(self.operation.fail(Failure::Order));
        }
        self.operation.finished = true;
        // A caller refusing before its entry sample still owes both prepaid
        // native destinations. These observations cannot reopen the body.
        if self.operation.before_result.is_none() {
            self.operation.before_result = Some(observe(self.common, &mut self.operation.before));
            if !matches!(self.operation.before_result, Some(Ok(()))) { self.operation.fail(Failure::Before); }
        }
        self.operation.after_result = Some(observe(self.common, &mut self.operation.after));
        if !matches!(self.operation.after_result, Some(Ok(()))) { self.operation.fail(Failure::After); }
        if self.operation.clock.finish_once().is_err() { self.operation.fail(Failure::Clock); }
        let method_complete = match self.operation.purpose.and_then(Purpose::method) {
            Some(_) => matches!(self.operation.method, Some(Ok(()))),
            None => self.operation.method.is_none()
                && !matches!(self.operation.purpose, Some(Purpose::NetworkRequestReceiving)),
        };
        if !method_complete || !matches!(self.operation.body, Some(Ok(()))) {
            self.operation.fail(Failure::Body);
        }
        // An issued worker programme cannot finish positively from RESULT,
        // death, Empty or K alone. Both actual child successes and this
        // parent's unchanged currentness joins must have completed.
        if self.operation.worker_birth_mask != 0
            && (self.operation.worker_birth_mask != 3 || self.operation.worker_success_mask != 3)
        {
            self.operation.fail(Failure::Body);
        }
        self.common.operation_active = false;
        if matches!(self.operation.purpose, Some(Purpose::MountInventory | Purpose::NetworkInventory
            | Purpose::NetworkPrepare | Purpose::NetworkDestroy)) {
            self.common.inventory_disposal_pending = self.operation.operation_ordinal;
        }
        self.common.operation_closed |= self.operation.first.is_some();
        if self.operation.first.is_some() { Err(self.operation.closed) } else { Ok(()) }
    }

    /// Requires the actual finished inventory interval before native retirement.
    ///
    /// # Errors
    /// Refuses another method/ordinal, failed body, missing after or changed F.
    pub fn require_completed_inventory_interval_v5(&self, method: u32)
        -> Result<(), FixedServiceOperationClosedV4> {
        self.require_completed_interval_v5(method)?;
        if !matches!(self.operation.purpose, Some(Purpose::MountInventory | Purpose::NetworkInventory))
            || self.common.inventory_disposal_pending != self.operation.operation_ordinal {
            return Err(self.operation.closed);
        }
        Ok(())
    }

    /// Requires this genuine finished Network request before native retirement.
    ///
    /// # Errors
    /// Refuses another purpose, ordinal, unfinished post or failed worker.
    pub fn require_completed_network_interval_v5(&self, method: u32)
        -> Result<(), FixedServiceOperationClosedV4> {
        self.require_completed_interval_v5(method)?;
        if !matches!(self.operation.purpose, Some(Purpose::NetworkInventory
            | Purpose::NetworkPrepare | Purpose::NetworkDestroy))
            || self.common.inventory_disposal_pending != self.operation.operation_ordinal {
            return Err(self.operation.closed);
        }
        Ok(())
    }

    /// Requires both real child successes and the completed Prepare63 interval.
    ///
    /// # Errors
    /// Refuses missing birth/status custody, another purpose or unfinished posts.
    pub fn require_completed_network_preparation_interval_v5(&self)
        -> Result<(), FixedServiceOperationClosedV4> {
        self.require_completed_network_interval_v5(63)?;
        if !matches!(self.operation.purpose, Some(Purpose::NetworkPrepare))
            || self.operation.worker_birth_mask != 3 || self.operation.worker_success_mask != 3 {
            return Err(self.operation.closed);
        }
        Ok(())
    }

    /// Requires both child successes and this completed Destroy9 interval.
    ///
    /// # Errors
    /// Refuses another purpose, incomplete child statuses or unfinished posts.
    pub fn require_completed_network_destroy_interval_v5(&self)
        -> Result<(), FixedServiceOperationClosedV4> {
        self.require_completed_network_interval_v5(9)?;
        if !matches!(self.operation.purpose, Some(Purpose::NetworkDestroy))
            || self.operation.worker_birth_mask != 3 || self.operation.worker_success_mask != 3 {
            return Err(self.operation.closed);
        }
        Ok(())
    }

    /// Releases the completed Network request's native-retirement gate.
    ///
    /// The caller first disposes its positive Domain and SDK owners. Accepted
    /// F charges and the actual operation ordinal remain unchanged.
    ///
    /// # Errors
    /// Refuses failed, foreign, unfinished or repeated retirement.
    pub fn finish_network_disposal_once_v5(&mut self, method: u32)
        -> Result<(), FixedServiceOperationClosedV4> {
        self.require_completed_network_interval_v5(method)?;
        drop(std::mem::take(&mut self.operation.before));
        drop(std::mem::take(&mut self.operation.after));
        self.common.inventory_disposal_pending = None;
        Ok(())
    }

    /// Requires the same actual completed Mount62 interval for native retirement.
    ///
    /// This comparison cannot reopen the operation or refund any F debit. Its
    /// domain caller retains the original namespace pin and charged ledger.
    ///
    /// # Errors
    /// Refuses another purpose, invocation, ordinal, body or unfinished post.
    pub fn require_completed_mount_attachment_interval_v5(&self)
        -> Result<(), FixedServiceOperationClosedV4> {
        self.require_completed_interval_v5(62)?;
        if !matches!(self.operation.purpose, Some(Purpose::MountAttachmentAnchor)) {
            return Err(self.operation.closed);
        }
        Ok(())
    }

    fn require_completed_interval_v5(&self, method: u32)
        -> Result<(), FixedServiceOperationClosedV4> {
        if !self.operation.finished || self.operation.first.is_some() || self.common.operation_closed
            || self.common.operation_active
            || self.operation.purpose.and_then(Purpose::method) != Some(method)
            || !self.operation.purpose.is_some_and(|purpose| purpose.role() == self.common.role)
            || self.operation.operation_ordinal != Some(self.common.operation_ordinal)
            || self.operation.invocation != self.common.enrollment.map(|value| value.recipient_invocation)
            || !matches!(self.operation.before_result, Some(Ok(())))
            || !matches!(self.operation.after_result, Some(Ok(())))
            || !matches!(self.operation.body, Some(Ok(())))
            || !matches!(self.operation.method, Some(Ok(())))
            || !self.operation.clock.completed_inventory_pair_v5()
        { return Err(self.operation.closed); }
        Ok(())
    }

    /// Releases only this completed inventory's pending native-retirement gate.
    ///
    /// The actual SDK caller first drops its positive request/response and
    /// domain native owners. Every accepted F charge remains permanent.
    ///
    /// # Errors
    /// Refuses incomplete, failed, foreign or repeated native retirement.
    pub fn finish_inventory_disposal_once_v5(&mut self, method: u32)
        -> Result<(), FixedServiceOperationClosedV4> {
        self.require_completed_inventory_interval_v5(method)?;
        // Both native sample owners are positive and no later operation can
        // begin while this actual loan still holds Common exclusively.
        drop(std::mem::take(&mut self.operation.before));
        drop(std::mem::take(&mut self.operation.after));
        self.common.inventory_disposal_pending = None;
        Ok(())
    }

    /// Borrows the original selected cause while retaining the whole interval.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        if matches!(self.operation.first, Some(Failure::Accounting)) {
            self.common.representation.as_ref().and_then(|ledger| ledger.failure()).map(|cause| cause as _)
                .or_else(|| self.operation.failure())
        } else { self.operation.failure() }
    }
}

fn observe(
    common: &mut FixedServiceReceivingCaptureV1<FixedServiceOperationClosedV4>,
    destination: &mut FixedServiceCurrentnessSampleV1<FixedServiceOperationClosedV4>,
) -> Result<(), FixedServiceOperationClosedV4> {
    let identity = common.process_before.as_ref().and_then(|value| value.as_ref().ok()).copied()
        .ok_or(FixedServiceOperationClosedV4)?;
    let info = common.membership.as_ref().and_then(|value| value.as_ref().ok()).copied()
        .ok_or(FixedServiceOperationClosedV4)?;
    let anchor = common.cgroup.as_ref().ok_or(FixedServiceOperationClosedV4)?;
    match common.network_aggregate.as_ref() {
        Some(aggregate) => destination.observe_network_aggregate_once_v4(&mut common.process,
            anchor, &common.limits, info, identity, common.startup_currentness.captured_context(), false, aggregate),
        None => destination.observe_once(&mut common.process, anchor, &common.limits, info, identity,
            common.startup_currentness.captured_context(), false),
    }
}

impl Drop for FixedServiceOperationOriginalV4 {
    fn drop(&mut self) {
        if self.entered && (!self.finished || self.first.is_some()) {
            // The real service keeps negative and unfinished owners resident.
            // Drop cannot silently release a failed native prefix.
            std::process::abort();
        }
    }
}
