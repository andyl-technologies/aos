//! Bounded guest-selectable catalog reconciliation and pending-request state.
//!
//! The live dispatcher will receive expectations from a launch-authenticated
//! daemon descriptor. This policy-free state machine compares guest setup
//! registrations byte-for-byte with those expectations, freezes the catalog at
//! the lifecycle ready point, and retains exactly one request while host choice
//! authority decides its reply.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use crucible_protocol::{
    SelectableProtocolError, SelectableRegister, SelectionReply, SelectionRequest,
    selectable_catalog_plan::{
        SELECTABLE_CATALOG_PLAN_MAX_DECLARATIONS, SELECTABLE_CATALOG_PLAN_MAX_REQUESTS,
        SelectableCatalogPlan, SelectableCatalogPlanError, SelectablePlanContinuation,
        SelectablePlanDeclaration, SelectablePlanLimits, SelectablePlanPendingRequest,
        SelectablePlanPhase, SelectablePlanPresence,
    },
};
use thiserror::Error;

use super::{
    SelectableCallbackCoordinate, SelectableDoorbellServiceError, SelectableRegistrationService,
    SelectableReplyDisposition, SelectableReplyService,
};

/// Absolute implementation ceiling for declarations in one node catalog.
pub const SELECTABLE_CATALOG_HARD_MAX_DECLARATIONS: usize = 4_096;
/// Absolute implementation ceiling for completed requests in one node run.
pub const SELECTABLE_CATALOG_HARD_MAX_REQUESTS: u64 = 1_000_000;

const _: () =
    assert!(SELECTABLE_CATALOG_HARD_MAX_DECLARATIONS == SELECTABLE_CATALOG_PLAN_MAX_DECLARATIONS);
const _: () = assert!(SELECTABLE_CATALOG_HARD_MAX_REQUESTS == SELECTABLE_CATALOG_PLAN_MAX_REQUESTS);

/// Scenario-owned ceilings applied to one node-local selectable catalog.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectableCatalogLimits {
    declarations: usize,
    requests_per_selectable: u64,
    total_requests: u64,
}

impl SelectableCatalogLimits {
    /// Builds bounded, nonzero catalog and request ceilings.
    ///
    /// # Errors
    ///
    /// Returns [`SelectableCatalogError::InvalidLimit`] when a ceiling is zero,
    /// exceeds its implementation hard maximum, or the per-selectable request
    /// ceiling exceeds the total request ceiling.
    pub fn new(
        declarations: usize,
        requests_per_selectable: u64,
        total_requests: u64,
    ) -> Result<Self, SelectableCatalogError> {
        let declaration_count = u64::try_from(declarations).map_err(|_source| {
            SelectableCatalogError::InvalidLimit {
                name: "declarations",
                actual: u64::MAX,
                maximum: SELECTABLE_CATALOG_HARD_MAX_DECLARATIONS as u64,
            }
        })?;
        validate_limit(
            "declarations",
            declaration_count,
            SELECTABLE_CATALOG_HARD_MAX_DECLARATIONS as u64,
        )?;
        validate_limit(
            "requests_per_selectable",
            requests_per_selectable,
            SELECTABLE_CATALOG_HARD_MAX_REQUESTS,
        )?;
        validate_limit(
            "total_requests",
            total_requests,
            SELECTABLE_CATALOG_HARD_MAX_REQUESTS,
        )?;
        if requests_per_selectable > total_requests {
            return Err(SelectableCatalogError::PerSelectableLimitExceedsTotal {
                requests_per_selectable,
                total_requests,
            });
        }
        Ok(Self {
            declarations,
            requests_per_selectable,
            total_requests,
        })
    }

    /// Returns the maximum declarations admitted before freeze.
    #[must_use]
    pub const fn declarations(self) -> usize {
        self.declarations
    }

    /// Returns the maximum completed requests for one selectable.
    #[must_use]
    pub const fn requests_per_selectable(self) -> u64 {
        self.requests_per_selectable
    }

    /// Returns the maximum completed requests across the node run.
    #[must_use]
    pub const fn total_requests(self) -> u64 {
        self.total_requests
    }
}

fn validate_limit(
    name: &'static str,
    actual: u64,
    maximum: u64,
) -> Result<(), SelectableCatalogError> {
    if actual == 0 || actual > maximum {
        Err(SelectableCatalogError::InvalidLimit {
            name,
            actual,
            maximum,
        })
    } else {
        Ok(())
    }
}

/// Whether one scenario-declared guest selectable must register before freeze.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectableExpectedPresence {
    /// Catalog freeze fails when this declaration was not observed.
    Required,
    /// The guest may omit this declaration, but any registration must match.
    Optional,
}

/// Exact launch-authenticated declaration contract, excluding guest sequence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectableExpectedDeclaration {
    selectable_id: String,
    domain: Vec<u8>,
    default_value: Vec<u8>,
    semantic_tags: Vec<String>,
    presence: SelectableExpectedPresence,
}

impl SelectableExpectedDeclaration {
    /// Builds one expected declaration using the standalone ABI field rules.
    ///
    /// # Errors
    ///
    /// Returns [`SelectableProtocolError`] when the identifier, domain,
    /// default value, tag list, or aggregate declaration size is invalid.
    pub fn new(
        selectable_id: impl Into<String>,
        domain: Vec<u8>,
        default_value: Vec<u8>,
        semantic_tags: Vec<String>,
        presence: SelectableExpectedPresence,
    ) -> Result<Self, SelectableProtocolError> {
        let registration =
            SelectableRegister::new(0, selectable_id, domain, default_value, semantic_tags)?;
        Ok(Self::from_registration(&registration, presence))
    }

    /// Copies the declaration contract from a canonical guest registration.
    #[must_use]
    pub fn from_registration(
        registration: &SelectableRegister,
        presence: SelectableExpectedPresence,
    ) -> Self {
        Self {
            selectable_id: registration.selectable_id().to_owned(),
            domain: registration.domain().to_vec(),
            default_value: registration.default_value().to_vec(),
            semantic_tags: registration.semantic_tags().to_vec(),
            presence,
        }
    }

    /// Returns the canonical selectable identifier.
    #[must_use]
    pub fn selectable_id(&self) -> &str {
        &self.selectable_id
    }

    /// Returns the canonical declared-domain bytes.
    #[must_use]
    pub fn domain(&self) -> &[u8] {
        &self.domain
    }

    /// Returns the canonical default-value bytes.
    #[must_use]
    pub fn default_value(&self) -> &[u8] {
        &self.default_value
    }

    /// Returns the canonical semantic tags.
    #[must_use]
    pub fn semantic_tags(&self) -> &[String] {
        &self.semantic_tags
    }

    /// Returns whether catalog freeze requires this declaration.
    #[must_use]
    pub const fn presence(&self) -> SelectableExpectedPresence {
        self.presence
    }

    fn matches(&self, registration: &SelectableRegister) -> bool {
        self.selectable_id == registration.selectable_id()
            && self.domain == registration.domain()
            && self.default_value == registration.default_value()
            && self.semantic_tags == registration.semantic_tags()
    }
}

/// Launch-authenticated expected catalog indexed by selectable identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectableCatalogExpectation {
    declarations: Arc<BTreeMap<String, SelectableExpectedDeclaration>>,
}

impl SelectableCatalogExpectation {
    /// Builds one exact expected catalog within the scenario declaration cap.
    ///
    /// # Errors
    ///
    /// Returns [`SelectableCatalogError`] when the catalog exceeds `limits` or
    /// contains two contracts for one selectable identifier.
    pub fn new(
        declarations: Vec<SelectableExpectedDeclaration>,
        limits: SelectableCatalogLimits,
    ) -> Result<Self, SelectableCatalogError> {
        if declarations.len() > limits.declarations() {
            return Err(SelectableCatalogError::DeclarationLimitExceeded {
                actual: declarations.len(),
                maximum: limits.declarations(),
            });
        }
        let mut indexed = BTreeMap::new();
        for declaration in declarations {
            let selectable_id = declaration.selectable_id.clone();
            if indexed.insert(selectable_id.clone(), declaration).is_some() {
                return Err(SelectableCatalogError::DuplicateExpectedDeclaration { selectable_id });
            }
        }
        Ok(Self {
            declarations: Arc::new(indexed),
        })
    }

    /// Returns expectations in canonical identifier order.
    #[must_use]
    pub fn declarations(&self) -> &BTreeMap<String, SelectableExpectedDeclaration> {
        self.declarations.as_ref()
    }
}

fn catalog_basis_from_plan(
    plan: &SelectableCatalogPlan,
) -> Result<(SelectableCatalogLimits, SelectableCatalogExpectation), SelectableCatalogError> {
    let plan_limits = plan.limits();
    let limits = SelectableCatalogLimits::new(
        plan_limits.declarations(),
        plan_limits.requests_per_selectable(),
        plan_limits.total_requests(),
    )?;
    let declarations = plan
        .declarations()
        .values()
        .map(|declaration| {
            SelectableExpectedDeclaration::from_registration(
                declaration.registration(),
                match declaration.presence() {
                    SelectablePlanPresence::Required => SelectableExpectedPresence::Required,
                    SelectablePlanPresence::Optional => SelectableExpectedPresence::Optional,
                },
            )
        })
        .collect::<Vec<_>>();
    let expectation = SelectableCatalogExpectation::new(declarations, limits)?;
    Ok((limits, expectation))
}

/// Current lifecycle phase of one guest-selectable catalog.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectableCatalogPhase {
    /// Setup registrations may still be admitted.
    Registering,
    /// The catalog is immutable and runtime requests may be admitted.
    Frozen,
}

/// Evidence returned after exact setup catalog reconciliation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectableCatalogFreeze {
    registered_declarations: usize,
    required_declarations: usize,
}

impl SelectableCatalogFreeze {
    /// Returns the number of guest declarations present at freeze.
    #[must_use]
    pub const fn registered_declarations(self) -> usize {
        self.registered_declarations
    }

    /// Returns the number of required declarations proved present.
    #[must_use]
    pub const fn required_declarations(self) -> usize {
        self.required_declarations
    }
}

/// Exact in-flight request ownership retained across a choice boundary.
#[derive(Clone, Debug)]
pub struct SelectablePendingRequest {
    incarnation: Arc<SelectableCatalogIncarnation>,
    request: SelectionRequest,
    coordinate: SelectableCallbackCoordinate,
    declaration: SelectableExpectedDeclaration,
}

#[derive(Debug)]
struct SelectableCatalogIncarnation;

impl PartialEq for SelectablePendingRequest {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.incarnation, &other.incarnation)
            && self.request == other.request
            && self.coordinate == other.coordinate
            && self.declaration == other.declaration
    }
}

impl Eq for SelectablePendingRequest {}

impl SelectablePendingRequest {
    /// Returns the complete request, including reply reservation ownership.
    #[must_use]
    pub const fn request(&self) -> &SelectionRequest {
        &self.request
    }

    /// Returns the exact trap coordinate at which the guest remains blocked.
    #[must_use]
    pub const fn coordinate(&self) -> SelectableCallbackCoordinate {
        self.coordinate
    }

    /// Returns the exact frozen declaration contract for this request.
    #[must_use]
    pub const fn declaration(&self) -> &SelectableExpectedDeclaration {
        &self.declaration
    }
}

/// Bounded node-local selectable catalog and request-continuation owner.
#[derive(Debug)]
pub struct SelectableCatalog {
    incarnation: Arc<SelectableCatalogIncarnation>,
    limits: SelectableCatalogLimits,
    expectation: SelectableCatalogExpectation,
    phase: SelectableCatalogPhase,
    registered: BTreeSet<String>,
    last_registration_sequence: Option<u64>,
    completed_requests: BTreeMap<String, u64>,
    total_completed_requests: u64,
    last_completed_request_sequence: Option<u64>,
    pending: Option<SelectablePendingRequest>,
}

impl SelectableCatalog {
    /// Starts one catalog in its setup registration phase.
    ///
    /// # Errors
    ///
    /// Returns [`SelectableCatalogError::DeclarationLimitExceeded`] when the
    /// expectation was constructed under a larger declaration limit than the
    /// limits supplied for this catalog incarnation.
    pub fn new(
        limits: SelectableCatalogLimits,
        expectation: SelectableCatalogExpectation,
    ) -> Result<Self, SelectableCatalogError> {
        if expectation.declarations.len() > limits.declarations() {
            return Err(SelectableCatalogError::DeclarationLimitExceeded {
                actual: expectation.declarations.len(),
                maximum: limits.declarations(),
            });
        }
        Ok(Self {
            incarnation: Arc::new(SelectableCatalogIncarnation),
            limits,
            expectation,
            phase: SelectableCatalogPhase::Registering,
            registered: BTreeSet::new(),
            last_registration_sequence: None,
            completed_requests: BTreeMap::new(),
            total_completed_requests: 0,
            last_completed_request_sequence: None,
            pending: None,
        })
    }

    /// Restores one catalog from an already decoded launch-authenticated plan.
    ///
    /// A fresh private incarnation is always created. Pending request bytes and
    /// accounting survive restore, but an in-process token from the prior
    /// plugin cannot complete the restored catalog.
    ///
    /// # Errors
    ///
    /// Returns [`SelectableCatalogError`] if plugin and process-protocol bounds
    /// drift or the plan cannot be represented by the plugin state machine.
    pub fn from_plan(plan: &SelectableCatalogPlan) -> Result<Self, SelectableCatalogError> {
        let (limits, expectation) = catalog_basis_from_plan(plan)?;
        Self::restore_from_plan_basis(plan, limits, expectation)
    }

    /// Builds the cold-launch and exact-restore catalog incarnations together.
    ///
    /// The two catalogs share one immutable expectation allocation. The cold
    /// catalog admits throwaway boot-barrier registrations, while the restored
    /// catalog retains the exact authenticated continuation for an allocation-
    /// free swap after VMState load. Their pending-request tokens belong to
    /// distinct private incarnations.
    ///
    /// # Errors
    ///
    /// Returns [`SelectableCatalogError`] if plugin and process-protocol bounds
    /// drift or the plan cannot be represented by the plugin state machine.
    pub fn launch_pair_from_plan(
        plan: &SelectableCatalogPlan,
    ) -> Result<(Self, Self), SelectableCatalogError> {
        let (limits, expectation) = catalog_basis_from_plan(plan)?;
        let cold = Self::new(limits, expectation.clone())?;
        let restored = Self::restore_from_plan_basis(plan, limits, expectation)?;
        Ok((cold, restored))
    }

    fn restore_from_plan_basis(
        plan: &SelectableCatalogPlan,
        limits: SelectableCatalogLimits,
        expectation: SelectableCatalogExpectation,
    ) -> Result<Self, SelectableCatalogError> {
        let mut catalog = Self::new(limits, expectation)?;
        let continuation = plan.continuation();
        catalog.phase = match continuation.phase() {
            SelectablePlanPhase::Registering => SelectableCatalogPhase::Registering,
            SelectablePlanPhase::Frozen => SelectableCatalogPhase::Frozen,
        };
        catalog.registered = continuation.registered().clone();
        catalog.last_registration_sequence = continuation.last_registration_sequence();
        catalog.completed_requests = continuation.completed_requests().clone();
        catalog.total_completed_requests = continuation.total_completed_requests();
        catalog.last_completed_request_sequence = continuation.last_completed_request_sequence();
        if let Some(pending) = continuation.pending() {
            let declaration = catalog
                .expectation
                .declarations
                .get(pending.request().selectable_id())
                .cloned()
                .ok_or_else(|| SelectableCatalogError::UnknownSelectable {
                    selectable_id: pending.request().selectable_id().to_owned(),
                })?;
            catalog.pending = Some(SelectablePendingRequest {
                incarnation: Arc::clone(&catalog.incarnation),
                request: pending.request().clone(),
                coordinate: SelectableCallbackCoordinate::new(
                    pending.icount(),
                    pending.vcpu_index(),
                ),
                declaration,
            });
        }
        Ok(catalog)
    }

    /// Serializes this catalog into the process-neutral canonical plan model.
    ///
    /// # Errors
    ///
    /// Returns [`SelectableCatalogPlanError`] when nested declarations or the
    /// retained continuation fail the protocol profile. A catalog constructed
    /// or restored through safe APIs is expected to serialize successfully.
    pub fn to_plan(&self) -> Result<SelectableCatalogPlan, SelectableCatalogPlanError> {
        let limits = SelectablePlanLimits::new(
            self.limits.declarations(),
            self.limits.requests_per_selectable(),
            self.limits.total_requests(),
        )?;
        let declarations = self
            .expectation
            .declarations
            .values()
            .map(|declaration| {
                SelectablePlanDeclaration::new(
                    declaration.selectable_id(),
                    declaration.domain().to_vec(),
                    declaration.default_value().to_vec(),
                    declaration.semantic_tags().to_vec(),
                    match declaration.presence() {
                        SelectableExpectedPresence::Required => SelectablePlanPresence::Required,
                        SelectableExpectedPresence::Optional => SelectablePlanPresence::Optional,
                    },
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let pending = self.pending.as_ref().map(|pending| {
            SelectablePlanPendingRequest::new(
                pending.request.clone(),
                pending.coordinate.icount(),
                pending.coordinate.vcpu_index(),
            )
        });
        let continuation = SelectablePlanContinuation::new(
            match self.phase {
                SelectableCatalogPhase::Registering => SelectablePlanPhase::Registering,
                SelectableCatalogPhase::Frozen => SelectablePlanPhase::Frozen,
            },
            self.registered.clone(),
            self.last_registration_sequence,
            self.completed_requests.clone(),
            self.last_completed_request_sequence,
            pending,
        )?;
        SelectableCatalogPlan::new(limits, declarations, continuation)
    }

    /// Returns the catalog lifecycle phase.
    #[must_use]
    pub const fn phase(&self) -> SelectableCatalogPhase {
        self.phase
    }

    /// Returns the exact scenario-owned limits.
    #[must_use]
    pub const fn limits(&self) -> SelectableCatalogLimits {
        self.limits
    }

    /// Returns the launch-authenticated catalog expectation.
    #[must_use]
    pub const fn expectation(&self) -> &SelectableCatalogExpectation {
        &self.expectation
    }

    /// Returns registered selectable identifiers in canonical order.
    #[must_use]
    pub const fn registered_declarations(&self) -> &BTreeSet<String> {
        &self.registered
    }

    /// Returns the last admitted registration sequence.
    #[must_use]
    pub const fn last_registration_sequence(&self) -> Option<u64> {
        self.last_registration_sequence
    }

    /// Returns completed per-selectable request counters in canonical order.
    #[must_use]
    pub const fn completed_request_counts(&self) -> &BTreeMap<String, u64> {
        &self.completed_requests
    }

    /// Returns the last completed request sequence.
    #[must_use]
    pub const fn last_completed_request_sequence(&self) -> Option<u64> {
        self.last_completed_request_sequence
    }

    /// Returns the currently retained request, if host choice authority has not replied.
    #[must_use]
    pub const fn pending_request(&self) -> Option<&SelectablePendingRequest> {
        self.pending.as_ref()
    }

    /// Admits one exact setup registration.
    ///
    /// Registration sequences must strictly increase. The identifier must be
    /// expected, must not already be present, and every declaration field must
    /// match its launch-authenticated contract.
    ///
    /// # Errors
    ///
    /// Returns [`SelectableCatalogError`] for a late, duplicate, regressing,
    /// unexpected, mismatched, or over-limit registration.
    pub fn register(
        &mut self,
        registration: &SelectableRegister,
    ) -> Result<(), SelectableCatalogError> {
        if self.phase != SelectableCatalogPhase::Registering {
            return Err(SelectableCatalogError::RegistrationAfterFreeze);
        }
        if self.registered.len() >= self.limits.declarations() {
            return Err(SelectableCatalogError::DeclarationLimitExceeded {
                actual: self.registered.len().saturating_add(1),
                maximum: self.limits.declarations(),
            });
        }
        require_increasing_sequence(
            "registration",
            self.last_registration_sequence,
            registration.sequence(),
        )?;
        let selectable_id = registration.selectable_id();
        if self.registered.contains(selectable_id) {
            return Err(SelectableCatalogError::DuplicateRegistration {
                selectable_id: selectable_id.to_owned(),
            });
        }
        let expected = self
            .expectation
            .declarations
            .get(selectable_id)
            .ok_or_else(|| SelectableCatalogError::UnexpectedDeclaration {
                selectable_id: selectable_id.to_owned(),
            })?;
        if !expected.matches(registration) {
            return Err(SelectableCatalogError::DeclarationContractMismatch {
                selectable_id: selectable_id.to_owned(),
            });
        }

        self.registered.insert(selectable_id.to_owned());
        self.last_registration_sequence = Some(registration.sequence());
        Ok(())
    }

    /// Freezes the setup catalog after proving every required declaration.
    ///
    /// # Errors
    ///
    /// Returns [`SelectableCatalogError::CatalogAlreadyFrozen`] on a second
    /// freeze or [`SelectableCatalogError::MissingRequiredDeclarations`] when
    /// the guest omitted required declarations.
    pub fn freeze(&mut self) -> Result<SelectableCatalogFreeze, SelectableCatalogError> {
        if self.phase == SelectableCatalogPhase::Frozen {
            return Err(SelectableCatalogError::CatalogAlreadyFrozen);
        }
        let missing = self
            .expectation
            .declarations
            .values()
            .filter(|declaration| {
                declaration.presence == SelectableExpectedPresence::Required
                    && !self.registered.contains(declaration.selectable_id())
            })
            .map(|declaration| declaration.selectable_id.clone())
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(SelectableCatalogError::MissingRequiredDeclarations { missing });
        }
        self.phase = SelectableCatalogPhase::Frozen;
        let required_declarations = self
            .expectation
            .declarations
            .values()
            .filter(|declaration| declaration.presence == SelectableExpectedPresence::Required)
            .count();
        Ok(SelectableCatalogFreeze {
            registered_declarations: self.registered.len(),
            required_declarations,
        })
    }

    /// Retains one exact request before semantic narrowing and selection.
    ///
    /// Request sequences must strictly increase across completed requests. One
    /// request remains pending until [`Self::complete_request`] validates its
    /// exact reply; callers can checkpoint [`Self::pending_request`] meanwhile.
    ///
    /// # Errors
    ///
    /// Returns [`SelectableCatalogError`] when the catalog is not frozen, a
    /// request is already pending, the sequence regresses, the selectable was
    /// not registered, or a request ceiling would be exceeded.
    pub fn begin_request(
        &mut self,
        request: &SelectionRequest,
        coordinate: SelectableCallbackCoordinate,
    ) -> Result<SelectablePendingRequest, SelectableCatalogError> {
        if self.phase != SelectableCatalogPhase::Frozen {
            return Err(SelectableCatalogError::RequestBeforeFreeze);
        }
        if let Some(pending) = &self.pending {
            return Err(SelectableCatalogError::RequestAlreadyPending {
                pending_sequence: pending.request.sequence(),
                actual_sequence: request.sequence(),
            });
        }
        require_increasing_sequence(
            "request",
            self.last_completed_request_sequence,
            request.sequence(),
        )?;
        let selectable_id = request.selectable_id();
        if !self.registered.contains(selectable_id) {
            return Err(SelectableCatalogError::UnknownSelectable {
                selectable_id: selectable_id.to_owned(),
            });
        }
        if self.total_completed_requests >= self.limits.total_requests() {
            return Err(SelectableCatalogError::TotalRequestLimitExceeded {
                maximum: self.limits.total_requests(),
            });
        }
        let completed = self
            .completed_requests
            .get(selectable_id)
            .copied()
            .unwrap_or(0);
        if completed >= self.limits.requests_per_selectable() {
            return Err(SelectableCatalogError::SelectableRequestLimitExceeded {
                selectable_id: selectable_id.to_owned(),
                maximum: self.limits.requests_per_selectable(),
            });
        }
        let declaration = self
            .expectation
            .declarations
            .get(selectable_id)
            .cloned()
            .ok_or_else(|| SelectableCatalogError::UnknownSelectable {
                selectable_id: selectable_id.to_owned(),
            })?;
        let pending = SelectablePendingRequest {
            incarnation: Arc::clone(&self.incarnation),
            request: request.clone(),
            coordinate,
            declaration,
        };
        self.pending = Some(pending.clone());
        Ok(pending)
    }

    /// Completes the exact retained request with one sequence-bound reply.
    ///
    /// # Errors
    ///
    /// Returns [`SelectableCatalogError`] when no request is pending, the token
    /// is not the catalog-owned request, the reply sequence differs, or checked
    /// request accounting overflows. Failure leaves the request pending.
    pub fn complete_request(
        &mut self,
        pending: &SelectablePendingRequest,
        reply: &SelectionReply,
    ) -> Result<(), SelectableCatalogError> {
        let retained = self
            .pending
            .as_ref()
            .ok_or(SelectableCatalogError::NoPendingRequest)?;
        if retained != pending {
            return Err(SelectableCatalogError::PendingRequestMismatch);
        }
        if reply.sequence() != retained.request.sequence() {
            return Err(SelectableCatalogError::ReplySequenceMismatch {
                expected: retained.request.sequence(),
                actual: reply.sequence(),
            });
        }
        let selectable_id = retained.request.selectable_id().to_owned();
        let next_total = self
            .total_completed_requests
            .checked_add(1)
            .ok_or(SelectableCatalogError::RequestCountOverflow)?;
        let next_selectable = self
            .completed_requests
            .get(&selectable_id)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(SelectableCatalogError::RequestCountOverflow)?;

        self.total_completed_requests = next_total;
        self.completed_requests
            .insert(selectable_id, next_selectable);
        self.last_completed_request_sequence = Some(reply.sequence());
        self.pending = None;
        Ok(())
    }

    /// Returns the number of completed requests across the node run.
    #[must_use]
    pub const fn total_completed_requests(&self) -> u64 {
        self.total_completed_requests
    }

    /// Returns completed requests for one selectable identifier.
    #[must_use]
    pub fn completed_requests_for(&self, selectable_id: &str) -> u64 {
        self.completed_requests
            .get(selectable_id)
            .copied()
            .unwrap_or(0)
    }
}

/// Host authority that resolves one catalog-admitted pending request.
pub trait SelectableDecisionAuthority {
    /// Returns an exact reply or preserves one retained request as pending.
    ///
    /// # Errors
    ///
    /// Returns [`SelectableDoorbellServiceError`] when semantic narrowed-domain
    /// validation, opportunity construction, selection, or continuation
    /// authority cannot produce a disposition. The caller retains `pending` on
    /// failure or [`SelectableReplyDisposition::Pending`] so the request can be
    /// checkpointed or retried without admitting another request.
    fn decide_selection(
        &mut self,
        pending: &SelectablePendingRequest,
    ) -> Result<SelectableReplyDisposition, SelectableDoorbellServiceError>;
}

/// Combined catalog and decision service used by the safe doorbell callback.
pub struct CatalogedSelectableService<A> {
    catalog: SelectableCatalog,
    authority: A,
}

impl<A> CatalogedSelectableService<A> {
    /// Binds one catalog incarnation to its semantic decision authority.
    #[must_use]
    pub const fn new(catalog: SelectableCatalog, authority: A) -> Self {
        Self { catalog, authority }
    }

    /// Returns the catalog and its continuation state.
    #[must_use]
    pub const fn catalog(&self) -> &SelectableCatalog {
        &self.catalog
    }

    /// Freezes the exact setup catalog before runtime requests are admitted.
    ///
    /// # Errors
    ///
    /// Returns [`SelectableCatalogError`] when required registrations are
    /// missing or this service was already frozen.
    pub fn freeze(&mut self) -> Result<SelectableCatalogFreeze, SelectableCatalogError> {
        self.catalog.freeze()
    }

    /// Retries semantic resolution of the exact retained request.
    ///
    /// The catalog clears its pending token and charges request counts only
    /// after the authority returns an exact-sequence reply. Every failure leaves
    /// the same request retained.
    ///
    /// # Errors
    ///
    /// Returns [`SelectableDoorbellServiceError`] when there is no pending
    /// request, decision authority fails, or reply completion violates catalog
    /// ownership or sequence invariants.
    pub fn resolve_pending(
        &mut self,
    ) -> Result<SelectableReplyDisposition, SelectableDoorbellServiceError>
    where
        A: SelectableDecisionAuthority,
    {
        let pending = self.catalog.pending_request().cloned().ok_or_else(|| {
            SelectableDoorbellServiceError::new(
                SelectableCatalogError::NoPendingRequest.to_string(),
            )
        })?;
        let disposition = self.authority.decide_selection(&pending)?;
        if let SelectableReplyDisposition::Reply(reply) = &disposition {
            self.catalog
                .complete_request(&pending, reply)
                .map_err(catalog_service_error)?;
        }
        Ok(disposition)
    }
}

impl<A> SelectableRegistrationService for CatalogedSelectableService<A> {
    fn register_selectable(
        &mut self,
        registration: &SelectableRegister,
        _coordinate: SelectableCallbackCoordinate,
    ) -> Result<(), SelectableDoorbellServiceError> {
        self.catalog
            .register(registration)
            .map_err(catalog_service_error)
    }
}

impl<A> SelectableReplyService for CatalogedSelectableService<A>
where
    A: SelectableDecisionAuthority,
{
    fn serve_selection(
        &mut self,
        request: &SelectionRequest,
        coordinate: SelectableCallbackCoordinate,
    ) -> Result<SelectableReplyDisposition, SelectableDoorbellServiceError> {
        self.catalog
            .begin_request(request, coordinate)
            .map_err(catalog_service_error)?;
        self.resolve_pending()
    }
}

fn catalog_service_error(error: SelectableCatalogError) -> SelectableDoorbellServiceError {
    SelectableDoorbellServiceError::new(error.to_string())
}

fn require_increasing_sequence(
    kind: &'static str,
    previous: Option<u64>,
    actual: u64,
) -> Result<(), SelectableCatalogError> {
    if previous.is_some_and(|previous| actual <= previous) {
        Err(SelectableCatalogError::SequenceNotIncreasing {
            kind,
            previous,
            actual,
        })
    } else {
        Ok(())
    }
}

/// Failure while reconciling or using one guest-selectable catalog.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SelectableCatalogError {
    /// The process-neutral plan cannot be represented by plugin state.
    #[error(transparent)]
    CatalogPlan(#[from] SelectableCatalogPlanError),
    /// A configured limit is zero or exceeds its hard maximum.
    #[error("selectable catalog limit {name}={actual} is outside 1..={maximum}")]
    InvalidLimit {
        /// Stable limit name.
        name: &'static str,
        /// Configured value.
        actual: u64,
        /// Hard maximum.
        maximum: u64,
    },
    /// Per-selectable request accounting cannot exceed total accounting.
    #[error(
        "per-selectable request limit {requests_per_selectable} exceeds total request limit {total_requests}"
    )]
    PerSelectableLimitExceedsTotal {
        /// Configured per-selectable limit.
        requests_per_selectable: u64,
        /// Configured total limit.
        total_requests: u64,
    },
    /// The expected or observed catalog exceeds the scenario declaration cap.
    #[error("selectable declaration count {actual} exceeds limit {maximum}")]
    DeclarationLimitExceeded {
        /// Attempted declaration count.
        actual: usize,
        /// Scenario limit.
        maximum: usize,
    },
    /// The expected catalog contains one identifier twice.
    #[error("selectable `{selectable_id}` has duplicate expected declarations")]
    DuplicateExpectedDeclaration {
        /// Duplicate identifier.
        selectable_id: String,
    },
    /// A registration arrived after setup freeze.
    #[error("selectable registration arrived after catalog freeze")]
    RegistrationAfterFreeze,
    /// A registration identifier was already observed.
    #[error("selectable `{selectable_id}` registered more than once")]
    DuplicateRegistration {
        /// Duplicate identifier.
        selectable_id: String,
    },
    /// A registration was absent from the exact expected catalog.
    #[error("selectable `{selectable_id}` was not declared by the scenario")]
    UnexpectedDeclaration {
        /// Unexpected identifier.
        selectable_id: String,
    },
    /// A guest declaration differs from its expected contract.
    #[error("selectable `{selectable_id}` differs from its launch-authenticated declaration")]
    DeclarationContractMismatch {
        /// Mismatched identifier.
        selectable_id: String,
    },
    /// A registration or request sequence did not strictly advance.
    #[error("{kind} sequence {actual} does not strictly follow {previous:?}")]
    SequenceNotIncreasing {
        /// Sequence namespace.
        kind: &'static str,
        /// Previously accepted sequence, when present.
        previous: Option<u64>,
        /// Attempted sequence.
        actual: u64,
    },
    /// The catalog was frozen more than once.
    #[error("selectable catalog was already frozen")]
    CatalogAlreadyFrozen,
    /// Required scenario declarations were absent at freeze.
    #[error("required selectables were not registered: {missing:?}")]
    MissingRequiredDeclarations {
        /// Canonically ordered missing identifiers.
        missing: Vec<String>,
    },
    /// A runtime request arrived before setup freeze.
    #[error("selectable request arrived before catalog freeze")]
    RequestBeforeFreeze,
    /// A second request arrived while the guest already owns one pending reply.
    #[error(
        "selectable request {actual_sequence} arrived while request {pending_sequence} is pending"
    )]
    RequestAlreadyPending {
        /// Retained request sequence.
        pending_sequence: u64,
        /// New request sequence.
        actual_sequence: u64,
    },
    /// A request names no registered declaration.
    #[error("selectable request names unknown catalog entry `{selectable_id}`")]
    UnknownSelectable {
        /// Unknown identifier.
        selectable_id: String,
    },
    /// The total request ceiling was reached.
    #[error("selectable total request limit {maximum} was reached")]
    TotalRequestLimitExceeded {
        /// Scenario total limit.
        maximum: u64,
    },
    /// One selectable's request ceiling was reached.
    #[error("selectable `{selectable_id}` request limit {maximum} was reached")]
    SelectableRequestLimitExceeded {
        /// Exhausted identifier.
        selectable_id: String,
        /// Scenario per-selectable limit.
        maximum: u64,
    },
    /// Completion was attempted with no retained request.
    #[error("selectable completion has no pending request")]
    NoPendingRequest,
    /// Completion used a token from another catalog incarnation or request.
    #[error("selectable completion token differs from the retained request")]
    PendingRequestMismatch,
    /// Completion returned a reply for another request sequence.
    #[error("selectable reply sequence {actual} does not match pending sequence {expected}")]
    ReplySequenceMismatch {
        /// Retained sequence.
        expected: u64,
        /// Reply sequence.
        actual: u64,
    },
    /// Checked request accounting overflowed.
    #[error("selectable request accounting overflowed")]
    RequestCountOverflow,
}

#[cfg(test)]
mod tests;
