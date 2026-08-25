//! Immutable guest-selectable catalog and continuation launch plans.
//!
//! The daemon derives this process-neutral artifact from authenticated scenario
//! and checkpoint state. A future control-protocol setup profile passes its
//! canonical bytes in a sealed descriptor so the GPL-side plugin can reconcile
//! guest registrations and restore pending request ownership without linking
//! campaign implementation types.
//!
//! ```text
//! offset  size  field
//! 0       8     magic = "CRUCSCP2"
//! 8       4     schema version = 2, big-endian
//! 12      4     header length = 104
//! 16      4     total byte length
//! 20      4     flags: frozen, last-registration, last-request, pending
//! 24      4     declaration limit
//! 28      4     expected declaration count
//! 32      4     registered identifier count
//! 36      4     completed-counter count
//! 40      8     requests-per-selectable limit
//! 48      8     total-request limit
//! 56      8     total completed requests
//! 64      8     last registration sequence or zero
//! 72      8     last completed request sequence or zero
//! 80      8     pending trap icount or zero
//! 88      4     pending vCPU index or zero
//! 92      4     pending SelectionRequestV1 byte length or zero
//! 96      8     pending guest virtual reply address or zero
//! 104     ...   expected entries, registered IDs, completed counters, pending
//! ```
//!
//! Expected entries are `presence:u8`, three zero bytes, `length:u32`, and one
//! canonical sequence-zero [`crate::SelectableRegister`]. Registered IDs are
//! `length:u16` plus identifier bytes. Completed counters append one big-endian
//! `u64` count to that identifier form. All three collections are strictly
//! ordered by identifier and exact; no trailing bytes are admitted.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use crate::{
    SelectableProtocolError, SelectableRegister, SelectionRequest, validate_selectable_identifier,
};

/// Frozen magic at the start of every selectable catalog plan.
pub const SELECTABLE_CATALOG_PLAN_MAGIC: [u8; 8] = *b"CRUCSCP2";
/// Canonical selectable catalog plan schema version.
pub const SELECTABLE_CATALOG_PLAN_VERSION: u32 = 2;
/// Fixed plan header bytes.
pub const SELECTABLE_CATALOG_PLAN_HEADER_BYTES: usize = 104;
/// Maximum canonical bytes in one node-local plan.
pub const SELECTABLE_CATALOG_PLAN_MAX_BYTES: usize = 32 * 1024 * 1024;
/// Maximum expected or registered declarations in one node-local plan.
pub const SELECTABLE_CATALOG_PLAN_MAX_DECLARATIONS: usize = 4_096;
/// Maximum completed requests represented by one node-local plan.
pub const SELECTABLE_CATALOG_PLAN_MAX_REQUESTS: u64 = 1_000_000;

const FLAG_FROZEN: u32 = 1 << 0;
const FLAG_LAST_REGISTRATION: u32 = 1 << 1;
const FLAG_LAST_REQUEST: u32 = 1 << 2;
const FLAG_PENDING: u32 = 1 << 3;
const KNOWN_FLAGS: u32 = FLAG_FROZEN | FLAG_LAST_REGISTRATION | FLAG_LAST_REQUEST | FLAG_PENDING;
const EXPECTED_ENTRY_HEADER_BYTES: usize = 8;
const LEGACY_SELECTABLE_CATALOG_PLAN_MAGIC: [u8; 8] = *b"CRUCSCP1";
const LEGACY_SELECTABLE_CATALOG_PLAN_VERSION: u32 = 1;
const LEGACY_SELECTABLE_CATALOG_PLAN_HEADER_BYTES: usize = 96;

/// Whether one expected guest declaration is required at catalog freeze.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectablePlanPresence {
    /// The guest may omit the declaration, but any registration must match.
    Optional,
    /// Catalog freeze requires an exact registration.
    Required,
}

impl SelectablePlanPresence {
    const fn wire_value(self) -> u8 {
        match self {
            Self::Optional => 0,
            Self::Required => 1,
        }
    }

    fn from_wire_value(value: u8) -> Result<Self, SelectableCatalogPlanError> {
        match value {
            0 => Ok(Self::Optional),
            1 => Ok(Self::Required),
            _ => Err(SelectableCatalogPlanError::InvalidPresence { value }),
        }
    }
}

/// Exact expected declaration contract, normalized to sequence zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectablePlanDeclaration {
    registration: SelectableRegister,
    presence: SelectablePlanPresence,
}

impl SelectablePlanDeclaration {
    /// Builds one expected declaration from standalone ABI fields.
    ///
    /// # Errors
    ///
    /// Returns [`SelectableProtocolError`] when the declaration is not a
    /// canonical bounded selectable registration.
    pub fn new(
        selectable_id: impl Into<String>,
        domain: Vec<u8>,
        default_value: Vec<u8>,
        semantic_tags: Vec<String>,
        presence: SelectablePlanPresence,
    ) -> Result<Self, SelectableProtocolError> {
        Ok(Self {
            registration: SelectableRegister::new(
                0,
                selectable_id,
                domain,
                default_value,
                semantic_tags,
            )?,
            presence,
        })
    }

    /// Normalizes one canonical guest registration into an expectation.
    ///
    /// # Errors
    ///
    /// Returns [`SelectableProtocolError`] only if copied fields fail the
    /// standalone ABI validator.
    pub fn from_registration(
        registration: &SelectableRegister,
        presence: SelectablePlanPresence,
    ) -> Result<Self, SelectableProtocolError> {
        Self::new(
            registration.selectable_id(),
            registration.domain().to_vec(),
            registration.default_value().to_vec(),
            registration.semantic_tags().to_vec(),
            presence,
        )
    }

    /// Returns the sequence-zero canonical registration contract.
    #[must_use]
    pub const fn registration(&self) -> &SelectableRegister {
        &self.registration
    }

    /// Returns whether freeze requires this declaration.
    #[must_use]
    pub const fn presence(&self) -> SelectablePlanPresence {
        self.presence
    }
}

/// Scenario-owned node-local catalog and request ceilings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectablePlanLimits {
    declarations: usize,
    requests_per_selectable: u64,
    total_requests: u64,
}

impl SelectablePlanLimits {
    /// Builds one nonzero set of ceilings under the plan hard maxima.
    ///
    /// # Errors
    ///
    /// Returns [`SelectableCatalogPlanError`] when a ceiling is zero or too
    /// large, or the per-selectable ceiling exceeds the total ceiling.
    pub fn new(
        declarations: usize,
        requests_per_selectable: u64,
        total_requests: u64,
    ) -> Result<Self, SelectableCatalogPlanError> {
        if declarations == 0 || declarations > SELECTABLE_CATALOG_PLAN_MAX_DECLARATIONS {
            let actual = u64::try_from(declarations).unwrap_or(u64::MAX);
            return Err(SelectableCatalogPlanError::InvalidLimit {
                field: "declarations",
                actual,
                maximum: SELECTABLE_CATALOG_PLAN_MAX_DECLARATIONS as u64,
            });
        }
        validate_request_limit("requests_per_selectable", requests_per_selectable)?;
        validate_request_limit("total_requests", total_requests)?;
        if requests_per_selectable > total_requests {
            return Err(SelectableCatalogPlanError::PerSelectableLimitExceedsTotal {
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

    /// Returns the declaration ceiling.
    #[must_use]
    pub const fn declarations(self) -> usize {
        self.declarations
    }

    /// Returns the per-selectable completed-request ceiling.
    #[must_use]
    pub const fn requests_per_selectable(self) -> u64 {
        self.requests_per_selectable
    }

    /// Returns the total completed-request ceiling.
    #[must_use]
    pub const fn total_requests(self) -> u64 {
        self.total_requests
    }
}

fn validate_request_limit(
    field: &'static str,
    value: u64,
) -> Result<(), SelectableCatalogPlanError> {
    if value == 0 || value > SELECTABLE_CATALOG_PLAN_MAX_REQUESTS {
        Err(SelectableCatalogPlanError::InvalidLimit {
            field,
            actual: value,
            maximum: SELECTABLE_CATALOG_PLAN_MAX_REQUESTS,
        })
    } else {
        Ok(())
    }
}

/// Catalog lifecycle phase retained across a node launch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectablePlanPhase {
    /// Setup registrations remain open.
    Registering,
    /// The exact catalog is frozen and runtime requests may execute.
    Frozen,
}

/// Exact pending request and trap coordinate retained across restore.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectablePlanPendingRequest {
    request: SelectionRequest,
    icount: u64,
    vcpu_index: u32,
    guest_virtual_address: u64,
}

impl SelectablePlanPendingRequest {
    /// Builds one retained request coordinate.
    #[must_use]
    pub const fn new(
        request: SelectionRequest,
        icount: u64,
        vcpu_index: u32,
        guest_virtual_address: u64,
    ) -> Self {
        Self {
            request,
            icount,
            vcpu_index,
            guest_virtual_address,
        }
    }

    /// Returns the complete request and reply reservation.
    #[must_use]
    pub const fn request(&self) -> &SelectionRequest {
        &self.request
    }

    /// Returns the logical trap instruction count.
    #[must_use]
    pub const fn icount(&self) -> u64 {
        self.icount
    }

    /// Returns the vCPU that owns the pending request.
    #[must_use]
    pub const fn vcpu_index(&self) -> u32 {
        self.vcpu_index
    }

    /// Returns the process-neutral guest virtual address of the reply reservation.
    #[must_use]
    pub const fn guest_virtual_address(&self) -> u64 {
        self.guest_virtual_address
    }
}

/// Exact catalog continuation state restored into a fresh plugin process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectablePlanContinuation {
    phase: SelectablePlanPhase,
    registered: BTreeSet<String>,
    last_registration_sequence: Option<u64>,
    completed_requests: BTreeMap<String, u64>,
    total_completed_requests: u64,
    last_completed_request_sequence: Option<u64>,
    pending: Option<SelectablePlanPendingRequest>,
}

impl SelectablePlanContinuation {
    /// Builds one continuation; cross-checking against declarations occurs in
    /// [`SelectableCatalogPlan::new`].
    ///
    /// # Errors
    ///
    /// Returns [`SelectableCatalogPlanError`] when identifiers are invalid,
    /// counts are zero/overflowing, or sequence/pending shape contradicts the
    /// lifecycle phase.
    pub fn new(
        phase: SelectablePlanPhase,
        registered: BTreeSet<String>,
        last_registration_sequence: Option<u64>,
        completed_requests: BTreeMap<String, u64>,
        last_completed_request_sequence: Option<u64>,
        pending: Option<SelectablePlanPendingRequest>,
    ) -> Result<Self, SelectableCatalogPlanError> {
        if registered.len() > SELECTABLE_CATALOG_PLAN_MAX_DECLARATIONS {
            return Err(SelectableCatalogPlanError::CountTooLarge {
                field: "registered",
                actual: registered.len(),
                maximum: SELECTABLE_CATALOG_PLAN_MAX_DECLARATIONS,
            });
        }
        if completed_requests.len() > SELECTABLE_CATALOG_PLAN_MAX_DECLARATIONS {
            return Err(SelectableCatalogPlanError::CountTooLarge {
                field: "completed",
                actual: completed_requests.len(),
                maximum: SELECTABLE_CATALOG_PLAN_MAX_DECLARATIONS,
            });
        }
        for identifier in &registered {
            validate_selectable_identifier("registered_selectable", identifier)?;
        }
        if registered.is_empty() != last_registration_sequence.is_none() {
            return Err(SelectableCatalogPlanError::InvalidContinuation {
                reason: "registration watermark presence differs from registered catalog",
            });
        }
        if phase == SelectablePlanPhase::Registering
            && (!completed_requests.is_empty()
                || last_completed_request_sequence.is_some()
                || pending.is_some())
        {
            return Err(SelectableCatalogPlanError::InvalidContinuation {
                reason: "registering catalog carries runtime request state",
            });
        }
        let mut total_completed_requests = 0_u64;
        for (identifier, count) in &completed_requests {
            validate_selectable_identifier("completed_selectable", identifier)?;
            if *count == 0 {
                return Err(SelectableCatalogPlanError::InvalidContinuation {
                    reason: "completed request counter is zero",
                });
            }
            if *count > SELECTABLE_CATALOG_PLAN_MAX_REQUESTS {
                return Err(SelectableCatalogPlanError::RequestLimitExceeded {
                    field: "completed_counter",
                    actual: *count,
                    maximum: SELECTABLE_CATALOG_PLAN_MAX_REQUESTS,
                });
            }
            total_completed_requests = total_completed_requests
                .checked_add(*count)
                .ok_or(SelectableCatalogPlanError::CountOverflow)?;
        }
        if total_completed_requests > SELECTABLE_CATALOG_PLAN_MAX_REQUESTS {
            return Err(SelectableCatalogPlanError::RequestLimitExceeded {
                field: "total_completed_requests",
                actual: total_completed_requests,
                maximum: SELECTABLE_CATALOG_PLAN_MAX_REQUESTS,
            });
        }
        if (total_completed_requests == 0) != last_completed_request_sequence.is_none() {
            return Err(SelectableCatalogPlanError::InvalidContinuation {
                reason: "request watermark presence differs from completed request count",
            });
        }
        if pending.is_some() && phase != SelectablePlanPhase::Frozen {
            return Err(SelectableCatalogPlanError::InvalidContinuation {
                reason: "pending request belongs to an unfrozen catalog",
            });
        }
        if let Some(pending) = &pending
            && last_completed_request_sequence
                .is_some_and(|sequence| pending.request.sequence() <= sequence)
        {
            return Err(SelectableCatalogPlanError::InvalidContinuation {
                reason: "pending request sequence does not advance the completed watermark",
            });
        }
        Ok(Self {
            phase,
            registered,
            last_registration_sequence,
            completed_requests,
            total_completed_requests,
            last_completed_request_sequence,
            pending,
        })
    }

    /// Returns an empty cold-launch continuation.
    #[must_use]
    pub fn cold() -> Self {
        Self {
            phase: SelectablePlanPhase::Registering,
            registered: BTreeSet::new(),
            last_registration_sequence: None,
            completed_requests: BTreeMap::new(),
            total_completed_requests: 0,
            last_completed_request_sequence: None,
            pending: None,
        }
    }

    /// Returns the retained catalog phase.
    #[must_use]
    pub const fn phase(&self) -> SelectablePlanPhase {
        self.phase
    }

    /// Returns registered identifiers in canonical order.
    #[must_use]
    pub const fn registered(&self) -> &BTreeSet<String> {
        &self.registered
    }

    /// Returns the registration sequence watermark.
    #[must_use]
    pub const fn last_registration_sequence(&self) -> Option<u64> {
        self.last_registration_sequence
    }

    /// Returns completed per-selectable request counts.
    #[must_use]
    pub const fn completed_requests(&self) -> &BTreeMap<String, u64> {
        &self.completed_requests
    }

    /// Returns the total completed request count.
    #[must_use]
    pub const fn total_completed_requests(&self) -> u64 {
        self.total_completed_requests
    }

    /// Returns the completed-request sequence watermark.
    #[must_use]
    pub const fn last_completed_request_sequence(&self) -> Option<u64> {
        self.last_completed_request_sequence
    }

    /// Returns the retained pending request, if any.
    #[must_use]
    pub const fn pending(&self) -> Option<&SelectablePlanPendingRequest> {
        self.pending.as_ref()
    }
}

/// Complete node-local launch-authenticated selectable catalog plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectableCatalogPlan {
    limits: SelectablePlanLimits,
    declarations: BTreeMap<String, SelectablePlanDeclaration>,
    continuation: SelectablePlanContinuation,
}

impl Default for SelectableCatalogPlan {
    fn default() -> Self {
        Self {
            limits: SelectablePlanLimits {
                declarations: 1,
                requests_per_selectable: 1,
                total_requests: 1,
            },
            declarations: BTreeMap::new(),
            continuation: SelectablePlanContinuation::cold(),
        }
    }
}

impl SelectableCatalogPlan {
    /// Builds and cross-validates one complete plan.
    ///
    /// # Errors
    ///
    /// Returns [`SelectableCatalogPlanError`] when declarations are duplicate
    /// or over limit, continuation identifiers are unknown, required frozen
    /// declarations are missing, counters exceed limits, or canonical bytes
    /// exceed the plan profile.
    pub fn new(
        limits: SelectablePlanLimits,
        declarations: Vec<SelectablePlanDeclaration>,
        continuation: SelectablePlanContinuation,
    ) -> Result<Self, SelectableCatalogPlanError> {
        if declarations.len() > limits.declarations() {
            return Err(SelectableCatalogPlanError::CountTooLarge {
                field: "declarations",
                actual: declarations.len(),
                maximum: limits.declarations(),
            });
        }
        let mut indexed = BTreeMap::new();
        for declaration in declarations {
            let identifier = declaration.registration.selectable_id().to_owned();
            if indexed.insert(identifier.clone(), declaration).is_some() {
                return Err(SelectableCatalogPlanError::DuplicateIdentifier {
                    field: "declarations",
                    identifier,
                });
            }
        }
        for registered in &continuation.registered {
            if !indexed.contains_key(registered) {
                return Err(SelectableCatalogPlanError::UnknownIdentifier {
                    field: "registered",
                    identifier: registered.clone(),
                });
            }
        }
        if continuation.phase == SelectablePlanPhase::Frozen {
            for declaration in indexed.values() {
                if declaration.presence == SelectablePlanPresence::Required
                    && !continuation
                        .registered
                        .contains(declaration.registration.selectable_id())
                {
                    return Err(SelectableCatalogPlanError::MissingRequiredDeclaration {
                        identifier: declaration.registration.selectable_id().to_owned(),
                    });
                }
            }
        }
        for (identifier, count) in &continuation.completed_requests {
            if !continuation.registered.contains(identifier) {
                return Err(SelectableCatalogPlanError::UnknownIdentifier {
                    field: "completed",
                    identifier: identifier.clone(),
                });
            }
            if *count > limits.requests_per_selectable() {
                return Err(SelectableCatalogPlanError::RequestLimitExceeded {
                    field: "requests_per_selectable",
                    actual: *count,
                    maximum: limits.requests_per_selectable(),
                });
            }
        }
        if continuation.total_completed_requests > limits.total_requests() {
            return Err(SelectableCatalogPlanError::RequestLimitExceeded {
                field: "total_requests",
                actual: continuation.total_completed_requests,
                maximum: limits.total_requests(),
            });
        }
        if let Some(pending) = &continuation.pending
            && !continuation
                .registered
                .contains(pending.request.selectable_id())
        {
            return Err(SelectableCatalogPlanError::UnknownIdentifier {
                field: "pending",
                identifier: pending.request.selectable_id().to_owned(),
            });
        }
        let value = Self {
            limits,
            declarations: indexed,
            continuation,
        };
        let bytes = value.encoded_len()?;
        if bytes > SELECTABLE_CATALOG_PLAN_MAX_BYTES {
            return Err(SelectableCatalogPlanError::PlanTooLarge {
                bytes,
                maximum: SELECTABLE_CATALOG_PLAN_MAX_BYTES,
            });
        }
        Ok(value)
    }

    /// Returns scenario-owned limits.
    #[must_use]
    pub const fn limits(&self) -> SelectablePlanLimits {
        self.limits
    }

    /// Returns expected declarations in canonical identifier order.
    #[must_use]
    pub const fn declarations(&self) -> &BTreeMap<String, SelectablePlanDeclaration> {
        &self.declarations
    }

    /// Returns exact cold or restored continuation state.
    #[must_use]
    pub const fn continuation(&self) -> &SelectablePlanContinuation {
        &self.continuation
    }

    /// Encodes this plan into its canonical descriptor body.
    ///
    /// # Errors
    ///
    /// Returns [`SelectableCatalogPlanError`] only if checked length arithmetic
    /// overflows or a nested standalone message can no longer encode.
    pub fn encode(&self) -> Result<Vec<u8>, SelectableCatalogPlanError> {
        let total_len = self.encoded_len()?;
        let mut flags = 0_u32;
        if self.continuation.phase == SelectablePlanPhase::Frozen {
            flags |= FLAG_FROZEN;
        }
        if self.continuation.last_registration_sequence.is_some() {
            flags |= FLAG_LAST_REGISTRATION;
        }
        if self.continuation.last_completed_request_sequence.is_some() {
            flags |= FLAG_LAST_REQUEST;
        }
        if self.continuation.pending.is_some() {
            flags |= FLAG_PENDING;
        }
        let pending_bytes = self
            .continuation
            .pending
            .as_ref()
            .map(|pending| pending.request.encode())
            .transpose()?;
        let pending_len = pending_bytes.as_ref().map_or(0, Vec::len);

        let mut bytes = vec![0; SELECTABLE_CATALOG_PLAN_HEADER_BYTES];
        bytes[..8].copy_from_slice(&SELECTABLE_CATALOG_PLAN_MAGIC);
        write_u32(&mut bytes, 8, SELECTABLE_CATALOG_PLAN_VERSION)?;
        write_u32(
            &mut bytes,
            12,
            u32_len(SELECTABLE_CATALOG_PLAN_HEADER_BYTES)?,
        )?;
        write_u32(&mut bytes, 16, u32_len(total_len)?)?;
        write_u32(&mut bytes, 20, flags)?;
        write_u32(&mut bytes, 24, u32_len(self.limits.declarations)?)?;
        write_u32(&mut bytes, 28, u32_len(self.declarations.len())?)?;
        write_u32(&mut bytes, 32, u32_len(self.continuation.registered.len())?)?;
        write_u32(
            &mut bytes,
            36,
            u32_len(self.continuation.completed_requests.len())?,
        )?;
        write_u64(&mut bytes, 40, self.limits.requests_per_selectable)?;
        write_u64(&mut bytes, 48, self.limits.total_requests)?;
        write_u64(&mut bytes, 56, self.continuation.total_completed_requests)?;
        write_u64(
            &mut bytes,
            64,
            self.continuation.last_registration_sequence.unwrap_or(0),
        )?;
        write_u64(
            &mut bytes,
            72,
            self.continuation
                .last_completed_request_sequence
                .unwrap_or(0),
        )?;
        write_u64(
            &mut bytes,
            80,
            self.continuation
                .pending
                .as_ref()
                .map_or(0, SelectablePlanPendingRequest::icount),
        )?;
        write_u32(
            &mut bytes,
            88,
            self.continuation
                .pending
                .as_ref()
                .map_or(0, SelectablePlanPendingRequest::vcpu_index),
        )?;
        write_u32(&mut bytes, 92, u32_len(pending_len)?)?;
        write_u64(
            &mut bytes,
            96,
            self.continuation
                .pending
                .as_ref()
                .map_or(0, SelectablePlanPendingRequest::guest_virtual_address),
        )?;

        for declaration in self.declarations.values() {
            let registration = declaration.registration.encode()?;
            bytes.push(declaration.presence.wire_value());
            bytes.extend_from_slice(&[0; 3]);
            bytes.extend_from_slice(&u32_len(registration.len())?.to_be_bytes());
            bytes.extend_from_slice(&registration);
        }
        for identifier in &self.continuation.registered {
            append_identifier(&mut bytes, identifier)?;
        }
        for (identifier, count) in &self.continuation.completed_requests {
            append_identifier(&mut bytes, identifier)?;
            bytes.extend_from_slice(&count.to_be_bytes());
        }
        if let Some(pending_bytes) = pending_bytes {
            bytes.extend_from_slice(&pending_bytes);
        }
        debug_assert_eq!(bytes.len(), total_len);
        Ok(bytes)
    }

    /// Decodes one complete canonical descriptor body.
    ///
    /// # Errors
    ///
    /// Returns [`SelectableCatalogPlanError`] for any size, header, flag,
    /// ordering, nested-message, limit, continuation, or trailing-byte failure.
    pub fn decode(bytes: &[u8]) -> Result<Self, SelectableCatalogPlanError> {
        if bytes.len() > SELECTABLE_CATALOG_PLAN_MAX_BYTES {
            return Err(SelectableCatalogPlanError::PlanTooLarge {
                bytes: bytes.len(),
                maximum: SELECTABLE_CATALOG_PLAN_MAX_BYTES,
            });
        }
        if bytes.len() < LEGACY_SELECTABLE_CATALOG_PLAN_HEADER_BYTES {
            return Err(SelectableCatalogPlanError::Truncated);
        }
        let version = read_u32(bytes, 8)?;
        let legacy = if bytes[..8] == SELECTABLE_CATALOG_PLAN_MAGIC {
            if version != SELECTABLE_CATALOG_PLAN_VERSION {
                return Err(SelectableCatalogPlanError::UnsupportedVersion { version });
            }
            false
        } else if bytes[..8] == LEGACY_SELECTABLE_CATALOG_PLAN_MAGIC {
            if version != LEGACY_SELECTABLE_CATALOG_PLAN_VERSION {
                return Err(SelectableCatalogPlanError::UnsupportedVersion { version });
            }
            true
        } else {
            return Err(SelectableCatalogPlanError::InvalidMagic);
        };
        let expected_header_len = if legacy {
            LEGACY_SELECTABLE_CATALOG_PLAN_HEADER_BYTES
        } else {
            SELECTABLE_CATALOG_PLAN_HEADER_BYTES
        };
        let header_len = usize_from_u32(read_u32(bytes, 12)?)?;
        if header_len != expected_header_len {
            return Err(SelectableCatalogPlanError::InvalidHeaderLength { header_len });
        }
        let total_len = usize_from_u32(read_u32(bytes, 16)?)?;
        if total_len != bytes.len() {
            return Err(SelectableCatalogPlanError::InvalidTotalLength {
                declared: total_len,
                actual: bytes.len(),
            });
        }
        let flags = read_u32(bytes, 20)?;
        if flags & !KNOWN_FLAGS != 0 {
            return Err(SelectableCatalogPlanError::UnknownFlags { flags });
        }
        let limits = SelectablePlanLimits::new(
            usize_from_u32(read_u32(bytes, 24)?)?,
            read_u64(bytes, 40)?,
            read_u64(bytes, 48)?,
        )?;
        let expected_count =
            bounded_count(read_u32(bytes, 28)?, "declarations", limits.declarations)?;
        let registered_count = bounded_count(
            read_u32(bytes, 32)?,
            "registered",
            SELECTABLE_CATALOG_PLAN_MAX_DECLARATIONS,
        )?;
        let completed_count = bounded_count(
            read_u32(bytes, 36)?,
            "completed",
            SELECTABLE_CATALOG_PLAN_MAX_DECLARATIONS,
        )?;
        let total_completed = read_u64(bytes, 56)?;
        let last_registration = optional_u64(
            flags & FLAG_LAST_REGISTRATION != 0,
            read_u64(bytes, 64)?,
            "last_registration_sequence",
        )?;
        let last_request = optional_u64(
            flags & FLAG_LAST_REQUEST != 0,
            read_u64(bytes, 72)?,
            "last_completed_request_sequence",
        )?;
        let pending_icount = read_u64(bytes, 80)?;
        let pending_vcpu = read_u32(bytes, 88)?;
        let pending_len = usize_from_u32(read_u32(bytes, 92)?)?;
        let pending_guest_virtual_address = if legacy { 0 } else { read_u64(bytes, 96)? };
        if flags & FLAG_PENDING == 0
            && (pending_icount != 0
                || pending_vcpu != 0
                || pending_len != 0
                || pending_guest_virtual_address != 0)
        {
            return Err(SelectableCatalogPlanError::InvalidContinuation {
                reason: "absent pending request has nonzero header fields",
            });
        }
        if flags & FLAG_PENDING != 0 && pending_len == 0 {
            return Err(SelectableCatalogPlanError::InvalidContinuation {
                reason: "present pending request has zero byte length",
            });
        }
        if legacy && flags & FLAG_PENDING != 0 {
            return Err(SelectableCatalogPlanError::LegacyPendingReplyTargetMissing);
        }

        let mut cursor = expected_header_len;
        let mut declarations = Vec::with_capacity(expected_count);
        let mut previous_identifier: Option<String> = None;
        for _ in 0..expected_count {
            let header = take(bytes, &mut cursor, EXPECTED_ENTRY_HEADER_BYTES)?;
            let presence = SelectablePlanPresence::from_wire_value(header[0])?;
            if header[1..4] != [0; 3] {
                return Err(SelectableCatalogPlanError::NonzeroReserved);
            }
            let body_len = usize_from_u32(u32::from_be_bytes([
                header[4], header[5], header[6], header[7],
            ]))?;
            let registration = SelectableRegister::decode(take(bytes, &mut cursor, body_len)?)?;
            if registration.sequence() != 0 {
                return Err(SelectableCatalogPlanError::InvalidContinuation {
                    reason: "expected declaration sequence is not zero",
                });
            }
            require_strict_identifier_order(
                &mut previous_identifier,
                registration.selectable_id(),
                "declarations",
            )?;
            declarations.push(SelectablePlanDeclaration::from_registration(
                &registration,
                presence,
            )?);
        }

        let mut registered = BTreeSet::new();
        previous_identifier = None;
        for _ in 0..registered_count {
            let identifier = decode_identifier(bytes, &mut cursor, "registered")?;
            require_strict_identifier_order(&mut previous_identifier, &identifier, "registered")?;
            registered.insert(identifier);
        }

        let mut completed = BTreeMap::new();
        previous_identifier = None;
        for _ in 0..completed_count {
            let identifier = decode_identifier(bytes, &mut cursor, "completed")?;
            require_strict_identifier_order(&mut previous_identifier, &identifier, "completed")?;
            let count_bytes = take(bytes, &mut cursor, 8)?;
            let count = u64::from_be_bytes(
                count_bytes
                    .try_into()
                    .map_err(|_source| SelectableCatalogPlanError::Truncated)?,
            );
            completed.insert(identifier, count);
        }

        let pending = if flags & FLAG_PENDING != 0 {
            let request = SelectionRequest::decode(take(bytes, &mut cursor, pending_len)?)?;
            Some(SelectablePlanPendingRequest::new(
                request,
                pending_icount,
                pending_vcpu,
                pending_guest_virtual_address,
            ))
        } else {
            None
        };
        if cursor != bytes.len() {
            return Err(SelectableCatalogPlanError::TrailingBytes {
                bytes: bytes.len() - cursor,
            });
        }
        let phase = if flags & FLAG_FROZEN != 0 {
            SelectablePlanPhase::Frozen
        } else {
            SelectablePlanPhase::Registering
        };
        let continuation = SelectablePlanContinuation::new(
            phase,
            registered,
            last_registration,
            completed,
            last_request,
            pending,
        )?;
        if continuation.total_completed_requests != total_completed {
            return Err(SelectableCatalogPlanError::InvalidContinuation {
                reason: "encoded total completed requests differs from counter sum",
            });
        }
        let value = Self::new(limits, declarations, continuation)?;
        if !legacy && value.encode()?.as_slice() != bytes {
            return Err(SelectableCatalogPlanError::NonCanonicalEncoding);
        }
        Ok(value)
    }

    fn encoded_len(&self) -> Result<usize, SelectableCatalogPlanError> {
        let mut total = SELECTABLE_CATALOG_PLAN_HEADER_BYTES;
        for declaration in self.declarations.values() {
            let bytes = declaration.registration.encode()?.len();
            total = checked_add(total, EXPECTED_ENTRY_HEADER_BYTES)?;
            total = checked_add(total, bytes)?;
        }
        for identifier in &self.continuation.registered {
            total = checked_add(total, 2)?;
            total = checked_add(total, identifier.len())?;
        }
        for identifier in self.continuation.completed_requests.keys() {
            total = checked_add(total, 2)?;
            total = checked_add(total, identifier.len())?;
            total = checked_add(total, 8)?;
        }
        if let Some(pending) = &self.continuation.pending {
            total = checked_add(total, pending.request.encode()?.len())?;
        }
        Ok(total)
    }
}

fn append_identifier(
    bytes: &mut Vec<u8>,
    identifier: &str,
) -> Result<(), SelectableCatalogPlanError> {
    let len = u16::try_from(identifier.len())
        .map_err(|_source| SelectableCatalogPlanError::LengthOverflow)?;
    bytes.extend_from_slice(&len.to_be_bytes());
    bytes.extend_from_slice(identifier.as_bytes());
    Ok(())
}

fn decode_identifier(
    bytes: &[u8],
    cursor: &mut usize,
    field: &'static str,
) -> Result<String, SelectableCatalogPlanError> {
    let len_bytes = take(bytes, cursor, 2)?;
    let len = usize::from(u16::from_be_bytes([len_bytes[0], len_bytes[1]]));
    let value = std::str::from_utf8(take(bytes, cursor, len)?)
        .map_err(|_source| SelectableCatalogPlanError::InvalidUtf8 { field })?
        .to_owned();
    validate_selectable_identifier(field, &value)?;
    Ok(value)
}

fn require_strict_identifier_order(
    previous: &mut Option<String>,
    actual: &str,
    field: &'static str,
) -> Result<(), SelectableCatalogPlanError> {
    if previous
        .as_deref()
        .is_some_and(|previous| previous >= actual)
    {
        return Err(SelectableCatalogPlanError::IdentifiersNotIncreasing { field });
    }
    *previous = Some(actual.to_owned());
    Ok(())
}

fn optional_u64(
    present: bool,
    value: u64,
    field: &'static str,
) -> Result<Option<u64>, SelectableCatalogPlanError> {
    if present {
        Ok(Some(value))
    } else if value == 0 {
        Ok(None)
    } else {
        Err(SelectableCatalogPlanError::NonzeroAbsentField { field })
    }
}

fn bounded_count(
    value: u32,
    field: &'static str,
    maximum: usize,
) -> Result<usize, SelectableCatalogPlanError> {
    let actual = usize_from_u32(value)?;
    if actual > maximum {
        Err(SelectableCatalogPlanError::CountTooLarge {
            field,
            actual,
            maximum,
        })
    } else {
        Ok(actual)
    }
}

fn take<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    len: usize,
) -> Result<&'a [u8], SelectableCatalogPlanError> {
    let end = cursor
        .checked_add(len)
        .ok_or(SelectableCatalogPlanError::LengthOverflow)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(SelectableCatalogPlanError::Truncated)?;
    *cursor = end;
    Ok(value)
}

fn checked_add(left: usize, right: usize) -> Result<usize, SelectableCatalogPlanError> {
    left.checked_add(right)
        .ok_or(SelectableCatalogPlanError::LengthOverflow)
}

fn u32_len(value: usize) -> Result<u32, SelectableCatalogPlanError> {
    u32::try_from(value).map_err(|_source| SelectableCatalogPlanError::LengthOverflow)
}

fn usize_from_u32(value: u32) -> Result<usize, SelectableCatalogPlanError> {
    usize::try_from(value).map_err(|_source| SelectableCatalogPlanError::LengthOverflow)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, SelectableCatalogPlanError> {
    let value = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or(SelectableCatalogPlanError::Truncated)?;
    Ok(u32::from_be_bytes(value.try_into().map_err(|_source| {
        SelectableCatalogPlanError::Truncated
    })?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, SelectableCatalogPlanError> {
    let value = bytes
        .get(offset..offset.saturating_add(8))
        .ok_or(SelectableCatalogPlanError::Truncated)?;
    Ok(u64::from_be_bytes(value.try_into().map_err(|_source| {
        SelectableCatalogPlanError::Truncated
    })?))
}

fn write_u32(
    bytes: &mut [u8],
    offset: usize,
    value: u32,
) -> Result<(), SelectableCatalogPlanError> {
    let field = bytes
        .get_mut(offset..offset.saturating_add(4))
        .ok_or(SelectableCatalogPlanError::LengthOverflow)?;
    field.copy_from_slice(&value.to_be_bytes());
    Ok(())
}

fn write_u64(
    bytes: &mut [u8],
    offset: usize,
    value: u64,
) -> Result<(), SelectableCatalogPlanError> {
    let field = bytes
        .get_mut(offset..offset.saturating_add(8))
        .ok_or(SelectableCatalogPlanError::LengthOverflow)?;
    field.copy_from_slice(&value.to_be_bytes());
    Ok(())
}

/// Invalid canonical selectable catalog launch plan.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SelectableCatalogPlanError {
    /// A nested standalone registration or request is invalid.
    #[error("selectable catalog plan contains an invalid standalone message: {0}")]
    Protocol(#[from] SelectableProtocolError),
    /// The body is too short for its header or declared entries.
    #[error("selectable catalog plan is truncated")]
    Truncated,
    /// The fixed plan magic differs.
    #[error("selectable catalog plan magic is invalid")]
    InvalidMagic,
    /// The schema version is unsupported.
    #[error("selectable catalog plan version {version} is unsupported")]
    UnsupportedVersion {
        /// Unsupported version.
        version: u32,
    },
    /// A version-1 continuation retained a request without its guest reply address.
    #[error("selectable catalog plan v1 pending request lacks a guest reply target")]
    LegacyPendingReplyTargetMissing,
    /// The fixed header length differs.
    #[error("selectable catalog plan header length {header_len} is invalid")]
    InvalidHeaderLength {
        /// Declared header bytes.
        header_len: usize,
    },
    /// The body length does not equal the declared total.
    #[error("selectable catalog plan length {actual} differs from declared {declared}")]
    InvalidTotalLength {
        /// Declared bytes.
        declared: usize,
        /// Actual bytes.
        actual: usize,
    },
    /// Unknown plan flags are set.
    #[error("selectable catalog plan flags {flags:#x} contain unknown bits")]
    UnknownFlags {
        /// Complete flags word.
        flags: u32,
    },
    /// A configured limit is zero or above its hard maximum.
    #[error("selectable catalog plan limit {field}={actual} is outside 1..={maximum}")]
    InvalidLimit {
        /// Limit field.
        field: &'static str,
        /// Actual value.
        actual: u64,
        /// Hard maximum.
        maximum: u64,
    },
    /// Per-selectable request limit exceeds the total limit.
    #[error(
        "selectable per-entry request limit {requests_per_selectable} exceeds total {total_requests}"
    )]
    PerSelectableLimitExceedsTotal {
        /// Per-entry ceiling.
        requests_per_selectable: u64,
        /// Total ceiling.
        total_requests: u64,
    },
    /// A collection count exceeds its bound.
    #[error("selectable catalog plan {field} count {actual} exceeds {maximum}")]
    CountTooLarge {
        /// Collection name.
        field: &'static str,
        /// Actual count.
        actual: usize,
        /// Maximum count.
        maximum: usize,
    },
    /// A canonical body exceeds its byte profile.
    #[error("selectable catalog plan has {bytes} bytes, maximum {maximum}")]
    PlanTooLarge {
        /// Actual bytes.
        bytes: usize,
        /// Maximum bytes.
        maximum: usize,
    },
    /// Expected declarations contain one ID twice.
    #[error("selectable catalog plan {field} contains duplicate `{identifier}`")]
    DuplicateIdentifier {
        /// Collection name.
        field: &'static str,
        /// Duplicate identifier.
        identifier: String,
    },
    /// A continuation identifier is not declared or registered as required.
    #[error("selectable catalog plan {field} names unknown `{identifier}`")]
    UnknownIdentifier {
        /// Collection name.
        field: &'static str,
        /// Unknown identifier.
        identifier: String,
    },
    /// A required declaration is missing from a frozen catalog.
    #[error("frozen selectable catalog is missing required `{identifier}`")]
    MissingRequiredDeclaration {
        /// Missing identifier.
        identifier: String,
    },
    /// A completed request counter exceeds a configured ceiling.
    #[error("selectable request count {field}={actual} exceeds {maximum}")]
    RequestLimitExceeded {
        /// Limit class.
        field: &'static str,
        /// Actual count.
        actual: u64,
        /// Configured maximum.
        maximum: u64,
    },
    /// Checked count addition overflowed.
    #[error("selectable catalog request counts overflow")]
    CountOverflow,
    /// Continuation state contradicts another retained field.
    #[error("selectable catalog continuation is invalid: {reason}")]
    InvalidContinuation {
        /// Stable invariant diagnostic.
        reason: &'static str,
    },
    /// An expected entry presence byte is outside the closed vocabulary.
    #[error("selectable catalog declaration presence {value} is invalid")]
    InvalidPresence {
        /// Invalid wire value.
        value: u8,
    },
    /// Reserved bytes are nonzero.
    #[error("selectable catalog plan has nonzero reserved bytes")]
    NonzeroReserved,
    /// A length-framed identifier is not UTF-8.
    #[error("selectable catalog plan {field} identifier is not UTF-8")]
    InvalidUtf8 {
        /// Identifier collection.
        field: &'static str,
    },
    /// A canonical identifier collection is duplicate or unsorted.
    #[error("selectable catalog plan {field} identifiers are not strictly increasing")]
    IdentifiersNotIncreasing {
        /// Identifier collection.
        field: &'static str,
    },
    /// A field whose presence flag is clear contains nonzero data.
    #[error("selectable catalog absent field {field} is nonzero")]
    NonzeroAbsentField {
        /// Field name.
        field: &'static str,
    },
    /// Checked byte-length arithmetic or conversion overflowed.
    #[error("selectable catalog plan length overflow")]
    LengthOverflow,
    /// Bytes remain after every declared collection.
    #[error("selectable catalog plan has {bytes} trailing bytes")]
    TrailingBytes {
        /// Trailing byte count.
        bytes: usize,
    },
    /// The decoded body has an alternative noncanonical representation.
    #[error("selectable catalog plan encoding is noncanonical")]
    NonCanonicalEncoding,
}

#[cfg(test)]
mod tests;
