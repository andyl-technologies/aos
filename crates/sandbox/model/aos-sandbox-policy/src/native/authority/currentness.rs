//! Retains a complete reached Authority currentness check across returned errors.
//!
//! Each entry pays its actual fixed capture and return carrier before creating
//! the destination. The same destination owns every native prefix before any
//! observation; failure moves that destination into the same resident owner before returning a marker.
//! Diagnostics only borrow it and never allocate, retry or repair a check.

use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;

use crate::native::PolicyNativeJournalErrorV1;
use crate::native::journal::RootPolicyJournalV1;

use super::error::RootAuthorityErrorV1;
use super::history::RootAuthorityHistoryOriginalV1;
use super::names::{RootAuthorityNameRecipeV1, RootAuthorityNamesOriginalV1};
use super::pins::RootAuthorityPinsOriginalV1;

struct RootAuthorityCurrentOriginalV1 {
    owner: RootAuthorityNamesOriginalV1,
    pins_owner: RootAuthorityNamesOriginalV1,
    pins: Option<Result<(), RootAuthorityErrorV1>>,
    issuers: aos_sandbox_broker::systemd_credentials::RootCurrentIssuerReadbackOriginalV1,
    physical: RootAuthorityNamesOriginalV1,
    names: Option<Result<(), RootAuthorityErrorV1>>,
    history: RootAuthorityHistoryOriginalV1,
    entered: bool,
}

// This actual resident destination exists before any observation. In
// particular, unwinding cannot destroy a callee-local failed native graph.
pub(super) struct RootAuthorityCurrentCustodyV1 {
    working: Mutex<Option<RootAuthorityCurrentOriginalV1>>,
    failed: OnceLock<RootAuthorityCurrentOriginalV1>,
    refused: AtomicBool,
}

impl RootAuthorityCurrentCustodyV1 {
    pub(super) fn new() -> Self {
        Self {
            working: Mutex::new(None),
            failed: OnceLock::new(),
            refused: AtomicBool::new(false),
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.failed.get().and_then(|original| original.failure())
    }
}

impl RootAuthorityCurrentOriginalV1 {
    fn new() -> Self {
        Self {
            owner: RootAuthorityNamesOriginalV1::new(),
            pins_owner: RootAuthorityNamesOriginalV1::new(),
            pins: None,
            issuers:
                aos_sandbox_broker::systemd_credentials::RootCurrentIssuerReadbackOriginalV1::new(),
            physical: RootAuthorityNamesOriginalV1::new(),
            names: None,
            history: RootAuthorityHistoryOriginalV1::new(),
            entered: false,
        }
    }

    fn fixed_demand_v1() -> Result<ResourceVector, RootAuthorityErrorV1> {
        let overflow = || PolicyNativeJournalErrorV1::geometry();
        let owner =
            RootAuthorityNamesOriginalV1::fixed_demand_v1(RootAuthorityNameRecipeV1::Owner)?;
        let physical =
            RootAuthorityNamesOriginalV1::fixed_demand_v1(RootAuthorityNameRecipeV1::Physical)?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<RootAuthorityCurrentFailureV1>().checked_mul(3)?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<Result<(), RootAuthorityErrorV1>>().checked_mul(3)?,
                )
            })
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(overflow)?;
        let issuers = aos_sandbox_broker::systemd_credentials::RootCurrentIssuerReadbackOriginalV1::observation_demand_v1()
            .ok_or_else(overflow)?;
        owner
            .checked_add(owner)
            .and_then(|demand| demand.checked_add(physical))
            .and_then(|demand| demand.checked_add(issuers))
            .and_then(|demand| demand.checked_add(ResourceVector::ZERO
                .with(D::MemoryBytes, bytes)
                // Owner, pin-owner and physical are distinct real originals.
                .with(D::MetadataEntries, crate::native::RootPolicyNameObservationOriginalV1::retained_control_cells_v1() * 3)))
            .map_err(|_| overflow().into())
    }

    fn observe_once(
        &mut self,
        journal: &RootPolicyJournalV1,
        pins: &RootAuthorityPinsOriginalV1,
        expected_names: ProtectedJournalNamesV1,
    ) -> Result<(), ()> {
        if self.entered {
            return Err(());
        }
        self.entered = true;

        // The two owner checks are distinct original frontiers. The old pins
        // recheck repeated the fixed-owner check before inspecting credentials.
        self.owner
            .observe_once(journal, RootAuthorityNameRecipeV1::Owner)?;
        self.owner.settle_positive_once_v1();
        self.pins_owner
            .observe_once(journal, RootAuthorityNameRecipeV1::Owner)?;
        self.pins_owner.settle_positive_once_v1();
        self.pins = Some(pins.recheck(journal, &mut self.issuers));
        if !matches!(self.pins, Some(Ok(()))) {
            return Err(());
        }
        self.physical
            .observe_once(journal, RootAuthorityNameRecipeV1::Physical)?;
        self.physical.settle_positive_once_v1();
        self.names = Some(if self.physical.names() == Some(expected_names) {
            Ok(())
        } else {
            Err(RootAuthorityErrorV1::Stale)
        });
        if !matches!(self.names, Some(Ok(()))) {
            return Err(());
        }
        self.history.observe_once(journal, pins)
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.owner
            .failure()
            .or_else(|| self.pins_owner.failure())
            .or_else(|| self.issuers.failure().map(|cause| cause as _))
            .or_else(|| {
                self.pins
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| self.physical.failure())
            .or_else(|| {
                self.names
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| self.history.failure())
    }
}

/// Marks a failed native currentness operation whose actual graph stays resident.
///
/// The same [`super::RootAuthorityOriginalV1`] retains every reached native
/// prefix and first error. Callers borrow `retained_failure` there before later
/// posts; this marker neither detaches the failure graph nor permits retry.
#[derive(Debug)]
pub struct RootAuthorityCurrentFailureV1;

impl fmt::Display for RootAuthorityCurrentFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the original Root Authority retains a failed currentness check")
    }
}

impl Error for RootAuthorityCurrentFailureV1 {}

pub(super) fn require_current_v1(
    journal: &RootPolicyJournalV1,
    pins: &RootAuthorityPinsOriginalV1,
    expected_names: ProtectedJournalNamesV1,
    custody: &RootAuthorityCurrentCustodyV1,
) -> Result<(), RootAuthorityErrorV1> {
    if custody.refused.load(Ordering::Acquire) || custody.failed.get().is_some() {
        return Err(RootAuthorityErrorV1::Stale);
    }
    let mut working = match custody.working.try_lock() {
        Ok(working) if working.is_none() => working,
        _ => {
            custody.refused.store(true, Ordering::Release);
            return Err(RootAuthorityErrorV1::Stale);
        }
    };
    let demand = match RootAuthorityCurrentOriginalV1::fixed_demand_v1() {
        Ok(demand) => demand,
        Err(cause) => {
            custody.refused.store(true, Ordering::Release);
            return Err(cause);
        }
    };
    // This actual branch admission returns all L/U/financial guards before the
    // destination construction and the first native observation. Each native
    // sampler independently retains its actual invocation N fence over IO.
    if let Err(cause) = journal.admit_role_observation_v1(demand) {
        custody.refused.store(true, Ordering::Release);
        return Err(cause.into());
    }
    *working = Some(RootAuthorityCurrentOriginalV1::new());
    let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        working
            .as_mut()
            .ok_or(())?
            .observe_once(journal, pins, expected_names)
    }));
    match observed {
        Ok(result) => {
            let Some(original) = working.take() else {
                custody.refused.store(true, Ordering::Release);
                return Err(RootAuthorityErrorV1::Stale);
            };
            drop(working);
            if result.is_err() {
                custody.refused.store(true, Ordering::Release);
                if let Err(_still_owned) = custody.failed.set(original) {
                    std::process::abort();
                }
                return Err(RootAuthorityCurrentFailureV1.into());
            }
            // All reached subobservations completed positively. Destroy only
            // their temporary backing; no ledger debit is reset or refunded.
            drop(original);
            Ok(())
        }
        Err(payload) => {
            custody.refused.store(true, Ordering::Release);
            if let Some(original) = working.take() {
                if let Err(_still_owned) = custody.failed.set(original) {
                    // No failed prefix may be destroyed on an impossible
                    // second transfer. Abort while both graphs remain held.
                    std::process::abort();
                }
            }
            drop(working);
            std::panic::resume_unwind(payload)
        }
    }
}
