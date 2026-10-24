//! Retains fixed Policy name observations in their genuine current owner.
//!
//! The shared native Owner recipe performs the original binding, directory,
//! health and names sequence. Each failed prefix remains resident; positive
//! temporary probes retire before returning to the original caller frontier.

use crate::native::{
    PolicyNativeJournalErrorV1 as ErrorV1, RootPolicyNameObservationOriginalV1 as Names,
    journal::{
        RootPolicyJournalV1,
        names::{RootFixedNameRecipeV1, RootFixedNameRoleV1},
    },
};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use std::{
    error::Error,
    fmt,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

pub(super) struct PolicyTargetCurrentCustodyV1 {
    working: Mutex<Option<Names>>,
    failed: OnceLock<Names>,
    refused: AtomicBool,
}

impl PolicyTargetCurrentCustodyV1 {
    pub(super) fn new() -> Self {
        Self {
            working: Mutex::new(None),
            failed: OnceLock::new(),
            refused: AtomicBool::new(false),
        }
    }

    pub(super) fn constructor_demand_v1() -> Result<ResourceVector, ErrorV1> {
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(ErrorV1::geometry)?;
        // These are the three actual retained cells, independent of layout.
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, bytes)
            .with(D::MetadataEntries, 3))
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.failed.get().and_then(Names::failure)
    }
}

impl Drop for PolicyTargetCurrentCustodyV1 {
    fn drop(&mut self) {
        // Preserve the old native original's failed-prefix disposal rule.
        // No entered failed/partial graph may disappear through target Drop.
        if self.failed.get().is_some()
            || match self.working.get_mut() {
                Ok(working) => working.is_some(),
                Err(_) => true,
            }
        {
            std::process::abort();
        }
    }
}

/// Marks a refusal whose actual native graph remains in the same target owner.
///
/// The observing current or owed-post destination supplies the corresponding
/// borrowed cause. This marker does not retry, transfer or adopt native state.
#[derive(Debug)]
pub struct PolicyTargetCurrentFailureV1;

impl fmt::Display for PolicyTargetCurrentFailureV1 {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str("the Policy target retains a failed original name check")
    }
}

impl Error for PolicyTargetCurrentFailureV1 {}

fn observation_demand_v1() -> Result<ResourceVector, ErrorV1> {
    let carriers = Names::fixed_carrier_demand_v1().ok_or_else(ErrorV1::geometry)?;
    let native =
        Names::additional_demand_v1(RootFixedNameRoleV1::Policy, RootFixedNameRecipeV1::Owner)?;
    let bytes = std::mem::size_of::<Result<(), ErrorV1>>()
        .checked_mul(3)
        .and_then(|bytes| {
            bytes
                .checked_add(std::mem::size_of::<Result<ResourceVector, ErrorV1>>().checked_mul(3)?)
        })
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ResourceVector>().checked_mul(3)?))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(ErrorV1::geometry)?;
    carriers
        .checked_add(native)
        .and_then(|demand| {
            demand.checked_add(
                ResourceVector::ZERO
                    .with(D::MemoryBytes, bytes)
                    .with(D::MetadataEntries, Names::retained_control_cells_v1()),
            )
        })
        .map_err(|_| ErrorV1::geometry())
}

pub(super) fn require_current_names_v1(
    journal: &RootPolicyJournalV1,
    custody: &PolicyTargetCurrentCustodyV1,
) -> Result<(), ErrorV1> {
    if custody.refused.load(Ordering::Acquire) || custody.failed.get().is_some() {
        return Err(ErrorV1::boundary());
    }
    let mut working = match custody.working.try_lock() {
        Ok(working) if working.is_none() => working,
        _ => {
            custody.refused.store(true, Ordering::Release);
            return Err(ErrorV1::boundary());
        }
    };
    let demand = observation_demand_v1()?;
    journal.admit_role_observation_v1(demand)?;
    *working = Some(Names::new());
    let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        working.as_mut().ok_or(())?.observe_once(
            journal,
            RootFixedNameRoleV1::Policy,
            RootFixedNameRecipeV1::Owner,
        )
    }));
    match observed {
        Ok(Ok(())) => {
            if let Some(original) = working.as_mut() {
                original.settle_positive_once_v1();
            }
            drop(working.take());
            Ok(())
        }
        outcome => {
            custody.refused.store(true, Ordering::Release);
            if let Some(original) = working.take() {
                if let Err(_still_owned) = custody.failed.set(original) {
                    std::process::abort();
                }
            }
            drop(working);
            match outcome {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(Err(())) => Err(ErrorV1::TargetCurrent(PolicyTargetCurrentFailureV1)),
                Ok(Ok(())) => Err(ErrorV1::boundary()),
            }
        }
    }
}
