//! Owns the installed Publisher observer's finite recurring C operation.
//!
//! The actual Native registration owner keeps environment, asynchronous jobs,
//! native samples and typed output. This receiver retains the same original
//! claim and complete operation arithmetic without exporting a capacity pair,
//! account, callback, service constructor or completion flag.

use std::error::Error;
use std::sync::Arc;

use aos_sandbox_core::ResourceVector;

use crate::receiving::ComponentReceivingOwnedOperationV1;
use super::profile::ControllerSelfProfileOriginalV1;
use super::publisher_schedule::{ControllerPublisherStartupDataV1, operation_demand};
use super::shapes::ControllerRuntimeRequestedCountsV1;
use super::{ControllerReceivingErrorV1, ControllerReceivingOriginalV1};

/// Retains finite operation stages for the actual installed Publisher observer.
///
/// Only the trusted Native bank constructs its real registration receiver.
/// This mechanical owner cannot construct a registration or native service;
/// its disposal continuation advances no product or startup authority.
#[must_use = "retain the same operation with its actual native observer"]
pub struct ControllerPublisherOperationReceivingV1 {
    original: Arc<ControllerReceivingOriginalV1>,
    preparation: Option<Result<(), ControllerReceivingErrorV1>>,
    begin: Option<Result<ResourceVector, ControllerReceivingErrorV1>>,
    required: Option<Result<ResourceVector, ControllerReceivingErrorV1>>,
    operation: Option<ComponentReceivingOwnedOperationV1>,
    consumption: Option<Result<(), crate::receiving::ComponentReceivingOperationClosedV1>>,
    finish: Option<Result<(), ControllerReceivingErrorV1>>,
    disposed: bool,
    fenced: bool,
}

impl ControllerPublisherOperationReceivingV1 {
    /// Creates inert destinations bound to the actual original C.
    #[doc(hidden)]
    #[must_use]
    pub fn new(original: Arc<ControllerReceivingOriginalV1>) -> Self {
        Self {
            original,
            preparation: None,
            begin: None,
            required: None,
            operation: None,
            consumption: None,
            finish: None,
            disposed: false,
            fenced: false,
        }
    }

    /// Projects the sole existing operation supplier as readonly count DATA.
    ///
    /// # Errors
    /// Retains incomplete or overflowing concrete representation refusal.
    #[doc(hidden)]
    pub fn requested_counts_v1()
        -> Result<ControllerRuntimeRequestedCountsV1, ControllerReceivingErrorV1>
    {
        operation_demand().map(ControllerRuntimeRequestedCountsV1::from_demand)
    }

    /// Claims the existing fixed reservation against the same genuine profile.
    ///
    /// # Errors
    /// Refuses foreign C/profile, repeated, closed or unfunded startup state.
    #[doc(hidden)]
    pub fn prepare_once(
        &mut self,
        profile: &ControllerSelfProfileOriginalV1,
        startup: ControllerPublisherStartupDataV1,
    ) -> Result<(), ControllerReceivingErrorV1> {
        if self.preparation.is_some() || self.fenced {
            self.fence();
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        self.preparation = Some(self.original.claim_publisher_receiving(profile, startup));
        if matches!(self.preparation, Some(Ok(()))) {
            Ok(())
        } else {
            self.fence();
            Err(ControllerReceivingErrorV1::Conflict)
        }
    }

    /// Reports whether the actual prior flight permits another native attempt.
    #[must_use]
    pub fn can_begin_v1(&self) -> bool {
        !self.fenced && matches!(self.preparation, Some(Ok(())))
            && (self.begin.is_none() || self.completed_positive_v1())
    }

    /// Enters one original operation before the actual future or environment IO.
    ///
    /// # Errors
    /// Retains overlapping, closed, unfunded or overflowing original refusal.
    #[doc(hidden)]
    pub fn begin_operation_once(&mut self) -> Result<(), ControllerReceivingErrorV1> {
        if !self.can_begin_v1() {
            self.fence();
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        // Only a fully disposed prior positive flight can release its compact
        // arithmetic records. Permanent original funding remains charged.
        self.disposed = false;
        self.finish = None;
        self.consumption = None;
        self.required = None;
        self.operation = None;
        self.begin = Some(self.original.begin_publisher_operation());
        let Some(Ok(capacity)) = self.begin.as_ref() else {
            self.fence();
            return Err(ControllerReceivingErrorV1::Conflict);
        };
        self.required = Some(operation_demand());
        let Some(Ok(required)) = self.required.as_ref() else {
            self.fence();
            return Err(ControllerReceivingErrorV1::Conflict);
        };
        self.operation = Some(ComponentReceivingOwnedOperationV1::preflight(*capacity, *required));
        Ok(())
    }

    /// Consumes the complete finite operation before any profile or service RPC.
    ///
    /// # Errors
    /// Retains repeated consumption or the actual complete-vector refusal.
    #[doc(hidden)]
    pub fn consume_native_once(&mut self) -> Result<(), ControllerReceivingErrorV1> {
        if self.fenced || self.consumption.is_some() || self.disposed {
            self.fence();
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        let Some(operation) = self.operation.as_mut() else {
            self.fence();
            return Err(ControllerReceivingErrorV1::Conflict);
        };
        self.consumption = Some(operation.consume_once());
        if matches!(self.consumption, Some(Ok(()))) {
            Ok(())
        } else {
            self.fence();
            Err(ControllerReceivingErrorV1::Conflict)
        }
    }

    /// Compares the returned actual recipient to this same original state.
    ///
    /// This readonly comparison creates no flight or permission to do IO.
    ///
    /// # Errors
    /// Refuses a recipient different from the actual original Runtime record.
    #[doc(hidden)]
    pub fn require_recipient_v1(
        &self,
        recipient: [u8; 16],
        producer: [u8; 16],
    ) -> Result<(), ControllerReceivingErrorV1> {
        self.original.require_runtime_recipient(recipient, producer)
    }

    /// Completes the finite operation at the trusted Native disposal frontier.
    ///
    /// Native calls this only after its actual output is resident, all profile,
    /// environment and native posts pass, and its same native sample is dropped.
    /// No caller bool, result, output adoption, callback or capacity is accepted.
    /// The original bank still independently owns the registration receiver.
    ///
    /// # Errors
    /// Retains incomplete consumption, repeated disposal or original refusal.
    #[doc(hidden)]
    pub fn complete_after_sample_disposal_once(&mut self)
        -> Result<(), ControllerReceivingErrorV1>
    {
        if self.fenced || self.disposed
            || !matches!(self.consumption, Some(Ok(())))
            || !self.operation.as_ref().is_some_and(
                ComponentReceivingOwnedOperationV1::is_consumed_current,
            )
        {
            self.fence();
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        let Some(operation) = self.operation.take() else {
            self.fence();
            return Err(ControllerReceivingErrorV1::Conflict);
        };
        operation.complete_after_disposal();
        self.finish = Some(self.original.finish_publisher_operation());
        if !matches!(self.finish, Some(Ok(()))) {
            self.fence();
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        self.disposed = true;
        Ok(())
    }

    /// Reports actual same-flight positive disposition as comparison DATA.
    #[must_use]
    pub fn completed_positive_v1(&self) -> bool {
        !self.fenced && self.disposed && matches!(self.finish, Some(Ok(())))
    }

    /// Permanently closes the same original after an actual observer refusal.
    #[doc(hidden)]
    pub fn fence(&mut self) {
        self.fenced = true;
        self.original.close_publisher_receiving();
    }

    /// Borrows the actual initial claim refusal.
    #[must_use]
    pub fn preparation_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.preparation)
    }

    /// Borrows the actual next-operation or supplier refusal.
    #[must_use]
    pub fn begin_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.begin).or_else(|| error(&self.required))
    }

    /// Borrows the whole preflight or consumption refusal.
    #[must_use]
    pub fn consumption_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.operation.as_ref()
            .and_then(ComponentReceivingOwnedOperationV1::failure)
            .map(|cause| cause as _)
            .or_else(|| error(&self.consumption))
    }

    /// Borrows the same original's final operation refusal.
    #[must_use]
    pub fn finish_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.finish)
    }
}

fn error<T, E: Error + 'static>(slot: &Option<Result<T, E>>)
    -> Option<&(dyn Error + 'static)>
{
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
}
