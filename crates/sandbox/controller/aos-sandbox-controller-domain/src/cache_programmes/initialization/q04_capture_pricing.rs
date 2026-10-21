//! Keeps the actual Q intake above Cache-native shape and held-cut custody.
//!
//! The native borrower owns every same-writer shape result. This upper wrapper
//! stores the real Controller reservation check at its original frontier and
//! consumes the same native borrower only after that genuine intake succeeds.

use super::original_q04::{OriginalQ04CacheOwnerCutV1, Q04UpperProgressV1};
use super::*;

pub(crate) type OriginalQ04CacheCaptureShapeV1 = aos_sandbox_cache::OriginalQ04CacheCaptureShapeV1;

/// Holds the same native Cache capture and upper Controller intake destination.
pub(crate) struct OriginalQ04CachePreflightLoanV1<'cache> {
    native: aos_sandbox_cache::OriginalQ04CachePreflightLoanV1<'cache>,
    upper: &'cache mut Q04UpperProgressV1,
}

impl<'cache> OriginalQ04CachePreflightLoanV1<'cache> {
    pub(crate) fn park(
        initialization: &'cache mut CacheResidentInitializationV1,
        owner: &'cache mut aos_sandbox_cache::CacheResidencyProtectedOwnerV1,
        physical: &'cache aos_sandbox_cache::DormantCacheOwnerV1,
    ) -> Self {
        Self {
            native: aos_sandbox_cache::OriginalQ04CachePreflightLoanV1::park(
                &mut initialization.native,
                owner,
                physical,
            ),
            upper: &mut initialization.q04,
        }
    }

    pub(crate) fn capture_shape(
        &mut self,
    ) -> Result<&OriginalQ04CacheCaptureShapeV1, aos_sandbox_cache::CacheResidentUnavailableV1>
    {
        if self.upper.paid_intake.is_some() || self.upper.source.is_some() {
            return Err(aos_sandbox_cache::CacheResidentUnavailableV1);
        }
        match self.native.capture_shape() {
            Ok(shape) => Ok(shape),
            Err(cause) => {
                self.upper.select_native();
                Err(cause)
            }
        }
    }

    pub(crate) fn fixed_capture_memory_bytes(
        &self,
    ) -> Result<usize, aos_sandbox_cache::CacheResidentUnavailableV1> {
        let upper = std::mem::size_of::<(
            Self,
            OriginalQ04CacheOwnerCutV1<'_>,
            Q04UpperProgressV1,
            Option<Result<(), crate::controller_resource_reservation::ResourceReservationErrorV1>>,
            super::original_q04::OriginalQ04CacheClearanceLoanV1<'_, '_, '_, '_, '_>,
            aos_sandbox_cache::CacheQ04ErrorV1,
            Result<
                aos_sandbox_protocol::cache_owner_readback::CacheOwnerReadbackChallengeV1,
                crate::policy_compiler::create_q04::CreateQ04ErrorV1,
            >,
        )>()
        .checked_mul(2)
        .ok_or(aos_sandbox_cache::CacheResidentUnavailableV1)?;
        let returns = std::mem::size_of::<Self>()
            .checked_add(std::mem::size_of::<
                Result<
                    OriginalQ04CacheOwnerCutV1<'_>,
                    aos_sandbox_cache::CacheResidentUnavailableV1,
                >,
            >())
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<
                    Result<
                        super::original_q04::OriginalQ04CacheClearanceLoanV1<'_, '_, '_, '_, '_>,
                        (),
                    >,
                >())
            })
            .ok_or(aos_sandbox_cache::CacheResidentUnavailableV1)?;
        self.native
            .fixed_capture_memory_bytes()?
            .checked_add(upper)
            .and_then(|bytes| bytes.checked_add(returns))
            .and_then(|bytes| bytes.checked_add(super::original_q04::terminal_provider_control_receiving_bytes_v1()?))
            .and_then(|bytes| bytes.checked_add(super::original_q04::append_driver_control_receiving_bytes_v1()?))
            .ok_or(aos_sandbox_cache::CacheResidentUnavailableV1)
    }

    pub(crate) fn require_shape(
        &mut self,
    ) -> Result<(), aos_sandbox_cache::CacheResidentUnavailableV1> {
        let returned = self.native.require_shape();
        if returned.is_err() {
            self.upper.select_native();
        }
        returned
    }

    pub(crate) fn begin(
        self,
        paid: &crate::ProjectPreparationReservationAttemptV1,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<OriginalQ04CacheOwnerCutV1<'cache>, aos_sandbox_cache::CacheResidentUnavailableV1>
    {
        if self.upper.paid_intake.is_some() || self.upper.source.is_some() {
            return Err(aos_sandbox_cache::CacheResidentUnavailableV1);
        }
        self.native.require_prepared_native_capture_v1()?;
        self.upper.paid_intake = Some(paid.require_original_intake(profile));
        if self.upper.paid_intake.as_ref().is_none_or(Result::is_err) {
            self.upper.select_upper();
            return Err(aos_sandbox_cache::CacheResidentUnavailableV1);
        }
        let native = match self.native.begin_native_after_intake_v1() {
            Ok(native) => native,
            Err(cause) => {
                self.upper.select_native();
                return Err(cause);
            }
        };
        self.upper.entered = true;
        Ok(OriginalQ04CacheOwnerCutV1 {
            native,
            upper: self.upper,
        })
    }
}
