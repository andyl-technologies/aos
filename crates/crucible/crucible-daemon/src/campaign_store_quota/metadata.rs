//! Metadata admission and physical cache reclamation for the quota service.
//!
//! Every allocation borrows the same retained service accounts. Caller checks
//! run outside admission/cache locks. Reclamation closes actual cache bodies
//! before the final paired grant. Credits preserve body-before-refund custody and do
//! not retain a service alias or supply another operation clock.

use std::time::Duration;

use crucible_host_resources::host_services::HostServiceLease;
use crucible_host_resources::host_supervision::{HostOperationClass, HostOperationGuard};

use super::{
    ProviderCause, QuotaDescriptorCredit, QuotaMetadataCredit, QuotaService, StoreError,
    store_error, supervision_error,
};

impl QuotaService {
    pub(super) fn reserve_descriptor_metadata(
        &self,
        descriptors: u64,
        bytes: u64,
    ) -> Result<QuotaDescriptorCredit, StoreError> {
        // Pay the descriptor control before creating it. The returned field
        // order keeps that payment through all subsequent binding failures.
        let metadata = self.reserve_metadata(
            bytes
                .checked_add(HostServiceLease::metadata_bytes())
                .ok_or(StoreError::Quota)?,
        )?;
        let descriptors = self
            .resources
            .reserve_resources(0, descriptors, 0)
            .map_err(supervision_error)?;
        Ok(QuotaDescriptorCredit {
            descriptors,
            metadata,
        })
    }

    pub(super) fn reserve_metadata(&self, bytes: u64) -> Result<QuotaMetadataCredit, StoreError> {
        self.reserve_metadata_checked(bytes, None)
    }

    pub(super) fn reserve_metadata_checked(
        &self,
        bytes: u64,
        mut caller: Option<&mut dyn FnMut() -> Result<(), StoreError>>,
    ) -> Result<QuotaMetadataCredit, StoreError> {
        if let Some(check) = caller.as_mut() {
            check()?;
        }
        let operation = self
            .supervisor
            .begin(HostOperationClass::Preparation)
            .map_err(supervision_error)?;
        let charged = bytes
            .checked_add(2 * HostServiceLease::metadata_bytes())
            .ok_or(StoreError::Quota)?;
        let mut caller_failure = None;
        let mut check = || {
            if let Some(check) = caller.as_mut() {
                if let Err(first) = check() {
                    caller_failure = Some(first);
                    return Err(
                        crucible_host_resources::host_services::HostServiceError::Unavailable
                            .into(),
                    );
                }
            }
            Ok(())
        };
        let reservation = self.reserve_precharged_metadata(charged, &operation, &mut check);
        drop(check);
        if let Some(first) = caller_failure {
            return Err(first);
        }
        let credit = reservation.map_err(|cause| match cause {
            ProviderCause::Resources(error) => supervision_error(error),
            ProviderCause::Supervision(error) => supervision_error(error),
            ProviderCause::PhysicalQuota(error) => store_error(error),
        })?;
        // The admission latch has closed before arbitrary caller checks. An
        // expired caller closes this real credit rather than starting its next
        // reservation or publishing a row under service-only Preparation.
        let caller_post = match caller.as_mut() {
            Some(check) => check(),
            None => Ok(()),
        };
        let service_post = credit.complete(&operation);
        caller_post?;
        service_post
    }

    pub(super) fn reserve_precharged_metadata(
        &self,
        charged: u64,
        operation: &HostOperationGuard,
        caller: &mut dyn FnMut() -> Result<(), ProviderCause>,
    ) -> Result<QuotaMetadataCredit, ProviderCause> {
        use crucible_host_resources::host_services::HostServiceError;
        use std::sync::TryLockError;

        loop {
            operation.wait_slice()?;
            caller()?;
            // No user boundary runs under either shared mutex. Only actual
            // bookkeeping/physical cache destruction occurs during admission.
            let admission = match self.metadata_admission.try_lock() {
                Ok(admission) => admission,
                Err(TryLockError::WouldBlock) => {
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Err(TryLockError::Poisoned(_)) => return Err(HostServiceError::Unavailable.into()),
            };
            let mut contended = false;
            let reservation = self.metadata.reserve_paired_bytes_reclaiming(
                &self.resources,
                charged,
                |required| match self
                    .packed_metadata
                    .reclaim(required)
                    .map_err(|_| HostServiceError::Unavailable)?
                {
                    Some(freed) => Ok(freed),
                    None => {
                        contended = true;
                        Err(HostServiceError::Unavailable)
                    }
                },
            );
            drop(admission);
            if contended {
                // This is cache-lock contention before any real pair grant,
                // never a swallowed quota refusal or a disabled-cache fallback.
                std::thread::sleep(Duration::from_millis(1));
                continue;
            }
            let (metadata, resident) = reservation?;
            return Ok(QuotaMetadataCredit::new(resident, metadata));
        }
    }
}
