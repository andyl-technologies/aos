//! Genuine companion shutdown followed by owned provider-group reclamation.

use crucible_node_contract::*;
use crucible_node_provider::{
    ProviderError,
    bodies::*,
    envelope::{Method, Nullable},
    reference_device::DeviceStatus,
};

use super::control::{CnpControlledReference, original_id};

impl CnpControlledReference {
    pub(super) fn quarantine_public(&mut self) -> Result<bool, ProviderError> {
        if self.status == DeviceStatus::Reaped {
            return Ok(true);
        }
        if self.status != DeviceStatus::Quarantined {
            let graceful = self.close_native_application();
            self.status = DeviceStatus::Quarantined;
            // A failed public cleanup is not reaping evidence. The actual
            // original group remains owned by the reserved supervisor slot.
            if graceful.is_err() {
                self.controller_mut()?.fence();
            }
        }
        let custody = self
            .guard
            .custody
            .as_mut()
            .ok_or(ProviderError::Correlation(
                "original public process unavailable",
            ))?;
        if custody.poll_reclamation()? {
            self.status = DeviceStatus::Reaped;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn close_native_application(&mut self) -> Result<(), ProviderError> {
        let bootstrap = self.controller()?.bootstrap.clone();
        if self.active.is_none() {
            let request_id = original_id("abort", &bootstrap.transaction_id)?;
            let response = self.controller_mut()?.call(
                request_id.clone(),
                None,
                Method::Abort,
                false,
                AbortRequest {
                    transaction_id: bootstrap.transaction_id.clone(),
                    reason: Id::new("host-native-shutdown")?,
                    extensions: Extensions::new(),
                },
            )?;
            let Some(MethodResult::Abort(result)) = response.result else {
                return Err(ProviderError::Correlation(
                    "original abort cleanup unresolved",
                ));
            };
            self.verify_cleanup(&result.cleanup_receipt, &request_id, None)?;
        } else {
            if self.windows.values().any(|window| !window.consumed) {
                return Err(ProviderError::Correlation(
                    "public native output obligations remain unresolved",
                ));
            }
            let operation = original_id("shutdown-operation", &bootstrap.authority.realization_id)?;
            let request_id = original_id("shutdown", &bootstrap.authority.realization_id)?;
            let arguments = serde_json::to_value(ShutdownArguments {
                participant_ids: self.controller()?.profile.owner.participant_ids.clone(),
                reason: Id::new("host-native-shutdown")?,
            })
            .map_err(ContractError::from)?
            .as_object()
            .cloned()
            .ok_or(ProviderError::Frame("shutdown arguments are not an object"))?;
            let binding_hash = self.owner_binding.identity()?;
            let response = self.controller_mut()?.call(
                request_id.clone(),
                Some(operation.clone()),
                Method::Begin,
                true,
                BeginRequest {
                    kind: BeginKind::Shutdown,
                    binding_hash,
                    owner_generation: bootstrap.authority.owner_generation,
                    activation_id: Nullable(Some(bootstrap.activation_id)),
                    world_generation: bootstrap.world_generation,
                    arguments,
                    extensions: Extensions::new(),
                },
            )?;
            let Some(MethodResult::Shutdown(result)) = response.result else {
                return Err(ProviderError::Correlation(
                    "original shutdown cleanup unresolved",
                ));
            };
            if !result.stopped || !result.reaped {
                return Err(ProviderError::Correlation(
                    "public native child shutdown unresolved",
                ));
            }
            self.verify_cleanup(&result.cleanup_receipt, &request_id, Some(&operation))?;
        }
        // Positive provider claims do not discharge native process custody.
        // Observe actual companion absence before retaining a released endpoint.
        match std::fs::metadata(format!("/proc/{}", self.companion_pid)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => {
                return Err(ProviderError::Correlation(
                    "native companion remains present after cleanup",
                ));
            }
        }
        let request_id = original_id("release", &bootstrap.authority.realization_id)?;
        let response = self.controller_mut()?.call(
            request_id.clone(),
            None,
            Method::Release,
            false,
            ReleaseRequest {
                realization_id: bootstrap.authority.realization_id,
                extensions: Extensions::new(),
            },
        )?;
        let Some(MethodResult::Release(result)) = response.result else {
            return Err(ProviderError::Correlation(
                "public original release unresolved",
            ));
        };
        if !result.released
            || result.realization_id != self.controller()?.bootstrap.authority.realization_id
            || result.owner_ids != [self.controller()?.bootstrap.owner_id.clone()]
        {
            return Err(ProviderError::Correlation(
                "public release retained obligations or changed original owner",
            ));
        }
        self.verify_cleanup(&result.cleanup_receipt, &request_id, None)
    }

    fn verify_cleanup(
        &self,
        reference: &ContentRef,
        request: &Id,
        operation: Option<&Id>,
    ) -> Result<(), ProviderError> {
        let controller = self.controller()?;
        let receipt: ControlReceipt = controller.record(reference)?;
        let record: CleanupRecord = controller.record(&receipt.record_ref)?;
        let bootstrap = &controller.bootstrap;
        if receipt.kind != ControlReceiptKind::Cleanup
            || receipt.issuer != ReceiptIssuer::Provider
            || receipt.session_id != bootstrap.authority.session_id
            || receipt.incarnation_id != bootstrap.authority.incarnation_id
            || receipt.request_id != *request
            || receipt.operation_id.as_ref() != operation
            || receipt.owner_ids != [bootstrap.owner_id.clone()]
            || !receipt.extensions.is_empty()
            || record.owner_ids != [bootstrap.owner_id.clone()]
            || record.disposition != CleanupDisposition::Retained
            || record.supervisor_receipt.is_some()
            || !record.extensions.is_empty()
        {
            return Err(ProviderError::Correlation(
                "public cleanup changed original scope or unresolved native effects",
            ));
        }
        Ok(())
    }
}
