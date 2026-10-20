//! Preserves original public/native cleanup and private operational history.

mod history;

use crucible_node_format::{Bytes, canonical};
use crucible_node_transport::{ProviderError, reference_device::DeviceStatus};
use history::{Activation, Buffer, ByteCredit, CanonicalCounter, Counter, Sequence};

use crate::{node_contract::OperationFailure, node_scheduling::InputPayload};

use super::{
    control::CnpControlledReference,
    readiness::{refused, unknown},
};

impl CnpControlledReference {
    pub(super) fn original_graceful_retirement_available(&self) -> bool {
        self.control_process == std::process::id()
            && self.control_thread == std::thread::current().id()
            && self.status == DeviceStatus::Parked
            && self.guard.custody.is_some()
            && self.active.is_some()
            && self.input.is_none()
            && self.pending.is_none()
            && self
                .prepared
                .as_ref()
                .is_some_and(|prepared| prepared.registry_complete)
            && self.windows.values().all(|window| {
                window.closed
                    && window.consumed
                    && window.receipt.is_some()
                    && window.result.is_some()
                    && window.observations.is_some()
            })
    }

    pub(super) fn shutdown_original_retirement(&mut self) -> Result<(), OperationFailure> {
        self.require_retirement_owner().map_err(unknown)?;
        if self.semantic_release
            && matches!(
                self.status,
                DeviceStatus::Quarantined | DeviceStatus::Reaped
            )
        {
            return Ok(());
        }
        if !self.original_graceful_retirement_available() {
            return Err(refused("original public graceful cleanup is unavailable"));
        }
        self.verify_native_custody().map_err(unknown)?;
        // The first source-owned shutdown attempt is never renewed. Failed
        // cleanup retains its original journal and cannot enter signal fallback.
        self.status = DeviceStatus::Quarantined;
        match self.close_native_application() {
            Ok(()) => {
                self.semantic_release = true;
                Ok(())
            }
            Err(error) => {
                if let Ok(controller) = self.controller_mut() {
                    controller.fence();
                }
                Err(unknown(error))
            }
        }
    }

    pub(super) fn poll_original_retirement(&mut self) -> Result<bool, ProviderError> {
        self.require_retirement_owner()?;
        if !self.semantic_release
            || !matches!(
                self.status,
                DeviceStatus::Quarantined | DeviceStatus::Reaped
            )
        {
            return Err(ProviderError::Correlation(
                "original Shutdown remains unresolved",
            ));
        }
        if self.status == DeviceStatus::Reaped {
            return Ok(true);
        }
        let original = self
            .guard
            .custody
            .as_mut()
            .ok_or(ProviderError::Correlation(
                "original graceful native custody is absent",
            ))?;
        if original.poll_reclamation()? {
            self.status = DeviceStatus::Reaped;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub(super) fn transfer_original_retirement(&mut self) -> Result<(), OperationFailure> {
        self.require_retirement_owner().map_err(unknown)?;
        if !self.semantic_release || self.status != DeviceStatus::Reaped {
            return Err(refused(
                "original public semantic or native cleanup is incomplete",
            ));
        }
        if self.guard.custody.is_none() {
            return self
                .retired_history
                .as_ref()
                .map(|_| ())
                .ok_or_else(|| refused("original retirement history was not retained"));
        }
        if self.retired_history.is_none() {
            self.retired_history = Some(self.original_retirement_history(64 * 1024 * 1024)?);
        }
        self.retain_runtime_originals();
        self.guard.transfer_reclaimed_original().map_err(unknown)
    }

    pub(super) fn original_retirement_history(
        &self,
        maximum_bytes: usize,
    ) -> Result<InputPayload, OperationFailure> {
        self.require_retirement_owner().map_err(unknown)?;
        if maximum_bytes == 0 || maximum_bytes > 64 * 1024 * 1024 {
            return Err(refused("original public history geometry is invalid"));
        }
        if let Some(original) = &self.retired_history {
            if original.bytes.len() > maximum_bytes {
                return Err(refused(
                    "original transferred history exceeds selected credit",
                ));
            }
            let mut credit = Counter::new(maximum_bytes);
            serde_json::to_writer(&mut credit, &original.reference).map_err(|error| {
                unknown(crucible_node_format::ContractError::from(error).into())
            })?;
            std::io::Write::write_all(&mut credit, &original.bytes)
                .map_err(|error| unknown(error.into()))?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(original.bytes.len())
                .map_err(|_| refused("original cached history allocation is unavailable"))?;
            bytes.extend_from_slice(&original.bytes);
            return Ok(InputPayload {
                reference: original.reference.clone(),
                bytes,
            });
        }
        if self.input.is_some() || self.pending.is_some() {
            return Err(refused(
                "original input or operation must remain with its owning controller",
            ));
        }
        let controller_credit = self
            .controller()
            .map_err(unknown)?
            .private_original_history_credit(maximum_bytes)
            .map_err(unknown)?;
        let mut credit = CanonicalCounter::new(maximum_bytes);
        // The complete borrowed JSON credit precedes every full controller,
        // archive, activation or canonical body copy. Numeric tokens are counted
        // by the authoritative JCS encoder; byte leaves cover base64 expansion.
        serde_json::to_writer(
            &mut credit,
            &self.borrowed_retirement_history(ByteCredit(controller_credit)),
        )
        .map_err(|error| unknown(crucible_node_format::ContractError::from(error).into()))?;
        let output_credit = credit.finish().map_err(|error| unknown(error.into()))?;
        let mut controller = Buffer::new(controller_credit.min(maximum_bytes))
            .map_err(|error| unknown(error.into()))?;
        self.controller()
            .map_err(unknown)?
            .write_private_original_history(&mut controller)
            .map_err(unknown)?;
        let value = serde_json::to_value(
            self.borrowed_retirement_history(Bytes::new(controller.into_bytes())),
        )
        .map_err(|error| unknown(crucible_node_format::ContractError::from(error).into()))?;
        let mut output = Buffer::new(output_credit).map_err(|error| unknown(error.into()))?;
        canonical::canonical_json_to_writer(&value, &mut output)
            .map_err(|error| unknown(error.into()))?;
        let bytes = output.into_bytes();
        let reference = canonical::content_ref(&bytes, "application/json")
            .map_err(|error| unknown(error.into()))?;
        Ok(InputPayload { reference, bytes })
    }

    fn borrowed_retirement_history<'a, C: serde::Serialize + 'a>(
        &'a self,
        controller: C,
    ) -> impl serde::Serialize + 'a {
        let windows = Sequence(|| {
            self.windows.values().map(|window| {
                (
                    window.original.token().operation(),
                    window.original.request(),
                    &window.grant,
                    &window.receipt,
                    &window.result,
                    &window.observations,
                    window.closed,
                    window.consumed,
                )
            })
        });
        let commits = Sequence(|| {
            self.input_commit_history.values().map(|attempt| {
                (
                    attempt.original.node(),
                    attempt.original.stage_operation(),
                    attempt.original.batch(),
                    attempt.original.inventory(),
                    attempt.original.cutoff(),
                    &attempt.intent,
                    &attempt.request,
                    &attempt.request_hash,
                    &attempt.inventory_bytes,
                    &attempt.receipt,
                    &attempt.record,
                )
            })
        });
        let prepared = self.prepared.as_ref().map(|prepared| {
            (
                Activation::from(&prepared.record),
                &prepared.ready,
                &prepared.owner,
                prepared.registry_complete,
            )
        });
        let status = match self.status {
            DeviceStatus::Parked => "Parked",
            DeviceStatus::Staged => "Staged",
            DeviceStatus::Active => "Active",
            DeviceStatus::ClosedPending => "ClosedPending",
            DeviceStatus::Quarantined => "Quarantined",
            DeviceStatus::Reaped => "Reaped",
        };
        (
            "crucible.private-cnp-controlled-history.v1",
            &self.binding,
            &self.owner_binding,
            &self.gate,
            self.active.as_ref().map(Activation::from),
            (
                windows,
                commits,
                prepared,
                self.preparation_attempt.as_ref().map(Activation::from),
            ),
            status,
            self.semantic_release,
            self.next_input_sequence,
            self.checksum,
            Sequence(|| self.boundary_evidence.values()),
            Sequence(|| self.boundary_dependencies.iter()),
            controller,
        )
    }

    fn require_retirement_owner(&self) -> Result<(), ProviderError> {
        if self.control_process != std::process::id()
            || self.control_thread != std::thread::current().id()
        {
            return Err(ProviderError::Correlation(
                "original retirement has foreign process or thread custody",
            ));
        }
        Ok(())
    }
}
