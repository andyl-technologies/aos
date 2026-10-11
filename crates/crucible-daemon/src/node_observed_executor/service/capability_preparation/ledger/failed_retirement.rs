//! Binds no-archive native retirement to the same original durable refusal.
//!
//! This operational signature joins the original common claim, unchanged
//! Unavailable result, complete source/model/private-ACK roots and actual first
//! Shutdown/reaping references. It is not a capture, continuation or new result.
//!
//! ```text
//! failed-retirement.1 = original request/result + activation + closed retained
//!   source/history/Shutdown/reap roster + original operational authentication
//! ```

use super::*;
use crate::node_observed_executor::factory::FailureRetirementSummary;
use crucible::node_contract::{ActivationRecord, SavedRuntimeActivation};
use serde::Serialize;

#[derive(Serialize)]
struct Body<'a> {
    format: &'static str,
    version: u16,
    request: &'a str,
    completion: String,
    activation: SavedRuntimeActivation,
    retained: &'a FailureRetirementSummary,
}

#[derive(Serialize)]
struct Signed<'a> {
    body: &'a Body<'a>,
    authentication: crucible_node_contract::Bytes,
}

pub(in crate::node_observed_executor::service::capability_preparation) struct SealedFailedRetirement
{
    body: Vec<u8>,
    authentication: Vec<u8>,
    bytes: Vec<u8>,
    identity: ContentId,
}

impl CapabilityPreparationLedger {
    pub(in crate::node_observed_executor::service::capability_preparation) fn seal_failed_retirement(
        &self,
        reservation: &CapabilityReservation,
        completion: &SealedCompletion,
        target: &ActivationRecord,
        retained: &FailureRetirementSummary,
        authenticator: &super::super::group::retirement_auth::Authenticator,
    ) -> Result<SealedFailedRetirement, NodeObservationServiceError> {
        if !reservation.original_dispatch
            || target.owners.len() != 4
            || retained.histories.len() > 16
            || !matches!(
                completion.record.outcome,
                CapabilityPreparationState::Unavailable { .. }
            )
            || completion.record.request != reservation.record.request
        {
            return Err(refused("original no-archive retirement scope differs"));
        }
        let body = Body {
            format: "crucible.capability-failed-retirement",
            version: 1,
            request: &reservation.record.request,
            completion: completion.identity.encode(),
            activation: target.into(),
            retained,
        };
        serde_json::to_writer(Credit(96 * 1024), &body).map_err(refused)?;
        let original = encode(&body)?;
        let authentication = authenticator.sign(&original)?;
        let record = Signed {
            body: &body,
            authentication: crucible_node_contract::Bytes::new(authentication.clone()),
        };
        let bytes = encode(&record)?;
        if bytes.len() > 128 * 1024 {
            return Err(refused("original failed retirement record exceeds credit"));
        }
        let identity = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
        Ok(SealedFailedRetirement {
            body: original,
            authentication,
            bytes,
            identity,
        })
    }

    pub(in crate::node_observed_executor::service::capability_preparation) fn place_failed_retirement(
        &self,
        reservation: &CapabilityReservation,
        sealed: &SealedFailedRetirement,
    ) -> Result<(), NodeObservationServiceError> {
        let _publication = self.refs.acquire_publication_guard().map_err(refused)?;
        self.put(sealed.identity, sealed.bytes.clone())?;
        match self
            .refs
            .compare_exchange(
                &failure_ref(&reservation.record.execution)?,
                None,
                sealed.identity,
            )
            .map_err(refused)?
        {
            RefCasOutcome::Advanced { next } if next == sealed.identity => Ok(()),
            RefCasOutcome::Conflict {
                current: Some(current),
                ..
            } if current == sealed.identity => Ok(()),
            _ => Err(refused(
                "same original failed retirement requires byte-identical reconciliation",
            )),
        }
    }

    pub(in crate::node_observed_executor::service::capability_preparation) fn authenticate_failed_release(
        &self,
        reservation: &CapabilityReservation,
        completion: &SealedCompletion,
        target: &ActivationRecord,
        retained: &FailureRetirementSummary,
        sealed: &SealedFailedRetirement,
        authenticator: &super::super::group::retirement_auth::Authenticator,
    ) -> Result<(), NodeObservationServiceError> {
        if !reservation.original_dispatch
            || !matches!(
                completion.record.outcome,
                CapabilityPreparationState::Unavailable { .. }
            )
            || completion.record.request != reservation.record.request
            || self
                .refs
                .read_ref(&operation_ref(&reservation.record.execution)?)
                .map_err(refused)?
                != Some(completion.identity)
            || self
                .refs
                .read_ref(&retained_completion_ref(&reservation.record.execution)?)
                .map_err(refused)?
                != Some(completion.identity)
            || self.read_bytes(completion.identity, MAXIMUM_RECORD_BYTES)? != completion.bytes
            || self
                .refs
                .read_ref(&failure_ref(&reservation.record.execution)?)
                .map_err(refused)?
                != Some(sealed.identity)
            || self.read_bytes(sealed.identity, 128 * 1024)? != sealed.bytes
        {
            return Err(refused(
                "same original durable refusal or failed release root differs",
            ));
        }
        let request_bytes = self.read_bytes(
            ContentId::parse(&completion.record.request).map_err(refused)?,
            MAXIMUM_REQUEST_BYTES,
        )?;
        let request = CapabilityPreparationRequest::from_json(&request_bytes)?;
        if request.execution != reservation.record.execution
            || !super::super::super::original_claim::OriginalClaims::new(
                self.blobs.clone(),
                self.refs.clone(),
            )?
            .existing(
                &request.execution,
                super::super::super::original_claim::Route::Capability,
                &request_bytes,
            )?
        {
            return Err(refused("same original common failure claim differs"));
        }
        let actual = Body {
            format: "crucible.capability-failed-retirement",
            version: 1,
            request: &reservation.record.request,
            completion: completion.identity.encode(),
            activation: target.into(),
            retained,
        };
        serde_json::to_writer(Credit(96 * 1024), &actual).map_err(refused)?;
        if encode(&actual)? != sealed.body {
            return Err(refused("fresh original failed release association differs"));
        }
        authenticator.verify(&sealed.body, &sealed.authentication)
    }
}

fn failure_ref(execution: &str) -> Result<RefName, NodeObservationServiceError> {
    validate_execution(execution)?;
    RefName::new(format!("node-capability-failed-retirement/{execution}")).map_err(refused)
}

struct Credit(usize);

impl std::io::Write for Credit {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.checked_sub(bytes.len()).ok_or_else(|| {
            std::io::Error::other("original failed retirement body credit exhausted")
        })?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
