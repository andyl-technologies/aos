//! Binds actual source cleanup to its original operator Capture record.
//!
//! ```text
//! CapabilityRetirement.1 = original request + signed artifact + original
//!   activation + exact sealed native cleanup proof after runtime reclamation
//! ```
//!
//! This closed host-authored record is written only by the lane holding the
//! qualified original capsule. A signed archive or copied proof alone cannot
//! install a retirement relation or authorize a fresh operator continuation.

use super::*;
use crucible::{
    node_contract::{ActivationRecord, SavedRuntimeActivation},
    node_state::NativeArchiveRecord,
};
use crucible_node_contract::{Bytes, ContentRef};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RetirementBody {
    format: String,
    version: u32,
    request: String,
    artifact: ContentRef,
    activation: SavedRuntimeActivation,
    native_proof: ContentRef,
    native_body: Bytes,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Retirement {
    body: RetirementBody,
    authentication: Bytes,
}

pub(in crate::node_observed_executor::service::capability_preparation) struct SealedRetirement {
    bytes: Vec<u8>,
    identity: ContentId,
}

impl CapabilityPreparationLedger {
    pub(in crate::node_observed_executor::service::capability_preparation) fn seal_retirement(
        &self,
        reservation: &CapabilityReservation,
        artifact: &ContentRef,
        target: &ActivationRecord,
        native_proof: ContentRef,
        native_body: Vec<u8>,
        authenticator: &super::super::group::retirement_auth::Authenticator,
    ) -> Result<SealedRetirement, NodeObservationServiceError> {
        if native_body.len() > 64 * 1024 || !reservation.original_dispatch {
            return Err(refused(
                "original native retirement credit or dispatch differs",
            ));
        }
        native_proof.verify(&native_body).map_err(refused)?;
        let body = RetirementBody {
            format: "crucible.capability-native-retirement".into(),
            version: 1,
            request: reservation.record.request.clone(),
            artifact: artifact.clone(),
            activation: target.into(),
            native_proof,
            native_body: Bytes::new(native_body),
        };
        let authentication = authenticator.sign(&encode(&body)?)?;
        let record = Retirement {
            body,
            authentication: Bytes::new(authentication),
        };
        let bytes = encode(&record)?;
        if bytes.len() > 128 * 1024 {
            return Err(refused("original retirement record exceeds credit"));
        }
        let identity = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
        Ok(SealedRetirement { bytes, identity })
    }

    pub(in crate::node_observed_executor::service::capability_preparation) fn place_retirement(
        &self,
        reservation: &CapabilityReservation,
        sealed: &SealedRetirement,
    ) -> Result<(), NodeObservationServiceError> {
        let _guard = self.refs.acquire_publication_guard().map_err(refused)?;
        self.put(sealed.identity, sealed.bytes.clone())?;
        let reference = retirement_ref(&reservation.record.execution)?;
        match self
            .refs
            .compare_exchange(&reference, None, sealed.identity)
            .map_err(refused)?
        {
            RefCasOutcome::Advanced { next } if next == sealed.identity => Ok(()),
            RefCasOutcome::Conflict {
                current: Some(current),
                ..
            } if current == sealed.identity => Ok(()),
            _ => Err(refused(
                "original retirement relation requires same-byte reconciliation",
            )),
        }
    }

    pub(super) fn authenticate_retirement(
        &self,
        execution: &str,
        request: &str,
        source: &NativeArchiveRecord,
        authenticator: &super::super::group::retirement_auth::Authenticator,
    ) -> Result<(), NodeObservationServiceError> {
        let identity = self
            .refs
            .read_ref(&retirement_ref(execution)?)
            .map_err(refused)?
            .ok_or_else(|| refused("original captured owner has no durable cleanup relation"))?;
        let bytes = self.read_bytes(identity, 128 * 1024)?;
        let signed: Retirement =
            serde_json::from_value(canonical::parse_json(&bytes, 128 * 1024).map_err(refused)?)
                .map_err(refused)?;
        authenticator.verify(&encode(&signed.body)?, signed.authentication.as_slice())?;
        let saved = &signed.body;
        if saved.format != "crucible.capability-native-retirement"
            || saved.version != 1
            || saved.request != request
            || saved.artifact != *source.artifact()
            || saved.activation
                != source
                    .runtime_snapshot()
                    .map_err(refused)?
                    .source_activation
            || saved.native_body.as_slice().len() > 64 * 1024
            || encode(&signed)? != bytes
        {
            return Err(refused(
                "original operator cleanup/source/activation relation differs",
            ));
        }
        saved
            .native_proof
            .verify(saved.native_body.as_slice())
            .map_err(refused)
    }
}

fn retirement_ref(execution: &str) -> Result<RefName, NodeObservationServiceError> {
    validate_execution(execution)?;
    RefName::new(format!("node-capability-native-retirement/{execution}")).map_err(refused)
}
