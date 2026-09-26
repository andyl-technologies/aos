//! Authenticated Storage Create preparation and its exact catalog handoff.
//!
//! The signed Prepare response is non-authorizing. Its catalog binding may be
//! used only with a separate signed Create Apply, and the original signed
//! outcome stays in custody for durable source and recovery joins.

use aos_proto::aos::sandbox::local::v1::{BrokerMethod, PrepareStorageCatalogResponse};
use aos_sandbox::{EffectFailure, PreparedAuthorityEffectV1};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_protocol::ValidatedAssignmentFence;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
};
use aos_sandbox_protocol::semantics::{
    CanonicalStoragePreparationSemanticsV1, CatalogBindingV1, ProtectedStorageCreatePreparationV1,
};
use buffa::Message as _;

/// Retains the signed Create Prepare result and broker-minted catalog binding.
#[must_use = "retain the signed preparation through the independent Apply grant"]
pub struct AuthenticatedStorageCreatePreparationV1 {
    operation_id: [u8; 16],
    fence: ValidatedAssignmentFence,
    catalog: CatalogBindingV1,
    outcome: AuthenticatedBrokerMethodOutcomeV1,
}

impl AuthenticatedStorageCreatePreparationV1 {
    pub(crate) fn from_outcome(
        protected: &ProtectedStorageCreatePreparationV1,
        authority: &PreparedAuthorityEffectV1,
        outcome: AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<Self, EffectFailure> {
        let now = crate::handshake::protected_boottime_nanoseconds().map_err(|_| {
            EffectFailure::Retryable("Storage preparation clock is unavailable".to_owned())
        })?;
        let request = outcome.request();
        let decoded = CanonicalStoragePreparationSemanticsV1::decode(
            request.exact_body(),
            request.peer(),
            request.peer_policy(),
            now,
        )
        .map_err(|_| {
            EffectFailure::Permanent("Storage preparation request is no longer current".to_owned())
        })?;
        if outcome.method() != BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG
            || request.authorization().is_none()
            || !protected.matches_decoded(&decoded)
        {
            return Err(EffectFailure::Permanent(
                "Storage preparation differs from protected Create inputs".to_owned(),
            ));
        }
        authority
            .validate_authenticated_outcome(&outcome)
            .map_err(|_| {
                EffectFailure::Permanent(
                    "Storage preparation returned a contradictory result".to_owned(),
                )
            })?;

        let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
            return Err(EffectFailure::Permanent(
                "Storage preparation returned a broker error".to_owned(),
            ));
        };
        let response =
            PrepareStorageCatalogResponse::decode_from_slice(exact_body).map_err(|_| {
                EffectFailure::Permanent("Storage preparation response is malformed".to_owned())
            })?;
        if !response.__buffa_unknown_fields.is_empty()
            || response.encode_to_vec().as_slice() != exact_body.as_slice()
            || response.operation_id.as_slice() != decoded.operation_id()
            || response.preparation_expires_boottime_nanoseconds
                != decoded.expires_boottime_nanoseconds()
            || response.non_authorizing_receipt.is_empty()
        {
            return Err(EffectFailure::Permanent(
                "Storage preparation response changed its authenticated meaning".to_owned(),
            ));
        }
        let catalog = CatalogBindingV1::from_publisher(
            response.catalog_generation,
            ObjectDigest::from_bytes(response.catalog_digest.as_slice().try_into().map_err(
                |_| {
                    EffectFailure::Permanent(
                        "Storage preparation catalog digest is invalid".to_owned(),
                    )
                },
            )?),
        )
        .map_err(|_| {
            EffectFailure::Permanent("Storage preparation catalog is invalid".to_owned())
        })?;

        Ok(Self {
            operation_id: decoded.operation_id(),
            fence: *decoded.fence(),
            catalog,
            outcome,
        })
    }

    /// Returns the exact public Create operation bound by signed preparation.
    #[must_use]
    pub const fn operation_id(&self) -> [u8; 16] {
        self.operation_id
    }

    /// Returns the exact assignment fence bound by signed preparation.
    #[must_use]
    pub const fn fence(&self) -> ValidatedAssignmentFence {
        self.fence
    }

    /// Returns the broker-minted catalog that a separate Apply must name.
    #[must_use]
    pub const fn catalog(&self) -> CatalogBindingV1 {
        self.catalog
    }

    /// Returns the exact signed Prepare exchange for durable source custody.
    #[must_use]
    pub const fn outcome(&self) -> &AuthenticatedBrokerMethodOutcomeV1 {
        &self.outcome
    }
}
