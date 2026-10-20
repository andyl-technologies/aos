//! Computes nonissuing byte shapes for the one Create Storage Prepare request.
//!
//! Root and Controller run this same canonical encoder under their own original
//! admission. Maximal CBOR time widths remove their sampling-time difference;
//! these zero-signature bytes cannot become a signed plan or request authority.

use std::error::Error;

use aos_proto::aos::sandbox::local::v1::{BrokerMethod, BrokerRequestEnvelope};
use aos_sandbox_core::{BrokerAudience, BrokerAuthorizationPlan, BrokerVerb, ProtocolId};
use aos_sandbox_core::format::encode_signature;
use aos_sandbox_core::model::{Signature, SignatureBytes};
use buffa::Message as _;

use super::{BrokerPlanPreparation, SigningAuthority};

#[derive(Debug, thiserror::Error)]
#[error("the nonissuing Storage Prepare shape differs from its closed purpose")]
struct Changed;

/// Encodes a conservative signature and complete authenticated request shape.
///
/// The tuple contains a zero detached signature followed by the raw request
/// envelope with a fixed-width zero Session artifact. Every non-time plan field
/// and the complete body/lease quartet are preserved. Both validity fields use
/// maximal canonical integer widths, so independently sampled Root/Controller
/// plans with the same other fields produce identical receiving sizes.
///
/// These bytes are sizing DATA. The function never constructs a signed plan,
/// verifies a signature, accepts a request, opens a file or reserves resources.
/// Its actual owning caller must admit all construction before invoking it.
///
/// # Errors
/// Rejects another purpose, invalid shared plan/signature/envelope construction,
/// or a request exceeding the unchanged ordinary authenticated wire ceiling.
pub fn storage_create_prepare_request_shape_v1(
    plan: &BrokerAuthorizationPlan,
    authority: &SigningAuthority,
    body: &[u8],
    ownership_lease: &[u8],
    ownership_lease_signature: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error + Send + Sync>> {
    storage_request_shape_v1(
        plan, authority, body, ownership_lease, ownership_lease_signature,
        StorageRequestShapePurposeV1::Prepare,
    )
}

/// Encodes the distinct Create Apply signature and catalog-bound request shape.
///
/// Both returned artifacts are zero-signature sizing DATA. The complete exact
/// catalog association is encoded by the same ordinary envelope engine.
///
/// # Errors
/// Rejects another plan purpose or the same canonical/wire construction errors
/// as the original Prepare shape. Actual callers must prepay construction.
pub fn storage_create_apply_request_shape_v1(
    plan: &BrokerAuthorizationPlan,
    authority: &SigningAuthority,
    body: &[u8],
    catalog: crate::semantics::CatalogBindingV1,
    ownership_lease: &[u8],
    ownership_lease_signature: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error + Send + Sync>> {
    storage_request_shape_v1(
        plan, authority, body, ownership_lease, ownership_lease_signature,
        StorageRequestShapePurposeV1::Apply(catalog),
    )
}

// Fixed pure codec selectors carry no role, clock, grant or native owner.
enum StorageRequestShapePurposeV1 {
    Prepare,
    Apply(crate::semantics::CatalogBindingV1),
}

fn storage_request_shape_v1(
    plan: &BrokerAuthorizationPlan,
    authority: &SigningAuthority,
    body: &[u8],
    ownership_lease: &[u8],
    ownership_lease_signature: &[u8],
    purpose: StorageRequestShapePurposeV1,
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error + Send + Sync>> {
    let (method, verb, bindings) = match purpose {
        StorageRequestShapePurposeV1::Prepare => (
            BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG,
            BrokerVerb::StoragePrepareCatalog, None,
        ),
        StorageRequestShapePurposeV1::Apply(catalog) => (
            BrokerMethod::BROKER_METHOD_STORAGE_APPLY,
            BrokerVerb::StorageCreateWorkspace,
            Some(aos_proto::aos::sandbox::local::v1::BrokerSemanticBindingsV1 {
                storage_catalog_generation: catalog.generation(),
                storage_catalog_digest: catalog.digest().as_bytes().to_vec(),
                ..Default::default()
            }),
        ),
    };
    if plan.audience() != BrokerAudience::Storage
        || plan.protocol() != ProtocolId::StorageBroker
        || plan.grants().len() != 1
        || plan.grants()[0].verb() != verb
    {
        return Err(Box::new(Changed));
    }

    let sizing = BrokerAuthorizationPlan::new(
        plan.audience(), plan.protocol(), plan.protocol_version(), plan.assignment(),
        plan.node(), plan.ownership_authority().clone(), plan.grants().to_vec(),
        plan.policy_commitment(), plan.revocation_scope(), i64::MIN, i64::MAX,
        plan.required_features().to_vec(),
    )?;
    let preparation = BrokerPlanPreparation::new(sizing, authority.clone())?;
    let signature = encode_signature(&Signature::new(
        preparation.signing_request().statement().clone(),
        SignatureBytes::new([0; 64]),
    ));
    let envelope = crate::encode_authorized_request_envelope_with_bindings_v1(
        ProtocolId::StorageBroker, method,
        body, &[], crate::AuthorizationArtifactBytes {
            broker_plan: preparation.canonical_plan(),
            broker_plan_signature: &signature,
            ownership_lease,
            ownership_lease_signature,
        }, bindings.as_ref(),
    )?;
    let mut envelope = BrokerRequestEnvelope::decode_from_slice(&envelope)?;
    envelope.signed_session_request = vec![0;
        aos_sandbox_broker_session_protocol::SIGNED_BROKER_REQUEST_BYTES];
    let request = envelope.encode_to_vec();
    if request.len() > aos_sandbox_broker_session_protocol::AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES {
        return Err(Box::new(Changed));
    }
    Ok((signature, request))
}
