//! Decodes dedicated bootstrap18 body DATA independently of ordinary Admit.
//!
//! Generic Connection and baseline body dispatch refuse this method. Only the
//! actual selected Source/native bootstrap path may retain these parsed bodies
//! in its dedicated Session/occurrence slot after genuine preflight admission.

use super::*;
use crate::bodies::{OperationState, ResponseShape};

/// Retains the profile result separately from baseline method results.
#[derive(Debug)]
pub struct PacketNativeImport18BootstrapResponseBody {
    /// Preserves the full common response, including actual refused/error DATA.
    pub shape: ResponseShape,
    /// Retains the exact bootstrap-only result on successful completion.
    pub result: Option<PacketNativeImport18BootstrapResult>,
}

/// Classifies only the profile-specific bootstrap request and response.
#[derive(Debug)]
pub enum PacketNativeImport18BootstrapReceivedBody {
    /// Retains the closed bootstrap request without ordinary lifecycle flags.
    Request(PacketNativeImport18BootstrapRequest),
    /// Retains the correlated complete result or actual bounded refusal.
    Response(PacketNativeImport18BootstrapResponseBody),
}

/// Decodes the closed profile request after its independently funded raw prewalk.
///
/// Actual feature/profile/current service ownership and receiving sequence are
/// separate mandatory private guards. Structural decoding issues no allowance.
///
/// # Errors
/// Refuses another method/kind, malformed schema/width/row or unknown fields.
pub fn native_import18_bootstrap_request_body_data(
    original: &Envelope,
) -> Result<PacketNativeImport18BootstrapRequest, ProviderError> {
    original.validate()?;
    if original.method != Method::NativeImport18Bootstrap
        || original.message != MessageKind::Request
    {
        return Err(invalid());
    }
    let request: PacketNativeImport18BootstrapRequest =
        serde_json::from_value(serde_json::Value::Object(original.body.clone()))
            .map_err(ContractError::from)?;
    request.validate_data()?;
    Ok(request)
}

/// Decodes a correlated profile response without interpreting it as AdmitResult.
///
/// # Errors
/// Refuses changed correlation, accepted/running status, nonempty common body
/// extensions, another result schema/state or changed original recipe/row.
pub fn native_import18_bootstrap_response_body_data(
    original: &Envelope,
    response: &Envelope,
) -> Result<PacketNativeImport18BootstrapResponseBody, ProviderError> {
    let request = native_import18_bootstrap_request_body_data(original)?;
    original.matches_response(response)?;
    response.validate()?;
    let shape = crate::bodies::decode_response_shape(&response.body)?;
    let result = match &shape {
        ResponseShape::Completed {
            operation_state,
            result,
            extensions,
        } => {
            if *operation_state != OperationState::Completed || !extensions.is_empty() {
                return Err(invalid());
            }
            let result: PacketNativeImport18BootstrapResult =
                serde_json::from_value(serde_json::Value::Object(result.clone()))
                    .map_err(ContractError::from)?;
            result.authenticate_request_data(&request)?;
            Some(result)
        }
        ResponseShape::Error { extensions, .. } if extensions.is_empty() => None,
        ResponseShape::Error { .. } | ResponseShape::Accepted { .. } => return Err(invalid()),
    };
    Ok(PacketNativeImport18BootstrapResponseBody { shape, result })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_method_and_closed_request_do_not_alias_admit() {
        assert_eq!(
            serde_json::to_value(Method::NativeImport18Bootstrap).unwrap(),
            "native_import18_bootstrap"
        );
        let mut original = crate::envelope::tests::request();
        original.method = Method::NativeImport18Bootstrap;
        original.body = serde_json::to_value(PacketNativeImport18BootstrapRequest {
            schema: NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA.into(),
            recipe_identity: Bytes::new(vec![1; 32]),
            initial_funding: PacketNativeStartupAllocationRow {
                retained_requested_bytes: U64::new(1),
                maximum_simultaneous_transient_bytes: U64::new(1),
                declared_counter_scratch_bytes: U64::new(1),
            },
        })
        .unwrap()
        .as_object()
        .unwrap()
        .clone();
        native_import18_bootstrap_request_body_data(&original).unwrap();
        assert!(crate::bodies::decode_request(original.method, &original.body).is_err());
        original.method = Method::Admit;
        assert!(native_import18_bootstrap_request_body_data(&original).is_err());
        original.method = Method::NativeImport18Bootstrap;
        original
            .body
            .insert("bindings".into(), serde_json::Value::Array(vec![]));
        assert!(native_import18_bootstrap_request_body_data(&original).is_err());
    }
}
