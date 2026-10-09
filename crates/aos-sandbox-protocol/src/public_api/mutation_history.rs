//! Complete plain, Nix and FUSE historical public-mutation DATA ownership.
//! Canonical decoding and context joins do not authenticate peers, restore grants,
//! or create protected Native writers, current owners, leases or admission tokens.
//!
//! The three original framing domains remain distinct; recognized Nix/FUSE
//! failures never fall back to the plain AOSPME01 decoder.
//!
//! ```text
//! AOSNCA02 -> Nix Start history containing an AOSPME01 context
//! AOSFCA01 -> FUSE admission history containing an AOSPME01 context
//! AOSPME01 -> plain public-mutation context
//! ```
//!
//! Selection checks Nix, then FUSE, then plain framing. Context binding compares
//! the complete nested plain bytes; Nix binding also preflights the whole carrier.

mod nix;
mod fuse;
pub use nix::{
    AssignmentPreimagesV2, CheckedStartAuthorityV2, NixStartAdmissionCarrierV2,
    OriginalAssignmentV2, OriginalPublicMutationCoordinatesV2,
};
pub use fuse::{AdmissionAuthorityV1, ControllerFuseAdmissionCarrierV1};
pub use nix::MAXIMUM_BYTES as NIX_START_ADMISSION_MAXIMUM_BYTES_V2;

use aos_sandbox_core::OperationId;
use sha2::{Digest as _, Sha256};
use super::{
    PublicOperationMethodV1,
    public_mutation_context::{InvalidPublicMutationContext, PublicMutationContextV1},
};

/// Refuses inconsistent historical Start DATA or preserves its original JSON cause.
#[derive(Debug, thiserror::Error)]
pub enum NixHistoryDataError {
    /// The original historical claims, joins or framing disagree.
    #[error("retained Nix Start admission is unavailable or inconsistent")]
    Invalid,
    /// JSON encoding or decoding failed at its original stage.
    #[error(transparent)]
    Encoding(#[from] serde_json::Error),
}

/// Refuses historical FUSE DATA while retaining plain context first causes.
#[derive(Debug, thiserror::Error)]
pub enum FuseHistoryDataError {
    /// Historical framing, scalar claims or resource joins disagree.
    #[error("Controller FUSE admission is unavailable or changed")]
    Rejected,
    /// The nested plain context failed its established typed validation.
    #[error(transparent)]
    Context(#[from] InvalidPublicMutationContext),
}

const PUBLIC_RESOURCE_VERSION_DOMAIN: &[u8] = b"aos.sandbox.public-resource-version.v1\0";

/// Computes the original compiler resource-version transcript.
/// This hash is distinct from the operation metadata projection resource version.
pub fn compiler_resource_version(
    operation: OperationId,
    method: PublicOperationMethodV1,
    generation: u64,
    request_digest: [u8; 32],
) -> Vec<u8> {
    Sha256::new()
        .chain_update(PUBLIC_RESOURCE_VERSION_DOMAIN)
        .chain_update(operation.as_bytes())
        .chain_update([
            crate::domain_ledger::public_operation::public_operation_method_record_code_v1(method),
        ])
        .chain_update(generation.to_be_bytes())
        .chain_update(request_digest)
        .finalize()
        .to_vec()
}

/// Retains the original flat context/selection reason for Native projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("{0}")]
pub struct PublicMutationHistoryErrorV1(&'static str);

impl PublicMutationHistoryErrorV1 {
    /// Returns the unchanged original static refusal reason.
    pub const fn reason(self) -> &'static str {
        self.0
    }
}

fn context_error(error: InvalidPublicMutationContext) -> PublicMutationHistoryErrorV1 {
    PublicMutationHistoryErrorV1(error.reason())
}

/// Encodes the sole selected historical format, retaining Nix-first precedence.
///
/// # Errors
/// Refuses mixed carriers, the selected Nix codec, or the original plain codec.
pub fn encode_history(
    plain: &PublicMutationContextV1,
    fuse: Option<&ControllerFuseAdmissionCarrierV1>,
    nix: Option<&NixStartAdmissionCarrierV2>,
) -> Result<Vec<u8>, PublicMutationHistoryErrorV1> {
    if let Some(carrier) = nix {
        if fuse.is_some() {
            return Err(PublicMutationHistoryErrorV1(
                "mixed public admission carriers",
            ));
        }
        return carrier
            .encode()
            .map_err(|_| PublicMutationHistoryErrorV1("invalid Nix Start carrier"));
    }
    if let Some(carrier) = fuse {
        return Ok(carrier.canonical_bytes().to_vec());
    }
    plain.encode().map_err(context_error)
}

/// Requires the original FUSE/plain join without adopting the historical claims.
///
/// # Errors
/// Refuses a Nix carrier, plain encoding failure, or unequal original bytes.
pub fn require_fuse_context(
    plain: &PublicMutationContextV1,
    nix: Option<&NixStartAdmissionCarrierV2>,
    carrier: &ControllerFuseAdmissionCarrierV1,
) -> Result<(), PublicMutationHistoryErrorV1> {
    if nix.is_some() || plain.encode().map_err(context_error)? != carrier.ordinary_effect() {
        return Err(PublicMutationHistoryErrorV1(
            "FUSE admission context mismatch",
        ));
    }
    Ok(())
}

/// Requires the complete original Start/plain join and bounded wrapper preflight.
///
/// # Errors
/// Preserves mixed/context/request refusal before complete Nix encoding refusal.
pub fn require_nix_context(
    plain: &PublicMutationContextV1,
    fuse: Option<&ControllerFuseAdmissionCarrierV1>,
    carrier: &NixStartAdmissionCarrierV2,
) -> Result<(), PublicMutationHistoryErrorV1> {
    if fuse.is_some()
        || plain.encode().map_err(context_error)? != carrier.ordinary_effect()
        || !matches!(
            plain.validated_request().map_err(context_error)?,
            crate::public_api::request::DormantSandboxRequestKindV1::Start(_)
        )
    {
        return Err(PublicMutationHistoryErrorV1("Nix Start context mismatch"));
    }
    // Preflight the complete wrapper at the original context-binding stage.
    carrier
        .encode()
        .map_err(|_| PublicMutationHistoryErrorV1("Nix Start carrier exceeds bound"))?;
    Ok(())
}

/// Decodes the complete closed historical format family without fallback on recognition.
///
/// # Errors
/// Preserves selected framing, nested plain context, request and wrapper first causes.
pub fn decode_history(
    bytes: &[u8],
) -> Result<
    Option<(
        PublicMutationContextV1,
        Option<ControllerFuseAdmissionCarrierV1>,
        Option<NixStartAdmissionCarrierV2>,
    )>,
    PublicMutationHistoryErrorV1,
> {
    if let Some(carrier) = NixStartAdmissionCarrierV2::decode(bytes)
        .map_err(|_| PublicMutationHistoryErrorV1("invalid Nix Start carrier"))?
    {
        let context = PublicMutationContextV1::decode(carrier.ordinary_effect())
            .map_err(context_error)?
            .ok_or(PublicMutationHistoryErrorV1("missing Nix Start context"))?;
        let (context, carrier) = bind_decoded_nix_context(context, carrier)?;
        return Ok(Some((context, None, Some(carrier))));
    }
    if let Some(carrier) = ControllerFuseAdmissionCarrierV1::decode(bytes)
        .map_err(|_| PublicMutationHistoryErrorV1("invalid FUSE admission carrier"))?
    {
        let context = PublicMutationContextV1::decode(carrier.ordinary_effect())
            .map_err(context_error)?
            .ok_or(PublicMutationHistoryErrorV1(
                "missing FUSE admission context",
            ))?;
        return Ok(Some((context, Some(carrier), None)));
    }
    PublicMutationContextV1::decode(bytes)
        .map(|context| context.map(|plain| (plain, None, None)))
        .map_err(context_error)
}

fn bind_decoded_nix_context(
    context: PublicMutationContextV1,
    carrier: NixStartAdmissionCarrierV2,
) -> Result<(PublicMutationContextV1, NixStartAdmissionCarrierV2), PublicMutationHistoryErrorV1> {
    // Keep the original consuming receiver/argument order and error cleanup.
    require_nix_context(&context, None, &carrier)?;
    Ok((context, carrier))
}
