//! Shares the existing actual Delete request and saved authorization model peaks.
//!
//! Arguments are actual input/record bytes and row counts; no caller chooses a
//! ceiling or native account. Existing protected/native/peer terms stay upper.

use super::*;

pub(crate) fn delete_decode_bytes_v1(encoded: usize) -> Option<usize> {
    use aos_proto::aos::sandbox::v1 as wire;
    // Every unknown field consumes at least one input tag byte, and each
    // repeated Feature consumes at least one message tag byte. These are the actual reached
    // collection element layouts, not a largest request model per input byte.
    let nodes = size_of::<buffa::UnknownField>().checked_add(size_of::<wire::Feature>())?;
    let dynamic = encoded.checked_mul(nodes)?.checked_mul(6)?;
    let fixed = size_of::<wire::DeleteSandboxRequest>()
        .checked_add(size_of::<wire::MutationContext>())?
        .checked_add(size_of::<wire::Duration>())?
        .checked_add(size_of::<AuthorizedPublicMutationRequestV1>())?
        .checked_mul(4)?;
    // Envelope/body ownership, validated-kind clone, canonical protobuf and
    // JSON authorization envelope/hex scratch coexist under these byte lanes.
    dynamic
        .checked_add(encoded.checked_mul(32)?)?
        .checked_add(fixed)
}

pub(crate) fn authorization_model_bytes_v1(encoded: usize, rows: usize) -> Option<usize> {
    use aos_sandbox_core::model::{ExplanationReason, Optimization, PolicyViewAction};
    use aos_sandbox_core::{FeatureRef, Grant, ObjectDescriptor, Selector};
    use aos_sandbox_protocol::domain_ledger::runtime_authority_history as runtime;
    // The capability JSON and policy CBOR arrays each require at least one
    // encoded byte per reached element. Sum their actual leaf/node layouts;
    // byte strings/path components and canonical/reencode copies are separate.
    let nodes = size_of::<Grant>()
        .checked_add(size_of::<Selector>())?
        .checked_add(size_of::<FeatureRef>())?
        .checked_add(size_of::<ObjectDescriptor>())?
        .checked_add(size_of::<PolicyViewAction>())?
        .checked_add(size_of::<Optimization>())?
        .checked_add(size_of::<ExplanationReason>())?
        .checked_add(size_of::<Vec<u8>>())?;
    let dynamic = encoded.checked_mul(nodes)?.checked_mul(32)?;
    // Registry handle/fanout maps, complete runtime cross-link maps, current
    // capability/policy decision and prospective floor copies coexist. Fixed
    // row layouts are multiplied by actual row count, never by encoded bytes.
    let row = size_of::<CurrentCapabilityDecisionV1>()
        .checked_add(size_of::<runtime::RuntimeAuthorityPendingV1>())?
        .checked_add(size_of::<runtime::RuntimeAuthorityBindingV1>())?
        .checked_add(size_of::<runtime::RuntimeAuthorityHeadV1>())?
        .checked_add(size_of::<([u8; 32], [u8; 16], [usize; 3])>())?;
    let fixed = rows.checked_add(2)?.checked_mul(row)?.checked_mul(32)?;
    dynamic
        .checked_add(encoded.checked_mul(128)?)?
        .checked_add(fixed)?
        .checked_add(aos_sandbox_protocol::domain_ledger::delete_batch::new_use::public_mutation_new_use_receiving_bytes_v2())
}
