//! Retains complete ordinary request owners before later decoding failures.

use super::*;
use crate::protocol_snapshot::owned11::typed::native17_build::native17_struct;

native17_struct!(BeginRequest {
    kind:BeginKind,
    binding_hash:HashRef,
    owner_generation:U64,
    activation_id:Nullable<Id>,
    world_generation:U64,
    arguments:Map<String,Value>,
    extensions:Extensions,
});

native17_struct!(ActivateRequest {
    admission_id: Id,
    activation_id: Id,
    world_generation: U64,
    prepared_token: Id,
    world_binding_hash: HashRef,
    gate_id: Id,
    extensions: Extensions,
});

native17_struct!(WorldActivateRequest {
    transaction_id: Id,
    activation_id: Id,
    world_generation: U64,
    prepared_token: Id,
    world_binding_hash: HashRef,
    gate_id: Id,
    activation_manifest: ContentRef,
    extensions: Extensions,
});
