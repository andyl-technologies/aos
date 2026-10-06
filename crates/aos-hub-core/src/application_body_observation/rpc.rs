//! Closed request/reply type pairs for the actual publication workload.
//!
//! Canonical encoding equality rejects ignored request fields and trailing bytes
//! as observational evidence. Existing service validators and current original /
//! SQL joins remain required; a serializer alone grants no metadata conclusion.

use super::{canonical, image, BodyEvidence, EncodedImage};
use aos_proto_types::*;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::any::{Any, TypeId};

const MAX_CANONICAL: u64 = 8 * 1024 * 1024;

pub(crate) struct Prepared {
    kind: &'static str,
    request: EncodedImage,
    response_type: TypeId,
}

pub(crate) fn request<Req: 'static, Resp: 'static>(value: &Req, raw: &[u8]) -> Option<Prepared> {
    if !super::enabled() {
        return None;
    }
    let value = value as &dyn Any;
    macro_rules! pair {
        ($request:ty, $reply:ty, $kind:literal) => {
            if TypeId::of::<Resp>() == TypeId::of::<$reply>() {
                if let Some(typed) = value.downcast_ref::<$request>() {
                    let expected = canonical(typed, MAX_CANONICAL)?;
                    let actual = image(raw);
                    if expected.byte_size != actual.byte_size || expected.sha256 != actual.sha256 {
                        return None;
                    }
                    return Some(Prepared {
                        kind: $kind,
                        request: expected,
                        response_type: TypeId::of::<$reply>(),
                    });
                }
            }
        };
    }
    pair!(
        BeginRegistryPublicationManifestRequest,
        RegistryPublicationManifestSession,
        "publication_manifest_begin"
    );
    pair!(
        AppendRegistryPublicationManifestRequest,
        RegistryPublicationManifestSession,
        "publication_manifest_append"
    );
    pair!(
        SealRegistryPublicationManifestRequest,
        RegistryPublication,
        "publication_manifest_seal"
    );
    pair!(
        GetRegistryPublicationRequest,
        RegistryPublication,
        "publication_get"
    );
    pair!(
        CommitRegistryPublicationRequest,
        RegistryPublication,
        "publication_commit"
    );
    pair!(
        ListRegistryPublicationsRequest,
        ListRegistryPublicationsResponse,
        "publication_list"
    );
    pair!(GetRegistryRequest, GetRegistryResponse, "registry_get");
    pair!(WhoAmIRequest, WhoAmIResponse, "identity_who_am_i");
    None
}

pub(crate) fn reply<Resp: Serialize + 'static>(
    prepared: Option<Prepared>,
    value: &Resp,
) -> Option<BodyEvidence> {
    let prepared = prepared?;
    if prepared.response_type != TypeId::of::<Resp>() {
        return None;
    }
    let reply = canonical(value, MAX_CANONICAL)?;
    let mut source = Sha256::new();
    source.update(include_bytes!("../application_body_observation.rs"));
    source.update(include_bytes!("rpc.rs"));
    source.update(include_bytes!("../connect.rs"));
    Some(BodyEvidence {
        constructor: prepared.kind,
        constructor_source_sha256: hex::encode(source.finalize()),
        request: Some(prepared.request),
        reply,
        required_projection: "bounded_original_and_current_sql_projection",
    })
}
