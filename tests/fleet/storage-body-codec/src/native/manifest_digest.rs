//! Exact source-extracted production manifest-page serializer.

use aos_hub_core::service::RpcError;
use aos_proto_types as pb;
use sha2::{Digest as _, Sha256};

fn registry_publication_manifest_chunk_digest(
    objects: &[pb::RegistryPublicationObjectInput],
) -> Result<String, RpcError> {
    let canonical = objects
        .iter()
        .map(|object| {
            (
                &object.path,
                &object.sha256,
                object.byte_size,
                &object.kind,
                &object.media_type,
            )
        })
        .collect::<Vec<_>>();
    Ok(hex::encode(Sha256::digest(
        serde_json::to_vec(&canonical).map_err(RpcError::internal)?,
    )))
}

pub(super) fn digest(objects: &[pb::RegistryPublicationObjectInput]) -> Result<String, RpcError> {
    registry_publication_manifest_chunk_digest(objects)
}
