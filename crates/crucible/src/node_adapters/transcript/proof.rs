//! Versioned producer-proof inventories retained inside authenticated records.
//!
//! These objects describe actual source-selected codec closure. They do not
//! authorize native work or convert physical provenance into exact computation.

use crucible_node_contract::{ContentRef, HashRef, Id, canonical};
use serde::{Deserialize, Serialize};

use crate::{node_contract::OwnerIdentity, node_scheduling::InputPayload};

use super::{
    codec::{TranscriptError, encode, invalid},
    types::TranscriptOrigin,
};

const MEDIA_TYPE: &str = "application/vnd.crucible.transcript-producer-proof+json;version=1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecordedProofClosure {
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    schema_version: u16,
    world: HashRef,
    node: Id,
    owners: Vec<OwnerIdentity>,
    pub(super) root: ContentRef,
    pub(super) dependencies: Vec<ContentRef>,
}

impl RecordedProofClosure {
    pub(super) fn capture(
        origin: &TranscriptOrigin,
        root: ContentRef,
        dependencies: Vec<ContentRef>,
    ) -> Result<InputPayload, TranscriptError> {
        let closure = Self {
            schema_version: 1,
            world: origin.activation.world_binding_hash.clone(),
            node: origin.route.node.clone(),
            owners: origin.route.owners.clone(),
            root,
            dependencies,
        };
        let bytes = encode(&closure)?;
        let reference = canonical::content_ref(&bytes, MEDIA_TYPE).map_err(invalid)?;
        Ok(InputPayload { reference, bytes })
    }

    pub(super) fn decode(
        object: &InputPayload,
        origin: &TranscriptOrigin,
    ) -> Result<Option<Self>, TranscriptError> {
        if object.reference.media_type != MEDIA_TYPE {
            return Ok(None);
        }
        object.reference.verify(&object.bytes).map_err(invalid)?;
        let closure: Self = serde_json::from_slice(&object.bytes).map_err(invalid)?;
        if closure.schema_version != 1
            || closure.world != origin.activation.world_binding_hash
            || closure.node != origin.route.node
            || closure.owners != origin.route.owners
            || closure.dependencies.contains(&closure.root)
            || encode(&closure)? != object.bytes
        {
            return Err(TranscriptError::Invalid(
                "original producer-proof inventory scope or canonical bytes changed".into(),
            ));
        }
        Ok(Some(closure))
    }
}
