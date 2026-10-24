//! Decodes the protected certificate-to-principal registration table.
//!
//! The deployment credential uses this closed JSON shape:
//!
//! ```json
//! {"version":1,"peers":[{"certificate_sha256":[1,2],"principal":"UUID","project":"UUID"}]}
//! ```
//!
//! The abbreviated fingerprint above must contain exactly 32 bytes in a real
//! credential. Registration identifies a peer; it grants no capability.

use std::collections::BTreeMap;

use aos_sandbox_model::{PrincipalId, ProjectId};
use serde::Deserialize;

use super::PublicApiSessionError;

const MAXIMUM_REGISTERED_PEERS: usize = 4096;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrationDocument {
    version: u16,
    peers: Vec<Registration>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Registration {
    pub(super) certificate_sha256: [u8; 32],
    pub(super) principal: PrincipalId,
    pub(super) project: ProjectId,
}

pub(super) fn decode(
    bytes: &[u8],
) -> Result<BTreeMap<[u8; 32], Registration>, PublicApiSessionError> {
    let document: RegistrationDocument =
        serde_json::from_slice(bytes).map_err(|_| PublicApiSessionError::Configuration)?;
    if document.version != 1
        || document.peers.is_empty()
        || document.peers.len() > MAXIMUM_REGISTERED_PEERS
    {
        return Err(PublicApiSessionError::Configuration);
    }
    let mut peers = BTreeMap::new();
    for peer in document.peers {
        if peer.certificate_sha256 == [0; 32]
            || peer.principal.as_bytes() == &[0; 16]
            || peer.project.as_bytes() == &[0; 16]
            || peers.insert(peer.certificate_sha256, peer).is_some()
        {
            return Err(PublicApiSessionError::Configuration);
        }
    }
    Ok(peers)
}

// Prices the typed Vec/map even for a structurally valid table rejected later.
// Each completed fingerprint alone consumes at least 65 JSON bytes: 32 digits,
// 31 commas and brackets. Missing/malformed fields never push a Registration.
pub(super) fn startup_representation_bound(encoded: usize) -> Option<(usize, usize)> {
    let rows = encoded.checked_div(65)?.checked_add(4)?;
    let vector = rows.checked_mul(3)?.checked_mul(std::mem::size_of::<Registration>())?;
    let map_rows = rows.min(MAXIMUM_REGISTERED_PEERS);
    // BTree nodes contain keys/values and links. Four carrier widths per row
    // plus a complete small root allow sparse/split nodes without an exact
    // private-allocator model. The decoded Vec can coexist with this map.
    let cell = std::mem::size_of::<([u8; 32], Registration)>()
        .checked_add(8 * std::mem::size_of::<usize>())?;
    let map = map_rows.checked_mul(4)?.checked_add(16)?.checked_mul(cell)?;
    let scratch = encoded.checked_mul(6)?;
    let bytes = vector.checked_add(map)?.checked_add(scratch)?
        .checked_add(std::mem::size_of::<RegistrationDocument>())?;
    // The decoded registration rows coexist with the keyed certificate
    // registry. Vec growth, sparse BTree nodes and headers remain bytes.
    let entries = rows.checked_add(map_rows)?;
    Some((bytes, entries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn document() -> Value {
        json!({
            "version": 1,
            "peers": [{
                "certificate_sha256": vec![1_u8; 32],
                "principal": PrincipalId::from_bytes([2; 16]),
                "project": ProjectId::from_bytes([3; 16]),
            }],
        })
    }

    fn parse(document: &Value) -> Result<BTreeMap<[u8; 32], Registration>, PublicApiSessionError> {
        decode(&serde_json::to_vec(document).unwrap())
    }

    #[test]
    fn preserves_explicit_principal_and_project_binding() {
        let peers = parse(&document()).unwrap();

        assert_eq!(peers.len(), 1);
        assert_eq!(peers[&[1; 32]].principal, PrincipalId::from_bytes([2; 16]));
        assert_eq!(peers[&[1; 32]].project, ProjectId::from_bytes([3; 16]));
    }

    #[test]
    fn rejects_duplicate_certificate_even_for_identical_registration() {
        let mut document = document();
        let duplicate = document["peers"][0].clone();
        document["peers"].as_array_mut().unwrap().push(duplicate);

        assert!(parse(&document).is_err());
    }

    #[test]
    fn rejects_unknown_fields_at_both_schema_levels() {
        let mut top_level = document();
        top_level["authority"] = json!("administrator");
        let mut peer = document();
        peer["peers"][0]["authority"] = json!("administrator");

        assert!(parse(&top_level).is_err());
        assert!(parse(&peer).is_err());
    }

    #[test]
    fn rejects_empty_oversized_or_unknown_version_documents() {
        let mut empty = document();
        empty["peers"] = json!([]);
        let mut oversized = document();
        oversized["peers"] = json!(vec![
            oversized["peers"][0].clone();
            MAXIMUM_REGISTERED_PEERS + 1
        ]);
        let mut unsupported = document();
        unsupported["version"] = json!(2);

        for invalid in [empty, oversized, unsupported] {
            assert!(parse(&invalid).is_err());
        }
    }

    #[test]
    fn rejects_zero_identity_and_malformed_fingerprints() {
        for (field, value) in [
            ("certificate_sha256", json!(vec![0_u8; 32])),
            ("certificate_sha256", json!(vec![1_u8; 31])),
            ("certificate_sha256", json!(vec![1_u8; 33])),
            ("principal", json!(PrincipalId::from_bytes([0; 16]))),
            ("project", json!(ProjectId::from_bytes([0; 16]))),
        ] {
            let mut invalid = document();
            invalid["peers"][0][field] = value;

            assert!(parse(&invalid).is_err(), "accepted invalid {field}");
        }
    }
}
