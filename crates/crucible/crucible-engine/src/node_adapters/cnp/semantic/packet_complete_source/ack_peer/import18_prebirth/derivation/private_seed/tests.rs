//! Checks original operand commitment framing without issuing a seed or grant.

use super::*;
use crucible_node_format::{HashRef, U64};

fn host() -> ContentRef {
    ContentRef {
        hash: HashRef {
            algorithm: "blake3-256".into(),
            domain: "cnp.blob.v1".into(),
            digest: "0".repeat(64),
        },
        length: U64::new(1),
        media_type: "application/octet-stream".into(),
    }
}

#[test]
fn private_host_commitment_binds_all_original_reference_fields() {
    let host = host();
    let original = host_reference_identity(&host).unwrap();
    for field in 0..5 {
        let mut changed = host.clone();
        match field {
            0 => changed.hash.algorithm.push('x'),
            1 => changed.hash.domain.push('x'),
            2 => changed.hash.digest.replace_range(0..1, "1"),
            3 => changed.media_type.push('x'),
            _ => changed.length = U64::new(2),
        }
        assert_ne!(host_reference_identity(&changed).unwrap(), original);
    }
    let mut ambiguous = host.clone();
    ambiguous.hash.algorithm = "blake3-256cnp.".into();
    ambiguous.hash.domain = "blob.v1".into();
    assert_ne!(host_reference_identity(&ambiguous).unwrap(), original);
    assert_eq!(host_reference_identity(&host.clone()).unwrap(), original);
}

#[test]
fn genuine_ordinary_sources_refuse_seed_without_spending_or_rebinding() {
    use crate::node_adapters::cnp::semantic::packet_complete_source::tests as fixture;

    for reactive in [false, true] {
        let coordinator = fixture::coordinator();
        let mut source = if reactive {
            PacketCompleteSemanticSource::new_reactive_for_collecting_world(
                fixture::installation(&coordinator, 1),
                fixture::reactive(&coordinator, 1),
                coordinator,
                fixture::storage_selection(),
            )
            .unwrap()
        } else {
            PacketCompleteSemanticSource::new_producer_for_collecting_world(
                fixture::installation(&coordinator, 0),
                fixture::producer(),
                coordinator,
                fixture::storage_selection(),
            )
            .unwrap()
        };
        let expected = host();

        assert!(
            source
                .native_import18_private_seed_construction_data(&expected, usize::MAX)
                .is_err()
        );
        assert!(
            source
                .prepare_native_import18_private_seed_into(&expected)
                .is_err()
        );
        assert!(
            source
                .native_import18_private_birth_construction_data(usize::MAX)
                .is_err()
        );
        assert!(source.prepare_native_import18_private_birth_into().is_err());
        assert!(source.native_import18_source_declaration_data().is_err());
        assert!(
            source
                .native_import18_original_mapping_nonce_data()
                .is_err()
        );
        assert!(
            source
                .native_import18_declaration_encoding_construction_data(usize::MAX)
                .is_err()
        );
        let mut encoded = None;
        assert!(
            source
                .encode_native_import18_source_declaration_into_data(usize::MAX, &mut encoded)
                .is_err()
        );
        assert!(encoded.is_none());
        let mut occupied = Some(b"original DATA".to_vec());
        assert!(
            source
                .encode_native_import18_source_declaration_into_data(usize::MAX, &mut occupied)
                .is_err()
        );
        assert_eq!(occupied.as_deref(), Some(b"original DATA".as_slice()));
        assert!(source.native_import18_derivation.is_none());
        assert!(source.native_import18_derivation_mechanism.is_none());
        assert!(source.native_import18_birth_construction.is_none());
        assert!(!source.ack_birth_attempted);
        assert_eq!(source.isolated_derivation_known_backing_data(0), Ok(0));
    }
}
