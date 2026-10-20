//! Checks the public DRV-21 memo data contract without recipe or authority claims.

use super::support::{Generator, cbor_properties};
use terrane_format::derivation::Memo;

fn frame(recipe: &[u8], root: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0xa2, 1, 0x58, recipe.len() as u8];
    bytes.extend_from_slice(recipe);
    bytes.extend_from_slice(&[2, 0x58, root.len() as u8]);
    bytes.extend_from_slice(root);
    bytes
}

#[test]
fn common_memo_models_preserve_fields_and_distinct_record_identity() {
    let mut generator = Generator::new(0x3789_423b_afe1_622d);
    for sample in 0..64 {
        let recipe = match sample {
            0 => [0; 32],
            1 => [255; 32],
            _ => generator.bytes(),
        };
        let root = generator.bytes();
        let expected = frame(&recipe, &root);
        let memo = Memo::new(recipe, root);

        assert_eq!(expected.len(), 71);
        assert_eq!(memo.encode(), expected);
        assert_eq!(Memo::decode(&expected).unwrap(), memo);
        assert_eq!(memo.recipe_hash(), recipe);
        assert_eq!(memo.result_root(), root);
        let mut preimage = b"terrane-memo-v1\0".to_vec();
        preimage.extend_from_slice(&expected);
        assert_eq!(
            memo.identity().unwrap(),
            *blake3::hash(&preimage).as_bytes()
        );
        assert_ne!(memo.identity().unwrap(), recipe);
        cbor_properties("common memo", &expected, |bytes| {
            Memo::decode(bytes).map(|decoded| decoded.encode())
        });
    }
}

#[test]
fn common_memo_refuses_independent_schema_and_hostile_length_models() {
    for length in [0, 1, 31, 33, 64] {
        assert!(Memo::decode(&frame(&vec![0; length], &[1; 32])).is_err());
        assert!(Memo::decode(&frame(&[0; 32], &vec![1; length])).is_err());
    }
    let mut unknown = frame(&[0; 32], &[1; 32]);
    unknown[1] = 3;
    assert!(Memo::decode(&unknown).is_err());
    let mut duplicate = frame(&[0; 32], &[1; 32]);
    duplicate[36] = 1;
    assert!(Memo::decode(&duplicate).is_err());
    for bytes in [
        vec![0xbf, 0xff],
        vec![0xa2, 1, 0x5b, 255, 255, 255, 255, 255, 255, 255, 255],
        vec![0xbb, 255, 255, 255, 255, 255, 255, 255, 255],
        vec![0; 72],
    ] {
        assert!(Memo::decode(&bytes).is_err());
    }
}
