//! Ordering and extent controls for borrowed device table admission.

use super::*;

fn decode<const MAX: u64>(
    bytes: &[u8],
    callback: &mut dyn FnMut(u64) -> Result<(), &'static str>,
) -> Result<BoundedVec<u64, MAX>, ciborium::de::Error<std::io::Error>> {
    let mut scratch = [0; 128];
    let admission = RefCell::new(callback);
    let seed = BoundedVecSeed::<_, MAX>::new(ValueSeed::<u64>::new(), &admission);
    ciborium::de::from_reader_with_buffer_seed(seed, bytes, &mut scratch)
}

#[test]
fn declared_max_refuses_before_table_or_member() {
    let mut calls = 0;
    let error = decode::<2>(&[0x83, 0xff], &mut |_| {
        calls += 1;
        Ok(())
    })
    .err()
    .unwrap();

    assert!(matches!(error, ciborium::de::Error::Semantic(_, _)));
    assert_eq!(calls, 0);
}

#[test]
fn typed_table_admission_precedes_malformed_first_member() {
    let mut requested = Vec::new();
    let error = decode::<4>(&[0x82, 0xff], &mut |bytes| {
        requested.push(bytes);
        Err("saved original refused table")
    })
    .err()
    .unwrap();

    assert_eq!(requested, [2 * std::mem::size_of::<u64>() as u64]);
    assert!(matches!(error, ciborium::de::Error::Semantic(_, message)
        if message == "saved original refused table"));
}

#[test]
fn indefinite_growth_admits_old_and_new_typed_tables() {
    let mut requested = Vec::new();
    let decoded = decode::<4>(&[0x9f, 1, 2, 3, 0xff], &mut |bytes| {
        requested.push(bytes);
        Ok(())
    })
    .unwrap();

    assert_eq!(decoded.as_slice(), [1, 2, 3]);
    assert_eq!(requested, [0, 8, 16, 32]);
}

#[test]
fn second_growth_refusal_preserves_callback_identity() {
    let mut requested = Vec::new();
    let error = decode::<4>(&[0x9f, 1, 2, 0xff], &mut |bytes| {
        requested.push(bytes);
        if bytes == 16 {
            Err("same original refused second table")
        } else {
            Ok(())
        }
    })
    .err()
    .unwrap();

    assert_eq!(requested, [0, 8, 16]);
    assert!(matches!(error, ciborium::de::Error::Semantic(_, message)
        if message == "same original refused second table"));
}
