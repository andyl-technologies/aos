//! Compares actual shared generic rows with the retained original algorithm.

use super::*;

#[path = "original.rs"]
mod original;

fn observation(value: Result<usize, ProviderError>) -> Result<usize, String> {
    value.map_err(|error| error.to_string())
}

#[test]
fn generic_scan_keeps_independent_phase_tax_and_original_refusals()
-> Result<(), Box<dyn std::error::Error>> {
    let value_node = map_node(
        size_of::<String>() + size_of::<Value>(),
        align_of::<Value>(),
    )?;
    assert_eq!(
        value_node,
        original::map_node(
            size_of::<String>() + size_of::<Value>(),
            align_of::<Value>()
        )?
    );

    for raw in [
        b"{}".as_slice(),
        b"[]",
        b"null",
        b"0",
        br#""""#,
        br#"{"a":[0,1,{},[]],"a":{"escaped":"\u0000\n\"\\"}}"#,
        b"",
        b"[",
        b"{]",
        br#""unfinished"#,
        b"\"trailing\\",
    ] {
        for maximum in [raw.len().saturating_sub(1), raw.len(), usize::MAX] {
            for (dom, typed, canonical) in [(1, 1, 1), (3, 1, 2), (2, 0, 1)] {
                let actual =
                    scan(raw, maximum, size_of::<Value>(), value_node).and_then(|credit| {
                        credit.requested(&Phases {
                            dom,
                            typed,
                            canonical,
                        })
                    });
                let old = original::scan(raw, maximum, size_of::<Value>(), value_node).and_then(
                    |credit| {
                        credit.requested(&original::Phases {
                            dom,
                            typed,
                            canonical,
                        })
                    },
                );
                assert_eq!(observation(actual), observation(old));
            }
        }
    }

    let raw = b"{}";
    let row = scan(raw, raw.len(), size_of::<Value>(), value_node)?.requested(&Phases {
        dom: 1,
        typed: 1,
        canonical: 1,
    })?;
    assert!(row > raw.len());
    let depth64 = format!("{}null{}", "[".repeat(64), "]".repeat(64));
    let depth65 = format!("[{}]", depth64);
    assert!(scan(depth64.as_bytes(), usize::MAX, 1, value_node).is_ok());
    assert!(scan(depth65.as_bytes(), usize::MAX, 1, value_node).is_err());
    assert!(scan(raw, usize::MAX, 0, value_node).is_err());
    assert!(scan(raw, usize::MAX, usize::MAX, value_node).is_err());
    Ok(())
}

#[test]
fn native_dto_and_value_rows_preserve_independent_original_boundaries()
-> Result<(), Box<dyn std::error::Error>> {
    for raw in [
        b"{}".as_slice(),
        b"[]",
        b"0",
        br#"{"a":[{},{}],"b":{"c":"x"}}"#,
    ] {
        let dto = selected_native_dto_decode_storage_data(raw, size_of::<Value>(), usize::MAX)?;
        let value = selected_value_decode_storage_data(raw, usize::MAX)?;
        for maximum in [
            raw.len().saturating_sub(1),
            dto - 1,
            dto,
            value - 1,
            value,
            usize::MAX,
        ] {
            assert_eq!(
                observation(selected_native_dto_decode_storage_data(
                    raw,
                    size_of::<Value>(),
                    maximum
                )),
                observation(original::selected_native_dto_decode_storage_data(
                    raw,
                    size_of::<Value>(),
                    maximum
                )),
            );
            assert_eq!(
                observation(selected_value_decode_storage_data(raw, maximum)),
                observation(original::selected_value_decode_storage_data(raw, maximum)),
            );
        }
    }
    Ok(())
}
