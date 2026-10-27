//! Checks shared geometry limits without manufacturing native authority.

use super::*;
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn exact_component_ceiling_and_one_short_refuse_the_same_completed_shape() -> TestResult {
    let purpose = json!({"purpose":"original_execution","source":null,"target":{}});
    let quote = |maximum| {
        InvocationConstructionShape::new(&purpose, maximum)?.finish(32, 4096, 8192, 128, maximum)
    };
    let row = quote(usize::MAX)?;
    let maximum = [
        row.native_retained_requested_bytes(),
        row.native_transient_requested_bytes(),
        row.private_retained_requested_bytes(),
        row.private_transient_requested_bytes(),
        row.source_finalization_requested_bytes(),
        row.wire_growth_requested_bytes(),
        row.maximum_private_boot_body_bytes(),
    ]
    .into_iter()
    .max()
    .ok_or("missing geometry component")?;
    let exact = quote(maximum)?;
    assert_eq!(
        row.native_retained_requested_bytes(),
        exact.native_retained_requested_bytes()
    );
    assert!(quote(maximum - 1).is_err());
    Ok(())
}

#[test]
fn actual_extent_subtraction_overflow_and_both_absolute_frame_ceilings_refuse() -> TestResult {
    let purpose = json!({"purpose":"original_execution","source":null,"target":{}});
    for (nested, wrapper, boot, typed) in [
        (4096, 4095, 8192, 128),
        (32, 1024 * 1024 + 1, 8192, 128),
        (32, 4096, 512 * 1024, 128),
        (32, 4096, 8192, usize::MAX),
        (32, 4096, usize::MAX, 128),
    ] {
        assert!(
            InvocationConstructionShape::new(&purpose, usize::MAX)?
                .finish(nested, wrapper, boot, typed, usize::MAX)
                .is_err()
        );
    }
    Ok(())
}
