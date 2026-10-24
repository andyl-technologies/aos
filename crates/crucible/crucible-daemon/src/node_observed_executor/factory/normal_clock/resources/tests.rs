//! Checks ceiling arithmetic without installing limits or creating quota owners.

use super::*;

#[test]
fn bounded_process_ceiling_refuses_unlimited_and_one_over() {
    let exact = Rlimit {
        current: Some(17),
        maximum: Some(17),
    };
    assert_eq!(bounded(exact, 17), Ok(()));
    assert_eq!(bounded(exact, 16), Err(RuntimeError::ResourceLimit));
    assert_eq!(
        bounded(
            Rlimit {
                current: None,
                maximum: Some(17)
            },
            17
        ),
        Err(RuntimeError::ResourceLimit)
    );
    assert_eq!(
        bounded(
            Rlimit {
                current: Some(17),
                maximum: None
            },
            17
        ),
        Err(RuntimeError::ResourceLimit)
    );
    assert_eq!(
        bounded(
            Rlimit {
                current: Some(18),
                maximum: Some(17)
            },
            18
        ),
        Err(RuntimeError::ResourceLimit)
    );
    assert_eq!(
        bounded(
            Rlimit {
                current: Some(0),
                maximum: Some(0)
            },
            0
        ),
        Err(RuntimeError::ResourceLimit)
    );
}
