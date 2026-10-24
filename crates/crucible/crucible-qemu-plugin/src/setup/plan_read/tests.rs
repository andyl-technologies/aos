//! Exercises read progress and refusal ordering without issuing a native Source.
// SPDX-License-Identifier: GPL-2.0-only

#![allow(clippy::unwrap_used)]

use std::fs::File;
use std::os::unix::fs::FileExt;

use super::*;

const REFUSAL: StartupSourceError = StartupSourceError::NativeStatus {
    status: -libc::ECANCELED,
};

#[test]
fn interrupted_plan_read_rechecks_before_resuming_the_actual_file() {
    let file = File::open(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap();
    let mut expected = [0; 16];
    assert_eq!(file.read_at(&mut expected, 0).unwrap(), expected.len());
    let mut bytes = [0; 16];
    let mut checks = 0;
    let mut effects = 0;

    read_with(
        &mut bytes,
        || {
            checks += 1;
            Ok(())
        },
        |destination, offset| {
            effects += 1;
            if effects == 1 {
                return Err(libc::EINTR);
            }
            file.read_at(destination, offset as u64)
                .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))
        },
    )
    .unwrap();

    assert_eq!(bytes, expected);
    assert_eq!((checks, effects), (4, 2));
}

#[test]
fn interrupted_plan_read_keeps_first_errno_and_negative_post_without_retry() {
    let mut bytes = [0; 16];
    let mut checks = 0;
    let mut effects = 0;

    let result = read_with(
        &mut bytes,
        || {
            checks += 1;
            if checks == 2 { Err(REFUSAL) } else { Ok(()) }
        },
        |_, _| {
            effects += 1;
            Err(libc::EINTR)
        },
    );

    assert_eq!(
        result,
        Err(PluginSetupPlanDescriptorError::ReadOriginal {
            offset: 0,
            result: Err(libc::EINTR),
            original_after: REFUSAL,
        })
    );
    assert_eq!((checks, effects), (2, 1));
}

#[test]
fn partial_plan_read_stops_at_the_next_original_precheck() {
    let file = File::open(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap();
    let mut expected = [0; 2];
    assert_eq!(file.read_at(&mut expected, 0).unwrap(), expected.len());
    let mut bytes = [0; 16];
    let mut checks = 0;
    let mut effects = 0;

    let result = read_with(
        &mut bytes,
        || {
            checks += 1;
            if checks == 3 { Err(REFUSAL) } else { Ok(()) }
        },
        |destination, offset| {
            effects += 1;
            file.read_at(&mut destination[..2], offset as u64)
                .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))
        },
    );

    assert_eq!(
        result,
        Err(PluginSetupPlanDescriptorError::Original { source: REFUSAL })
    );
    assert_eq!(&bytes[..2], &expected);
    assert_eq!(&bytes[2..], &[0; 14]);
    assert_eq!((checks, effects), (3, 1));
}

#[test]
fn plan_read_first_error_and_negative_post_are_both_retained() {
    for first in [Err(libc::EIO), Ok(0)] {
        let mut bytes = [0; 16];
        let mut checks = 0;
        let mut effects = 0;

        let result = read_with(
            &mut bytes,
            || {
                checks += 1;
                if checks == 2 { Err(REFUSAL) } else { Ok(()) }
            },
            |_, _| {
                effects += 1;
                first
            },
        );

        assert_eq!(
            result,
            Err(PluginSetupPlanDescriptorError::ReadOriginal {
                offset: 0,
                result: first,
                original_after: REFUSAL,
            })
        );
        assert_eq!((checks, effects), (2, 1));
    }
}

#[test]
fn plan_read_precheck_refusal_performs_no_file_effect() {
    let mut bytes = [0; 16];
    let mut effects = 0;

    let result = read_with(
        &mut bytes,
        || Err(REFUSAL),
        |_, _| {
            effects += 1;
            Ok(16)
        },
    );

    assert_eq!(
        result,
        Err(PluginSetupPlanDescriptorError::Original { source: REFUSAL })
    );
    assert_eq!(effects, 0);
    assert_eq!(bytes, [0; 16]);
}

#[test]
fn completed_plan_read_negative_post_keeps_actual_progress() {
    let file = File::open(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap();
    let mut expected = [0; 16];
    assert_eq!(file.read_at(&mut expected, 0).unwrap(), expected.len());
    let mut bytes = [0; 16];
    let mut checks = 0;
    let mut effects = 0;

    let result = read_with(
        &mut bytes,
        || {
            checks += 1;
            if checks == 2 { Err(REFUSAL) } else { Ok(()) }
        },
        |destination, offset| {
            effects += 1;
            file.read_at(destination, offset as u64)
                .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))
        },
    );

    assert_eq!(
        result,
        Err(PluginSetupPlanDescriptorError::ReadOriginal {
            offset: 0,
            result: Ok(16),
            original_after: REFUSAL,
        })
    );
    assert_eq!(bytes, expected);
    assert_eq!((checks, effects), (2, 1));
}
