//! VM-only physical held-snapshot tree measurement probe.
//!
//! This target is gated by `held-tree-fixture`; the production Storage package
//! neither builds nor installs it. Its JSON output is test evidence only and
//! cannot be decoded as a signed Storage or SourceProvider receipt.

use std::process::ExitCode;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_storage::{run_bound_held_snapshot_tree_fixture, run_held_snapshot_tree_fixture};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-sandbox-held-tree-fixture: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut arguments = std::env::args();
    let _program = arguments.next();
    let snapshot = arguments
        .next()
        .ok_or_else(|| "snapshot source is absent".to_owned())?;
    let expected = match arguments.next() {
        Some(value) => Some(
            value
                .parse::<ObjectDigest>()
                .map_err(|error| error.to_string())?,
        ),
        None => None,
    };
    let pool_guid = arguments.next();
    let snapshot_guid = arguments.next();
    if arguments.next().is_some() {
        return Err("expected snapshot, optional digest, and optional GUID pair".to_owned());
    }

    let report = match (expected, pool_guid, snapshot_guid) {
        (Some(digest), Some(pool), Some(snapshot_guid)) => {
            let pool = pool.parse::<u64>().map_err(|error| error.to_string())?;
            let snapshot_guid = snapshot_guid
                .parse::<u64>()
                .map_err(|error| error.to_string())?;
            run_bound_held_snapshot_tree_fixture(&snapshot, digest, pool, snapshot_guid)
        }
        (expected, None, None) => run_held_snapshot_tree_fixture(&snapshot, expected),
        _ => {
            return Err(
                "mounted GUID proof requires digest, pool GUID, and snapshot GUID".to_owned(),
            );
        }
    }
    .map_err(|error| error.to_string())?;
    println!("{report}");
    Ok(())
}
