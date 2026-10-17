//! Bounded stale-snapshot refresh for public lifecycle drain-pause commands.

use super::*;

pub(super) fn pause_running_campaign(
    fixture: &FlightFixture,
    command_identity: &str,
    operation: &str,
) -> Result<Value, Box<dyn Error>> {
    let output = refresh_stale_pause(
        || json_string(&campaign_status(fixture)?, "snapshot"),
        |snapshot| {
            Ok(connected_campaign(fixture)
                .args([
                    "pause",
                    CAMPAIGN,
                    "--expected",
                    snapshot,
                    "--command",
                    command_identity,
                    "--active",
                    "drain",
                ])
                .output()?)
        },
    )?;

    parse_json_output(output, operation)
}

fn refresh_stale_pause<E>(
    mut read_snapshot: impl FnMut() -> Result<String, E>,
    mut pause: impl FnMut(&str) -> Result<std::process::Output, E>,
) -> Result<std::process::Output, E> {
    let mut attempts = 0;

    loop {
        let snapshot = read_snapshot()?;
        let output = pause(&snapshot)?;
        attempts += 1;

        // Live feedback can advance the head before the command reaches the
        // service. Stale refusal precedes command publication, so only that
        // response permits a fresh expected snapshot with the same command ID.
        if !is_stale_snapshot_response(&output) || attempts == MAX_STALE_BRANCH_RETRIES {
            // Preserve the actual final refusal and original operation label,
            // including when the finite refresh allowance has been exhausted.
            return Ok(output);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::io;
    use std::os::unix::process::ExitStatusExt;

    use super::*;

    fn output(status: i32, stderr: &str) -> std::process::Output {
        std::process::Output {
            status: std::process::ExitStatus::from_raw(status << 8),
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    fn stale_output() -> std::process::Output {
        output(
            4,
            "crucible: campaign pause failed: campaign request used stale snapshot old; current snapshot is new\n",
        )
    }

    #[test]
    fn drain_pause_reads_a_fresh_snapshot_only_after_explicit_stale_refusal() {
        let reads = Cell::new(0);
        let supplied = RefCell::new(Vec::new());

        let result: Result<_, io::Error> = refresh_stale_pause(
            || {
                reads.set(reads.get() + 1);
                Ok(format!("snapshot-{}", reads.get()))
            },
            |snapshot| {
                supplied.borrow_mut().push(snapshot.to_owned());
                Ok(if supplied.borrow().len() == 1 {
                    stale_output()
                } else {
                    output(0, "")
                })
            },
        );

        assert!(result.expect("bounded refresh").status.success());
        assert_eq!(reads.get(), 2);
        assert_eq!(*supplied.borrow(), ["snapshot-1", "snapshot-2"]);
    }

    #[test]
    fn drain_pause_preserves_nonstale_failures_without_refreshing() {
        for original in [
            output(
                4,
                "crucible: campaign pause failed: campaign service is temporarily unavailable\n",
            ),
            output(4, "crucible: campaign pause failed: permission denied\n"),
            output(0, "campaign request used stale snapshot"),
        ] {
            let reads = Cell::new(0);
            let calls = Cell::new(0);

            let result: Result<_, io::Error> = refresh_stale_pause(
                || {
                    reads.set(reads.get() + 1);
                    Ok("snapshot".to_owned())
                },
                |_| {
                    calls.set(calls.get() + 1);
                    Ok(original.clone())
                },
            );

            assert_eq!(result.expect("original response"), original);
            assert_eq!(reads.get(), 1);
            assert_eq!(calls.get(), 1);
        }
    }

    #[test]
    fn drain_pause_preserves_eighth_stale_response_at_the_existing_bound() {
        let reads = Cell::new(0);
        let calls = Cell::new(0);

        let result: Result<_, io::Error> = refresh_stale_pause(
            || {
                reads.set(reads.get() + 1);
                Ok(format!("snapshot-{}", reads.get()))
            },
            |_| {
                calls.set(calls.get() + 1);
                Ok(stale_output())
            },
        );

        let response = result.expect("finite refusal");
        assert_eq!(response, stale_output());
        assert_eq!(reads.get(), MAX_STALE_BRANCH_RETRIES);
        assert_eq!(calls.get(), MAX_STALE_BRANCH_RETRIES);
        let error = parse_json_output(response, "pause resumed campaign before bounded expansion")
            .expect_err("last authenticated stale response remains a failure");
        assert!(
            error
                .to_string()
                .contains("campaign request used stale snapshot")
        );
        assert!(
            error
                .to_string()
                .contains("pause resumed campaign before bounded expansion")
        );
    }
}
