//! Bounded stale-only refresh for public lifecycle report observations.

use super::*;

pub(super) fn current_campaign_report(
    fixture: &FlightFixture,
    observed_snapshot: &str,
) -> Result<Value, Box<dyn Error>> {
    let output = refresh_stale_report(
        observed_snapshot.to_owned(),
        || json_string(&campaign_status(fixture)?, "snapshot"),
        |snapshot| {
            Ok(connected_campaign(fixture)
                .args(["report", CAMPAIGN, "--snapshot", snapshot, "--pages", "2"])
                .output()?)
        },
    )?;

    parse_json_output(output, "read campaign report")
}

fn refresh_stale_report<E>(
    mut snapshot: String,
    mut read_snapshot: impl FnMut() -> Result<String, E>,
    mut report: impl FnMut(&str) -> Result<Output, E>,
) -> Result<Output, E> {
    let mut attempts = 0;

    loop {
        let output = report(&snapshot)?;
        attempts += 1;

        // The report remains bound to one authenticated snapshot. Only an
        // explicit stale refusal permits reading a fresh head and trying again.
        if !is_stale_snapshot_response(&output) || attempts == MAX_STALE_BRANCH_RETRIES {
            return Ok(output);
        }
        snapshot = read_snapshot()?;
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::io;
    use std::os::unix::process::ExitStatusExt;

    use super::*;

    fn output(status: i32, stderr: &str) -> Output {
        Output {
            status: std::process::ExitStatus::from_raw(status << 8),
            stdout: b"{\"complete\":true}\n".to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    fn stale_output() -> Output {
        output(
            4,
            "campaign request used stale snapshot old; current snapshot is new\n",
        )
    }

    #[test]
    fn lifecycle_report_refreshes_only_after_an_explicit_stale_refusal() {
        let reads = Cell::new(0);
        let supplied = RefCell::new(Vec::new());
        let response: Result<_, io::Error> = refresh_stale_report(
            "observed".to_owned(),
            || {
                reads.set(reads.get() + 1);
                Ok("current".to_owned())
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

        assert!(response.expect("refreshed report").status.success());
        assert_eq!(reads.get(), 1);
        assert_eq!(*supplied.borrow(), ["observed", "current"]);
    }

    #[test]
    fn lifecycle_report_preserves_success_and_nonstale_refusals_without_refresh() {
        for original in [
            output(0, ""),
            output(4, "campaign service principal is not authorized"),
            output(4, "campaign service is temporarily unavailable"),
            output(0, "campaign request used stale snapshot"),
        ] {
            let response: Result<_, io::Error> = refresh_stale_report(
                "observed".to_owned(),
                || panic!("a nonstale response cannot refresh the head"),
                |snapshot| {
                    assert_eq!(snapshot, "observed");
                    Ok(original.clone())
                },
            );

            assert_eq!(response.expect("original output"), original);
        }
    }

    #[test]
    fn lifecycle_report_retains_the_eighth_stale_refusal() {
        let reads = Cell::new(0);
        let calls = Cell::new(0);
        let response: Result<_, io::Error> = refresh_stale_report(
            "observed".to_owned(),
            || {
                reads.set(reads.get() + 1);
                Ok(format!("current-{}", reads.get()))
            },
            |_| {
                calls.set(calls.get() + 1);
                Ok(output(
                    4,
                    &format!(
                        "campaign request used stale snapshot attempt {}",
                        calls.get()
                    ),
                ))
            },
        );

        assert_eq!(calls.get(), MAX_STALE_BRANCH_RETRIES);
        assert_eq!(reads.get(), MAX_STALE_BRANCH_RETRIES - 1);
        let error = parse_json_output(response.expect("finite refusal"), "read campaign report")
            .expect_err("churn remains a stale failure");
        assert!(error.to_string().contains("read campaign report"));
        assert!(error.to_string().contains("stale snapshot attempt 8"));
    }

    #[test]
    fn lifecycle_report_propagates_command_and_refresh_errors() {
        let command_error = refresh_stale_report(
            "observed".to_owned(),
            || panic!("failed commands cannot refresh the head"),
            |_| Err(io::Error::other("report transport failed")),
        )
        .expect_err("transport failure");
        assert_eq!(command_error.to_string(), "report transport failed");

        let refresh_error = refresh_stale_report(
            "observed".to_owned(),
            || Err(io::Error::other("head read failed")),
            |_| Ok(stale_output()),
        )
        .expect_err("head failure");
        assert_eq!(refresh_error.to_string(), "head read failed");
    }

    #[test]
    fn lifecycle_report_recovers_from_a_real_public_repository_stale_refusal()
    -> Result<(), Box<dyn Error>> {
        let fixture = FlightFixture::new()?;
        let generated = run_json(
            command(&[
                "--format",
                "jsonl",
                "campaign",
                "fixture",
                "worked-network",
                "--output",
            ])
            .arg(&fixture.fixture),
            "generate report fixture",
        )?;
        let manifest = json_path(&generated, "manifest")?;
        let mut service = fixture.start_service(Some(&manifest))?;
        run_json(
            connected_campaign(&fixture)
                .args(["create", CAMPAIGN, "--lineage"])
                .arg(json_path(&generated, "lineage")?)
                .arg("--policy")
                .arg(json_path(&generated, "policy")?)
                .args(["--start-command", START_COMMAND]),
            "create report campaign",
        )?;
        let observed = json_string(&campaign_status(&fixture)?, "snapshot")?;

        run_json(
            connected_campaign(&fixture).args([
                "pause",
                CAMPAIGN,
                "--expected",
                &observed,
                "--command",
                &"b1".repeat(32),
                "--active",
                "drain",
            ]),
            "advance the authentic report head",
        )?;
        let current = campaign_status(&fixture)?;
        assert_eq!(current["state"], "paused");
        assert_ne!(current["snapshot"], observed);
        let original_error = campaign_report(&fixture, &observed)
            .expect_err("the original public snapshot guard must refuse");
        assert!(
            original_error
                .to_string()
                .contains("campaign request used stale snapshot")
        );

        let report = current_campaign_report(&fixture, &observed)?;
        assert_eq!(report["snapshot"], current["snapshot"]);
        assert_eq!(report["complete"], true);
        service.stop()?;
        Ok(())
    }
}
