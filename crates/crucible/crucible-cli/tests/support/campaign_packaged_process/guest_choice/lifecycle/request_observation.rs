//! Matches public request observations and retains their own execution failure.

use std::error::Error;

use serde_json::Value;

// The packaged producer bounds its diagnostic to 8 KiB, then appends a newline.
const MAX_FAILURE_RECORD_BYTES: usize = 8 * 1024 + 1;

/// Outcome for the exact public request/attempt/value association being awaited.
pub(super) enum Observation<'a> {
    Pending,
    Completed,
    TerminalFailure { execution: &'a str },
}

/// Classifies only an explanation belonging to the requested branch attempt.
///
/// # Errors
///
/// Returns an error if a matching terminal failure omits its canonical execution ID.
pub(super) fn classify<'a>(
    request: &str,
    attempt: &str,
    value: &str,
    explanation: &'a Value,
) -> Result<Observation<'a>, Box<dyn Error>> {
    // The page binds request/value/attempt; the explanation must independently
    // agree before its live execution phase can abort this branch's wait.
    if explanation["attempt"]["id"] != attempt
        || explanation["proposal"]["request"] != request
        || explanation["proposal"]["value"] != value
    {
        return Ok(Observation::Pending);
    }

    if !explanation["observation"].is_null() && explanation["runtime"]["phase"] == "completed" {
        return Ok(Observation::Completed);
    }
    if explanation["runtime"]["phase"] != "terminal-failure" {
        return Ok(Observation::Pending);
    }

    let execution = explanation["runtime"]["execution"]
        .as_str()
        .ok_or("matching public terminal failure omitted its execution ID")?;
    if execution.len() != 32
        || !execution
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("matching public terminal failure has a noncanonical execution ID".into());
    }
    Ok(Observation::TerminalFailure { execution })
}

/// Renders the matched public execution and its bounded operational diagnostic.
pub(super) fn failure_message(
    request: &str,
    attempt: &str,
    execution: &str,
    stderr: &str,
) -> String {
    let detail = execution_failure(stderr, execution)
        .unwrap_or("<matching execution diagnostic unavailable in bounded stderr capture>");
    format!(
        "request {request} attempt {attempt} execution {execution} reported terminal-failure; original execution diagnostic: {detail}"
    )
}

fn execution_failure<'a>(stderr: &'a str, execution: &str) -> Option<&'a str> {
    let prefix = format!("packaged campaign execution {execution} failed: ");
    let mut matched = None;
    let mut active = false;
    let mut offset = 0;

    for line in stderr.split_inclusive('\n') {
        // A partially written final record cannot supply original failure detail.
        if !line.ends_with('\n') {
            if active {
                matched = None;
            }
            break;
        }
        let end = offset + line.len();
        if line.starts_with(&prefix) {
            matched = Some((offset, end));
            active = true;
        } else if active
            && (line.starts_with("  caused by [")
                || line.starts_with("  ... source chain truncated")
                || line == "  ... diagnostic truncated\n")
        {
            matched = matched.filter(|(start, _)| end - start <= MAX_FAILURE_RECORD_BYTES);
            matched = matched.map(|(start, _)| (start, end));
            active = matched.is_some();
        } else {
            active = false;
        }
        offset = end;
    }

    matched
        .filter(|(start, end)| end - start <= MAX_FAILURE_RECORD_BYTES)
        .map(|(start, end)| &stderr[start..end])
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const EXECUTION: &str = "9a664940a44ffa4984786a01dc187b92";

    fn explanation(phase: &str) -> Value {
        json!({
            "attempt": {"id": "requested-attempt"},
            "proposal": {"request": "requested-branch", "value": "discrete:fast"},
            "observation": null,
            "runtime": {"phase": phase, "execution": EXECUTION},
        })
    }

    #[test]
    fn matching_terminal_failure_is_immediate_but_foreign_associations_remain_pending() {
        let matching = explanation("terminal-failure");
        assert!(matches!(
            classify(
                "requested-branch",
                "requested-attempt",
                "discrete:fast",
                &matching
            ),
            Ok(Observation::TerminalFailure {
                execution: EXECUTION
            })
        ));

        for (object, field) in [
            ("attempt", "id"),
            ("proposal", "request"),
            ("proposal", "value"),
        ] {
            let mut foreign = matching.clone();
            foreign[object][field] = json!("unrelated");
            assert!(matches!(
                classify(
                    "requested-branch",
                    "requested-attempt",
                    "discrete:fast",
                    &foreign
                ),
                Ok(Observation::Pending)
            ));
        }
    }

    #[test]
    fn completion_still_requires_an_observation_and_pending_phases_keep_waiting() {
        for phase in ["running", "paused", "publishing", "completed", "canceled"] {
            assert!(matches!(
                classify(
                    "requested-branch",
                    "requested-attempt",
                    "discrete:fast",
                    &explanation(phase)
                ),
                Ok(Observation::Pending)
            ));
        }
        let mut completed = explanation("completed");
        completed["observation"] = json!({"stop": "reached:next-choice"});
        assert!(matches!(
            classify(
                "requested-branch",
                "requested-attempt",
                "discrete:fast",
                &completed
            ),
            Ok(Observation::Completed)
        ));

        let mut invalid = explanation("terminal-failure");
        invalid["runtime"]["execution"] = json!("foreign or malformed execution");
        assert!(
            classify(
                "requested-branch",
                "requested-attempt",
                "discrete:fast",
                &invalid
            )
            .is_err()
        );
    }

    #[test]
    fn terminal_error_retains_only_the_exact_execution_original_cause_block() {
        let retained = format!(
            "packaged campaign execution {EXECUTION} failed: terminal execution failure\n  caused by [1]: post-device control boundary token 8154\n"
        );
        let stderr = format!(
            "packaged campaign execution 00000000000000000000000000000000 failed: unrelated\n  caused by [1]: foreign cause\n{retained}ordinary progress\n"
        );
        assert_eq!(
            execution_failure(&stderr, EXECUTION),
            Some(retained.as_str())
        );
        let message = failure_message("requested-branch", "requested-attempt", EXECUTION, &stderr);
        assert!(message.contains("requested-branch attempt requested-attempt"));
        assert!(message.contains(EXECUTION));
        assert!(message.contains(&retained));
        assert!(!message.contains("foreign cause"));

        assert!(execution_failure("unrelated diagnostic\n", EXECUTION).is_none());
        assert!(execution_failure(retained.trim_end_matches('\n'), EXECUTION).is_none());
        let truncated = format!("{retained}  ... diagnostic truncated\n");
        assert_eq!(
            execution_failure(&truncated, EXECUTION),
            Some(truncated.as_str())
        );
        let oversized = format!(
            "packaged campaign execution {EXECUTION} failed: {}\n",
            "x".repeat(MAX_FAILURE_RECORD_BYTES)
        );
        assert!(execution_failure(&oversized, EXECUTION).is_none());
        assert!(
            failure_message("requested-branch", "requested-attempt", EXECUTION, "")
                .contains("diagnostic unavailable")
        );
    }
}
