//! Shares helper invocation ordering across immediate readers and retained roles.
//!
//! A native destination determines custody; the recipe determines the same
//! before/run/status/after order. Independent posts after entered selected
//! work do not depend on primary success. No payer or authority lives here.

use super::*;

pub(crate) trait FixedHelperNativeV4 {
    type Error;

    fn before(&mut self) -> Result<(), Self::Error>;
    fn run(&mut self) -> Result<(), Self::Error>;
    fn status(&mut self) -> Result<(), Self::Error>;
    fn after(&mut self) -> Result<(), Self::Error>;
    fn independent_after(&self) -> bool;
}

pub(crate) fn run_fixed_helper_recipe_v4<N: FixedHelperNativeV4>(
    native: &mut N,
) -> Result<(), N::Error> {
    native.before()?;
    let run = native.run();
    if native.independent_after() {
        // A negative completed status precedes the later independently owed
        // artifact post. The post still runs on every entered process result.
        let primary = run.and_then(|()| native.status());
        let after = native.after();
        primary?;
        after
    } else {
        // Immediate callers preserve their historical short-circuit order.
        run?;
        native.after()?;
        native.status()
    }
}

pub(super) fn run_artifact_local_v4(
    artifact: &PinnedArtifact,
    arguments: &[OsString],
    maximum_stdout_bytes: usize,
) -> Result<FixedProcessOutcome, NetworkKernelReaderError> {
    let mut native = LocalArtifactRunV4 {
        artifact,
        arguments,
        maximum_stdout_bytes,
        outcome: None,
    };
    run_fixed_helper_recipe_v4(&mut native)?;
    native.outcome.ok_or(NetworkKernelReaderError::HelperFailed)
}

struct LocalArtifactRunV4<'held> {
    artifact: &'held PinnedArtifact,
    arguments: &'held [OsString],
    maximum_stdout_bytes: usize,
    outcome: Option<FixedProcessOutcome>,
}

impl FixedHelperNativeV4 for LocalArtifactRunV4<'_> {
    type Error = NetworkKernelReaderError;

    fn before(&mut self) -> Result<(), Self::Error> {
        self.artifact.validate_current()
    }

    fn run(&mut self) -> Result<(), Self::Error> {
        self.outcome = Some(run_fixed_process(FixedProcessRequest {
            executable: self.artifact.path(),
            arguments: self.arguments,
            timeout: HELPER_TIMEOUT,
            maximum_stdout_bytes: self.maximum_stdout_bytes,
            maximum_stderr_bytes: MAXIMUM_HELPER_STDERR_BYTES,
        })?);
        Ok(())
    }

    fn status(&mut self) -> Result<(), Self::Error> {
        // The reader's existing semantic decoder still consumes the complete
        // outcome and decides status. This facade does not discard it early.
        Ok(())
    }

    fn after(&mut self) -> Result<(), Self::Error> {
        self.artifact.validate_current()
    }

    fn independent_after(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EnteredFailure {
        selected: bool,
        calls: Vec<&'static str>,
    }

    impl FixedHelperNativeV4 for EnteredFailure {
        type Error = u8;

        fn before(&mut self) -> Result<(), u8> {
            self.calls.push("before");
            Ok(())
        }

        fn run(&mut self) -> Result<(), u8> {
            self.calls.push("run");
            Err(1)
        }

        fn status(&mut self) -> Result<(), u8> {
            self.calls.push("status");
            Ok(())
        }

        fn after(&mut self) -> Result<(), u8> {
            self.calls.push("after");
            Err(2)
        }

        fn independent_after(&self) -> bool {
            self.selected
        }
    }

    #[test]
    fn selected_and_immediate_callers_share_recipe_with_exact_owed_post_order() {
        let mut selected = EnteredFailure {
            selected: true,
            calls: Vec::new(),
        };
        assert_eq!(run_fixed_helper_recipe_v4(&mut selected), Err(1));
        assert_eq!(selected.calls, ["before", "run", "after"]);

        let mut immediate = EnteredFailure {
            selected: false,
            calls: Vec::new(),
        };
        assert_eq!(run_fixed_helper_recipe_v4(&mut immediate), Err(1));
        assert_eq!(immediate.calls, ["before", "run"]);
    }
}
