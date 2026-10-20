//! Opt-in advisory retention before an adopted child's target storage is released.
//!
//! Private stderr and the pinned native log file are distinct artifacts. API
//! identity labels name the retained owner; they do not authenticate native
//! row origin or turn diagnostic fields into canonical receipts.

use std::io::Write;

use super::*;

pub(super) fn live_diagnostics_enabled() -> bool {
    live_diagnostics_enabled_from(
        std::env::var_os("CRUCIBLE_CONTROL_CALLBACK_WITNESS").as_deref(),
        std::env::var_os("CRUCIBLE_RR_CLAMP_TAIL").as_deref(),
    )
}

fn live_diagnostics_enabled_from(
    callback: Option<&std::ffi::OsStr>,
    trace: Option<&std::ffi::OsStr>,
) -> bool {
    [callback, trace]
        .into_iter()
        .any(|setting| setting == Some(std::ffi::OsStr::new("1")))
}

pub(super) fn observe_live_diagnostics<'a>(
    enabled: bool,
    consumer: impl FnOnce() -> Option<&'a mut QemuHotForkChildDiagnosticConsumer>,
) {
    if !enabled {
        return;
    }
    let Some(consumer) = consumer() else {
        return;
    };
    if consumer.live_drain_error().is_none() {
        // The exact consumer retains its first failure for reporting and release.
        // Diagnostics never replace the operation or resource-guard result.
        let _drain_result = consumer.drain_available_bounded();
    }
}

impl<G> LinuxQemuHotForkReconciliationBackend<G>
where
    G: crate::QemuAttemptResourceGuard,
{
    pub(super) fn report_child_diagnostics(
        &self,
        identity: &ProductionVmNodeGeneration,
        complete: bool,
    ) {
        let callback_enabled = std::env::var_os("CRUCIBLE_CONTROL_CALLBACK_WITNESS").as_deref()
            == Some(std::ffi::OsStr::new("1"));
        let trace_enabled = std::env::var_os("CRUCIBLE_RR_CLAMP_TAIL").as_deref()
            == Some(std::ffi::OsStr::new("1"));
        if !callback_enabled && !trace_enabled {
            return;
        }

        let node = identity.node().name.chars().take(80).collect::<String>();
        let pid = self.basis.child_process_id();
        // Ignore diagnostic sink errors; reconciliation retains its original result.
        let mut sink = std::io::stderr().lock();
        if let Some(error) = self.diagnostics_consumer.live_drain_error() {
            // crucible-lint: allow direct-diagnostic -- sticky loss remains advisory and cannot replace the original runtime result.
            let _report_result = writeln!(
                sink,
                "CRUCIBLE-HOT-FORK-STDERR-LOSS-V1 node={node:?} generation={} owner_pid={pid} retention_complete=false error={error:?}",
                identity.generation(),
            );
        }
        if callback_enabled {
            let summary = match &self.diagnostics {
                Some(capture) => capture.control_diagnostics_summary(pid),
                None => self.diagnostics_consumer.control_diagnostics_summary(pid),
            };
            // crucible-lint: allow direct-diagnostic -- bounded advisory rows expose an exact owned child capture without changing execution.
            let _report_result = writeln!(
                sink,
                "CRUCIBLE-HOT-FORK-STDERR-TAIL-V1 node={node:?} generation={} owner_pid={pid} capture_complete={complete} stream=private-stderr advisory=true\n{summary}",
                identity.generation(),
            );
        }
        if !trace_enabled || !complete {
            // Error paths may inspect retained bytes only, without reopening storage.
            return;
        }

        let summary = self
            .run_directory
            .as_ref()
            .map(|directory| directory.summarize_rr_control_boundary_trace_after_reap());
        match summary {
            Some(Ok(summary)) => {
                for (index, row) in summary.lines().enumerate() {
                    if index == 0 {
                        // crucible-lint: allow direct-diagnostic -- identity labels name the file owner, while row origin remains explicitly unproven.
                        let _report_result = writeln!(
                            sink,
                            "CRUCIBLE-RR-CLAMP-TAIL-V2 node={node:?} generation={} owner_pid={pid} artifact=prepared-target-file row_origin=unproven authenticated_full=true {row}",
                            identity.generation(),
                        );
                    } else {
                        // crucible-lint: allow direct-diagnostic -- the existing authenticated reader bounds this advisory tail to 32 schema-checked rows.
                        let _report_result = writeln!(
                            sink,
                            "CRUCIBLE-RR-CLAMP-ROW-V2 node={node:?} owner_pid={pid} row_origin=unproven {row}"
                        );
                    }
                }
            }
            Some(Err(error)) => {
                // crucible-lint: allow direct-diagnostic -- trace absence or refusal is advisory and cannot replace cleanup errors.
                let _report_result = writeln!(
                    sink,
                    "CRUCIBLE-RR-CLAMP-TAIL-V2 node={node:?} generation={} owner_pid={pid} artifact=prepared-target-file error={error}",
                    identity.generation(),
                );
            }
            None => {
                // crucible-lint: allow direct-diagnostic -- an unavailable pinned artifact is reported without reconstituting authority.
                let _report_result = writeln!(
                    sink,
                    "CRUCIBLE-RR-CLAMP-TAIL-V2 node={node:?} generation={} owner_pid={pid} artifact=prepared-target-file error=run-directory-unavailable",
                    identity.generation(),
                );
            }
        }
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;

    #[test]
    fn disabled_admission_never_borrows_the_owned_consumer() {
        for setting in [
            None,
            Some(""),
            Some("0"),
            Some("01"),
            Some("true"),
            Some("1 "),
        ] {
            let setting = setting.map(std::ffi::OsStr::new);
            let enabled = live_diagnostics_enabled_from(setting, setting);
            assert!(!enabled);
            observe_live_diagnostics(enabled, || {
                panic!("disabled diagnostics must not borrow or read its consumer")
            });
        }
        assert!(live_diagnostics_enabled_from(
            Some(std::ffi::OsStr::new("1")),
            None
        ));
        assert!(live_diagnostics_enabled_from(
            None,
            Some(std::ffi::OsStr::new("1"))
        ));

        let mut called = false;
        observe_live_diagnostics(true, || {
            called = true;
            None
        });
        assert!(called);
    }
}
