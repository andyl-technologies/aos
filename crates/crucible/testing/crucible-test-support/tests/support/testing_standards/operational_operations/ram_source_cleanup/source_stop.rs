//! Reviews only the saved-Cleanup wait around actual native worker return.
//!
//! Complete stop and outcome paths retain their original history and physical
//! owner. Existing caller, Original and native-join companions remain required;
//! this source classification supplies no Native or cached-stack return proof.

use super::super::Contract;

pub(super) const CONTRACT: Contract = Contract {
    package: "crucible-qemu-host",
    target: "src/ram_source/stop",
    required: &[
        (
            r#"pub fn stop(
        &mut self,
        original: Option<crate::ram_control::RamCleanupOriginal<'_>>,
    ) -> (bool, Result<(), QemuRamSourceStopHistory>) {
        if self
            .worker
            .as_ref()
            .is_some_and(|worker| !worker.native.belongs_to_current_process())
        {
            self.stop
                .history
                .native
                .get_or_insert(NativeJoinError::ForeignProcess);
            return (false, Err(self.stop.journal.snapshot(&self.stop.history)));
        }
        if self.stop.history.birth != (self.birth_before, self.birth_after) {
            self.stop.history.birth = (self.birth_before, self.birth_after);
            self.stop.version += 1;
        }
        if !self.spawn_attempted {
            self.failure.no_birth(None);
            self.stop.join_returned = true;
            self.capture_returned_outcome();
            return self.stop_observation();
        }
        if self.spawn_returned && !self.worker_started {
            self.stop.join_returned = true;
            self.capture_returned_outcome();
            return self.stop_observation();
        }
        if !self.stop.cancel_entered {
            let before = self.stop_original_check(original).err();
            self.stop.observe(0, false, before);
            self.stop.cancel_entered = true;
            self.cancellation.store(true, Ordering::Release);
            if let Err(first) = self.wake.shutdown(Shutdown::Both) {
                self.stop.history.cancellation = Some(BackendOperationalCause::new(first));
                self.stop.version += 1;
            }
            self.stop.cancel_returned = true;
            let after = self.stop_original_check(original).err();
            self.stop.observe(0, true, after);
        }
        if !self.stop.cancel_returned {
            if !self.stop.history.uncertain {
                self.stop.history.uncertain = true;
                self.stop.version += 1;
            }
            return self.stop_observation();
        }

        loop {
            if self.stop.join_returned {
                self.capture_returned_outcome();
                return self.stop_observation();
            }
            let before = self.stop_original_check(original).err();
            self.stop.observe(2, false, before);
            let observed = match self.worker.as_mut() {
                Some(worker) => {
                    let observed = worker.native.poll();
                    self.stop.history.native_status = worker.native.last_status();
                    observed
                }
                None => Err(NativeJoinError::MissingOwner),
            };
            match observed {
                Ok(NativeJoinObservation::Returned) => {
                    // The native owner latched zero before this independent
                    // status and result observation; no subsequent poll joins.
                    self.stop.join_returned = true;
                    if let Some(join) = &mut self.launch_join {
                        join.joined();
                    }
                    self.capture_returned_outcome();
                    drop(self.worker.take());
                }
                Ok(NativeJoinObservation::Pending) => {}
                Err(first) => {
                    if self.stop.history.native.is_none() {
                        self.stop.history.native = Some(first);
                        self.stop.version += 1;
                    }
                }
            }
            let after = self.stop_original_check(original).err();
            self.stop.observe(2, true, after);
            if self.stop.join_returned
                || self.stop.history.native.is_some()
                || before.is_some()
                || after.is_some()
            {
                return self.stop_observation();
            }

            let before = self.stop_original_check(original);
            self.stop.observe(1, false, before.as_ref().err().copied());
            if let Ok(slice) = before {"#,
            1,
        ),
        (
            r#"}
            let after = self.stop_original_check(original);
            self.stop.observe(1, true, after.as_ref().err().copied());
            if before.is_err() || after.is_err() {
                // No effect follows refused entry. The independently evaluated
                // post is retained even when the precheck already refused.
                return self.stop_observation();
            }
        }
    }"#,
            1,
        ),
        (
            r#"fn capture_returned_outcome(&mut self) {
        if self.stop.outcome_captured {
            return;
        }
        let outcome = match self.worker.as_ref() {
            Some(worker) => worker.outcome.snapshot(),
            None => self.failure.snapshot(),
        };
        if let Some(first) = outcome.failure
            && self.stop.history.worker.is_none()
        {
            self.stop.history.worker = Some(first);
            self.stop.version += 1;
        }
        if let Some(panic) = outcome.panic
            && self.stop.history.panic.is_none()
        {
            self.stop.history.panic = Some(panic);
            self.stop.version += 1;
        }
        self.stop.outcome_captured = outcome.delivered;
        if (!outcome.delivered || outcome.uncertain) && !self.stop.history.uncertain {
            self.stop.history.uncertain = true;
            self.stop.version += 1;
        }
    }"#,
            1,
        ),
    ],
    expressions: &[("thread::sleep(slice.min(Duration::from_millis(20)))", 1)],
    identifiers: &[],
    companions: super::CONTRACT.companions,
};

#[cfg(test)]
mod tests {
    use super::super::super::{
        mask_contract, read_companions, replace_one_obligation, source_pattern,
    };
    use super::CONTRACT;

    #[test]
    fn source_stop_wait_requires_same_cleanup_actual_join_and_independent_history()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = crate::workspace::package_path(
            &crate::workspace_root().join("crates"),
            CONTRACT.package,
        )
        .join(format!("{}.rs", CONTRACT.target));
        let code = crate::scrub_comments_and_strings(&std::fs::read_to_string(path)?);
        let companions = read_companions(&CONTRACT)?;
        assert_ne!(mask_contract(&CONTRACT, &code, &companions), code);

        for (before, after) in [
            (
                "self.stop.journal.snapshot(&self.stop.history)",
                "self.stop.history.clone()",
            ),
            (
                "self.stop_original_check(original)",
                "self.stop_original_check(replacement_original)",
            ),
            (
                "worker.native.poll()",
                "Ok(NativeJoinObservation::Returned)",
            ),
            (
                "self.stop.history.native_status = worker.native.last_status();",
                "discard_native_status();",
            ),
            (
                "self.stop.observe(2, true, after);",
                "discard_join_post(after);",
            ),
            (
                "if let Ok(slice) = before",
                "if let Ok(slice) = Ok(Duration::from_secs(60))",
            ),
            (
                "thread::sleep(slice.min(Duration::from_millis(20)))",
                "thread::sleep(Duration::from_secs(60))",
            ),
            (
                "self.stop.observe(1, true, after.as_ref().err().copied());",
                "discard_wait_post(after);",
            ),
            ("self.stop.history.worker = Some(first);", "drop(first);"),
            ("self.stop.history.panic = Some(panic);", "drop(panic);"),
        ] {
            let changed = replace_one_obligation(&code, &source_pattern(before), after);
            assert_ne!(changed, code, "missing actual stop obligation: {before}");
            assert_eq!(
                mask_contract(&CONTRACT, &changed, &companions),
                changed,
                "changed stop obligation was classified: {before}",
            );
        }
        Ok(())
    }
}
