//! Joins existing-only main-writer acquisition and replay to the actual Source.
//!
//! Fixed acquisition and the same held physical prefix receive separate debits.
//! The native writer and all failures remain parked through the final owed name
//! observation. This stage creates no schema, signed request, intent or floor.

use super::*;

impl Method46InitialStartupOriginalV1 {
    /// Acquires and replays the fixed existing nonempty main writer once.
    ///
    /// The original admitted unit, credentials and all initial stopped-owner
    /// cuts must already be complete. Paths, owner identity and limits come
    /// from the actual purpose and measured image; callers supply none. The
    /// same Source pays native acquisition before opening, then pays replay
    /// from that exact held prefix. No Journal or writer grant escapes.
    ///
    /// Independent final name observation stays owed even if preparation,
    /// funding or replay fails. Existing-only mode forbids creating missing
    /// names, cleaning compaction or repairing a tail. An empty native history
    /// or sequence-exhausted journal refuses. Session schema, current HEAD,
    /// independent approval, job exclusion and TPM custody remain separate.
    ///
    /// # Errors
    /// Refuses missing original prerequisites, reentry, a closed Source,
    /// insufficient actual funding, unsafe names/ancestry/ownership, conflicting
    /// writer custody, malformed history or an empty/exhausted main journal.
    pub fn capture_initial_main_writer_once_v1(
        &self,
    ) -> Result<(), Method46InitialStartupClosedV1> {
        let result = self.capture_initial_main_writer();
        result.map_err(|_| self.fail(First::MainWriter))
    }

    fn capture_initial_main_writer(&self) -> Result<(), Method46InitialStartupClosedV1> {
        if self.first.get().is_some() || self.after_attempted.get() {
            return Err(self.closed);
        }
        self.source
            .try_borrow()
            .map_err(|_| self.closed)?
            .require_current_v1()
            .map_err(|_| self.closed)?;
        let body = self.body.as_ref().ok_or(self.closed)?;
        if !body.unit.initial_admitted()
            || !body.stopped_cgroups.before_complete()
            || !body
                .credentials
                .try_borrow()
                .is_ok_and(|credentials| credentials.admitted_before_post())
        {
            return Err(self.closed);
        }
        let profile = body
            .profile_decoded
            .as_ref()
            .and_then(|profile| profile.as_ref().ok())
            .ok_or(self.closed)?;
        let role = self.origin.as_ref().ok_or(self.closed)?.role;
        let mut writer = body.main_writer.try_borrow_mut().map_err(|_| self.closed)?;
        let fixed = writer.quote_fixed_once(role).ok_or(self.closed)?;
        self.fund_additional(Some(fixed))?;

        writer.prepare_once(role, profile.controller_uid);
        let replay = writer.quote_replay_once().ok_or(self.closed)?;
        self.fund_additional(Some(replay))?;
        writer.replay_once().map_err(|_| self.closed)
    }
}

#[cfg(test)]
mod tests {
    use std::mem::ManuallyDrop;

    use super::*;

    #[test]
    fn method46_initial_main_writer_requires_source_before_any_payment_or_io() {
        let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(
            Method46InitialServiceRoleV1::StorageBroker,
        ));

        assert!(startup.capture_initial_main_writer_once_v1().is_err());
        assert!(startup.capture_before_arguments_once_v1().is_err());

        assert!(startup.body.is_none());
        assert!(!startup.capture_attempted);
        assert_eq!(startup.receiving.get(), ResourceVector::ZERO);
        assert!(matches!(startup.first.get(), Some(First::MainWriter)));
    }

    #[test]
    fn method46_initial_main_writer_busy_post_keeps_other_posts_and_source_after_owed() {
        let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(
            Method46InitialServiceRoleV1::ControllerStorageClient,
        ));
        startup.body = Some(Box::new(StartupRolesOriginalV1::new()));
        let held = startup.body.as_ref().unwrap().main_writer.borrow_mut();

        assert!(startup.finish_source_after_owed_once_v1(Ok(())).is_err());

        assert!(startup.after_attempted.get());
        assert!(matches!(startup.after_result.get(), Some(Err(_))));
        assert!(matches!(startup.first.get(), Some(First::Order)));
        drop(held);
    }
}
