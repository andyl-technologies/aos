//! Prepays the same manual Source's empty floor writer before main approval.
//!
//! The actual main selects directory, normal UID and limits. Fixed preparation,
//! its captured empty replay extent and native currentness each receive their
//! own debit before IO or allocation. All original files stay on this owner.

use super::*;

impl Method46InitialStartupOriginalV1 {
    /// Prepares and holds the fixed empty floor writer beside this same main.
    ///
    /// This must precede the strict main readback/approval interval. It creates
    /// missing empty names exclusively, or completes ownership of an exact
    /// empty root-owned creation prefix, then uses the existing-only protected
    /// writer engine. No tail repair, cleanup, nonempty normalization, writer
    /// export, private auth readback or physical TPM operation is permitted.
    /// The existing manual unit's capabilities suffice for normal Controller
    /// ownership; this operation neither changes UID nor expands capabilities.
    ///
    /// # Errors
    /// Refuses missing or ended Source/main custody, reentry, insufficient
    /// actual funding, unsafe/nonempty/conflicting files, held foreign locks,
    /// native IO/replay failure or changed main/floor names and metadata.
    pub fn prepare_initial_floor_writer_once_v1(
        &self,
    ) -> Result<(), Method46InitialStartupClosedV1> {
        let result = (|| {
            if self.first.get().is_some() || self.after_attempted.get() {
                return Err(self.closed);
            }
            self.source
                .try_borrow()
                .map_err(|_| self.closed)?
                .require_current_v1()
                .map_err(|_| self.closed)?;
            let body = self.body.as_ref().ok_or(self.closed)?;
            let mut writer = body.main_writer.try_borrow_mut().map_err(|_| self.closed)?;
            let fixed = writer.quote_initial_floor_fixed_once().ok_or(self.closed)?;
            self.fund_additional(Some(fixed))?;
            writer
                .prepare_initial_floor_once()
                .map_err(|_| self.closed)?;
            let replay = writer
                .quote_initial_floor_replay_once()
                .ok_or(self.closed)?;
            self.fund_additional(Some(replay))?;
            writer
                .replay_initial_floor_once()
                .map_err(|_| self.closed)?;
            let currentness = writer
                .quote_initial_floor_currentness_once()
                .ok_or(self.closed)?;
            self.fund_additional(Some(currentness))?;
            writer
                .begin_initial_floor_currentness_once()
                .map_err(|_| self.closed)
        })();
        if result.is_err() {
            // Preserve the original refusal before independently owed posts.
            self.fail(First::MainWriter);
            if let Some(body) = self.body.as_ref() {
                if let Ok(mut writer) = body.main_writer.try_borrow_mut() {
                    let _after = writer.finish_initial_floor_after_owed();
                }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use std::mem::ManuallyDrop;

    use super::*;

    #[test]
    fn method46_initial_floor_writer_requires_genuine_source_before_any_io() {
        for role in [
            Method46InitialServiceRoleV1::ControllerStorageClient,
            Method46InitialServiceRoleV1::StorageBroker,
        ] {
            let startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(role));

            assert!(startup.prepare_initial_floor_writer_once_v1().is_err());

            assert!(startup.body.is_none());
            assert_eq!(startup.receiving.get(), ResourceVector::ZERO);
            assert!(startup.finish_source_after_owed_once_v1(Ok(())).is_err());
        }
    }
}
