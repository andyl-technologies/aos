//! Lends the same Source's retained pair of original writer lock descriptions.

use std::cell::Ref;
use std::os::fd::BorrowedFd;

use super::*;

/// Borrows the initial Source's two lock duplicates through their owed posts.
///
/// Construction requires the same main's completed durable intent publication.
/// This loan neither exposes private index authentication nor admits a helper,
/// authorizes an Extend, or supplies a checkpoint. A recipient of the duplicate
/// descriptions can unlock them and must be independently trusted and confined.
#[must_use = "retain the actual lock owner until the helper and both posts finish"]
pub struct Method46InitialTpmLockLoanV1<'owner> {
    pub(in crate::method46_initial_startup) startup: &'owner Method46InitialStartupOriginalV1,
}

/// Holds an immutable borrow of the actual retained pair of lock descriptions.
///
/// Keeping this view alive prevents the mutable owed post from succeeding.
/// Drop the temporary view before completing that post; the Source retains the
/// actual duplicated descriptors throughout either outcome.
pub struct Method46InitialTpmLockViewV1<'owner> {
    startup: &'owner Method46InitialStartupOriginalV1,
    writer: Ref<'owner, crate::journal::Method46InitialMainWriterOriginalV1>,
}

impl Method46InitialTpmLockViewV1<'_> {
    /// Borrows only the exact two duplicated writer lock descriptions.
    ///
    /// # Errors
    /// Refuses an incomplete, failed or ended native lock interval.
    pub fn borrowed_descriptors_v1(
        &self,
    ) -> Result<[BorrowedFd<'_>; 2], Method46InitialStartupClosedV1> {
        require_current(self.startup)?;
        self.writer
            .initial_tpm_lock_descriptors()
            .ok_or(Method46InitialStartupClosedV1)
    }

    /// Copies the captured lock device, inode and UID tuple as comparison DATA.
    ///
    /// This performs no fresh native observation and authenticates no child.
    ///
    /// # Errors
    /// Refuses an incomplete, failed or ended native lock interval.
    pub fn identities_data_v1(
        &self,
    ) -> Result<[(u64, u64, u32); 2], Method46InitialStartupClosedV1> {
        require_current(self.startup)?;
        self.writer
            .initial_tpm_lock_identities_data()
            .ok_or(Method46InitialStartupClosedV1)
    }
}

fn require_current(
    startup: &Method46InitialStartupOriginalV1,
) -> Result<(), Method46InitialStartupClosedV1> {
    let result = (|| {
        if startup.first.get().is_some() || startup.after_attempted.get() {
            return Err(startup.closed);
        }
        startup
            .source
            .try_borrow()
            .map_err(|_| startup.closed)?
            .require_current_v1()
            .map_err(|_| startup.closed)
    })();
    result.map_err(|_| startup.fail(First::MainWriter))
}

impl Method46InitialTpmLockLoanV1<'_> {
    /// Borrows the actual pair while this same Source is current.
    ///
    /// # Errors
    /// Refuses a failed/ended Source, busy owner or incomplete lock capture.
    pub fn borrow_custody_v1(
        &self,
    ) -> Result<Method46InitialTpmLockViewV1<'_>, Method46InitialStartupClosedV1> {
        let result: Result<_, Method46InitialStartupClosedV1> = (|| {
            require_current(self.startup)?;
            let body = self.startup.body.as_ref().ok_or(self.startup.closed)?;
            let writer = body
                .main_writer
                .try_borrow()
                .map_err(|_| self.startup.closed)?;
            writer
                .initial_tpm_lock_descriptors()
                .ok_or(self.startup.closed)?;
            Ok(Method46InitialTpmLockViewV1 {
                startup: self.startup,
                writer,
            })
        })();
        result.map_err(|_| self.startup.fail(First::MainWriter))
    }

    /// Attempts both independent lock and writer posts after any reached failure.
    ///
    /// This deliberately does not require a still-successful Source. Neither
    /// descriptor is released or explicitly unlocked by the post.
    ///
    /// # Errors
    /// Refuses an ended/busy owner, changed names or held metadata, or a retained
    /// duplication failure. Successful posts are retained and never repeated.
    pub fn finish_after_owed_v1(&self) -> Result<(), Method46InitialStartupClosedV1> {
        let result = (|| {
            if self.startup.after_attempted.get() {
                return Err(self.startup.closed);
            }
            self.startup
                .body
                .as_ref()
                .ok_or(self.startup.closed)?
                .main_writer
                .try_borrow_mut()
                .map_err(|_| self.startup.closed)?
                .finish_initial_tpm_locks_after_owed()
                .map_err(|_| self.startup.closed)
        })();
        result.map_err(|_| self.startup.fail(First::MainWriter))
    }
}

impl<'owner> Method46InitialIntentFileLoanV1<'owner> {
    /// Prepays and retains the same initial writers' actual lock duplicates once.
    ///
    /// The original Source must already have completed its fixed intent file's
    /// fsync, parent fsync and native posts. Both lock duplicates and all reached
    /// errors remain with that Source. No path, UID, descriptor, private auth or
    /// funding amount enters from the caller. Signature and helper admission
    /// remain the Security composition's separate responsibilities.
    ///
    /// # Errors
    /// Refuses missing durable publication, failed/ended Source, reentry, busy
    /// owners, funding refusal, changed writers or native duplication failure.
    pub fn lend_tpm_lock_custody_once_v1(
        &self,
    ) -> Result<Method46InitialTpmLockLoanV1<'owner>, Method46InitialStartupClosedV1> {
        let result = (|| {
            self.require_current()?;
            if !self.published.get() {
                return Err(self.startup.closed);
            }
            let body = self.startup.body.as_ref().ok_or(self.startup.closed)?;
            let mut writer = body
                .main_writer
                .try_borrow_mut()
                .map_err(|_| self.startup.closed)?;
            let demand = writer
                .quote_initial_tpm_locks_once()
                .ok_or(self.startup.closed)?;
            self.startup.fund_additional(Some(demand))?;
            writer
                .capture_initial_tpm_locks_once()
                .map_err(|_| self.startup.closed)?;
            Ok(Method46InitialTpmLockLoanV1 {
                startup: self.startup,
            })
        })();
        if result.is_err() {
            // Fence before independently owed native work, preserving the
            // earlier action error even if a later name observation also fails.
            self.startup.fail(First::MainWriter);
            if let Some(body) = self.startup.body.as_ref() {
                if let Ok(mut writer) = body.main_writer.try_borrow_mut() {
                    let _after = writer.finish_initial_tpm_locks_after_owed();
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
    fn method46_initial_tpm_locks_cannot_enter_without_original_source() {
        let startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(
            Method46InitialServiceRoleV1::StorageBroker,
        ));
        let intent = Method46InitialIntentFileLoanV1 {
            startup: &startup,
            published: Cell::new(true),
        };

        assert!(intent.lend_tpm_lock_custody_once_v1().is_err());

        assert!(startup.body.is_none());
        assert_eq!(startup.receiving.get(), ResourceVector::ZERO);
        assert!(matches!(startup.first.get(), Some(First::MainWriter)));
    }
}
