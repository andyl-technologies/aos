//! Lends the actual Source-paid separate intent publication reservoir.
//!
//! Fixed names, ownership and native file custody stay with the held main.
//! Signed-byte admission belongs to Security; this loan grants no TPM effect.

use super::*;

/// Fixes the separate signed initial-intent byte extent.
pub const METHOD46_INITIAL_INTENT_NATIVE_BYTES_V1: usize = 398;

/// Borrows one genuine startup's original initial-intent file operations.
///
/// Only the held main's readback loan can construct this after its Source pays
/// every original, buffer, descriptor and storage allowance. No path, UID,
/// Journal, private credential, amount or publication callback enters from the
/// caller. Signed-byte admission remains with the Security composition.
#[must_use = "retain the native original loan through publication and owed posts"]
pub struct Method46InitialIntentFileLoanV1<'owner> {
    startup: &'owner Method46InitialStartupOriginalV1,
    published: Cell<bool>,
}

impl Method46InitialIntentFileLoanV1<'_> {
    /// Copies a complete existing intent from the actual captured fixed name.
    ///
    /// A partial stage requires independent approval before it can be resumed.
    /// Returned bytes are comparison DATA, without approval or TPM authority.
    ///
    /// # Errors
    /// Refuses a failed/ended Source, busy owner or failed native capture.
    pub fn captured_intent_bytes_data_v1(
        &self,
    ) -> Result<Option<[u8; METHOD46_INITIAL_INTENT_NATIVE_BYTES_V1]>, Method46InitialStartupClosedV1>
    {
        self.require_current()?;
        let body = self.startup.body.as_ref().ok_or(self.startup.closed)?;
        body.main_writer
            .try_borrow()
            .map_err(|_| self.startup.closed)?
            .captured_initial_intent_data()
            .map_err(|_| self.startup.fail(First::MainWriter))
    }

    /// Publishes exact admitted bytes once with file and parent durability.
    ///
    /// Security calls this with its resident same-Source verified approval.
    /// Conflicts are preserved; an existing stage resumes only its exact prefix.
    /// This mechanical operation cannot initialize or access a TPM and its
    /// completion is not an Extend or checkpoint permission.
    ///
    /// # Errors
    /// Refuses reentry, failed/ended Source, busy owner, conflicting file state,
    /// unsafe metadata, native IO failure or changed main/name bookends.
    pub fn publish_exact_once_v1(
        &self,
        bytes: [u8; METHOD46_INITIAL_INTENT_NATIVE_BYTES_V1],
    ) -> Result<(), Method46InitialStartupClosedV1> {
        let result = (|| {
            if self.published.replace(true) {
                return Err(self.startup.closed);
            }
            self.require_current()?;
            let body = self.startup.body.as_ref().ok_or(self.startup.closed)?;
            body.main_writer
                .try_borrow_mut()
                .map_err(|_| self.startup.closed)?
                .publish_initial_intent_once(bytes)
                .map_err(|_| self.startup.closed)?;
            self.require_current()
        })();
        result.map_err(|_| self.startup.fail(First::MainWriter))
    }

    /// Attempts independently owed native posts even after semantic refusal.
    ///
    /// # Errors
    /// Refuses an ended or busy owner, or retained native name/metadata failure.
    pub fn finish_after_owed_v1(&self) -> Result<(), Method46InitialStartupClosedV1> {
        let result = (|| {
            if self.startup.after_attempted.get() {
                return Err(self.startup.closed);
            }
            let body = self.startup.body.as_ref().ok_or(self.startup.closed)?;
            body.main_writer
                .try_borrow_mut()
                .map_err(|_| self.startup.closed)?
                .finish_initial_intent_after_owed()
                .map_err(|_| self.startup.closed)
        })();
        result.map_err(|_| self.startup.fail(First::MainWriter))
    }

    fn require_current(&self) -> Result<(), Method46InitialStartupClosedV1> {
        if self.startup.first.get().is_some() || self.startup.after_attempted.get() {
            return Err(self.startup.closed);
        }
        self.startup
            .source
            .try_borrow()
            .map_err(|_| self.startup.closed)?
            .require_current_v1()
            .map_err(|_| self.startup.closed)
    }
}

impl<'owner> Method46InitialMainReadbackLoanV1<'owner> {
    /// Prepays and captures separate initial-intent names on this same main.
    ///
    /// Complete/partial/conflicting file originals stay with the actual writer.
    /// The additional main interval is bound to the original replay metadata,
    /// never a later substituted baseline. Capture performs no file mutation.
    ///
    /// # Errors
    /// Refuses failed/ended Source, reentry, missing custody or funding, unsafe
    /// files, nonempty completed floor, conflicting names or changed main.
    pub fn capture_initial_intent_files_once_v1(
        &self,
    ) -> Result<Method46InitialIntentFileLoanV1<'owner>, Method46InitialStartupClosedV1> {
        let result = (|| {
            self.origin_data_v1()?;
            let body = self.startup.body.as_ref().ok_or(self.startup.closed)?;
            let mut writer = body
                .main_writer
                .try_borrow_mut()
                .map_err(|_| self.startup.closed)?;
            let demand = writer
                .quote_initial_intent_once()
                .ok_or(self.startup.closed)?;
            self.startup.fund_additional(Some(demand))?;
            let capture = writer.capture_initial_intent_once();
            if capture.is_err() {
                let _after = writer.finish_initial_intent_after_owed();
                return Err(self.startup.closed);
            }
            Ok(Method46InitialIntentFileLoanV1 {
                startup: self.startup,
                published: Cell::new(false),
            })
        })();
        result.map_err(|_| self.startup.fail(First::MainWriter))
    }
}
