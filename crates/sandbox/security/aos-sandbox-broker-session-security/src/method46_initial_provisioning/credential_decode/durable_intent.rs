//! Composes original approval with Source-paid separate intent publication.
//!
//! The same continuously borrowed startup owns public credentials, the canonical
//! main cut, strict approval and actual native file reservoirs. Copied intent
//! DATA is never accepted by this composition as permission to publish.

use aos_sandbox_controller_domain::method46_initial_startup::{
    METHOD46_INITIAL_INTENT_NATIVE_BYTES_V1, Method46InitialIntentFileLoanV1,
    Method46InitialTpmLockLoanV1,
};

use super::*;

pub(super) struct InitialIntentPublicationOriginal<'owner> {
    entered: bool,
    loan: Option<Method46InitialIntentFileLoanV1<'owner>>,
    captured: Option<
        Result<Option<[u8; METHOD46_INITIAL_INTENT_BYTES_V1]>, Method46InitialStartupClosedV1>,
    >,
    approval: Option<Result<Method46InitialIntentDataV1, Method46InitialDataErrorV1>>,
    encoded: Option<[u8; METHOD46_INITIAL_INTENT_BYTES_V1]>,
    native: Option<Result<(), Method46InitialStartupClosedV1>>,
    result: Option<Result<(), Method46InitialDataErrorV1>>,
    after: Option<Result<(), Method46InitialStartupClosedV1>>,
    locks_entered: bool,
    locks: Option<Method46InitialTpmLockLoanV1<'owner>>,
    locks_result: Option<Result<(), Method46InitialDataErrorV1>>,
    locks_after: Option<Result<(), Method46InitialStartupClosedV1>>,
}

const _: () = assert!(METHOD46_INITIAL_INTENT_BYTES_V1 == METHOD46_INITIAL_INTENT_NATIVE_BYTES_V1);

impl<'owner> InitialIntentPublicationOriginal<'owner> {
    pub(super) fn new() -> Self {
        Self {
            entered: false,
            loan: None,
            captured: None,
            approval: None,
            encoded: None,
            native: None,
            result: None,
            after: None,
            locks_entered: false,
            locks: None,
            locks_result: None,
            locks_after: None,
        }
    }

    fn finish_after_owed(&mut self) {
        if self.locks_after.is_none() {
            if let Some(locks) = self.locks.as_ref() {
                self.locks_after = Some(locks.finish_after_owed_v1());
            }
        }
        if self.after.is_none() {
            if let Some(loan) = self.loan.as_ref() {
                self.after = Some(loan.finish_after_owed_v1());
            }
        }
    }
}

impl<'owner> Method46InitialProvisionDecodeOriginalV1<'owner> {
    /// Captures and prepays initial-intent files on the same admitted main once.
    ///
    /// This read-only capture precedes fresh approval or cold verification.
    /// Partial stages remain unapproved public prefixes. No supplied pathname,
    /// owner, amount or byte buffer selects the native receiving operation.
    ///
    /// # Errors
    /// Refuses foreign/failed/ended originals, repeated capture, missing funding,
    /// unsafe or conflicting files, a nonempty floor or changed native main.
    pub fn capture_initial_intent_files_once_v1(
        &self,
        main: &Method46InitialMainCutOriginalV1<'owner>,
    ) -> Result<(), Method46InitialDataErrorV1> {
        let result = (|| {
            self.request_for_main_original_data_v1(main)?;
            self.approval
                .try_borrow()
                .map_err(|_| Method46InitialDataErrorV1::Conflict)?
                .require_fresh()?;
            let mut intent = self
                .intent
                .try_borrow_mut()
                .map_err(|_| Method46InitialDataErrorV1::Conflict)?;
            if intent.entered {
                return Err(Method46InitialDataErrorV1::Conflict);
            }
            intent.entered = true;
            intent.loan = Some(
                main.capture_initial_intent_files_once_v1()
                    .map_err(|_| Method46InitialDataErrorV1::Conflict)?,
            );
            intent.captured = intent
                .loan
                .as_ref()
                .map(|loan| loan.captured_intent_bytes_data_v1());
            if !matches!(intent.captured, Some(Ok(_))) {
                return Err(Method46InitialDataErrorV1::Conflict);
            }
            Ok(())
        })();
        if result.is_err() {
            self.refuse_intent_and_finish_after();
        }
        result
    }

    /// Verifies the complete initial intent read from the actual fixed name.
    ///
    /// This shares the ordinary strict approval attempt and independently owed
    /// main post. Missing final files and partial stages require fresh approval;
    /// caller-supplied intent bytes cannot enter this cold recovery route.
    ///
    /// # Errors
    /// Refuses missing/failed capture, prior approval, invalid signature, changed
    /// request or failed same-Source main/currentness observations.
    pub fn verify_captured_initial_intent_once_v1(
        &self,
        main: &Method46InitialMainCutOriginalV1<'_>,
    ) -> Result<Method46InitialIntentDataV1, Method46InitialDataErrorV1> {
        let bytes = self
            .intent
            .try_borrow()
            .ok()
            .and_then(|intent| match intent.captured {
                Some(Ok(Some(bytes))) => Some(bytes),
                _ => None,
            });
        let result = match bytes {
            Some(bytes) => self.decode_captured_pin_intent_once_v1(main, bytes),
            None => Err(Method46InitialDataErrorV1::Conflict),
        };
        if result.is_err() {
            self.refuse_intent_and_finish_after();
        }
        result
    }

    /// Durably publishes the resident same-Source verified initial intent once.
    ///
    /// The canonical request is rederived from the genuine admitted main and
    /// compared with the retained strict approval. File fsync, no-replace rename,
    /// parent fsync and independent native posts must all complete. Existing
    /// exact intent bytes are resynced; conflicting state is preserved.
    /// Completion grants no TPM Extend or checkpoint authority.
    ///
    /// # Errors
    /// Refuses missing/foreign/ended originals, prior publication, unverified or
    /// changed approval, failed approval main post, native conflict or IO error.
    pub fn publish_approved_initial_intent_once_v1(
        &self,
        main: &Method46InitialMainCutOriginalV1<'_>,
    ) -> Result<(), Method46InitialDataErrorV1> {
        let result = (|| {
            let mut intent = self
                .intent
                .try_borrow_mut()
                .map_err(|_| Method46InitialDataErrorV1::Conflict)?;
            if intent.result.is_some() {
                return Err(Method46InitialDataErrorV1::Conflict);
            }
            let result = (|| {
                let current = self.request_for_main_original_data_v1(main)?;
                if !self
                    .approval_main_after
                    .try_borrow()
                    .is_ok_and(|after| matches!(*after, Some(Ok(()))))
                {
                    return Err(Method46InitialDataErrorV1::Conflict);
                }
                intent.approval = Some(
                    self.approval
                        .try_borrow()
                        .map_err(|_| Method46InitialDataErrorV1::Conflict)?
                        .verified_intent(),
                );
                let approved = intent
                    .approval
                    .ok_or(Method46InitialDataErrorV1::Conflict)??;
                if approved.request() != current {
                    return Err(Method46InitialDataErrorV1::Conflict);
                }
                intent.encoded = Some(approved.encode());
                let loan = intent
                    .loan
                    .as_ref()
                    .ok_or(Method46InitialDataErrorV1::Conflict)?;
                intent.native = Some(loan.publish_exact_once_v1(
                    intent.encoded.ok_or(Method46InitialDataErrorV1::Conflict)?,
                ));
                if !matches!(intent.native, Some(Ok(()))) {
                    return Err(Method46InitialDataErrorV1::Conflict);
                }
                Ok(())
            })();
            intent.result = Some(result);
            intent.finish_after_owed();
            result?;
            if matches!(intent.after, Some(Ok(()))) {
                Ok(())
            } else {
                Err(Method46InitialDataErrorV1::Conflict)
            }
        })();
        if result.is_err() {
            self.refuse_intent_and_finish_after();
        }
        result
    }

    /// Retains both actual initial writer lock duplicates after durable approval.
    ///
    /// No lock descriptors or private authentication enter from the caller. The
    /// canonical request is rederived from the same genuine main and compared
    /// with the resident verified approval before its durable native intent can
    /// lend custody. This prepares no helper and performs no TPM operation.
    ///
    /// # Errors
    /// Refuses a foreign/ended main, missing completed intent or approval,
    /// repeated entry, funding refusal, or failed native lock capture. Every
    /// reached post remains owed on the same Source after a refusal.
    pub fn prepare_approved_initial_tpm_locks_once_v1(
        &self,
        main: &Method46InitialMainCutOriginalV1<'_>,
    ) -> Result<(), Method46InitialDataErrorV1> {
        let result = (|| {
            let mut intent = self
                .intent
                .try_borrow_mut()
                .map_err(|_| Method46InitialDataErrorV1::Conflict)?;
            if std::mem::replace(&mut intent.locks_entered, true) {
                return Err(Method46InitialDataErrorV1::Conflict);
            }
            let result = (|| {
                let request = self.request_for_main_original_data_v1(main)?;
                if !matches!(intent.result, Some(Ok(())))
                    || !matches!(intent.native, Some(Ok(())))
                    || !matches!(intent.after, Some(Ok(())))
                    || self
                        .approval
                        .try_borrow()
                        .map_err(|_| Method46InitialDataErrorV1::Conflict)?
                        .verified_intent()?
                        .request()
                        != request
                {
                    return Err(Method46InitialDataErrorV1::Conflict);
                }
                intent.locks = Some(
                    intent
                        .loan
                        .as_ref()
                        .ok_or(Method46InitialDataErrorV1::Conflict)?
                        .lend_tpm_lock_custody_once_v1()
                        .map_err(|_| Method46InitialDataErrorV1::Conflict)?,
                );
                Ok(())
            })();
            intent.locks_result = Some(result);
            result
        })();
        if result.is_err() {
            self.refuse_intent_and_finish_after();
        }
        result
    }

    pub(super) fn refuse_intent_and_finish_after(&self) {
        // Preserve semantic first cause before servicing independent native debt.
        self.readback.refuse_decode_v1();
        if let Ok(mut intent) = self.intent.try_borrow_mut() {
            intent.finish_after_owed();
        }
    }
}
