//! Lends the same captured public provisioning bytes to the canonical codec.
//!
//! One genuine Source prepays the bounded decode carrier before issuing its
//! sole readback loan. The loan neither extracts private index authentication
//! nor grants writer, approval, physical TPM or publication authority.

use std::cell::Ref;

use super::*;

/// Bounds the co-live canonical provisioning decoder and result carriers.
///
/// The Security codec checks its compiled layout against this prepaid bound.
/// Actual credential buffers and original native observations are paid by the
/// enclosing file owner separately. This size alone authenticates no payer.
pub const METHOD46_INITIAL_PROVISION_DECODE_BYTES_V1: usize = 8192;

/// Borrows one Source-paid original public provisioning readback for decoding.
///
/// Only the actual startup owner constructs this loan after unit and credential
/// admission. The original files remain resident; all reached posts are still
/// owed. Neither this loan nor a decoded public record authorizes an effect.
#[must_use = "retain the original readback loan with its canonical decode result"]
pub struct Method46InitialProvisionReadbackLoanV1<'owner> {
    startup: &'owner Method46InitialStartupOriginalV1,
}

impl Method46InitialProvisionReadbackLoanV1<'_> {
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

    /// Borrows the actual public bytes while their original custody is current.
    ///
    /// This performs no IO or copying. Holding this borrow through a credential
    /// post makes that post refuse; the independent Source after remains owed.
    ///
    /// # Errors
    /// Refuses a completed/failed Source, busy owner, missing original readback
    /// or already entered post. It never replaces or reopens a credential.
    pub fn provision_bytes_v1(&self) -> Result<Ref<'_, [u8]>, Method46InitialStartupClosedV1> {
        self.require_current()?;
        let body = self.startup.body.as_ref().ok_or(self.startup.closed)?;
        let credentials = body
            .credentials
            .try_borrow()
            .map_err(|_| self.startup.closed)?;
        if !credentials.completed || credentials.post_entered || !credentials.decode_loan_issued {
            return Err(self.startup.closed);
        }
        Ref::filter_map(credentials, |credentials| {
            credentials.credentials[0].bytes[0]
                .as_deref()
                .map(|bytes| bytes.as_slice())
        })
        .map_err(|_| self.startup.closed)
    }

    /// Copies comparison identity from this same genuine Source original.
    ///
    /// The resource-policy epoch is not the TPM deployment epoch. These fields
    /// remain comparison DATA and cannot construct another loan or payer.
    ///
    /// # Errors
    /// Refuses a failed, completed or missing original Source interval.
    pub fn origin_data_v1(
        &self,
    ) -> Result<Method46InitialOriginComparisonDataV1, Method46InitialStartupClosedV1> {
        self.require_current()?;
        self.startup.origin.ok_or(self.startup.closed)
    }

    /// Fences this same startup after a canonical provisioning decode refusal.
    ///
    /// Native credentials and decode originals stay with their owners. Fencing
    /// does not suppress their independently owed posts or heal earlier failure.
    pub fn refuse_decode_v1(&self) {
        self.startup.fail(First::Credentials);
    }
}

impl Method46InitialStartupOriginalV1 {
    /// Prepays and lends the original public provisioning readback once.
    ///
    /// The finite codec allowance comes from this same actual Source before
    /// the Security result carrier exists. No supplied bytes, amount, purpose
    /// or descriptor can manufacture the returned loan. Private auth stays in
    /// the credential owner; independent key and protected writer admission
    /// remain separate obligations.
    ///
    /// # Errors
    /// Refuses missing unit/credential admission, repeated issuance, busy native
    /// custody, an ended Source or exhausted genuine receiving allocation.
    pub fn lend_provisioning_readback_once_v1(
        &mut self,
    ) -> Result<Method46InitialProvisionReadbackLoanV1<'_>, Method46InitialStartupClosedV1> {
        let ready = self.body.as_ref().is_some_and(|body| {
            body.unit.initial_admitted()
                && body.credentials.try_borrow().is_ok_and(|credentials| {
                    credentials.completed
                        && !credentials.post_entered
                        && !credentials.decode_loan_issued
                })
        });
        if !ready {
            return Err(self.fail(First::Order));
        }
        self.source
            .get_mut()
            .require_current_v1()
            .map_err(|_| self.closed)?;
        self.fund_additional(Some(ResourceVector::ZERO.with(
            D::MemoryBytes,
            METHOD46_INITIAL_PROVISION_DECODE_BYTES_V1 as u64,
        )))?;
        self.body
            .as_ref()
            .ok_or(self.closed)?
            .credentials
            .try_borrow_mut()
            .map_err(|_| self.closed)?
            .decode_loan_issued = true;
        Ok(Method46InitialProvisionReadbackLoanV1 { startup: self })
    }
}

#[cfg(test)]
mod tests {
    use std::mem::ManuallyDrop;

    use super::*;

    #[test]
    fn initial_provision_decode_requires_actual_credential_admission_before_funding() {
        let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(
            Method46InitialServiceRoleV1::StorageBroker,
        ));
        startup.body = Some(Box::new(StartupRolesOriginalV1::new()));

        assert!(startup.lend_provisioning_readback_once_v1().is_err());

        let credentials = startup.body.as_ref().unwrap().credentials.borrow();
        assert!(!credentials.decode_loan_issued);
        assert!(!credentials.entered);
        assert_eq!(startup.receiving.get(), ResourceVector::ZERO);
    }

    #[test]
    fn initial_provision_decode_refusal_keeps_the_source_after_owed() {
        let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(
            Method46InitialServiceRoleV1::ControllerStorageClient,
        ));
        startup.body = Some(Box::new(StartupRolesOriginalV1::new()));
        // Private test-only construction exercises failure dispatch. It has no
        // source or successful credential, and therefore cannot lend any bytes.
        let loan = Method46InitialProvisionReadbackLoanV1 { startup: &startup };
        assert!(loan.provision_bytes_v1().is_err());
        assert!(loan.origin_data_v1().is_err());
        loan.refuse_decode_v1();

        assert!(startup.finish_source_after_owed_once_v1(Ok(())).is_err());

        assert!(matches!(startup.first.get(), Some(First::Credentials)));
        assert!(startup.after_attempted.get());
        assert!(matches!(startup.after_result.get(), Some(Err(_))));
    }
}
