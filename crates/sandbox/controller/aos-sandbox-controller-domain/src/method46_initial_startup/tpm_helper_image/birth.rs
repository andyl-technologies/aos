//! Lends Source-paid fixed helper birth after actual durable-intent lock custody.
//!
//! The Source retains the image, native setup, process and failed prefixes.
//! Temporary loans keep that same owner borrowed across child measurement;
//! they export neither private auth nor a native channel. The helper image
//! post and original Source after remain independent and owed after failure.

use std::cell::RefMut;

use aos_sandbox_broker::fixed_initial_tpm_helper_birth::{
    FixedInitialTpmHelperBirthOriginalV1, InitialTpmHelperDrivingLoanV1,
};

use super::*;

/// Borrows the same Source's funded fixed initial helper and native reservoir.
///
/// Only its actual durable-intent lock loan can construct this value. Drop the
/// loan before the Source's terminal image post; the native owner stays resident
/// with that Source regardless of preparation, child or measurement failure.
#[must_use = "retain the Source and native owner through the helper's disposition"]
pub struct Method46InitialTpmHelperBirthLoanV1<'owner> {
    startup: &'owner Method46InitialStartupOriginalV1,
    helper: RefMut<'owner, InitialTpmHelperImageOriginalV1>,
}

/// Keeps the real Source and child borrowed across the native birth checks.
///
/// This supplies no private-auth destination, TPM operation or approval claim.
/// Dropping the loan stops automatic progress and signals the retained child.
#[must_use = "retain this same child borrow through its purpose disposition"]
pub struct Method46InitialTpmHelperDrivingLoanV1<'owner> {
    startup: &'owner Method46InitialStartupOriginalV1,
    native: InitialTpmHelperDrivingLoanV1<'owner>,
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
    result.map_err(|_| startup.fail(First::TpmHelperBirth))
}

impl<'owner> Method46InitialTpmLockLoanV1<'owner> {
    /// Prepays and lends the same Source's fixed helper birth reservoir once.
    ///
    /// The actual two lock descriptions must already follow durable intent
    /// publication. The same Source retains the measured fixed image, prepays
    /// native construction, observes its inherited stack, then prepays complete
    /// child/pair/proc custody. No caller selects resources, image or descriptors.
    /// No native child, secret transfer or TPM operation occurs in this method.
    ///
    /// # Errors
    /// Refuses failed/ended Source, incomplete locks or helper-image admission,
    /// reentry, busy owners, unlimited stack or insufficient Source funding.
    /// Every reached native owner and the original image remain resident.
    pub fn lend_initial_helper_birth_once_v1(
        &self,
    ) -> Result<Method46InitialTpmHelperBirthLoanV1<'owner>, Method46InitialStartupClosedV1> {
        let result = (|| {
            require_current(self.startup)?;
            {
                // This real view checks both retained descriptions and the
                // same Source; it is not replaced by copied identity tuples.
                let locks = self.borrow_custody_v1()?;
                locks.borrowed_descriptors_v1()?;
            }
            let body = self.startup.body.as_ref().ok_or(self.startup.closed)?;
            let mut helper = body
                .tpm_helper_image
                .try_borrow_mut()
                .map_err(|_| self.startup.closed)?;
            if !helper.entered
                || helper.posted
                || helper.node_matches != Some(true)
                || helper.image.is_none()
                || helper.birth.is_some()
            {
                return Err(self.startup.closed);
            }
            let header = std::mem::size_of::<Method46InitialTpmHelperBirthLoanV1<'_>>()
                .checked_add(std::mem::size_of::<Method46InitialTpmHelperDrivingLoanV1<'_>>())
                .and_then(|bytes| bytes.checked_mul(2))
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(self.startup.closed)?;
            let construction = FixedInitialTpmHelperBirthOriginalV1::construction_demand_v1()
                .and_then(|demand| {
                    demand
                        .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, header))
                        .ok()
                });
            self.startup.fund_additional(construction)?;
            let image = helper.image.take().ok_or(self.startup.closed)?;
            helper.birth = Some(Box::new(FixedInitialTpmHelperBirthOriginalV1::new(image)));
            let birth = helper.birth.as_mut().ok_or(self.startup.closed)?;
            birth
                .observe_stack_once_v1()
                .map_err(|_| self.startup.closed)?;
            self.startup
                .fund_additional(birth.native_receiving_demand_v1())?;
            require_current(self.startup)?;
            Ok(Method46InitialTpmHelperBirthLoanV1 {
                startup: self.startup,
                helper,
            })
        })();
        result.map_err(|_| self.startup.fail(First::TpmHelperBirth))
    }
}

impl Method46InitialTpmHelperBirthLoanV1<'_> {
    /// Prepares and borrows the one Source-funded fixed native supervisor once.
    ///
    /// # Errors
    /// Refuses failed/ended Source, reentry, missing custody, native pair or
    /// preparation errors. Native prefixes stay with the Source after refusal.
    pub fn drive_once_v1(
        &mut self,
    ) -> Result<Method46InitialTpmHelperDrivingLoanV1<'_>, Method46InitialStartupClosedV1> {
        require_current(self.startup)?;
        let birth = self.helper.birth.as_mut().ok_or(self.startup.closed)?;
        birth
            .prepare_once_v1()
            .map_err(|_| self.startup.fail(First::TpmHelperBirth))?;
        require_current(self.startup)?;
        let native = birth
            .drive_once_v1()
            .map_err(|_| self.startup.fail(First::TpmHelperBirth))?;
        Ok(Method46InitialTpmHelperDrivingLoanV1 {
            startup: self.startup,
            native,
        })
    }
}

impl Method46InitialTpmHelperDrivingLoanV1<'_> {
    /// Starts and measures the real fixed initial child under this same Source.
    ///
    /// No HELLO or private authentication is transmitted. Actual pidfd-anchored
    /// stat/context and executable/loader observations remain retained on error.
    ///
    /// # Errors
    /// Refuses changed/ended Source, native spawn/proc errors, wrong child MAC
    /// or image, repeated entry or missing original exec confirmation.
    pub fn start_child_once_v1(&mut self) -> Result<(), Method46InitialStartupClosedV1> {
        require_current(self.startup)?;
        let action = self.native.start_child_once_v1();
        // Observe the Source independently after a reached failed native birth.
        let after = require_current(self.startup);
        if action.is_err() || after.is_err() {
            Err(self.startup.fail(First::TpmHelperBirth))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::mem::ManuallyDrop;

    use super::*;

    #[test]
    fn method46_initial_helper_birth_requires_the_original_source_before_receiving() {
        for role in [
            Method46InitialServiceRoleV1::ControllerStorageClient,
            Method46InitialServiceRoleV1::StorageBroker,
        ] {
            let startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(role));
            let locks = Method46InitialTpmLockLoanV1 { startup: &startup };

            assert!(locks.lend_initial_helper_birth_once_v1().is_err());

            assert!(startup.body.is_none());
            assert_eq!(startup.receiving.get(), ResourceVector::ZERO);
            assert!(matches!(startup.first.get(), Some(First::TpmHelperBirth)));
        }
    }
}
