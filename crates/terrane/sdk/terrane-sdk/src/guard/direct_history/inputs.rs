//! Closes one full direct history against its exact original physical inputs.

use super::{DirectPurpose, invalid};
use crate::bucket::{
    BucketBinding,
    publication::{SelectedObservation, receipts::RecordRead},
};
use crate::store::{LocalFs, StoreFailure};
use terrane_format::gc::publication::evidence::{PhysicalRegistration, RequiredControlPin};

/// Pairs successful native physical closure with one exact direct invocation.
///
/// Only the factory below initializes this carrier after a genuine physical
/// read projection. It supplies no candidate, mutation or ACL permission.
pub(crate) struct CheckedDirectHistoryInputs<'scope, 'history, 'held> {
    purpose: &'scope DirectPurpose<'history, 'held>,
    scope: &'scope dyn crate::bucket::held::DirectNodeReads,
    pins: Vec<RequiredControlPin>,
    physical: crate::store::native_publication_effects::DirectHistoryPhysicalInputs<'scope, 'held>,
}

impl<'scope, 'history, 'held> CheckedDirectHistoryInputs<'scope, 'history, 'held> {
    /// Closes original DATA, selected and protected recipes before making proof.
    ///
    /// # Errors
    /// Refuses foreign scopes, missing controls, changed exact pins or original
    /// physical recipes, incomplete reads, inventory failure and unsupported
    /// native retention. A failed close never produces a completion carrier.
    pub(in crate::guard) async fn close<F: LocalFs + BucketBinding>(
        fs: &F,
        observed: &'scope SelectedObservation<'held>,
        purpose: &'scope DirectPurpose<'history, 'held>,
        scope: &'scope dyn crate::bucket::held::DirectNodeReads,
        controls: &[crate::guard::RetainedControls],
        original_reads: &[RecordRead],
    ) -> Result<Self, StoreFailure> {
        purpose.check(purpose.target, purpose.observation)?;
        scope.check_holder(purpose.observation.identity().ok_or_else(invalid)?)?;
        scope.check_selection(observed)?;
        scope.check_direct(purpose.read_check())?;
        if !std::ptr::eq(purpose.selected, observed) {
            return Err(invalid());
        }
        let pins = purpose
            .observation
            .resolver()
            .ok_or_else(invalid)?
            .control_pins()?;
        for pin in &pins {
            let PhysicalRegistration::Local(owner) = &pin.owner else {
                return Err(crate::store::StoreFailure::new(
                    crate::store::StoreErrorKind::Unsupported,
                ));
            };
            let record = controls
                .iter()
                .filter(|retained| {
                    retained.directory().as_os_str().as_encoded_bytes() == owner.control.as_slice()
                })
                .find_map(|retained| {
                    retained
                        .records()
                        .iter()
                        .find(|record| record.path() == retained.directory().join(&pin.key))
                })
                .ok_or_else(invalid)?;
            pin.check_record(record.bytes()).map_err(|_| invalid())?;
        }

        let payload_reads = scope.begin_closing()?;
        let physical =
            crate::store::native_publication_effects::DirectHistoryPhysicalInputs::close(
                fs,
                observed,
                controls,
                original_reads,
                payload_reads,
                purpose.read_check(),
            )
            .await?;
        let checked = Self {
            purpose,
            scope,
            pins,
            physical,
        };
        checked.check_reader_scope(scope)?;
        scope.complete_direct_closing(&checked)?;
        Ok(checked)
    }

    /// Requires this proof to belong to the same exact direct purpose.
    ///
    /// # Errors
    /// Refuses a foreign purpose even for the same immutable target.
    pub(in crate::guard) fn check_purpose(
        &self,
        purpose: &DirectPurpose<'_, '_>,
    ) -> Result<(), StoreFailure> {
        if !std::ptr::addr_eq(
            std::ptr::from_ref(self.purpose).cast::<()>(),
            std::ptr::from_ref(purpose).cast::<()>(),
        ) {
            return Err(invalid());
        }
        Ok(())
    }

    /// Requires this proof's exact reader, invocation and unchanged consumed pins.
    ///
    /// # Errors
    /// Refuses a foreign reader, holder or selected observation, changed resolver
    /// pins and a failed genuine registration inventory check.
    pub(crate) fn check_reader_scope(
        &self,
        scope: &dyn crate::bucket::held::DirectNodeReads,
    ) -> Result<(), StoreFailure> {
        self.purpose
            .check(self.purpose.target, self.purpose.observation)?;
        if !std::ptr::addr_eq(self.scope, scope) {
            return Err(invalid());
        }
        if !std::ptr::eq(self.purpose.selected, self.physical.observed()) {
            return Err(invalid());
        }
        scope.check_holder(self.purpose.observation.identity().ok_or_else(invalid)?)?;
        scope.check_selection(self.physical.observed())?;
        scope.check_direct(self.purpose.read_check())?;
        if self
            .purpose
            .observation
            .resolver()
            .ok_or_else(invalid)?
            .control_pins()?
            != self.pins
        {
            return Err(invalid());
        }
        Ok(())
    }
}
