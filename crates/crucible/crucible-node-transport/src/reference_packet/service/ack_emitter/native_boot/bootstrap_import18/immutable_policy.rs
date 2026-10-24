//! Adopts immutable policy DATA without constructing a native runtime model.
//!
//! This transition retains the exact original shared launch after full pure
//! validation, three-definition selection and actual SDK Hello publication.
//! Genuine enclosing Source/Birth credit and native ACK/phase issuers remain
//! separate; model callbacks in controls cannot create those permissions.

use super::*;
use crate::hello_frames::OriginalHelloFrameDigests;
use crate::reference_packet::NativeImport18PolicyData;
use std::rc::Rc;

/// Admits the actual additional shared owner beside all original populations.
pub(in super::super) trait OriginalImport18ImmutablePolicyAdmission {
    /// Admits the complete policy constructor before its shared allocation.
    ///
    /// # Errors
    /// Refuses unavailable original funding or incomplete enclosing custody.
    fn construct_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        row: [usize; 3],
    ) -> Result<(), ProviderError>;

    /// Observes the retained policy and every surviving original owner.
    ///
    /// # Errors
    /// Refuses short original credit or an incomplete whole-owner census.
    fn finish_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        actual_backing: usize,
    ) -> Result<(), ProviderError>;
}

/// Retains one nonrenewing policy construction occurrence and every output prefix.
pub(super) struct Attempt {
    cut: OperationalDeadline,
    started: bool,
    complete: bool,
    row: Option<[usize; 3]>,
    policy: Option<Rc<NativeImport18PolicyData>>,
}

impl Attempt {
    /// Initializes fixed controls before private bootstrap receipt.
    pub(super) fn empty_data(cut: OperationalDeadline) -> Self {
        Self {
            cut,
            started: false,
            complete: false,
            row: None,
            policy: None,
        }
    }

    fn guard_cut(&self, cut: OperationalDeadline) -> Result<(), ProviderError> {
        if self.cut != cut || self.cut.is_expired() {
            return Err(refused());
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn row_data(&self) -> Option<[usize; 3]> {
        self.row
    }
}

impl OriginalImport18RawBootstrap {
    /// Retains the original immutable policy DATA once under the original cut.
    ///
    /// Full baseline validation, exact full18 rosters and actual original Hello
    /// publication precede this construction. Failed terminal checks contain the
    /// actual SDK lease while leaving the policy and all original outputs owned.
    /// This creates no native model, ACK, opaque Initial/Recipe or phase permission.
    ///
    /// # Errors
    /// Refuses retry, missing/refused prior stages, changed original custody/cut,
    /// short admission, policy construction or terminal observation failure.
    pub(in super::super) fn construct_immutable_policy_data(
        &mut self,
        admission: &dyn OriginalImport18ImmutablePolicyAdmission,
    ) -> Result<(), ProviderError> {
        if self.immutable_policy.started {
            return Err(refused());
        }
        self.immutable_policy.started = true;

        let outcome = self.construct_current_policy(admission);
        let terminal = self.guard_immutable_policy_inputs();
        if let Err(error) = outcome.and(terminal.map(|_| ())) {
            let _ = self.hello_registrar.contain_admission_data();
            return Err(error);
        }
        self.immutable_policy.complete = true;
        Ok(())
    }

    fn guard_immutable_policy_inputs(&self) -> Result<OriginalHelloFrameDigests, ProviderError> {
        self.immutable_policy.guard_cut(self.cut)?;
        if !self.initial_reconstructed || !self.selection_authenticated {
            return Err(refused());
        }
        self.with_validated_launch_data(|_| Ok(()))?;
        let pair = self.with_published_hello_frame_digests_data(Ok)?;
        if let Some(policy) = &self.immutable_policy.policy {
            policy.authenticate_original_data(self.parsed.shared_launch_data()?)?;
            if policy.hello_data() != pair
                || policy.recipe_identity_data()
                    != self.typed_bodies_data()?.recipe.announced_identity_data()
            {
                return Err(refused());
            }
        }
        Ok(pair)
    }

    fn construct_current_policy(
        &mut self,
        admission: &dyn OriginalImport18ImmutablePolicyAdmission,
    ) -> Result<(), ProviderError> {
        self.guard_immutable_policy_inputs()?;
        self.admit_source_row(self.initial_construction.as_ref().ok_or_else(refused)?.row)?;
        let row = construction_data(self.bounds.requested_peak)?;
        self.immutable_policy.row = Some(row);
        admission.construct_data(self, row)?;
        self.guard_immutable_policy_inputs()?;

        let outcome = self.retain_current_policy();
        let terminal = self.guard_immutable_policy_inputs();
        let census = self
            .immutable_policy_backing_data()
            .and_then(|actual| admission.finish_data(self, actual));
        outcome?;
        terminal?;
        census
    }

    fn retain_current_policy(&mut self) -> Result<(), ProviderError> {
        let pair = self.guard_immutable_policy_inputs()?;
        let recipe = *self.typed_bodies_data()?.recipe.announced_identity_data();
        let launch = Rc::clone(self.parsed.shared_launch_data()?);
        let policy = NativeImport18PolicyData::from_original_data(launch, recipe, pair)?;
        // Install the shared owner before any subsequent fallible original guard.
        self.immutable_policy.policy = Some(Rc::new(policy));
        Ok(())
    }

    /// Lends completed policy DATA under the original SDK, launch and cut guards.
    ///
    /// The caller independently funds inspection and its Copy result. Neither the
    /// shared owner nor any configuration child moves or becomes a live witness.
    ///
    /// # Errors
    /// Refuses incomplete/refused construction, stale originals, callback refusal
    /// or a failed terminal guard, including when inspection itself returns an error.
    pub(in super::super) fn with_immutable_policy_data<R: Copy>(
        &self,
        inspect: impl FnOnce(&NativeImport18PolicyData) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.guard_immutable_policy_inputs()?;
        if !self.immutable_policy.complete {
            return Err(refused());
        }
        let policy = self.immutable_policy.policy.as_ref().ok_or_else(refused)?;
        let outcome = inspect(policy);
        let terminal = self.guard_immutable_policy_inputs();
        let output = outcome?;
        terminal?;
        Ok(output)
    }

    /// Names complete loan guards and the caller's concrete Copy result controls.
    ///
    /// Callback construction and retained outputs remain independently funded.
    /// This allocation-free quote does not lend a policy or admit inspection.
    ///
    /// # Errors
    /// Refuses checked layout accumulation overflow for the concrete result.
    pub(in super::super) fn immutable_policy_loan_counter_scratch_data<R: Copy>()
    -> Result<usize, ProviderError> {
        [
            size_of::<&NativeImport18PolicyData>(),
            size_of::<R>(),
            size_of::<R>(),
            size_of::<Result<R, ProviderError>>(),
            size_of::<Result<R, ProviderError>>(),
        ]
        .into_iter()
        .try_fold(counter_scratch_data(), |sum, field| {
            sum.checked_add(field).ok_or_else(refused)
        })
    }

    /// Counts the additional policy allocation only after proving the shared edge.
    ///
    /// The decoder already counts the original launch and every child. Pointer
    /// equality is mandatory before granting this one-graph alias discount.
    ///
    /// # Errors
    /// Refuses a different original allocation or requested-layout overflow.
    pub(super) fn immutable_policy_backing_data(&self) -> Result<usize, ProviderError> {
        match &self.immutable_policy.policy {
            Some(policy) => {
                policy.authenticate_original_data(self.parsed.shared_launch_data()?)?;
                NativeImport18PolicyData::shared_backing_data()
            }
            None => Ok(0),
        }
    }
}

/// Quotes actual shared construction beside original launch/Hello guard controls.
///
/// # Errors
/// Refuses requested-layout overflow or an independently short complete peak.
pub(in crate::reference_packet::service) fn construction_data(
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    let mut row = NativeImport18PolicyData::construction_data(maximum)?;
    row[2] = row[2].max(counter_scratch_data());
    if row
        .into_iter()
        .try_fold(0usize, usize::checked_add)
        .is_none_or(|n| n > maximum)
    {
        return Err(refused());
    }
    Ok(row)
}

/// Names this original transition and its sequential complete guard windows.
pub(in crate::reference_packet::service) fn counter_scratch_data() -> usize {
    launch_validation::counter_scratch_data().max(hello_evidence::counter_scratch_data())
        + NativeImport18PolicyData::counter_scratch_data()
        + private_body_owner_counter_scratch_data()
        + size_of::<Attempt>()
        + size_of::<&OriginalImport18RawBootstrap>() * 3
        + size_of::<&mut OriginalImport18RawBootstrap>() * 2
        + size_of::<&dyn OriginalImport18ImmutablePolicyAdmission>()
        + size_of::<OriginalHelloFrameDigests>() * 4
        + size_of::<Result<OriginalHelloFrameDigests, ProviderError>>() * 4
        + size_of::<Rc<NativeImport18PolicyData>>() * 2
        + size_of::<&Rc<NativeImport18PolicyData>>() * 2
        + size_of::<Option<&Rc<NativeImport18PolicyData>>>()
        + size_of::<[usize; 3]>() * 2
        + size_of::<Result<[usize; 3], ProviderError>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<(), ProviderError>>() * 6
        + size_of::<OperationalDeadline>()
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original immutable import18 policy DATA refused")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_policy_peak_and_concrete_inspection_controls_are_independent() {
        let row = construction_data(usize::MAX).unwrap();
        let peak = row
            .into_iter()
            .try_fold(0usize, usize::checked_add)
            .unwrap();
        assert_eq!(construction_data(peak).unwrap(), row);
        assert!(construction_data(peak - 1).is_err());
        assert!(row[0] > size_of::<NativeImport18PolicyData>());
        let unit = OriginalImport18RawBootstrap::immutable_policy_loan_counter_scratch_data::<()>()
            .unwrap();
        let large = OriginalImport18RawBootstrap::immutable_policy_loan_counter_scratch_data::<
            [u8; 4096],
        >()
        .unwrap();
        assert!(large >= unit + 8192);
    }
}
