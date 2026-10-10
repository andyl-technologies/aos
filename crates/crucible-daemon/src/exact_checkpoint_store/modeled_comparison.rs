//! Compares complete captured continuation before node-only materialization.
//!
//! Actual capture and supplied configuration owners stay borrowed throughout.
//! Choices are authenticated before `into_closure` can discard their presence.

use std::error::Error;
use std::fmt;
use std::io;

use crucible::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeCustody};
use crucible::{Configuration, Decision, ScenarioDefForm};
use crucible_api::OriginalCheckpointDecodeError;

use super::CapturedAttemptCheckpoint;
use crate::qemu_campaign_lifecycle::{
    GuardedCampaignReplayClosure, GuardedCampaignReplayClosureError,
};

#[derive(Debug)]
enum ComparisonFailure {
    Model(OriginalCheckpointDecodeError),
    Original(DecodeAdmissionError),
    Boundary(io::Error),
    Choice(GuardedCampaignReplayClosureError),
}

#[derive(Debug)]
struct ComparisonDiagnostic {
    first: Option<ComparisonFailure>,
    choice: Option<GuardedCampaignReplayClosureError>,
    admission: Option<DecodeAdmissionError>,
}

#[derive(Debug)]
enum EarlyFailure {
    Original(DecodeAdmissionError),
    Allocation(std::collections::TryReserveError),
}

/// Retains the first comparison cause and both original resource custodies.
///
/// Diagnostic storage is admitted and fallibly reserved before any comparison
/// callback or source read. Errors move into that existing storage without a
/// late allocation. Both original custodies outlive its actual physical free.
/// Cause access stays borrowed; no decoded model or raw account is exposed.
#[derive(Debug)]
pub struct CapturedModeledComparisonError {
    diagnostic: Vec<ComparisonDiagnostic>,
    early: Option<EarlyFailure>,
    first_custody: DecodeCustody,
    second_custody: DecodeCustody,
}

impl Drop for CapturedModeledComparisonError {
    fn drop(&mut self) {
        drop(std::mem::take(&mut self.diagnostic));
        drop(self.early.take());
    }
}

impl fmt::Display for CapturedModeledComparisonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(first) = self.primary_failure() {
            match first {
                ComparisonFailure::Model(error) => fmt::Display::fmt(error, formatter),
                ComparisonFailure::Original(error) => fmt::Display::fmt(error, formatter),
                ComparisonFailure::Boundary(error) => fmt::Display::fmt(error, formatter),
                ComparisonFailure::Choice(error) => fmt::Display::fmt(error, formatter),
            }
        } else {
            match &self.early {
                Some(EarlyFailure::Original(error)) => fmt::Display::fmt(error, formatter),
                Some(EarlyFailure::Allocation(error)) => fmt::Display::fmt(error, formatter),
                None => formatter.write_str("prepared comparison diagnostic"),
            }
        }
    }
}

impl Error for CapturedModeledComparisonError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        if let Some(first) = self.primary_failure() {
            Some(match first {
                ComparisonFailure::Model(error) => error,
                ComparisonFailure::Original(error) => error,
                ComparisonFailure::Boundary(error) => error,
                ComparisonFailure::Choice(error) => error,
            })
        } else {
            match &self.early {
                Some(EarlyFailure::Original(error)) => Some(error),
                Some(EarlyFailure::Allocation(error)) => Some(error),
                None => None,
            }
        }
    }
}

impl CapturedModeledComparisonError {
    /// Borrows a choice diagnostic retained beside an earlier original refusal.
    #[must_use]
    pub fn secondary_choice_failure(&self) -> Option<&GuardedCampaignReplayClosureError> {
        self.diagnostic
            .first()
            .and_then(|record| record.choice.as_ref())
    }

    /// Borrows an original refusal observed beside an earlier boundary error.
    #[must_use]
    pub fn secondary_admission_failure(&self) -> Option<&DecodeAdmissionError> {
        self.diagnostic
            .first()
            .and_then(|record| record.admission.as_ref())
    }

    fn primary_failure(&self) -> Option<&ComparisonFailure> {
        self.diagnostic
            .first()
            .and_then(|record| record.first.as_ref())
    }

    fn early(original: &DecodeBudget, other: &DecodeBudget, early: EarlyFailure) -> Self {
        Self {
            diagnostic: Vec::new(),
            early: Some(early),
            first_custody: original.custody(),
            second_custody: other.custody(),
        }
    }
}

struct PreparedComparisonFailure {
    prepared: CapturedModeledComparisonError,
}

impl PreparedComparisonFailure {
    fn prepare(
        original: &DecodeBudget,
        other: &DecodeBudget,
    ) -> Result<Self, CapturedModeledComparisonError> {
        if let Err(error) = original.verify_live() {
            original.record_failure(error.clone());
            return Err(CapturedModeledComparisonError::early(
                original,
                other,
                EarlyFailure::Original(error),
            ));
        }
        original
            .charge_array::<ComparisonDiagnostic>(1)
            .map_err(|error| {
                CapturedModeledComparisonError::early(
                    original,
                    other,
                    EarlyFailure::Original(error),
                )
            })?;
        let mut diagnostic = Vec::new();
        diagnostic.try_reserve_exact(1).map_err(|error| {
            CapturedModeledComparisonError::early(original, other, EarlyFailure::Allocation(error))
        })?;
        diagnostic.push(ComparisonDiagnostic {
            first: None,
            choice: None,
            admission: None,
        });
        Ok(Self {
            prepared: CapturedModeledComparisonError {
                diagnostic,
                early: None,
                first_custody: original.custody(),
                second_custody: other.custody(),
            },
        })
    }

    fn capture(
        &mut self,
        first: ComparisonFailure,
        choice: Option<GuardedCampaignReplayClosureError>,
        admission: Option<DecodeAdmissionError>,
    ) -> CapturedModeledComparisonError {
        // Preparation creates exactly one record. Its first move exits the
        // comparison; no caller can extract or reuse the private slot.
        self.prepared.diagnostic[0] = ComparisonDiagnostic {
            first: Some(first),
            choice,
            admission,
        };
        CapturedModeledComparisonError {
            diagnostic: std::mem::take(&mut self.prepared.diagnostic),
            early: None,
            first_custody: self.prepared.first_custody.clone(),
            second_custody: self.prepared.second_custody.clone(),
        }
    }

    fn model(&mut self, error: OriginalCheckpointDecodeError) -> CapturedModeledComparisonError {
        self.capture(ComparisonFailure::Model(error), None, None)
    }

    fn choice(
        &mut self,
        original: &DecodeBudget,
        error: GuardedCampaignReplayClosureError,
    ) -> CapturedModeledComparisonError {
        match original.check() {
            Ok(()) => self.capture(ComparisonFailure::Choice(error), None, None),
            Err(admission) => {
                self.capture(ComparisonFailure::Original(admission), Some(error), None)
            }
        }
    }
}

fn verify_original(
    original: &DecodeBudget,
    failure: &mut PreparedComparisonFailure,
) -> Result<(), CapturedModeledComparisonError> {
    original.verify_live().map_err(|error| {
        original.record_failure(error.clone());
        failure.capture(ComparisonFailure::Original(error), None, None)
    })
}

fn check(
    original: &DecodeBudget,
    boundary: &mut dyn FnMut() -> io::Result<()>,
    failure: &mut PreparedComparisonFailure,
) -> Result<(), CapturedModeledComparisonError> {
    verify_original(original, failure)?;
    match boundary() {
        Ok(()) => verify_original(original, failure),
        Err(error) => {
            let admission = original.verify_live().err();
            if let Some(error) = &admission {
                original.record_failure(error.clone());
            }
            Err(failure.capture(ComparisonFailure::Boundary(error), None, admission))
        }
    }
}

fn verify_acceptance(
    original: &DecodeBudget,
    other: &DecodeBudget,
) -> Result<(), CapturedModeledComparisonError> {
    for account in [original, other] {
        if let Err(error) = account.verify_live() {
            account.record_failure(error.clone());
            return Err(CapturedModeledComparisonError::early(
                original,
                other,
                EarlyFailure::Original(error),
            ));
        }
    }
    Ok(())
}

fn authenticate_choices(
    capture: &CapturedAttemptCheckpoint,
    source: &ScenarioDefForm,
    configuration: &Configuration,
    original: &DecodeBudget,
    failure: &mut PreparedComparisonFailure,
) -> Result<(), CapturedModeledComparisonError> {
    let _scope = original.enter();
    match &capture.choice_closure {
        None => {
            if configuration
                .schedule
                .decisions()
                .iter()
                .any(|decision| matches!(decision, Decision::Selection(_)))
            {
                return Err(failure.choice(
                    original,
                    GuardedCampaignReplayClosureError::Invalid {
                        reason: "capture lacks complete choice records for its schedule",
                    },
                ));
            }
        }
        Some(bytes) => {
            let choices = GuardedCampaignReplayClosure::from_canonical_bytes(bytes)
                .map_err(|error| failure.choice(original, error))?;
            choices
                .validate_for_schedule(source, &configuration.schedule)
                .map_err(|error| failure.choice(original, error))?;
        }
    }
    Ok(())
}

impl CapturedAttemptCheckpoint {
    // Both real capture owners and their original/source/configuration inputs
    // are distinct authorities. Bundling them into an arbitrary grant would hide
    // the before-materialization ownership requirement.
    /// Compares both complete captured modeled continuations and choice records.
    ///
    /// This reads each actual retained capture before node-only materialization.
    /// Each supplied complete configuration must equal its opaque authenticated
    /// decoded owner before its schedule authenticates choice provenance. Both
    /// owning configurations, captures and original keepers remain caller-owned
    /// and paid until every returned failure and decoded owner has closed.
    ///
    /// Optional choice presence is exact: absent differs from a present empty
    /// closure, and partial discovery records never qualify complete coverage.
    /// This compares modeled state only; native RAM/device material and physical
    /// source grants remain independently required at the same stopped boundary.
    ///
    /// # Errors
    /// Returns the first original, boundary, source/relation, modeled decoder or
    /// choice authentication error while retaining its same-original custody.
    // crucible-lint: allow rust-allow -- Both retained captures and original accounts must remain distinct comparison inputs.
    #[allow(clippy::too_many_arguments)]
    pub fn same_modeled_continuation_under_original(
        &self,
        source: &ScenarioDefForm,
        configuration: &Configuration,
        other: &Self,
        other_source: &ScenarioDefForm,
        other_configuration: &Configuration,
        original: &DecodeBudget,
        other_original: &DecodeBudget,
        byte_limit: u64,
        boundary: &mut dyn FnMut() -> io::Result<()>,
    ) -> Result<bool, CapturedModeledComparisonError> {
        let Self {
            closure,
            choice_closure,
        } = self;
        let Self {
            closure: other_closure,
            choice_closure: other_choice_closure,
        } = other;
        let mut failure = PreparedComparisonFailure::prepare(original, other_original)?;
        check(original, boundary, &mut failure)?;
        check(other_original, boundary, &mut failure)?;
        let first = closure
            .decode_for_modeled_comparison_under_original(
                source,
                byte_limit,
                &mut *boundary,
                original,
            )
            .map_err(|error| failure.model(error))?;
        let second = other_closure
            .decode_for_modeled_comparison_under_original(
                other_source,
                byte_limit,
                &mut *boundary,
                other_original,
            )
            .map_err(|error| failure.model(error))?;
        first
            .authenticate_configuration(configuration)
            .map_err(|error| failure.model(error))?;
        second
            .authenticate_configuration(other_configuration)
            .map_err(|error| failure.model(error))?;
        check(original, boundary, &mut failure)?;
        authenticate_choices(self, source, configuration, original, &mut failure)?;
        check(other_original, boundary, &mut failure)?;
        authenticate_choices(
            other,
            other_source,
            other_configuration,
            other_original,
            &mut failure,
        )?;
        let equal = first
            .same_modeled_continuation(source, &second, other_source)
            .map_err(|error| failure.model(error))?
            && choice_closure == other_choice_closure;

        // Model allocations close before the final original acceptance cuts.
        drop(second);
        drop(first);
        check(original, boundary, &mut failure)?;
        check(other_original, boundary, &mut failure)?;
        // The last callback can invalidate either account. Both no-callback
        // cuts follow every callback before a healthy comparison is exposed.
        drop(failure);
        verify_acceptance(original, other_original)?;
        Ok(equal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible::{ContentHash, ScenarioDef};
    use crucible_api::build_authenticated_production_checkpoint_codec_fixture;

    #[test]
    fn captured_consumer_authenticates_owners_and_preserves_choice_presence()
    -> Result<(), Box<dyn Error>> {
        let resources = crate::exact_checkpoint_store::test_support::fixture_ram_root_resources()?;
        let original = DecodeBudget::for_store(resources)?;
        let _scope = original.enter();
        let directory = tempfile::tempdir()?;
        let fixture = build_authenticated_production_checkpoint_codec_fixture(directory.path())?;
        let first = CapturedAttemptCheckpoint::from_production_closure(fixture.closure().clone());
        let mut second =
            CapturedAttemptCheckpoint::from_production_closure(fixture.closure().clone());
        let source = fixture.source();
        let configuration = fixture.configuration();
        let mut boundary = || Ok(());

        assert!(first.same_modeled_continuation_under_original(
            source,
            configuration,
            &second,
            source,
            configuration,
            &original,
            &original,
            64 * 1024 * 1024,
            &mut boundary,
        )?);
        second.choice_closure = Some(GuardedCampaignReplayClosure::empty().to_canonical_bytes()?);
        assert!(!first.same_modeled_continuation_under_original(
            source,
            configuration,
            &second,
            source,
            configuration,
            &original,
            &original,
            64 * 1024 * 1024,
            &mut boundary,
        )?);

        // The same identity handle cannot replace full material equality.
        let mut wrong_configuration = configuration.clone();
        wrong_configuration.def = ScenarioDef::from_trusted_identity(
            configuration.def.id(),
            configuration.def.seed(),
            configuration.def.app_random_draw_cap() + 1,
        );
        let error = first
            .same_modeled_continuation_under_original(
                source,
                &wrong_configuration,
                &second,
                source,
                configuration,
                &original,
                &original,
                64 * 1024 * 1024,
                &mut boundary,
            )
            .expect_err("full supplied configuration mismatch");
        assert!(matches!(
            error.primary_failure(),
            Some(ComparisonFailure::Model(_))
        ));
        original.verify_live()?;
        Ok(())
    }

    #[test]
    fn captured_consumer_stops_on_original_refusal_before_any_read_boundary()
    -> Result<(), Box<dyn Error>> {
        let resources = crate::exact_checkpoint_store::test_support::fixture_ram_root_resources()?;
        let original = DecodeBudget::for_store(resources)?;
        let _scope = original.enter();
        let directory = tempfile::tempdir()?;
        let fixture = build_authenticated_production_checkpoint_codec_fixture(directory.path())?;
        let first = CapturedAttemptCheckpoint::from_production_closure(fixture.closure().clone());
        let second = CapturedAttemptCheckpoint::from_production_closure(fixture.closure().clone());
        let refused = original
            .charge_bytes(u64::MAX)
            .expect_err("same original refusal");
        let mut callbacks = 0;
        let mut boundary = || {
            callbacks += 1;
            Ok(())
        };

        let error = first
            .same_modeled_continuation_under_original(
                fixture.source(),
                fixture.configuration(),
                &second,
                fixture.source(),
                fixture.configuration(),
                &original,
                &original,
                64 * 1024 * 1024,
                &mut boundary,
            )
            .expect_err("first original failure");
        match &error.early {
            Some(EarlyFailure::Original(actual)) => assert_eq!(actual, &refused),
            other => {
                return Err(io::Error::other(format!("unexpected first cause: {other:?}")).into());
            }
        }
        assert_eq!(callbacks, 0);
        assert_eq!(fixture.closure().scenario(), fixture.source().id());
        assert_ne!(fixture.closure().identity(), ContentHash::default());
        Ok(())
    }

    #[test]
    fn boundary_payload_stays_first_when_its_postcheck_observes_original_refusal()
    -> Result<(), Box<dyn Error>> {
        let resources = crate::exact_checkpoint_store::test_support::fixture_ram_root_resources()?;
        let original = DecodeBudget::for_store(resources)?;
        let mut refused = None;
        let mut boundary = || {
            refused = Some(
                original
                    .charge_bytes(u64::MAX)
                    .expect_err("same original refusal"),
            );
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        };

        let mut failure = PreparedComparisonFailure::prepare(&original, &original)?;
        let error = check(&original, &mut boundary, &mut failure)
            .expect_err("actual boundary remains first");

        match error.primary_failure() {
            Some(ComparisonFailure::Boundary(actual)) => {
                assert_eq!(actual.kind(), io::ErrorKind::PermissionDenied);
            }
            other => panic!("unexpected first cause: {other:?}"),
        }
        assert_eq!(error.secondary_admission_failure(), refused.as_ref());
        Ok(())
    }

    fn final_callback_refusal(poison_other_account: bool) -> Result<(), Box<dyn Error>> {
        let resources = crate::exact_checkpoint_store::test_support::fixture_ram_root_resources()?;
        let fixture_original = DecodeBudget::for_store(resources.clone())?;
        let _scope = fixture_original.enter();
        let directory = tempfile::tempdir()?;
        let fixture = build_authenticated_production_checkpoint_codec_fixture(directory.path())?;
        let first = CapturedAttemptCheckpoint::from_production_closure(fixture.closure().clone());
        let second = CapturedAttemptCheckpoint::from_production_closure(fixture.closure().clone());
        let first_original = DecodeBudget::for_store(resources.clone())?;
        let second_original = DecodeBudget::for_store(resources)?;
        let mut expected_callbacks = 0;
        let mut healthy_boundary = || {
            expected_callbacks += 1;
            Ok(())
        };
        assert!(first.same_modeled_continuation_under_original(
            fixture.source(),
            fixture.configuration(),
            &second,
            fixture.source(),
            fixture.configuration(),
            &first_original,
            &second_original,
            64 * 1024 * 1024,
            &mut healthy_boundary,
        )?);
        assert!(expected_callbacks >= 2);

        let target = if poison_other_account {
            &first_original
        } else {
            &second_original
        };
        let mut callbacks = 0;
        let mut refused = None;
        let mut boundary = || {
            callbacks += 1;
            if callbacks == expected_callbacks {
                refused = Some(
                    target
                        .charge_bytes(u64::MAX)
                        .expect_err("last callback refusal"),
                );
            }
            Ok(())
        };
        let error = first
            .same_modeled_continuation_under_original(
                fixture.source(),
                fixture.configuration(),
                &second,
                fixture.source(),
                fixture.configuration(),
                &first_original,
                &second_original,
                64 * 1024 * 1024,
                &mut boundary,
            )
            .expect_err("no healthy result after the final callback refusal");

        assert_eq!(
            error
                .source()
                .and_then(|cause| cause.downcast_ref::<DecodeAdmissionError>()),
            refused.as_ref()
        );
        assert_eq!(callbacks, expected_callbacks);
        assert_eq!(target.check().err().as_ref(), refused.as_ref());
        Ok(())
    }

    #[test]
    fn final_successful_callback_cannot_hide_its_original_refusal() -> Result<(), Box<dyn Error>> {
        final_callback_refusal(false)
    }

    #[test]
    fn final_successful_callback_cannot_invalidate_the_other_original_unnoticed()
    -> Result<(), Box<dyn Error>> {
        final_callback_refusal(true)
    }
}

#[cfg(test)]
mod diagnostic_geometry_tests {
    use super::*;

    struct Authority {
        used: std::sync::Arc<std::sync::atomic::AtomicU64>,
        calls: std::sync::atomic::AtomicU64,
        refusing: std::sync::atomic::AtomicBool,
    }

    struct Credit {
        used: std::sync::Arc<std::sync::atomic::AtomicU64>,
        extent: u64,
    }

    impl Drop for Credit {
        fn drop(&mut self) {
            self.used
                .fetch_sub(self.extent, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl crucible::owned_decode::DecodeResourceAuthority for Authority {
        fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
            Ok(())
        }

        fn reserve(
            &self,
            bytes: u64,
        ) -> Result<crucible::owned_decode::ResourceLoan, DecodeAdmissionError> {
            use std::sync::atomic::Ordering;
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.refusing.load(Ordering::SeqCst) {
                return Err(DecodeAdmissionError::new(std::fmt::Error));
            }
            self.used.fetch_add(bytes, Ordering::SeqCst);
            Ok(crucible::owned_decode::ResourceLoan::new(Credit {
                used: self.used.clone(),
                extent: bytes,
            }))
        }
    }

    fn original() -> Result<(DecodeBudget, std::sync::Arc<Authority>), DecodeAdmissionError> {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, AtomicU64, Ordering},
        };
        let authority = Arc::new(Authority {
            used: Arc::new(AtomicU64::new(0)),
            calls: AtomicU64::new(0),
            refusing: AtomicBool::new(false),
        });
        let original = DecodeBudget::new(authority.clone(), 1024 * 1024)?;
        authority.calls.store(0, Ordering::SeqCst);
        Ok((original, authority))
    }

    #[test]
    fn error_moves_into_same_prepaid_record_and_retains_original_until_drop()
    -> Result<(), Box<dyn Error>> {
        use std::sync::atomic::Ordering;
        let (original, authority) = original()?;
        let mut prepared = PreparedComparisonFailure::prepare(&original, &original)?;
        let address = prepared.prepared.diagnostic.as_ptr().addr();
        assert_eq!(authority.calls.load(Ordering::SeqCst), 1);

        let error = prepared.capture(
            ComparisonFailure::Boundary(io::ErrorKind::PermissionDenied.into()),
            None,
            None,
        );
        assert_eq!(error.diagnostic.as_ptr().addr(), address);
        assert_eq!(authority.calls.load(Ordering::SeqCst), 1);
        drop(prepared);
        drop(original);
        assert!(authority.used.load(Ordering::SeqCst) > 0);
        drop(error);
        assert_eq!(authority.used.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[test]
    fn diagnostic_original_refusal_stops_before_any_boundary() -> Result<(), Box<dyn Error>> {
        use std::sync::atomic::Ordering;
        let (original, authority) = original()?;
        authority.refusing.store(true, Ordering::SeqCst);

        let error = match PreparedComparisonFailure::prepare(&original, &original) {
            Ok(_) => panic!("diagnostic target must refuse"),
            Err(error) => error,
        };
        assert!(error.diagnostic.is_empty());
        assert_eq!(
            error
                .source()
                .and_then(|cause| cause.downcast_ref::<DecodeAdmissionError>()),
            original.failure()?.as_ref()
        );
        assert_eq!(authority.calls.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn first_boundary_cause_precedes_an_already_refused_second_original()
    -> Result<(), Box<dyn Error>> {
        let (first, _) = original()?;
        let (second, _) = original()?;
        let refused = second
            .charge_bytes(u64::MAX)
            .expect_err("second already refused");
        let mut prepared = PreparedComparisonFailure::prepare(&first, &second)?;
        let mut callbacks = 0;
        let mut boundary = || {
            callbacks += 1;
            Err(io::ErrorKind::PermissionDenied.into())
        };

        let error = check(&first, &mut boundary, &mut prepared)
            .expect_err("first actual callback retains its earlier cause");
        assert_eq!(callbacks, 1);
        assert_eq!(
            error
                .source()
                .and_then(|cause| cause.downcast_ref::<io::Error>())
                .map(io::Error::kind),
            Some(io::ErrorKind::PermissionDenied)
        );
        assert!(error.secondary_admission_failure().is_none());
        assert_eq!(second.failure()?.as_ref(), Some(&refused));
        first.verify_live()?;
        Ok(())
    }

    #[test]
    fn comparison_error_stays_compact_with_one_prepaid_diagnostic_record() {
        assert!(std::mem::size_of::<CapturedModeledComparisonError>() <= 128);
        assert!(std::mem::size_of::<ComparisonDiagnostic>() > 128);
    }
}
