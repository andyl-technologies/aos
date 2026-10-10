//! Exact original and boundary failure reconciliation before legacy formatting.

use std::cell::Cell;
use std::sync::atomic::Ordering;

use super::*;

#[derive(Debug)]
struct BoundaryToken(u64);

impl fmt::Display for BoundaryToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "boundary token {}", self.0)
    }
}

impl Error for BoundaryToken {}

#[test]
fn original_refusal_keeps_the_same_carrier_and_skips_boundary() {
    let (original, used) = crate::admitted_output::tests::fixture_budget_with_counter()
        .expect("finite original fixture");
    let refused = original.charge_bytes(u64::MAX).expect_err("local overflow");
    let before = used.load(Ordering::SeqCst);
    let callbacks = Cell::new(0);
    let mut boundary = OriginalDecodeBoundary {
        original: &original,
        boundary: || {
            callbacks.set(callbacks.get() + 1);
            Ok(())
        },
        first: None,
        admission: None,
        failure: None,
    };

    assert!(boundary.check().is_err());
    assert!(boundary.check().is_err());
    let error = boundary
        .finish(Err(loop_factory_error("later malformed relation")))
        .expect_err("original remains first");

    assert_eq!(error.admission_failure(), Some(&refused));
    assert!(error.boundary_failure().is_none());
    assert!(error.decode_failure().is_some());
    assert_eq!(callbacks.get(), 0);
    assert_eq!(used.load(Ordering::SeqCst), before);
    drop(original);
    assert!(used.load(Ordering::SeqCst) > 0);
    drop(error);
    assert_eq!(used.load(Ordering::SeqCst), 0);
}

#[test]
fn incoming_boundary_payload_precedes_later_admission_and_decoder_errors() {
    let (original, used) = crate::admitted_output::tests::fixture_budget_with_counter()
        .expect("finite original fixture");
    let callbacks = Cell::new(0);
    let mut boundary = OriginalDecodeBoundary {
        original: &original,
        boundary: || {
            callbacks.set(callbacks.get() + 1);
            Err(io::Error::other(BoundaryToken(17)))
        },
        first: None,
        admission: None,
        failure: None,
    };

    assert!(boundary.check().is_err());
    let later = original.charge_bytes(u64::MAX).expect_err("later overflow");
    assert!(boundary.check().is_err());
    let error = boundary
        .finish(Err(loop_factory_error("formatted relation failure")))
        .expect_err("boundary remains first");

    assert!(matches!(error.first, FirstFailure::Boundary));
    let actual = error.boundary_failure().expect("same owned incoming error");
    assert_eq!(
        actual
            .get_ref()
            .and_then(|error| error.downcast_ref::<BoundaryToken>())
            .map(|token| token.0),
        Some(17),
    );
    assert_eq!(error.admission_failure(), Some(&later));
    assert!(error.decode_failure().is_some());
    assert_eq!(callbacks.get(), 1);
    drop(original);
    assert!(used.load(Ordering::SeqCst) > 0);
    drop(error);
    assert_eq!(used.load(Ordering::SeqCst), 0);
}

#[test]
fn healthy_original_does_not_replace_a_real_decoder_failure() {
    let (original, _) = crate::admitted_output::tests::fixture_budget_with_counter()
        .expect("finite original fixture");
    let boundary = OriginalDecodeBoundary {
        original: &original,
        boundary: || Ok(()),
        first: None,
        admission: None,
        failure: None,
    };
    let error = boundary
        .finish(Err(loop_factory_error("actual malformed scheduler")))
        .expect_err("real decoder failure");

    assert!(matches!(error.first, FirstFailure::Decode));
    assert!(error.admission_failure().is_none());
    assert!(error.boundary_failure().is_none());
    assert!(error.decode_failure().is_some());
    original.verify_live().expect("same healthy original");
}

#[test]
fn successful_boundary_cannot_hide_refusal_before_the_next_effect() {
    let (original, _) = crate::admitted_output::tests::fixture_budget_with_counter()
        .expect("finite original fixture");
    let callbacks = Cell::new(0);
    let refused = Cell::new(None);
    let mut boundary = OriginalDecodeBoundary {
        original: &original,
        boundary: || {
            callbacks.set(callbacks.get() + 1);
            refused.set(Some(
                original
                    .charge_bytes(u64::MAX)
                    .expect_err("same original refusal"),
            ));
            Ok(())
        },
        first: None,
        admission: None,
        failure: None,
    };

    assert!(boundary.check().is_err());
    assert!(boundary.check().is_err());
    let error = boundary
        .finish(Err(loop_factory_error("unreached effect")))
        .expect_err("callback refusal remains first");

    assert!(matches!(error.first, FirstFailure::Admission));
    assert_eq!(error.admission_failure(), refused.take().as_ref());
    assert!(error.boundary_failure().is_none());
    assert_eq!(callbacks.get(), 1);
}

#[cfg(feature = "test-support")]
mod captured {
    use super::*;
    use crate::vm_lifecycle::checkpoint_store::test_support::build_authenticated_production_checkpoint_codec_fixture;
    use crucible::owned_decode::{DecodeResourceAuthority, ResourceLoan};
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;

    struct Authority {
        resident: Arc<AtomicU64>,
        descriptors: Arc<AtomicU64>,
    }
    struct Credit {
        counter: Arc<AtomicU64>,
        extent: u64,
    }

    impl Drop for Credit {
        fn drop(&mut self) {
            self.counter.fetch_sub(self.extent, Ordering::SeqCst);
        }
    }

    impl DecodeResourceAuthority for Authority {
        fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
            Ok(())
        }

        fn reserve(&self, bytes: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
            self.resident
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                    used.checked_add(bytes)
                        .filter(|next| *next <= 256 * 1024 * 1024)
                })
                .map_err(|_| {
                    DecodeAdmissionError::new(io::Error::from(io::ErrorKind::OutOfMemory))
                })?;
            Ok(ResourceLoan::new(Credit {
                counter: Arc::clone(&self.resident),
                extent: bytes,
            }))
        }

        fn reserve_descriptors(
            &self,
            descriptors: u64,
        ) -> Result<ResourceLoan, DecodeAdmissionError> {
            self.descriptors
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                    used.checked_add(descriptors).filter(|next| *next <= 8)
                })
                .map_err(|_| {
                    DecodeAdmissionError::new(io::Error::from(io::ErrorKind::TooManyLinks))
                })?;
            Ok(ResourceLoan::new(Credit {
                counter: Arc::clone(&self.descriptors),
                extent: descriptors,
            }))
        }
    }

    fn fixture_original()
    -> Result<(DecodeBudget, Arc<AtomicU64>, Arc<AtomicU64>), DecodeAdmissionError> {
        let resident = Arc::new(AtomicU64::new(0));
        let descriptors = Arc::new(AtomicU64::new(0));
        let authority = Arc::new(Authority {
            resident: Arc::clone(&resident),
            descriptors: Arc::clone(&descriptors),
        });
        Ok((
            DecodeBudget::new(authority, 256 * 1024 * 1024)?,
            resident,
            descriptors,
        ))
    }

    #[test]
    fn actual_capture_decoder_retains_two_opaque_owners_and_no_descriptor_escape()
    -> Result<(), Box<dyn Error>> {
        let fixture_directory = tempfile::tempdir()?;
        let _fixture_original = crucible::test_support::fixture_decode_scope(256 * 1024 * 1024)?;
        let fixture =
            build_authenticated_production_checkpoint_codec_fixture(fixture_directory.path())?;
        let (original, resident, descriptors) = fixture_original()?;
        let source = fixture.source();

        let first = fixture
            .closure()
            .decode_for_modeled_comparison_under_original(
                source,
                64 * 1024 * 1024,
                || Ok(()),
                &original,
            )?;
        let one = resident.load(Ordering::SeqCst);
        assert_eq!(descriptors.load(Ordering::SeqCst), 0);
        let second = fixture
            .closure()
            .decode_for_modeled_comparison_under_original(
                source,
                64 * 1024 * 1024,
                || Ok(()),
                &original,
            )?;
        assert!(resident.load(Ordering::SeqCst) > one);
        assert_eq!(descriptors.load(Ordering::SeqCst), 0);
        first.authenticate_configuration(fixture.configuration())?;
        assert!(first.same_modeled_continuation(source, &second, source)?);
        assert!(
            first
                .decoded
                .as_ref()
                .expect("retained comparison owner")
                .checkpoint
                .repository_restore
                .is_none()
        );

        drop(original);
        drop(first);
        assert!(resident.load(Ordering::SeqCst) > 0);
        drop(second);
        assert_eq!(resident.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[test]
    fn actual_capture_refusal_and_native_open_error_keep_their_distinct_first_causes()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let _fixture_original = crucible::test_support::fixture_decode_scope(256 * 1024 * 1024)?;
        let fixture = build_authenticated_production_checkpoint_codec_fixture(directory.path())?;
        let (original, _, descriptors) = fixture_original()?;
        let callbacks = Cell::new(0);
        let refused = original
            .charge_bytes(u64::MAX)
            .expect_err("same original local overflow");
        let error = fixture
            .closure()
            .decode_for_modeled_comparison_under_original(
                fixture.source(),
                64 * 1024 * 1024,
                || {
                    callbacks.set(callbacks.get() + 1);
                    Ok(())
                },
                &original,
            )
            .expect_err("first original refusal");
        assert_eq!(error.admission_failure(), Some(&refused));
        assert_eq!(callbacks.get(), 0);
        assert_eq!(descriptors.load(Ordering::SeqCst), 0);
        drop(error);
        drop(original);

        let (healthy, _, descriptors) = fixture_original()?;
        let mut missing = fixture.closure().clone();
        missing.object_directory = directory.path().join("absent-capture-objects");
        let error = missing
            .decode_for_modeled_comparison_under_original(
                fixture.source(),
                64 * 1024 * 1024,
                || Ok(()),
                &healthy,
            )
            .expect_err("actual source open fails before semantic decode");
        assert_eq!(
            error.source_failure().map(io::Error::kind),
            Some(io::ErrorKind::NotFound)
        );
        assert!(matches!(error.first, FirstFailure::Source));
        assert!(error.admission_failure().is_none());
        assert!(error.decode_failure().is_some());
        assert_eq!(descriptors.load(Ordering::SeqCst), 0);
        Ok(())
    }
}
