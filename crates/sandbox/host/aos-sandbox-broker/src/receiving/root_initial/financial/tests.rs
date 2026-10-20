//! Exercises the sole passive complete-liability arithmetic and failure custody.
//!
//! These tests construct no enrollment, native invocation, writer, role loan or
//! disposal proof. Provided envelopes exercise only the private arithmetic.

use super::*;

#[test]
fn traffic_is_additive_and_never_accepts_a_resident_dimension() {
    let traffic = ResourceVector::ZERO
        .with(D::NetworkBytes, 4)
        .with(D::LogBytes, 2);
    let envelope = ResourceVector::ZERO
        .with(D::NetworkBytes, 10)
        .with(D::LogBytes, 6);
    let original = RootFinancialCustodyV1::new();
    assert!(
        original
            .mutate(envelope, MutationV1::Traffic(traffic))
            .is_ok()
    );
    assert!(
        original
            .mutate(envelope, MutationV1::Traffic(traffic))
            .is_ok()
    );
    assert!(
        original
            .mutate(envelope, MutationV1::Traffic(traffic))
            .is_err()
    );
    assert_eq!(
        original
            .state
            .lock()
            .unwrap()
            .native_debt
            .get(D::NetworkBytes),
        8
    );

    for dimension in D::ALL {
        let one = ResourceVector::ZERO.with(dimension, 1);
        let consumable = matches!(
            dimension,
            D::NetworkBytes | D::LogBytes | D::PublicationStagingBytes | D::OutputBytes
        );
        assert_eq!(require_traffic(one).is_ok(), consumable);
    }
}

#[test]
fn later_stages_and_flights_cannot_spend_retained_native_debt() {
    let envelope = ResourceVector::ZERO.with(D::MemoryBytes, 100);
    let stages = ResourceVector::ZERO.with(D::MemoryBytes, 40);
    let flight = ResourceVector::ZERO.with(D::MemoryBytes, 20);
    let debt = ResourceVector::ZERO.with(D::MemoryBytes, 30);
    assert!(require_complete(envelope, stages, flight, debt).is_ok());
    assert!(
        require_complete(
            envelope,
            ResourceVector::ZERO.with(D::MemoryBytes, 60),
            flight,
            debt
        )
        .is_err()
    );
    assert!(
        require_complete(
            envelope,
            stages,
            ResourceVector::ZERO.with(D::MemoryBytes, 40),
            debt
        )
        .is_err()
    );
    assert!(
        require_complete(
            envelope,
            ResourceVector::ZERO.with(D::MemoryBytes, 50),
            flight,
            debt
        )
        .is_ok()
    );
}

#[test]
fn failed_native_debit_preserves_all_prior_dimensions_and_first_cause() {
    let original = RootFinancialCustodyV1::new();
    let envelope = ResourceVector::ZERO
        .with(D::MemoryBytes, 100)
        .with(D::OpenFiles, 4);
    let stage = ResourceVector::ZERO
        .with(D::MemoryBytes, 70)
        .with(D::OpenFiles, 3);
    let native = ResourceVector::ZERO
        .with(D::MemoryBytes, 20)
        .with(D::OpenFiles, 1);
    assert!(original.mutate(envelope, MutationV1::Stage(stage)).is_ok());
    assert!(
        original
            .mutate(envelope, MutationV1::Native(native))
            .is_ok()
    );
    assert!(
        original
            .mutate(
                envelope,
                MutationV1::Native(ResourceVector::ZERO.with(D::OpenFiles, 1))
            )
            .is_err()
    );
    let first = original.failure().unwrap() as *const dyn Error;
    assert!(
        original
            .mutate(
                envelope,
                MutationV1::Native(ResourceVector::ZERO.with(D::MemoryBytes, 11))
            )
            .is_err()
    );
    assert!(std::ptr::eq(
        first,
        original.failure().unwrap() as *const dyn Error
    ));
    assert_eq!(original.state.lock().unwrap().native_debt, native);
}

#[test]
fn overflowing_native_debt_keeps_its_previous_value() {
    let original = RootFinancialCustodyV1::new();
    let maximum = ResourceVector::ZERO.with(D::MemoryBytes, u64::MAX);
    assert!(
        original
            .mutate(maximum, MutationV1::Native(maximum))
            .is_ok()
    );

    assert!(
        original
            .mutate(
                maximum,
                MutationV1::Native(ResourceVector::ZERO.with(D::MemoryBytes, 1)),
            )
            .is_err()
    );

    assert_eq!(original.state.lock().unwrap().native_debt, maximum);
    assert!(original.failure().is_some());
}

#[test]
fn native_debt_cannot_overlap_the_actual_stage_and_consumed_flight() {
    let envelope = ResourceVector::ZERO
        .with(D::MemoryBytes, 100)
        .with(D::OpenFiles, 5);
    let stage = ResourceVector::ZERO
        .with(D::MemoryBytes, 40)
        .with(D::OpenFiles, 2);
    let flight = ResourceVector::ZERO
        .with(D::MemoryBytes, 30)
        .with(D::OpenFiles, 2);
    let native = ResourceVector::ZERO
        .with(D::MemoryBytes, 30)
        .with(D::OpenFiles, 1);

    for dimension in [D::MemoryBytes, D::OpenFiles] {
        let original = RootFinancialCustodyV1::new();
        assert!(original.mutate(envelope, MutationV1::Stage(stage)).is_ok());
        assert!(
            original
                .mutate(envelope, MutationV1::BeginFlight(flight))
                .is_ok()
        );
        assert!(
            original
                .mutate(envelope, MutationV1::Native(native))
                .is_ok()
        );

        assert!(
            original
                .mutate(
                    envelope,
                    MutationV1::Native(ResourceVector::ZERO.with(dimension, 1)),
                )
                .is_err()
        );

        assert_eq!(original.state.lock().unwrap().native_debt, native);
        let failed_flight = original.failure.get().unwrap().flight.as_ref().unwrap();
        assert!(
            failed_flight
                .operation
                .as_ref()
                .unwrap()
                .is_consumed_current()
        );
    }
}

#[test]
fn failed_growth_retains_the_entered_operation_in_the_immutable_first_cell() {
    let original = RootFinancialCustodyV1::new();
    let envelope = ResourceVector::ZERO.with(D::MemoryBytes, 100);
    assert!(
        original
            .mutate(
                envelope,
                MutationV1::BeginFlight(ResourceVector::ZERO.with(D::MemoryBytes, 70))
            )
            .is_ok()
    );
    assert!(
        original
            .mutate(
                envelope,
                MutationV1::Stage(ResourceVector::ZERO.with(D::MemoryBytes, 40))
            )
            .is_err()
    );

    let failure = original.failure.get().unwrap();
    assert!(
        failure
            .flight
            .as_ref()
            .unwrap()
            .operation
            .as_ref()
            .unwrap()
            .is_consumed_current()
    );
    assert!(original.state.lock().unwrap().flight.is_none());
    assert!(
        original
            .mutate(envelope, MutationV1::BeginFlight(ResourceVector::ZERO))
            .is_err()
    );
}

#[test]
fn poison_keeps_its_actual_flight_in_place_and_exposes_one_stable_cause() {
    let original = RootFinancialCustodyV1::new();
    let envelope = ResourceVector::ZERO.with(D::MemoryBytes, 100);
    assert!(
        original
            .mutate(
                envelope,
                MutationV1::BeginFlight(ResourceVector::ZERO.with(D::MemoryBytes, 70))
            )
            .is_ok()
    );
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _state = original.state.lock().unwrap();
        panic!("actual sum lock unwound");
    }));
    assert!(caught.is_err());
    let first = original.failure().unwrap() as *const dyn Error;
    assert!(std::ptr::eq(
        first,
        original.failure().unwrap() as *const dyn Error
    ));
    assert!(original.failure.get().unwrap().flight.is_none());
    let state = match original.state.lock() {
        Ok(_) => panic!("poisoned custody healed"),
        Err(poisoned) => poisoned.into_inner(),
    };
    assert!(
        state
            .flight
            .as_ref()
            .unwrap()
            .operation
            .as_ref()
            .unwrap()
            .is_consumed_current()
    );
}
