//! Checks the actual never-born Source code observation and its exact boundary.

use super::super::tests::{coordinator, installation, producer, storage_selection};
use super::super::*;
use crate::node_contract::RuntimeError;
use std::rc::Rc;

#[test]
fn actual_never_born_code_source_raw_exact_and_one_short_preserve_legacy_backing()
-> Result<(), String> {
    let coordinator = coordinator();
    let mut program = producer();
    program.events.reserve(29);
    let source = Rc::new(
        PacketCompleteSemanticSource::new_producer_for_collecting_world(
            installation(&coordinator, 0),
            program,
            coordinator,
            storage_selection(),
        )
        .map_err(|error| format!("{error:?}"))?,
    );
    let legacy = source
        .original_complete_code_retained_storage_data(usize::MAX)
        .map_err(|error| format!("{error:?}"))?;
    let actual = source
        .original_complete_code_retained_storage_precredit_data(usize::MAX)
        .map_err(|error| format!("{error:?}"))?;
    assert!(actual > 0);
    assert_eq!(actual, legacy);
    assert_eq!(
        source.original_complete_code_retained_storage_precredit_data(actual),
        Ok(actual)
    );
    assert!(
        source
            .original_complete_code_retained_storage_precredit_data(actual - 1)
            .is_err()
    );
    assert_eq!(
        source
            .original_complete_code_retained_storage_data(usize::MAX)
            .map_err(|error| format!("{error:?}"))?,
        legacy
    );
    // This explicit code phase cannot become a ready-birth observation.
    assert_eq!(
        source.original_complete_report_startup_retained_storage_precredit_data(usize::MAX),
        Err(RuntimeError::UnsupportedFacet)
    );
    assert!(source.capture_banks.borrow().is_none());
    assert!(source.ack_peer_birth.borrow().is_none());
    Ok(())
}

#[test]
fn initial_source_walk_counts_both_reactive_roots_without_input_static_authority()
-> Result<(), String> {
    use super::super::tests::reactive;
    use crate::node_adapters::cnp::CnpSemanticLaunchGuard;
    use crate::node_adapters::cnp::semantic::{
        CnpSemanticSource, retained_storage::preparation::PreparationCounter,
    };

    let coordinator = coordinator();
    let producer = Rc::new(
        PacketCompleteSemanticSource::new_producer_for_collecting_world(
            installation(&coordinator, 0),
            producer(),
            coordinator.clone(),
            storage_selection(),
        )
        .map_err(|error| format!("{error:?}"))?,
    );
    let reactive_one = Rc::new(
        PacketCompleteSemanticSource::new_reactive_for_collecting_world(
            installation(&coordinator, 1),
            reactive(&coordinator, 1),
            coordinator.clone(),
            storage_selection(),
        )
        .map_err(|error| format!("{error:?}"))?,
    );
    let reactive_two = Rc::new(
        PacketCompleteSemanticSource::new_reactive_for_collecting_world(
            installation(&coordinator, 2),
            reactive(&coordinator, 2),
            coordinator.clone(),
            storage_selection(),
        )
        .map_err(|error| format!("{error:?}"))?,
    );
    let equal_foreign = Rc::new(
        PacketCompleteSemanticSource::new_reactive_for_collecting_world(
            installation(&coordinator, 1),
            reactive(&coordinator, 1),
            coordinator,
            storage_selection(),
        )
        .map_err(|error| format!("{error:?}"))?,
    );
    let mut sources = [producer, reactive_one, reactive_two];
    for source in &mut sources {
        Rc::get_mut(source)
            .ok_or("unique original source before bank reservation")?
            .reserve_complete_capture_banks(
                PacketCompleteCaptureBankLimits {
                    host_protocol_bytes: 2 * 1024 * 1024,
                    semantic_bytes: 128 * 1024,
                    ancestry_bytes: 128 * 1024,
                    journal_bytes: 128 * 1024,
                },
                4 * 1024 * 1024,
            )
            .map_err(|error| format!("{error:?}"))?;
    }

    // These are genuine independently allocated initial Source owners. No
    // native read, graph/Input permit or missing static graph is fabricated.
    for source in &sources[1..] {
        assert!(source.original_complete_input_static_storage().is_err());
        assert!(
            source
                .original_complete_retained_nested_precredit_data(usize::MAX)
                .is_err()
        );
    }
    let mut complete = PreparationCounter::new(usize::MAX);
    for source in &sources {
        let installed: Rc<dyn CnpSemanticSource> = source.clone();
        CnpSemanticLaunchGuard::charge_original_initial_lifecycle_source_precredit_data(
            &installed,
            source,
            &mut complete,
        )
        .map_err(|error| format!("{error:?}"))?;
    }
    let actual = complete
        .finish()
        .complete_requested_bytes_precredit_data()
        .map_err(|error| format!("{error:?}"))?;
    let expected = sources.iter().try_fold(0usize, |total, source| {
        let bytes = source
            .original_initial_lifecycle_source_storage_data(usize::MAX)
            .map_err(|error| format!("{error:?}"))?;
        total
            .checked_add(bytes)
            .ok_or_else(|| "source total overflow".to_owned())
    })?;
    assert_eq!(actual, expected);
    assert!(
        actual
            > sources
                .iter()
                .map(|source| std::mem::size_of_val(source.as_ref()))
                .sum::<usize>()
    );

    for maximum in [actual, actual - 1] {
        let mut counter = PreparationCounter::new(maximum);
        let mut result = Ok(());
        for source in &sources {
            let installed: Rc<dyn CnpSemanticSource> = source.clone();
            result =
                CnpSemanticLaunchGuard::charge_original_initial_lifecycle_source_precredit_data(
                    &installed,
                    source,
                    &mut counter,
                );
            if result.is_err() {
                break;
            }
        }
        if maximum == actual {
            result.map_err(|error| format!("{error:?}"))?;
            assert_eq!(
                counter.finish().complete_requested_bytes_precredit_data(),
                Ok(actual)
            );
        } else {
            assert!(result.is_err());
        }
    }

    let installed: Rc<dyn CnpSemanticSource> = sources[1].clone();
    let mut foreign = PreparationCounter::new(usize::MAX);
    foreign.add(17).map_err(|error| format!("{error:?}"))?;
    assert_eq!(
        CnpSemanticLaunchGuard::charge_original_initial_lifecycle_source_precredit_data(
            &installed,
            &sources[2],
            &mut foreign,
        ),
        Err(RuntimeError::ForeignAuthority)
    );
    assert_eq!(foreign.finish().known_requested_bytes(), 17);
    assert_eq!(
        CnpSemanticLaunchGuard::charge_original_initial_lifecycle_source_precredit_data(
            &installed,
            &equal_foreign,
            &mut foreign,
        ),
        Err(RuntimeError::ForeignAuthority)
    );
    assert_eq!(foreign.finish().known_requested_bytes(), 17);

    for source in &sources[1..] {
        assert!(source.original_complete_input_static_storage().is_err());
        assert!(
            source
                .original_complete_retained_nested_precredit_data(usize::MAX)
                .is_err()
        );
        assert!(source.authenticate_current_native().is_err());
    }
    Ok(())
}
