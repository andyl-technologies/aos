//! Observes real storage-only partials without constructing a native-ready Source.

use super::*;

pub(super) fn inert_row() -> Result<OriginalImport18CaptureBankConstructionData, RuntimeError> {
    let protocol =
        ProtocolSnapshotReservation::owned11_retained_reservation_construction_data(128, 256, 2, 7)
            .map_err(|_| RuntimeError::ResourceLimit)?;
    let retained = sum(
        [
            size_of::<Import18CaptureBankReservation>(),
            64,
            32,
            16,
            8,
            8,
            8192,
            protocol.0,
        ],
        usize::MAX,
    )?;
    Ok(OriginalImport18CaptureBankConstructionData {
        // This inert test row is never passed to a Source authentication or
        // reservation method. It cannot identify or authorize a live Source.
        source: std::ptr::null(),
        process: std::process::id(),
        thread: std::thread::current().id(),
        limits: PacketCompleteCaptureBankLimits {
            host_protocol_bytes: 128,
            semantic_bytes: 64,
            ancestry_bytes: 32,
            journal_bytes: 16,
        },
        metadata_rows: 7,
        storage_extents: Import18CaptureBankStorageExtents {
            native_snapshot: 8,
            native_control: 8,
            history_bytes: 256,
            lifetime_frames: 2,
        },
        axes: (retained, protocol.1, protocol.2),
    })
}

#[test]
fn missing_and_empty_partial_banks_have_distinct_passive_history() -> Result<(), RuntimeError> {
    let mut owner = Import18CaptureBankReservation::retaining(inert_row()?);
    let missing = owner.history_data();
    assert!(missing.started && missing.failed);
    assert!(!missing.complete && !missing.published);
    assert!(missing.partial_capacities.is_none());

    owner.banks = Some(PacketCompleteCaptureBanks::empty_import18_data());
    let empty = owner.history_data();
    assert_eq!(empty.partial_capacities, Some([0; 7]));
    assert!(empty.started && empty.failed);
    assert!(!empty.complete && !empty.published);
    assert_eq!(empty.row_axes, missing.row_axes);
    assert_eq!(empty.limits, [128, 64, 32, 16]);
    assert_eq!(empty.metadata_rows, 7);
    assert_eq!(
        owner.retained_backing_data::<RuntimeError>(usize::MAX)?,
        size_of::<Import18CaptureBankReservation>()
    );
    Ok(())
}

#[test]
fn later_real_reservation_refusal_keeps_prior_semantic_and_protocol_capacity()
-> Result<(), RuntimeError> {
    let mut owner = Import18CaptureBankReservation::retaining(inert_row()?);
    owner.banks = Some(PacketCompleteCaptureBanks::empty_import18_data());
    let banks = owner.banks.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
    CnpSemanticSnapshotReservation::reserve_into_with_error::<RuntimeError>(
        64,
        64,
        &mut banks.semantic,
    )?;
    CnpSemanticSnapshotReservation::reserve_into_with_error::<RuntimeError>(
        32,
        32,
        &mut banks.ancestry,
    )?;
    ProtocolSnapshotReservation::reserve_complete_owned11_into(128, 256, 2, 7, &mut banks.protocol)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    let protocol = banks
        .protocol
        .as_ref()
        .ok_or(RuntimeError::OwnerUnavailable)?
        .allocated_bytes();

    // The actual defining constructor refuses this empty later slot. No
    // fabricated completed Source or native callback is used to create failure.
    assert!(
        CnpSemanticSnapshotReservation::reserve_into_with_error::<RuntimeError>(
            0,
            0,
            &mut banks.journal,
        )
        .is_err()
    );
    assert!(banks.journal.is_none());
    let semantic_owner = std::ptr::from_ref(
        banks
            .semantic
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?,
    );
    assert!(
        CnpSemanticSnapshotReservation::reserve_into_with_error::<RuntimeError>(
            64,
            64,
            &mut banks.semantic,
        )
        .is_err()
    );
    assert_eq!(
        std::ptr::from_ref(
            banks
                .semantic
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
        ),
        semantic_owner
    );

    let expected = size_of::<Import18CaptureBankReservation>() + 64 + 32 + protocol;
    assert_eq!(
        owner.retained_backing_data::<RuntimeError>(expected)?,
        expected
    );
    assert!(
        owner
            .retained_backing_data::<RuntimeError>(expected - 1)
            .is_err()
    );
    assert_eq!(
        owner.history_data().partial_capacities,
        Some([64, 32, 0, 0, 0, 0, protocol])
    );
    assert!(owner.history_data().failed);
    assert!(!owner.history_data().complete && !owner.history_data().published);
    Ok(())
}

#[test]
fn unsupported_postconstruction_owner_is_refused_without_losing_its_capacity()
-> Result<(), RuntimeError> {
    let mut owner = Import18CaptureBankReservation::retaining(inert_row()?);
    owner.banks = Some(PacketCompleteCaptureBanks::empty_import18_data());
    let banks = owner.banks.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
    CnpSemanticSnapshotReservation::reserve_into_with_error::<RuntimeError>(
        8,
        8,
        &mut banks.native_after_bank,
    )?;

    // This initial-construction census must reject later Capture custody;
    // silently omitting that real bank would report a false retained total.
    assert!(
        owner
            .retained_backing_data::<RuntimeError>(usize::MAX)
            .is_err()
    );
    assert_eq!(
        owner
            .banks
            .as_ref()
            .and_then(|banks| banks.native_after_bank.as_ref())
            .ok_or(RuntimeError::OwnerUnavailable)?
            .allocated_bytes(),
        8
    );
    assert!(owner.history_data().failed);
    assert!(!owner.history_data().complete && !owner.history_data().published);
    Ok(())
}

#[test]
fn changed_immutable_allocation_inputs_refuse_the_same_private_row() -> Result<(), RuntimeError> {
    let row = inert_row()?;
    row.authenticate_current_geometry_data(&row.limits, &row.storage_extents)?;

    for which in 0..4 {
        let mut limits = row.limits;
        match which {
            0 => limits.host_protocol_bytes += 1,
            1 => limits.semantic_bytes += 1,
            2 => limits.ancestry_bytes += 1,
            _ => limits.journal_bytes += 1,
        }
        assert!(
            row.authenticate_current_geometry_data(&limits, &row.storage_extents)
                .is_err()
        );
    }
    for which in 0..4 {
        let mut extents = row.storage_extents;
        match which {
            0 => extents.native_snapshot += 1,
            1 => extents.native_control += 1,
            2 => extents.history_bytes += 1,
            _ => extents.lifetime_frames += 1,
        }
        assert!(
            row.authenticate_current_geometry_data(&row.limits, &extents)
                .is_err()
        );
    }
    // The pure guard has no destination or mutation path: a later matching
    // observation remains DATA, never a refreshed Source/native admission.
    row.authenticate_current_geometry_data(&row.limits, &row.storage_extents)?;
    Ok(())
}
