//! Native/outside conservation controls inside one modeled family envelope.

use super::*;

fn family() -> Result<HostRamProcessFamilyPartition, HostRamAdmissionError> {
    let envelope = HostResourceVector {
        resident_peak_bytes: 512 << 20,
        backing_peak_bytes: 1024 << 20,
        metadata_bytes: 16 << 20,
        staging_bytes: 8 << 20,
        paging_io_slots: 2,
        cpu_slots: 1,
        task_slots: 64,
        file_descriptors: 128,
    };
    let floor = HostResourceVector {
        resident_peak_bytes: 128 << 20,
        backing_peak_bytes: 256 << 20,
        metadata_bytes: 4 << 20,
        staging_bytes: 2 << 20,
        paging_io_slots: 1,
        cpu_slots: 1,
        task_slots: 8,
        file_descriptors: 32,
    };
    HostRamProcessFamilyPartition::with_staged(envelope, floor, floor)
}

fn native(
    process: HostResourceVector,
) -> Result<HostRamProcessNativeAllowance, HostRamAdmissionError> {
    HostRamProcessNativeAllowance::new(
        process,
        process.resident_peak_bytes - (16 << 20),
        process.metadata_bytes - (1 << 20),
        16 << 20,
        1 << 20,
    )
}

#[test]
fn native_full_and_total_exclude_each_retained_host_owner() -> Result<(), HostRamAdmissionError> {
    let family = family()?;
    let initial = native(family.initial())?;
    let staged = native(
        family
            .staged()
            .ok_or_else(|| HostRamAdmissionError::contract("modeled stage missing"))?,
    )?;
    let allowances = HostRamProcessFamilyNativeAllowances::new(family, initial, Some(staged))?;

    assert_eq!(allowances.initial().native_metadata_bytes(), 11 << 20);
    assert_eq!(
        allowances
            .staged()
            .ok_or_else(|| HostRamAdmissionError::contract("modeled stage missing"))?
            .native_metadata_bytes(),
        3 << 20
    );
    assert_eq!(
        initial.native_resident_bytes() + staged.native_resident_bytes(),
        family.envelope().resident_peak_bytes - (32 << 20)
    );
    assert_ne!(
        initial.native_metadata_bytes(),
        family.initial().metadata_bytes
    );
    Ok(())
}

#[test]
fn copying_the_generic_process_peak_cannot_cover_outside_owners()
-> Result<(), HostRamAdmissionError> {
    let initial = family()?.initial();
    assert!(
        HostRamProcessNativeAllowance::new(
            initial,
            initial.resident_peak_bytes,
            initial.metadata_bytes,
            16 << 20,
            1 << 20,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn scope_substitution_and_missing_stage_cannot_duplicate_the_family()
-> Result<(), HostRamAdmissionError> {
    let family = family()?;
    let initial = native(family.initial())?;
    assert!(HostRamProcessFamilyNativeAllowances::new(family, initial, None).is_err());
    assert!(HostRamProcessFamilyNativeAllowances::new(family, initial, Some(initial)).is_err());
    Ok(())
}

#[test]
fn metadata_and_overflow_refuse_without_a_residual_grant() -> Result<(), HostRamAdmissionError> {
    let process = family()?.initial();
    assert!(
        HostRamProcessNativeAllowance::new(
            process,
            1,
            process.metadata_bytes,
            process.resident_peak_bytes - 1,
            0,
        )
        .is_err()
    );
    assert!(HostRamProcessNativeAllowance::new(process, u64::MAX, 1, 1, 0).is_err());
    Ok(())
}
