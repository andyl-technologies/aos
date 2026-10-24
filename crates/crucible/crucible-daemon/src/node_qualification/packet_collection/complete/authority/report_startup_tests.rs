//! Exercises genuine no-Child private birth and Core-issued startup members.
//!
//! Controls read the real test ELF and source files, bind local Unix sockets and
//! read entropy for private keys. No native process, thread, Hello or readiness
//! is constructed. The same original Source remains unable to report native currentness.

// crucible-lint: allow panic-shortcut -- Assertion panics are control verdicts.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::node_qualification::packet_collection::complete::tests::POSITIVE_STARTUP_SETUP_MEMORY_BYTES;
use crucible_node_format::U64;

fn fixture() -> (
    super::super::super::tests::Scene,
    Rc<RefCell<PacketCompleteReportStartupHolder>>,
) {
    let original = super::super::super::tests::report_startup_fixture();
    // Select positive setup policy without changing the independent 512 MiB cases.
    original.1.borrow_mut().resources.memory_bytes = U64::new(POSITIVE_STARTUP_SETUP_MEMORY_BYTES);
    original
}

fn actual_peak(holder: &Rc<RefCell<PacketCompleteReportStartupHolder>>) -> usize {
    let held = holder.borrow();
    held.authenticate_origin().unwrap();
    assert!(!held.attempted.get());
    assert!(!held.in_flight.replace(true));
    let _loan = StartupLoan(&held.in_flight);
    let admission = held
        .plan
        .reserve_original_report_startup(
            &held.authority.roster.sources,
            &held.authority.original_launches,
        )
        .unwrap();
    admission.requested_peak_data()
}

#[test]
fn actual_report_startup_finalizes_ready_births_at_observed_exact_policy() {
    let (_scene, holder) = fixture();
    let peak = actual_peak(&holder);
    let before = {
        let held = holder.borrow();
        std::array::from_fn::<_, 3, _>(|member| {
            held.authority.roster.sources[member]
                .original_report_startup_audit_data()
                .unwrap()
        })
    };
    assert!(before.iter().all(|audit| audit.report_required
        && !audit.finalization_present
        && !audit.complete
        && !audit.refused
        && !audit.boot_started));
    holder.borrow_mut().resources.memory_bytes = U64::new(peak as u64);

    assert_eq!(
        PacketCompleteReportStartupHolder::finalize_original_report_startup(&holder).unwrap(),
        peak
    );
    let held = holder.borrow();
    assert!(held.completed.get());
    assert!(held.authority.roster.current_native().is_err());
    for (source, before) in held.authority.roster.sources.iter().zip(before) {
        let after = source.original_report_startup_audit_data().unwrap();
        assert!(
            after.finalization_present && after.complete && !after.refused && !after.boot_started
        );
        assert_ne!(before.encoded_birth_digest, after.encoded_birth_digest);
        assert_eq!(before.encoded_birth_capacity, after.encoded_birth_capacity);
        // This is a real source-issued loan after finalization, with no write/Child.
        let original_boot = source.begin_original_canonical_ack_private_boot().unwrap();
        drop(original_boot);
        assert!(source.begin_original_canonical_ack_private_boot().is_err());
        assert!(source.authenticate_current_native().is_err());
    }
    drop(held);
    assert!(PacketCompleteReportStartupHolder::finalize_original_report_startup(&holder).is_err());
}

#[test]
fn actual_report_startup_one_short_refuses_before_any_birth_replacement() {
    let (_scene, holder) = fixture();
    let peak = actual_peak(&holder);
    let before = {
        let held = holder.borrow();
        std::array::from_fn::<_, 3, _>(|member| {
            held.authority.roster.sources[member]
                .original_report_startup_audit_data()
                .unwrap()
        })
    };
    holder.borrow_mut().resources.memory_bytes = U64::new((peak - 1) as u64);

    assert!(PacketCompleteReportStartupHolder::finalize_original_report_startup(&holder).is_err());
    let held = holder.borrow();
    assert!(held.attempted.get());
    assert!(!held.completed.get());
    assert!(!held.in_flight.get());
    for (source, original) in held.authority.roster.sources.iter().zip(before) {
        assert_eq!(
            source.original_report_startup_audit_data().unwrap(),
            original
        );
        assert!(source.begin_original_canonical_ack_private_boot().is_err());
        assert!(source.authenticate_current_native().is_err());
    }
}

#[test]
fn actual_report_startup_member_is_once_spent_and_partial_owners_remain() {
    let (_scene, holder) = fixture();
    let held = holder.borrow();
    assert!(!held.in_flight.replace(true));
    let _loan = StartupLoan(&held.in_flight);
    let mut admission = held
        .plan
        .reserve_original_report_startup(
            &held.authority.roster.sources,
            &held.authority.original_launches,
        )
        .unwrap();

    let original = std::array::from_fn::<_, 3, _>(|member| {
        held.authority.roster.sources[member]
            .original_report_startup_audit_data()
            .unwrap()
    });
    admission.finalize_original_source(0).unwrap();
    let completed = held.authority.roster.sources[0]
        .original_report_startup_audit_data()
        .unwrap();
    assert!(completed.finalization_present && completed.complete && !completed.refused);
    assert!(admission.finalize_original_source(0).is_err());
    assert_eq!(
        held.authority.roster.sources[0]
            .original_report_startup_audit_data()
            .unwrap(),
        completed
    );
    for member in 1..3 {
        assert_eq!(
            held.authority.roster.sources[member]
                .original_report_startup_audit_data()
                .unwrap(),
            original[member]
        );
    }
    assert!(
        held.authority.roster.sources[1]
            .begin_original_canonical_ack_private_boot()
            .is_err()
    );
    assert!(
        held.authority.roster.sources[2]
            .begin_original_canonical_ack_private_boot()
            .is_err()
    );
    drop(admission);
    drop(_loan);
    assert!(
        held.authority.roster.sources[0]
            .begin_original_canonical_ack_private_boot()
            .is_err()
    );

    // Dropping a partially used Core grant retains the completed member and the
    // other original full births; it neither fabricates completion nor boots.
    assert!(!held.completed.get());
    assert!(held.authority.roster.current_native().is_err());
    for source in &held.authority.roster.sources {
        assert!(
            source
                .original_complete_report_startup_retained_storage_data(usize::MAX)
                .is_ok()
        );
    }
}

struct UnlaunchedSlot {
    identity_reads: Rc<Cell<usize>>,
    returned: Rc<RefCell<Option<crucible_engine::node_adapters::cnp::CnpSemanticProcessCustody>>>,
}

impl crucible_engine::node_adapters::cnp::CnpSemanticProcessSlot for UnlaunchedSlot {
    fn identity(&self) -> U64 {
        self.identity_reads.set(self.identity_reads.get() + 1);
        U64::new(43)
    }

    fn retain(&mut self, custody: crucible_engine::node_adapters::cnp::CnpSemanticProcessCustody) {
        *self.returned.borrow_mut() = Some(custody);
    }
}

#[test]
fn actual_report_startup_refuses_after_same_real_launch_reservation_is_spent() {
    let (_scene, holder) = fixture();
    PacketCompleteReportStartupHolder::finalize_original_report_startup(&holder).unwrap();
    let held = holder.borrow();
    let source = &held.authority.roster.sources[0];
    let before = source.original_report_startup_audit_data().unwrap();
    let identity_reads = Rc::new(Cell::new(0));
    let returned = Rc::new(RefCell::new(None));
    let executable = held.authority.original_launches[0]
        .selection
        .provider
        .implementation
        .artifacts
        .iter()
        .find(|artifact| artifact.role.as_str() == "executable")
        .unwrap()
        .content
        .clone();

    let reservation = source
        .reserve_original_complete_bytes_launch(
            held.authority.directories[0].clone(),
            executable.clone(),
            Box::new(UnlaunchedSlot {
                identity_reads: Rc::clone(&identity_reads),
                returned: Rc::clone(&returned),
            }),
        )
        .unwrap();
    assert_eq!(identity_reads.get(), 1);
    assert!(returned.borrow().is_none());
    assert_eq!(source.original_report_startup_audit_data().unwrap(), before);
    assert!(
        source
            .original_complete_report_startup_retained_storage_data(usize::MAX)
            .is_err()
    );
    drop(reservation);

    assert!(
        source
            .reserve_original_complete_bytes_launch(
                held.authority.directories[0].clone(),
                executable,
                Box::new(UnlaunchedSlot {
                    identity_reads: Rc::clone(&identity_reads),
                    returned: Rc::clone(&returned),
                })
            )
            .is_err()
    );
    assert_eq!(identity_reads.get(), 1);
    assert!(returned.borrow().is_none());
    assert_eq!(source.original_report_startup_audit_data().unwrap(), before);
    assert!(source.authenticate_current_native().is_err());
}

#[test]
fn actual_report_startup_material_refuses_holder_revocation_without_losing_birth() {
    let (_scene, holder) = fixture();
    PacketCompleteReportStartupHolder::finalize_original_report_startup(&holder).unwrap();
    let source = Rc::clone(&holder.borrow().authority.roster.sources[0]);
    let material = source.begin_original_canonical_ack_private_boot().unwrap();
    assert!(material.authenticate_original().is_ok());
    assert!(material.private_key().is_ok());
    assert!(material.source_birth_bytes().is_ok());
    let before = source.original_report_startup_audit_data().unwrap();
    assert!(before.complete && before.boot_started && !before.refused);

    holder.borrow_mut().graph_owner.revoke();

    assert!(material.authenticate_original().is_err());
    assert!(material.private_key().is_err());
    assert!(material.birth_id().is_err());
    assert!(material.source_birth_bytes().is_err());
    assert!(material.expected_host_registration_bytes().is_err());
    assert_eq!(source.original_report_startup_audit_data().unwrap(), before);
    drop(material);
    assert_eq!(source.original_report_startup_audit_data().unwrap(), before);
    assert!(source.authenticate_current_native().is_err());
}

#[test]
fn actual_report_startup_64k_frame_refuses_512m_without_replacing_births() {
    let (_scene, holder) = super::super::super::tests::report_startup_fixture_with_frame(65_536);
    let before = {
        let held = holder.borrow();
        assert_eq!(held.resources.memory_bytes.get(), 512 * 1024 * 1024);
        for launch in &held.authority.original_launches {
            assert_eq!(launch.limits.frame_bytes.get(), 65_536);
        }
        std::array::from_fn::<_, 3, _>(|member| {
            held.authority.roster.sources[member]
                .original_report_startup_audit_data()
                .unwrap()
        })
    };

    assert!(PacketCompleteReportStartupHolder::finalize_original_report_startup(&holder).is_err());

    let held = holder.borrow();
    assert!(held.attempted.get());
    assert!(!held.completed.get());
    for (source, original) in held.authority.roster.sources.iter().zip(before) {
        assert_eq!(
            source.original_report_startup_audit_data().unwrap(),
            original
        );
        assert!(source.begin_original_canonical_ack_private_boot().is_err());
        assert!(source.authenticate_current_native().is_err());
    }
}

#[test]
fn actual_report_startup_diagnostic_groups_restore_512m_and_preserve_births() {
    use crucible_node_transport::reference_packet::service::report_startup::{
        PacketNativeReportStartupPurpose, original_report_startup_storage_data,
    };

    // Keep this diagnostic on the independent 512 MiB base policy.
    let (_scene, holder) = super::super::super::tests::report_startup_fixture();
    let original_policy = holder.borrow().resources.memory_bytes;
    assert_eq!(original_policy.get(), 512 * 1024 * 1024);
    let before = {
        let held = holder.borrow();
        std::array::from_fn::<_, 3, _>(|member| {
            held.authority.roster.sources[member]
                .original_report_startup_audit_data()
                .unwrap()
        })
    };

    // This explicit finite ceiling is solely for numeric diagnosis without
    // finalization. It is not a supported fixture policy or native admission.
    // Restore the actual policy before inspecting even a failed observation.
    holder.borrow_mut().resources.memory_bytes = U64::new(8 * 1024 * 1024 * 1024);
    let observed = {
        let held = holder.borrow();
        assert!(!held.attempted.get());
        assert!(!held.in_flight.replace(true));
        let _loan = StartupLoan(&held.in_flight);
        held.plan.reserve_original_report_startup(
            &held.authority.roster.sources,
            &held.authority.original_launches,
        ).and_then(|admission| {
            let total = admission.requested_peak_data();
            let maximum = usize::try_from(held.resources.memory_bytes.get()).unwrap();
            let holder_data = PacketCompleteReportStartupHolder::storage_data(&holder, &held, maximum)
                .unwrap();
            let mut source_bytes = [0usize; 3];
            let mut purpose_axes = [[0usize; 3]; 3];
            let mut attributed = holder_data.retained_holder_bytes
                .checked_add(holder_data.maximum_simultaneous_transient_bytes).unwrap();
            for member in 0..3 {
                let launch = &held.authority.original_launches[member];
                assert_eq!(launch.limits.frame_bytes.get(), 16 * 1024);
                assert!(launch.capture_allocation_selection.is_some());
                assert!(launch.fresh_restore_allocation_selection.is_none());
                source_bytes[member] = held.authority.roster.sources[member]
                    .original_complete_report_startup_retained_storage_data(maximum).unwrap();
                let row = original_report_startup_storage_data(
                    launch, PacketNativeReportStartupPurpose::OriginalObserve12).unwrap();
                purpose_axes[member] = [row.retained_growth_bytes(),
                    row.maximum_simultaneous_transient_bytes(), row.declared_counter_scratch_bytes()];
                attributed = attributed.checked_add(source_bytes[member]).unwrap();
                for axis in purpose_axes[member] {
                    attributed = attributed.checked_add(axis).unwrap();
                }
            }
            // This is an aggregate residual, not an assertion that its private
            // Core fixed/three-finalization terms have been individually read.
            let core_fixed_and_three_finalizations = total.checked_sub(attributed).unwrap();
            assert!(core_fixed_and_three_finalizations > 0);
            eprintln!("original report startup numeric diagnostic: frame=16384, diagnostic_policy=8589934592, total={total}, holder_retained={}, holder_transient={}, source3={source_bytes:?}, observe3_retained_transient_scratch={purpose_axes:?}, residual_core_fixed_plus_three_finalizations={core_fixed_and_three_finalizations}",
                holder_data.retained_holder_bytes, holder_data.maximum_simultaneous_transient_bytes);
            assert_eq!(attributed.checked_add(core_fixed_and_three_finalizations).unwrap(), total);
            Ok(total)
        })
    };
    holder.borrow_mut().resources.memory_bytes = original_policy;
    let observed_peak = observed.unwrap();
    let restored_limit = usize::try_from(original_policy.get()).unwrap();

    let held = holder.borrow();
    assert_eq!(held.resources.memory_bytes, original_policy);
    assert!(!held.in_flight.replace(true));
    let _loan = StartupLoan(&held.in_flight);
    let restored_admission = held.plan.reserve_original_report_startup(
        &held.authority.roster.sources,
        &held.authority.original_launches,
    );
    // A changed quote can cross this fixed policy without changing semantics.
    // This is admission-only: neither branch finalizes or replaces a birth.
    if observed_peak <= restored_limit {
        assert_eq!(
            restored_admission.unwrap().requested_peak_data(),
            observed_peak,
        );
    } else {
        assert!(matches!(restored_admission, Err(error)
            if error.message == "original startup requested allocation exceeds installed resource policy"));
    }
    assert!(!held.attempted.get());
    assert!(!held.completed.get());
    for (source, original) in held.authority.roster.sources.iter().zip(before) {
        assert_eq!(
            source.original_report_startup_audit_data().unwrap(),
            original
        );
        assert!(source.authenticate_current_native().is_err());
    }
}
