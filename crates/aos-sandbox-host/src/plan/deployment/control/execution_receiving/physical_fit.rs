//! Compares shared Host process residency with its genuine service remainder.
//!
//! Control remains a separate spent financial subdivision. Its native/model
//! originals nevertheless share HostService memory, task and descriptor limits.
//! This comparison reserves nothing and never transfers Control traffic.

use super::{AccountingError, Closed, D, HostExecutionReceivingV2, ResourceVector};

impl HostExecutionReceivingV2 {
    // Only actual paid Phase0 arms this before allocating its whole capture.
    // Initial manager startup retains its original paid bootstrap/backstop.
    pub(in crate::plan::deployment::control) fn arm_component_physical_fit_once_v2(
        &mut self,
    ) -> Result<(), Closed> {
        if !self.control_was_consumed()
            || self.execution_admitted
            || self.physical_baseline.is_some()
        {
            return Err(Closed);
        }
        self.physical_baseline = Some(super::super::component_baseline_receiving_demand_v2());
        if !matches!(self.physical_baseline, Some(Ok(_))) {
            self.closed = true;
            return Err(Closed);
        }
        Ok(())
    }

    // Select the actual financial boundary cause before independent posts.
    // A prior native refusal may still allow its genuine fresh negative Stop
    // purpose; this getter neither heals that refusal nor grants entry.
    pub(in crate::plan::deployment::control) fn control_preparation_failure_v2(
        &self,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        self.control_requirement
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|error| error as _)
            .or_else(|| {
                self.physical_baseline
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|error| error as _)
            })
            .or_else(|| {
                self.physical_requirement
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|error| error as _)
            })
    }

    // Later extensions reuse this same engine. Actual source/arithmetic errors
    // remain on this owner, even when separately owed posts introduce errors.
    pub(super) fn require_control_physical_fit_v2(
        &mut self,
        complete_control: ResourceVector,
    ) -> Result<(), Closed> {
        let Some(source) = self.physical_baseline.as_ref() else {
            return Ok(());
        };
        if self
            .physical_requirement
            .as_ref()
            .is_some_and(Result::is_err)
        {
            return Err(Closed);
        }
        let baseline = match source {
            Ok(source) => *source,
            Err(_) => {
                self.closed = true;
                return Err(Closed);
            }
        };
        self.physical_requirement = Some(remaining_physical_baseline_v2(
            self.baseline_capacity,
            baseline,
            complete_control,
        ));
        if !matches!(self.physical_requirement, Some(Ok(_))) {
            self.closed = true;
            return Err(Closed);
        }
        Ok(())
    }
}

// Pure representation DATA, never a source, admission or effect borrower.
// Rate/traffic dimensions retain their existing separate financial checks.
fn physical_resident_v2(source: ResourceVector) -> ResourceVector {
    let mut resident = ResourceVector::ZERO;
    for dimension in [D::MemoryBytes, D::Pids, D::OpenFiles] {
        resident = resident.with(dimension, source.get(dimension));
    }
    resident
}

fn remaining_physical_baseline_v2(
    declared_service_remainder: ResourceVector,
    actual_baseline: ResourceVector,
    complete_control: ResourceVector,
) -> Result<ResourceVector, AccountingError> {
    let required = physical_resident_v2(actual_baseline)
        .checked_add(physical_resident_v2(complete_control))?;
    physical_resident_v2(declared_service_remainder).checked_sub(required)
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;
    use std::path::Path;

    fn actual_source_requirements() -> (ResourceVector, ResourceVector) {
        // Canonical path DATA exercise actual passive shape suppliers only.
        // These fixtures construct no native source or financial permission.
        let baseline = super::super::super::component_baseline_receiving_demand_v2().unwrap();
        let phase0 = crate::plan::deployment::component_phase0::HostComponentPhase0OriginalV2::receiving_demand_v2(
            Path::new("/run/credentials/aos-sandbox-hostd.service"),
            Path::new("/var/lib/aos/sandbox-host"),
            "/nix/store/00000000000000000000000000000000-systemd-261.2/bin/systemd-nspawn",
            Path::new("/nix/store/11111111111111111111111111111111-aos-sandbox-hostd/bin/aos-sandbox-hostd"),
            "/nix/store/22222222222222222222222222222222-aos-selinux-kernel-policy-readback-1/policy.33",
            crate::plan::deployment::HOST_SYSCALL_PROFILE.len(),
        ).unwrap();
        assert!(phase0.get(D::MemoryBytes) > 0);
        assert!(phase0.get(D::OpenFiles) > 0);
        assert!(phase0.get(D::OutputBytes) > 0);
        (baseline, phase0)
    }

    #[test]
    fn former_baseline_only_remainder_cannot_hide_retained_phase0() {
        let (baseline, phase0) = actual_source_requirements();
        assert!(baseline.checked_sub(baseline).is_ok());
        assert!(remaining_physical_baseline_v2(baseline, baseline, phase0).is_err());
    }

    #[test]
    fn source_derived_residency_fits_without_rebilling_control_traffic() {
        let (baseline, phase0) = actual_source_requirements();
        let sufficient = physical_resident_v2(baseline)
            .checked_add(physical_resident_v2(phase0))
            .unwrap();
        assert_eq!(sufficient.get(D::OutputBytes), 0);
        assert_eq!(
            remaining_physical_baseline_v2(sufficient, baseline, phase0).unwrap(),
            ResourceVector::ZERO
        );
        for dimension in [D::MemoryBytes, D::Pids, D::OpenFiles] {
            let one_short =
                sufficient.with(dimension, sufficient.get(dimension).checked_sub(1).unwrap());
            assert!(remaining_physical_baseline_v2(one_short, baseline, phase0).is_err());
        }
    }

    #[test]
    fn actual_physical_refusal_survives_a_later_accounting_attempt() {
        let (baseline, phase0) = actual_source_requirements();
        let slice = phase0.with(D::ConcurrentOperations, 1);
        let service = slice
            .checked_add(slice)
            .unwrap()
            .checked_add(slice)
            .unwrap()
            .checked_add(physical_resident_v2(baseline))
            .unwrap();
        let control = phase0.checked_add(phase0).unwrap();
        let profile = super::super::ExecutionReceivingProfileV2 {
            prepare: D::ALL.map(|dimension| slice.get(dimension)),
            accept: D::ALL.map(|dimension| slice.get(dimension)),
            launch: D::ALL.map(|dimension| slice.get(dimension)),
            boot_preparation: None,
        };
        // This private fixture owns accounting DATA only, not a captured
        // source, consumed operation, native permit or authenticated request.
        let mut owner =
            HostExecutionReceivingV2::from_reserved_subdivisions(service, profile, control)
                .unwrap();
        owner.physical_baseline = Some(Ok(baseline));
        owner.control_requirement = Some(Ok(control));
        assert!(owner.require_control_physical_fit_v2(phase0).is_err());
        let first = owner.failure().unwrap() as *const dyn std::error::Error;

        assert!(owner.account_control_preparation_v5(phase0).is_err());
        assert_eq!(
            owner.control_requirement.as_ref().unwrap().as_ref().ok(),
            Some(&control)
        );
        assert!(std::ptr::eq(
            first,
            owner.failure().unwrap() as *const dyn std::error::Error
        ));
        assert!(
            owner
                .control_preparation_failure_v2()
                .unwrap()
                .downcast_ref::<AccountingError>()
                .is_some()
        );
    }
}
