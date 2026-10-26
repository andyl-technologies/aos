//! Retains Source-paid native Controller and Storage cgroup population cuts.
//!
//! All supported fixed owner subtrees are observed independently, including
//! both Storage layouts when PID1 reports no current cgroup. A missing subtree
//! cannot select an alternative probe. All final observations remain owed on
//! the same actual Source after body refusal, before Source's own native after.

use aos_sandbox_linux::cgroup::{
    Method46StoppedOwnerCgroupOriginalV1, Method46StoppedOwnerCgroupV1, StorageCgroupLayoutV1,
};

use super::*;

const OWNERS: [Method46StoppedOwnerCgroupV1; 3] = [
    Method46StoppedOwnerCgroupV1::Controller,
    Method46StoppedOwnerCgroupV1::Storage(StorageCgroupLayoutV1::Ordinary),
    Method46StoppedOwnerCgroupV1::Storage(StorageCgroupLayoutV1::ReceivingAggregate),
];

pub(super) struct InitialStoppedCgroupsOriginalV1 {
    samples: [[RefCell<CgroupSampleOriginalV1>; 3]; 2],
    paid: Cell<bool>,
}

struct CgroupSampleOriginalV1 {
    original: Method46StoppedOwnerCgroupOriginalV1,
    result: Option<Result<(), Method46InitialReceivingClosedV1>>,
    entered: bool,
}

impl CgroupSampleOriginalV1 {
    fn new() -> Self {
        Self {
            original: Method46StoppedOwnerCgroupOriginalV1::new(),
            result: None,
            entered: false,
        }
    }
}

impl InitialStoppedCgroupsOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            samples: std::array::from_fn(|_| {
                std::array::from_fn(|_| RefCell::new(CgroupSampleOriginalV1::new()))
            }),
            paid: Cell::new(false),
        }
    }

    fn observe(
        &self,
        startup: &Method46InitialStartupOriginalV1,
        round: usize,
    ) -> Result<(), Method46InitialStartupClosedV1> {
        let mut refused = false;
        for (index, owner) in OWNERS.iter().enumerate() {
            let result = (|| {
                let mut sample = self.samples[round][index]
                    .try_borrow_mut()
                    .map_err(|_| startup.closed)?;
                if !self.paid.get() || sample.entered {
                    return Err(startup.closed);
                }
                sample.entered = true;
                sample.result = Some(match startup.source.try_borrow_mut() {
                    Ok(mut source) if round == 0 => {
                        source.observe_stopped_owner_cgroup_once_v1(*owner, &mut sample.original)
                    }
                    Ok(mut source) => source
                        .observe_stopped_owner_cgroup_owed_once_v1(*owner, &mut sample.original),
                    Err(_) => Err(Method46InitialReceivingClosedV1),
                });
                if matches!(sample.result, Some(Ok(())))
                    && sample.original.is_empty_or_absent_data_v1()
                {
                    Ok(())
                } else {
                    Err(startup.closed)
                }
            })();
            // A failed or busy destination cannot suppress another owed post.
            refused |= result.is_err();
        }
        if refused { Err(startup.closed) } else { Ok(()) }
    }

    pub(super) fn finish_post(
        &self,
        startup: &Method46InitialStartupOriginalV1,
    ) -> Result<(), Method46InitialStartupClosedV1> {
        if !self.paid.get() {
            return Ok(());
        }
        let posts = self.observe(startup, 1);
        // A caught unwind or an interrupted primary cannot be healed by three
        // later empty observations or a caller-supplied successful body marker.
        let before_complete = self.samples[0].iter().all(|sample| {
            sample.try_borrow().is_ok_and(|sample| {
                matches!(sample.result, Some(Ok(())))
                    && sample.original.is_empty_or_absent_data_v1()
            })
        });
        if before_complete {
            posts
        } else {
            Err(startup.closed)
        }
    }
}

fn receiving_demand() -> Option<ResourceVector> {
    let (bytes, files, coordinates) =
        Method46StoppedOwnerCgroupOriginalV1::receiving_obligations_v1()?;
    // All six original slots and their construction frames are paid before
    // the first read. The startup body already owns their inline storage.
    let total = |amount: usize| u64::try_from(amount.checked_mul(6)?).ok();
    Some(
        ResourceVector::ZERO
            .with(D::MemoryBytes, total(bytes)?)
            .with(D::OpenFiles, total(files)?)
            .with(D::MetadataEntries, total(coordinates)?)
            // Each fixed native recipe includes its bounded 4097-byte event read
            // and the kernel metadata/identity returns of all active probes.
            .with(D::OutputBytes, 6 * 8192),
    )
}

impl Method46InitialStartupOriginalV1 {
    /// Observes all fixed Controller and Storage cgroups as empty or absent.
    ///
    /// Both stopped-unit observations must already have completed. This same
    /// genuine Source prepays all six native before/after destinations before
    /// the first Root-relative lookup. Its original validated hierarchy is
    /// borrowed internally; no caller path, descriptor or amount enters.
    ///
    /// All three final observations remain independently owed after refusal,
    /// including a failed property post. These cuts neither prevent later
    /// starts/migrations nor supply exclusive journal or physical TPM custody.
    ///
    /// # Errors
    /// Refuses missing stopped-unit/Source admission, reentry, insufficient
    /// actual funding, a foreign or unavailable hierarchy, a populated subtree
    /// or any retained native failure. No alternative layout is tried to heal
    /// another observation; both fixed Storage coordinates are required.
    pub fn observe_stopped_owner_cgroups_once_v1(
        &mut self,
    ) -> Result<(), Method46InitialStartupClosedV1> {
        if self.source.get_mut().require_current_v1().is_err() {
            return Err(self.fail(First::Source));
        }
        let ready = self.body.as_ref().is_some_and(|body| {
            body.unit.stopped_units_before_completed() && !body.stopped_cgroups.paid.get()
        });
        if !ready {
            return Err(self.fail(First::Order));
        }
        self.fund_additional(receiving_demand())?;
        let original = &self.body.as_ref().ok_or(self.closed)?.stopped_cgroups;
        original.paid.set(true);
        original
            .observe(self, 0)
            .map_err(|_| self.fail(First::StoppedOwners))
    }
}

#[cfg(test)]
mod tests {
    use std::mem::ManuallyDrop;

    use super::*;

    #[test]
    fn stopped_owner_cgroups_require_actual_source_before_payment_or_io() {
        let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(
            Method46InitialServiceRoleV1::StorageBroker,
        ));

        assert!(startup.observe_stopped_owner_cgroups_once_v1().is_err());
        assert!(startup.capture_before_arguments_once_v1().is_err());

        assert!(startup.body.is_none());
        assert!(!startup.capture_attempted);
        assert_eq!(startup.receiving.get(), ResourceVector::ZERO);
        assert!(matches!(startup.first.get(), Some(First::Source)));
    }

    #[test]
    fn busy_cgroup_post_cannot_suppress_other_coordinates_or_source_after() {
        let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(
            Method46InitialServiceRoleV1::ControllerStorageClient,
        ));
        let body = StartupRolesOriginalV1::new();
        // Negative dispatch only: no positive Source or hierarchy is fabricated.
        body.stopped_cgroups.paid.set(true);
        startup.body = Some(Box::new(body));
        let original = &startup.body.as_ref().unwrap().stopped_cgroups;
        let held = original.samples[1][0].borrow_mut();

        assert!(startup.finish_source_after_owed_once_v1(Ok(())).is_err());

        assert!(startup.after_attempted.get());
        assert!(matches!(startup.after_result.get(), Some(Err(_))));
        assert!(matches!(startup.first.get(), Some(First::StoppedOwners)));
        for sample in &original.samples[1][1..] {
            let sample = sample.borrow();
            assert!(sample.entered);
            assert!(matches!(sample.result, Some(Err(_))));
            assert!(sample.original.failure_v1().is_none());
        }
        drop(held);
    }
}
