//! Fresh named-identity samples over the same original service-limit OFDs.
//!
//! These bounded observations carry DATA only. Each sample is entered once and
//! retains fresh named acquisitions, bytes and the whole first error. Recurring
//! consumers reuse the original readable OFDs rather than recapturing a second
//! service-limit reader or replacing the original successful observation.

use super::*;

#[derive(Debug)]
struct CurrentSlot {
    named: PendingRegularFileV1,
    bytes: [u8; LIMIT_CONTROL_BYTES + 1],
    length: usize,
    absent: Option<Error>,
}

impl Default for CurrentSlot {
    fn default() -> Self {
        Self { named: PendingRegularFileV1::default(),
               bytes: [0; LIMIT_CONTROL_BYTES + 1], length: 0, absent: None }
    }
}

/// Retains seven fresh control names and same-original-OFD byte observations.
///
/// Default construction creates no authority or original descriptor. The
/// genuine receiver prices this inline value and seven fresh named FDs before
/// entry. The initial reader retains its own original captures independently.
#[derive(Debug)]
pub struct CgroupLimitCurrentnessSampleV1 {
    slots: [CurrentSlot; 7],
    result: Option<Result<()>>,
    reentry: Option<Error>,
}

impl Default for CgroupLimitCurrentnessSampleV1 {
    fn default() -> Self {
        Self { slots: std::array::from_fn(|_| CurrentSlot::default()),
               result: None, reentry: None }
    }
}

impl CgroupLimitCurrentnessSampleV1 {
    /// Borrows the first whole native error without replacing prior results.
    #[must_use]
    pub fn failure(&self) -> Option<&Error> {
        self.result.as_ref().and_then(|result| result.as_ref().err())
            .or(self.reentry.as_ref())
    }
}

/// Retains one fresh cpu.max name and the same original CPU OFD's bytes.
///
/// This is bounded DATA with no caller-file or path constructor. Its single
/// named FD is separate from the original readable CPU descriptor.
#[derive(Debug, Default)]
pub struct CpuLimitCurrentnessSampleV1 {
    slot: CurrentSlot,
    result: Option<Result<()>>,
    reentry: Option<Error>,
}

impl CpuLimitCurrentnessSampleV1 {
    /// Borrows the first whole native error, including interrupted/repeated entry.
    #[must_use]
    pub fn failure(&self) -> Option<&Error> {
        self.result.as_ref().and_then(|result| result.as_ref().err())
            .or(self.reentry.as_ref())
    }
}

impl CgroupLimitReadbackV1 {
    /// Observes fresh names and bytes using this same original readable owner.
    ///
    /// Every output remains on the caller's prearmed sample. The original
    /// initial/final capture is unchanged and remains independently retained.
    ///
    /// # Errors
    /// Refuses incomplete/failed originals, stale anchors, changed original
    /// bytes, new or missing names, changed identity, and repeated samples.
    pub fn observe_current(
        &self, anchor: &RetainedCgroupAnchor, sample: &mut CgroupLimitCurrentnessSampleV1,
    ) -> Result<()> {
        if sample.result.is_some() || sample.reentry.is_some() {
            sample.reentry.get_or_insert_with(|| Error::invalid("cgroup current sample", "already entered"));
            return Err(Error::invalid("cgroup current sample", "first sample retained"));
        }
        sample.result = Some((|| {
            if !matches!(self.phase, LimitReadbackPhaseV1::Ready | LimitReadbackPhaseV1::Current)
                || self.failure.is_some()
            {
                return Err(Error::invalid("cgroup current sample", "original reader is not ready"));
            }
            anchor.validate_current()?;
            for control in CgroupLimitControlV1::ALL {
                observe_slot(anchor, Path::new(control.name()),
                    &self.slots[control as usize], &mut sample.slots[control as usize])?;
            }
            anchor.validate_current()
        })());
        match &sample.result {
            Some(Ok(())) => Ok(()),
            _ => Err(Error::invalid("cgroup current sample", "actual failure retained")),
        }
    }
}

impl FirstGlobalCpuReadbackV1 {
    /// Observes the same original CPU bytes and one independently fresh name.
    ///
    /// # Errors
    /// Refuses incomplete/failed originals, stale anchors, changed bytes or
    /// identity, syscall failures and a sample that was entered already.
    pub fn observe_current(
        &self, anchor: &RetainedCgroupAnchor, sample: &mut CpuLimitCurrentnessSampleV1,
    ) -> Result<()> {
        if sample.result.is_some() || sample.reentry.is_some() {
            sample.reentry.get_or_insert_with(|| Error::invalid("cpu current sample", "already entered"));
            return Err(Error::invalid("cpu current sample", "first sample retained"));
        }
        sample.result = Some((|| {
            if self.quota.is_none() || self.failure.is_some() {
                return Err(Error::invalid("cpu current sample", "original reader is not ready"));
            }
            anchor.validate_current()?;
            observe_slot(anchor, Path::new("cpu.max"), &self.slot, &mut sample.slot)?;
            anchor.validate_current()
        })());
        match &sample.result {
            Some(Ok(())) => Ok(()),
            _ => Err(Error::invalid("cpu current sample", "actual failure retained")),
        }
    }
}

fn observe_slot(anchor: &RetainedCgroupAnchor, name: &Path,
                original: &LimitControlSlotV1, sample: &mut CurrentSlot) -> Result<()> {
    if original.absent.is_some() {
        return match anchor.root.open_regular_retaining(name, &mut sample.named) {
            Err(error) if is_missing(&error) => { sample.absent = Some(error); Ok(()) }
            Err(error) => Err(error),
            Ok(()) => Err(Error::invalid("cgroup current sample", "absent original appeared")),
        };
    }
    read_limit_record(original.opening.file()?.as_fd(), &mut sample.bytes, &mut sample.length)?;
    if original.bytes[..original.length] != sample.bytes[..sample.length] {
        return Err(Error::invalid("cgroup current sample", "same-OFD bytes changed"));
    }
    anchor.root.open_regular_retaining(name, &mut sample.named)?;
    if original.opening.file()?.identity() != sample.named.file()?.identity() {
        return Err(Error::invalid("cgroup current sample", "fresh named identity changed"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_samples_are_data_and_have_no_successful_native_result() {
        let controls = CgroupLimitCurrentnessSampleV1::default();
        let cpu = CpuLimitCurrentnessSampleV1::default();
        assert!(controls.result.is_none());
        assert!(cpu.result.is_none());
        assert!(controls.slots.iter().all(|slot| slot.length == 0));
        assert_eq!(cpu.slot.length, 0);
    }

    #[test]
    fn retained_first_native_error_precedes_a_later_reentry_error() {
        let mut sample = CgroupLimitCurrentnessSampleV1::default();
        sample.result = Some(Err(Error::invalid("actual read", "first")));
        let first = sample.failure().unwrap() as *const Error;
        sample.reentry = Some(Error::invalid("reentry", "later"));
        assert_eq!(sample.failure().unwrap() as *const Error, first);
    }

    #[cfg(feature = "kernel-tests")]
    #[test]
    fn repeated_samples_use_original_ofds_and_retain_a_changed_cpu_cause() {
        let hierarchy = CgroupV2Root::from_owned(File::open("/sys/fs/cgroup").unwrap().into()).unwrap();
        let membership = std::fs::read_to_string("/proc/self/cgroup").unwrap();
        let current = membership.lines().find_map(|line| line.strip_prefix("0::/")).unwrap();
        let relative = Path::new(current).join(format!("aos-limit-samples-{}", std::process::id()));
        let path = Path::new("/sys/fs/cgroup").join(&relative);
        std::fs::create_dir(&path).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) { let _ = std::fs::remove_dir(&self.0); }
        }
        let _cleanup = Cleanup(path.clone());
        std::fs::write(path.join("cpu.max"), b"10000 100000\n").unwrap();
        let anchor = hierarchy.resolve(&relative).unwrap();
        let mut controls = CgroupLimitReadbackV1::default();
        let mut cpu = FirstGlobalCpuReadbackV1::default();
        controls.capture(&anchor).unwrap();
        cpu.capture(&anchor).unwrap();
        controls.recheck(&anchor).unwrap();
        cpu.recheck(&anchor).unwrap();
        let original_cpu = cpu.slot.opening.file().unwrap().identity();
        let original_controls: Vec<_> = controls.slots.iter()
            .map(|slot| slot.opening.file().ok().map(|file| file.identity()))
            .collect();
        controls.settle_positive_named_verifications_v1().unwrap();
        cpu.settle_positive_named_verifications_v1().unwrap();
        assert!(controls.slots.iter().all(|slot|
            slot.bookend.file().is_err() && slot.final_name.file().is_err()));
        assert!(cpu.slot.bookend.file().is_err());
        assert!(cpu.slot.final_name.file().is_err());
        assert_eq!(controls.slots.iter()
            .map(|slot| slot.opening.file().ok().map(|file| file.identity()))
            .collect::<Vec<_>>(), original_controls);
        assert_eq!(cpu.slot.opening.file().unwrap().identity(), original_cpu);

        for _ in 0..2 {
            let mut control_sample = CgroupLimitCurrentnessSampleV1::default();
            let mut cpu_sample = CpuLimitCurrentnessSampleV1::default();
            controls.observe_current(&anchor, &mut control_sample).unwrap();
            cpu.observe_current(&anchor, &mut cpu_sample).unwrap();
            assert!(control_sample.failure().is_none());
            assert!(cpu_sample.failure().is_none());
            assert_eq!(cpu.slot.opening.file().unwrap().identity(), original_cpu);
            // Actual completed positive verification names are disposed here.
        }

        std::fs::write(path.join("cpu.max"), b"20000 100000\n").unwrap();
        let mut refused = CpuLimitCurrentnessSampleV1::default();
        assert!(cpu.observe_current(&anchor, &mut refused).is_err());
        let original_error = refused.failure().unwrap() as *const Error;
        assert!(cpu.observe_current(&anchor, &mut refused).is_err());
        assert_eq!(refused.failure().unwrap() as *const Error, original_error);
        assert_eq!(cpu.slot.opening.file().unwrap().identity(), original_cpu);
    }

}
