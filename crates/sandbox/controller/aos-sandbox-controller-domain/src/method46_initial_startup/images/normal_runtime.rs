//! Measures the stopped normal owner's configured immutable runtime inventory.
//!
//! Genuine stopped-unit admission precedes this step. The original Source pays
//! retained slots before allocation and each native acquisition before IO. The
//! same per-file engine used for the initial producer retains every reached
//! prefix and independently owed post. No normal process is started or mapped;
//! file provenance does not establish live admission or exclude later PID1 jobs.

use super::*;

const MAXIMUM_NORMAL_PINS: usize = 512;

pub(in crate::method46_initial_startup) struct InitialNormalRuntimeOriginalV1 {
    pub(super) files: Vec<ImageOriginalV1>,
    reservation: Option<Result<(), std::collections::TryReserveError>>,
    result: Option<Result<(), Method46InitialStartupClosedV1>>,
    entered: bool,
    posted: Cell<bool>,
}

impl InitialNormalRuntimeOriginalV1 {
    pub(in crate::method46_initial_startup) fn new() -> Self {
        Self {
            files: Vec::new(),
            reservation: None,
            result: None,
            entered: false,
            posted: Cell::new(false),
        }
    }

    pub(in crate::method46_initial_startup) fn completed(&self) -> bool {
        matches!(self.result, Some(Ok(())))
            && !self.posted.get()
            && !self.files.is_empty()
            && self.files.iter().all(|image| {
                matches!(image.measurement, Some(Ok(())))
                    && image.acquisition.completed_measurement().is_some()
            })
    }

    pub(in crate::method46_initial_startup) fn finish_posts(
        &self,
    ) -> Result<(), Method46InitialStartupClosedV1> {
        if !self.entered {
            return Ok(());
        }
        if self.posted.replace(true) {
            return Err(Method46InitialStartupClosedV1);
        }
        let mut refused = false;
        for image in &self.files {
            // A busy or refused file cannot suppress another reached post.
            refused |= image.finish_post().is_err();
        }
        if refused {
            Err(Method46InitialStartupClosedV1)
        } else {
            Ok(())
        }
    }
}

fn slots_demand(count: usize) -> Option<ResourceVector> {
    if !(1..=MAXIMUM_NORMAL_PINS).contains(&count) {
        return None;
    }
    let bytes = std::mem::size_of::<ImageOriginalV1>()
        .checked_mul(count)?
        .checked_mul(2)?
        .checked_add(256)?;
    Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?))
}

impl Method46InitialStartupOriginalV1 {
    /// Measures the selected stopped owner's Source-pinned runtime files once.
    ///
    /// The original native stopped-unit/fragment/command comparison must have
    /// succeeded. The same Source pays slot storage, native opens and retained
    /// same-file metadata before bounded immutable measurements and their owed
    /// posts. This step starts no command and authenticates selected file DATA
    /// without excluding later jobs, admitting a process or issuing floor authority.
    ///
    /// # Errors
    /// Refuses missing Source/profile/stopped-owner admission, poison, repeated
    /// entry, funding or allocation failure, oversized inventory/files, native
    /// IO and immutable image/digest mismatch. Reached prefixes stay resident.
    pub fn measure_normal_runtime_inventory_once_v1(
        &mut self,
    ) -> Result<(), Method46InitialStartupClosedV1> {
        self.source
            .get_mut()
            .require_current_v1()
            .map_err(|_| self.closed)?;
        if self.first.get().is_some() || self.after_attempted.get() {
            return Err(self.fail(First::Order));
        }
        let body = self.body.as_mut().ok_or(self.closed)?;
        if body.normal_runtime.entered
            || !matches!(body.profile_shape, Some(Ok(())))
            || !body.unit.stopped_units_before_completed()
        {
            return Err(self.fail(First::Order));
        }
        body.normal_runtime.entered = true;
        let result = self.measure_normal_runtime_inventory();
        if let Some(body) = self.body.as_mut() {
            body.normal_runtime.result = Some(result);
        }
        if result.is_err() {
            self.fail(First::Runtime);
        }
        result
    }

    fn measure_normal_runtime_inventory(&mut self) -> Result<(), Method46InitialStartupClosedV1> {
        let body = self.body.as_ref().ok_or(self.closed)?;
        let profile = body
            .profile_decoded
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(self.closed)?;
        let count = profile.normal_image.runtime_files.len();
        self.fund_additional(slots_demand(count))?;

        let original = &mut self.body.as_mut().ok_or(self.closed)?.normal_runtime;
        original.reservation = Some(original.files.try_reserve_exact(count));
        if !matches!(original.reservation, Some(Ok(()))) {
            return Err(self.closed);
        }
        for _ in 0..count {
            original.files.push(ImageOriginalV1::new());
        }
        for index in 0..count {
            self.measure_inventory_file(InventoryV1::Normal, index)?;
        }
        self.source
            .get_mut()
            .require_current_v1()
            .map_err(|_| self.closed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::ManuallyDrop;

    #[test]
    fn normal_inventory_requires_the_genuine_source_before_allocation_or_io() {
        for role in [
            Method46InitialServiceRoleV1::ControllerStorageClient,
            Method46InitialServiceRoleV1::StorageBroker,
        ] {
            let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(role));
            assert!(startup.measure_normal_runtime_inventory_once_v1().is_err());
            assert!(startup.body.is_none());
            assert_eq!(startup.receiving.get(), ResourceVector::ZERO);
        }
        for count in [0, MAXIMUM_NORMAL_PINS + 1, usize::MAX] {
            assert!(slots_demand(count).is_none());
        }
        assert!(slots_demand(MAXIMUM_NORMAL_PINS).is_some());
    }

    #[test]
    fn copied_inventory_result_cannot_replace_actual_native_measurements() {
        let mut original = InitialNormalRuntimeOriginalV1::new();
        original.result = Some(Ok(()));
        assert!(!original.completed());
        original.files.push(ImageOriginalV1::new());
        assert!(!original.completed());
    }

    #[test]
    fn busy_normal_file_post_cannot_suppress_the_next_reached_file_or_source_after() {
        let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(
            Method46InitialServiceRoleV1::StorageBroker,
        ));
        let mut body = StartupRolesOriginalV1::new();
        body.normal_runtime.entered = true;
        for _ in 0..2 {
            let mut image = ImageOriginalV1::new();
            image.preflight_entered = true;
            body.normal_runtime.files.push(image);
        }
        startup.body = Some(Box::new(body));
        let original = &startup.body.as_ref().unwrap().normal_runtime;
        let held = original.files[0].post.borrow_mut();

        assert!(startup.finish_source_after_owed_once_v1(Ok(())).is_err());

        assert!(original.posted.get());
        assert!(original.files[1].post.borrow().entered);
        assert!(startup.after_attempted.get());
        assert!(matches!(startup.first.get(), Some(First::Runtime)));
        drop(held);
    }
}
