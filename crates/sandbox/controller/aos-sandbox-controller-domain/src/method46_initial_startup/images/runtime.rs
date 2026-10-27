//! Retains paid acquisitions of the initial producer's runtime and policy pins.
//!
//! A decoded pin selects comparison DATA only. The actual captured Source pays
//! every retained slot and native open before IO, then pays digest work from the
//! same held file's metadata. Measurement grants no process, policy or journal
//! authority; mapped-file, live-policy and unit admission remain separate.

use super::*;

use aos_sandbox_broker::immutable_image::RetainedImmutableFileV1;
use aos_sandbox_broker::profile_data::images::{
    ActualExecutableMappingsClosedV1, ActualExecutableMappingsOriginalV1,
};

const POLICY_PINS: usize = 3;
const MAXIMUM_RUNTIME_PINS: usize = 512;

pub(in crate::method46_initial_startup) struct InitialRuntimeOriginalV1 {
    pub(super) files: Vec<ImageOriginalV1>,
    reservation: Option<Result<(), std::collections::TryReserveError>>,
    inventory_result: Option<Result<(), Method46InitialStartupClosedV1>>,
    maps: [RefCell<RuntimeMapsOriginalV1>; 2],
    maps_entered: bool,
    maps_paid: bool,
    entered: bool,
}

struct RuntimeMapsOriginalV1 {
    original: ActualExecutableMappingsOriginalV1,
    reservation: Option<Result<(), std::collections::TryReserveError>>,
    result: Option<Result<(), ActualExecutableMappingsClosedV1>>,
    roster_complete: Option<bool>,
    entered: bool,
}

impl RuntimeMapsOriginalV1 {
    fn new() -> Self {
        Self {
            original: ActualExecutableMappingsOriginalV1::new(),
            reservation: None,
            result: None,
            roster_complete: None,
            entered: false,
        }
    }
}

impl InitialRuntimeOriginalV1 {
    pub(in crate::method46_initial_startup) fn new() -> Self {
        Self {
            files: Vec::new(),
            reservation: None,
            inventory_result: None,
            maps: std::array::from_fn(|_| RefCell::new(RuntimeMapsOriginalV1::new())),
            maps_entered: false,
            maps_paid: false,
            entered: false,
        }
    }

    pub(in crate::method46_initial_startup) fn finish_posts(
        &self,
        profile: Option<&Method46InitialProfileDataV3>,
    ) -> Result<(), Method46InitialStartupClosedV1> {
        let mut refused = false;
        for image in &self.files {
            // A refused or busy sink cannot suppress another reached file.
            refused |= image.finish_post().is_err();
        }
        if self.maps_paid {
            refused |= profile
                .ok_or(Method46InitialStartupClosedV1)
                .and_then(|profile| self.observe_maps(1, profile))
                .is_err();
        }
        if refused {
            Err(Method46InitialStartupClosedV1)
        } else {
            Ok(())
        }
    }

    fn observe_maps(
        &self,
        index: usize,
        profile: &Method46InitialProfileDataV3,
    ) -> Result<(), Method46InitialStartupClosedV1> {
        let mut original = self
            .maps
            .get(index)
            .ok_or(Method46InitialStartupClosedV1)?
            .try_borrow_mut()
            .map_err(|_| Method46InitialStartupClosedV1)?;
        if original.entered {
            return Err(Method46InitialStartupClosedV1);
        }
        original.entered = true;
        let mut files = Vec::new();
        original.reservation = Some(files.try_reserve_exact(profile.runtime_files.len()));
        let reserved = matches!(original.reservation, Some(Ok(())));
        if reserved {
            for image in self.files.iter().take(profile.runtime_files.len()) {
                if let Some(file) = image.acquisition.completed_measurement() {
                    files.push(file);
                }
            }
        }
        let complete = reserved && files.len() == profile.runtime_files.len();
        original.roster_complete = Some(complete);
        // A file-post or scratch refusal must not suppress the separately paid
        // kernel read. Compare the available prefix, then keep the roster refusal.
        original.result =
            Some(original.original.observe_borrowed_once_v1(
                &files,
                &[&profile.executable.path, &profile.loader.path],
            ));
        if complete && matches!(original.result, Some(Ok(()))) {
            Ok(())
        } else {
            Err(Method46InitialStartupClosedV1)
        }
    }
}

fn maps_demand(count: usize) -> Option<ResourceVector> {
    if count > MAXIMUM_RUNTIME_PINS {
        return None;
    }
    let headers = std::mem::size_of::<ActualExecutableMappingsOriginalV1>().checked_mul(2)?;
    let reader = ActualExecutableMappingsOriginalV1::receiving_demand_v1(count)?
        .checked_sub(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(headers).ok()?))
        .ok()?;
    let references = std::mem::size_of::<&RetainedImmutableFileV1>()
        .checked_mul(count)?
        .checked_mul(2)?
        .checked_add(std::mem::size_of::<Vec<&RetainedImmutableFileV1>>().checked_mul(2)?)?
        .checked_add(128)?;
    let one = reader
        .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(references).ok()?))
        .ok()?;
    // The independent maps post is prepaid with the initial read. A later
    // refusal cannot depend on acquiring another loan before this owed IO.
    one.checked_add(one).ok()
}

fn slot_demand(count: usize) -> Option<ResourceVector> {
    if !(POLICY_PINS..=MAXIMUM_RUNTIME_PINS + POLICY_PINS).contains(&count) {
        return None;
    }
    // Include allocation rounding and a co-live slot-construction temporary.
    // The Vec and reservation-result headers already belong to the paid body.
    let bytes = std::mem::size_of::<ImageOriginalV1>()
        .checked_mul(count)?
        .checked_mul(2)?
        .checked_add(256)?;
    Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?))
}

pub(super) fn pin(profile: &Method46InitialProfileDataV3, index: usize) -> Option<&ImagePinV1> {
    if index < profile.runtime_files.len() {
        return profile.runtime_files.get(index);
    }
    match index.checked_sub(profile.runtime_files.len())? {
        0 => Some(&profile.canonical_policy),
        1 => Some(&profile.source_policy),
        2 => Some(&profile.effective_matrix),
        _ => None,
    }
}

impl Method46InitialStartupOriginalV1 {
    /// Measures the pinned runtime inventory and three immutable policy files.
    ///
    /// Positive original PID1/executing-image measurements precede this step.
    /// The same actual Source pays the bounded retained slots before allocation,
    /// native opens before IO and digest work from each held file's real length.
    /// Loader and executable pins occur in the strictly checked runtime list.
    /// Every reached prefix and independently owed post stays on this owner.
    /// These file comparisons grant no live-policy or process-map admission.
    ///
    /// # Errors
    /// Refuses missing earlier observations, repetition, poison, funding,
    /// allocation, native IO and immutable path/image comparisons. A refusal
    /// cannot replace or recapture the source or restart this inventory.
    pub fn measure_runtime_inventory_once_v1(
        &mut self,
    ) -> Result<(), Method46InitialStartupClosedV1> {
        if self.first.get().is_some() || self.after_attempted.get() {
            return Err(self.fail(First::Order));
        }
        let Some(body) = self.body.as_mut() else {
            return Err(self.fail(First::Order));
        };
        if body.runtime.entered
            || !matches!(body.profile_shape, Some(Ok(())))
            || !matches!(body.images.pid1.measurement, Some(Ok(())))
            || !matches!(body.images.executable.measurement, Some(Ok(())))
        {
            return Err(self.fail(First::Order));
        }
        body.runtime.entered = true;
        let result = self.measure_runtime_inventory();
        if let Some(body) = self.body.as_mut() {
            body.runtime.inventory_result = Some(result);
        }
        if result.is_err() {
            self.fail(First::Runtime);
        }
        result
    }

    /// Compares actual executable mappings against the measured runtime files.
    ///
    /// Reads only this process's kernel maps after complete inventory acquisition.
    /// The same Source prepays the initial reader, independent owed post and
    /// temporary borrowed-reference vectors. Acquisition owners retain their
    /// files and native results; no copied pin or caller-supplied map is accepted.
    /// This comparison grants no unit, live-policy or writer authority.
    ///
    /// # Errors
    /// Refuses missing positive acquisition, reentry, poison, funding, native map
    /// reads, foreign executable mappings and missing executable/loader members.
    /// All reached prefixes and the separately paid post remain on this owner.
    pub fn measure_actual_runtime_mappings_once_v1(
        &mut self,
    ) -> Result<(), Method46InitialStartupClosedV1> {
        if self.first.get().is_some() || self.after_attempted.get() {
            return Err(self.fail(First::Order));
        }
        let Some(body) = self.body.as_mut() else {
            return Err(self.fail(First::Order));
        };
        if body.runtime.maps_entered || !matches!(body.runtime.inventory_result, Some(Ok(()))) {
            return Err(self.fail(First::Order));
        }
        body.runtime.maps_entered = true;
        let result = self.measure_actual_runtime_mappings();
        if result.is_err() {
            self.fail(First::Runtime);
        }
        result
    }

    fn measure_actual_runtime_mappings(&mut self) -> Result<(), Method46InitialStartupClosedV1> {
        self.source
            .get_mut()
            .require_current_v1()
            .map_err(|_| self.closed)?;
        let body = self.body.as_ref().ok_or(self.closed)?;
        let profile = body
            .profile_decoded
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(self.closed)?;
        self.fund_additional(maps_demand(profile.runtime_files.len()))?;
        let body = self.body.as_mut().ok_or(self.closed)?;
        body.runtime.maps_paid = true;
        let profile = body
            .profile_decoded
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(self.closed)?;
        body.runtime.observe_maps(0, profile)
    }

    fn measure_runtime_inventory(&mut self) -> Result<(), Method46InitialStartupClosedV1> {
        self.source
            .get_mut()
            .require_current_v1()
            .map_err(|_| self.closed)?;
        let body = self.body.as_ref().ok_or(self.closed)?;
        let profile = body
            .profile_decoded
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(self.closed)?;
        let count = profile
            .runtime_files
            .len()
            .checked_add(POLICY_PINS)
            .ok_or(self.closed)?;
        self.fund_additional(slot_demand(count))?;

        let runtime = &mut self.body.as_mut().ok_or(self.closed)?.runtime;
        runtime.reservation = Some(runtime.files.try_reserve_exact(count));
        if !matches!(runtime.reservation, Some(Ok(()))) {
            return Err(self.closed);
        }
        for _ in 0..count {
            runtime.files.push(ImageOriginalV1::new());
        }
        for index in 0..count {
            self.measure_inventory_file(InventoryV1::Initial, index)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::mem::ManuallyDrop;

    use super::*;

    fn untrusted_profile_data() -> Method46InitialProfileDataV3 {
        let image = ImagePinV1 {
            path: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-untrusted/bin/image".to_owned(),
            sha256: [1; 32],
        };
        Method46InitialProfileDataV3 {
            format: String::new(),
            unit: String::new(),
            owner_context: String::new(),
            executable: image.clone(),
            pid1: image.clone(),
            loader: image.clone(),
            runtime_files: vec![image.clone(), image.clone()],
            closure_roots: Vec::new(),
            canonical_policy: image.clone(),
            source_policy: image.clone(),
            effective_matrix: image.clone(),
            unit_sha256: [1; 32],
            normal_unit_fragment: image.clone(),
            normal_image: aos_sandbox_broker::profile_data::method46_initial::normal_image::Method46NormalImageDataV1 {
                executable: image.clone(), loader: image.clone(), runtime_files: vec![image.clone()],
                closure_roots: Vec::new(), argv: Vec::new(),
            },
            controller_uid: 1,
            controller_gid: 1,
            approval_public_key: [1; 32],
        }
    }

    #[test]
    fn inventory_before_original_images_cannot_capture_or_allocate() {
        for role in [
            Method46InitialServiceRoleV1::ControllerStorageClient,
            Method46InitialServiceRoleV1::StorageBroker,
        ] {
            let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(role));

            assert!(startup.measure_runtime_inventory_once_v1().is_err());
            assert!(startup.capture_before_arguments_once_v1().is_err());

            assert!(matches!(startup.first.get(), Some(First::Order)));
            assert!(!startup.capture_attempted);
            assert!(startup.body.is_none());
            assert_eq!(startup.receiving.get(), ResourceVector::ZERO);
        }
    }

    #[test]
    fn maps_before_original_inventory_cannot_capture_or_read() {
        for role in [
            Method46InitialServiceRoleV1::ControllerStorageClient,
            Method46InitialServiceRoleV1::StorageBroker,
        ] {
            let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(role));

            assert!(startup.measure_actual_runtime_mappings_once_v1().is_err());
            assert!(startup.capture_before_arguments_once_v1().is_err());

            assert!(matches!(startup.first.get(), Some(First::Order)));
            assert!(!startup.capture_attempted);
            assert!(startup.body.is_none());
            assert_eq!(startup.receiving.get(), ResourceVector::ZERO);
        }
    }

    #[test]
    fn slot_geometry_rejects_oversized_counts_before_allocation() {
        assert!(slot_demand(MAXIMUM_RUNTIME_PINS + POLICY_PINS).is_some());
        assert!(maps_demand(MAXIMUM_RUNTIME_PINS).is_some());
        assert!(maps_demand(MAXIMUM_RUNTIME_PINS + 1).is_none());
        assert!(maps_demand(usize::MAX).is_none());
        for count in [
            0,
            POLICY_PINS - 1,
            MAXIMUM_RUNTIME_PINS + POLICY_PINS + 1,
            usize::MAX,
        ] {
            assert!(slot_demand(count).is_none());
        }
    }

    #[test]
    fn busy_runtime_post_does_not_suppress_later_post_or_source_after() {
        let startup =
            Method46InitialStartupOriginalV1::new(Method46InitialServiceRoleV1::StorageBroker);
        let mut startup = ManuallyDrop::new(startup);
        let mut body = StartupRolesOriginalV1::new();
        // Inert sinks exercise owed-post ordering without a Source or loan.
        for _ in 0..2 {
            let mut image = ImageOriginalV1::new();
            image.preflight_entered = true;
            body.runtime.files.push(image);
        }
        startup.body = Some(Box::new(body));
        let runtime = &startup.body.as_ref().unwrap().runtime;
        let held = runtime.files[0].post.borrow_mut();

        assert!(startup.finish_source_after_owed_once_v1(Ok(())).is_err());

        assert!(runtime.files[1].post.borrow().entered);
        assert!(startup.after_attempted.get());
        assert!(matches!(startup.first.get(), Some(First::Runtime)));
        assert!(matches!(startup.after_result.get(), Some(Err(_))));
        drop(held);
    }

    #[test]
    fn busy_file_post_cannot_suppress_paid_actual_maps_post() {
        let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(
            Method46InitialServiceRoleV1::ControllerStorageClient,
        ));
        let mut body = StartupRolesOriginalV1::new();
        // A mechanical negative fixture, not positive profile or Source custody.
        // Its incomplete file roster must still reach the independent reader.
        body.profile_decoded = Some(Ok(untrusted_profile_data()));
        body.runtime.maps_paid = true;
        let mut image = ImageOriginalV1::new();
        image.preflight_entered = true;
        body.runtime.files.push(image);
        startup.body = Some(Box::new(body));
        let runtime = &startup.body.as_ref().unwrap().runtime;
        let held = runtime.files[0].post.borrow_mut();

        assert!(startup.finish_source_after_owed_once_v1(Ok(())).is_err());

        let maps = runtime.maps[1].borrow();
        assert!(maps.entered);
        assert!(matches!(maps.result, Some(Err(_))));
        assert_eq!(maps.roster_complete, Some(false));
        assert!(maps.original.failure_v1().is_some());
        assert!(startup.after_attempted.get());
        assert!(matches!(startup.first.get(), Some(First::Runtime)));
        drop(held);
    }
}
