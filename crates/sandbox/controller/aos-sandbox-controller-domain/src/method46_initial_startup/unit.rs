//! Joins the actual manual invocation and immutable unit to its captured Source.
//!
//! One separately paid current-thread Runtime owns one finite readonly manager.
//! Original PID1 property bookends, unit bytes, native acquisition and independent
//! posts remain resident. Successful comparisons create no writer or TPM grant.

use aos_systemd_client::{
    ReadonlyPropertyManagerOriginalV2, ReadonlyPropertyReceiveScheduleV2,
    ServicePropertiesReadClosedV2, ServicePropertiesReadOriginalV2, Value,
};
use sha2::{Digest as _, Sha256};

use super::*;

const UNIT_BYTES: usize = 64 * 1024;
const PROPERTIES: &[&str] = &["FragmentPath", "DropInPaths", "Transient"];
const PROFILE_FD: &str = "aos-method46-initial-startup-profile";
const PLACEHOLDER: &str = "@AOS_METHOD46_INITIAL_STARTUP_PROFILE@";

pub(super) struct InitialUnitOriginalV1 {
    runtime: Option<std::io::Result<tokio::runtime::Runtime>>,
    manager: Option<ReadonlyPropertyManagerOriginalV2>,
    connection: Option<aos_systemd_client::Result<()>>,
    properties: [RefCell<UnitPropertiesOriginalV1>; 2],
    file: Option<File>,
    open: Option<std::io::Result<()>>,
    acquisition: ImmutableFileAcquisitionOriginalV1,
    measurement: Option<Result<(), ImmutableFileAcquisitionRefusalV1>>,
    read: Option<Result<(), ImmutableImageErrorV1>>,
    normalized: Option<Result<Vec<u8>, Method46InitialStartupClosedV1>>,
    file_post: RefCell<ProfilePostOriginalV1>,
    paid: bool,
    entered: bool,
}

struct UnitPropertiesOriginalV1 {
    original: ServicePropertiesReadOriginalV2,
    result: Option<Result<(), ServicePropertiesReadClosedV2>>,
    entered: bool,
}

impl UnitPropertiesOriginalV1 {
    fn new() -> Self {
        Self {
            original: ServicePropertiesReadOriginalV2::new(),
            result: None,
            entered: false,
        }
    }
}

impl InitialUnitOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            runtime: None,
            manager: None,
            connection: None,
            properties: std::array::from_fn(|_| RefCell::new(UnitPropertiesOriginalV1::new())),
            file: None,
            open: None,
            acquisition: ImmutableFileAcquisitionOriginalV1::new(),
            measurement: None,
            read: None,
            normalized: None,
            file_post: RefCell::new(ProfilePostOriginalV1 {
                original: ImmutableFileRevalidationOriginalV1::new(),
                result: None,
            }),
            paid: false,
            entered: false,
        }
    }

    fn observe_properties(
        &self,
        index: usize,
        origin: Option<&Method46InitialOriginComparisonDataV1>,
        profile: Option<&Method46InitialProfileDataV1>,
    ) -> Result<(), Method46InitialStartupClosedV1> {
        let mut observation = self
            .properties
            .get(index)
            .ok_or(Method46InitialStartupClosedV1)?
            .try_borrow_mut()
            .map_err(|_| Method46InitialStartupClosedV1)?;
        if observation.entered {
            return Err(Method46InitialStartupClosedV1);
        }
        observation.entered = true;
        // A caller in another Runtime cannot enter this owner's block_on.
        // Preserve refusal and let the enclosing Source after still run.
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(Method46InitialStartupClosedV1);
        }
        let runtime = self
            .runtime
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(Method46InitialStartupClosedV1)?;
        let manager = self
            .manager
            .as_ref()
            .and_then(|manager| manager.client_v2())
            .ok_or(Method46InitialStartupClosedV1)?;
        let profile = profile.ok_or(Method46InitialStartupClosedV1)?;
        let origin = origin.ok_or(Method46InitialStartupClosedV1)?;
        observation.result = Some(
            runtime.block_on(observation.original.observe_startup_once_v2(
                manager,
                &profile.unit,
                std::process::id(),
                &[],
                PROPERTIES,
            )),
        );
        if !matches!(observation.result, Some(Ok(())))
            || observation.original.completed_invocation_data_v1()
                != Some(origin.recipient_invocation)
        {
            return Err(Method46InitialStartupClosedV1);
        }
        let path = fragment_path(&observation.original)?;
        if index == 1
            && self
                .acquisition
                .completed_measurement()
                .is_some_and(|original| original.path() != std::path::Path::new(path))
        {
            return Err(Method46InitialStartupClosedV1);
        }
        Ok(())
    }

    fn measure_fragment(
        &mut self,
        origin: &Method46InitialOriginComparisonDataV1,
        profile: &Method46InitialProfileDataV1,
        profile_path: &std::path::Path,
    ) -> Result<(), Method46InitialStartupClosedV1> {
        let observation = self.properties[0]
            .try_borrow()
            .map_err(|_| Method46InitialStartupClosedV1)?;
        let path = fragment_path(&observation.original)?;
        self.open = Some(match File::open(path) {
            Ok(file) => {
                self.file = Some(file);
                Ok(())
            }
            Err(error) => Err(error),
        });
        let file = self.file.take().ok_or(Method46InitialStartupClosedV1)?;
        self.measurement = Some(self.acquisition.measure_original_once(
            PathBuf::from(path),
            file,
            Some(origin.unit_fragment_digest),
            UNIT_BYTES as u64,
            false,
        ));
        if !matches!(self.measurement, Some(Ok(()))) {
            return Err(Method46InitialStartupClosedV1);
        }
        self.read = Some(self.acquisition.read_completed_bounded());
        if !matches!(self.read, Some(Ok(()))) {
            return Err(Method46InitialStartupClosedV1);
        }
        self.normalized = Some(normalize_fragment(
            self.acquisition.bytes(),
            profile_path
                .to_str()
                .ok_or(Method46InitialStartupClosedV1)?,
        ));
        let normalized = self
            .normalized
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(Method46InitialStartupClosedV1)?;
        if <[u8; 32]>::from(Sha256::digest(normalized)) != profile.unit_sha256 {
            return Err(Method46InitialStartupClosedV1);
        }
        Ok(())
    }

    pub(super) fn finish_post(
        &self,
        origin: Option<&Method46InitialOriginComparisonDataV1>,
        profile: Option<&Method46InitialProfileDataV1>,
    ) -> Result<(), Method46InitialStartupClosedV1> {
        if !self.paid {
            return Ok(());
        }
        let properties = self.observe_properties(1, origin, profile);
        let file = match self.file_post.try_borrow_mut() {
            Ok(mut post) => {
                post.result = self
                    .acquisition
                    .observe_available_held_once_v1(&mut post.original);
                if matches!(post.result, Some(Err(_))) {
                    Err(Method46InitialStartupClosedV1)
                } else {
                    Ok(())
                }
            }
            Err(_) => Err(Method46InitialStartupClosedV1),
        };
        properties.and(file)
    }
}

fn fragment_path(
    original: &ServicePropertiesReadOriginalV2,
) -> Result<&str, Method46InitialStartupClosedV1> {
    let Some([fragment, dropins, transient]) = original.unit_values_v2() else {
        return Err(Method46InitialStartupClosedV1);
    };
    let (Value::Str(path), Value::Array(dropins), Value::Bool(false)) =
        (&**fragment, &**dropins, &**transient)
    else {
        return Err(Method46InitialStartupClosedV1);
    };
    if !dropins.inner().is_empty() || path.len() > PATH_BYTES {
        return Err(Method46InitialStartupClosedV1);
    }
    crate::normal_root::profile::require_store_path(path.as_str())
        .map_err(|_| Method46InitialStartupClosedV1)?;
    Ok(path.as_str())
}

fn normalize_fragment(
    bytes: &[u8],
    profile: &str,
) -> Result<Vec<u8>, Method46InitialStartupClosedV1> {
    if bytes.is_empty() || bytes.len() > UNIT_BYTES || profile.len() > PATH_BYTES {
        return Err(Method46InitialStartupClosedV1);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| Method46InitialStartupClosedV1)?;
    let actual = format!("OpenFile={profile}:{PROFILE_FD}:read-only\n");
    let replacement = format!("OpenFile={PLACEHOLDER}:{PROFILE_FD}:read-only\n");
    if text
        .split_inclusive('\n')
        .filter(|line| *line == actual)
        .count()
        != 1
    {
        return Err(Method46InitialStartupClosedV1);
    }
    Ok(text
        .split_inclusive('\n')
        .map(|line| {
            if line == actual {
                replacement.as_str()
            } else {
                line
            }
        })
        .collect::<String>()
        .into_bytes())
}

fn manager_schedule() -> Option<ReadonlyPropertyReceiveScheduleV2> {
    // Two fixed 17-call PID1 samples, Hello and bounded signal/header carryover.
    // These are native-enforced ceilings, never an account or semantic claim.
    ReadonlyPropertyReceiveScheduleV2::new(64, 80, 64 * 1024, 4096, 80 * 64 * 1024).ok()
}

fn unit_demand(schedule: ReadonlyPropertyReceiveScheduleV2) -> Option<ResourceVector> {
    let manager = ReadonlyPropertyManagerOriginalV2::receiving_memory_bytes_v2(schedule)?;
    let properties =
        ServicePropertiesReadOriginalV2::receiving_memory_bytes_v2(0, PROPERTIES.len())?;
    let memory = manager
        .checked_add(properties.checked_mul(2)?)?
        .checked_add(1024 * 1024)? // Runtime, task/driver and allocator scratch.
        .checked_add(8 * UNIT_BYTES + 8 * PATH_BYTES)?;
    let read = ImmutableFileAcquisitionOriginalV1::materialized_input_bytes_v1(UNIT_BYTES as u64)?
        .checked_add(UNIT_BYTES as u64 + 1)?;
    ResourceVector::ZERO
        .with(D::MemoryBytes, u64::try_from(memory).ok()?)
        .with(D::OpenFiles, 16)
        .with(D::MetadataEntries, 4 * PATH_BYTES as u64)
        .with(
            D::OutputBytes,
            read.checked_add((80 * 64 * 1024 + 64 * 4096 + 4096) as u64)?,
        )
        .checked_add(ImmutableFileAcquisitionOriginalV1::receiving_demand_v1(
            PATH_BYTES,
        )?)
        .ok()?
        .checked_add(ImmutableFileRevalidationOriginalV1::receiving_demand_v1()?)
        .ok()
}

impl Method46InitialStartupOriginalV1 {
    /// Binds actual startup properties and unit bytes to this original Source.
    ///
    /// A separately paid current-thread Runtime and finite readonly connection
    /// belong to this same owner. Both property samples compare the native
    /// recipient invocation; the immutable fragment must match the original raw
    /// digest and the profile's normalized digest. Posts remain independently
    /// owed after any reached failure. This synchronous entry runs outside Tokio.
    ///
    /// # Errors
    /// Refuses missing current Source/profile, nested Runtime, exhausted funding,
    /// reentry, foreign invocation, transient/drop-in units, mutable fragment,
    /// either digest mismatch or any native constructor/property/file failure.
    pub fn observe_unit_once_v1(&mut self) -> Result<(), Method46InitialStartupClosedV1> {
        self.source
            .get_mut()
            .require_current_v1()
            .map_err(|_| self.closed)?;
        let body = self.body.as_mut().ok_or(self.closed)?;
        if body.unit.entered
            || !matches!(body.profile_shape, Some(Ok(())))
            || tokio::runtime::Handle::try_current().is_ok()
        {
            return Err(self.fail(First::Unit));
        }
        body.unit.entered = true;
        let schedule = manager_schedule().ok_or_else(|| self.fail(First::Unit))?;
        self.fund_additional(unit_demand(schedule))?;

        let result = (|| {
            let body = self.body.as_mut().ok_or(self.closed)?;
            let unit = &mut body.unit;
            unit.paid = true;
            unit.runtime = Some(
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build(),
            );
            let runtime = unit
                .runtime
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(self.closed)?;
            unit.manager = Some(ReadonlyPropertyManagerOriginalV2::new(schedule));
            let manager = unit.manager.as_mut().ok_or(self.closed)?;
            unit.connection = Some(runtime.block_on(manager.connect_once()));
            if !matches!(unit.connection, Some(Ok(()))) {
                return Err(self.closed);
            }
            let profile = body
                .profile_decoded
                .as_ref()
                .and_then(|value| value.as_ref().ok());
            unit.observe_properties(0, self.origin.as_ref(), profile)?;
            let path = body
                .profile
                .completed_measurement()
                .ok_or(self.closed)?
                .path();
            unit.measure_fragment(
                self.origin.as_ref().ok_or(self.closed)?,
                profile.ok_or(self.closed)?,
                path,
            )
        })();
        if result.is_err() {
            return Err(self.fail(First::Unit));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::ManuallyDrop;

    #[test]
    fn normalization_replaces_only_the_one_exact_profile_line() {
        let text = format!(
            "[Service]\n# {PROFILE_FD}\nOpenFile=/nix/store/example:{PROFILE_FD}:read-only\nType=oneshot\n"
        );
        let normalized = normalize_fragment(text.as_bytes(), "/nix/store/example").unwrap();
        assert_eq!(
            normalized,
            text.replace(
                "OpenFile=/nix/store/example:",
                &format!("OpenFile={PLACEHOLDER}:")
            )
            .as_bytes()
        );
        assert!(normalize_fragment(text.as_bytes(), "/nix/store/other").is_err());
        assert!(
            normalize_fragment(format!("{text}{text}").as_bytes(), "/nix/store/example").is_err()
        );
        assert!(normalize_fragment(&[0xff], "/nix/store/example").is_err());
    }

    #[test]
    fn missing_source_cannot_construct_a_runtime_or_manager() {
        let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(
            Method46InitialServiceRoleV1::StorageBroker,
        ));
        startup.body = Some(Box::new(StartupRolesOriginalV1::new()));

        assert!(startup.observe_unit_once_v1().is_err());

        let unit = &startup.body.as_ref().unwrap().unit;
        assert!(!unit.paid);
        assert!(unit.runtime.is_none());
        assert!(unit.manager.is_none());
        assert_eq!(startup.receiving.get(), ResourceVector::ZERO);
    }

    #[test]
    fn busy_unit_post_cannot_suppress_source_after() {
        let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(
            Method46InitialServiceRoleV1::StorageBroker,
        ));
        let mut body = StartupRolesOriginalV1::new();
        body.unit.paid = true; // Negative dispatch only; no positive native proof.
        startup.body = Some(Box::new(body));
        let unit = &startup.body.as_ref().unwrap().unit;
        let held = unit.properties[1].borrow_mut();

        assert!(startup.finish_source_after_owed_once_v1(Ok(())).is_err());

        assert!(startup.after_attempted.get());
        assert!(matches!(startup.first.get(), Some(First::Unit)));
        drop(held);
    }
}
