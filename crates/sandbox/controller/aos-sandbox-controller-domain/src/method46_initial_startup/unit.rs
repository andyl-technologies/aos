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

mod confinement;
mod delivery;
mod normal_command;
mod normal_fragment;
mod service;
mod stopped;

const UNIT_BYTES: usize = 64 * 1024;
const PROPERTIES: &[&str] = &["FragmentPath", "DropInPaths", "Transient"];
const PROFILE_FD: &str = "aos-method46-initial-startup-profile";
const PLACEHOLDER: &str = "@AOS_METHOD46_INITIAL_STARTUP_PROFILE@";
const WORKER_STACK_BYTES: usize = 2 * 1024 * 1024;

pub(super) struct InitialUnitOriginalV1 {
    runtime: Option<std::io::Result<tokio::runtime::Runtime>>,
    manager: Option<ReadonlyPropertyManagerOriginalV2>,
    connection: Option<aos_systemd_client::Result<()>>,
    properties: [RefCell<UnitPropertiesOriginalV1>; 2],
    stopped: stopped::InitialStoppedOwnersOriginalV1,
    file: Option<File>,
    open: Option<std::io::Result<()>>,
    acquisition: ImmutableFileAcquisitionOriginalV1,
    measurement: Option<Result<(), ImmutableFileAcquisitionRefusalV1>>,
    read: Option<Result<(), ImmutableImageErrorV1>>,
    canonical_before: Option<std::io::Result<PathBuf>>,
    canonical_post: RefCell<CanonicalUnitPostOriginalV1>,
    normalized: Option<Result<Vec<u8>, Method46InitialStartupClosedV1>>,
    file_post: RefCell<ProfilePostOriginalV1>,
    paid: bool,
    entered: bool,
    admitted: bool,
}

struct UnitPropertiesOriginalV1 {
    original: ServicePropertiesReadOriginalV2,
    result: Option<Result<(), ServicePropertiesReadClosedV2>>,
    entered: bool,
}

struct CanonicalUnitPostOriginalV1 {
    result: Option<std::io::Result<PathBuf>>,
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
            stopped: stopped::InitialStoppedOwnersOriginalV1::new(),
            file: None,
            open: None,
            acquisition: ImmutableFileAcquisitionOriginalV1::new(),
            measurement: None,
            read: None,
            canonical_before: None,
            canonical_post: RefCell::new(CanonicalUnitPostOriginalV1 {
                result: None,
                entered: false,
            }),
            normalized: None,
            file_post: RefCell::new(ProfilePostOriginalV1 {
                original: ImmutableFileRevalidationOriginalV1::new(),
                result: None,
            }),
            paid: false,
            entered: false,
            admitted: false,
        }
    }

    pub(super) fn initial_admitted(&self) -> bool {
        self.admitted
    }

    fn observe_properties(
        &self,
        index: usize,
        origin: Option<&Method46InitialOriginComparisonDataV1>,
        profile: Option<&Method46InitialProfileDataV3>,
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
                service::PROPERTIES,
                PROPERTIES,
            )),
        );
        if !matches!(observation.result, Some(Ok(())))
            || observation.original.completed_invocation_data_v1()
                != Some(origin.recipient_invocation)
        {
            return Err(Method46InitialStartupClosedV1);
        }
        service::require_service(
            observation
                .original
                .service_values_v2()
                .ok_or(Method46InitialStartupClosedV1)?,
            &profile.unit,
            &profile.owner_context,
            &profile.executable.path,
            std::process::id(),
        )?;
        let path = fragment_path(&observation.original)?;
        require_fragment_name(path, &profile.unit)?;
        if index == 1 {
            let initial = self.properties[0]
                .try_borrow()
                .map_err(|_| Method46InitialStartupClosedV1)?;
            if fragment_path(&initial.original)? != path {
                return Err(Method46InitialStartupClosedV1);
            }
            delivery::require_delivery(
                observation
                    .original
                    .service_values_v2()
                    .ok_or(Method46InitialStartupClosedV1)?,
                self.acquisition.bytes(),
            )?;
        }
        Ok(())
    }

    fn measure_fragment(
        &mut self,
        origin: &Method46InitialOriginComparisonDataV1,
        profile: &Method46InitialProfileDataV3,
        profile_path: &std::path::Path,
    ) -> Result<(), Method46InitialStartupClosedV1> {
        let observation = self.properties[0]
            .try_borrow()
            .map_err(|_| Method46InitialStartupClosedV1)?;
        let path = fragment_path(&observation.original)?;
        require_fragment_name(path, &profile.unit)?;
        self.canonical_before = Some(std::fs::canonicalize(path));
        let canonical = self
            .canonical_before
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(Method46InitialStartupClosedV1)?;
        crate::normal_root::profile::require_store_path(
            canonical.to_str().ok_or(Method46InitialStartupClosedV1)?,
        )
        .map_err(|_| Method46InitialStartupClosedV1)?;
        if canonical.as_os_str().len() > PATH_BYTES {
            return Err(Method46InitialStartupClosedV1);
        }
        self.open = Some(match File::open(path) {
            Ok(file) => {
                self.file = Some(file);
                Ok(())
            }
            Err(error) => Err(error),
        });
        let file = self.file.take().ok_or(Method46InitialStartupClosedV1)?;
        self.measurement = Some(self.acquisition.measure_original_once(
            canonical.clone(),
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

    fn finish_canonical_post(&self) -> Result<(), Method46InitialStartupClosedV1> {
        // Re-resolve the original reported name independently of the manager
        // post. A changed /etc link must not hide behind a stable store inode.
        let mut post = self
            .canonical_post
            .try_borrow_mut()
            .map_err(|_| Method46InitialStartupClosedV1)?;
        if post.entered {
            return Err(Method46InitialStartupClosedV1);
        }
        post.entered = true;
        let initial = self.properties[0]
            .try_borrow()
            .map_err(|_| Method46InitialStartupClosedV1)?;
        let path = fragment_path(&initial.original)?;
        post.result = Some(std::fs::canonicalize(path));
        let observed = post
            .result
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(Method46InitialStartupClosedV1)?;
        let expected = self
            .canonical_before
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(Method46InitialStartupClosedV1)?;
        if observed != expected {
            return Err(Method46InitialStartupClosedV1);
        }
        Ok(())
    }

    pub(super) fn finish_post(
        &self,
        origin: Option<&Method46InitialOriginComparisonDataV1>,
        profile: Option<&Method46InitialProfileDataV3>,
    ) -> Result<(), Method46InitialStartupClosedV1> {
        if !self.paid {
            return Ok(());
        }
        let properties = self.observe_properties(1, origin, profile);
        let stopped = self.finish_stopped_post(origin.map(|origin| origin.role), profile);
        let canonical = self.finish_canonical_post();
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
        properties.and(stopped).and(canonical).and(file)
    }
}

fn fragment_path(
    original: &ServicePropertiesReadOriginalV2,
) -> Result<&str, Method46InitialStartupClosedV1> {
    fragment_values(
        original
            .unit_values_v2()
            .ok_or(Method46InitialStartupClosedV1)?,
    )
}

fn fragment_values(
    values: &[aos_systemd_client::OwnedValue],
) -> Result<&str, Method46InitialStartupClosedV1> {
    let [fragment, dropins, transient] = values else {
        return Err(Method46InitialStartupClosedV1);
    };
    let (Value::Str(path), Value::Array(dropins), Value::Bool(false)) =
        (&**fragment, &**dropins, &**transient)
    else {
        return Err(Method46InitialStartupClosedV1);
    };
    if !dropins.inner().is_empty()
        || dropins.element_signature() != Value::from("").value_signature()
        || path.is_empty()
        || path.len() > PATH_BYTES
    {
        return Err(Method46InitialStartupClosedV1);
    }
    Ok(path.as_str())
}

fn require_fragment_name(path: &str, unit: &str) -> Result<(), Method46InitialStartupClosedV1> {
    if path.strip_prefix("/etc/systemd/system/") == Some(unit) {
        return Ok(());
    }
    crate::normal_root::profile::require_store_path(path)
        .map_err(|_| Method46InitialStartupClosedV1)
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
    // Two 67-call startup samples and four 27-call stopped-owner samples,
    // plus Hello and bounded signal/header carryover.
    // These are native-enforced ceilings, never an account or semantic claim.
    ReadonlyPropertyReceiveScheduleV2::new(268, 284, 64 * 1024, 4096, 284 * 64 * 1024).ok()
}

fn unit_demand(schedule: ReadonlyPropertyReceiveScheduleV2) -> Option<ResourceVector> {
    let manager = ReadonlyPropertyManagerOriginalV2::receiving_memory_bytes_v2(schedule)?;
    let properties = ServicePropertiesReadOriginalV2::receiving_memory_bytes_v2(
        service::PROPERTIES.len(),
        PROPERTIES.len(),
    )?;
    let memory = manager
        .checked_add(properties.checked_mul(2)?)?
        .checked_add(stopped::receiving_memory_bytes()?)?
        // Include the one permitted blocking worker even if it is never used.
        // The remaining MiB covers Runtime, task/driver and allocator scratch.
        .checked_add(WORKER_STACK_BYTES + 1024 * 1024)?
        .checked_add(8 * UNIT_BYTES + 8 * PATH_BYTES)?;
    let read = ImmutableFileAcquisitionOriginalV1::materialized_input_bytes_v1(UNIT_BYTES as u64)?
        .checked_add(UNIT_BYTES as u64 + 1)?;
    ResourceVector::ZERO
        .with(D::MemoryBytes, u64::try_from(memory).ok()?)
        .with(D::Pids, 1)
        .with(D::OpenFiles, 16)
        .with(D::MetadataEntries, 4 * PATH_BYTES as u64)
        .with(
            D::OutputBytes,
            read.checked_add((284 * 64 * 1024 + 268 * 4096 + 4096) as u64)?,
        )
        .checked_add(ImmutableFileAcquisitionOriginalV1::receiving_demand_v1(
            PATH_BYTES,
        )?)
        .ok()?
        .checked_add(ImmutableFileRevalidationOriginalV1::receiving_demand_v1()?)
        .ok()
        .and_then(|demand| {
            demand
                .checked_add(normal_fragment::receiving_demand()?)
                .ok()
        })
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
                    .max_blocking_threads(1)
                    .thread_stack_size(WORKER_STACK_BYTES)
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
            )?;
            {
                let initial = unit.properties[0].try_borrow().map_err(|_| self.closed)?;
                delivery::require_delivery(
                    initial.original.service_values_v2().ok_or(self.closed)?,
                    unit.acquisition.bytes(),
                )?;
            }
            unit.admitted = true;
            Ok(())
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
    fn fragment_properties_require_a_nontransient_unit_without_typed_dropins() {
        fn value<T: Into<Value<'static>>>(input: T) -> aos_systemd_client::OwnedValue {
            aos_systemd_client::OwnedValue::try_from(input.into()).unwrap()
        }

        let path = "/etc/systemd/system/aos-storaged.service";
        let mut properties = [
            value(path.to_owned()),
            value(Vec::<String>::new()),
            value(false),
        ];
        assert_eq!(fragment_values(&properties).unwrap(), path);

        properties[1] = value(Vec::<u32>::new());
        assert!(fragment_values(&properties).is_err());
        properties[1] = value(vec!["/run/systemd/system/override.conf".to_owned()]);
        assert!(fragment_values(&properties).is_err());
        properties[1] = value(Vec::<String>::new());
        properties[2] = value(true);
        assert!(fragment_values(&properties).is_err());
        properties[2] = value(false);
        properties[0] = value(String::new());
        assert!(fragment_values(&properties).is_err());
        assert!(fragment_values(&[]).is_err());
    }

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
    fn reported_fragment_names_reject_foreign_mutable_unit_directories() {
        let unit = "aos-sandbox-storage-floor-initialize.service";

        assert!(require_fragment_name(&format!("/etc/systemd/system/{unit}"), unit).is_ok());
        assert!(require_fragment_name(&format!("/run/systemd/system/{unit}"), unit).is_err());
        assert!(require_fragment_name("/etc/systemd/system/other.service", unit).is_err());
        assert!(require_fragment_name("/etc/systemd/system/../other.service", unit).is_err());
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
        assert!(unit.canonical_post.borrow().entered);
        drop(held);
    }
}
