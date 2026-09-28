//! Closed Host-owned launch projection for one original FUSE worker instance.
//!
//! The descriptor table and launch role are versioned independently of broker
//! method admission. A specification is structural input to the existing Host
//! launcher, not Mount authority, a live worker proof, or public readiness.
//! The caller must retain image-owned executable admission, protected launch
//! custody, and the pre-loader environment seal through manager submission.

use std::num::NonZeroU32;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::path::{Component, Path};
use std::time::Duration;

use zbus::proxy::CacheProperties;
use zbus::zvariant::Fd;

use super::{
    ExactStartError, SandboxCgroupPath, bool_property, complex_property, duration_micros,
    exec_property, invalid, string_array_property, string_property, u32_property, u64_property,
};
use crate::client::{JobOutcome, SystemdClient};
use crate::error::Result;
use crate::manager_proxy::{AuxiliaryUnit, ServiceProxy, TransientProperty, UnitProxy};

const WORKER_EXECUTABLE: &str = "aos-filesystem-fuse-worker";
const WORKER_SLICE: &str = "aos-view-workers.slice";
const WORKER_SLICE_CGROUP: &str = "/aos.slice/aos-view.slice/aos-view-workers.slice";
const LAUNCH_ARGUMENT: &str = "--mount-owned-session-v1";

/// Enumerates the complete worker-session-v1 inherited descriptor table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FuseWorkerDescriptorRoleV1 {
    /// Image-owned executable pin, independently checked before libfuse entry.
    Executable = 3,
    /// Exact immutable original reservation and projection launch plan.
    Plan = 4,
    /// Duplicate of Mount's original freshly opened, connected FUSE OFD.
    Connection = 5,
    /// Mount-created private record endpoint, never a public listener.
    Records = 6,
    /// Fixed nonblocking cancellation reader.
    Cancellation = 7,
}

impl FuseWorkerDescriptorRoleV1 {
    /// Returns the exact order used in `ExtraFileDescriptors` and at startup.
    pub const ALL: [Self; 5] = [
        Self::Executable,
        Self::Plan,
        Self::Connection,
        Self::Records,
        Self::Cancellation,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Executable => "fuse-worker-executable-v1",
            Self::Plan => "fuse-worker-plan-v1",
            Self::Connection => "fuse-worker-connection-v1",
            Self::Records => "fuse-worker-records-v1",
            Self::Cancellation => "fuse-worker-cancellation-v1",
        }
    }
}

/// Names a single-use unit solely by its broker-minted original worker instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FuseWorkerUnitNameV1 {
    service: String,
}

impl FuseWorkerUnitNameV1 {
    /// Derives an exact unit locator without conferring launch authority.
    ///
    /// # Errors
    ///
    /// Returns an error for the zero worker-instance sentinel.
    pub fn from_instance(instance: [u8; 16]) -> Result<Self> {
        if instance == [0; 16] {
            return Err(invalid("FUSE worker instance is zero"));
        }

        Ok(Self {
            service: format!("aos-view-worker-{}.service", super::encode_hex(instance)),
        })
    }

    /// Returns the exact independently confined service locator.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.service
    }

    /// Returns the sole expected cgroup, outside every payload subtree.
    #[must_use]
    pub fn cgroup_path(&self) -> SandboxCgroupPath {
        SandboxCgroupPath(format!("{WORKER_SLICE_CGROUP}/{}", self.service))
    }
}

/// Retains the closed descriptor projection through one initial activation.
///
/// Descriptor admission belongs to Host's protected composition. In particular,
/// adopting a received character device here does not prove a fresh connection:
/// only Mount's retained original OFD and held dispatch can establish that join.
/// This structural type exposes no arbitrary executable name, argv, environment,
/// property map, listener, capability, or automatic restart setting.
pub struct FuseWorkerUnitSpecV1 {
    name: FuseWorkerUnitNameV1,
    executable_path: String,
    descriptors: [OwnedFd; 5],
}

/// Projects one manager observation without substituting for retained kernel custody.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FuseWorkerUnitObservationV1 {
    /// Exact original worker invocation, absent before first activation.
    pub invocation_id: Option<[u8; 16]>,
    /// Manager-reported active state.
    pub active_state: String,
    /// Manager-reported service substate.
    pub sub_state: String,
    /// Sole original worker leader, absent after exit.
    pub main_pid: Option<NonZeroU32>,
    /// Exact instance-derived cgroup, absent before realization.
    pub cgroup: Option<SandboxCgroupPath>,
}

impl FuseWorkerUnitSpecV1 {
    /// Pins a role-exact descriptor table for the fixed image-owned worker.
    ///
    /// `executable_path` must come from Host's image-owned deployment policy,
    /// not broker request bytes. Path shape and descriptor duplication here
    /// are structural checks; Host must separately establish the image pin,
    /// exact role types, original session binding, and final effect guard.
    ///
    /// # Errors
    ///
    /// Returns an error for a noncanonical fixed worker store path or failed
    /// duplication of any descriptor. Partial copies are closed on failure.
    pub fn new(
        name: FuseWorkerUnitNameV1,
        executable_path: String,
        descriptors: [BorrowedFd<'_>; 5],
    ) -> Result<Self> {
        validate_executable_path(&executable_path)?;
        let copies = descriptors
            .into_iter()
            .map(|descriptor| {
                descriptor
                    .try_clone_to_owned()
                    .map_err(|error| invalid(format!("cannot retain FUSE worker role: {error}")))
            })
            .collect::<Result<Vec<_>>>()?;
        let descriptors = copies
            .try_into()
            .map_err(|_| invalid("FUSE worker descriptor table length changed"))?;

        Ok(Self {
            name,
            executable_path,
            descriptors,
        })
    }

    /// Returns the original, single-use worker unit locator.
    #[must_use]
    pub const fn name(&self) -> &FuseWorkerUnitNameV1 {
        &self.name
    }

    fn properties(&self) -> Result<Vec<TransientProperty>> {
        let descriptors = FuseWorkerDescriptorRoleV1::ALL
            .into_iter()
            .zip(&self.descriptors)
            .map(|(role, descriptor)| {
                let copy = descriptor.as_fd().try_clone_to_owned().map_err(|error| {
                    invalid(format!("cannot transfer FUSE worker role: {error}"))
                })?;
                Ok((Fd::from(copy), role.name().to_owned()))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(vec![
            string_property("Description", "AOS original Mount-owned FUSE worker"),
            string_property("Type", "exec"),
            string_property("Slice", WORKER_SLICE),
            string_property("Restart", "no"),
            u64_property("StartLimitIntervalUSec", u64::MAX),
            u32_property("StartLimitBurst", 1),
            string_property("CollectMode", "inactive-or-failed"),
            string_property("KillMode", "control-group"),
            bool_property("DynamicUser", true),
            bool_property("SetLoginEnvironment", false),
            u32_property("UMask", 0o077),
            u64_property("CapabilityBoundingSet", 0),
            u64_property("AmbientCapabilities", 0),
            bool_property("NoNewPrivileges", true),
            string_property("ProtectSystem", "strict"),
            string_property("ProtectHome", "yes"),
            bool_property("PrivateNetwork", true),
            bool_property("PrivateIPC", true),
            bool_property("PrivateTmp", true),
            bool_property("PrivateDevices", true),
            bool_property("ProtectKernelTunables", true),
            bool_property("ProtectKernelModules", true),
            bool_property("ProtectControlGroups", true),
            bool_property("ProtectClock", true),
            bool_property("RestrictSUIDSGID", true),
            bool_property("RestrictRealtime", true),
            bool_property("LockPersonality", true),
            bool_property("MemoryDenyWriteExecute", true),
            u64_property("RestrictNamespaces", 0),
            u64_property("TasksMax", 8),
            u64_property("MemoryHigh", 64 * 1024 * 1024),
            u64_property("MemoryMax", 128 * 1024 * 1024),
            u64_property("MemorySwapMax", 0),
            u64_property("LimitNOFILE", 128),
            u64_property("LimitNOFILESoft", 128),
            complex_property(
                "RestrictAddressFamilies",
                (true, vec!["AF_UNIX".to_owned()]),
            )?,
            complex_property(
                "SystemCallFilter",
                (true, vec!["@system-service".to_owned()]),
            )?,
            complex_property(
                "SystemCallFilter",
                (
                    false,
                    vec![
                        "accept".to_owned(),
                        "accept4".to_owned(),
                        "bind".to_owned(),
                        "listen".to_owned(),
                    ],
                ),
            )?,
            string_array_property("SystemCallArchitectures", vec!["native".to_owned()])?,
            complex_property("ExtraFileDescriptors", descriptors)?,
            // Empty per-unit Environment does not itself remove PID 1's
            // manager environment. The required pre-loader launch seal must
            // exclude manager injection before this candidate can activate.
            string_array_property("Environment", Vec::new())?,
            u64_property(
                "TimeoutStartUSec",
                duration_micros(Duration::from_secs(5), "FUSE worker start timeout")?,
            ),
            u64_property(
                "TimeoutStopUSec",
                duration_micros(Duration::from_secs(5), "FUSE worker stop timeout")?,
            ),
            exec_property(
                &self.executable_path,
                vec![self.executable_path.clone(), LAUNCH_ARGUMENT.to_owned()],
            )?,
        ])
    }
}

impl SystemdClient {
    /// Observes only the exact original FUSE worker unit locator.
    ///
    /// Identity and invocation are sampled before and after the service fields.
    /// A stable result still requires a retained pidfd, cgroup membership, live
    /// Mount-owned channel, and the protected image/launch seal at consumption.
    ///
    /// # Errors
    ///
    /// Returns an error for manager failures, replaced units or invocations,
    /// malformed IDs, or a cgroup outside the sole original worker locator.
    pub async fn observe_fuse_worker_unit_v1(
        &self,
        name: &FuseWorkerUnitNameV1,
    ) -> Result<Option<FuseWorkerUnitObservationV1>> {
        let path = match self.manager.get_unit(name.as_str()).await {
            Ok(path) => path,
            Err(error) if crate::error::is_no_such_unit(&error) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let unit = UnitProxy::builder(&self.conn)
            .path(path.clone())?
            .cache_properties(CacheProperties::No)
            .build()
            .await?;
        let service = ServiceProxy::builder(&self.conn)
            .path(path.clone())?
            .cache_properties(CacheProperties::No)
            .build()
            .await?;

        let id_before = unit.id().await?;
        let invocation_before = super::parse_invocation_id(unit.invocation_id().await?)?;
        let active_state = unit.active_state().await?;
        let sub_state = unit.sub_state().await?;
        let main_pid = NonZeroU32::new(service.main_pid().await?);
        let cgroup =
            super::parse_exact_cgroup(&name.cgroup_path(), service.control_group().await?)?;
        let invocation_after = super::parse_invocation_id(unit.invocation_id().await?)?;
        let id_after = unit.id().await?;
        let current_path = self.manager.get_unit(name.as_str()).await?;

        if id_before != name.as_str()
            || id_before != id_after
            || invocation_before != invocation_after
            || current_path != path
        {
            return Err(invalid("FUSE worker unit changed during observation"));
        }

        Ok(Some(FuseWorkerUnitObservationV1 {
            invocation_id: invocation_before,
            active_state,
            sub_state,
            main_pid,
            cgroup,
        }))
    }

    /// Submits the closed worker launch only after the caller's final guard.
    ///
    /// This is not a broker admission surface. The protected Host caller must
    /// retain the actual Root/Mount hold, image/environment seal, exact original
    /// request/session, and descriptor custody through activation and readback.
    /// No broker method is registered or advertised by this transport helper.
    ///
    /// # Errors
    ///
    /// Returns [`ExactStartError::Guard`] if final admission fails, or a
    /// systemd error for property preparation, submission, or job completion.
    ///
    /// # Panics
    ///
    /// Propagates a panic from `before_submission` before manager submission.
    pub async fn start_fuse_worker_unit_guarded_v1<E>(
        &self,
        spec: &FuseWorkerUnitSpecV1,
        before_submission: &mut (dyn FnMut() -> std::result::Result<(), E> + Send),
    ) -> std::result::Result<JobOutcome, ExactStartError<E>> {
        let properties =
            super::exact_unit::prepare_then_guard(|| spec.properties(), before_submission)?;
        let auxiliary_units: Vec<AuxiliaryUnit> = Vec::new();
        let path = self
            .manager
            .start_transient_unit(spec.name.as_str(), "fail", &properties, &auxiliary_units)
            .await
            .map_err(crate::Error::from)
            .map_err(ExactStartError::Systemd)?;
        self.await_job(path).await.map_err(ExactStartError::Systemd)
    }
}

fn validate_executable_path(value: &str) -> Result<()> {
    let path = Path::new(value);
    if value.len() > 4096
        || value.as_bytes().contains(&0)
        || !value.starts_with("/nix/store/")
        || value
            .split('/')
            .skip(1)
            .any(|component| component.is_empty() || component == "." || component == "..")
        || path.file_name().and_then(|name| name.to_str()) != Some(WORKER_EXECUTABLE)
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(invalid(
            "FUSE worker must name the fixed image store executable",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_locator_is_single_instance_and_outside_payload_cgroups() {
        let name = FuseWorkerUnitNameV1::from_instance([0xab; 16]).unwrap();

        assert_eq!(
            name.as_str(),
            "aos-view-worker-abababababababababababababababab.service"
        );
        assert_eq!(
            name.cgroup_path().as_str(),
            "/aos.slice/aos-view.slice/aos-view-workers.slice/aos-view-worker-abababababababababababababababab.service"
        );
        assert!(FuseWorkerUnitNameV1::from_instance([0; 16]).is_err());
    }

    #[test]
    fn worker_role_table_and_executable_are_closed() {
        assert_eq!(
            FuseWorkerDescriptorRoleV1::ALL.map(|role| role as u8),
            [3, 4, 5, 6, 7]
        );
        assert!(
            validate_executable_path("/nix/store/image/bin/aos-filesystem-fuse-worker").is_ok()
        );

        for path in [
            "/run/aos-filesystem-fuse-worker",
            "/nix/store/image/bin/other-worker",
            "/nix/store/image/../bin/aos-filesystem-fuse-worker",
            "/nix/store/image/./bin/aos-filesystem-fuse-worker",
            "/nix/store/image//bin/aos-filesystem-fuse-worker",
            "/nix/store/image/bin/aos-filesystem-fuse-worker\0",
        ] {
            assert!(validate_executable_path(path).is_err(), "{path}");
        }
    }

    #[test]
    fn structural_launch_projection_keeps_caps_empty_and_never_restarts() {
        use std::fs::File;
        use zbus::zvariant::OwnedValue;

        // This tests structural property compilation only. These descriptors
        // deliberately carry no image, Mount, or worker admission authority.
        let placeholder = File::open("/dev/null").unwrap();
        let spec = FuseWorkerUnitSpecV1::new(
            FuseWorkerUnitNameV1::from_instance([7; 16]).unwrap(),
            "/nix/store/image/bin/aos-filesystem-fuse-worker".to_owned(),
            [placeholder.as_fd(); 5],
        )
        .unwrap();

        let properties = spec.properties().unwrap();
        let property = |name: &str| -> OwnedValue {
            let matches = properties
                .iter()
                .filter(|(key, _)| key == name)
                .collect::<Vec<_>>();
            assert_eq!(matches.len(), 1, "{name}");
            matches[0].1.try_clone().unwrap()
        };

        assert_eq!(u64::try_from(property("CapabilityBoundingSet")).unwrap(), 0);
        assert_eq!(u64::try_from(property("AmbientCapabilities")).unwrap(), 0);
        assert_eq!(u64::try_from(property("RestrictNamespaces")).unwrap(), 0);
        assert!(bool::try_from(property("NoNewPrivileges")).unwrap());
        assert_eq!(String::try_from(property("Restart")).unwrap(), "no");
        assert_eq!(u32::try_from(property("StartLimitBurst")).unwrap(), 1);
        assert!(
            Vec::<String>::try_from(property("Environment"))
                .unwrap()
                .is_empty()
        );
        assert!(properties.iter().all(|(name, _)| {
            !matches!(
                name.as_str(),
                "ExecStartPre" | "ExecStartPost" | "ExecStop" | "ExecStopPost"
            )
        }));
        let descriptors =
            Vec::<(Fd<'static>, String)>::try_from(property("ExtraFileDescriptors")).unwrap();
        assert_eq!(
            descriptors
                .into_iter()
                .map(|(_, name)| name)
                .collect::<Vec<_>>(),
            FuseWorkerDescriptorRoleV1::ALL.map(|role| role.name().to_owned())
        );
    }
}
