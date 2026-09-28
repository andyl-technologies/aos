//! Closed Host-owned launch projection for one original FUSE worker instance.
//!
//! The descriptor table and launch role are versioned independently of broker
//! method admission. A specification is structural input to the existing Host
//! launcher, not Mount authority, a live worker proof, or public readiness.
//! The caller must retain image-owned executable admission, protected launch
//! custody, and the pre-loader environment seal through manager submission.

use std::num::NonZeroU32;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};

use zbus::proxy::CacheProperties;
use zbus::zvariant::Fd;

use super::{ExactStartError, SandboxCgroupPath, invalid};
use crate::client::{JobOutcome, SystemdClient};
use crate::error::Result;
use crate::manager_proxy::{ServiceProxy, UnitProxy};

const WORKER_SLICE_CGROUP: &str = "/aos.slice/aos-view.slice/aos-view-workers.slice";

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
    /// Returns the exact inherited-role order admitted by PID 1 and at startup.
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

/// Projects an original worker-instance value into a structural unit locator.
///
/// A name does not prove protected reservation, global uniqueness, or confinement.
/// PID 1's launch arm applies to the currently loaded unit; after unit collection,
/// the same name can identify a fresh unit. The actual Host/Mount owner must
/// durably reserve and consume the original worker instance before activation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FuseWorkerUnitNameV1 {
    service: String,
    instance: [u8; 16],
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
            service: format!("aos-view-worker@{}.service", super::encode_hex(instance)),
            instance,
        })
    }

    /// Returns the exact structural service locator without launch authority.
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
    /// Retains the role-exact descriptors for the sole image-owned template.
    ///
    /// No executable path, argv, environment, or property map is accepted.
    /// PID 1 admits the fixed measured-image template and exact descriptor role
    /// shapes before arming its first command. Host/Mount still independently
    /// admit original session provenance; this structural table is not authority.
    ///
    /// # Errors
    ///
    /// Returns an error if any descriptor cannot be duplicated. Partial copies
    /// are closed on failure.
    pub fn new(name: FuseWorkerUnitNameV1, descriptors: [BorrowedFd<'_>; 5]) -> Result<Self> {
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

        Ok(Self { name, descriptors })
    }

    /// Returns the original structural worker unit locator.
    #[must_use]
    pub const fn name(&self) -> &FuseWorkerUnitNameV1 {
        &self.name
    }

    fn descriptor_table(&self) -> Result<Vec<(Fd<'static>, String)>> {
        FuseWorkerDescriptorRoleV1::ALL
            .into_iter()
            .zip(&self.descriptors)
            .map(|(role, descriptor)| {
                let copy = descriptor.as_fd().try_clone_to_owned().map_err(|error| {
                    invalid(format!("cannot transfer FUSE worker role: {error}"))
                })?;
                Ok((Fd::from(copy), role.name().to_owned()))
            })
            .collect()
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
            .destination(self.manager.inner().destination().clone())?
            .path(path.clone())?
            .cache_properties(CacheProperties::No)
            .build()
            .await?;
        let service = ServiceProxy::builder(&self.conn)
            .destination(self.manager.inner().destination().clone())?
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
    /// systemd error for descriptor preparation, submission, or job completion.
    ///
    /// # Panics
    ///
    /// Propagates a panic from `before_submission` before manager submission.
    pub(crate) async fn start_fuse_worker_unit_guarded_v1<E>(
        &self,
        spec: &FuseWorkerUnitSpecV1,
        before_submission: &mut (dyn FnMut() -> std::result::Result<(), E> + Send),
    ) -> std::result::Result<JobOutcome, ExactStartError<E>> {
        let descriptors =
            super::exact_unit::prepare_then_guard(|| spec.descriptor_table(), before_submission)?;
        let instance = super::encode_hex(spec.name.instance);
        let path = self
            .manager
            .launch_aos_fuse_worker_v1(&instance, &descriptors)
            .await
            .map_err(crate::Error::from)
            .map_err(ExactStartError::Systemd)?;

        // The exact method reply follows complete role-table consumption.
        // Close our transport copies before waiting for the worker invocation.
        drop(descriptors);
        self.await_job(path).await.map_err(ExactStartError::Systemd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_locator_is_single_instance_and_outside_payload_cgroups() {
        let name = FuseWorkerUnitNameV1::from_instance([0xab; 16]).unwrap();

        assert_eq!(
            name.as_str(),
            "aos-view-worker@abababababababababababababababab.service"
        );
        assert_eq!(
            name.cgroup_path().as_str(),
            "/aos.slice/aos-view.slice/aos-view-workers.slice/aos-view-worker@abababababababababababababababab.service"
        );
        assert!(FuseWorkerUnitNameV1::from_instance([0; 16]).is_err());
    }

    #[test]
    fn worker_role_table_is_fixed_and_contains_no_launch_properties() {
        use std::fs::File;

        assert_eq!(
            FuseWorkerDescriptorRoleV1::ALL.map(|role| role as u8),
            [3, 4, 5, 6, 7]
        );

        // Only descriptor transport is tested here. PID 1 must reject these
        // placeholder objects; they carry no image, Mount, or worker authority.
        let placeholder = File::open("/dev/null").unwrap();
        let spec = FuseWorkerUnitSpecV1::new(
            FuseWorkerUnitNameV1::from_instance([7; 16]).unwrap(),
            [placeholder.as_fd(); 5],
        )
        .unwrap();
        let descriptors = spec.descriptor_table().unwrap();

        assert_eq!(
            descriptors
                .into_iter()
                .map(|(_, name)| name)
                .collect::<Vec<_>>(),
            FuseWorkerDescriptorRoleV1::ALL.map(|role| role.name().to_owned())
        );
        assert_eq!(spec.name.instance, [7; 16]);
    }
}
