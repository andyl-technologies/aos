//! Sealed native Root startup custody from actual legacy or received originals.
//!
//! Public field views carry physical comparison DATA. Only the closed actual
//! legacy table producer and the same enrolled selected receiver construct the
//! native owner; no field DTO, file, snapshot or caller trait adopts one.

use std::fs::File;
use std::num::NonZeroU32;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use aos_sandbox_linux::cgroup::RetainedCgroupAnchor;
use aos_sandbox_linux::guest_confinement::require_subject;
use aos_sandbox_linux::inherited_fd::duplicate_initial_activation_table;
use aos_linux_descriptors::pidfd::PidFd;
use aos_sandbox_linux::pidfd::PidFdProcessIdentity;
use aos_sandbox_linux::selinux_policy::VerifiedLiveSelinuxPolicy;

use crate::profile_data::{images, schema as profile};
use crate::immutable_image::RetainedImmutableFileV1;
use profile::{CONTEXT, NormalRootProfileV1, UNIT};
use super::RootObservationErrorV1 as NormalRootStartupErrorV1;
use super::root_service as service;

mod currentness;
pub(super) use currentness::{RootLocalCurrentnessOriginalV1, RootUnitCurrentnessOriginalV1};

const PID1_FD_NAME: &str = "aos-normal-root-pid1-image";
const PROFILE_FD_NAME: &str = "aos-normal-root-profile";

/// Holds the actual legacy process's closed original two-role table.
pub struct RootLegacyStartupCaptureV1 {
    descriptors: Option<(OwnedFd, OwnedFd)>,
}

impl RootLegacyStartupCaptureV1 {
    /// Captures only the current process's exact original legacy table.
    ///
    /// # Errors
    /// Preserves the existing names, role and descriptor capture refusals.
    pub fn capture() -> Result<Self, NormalRootStartupErrorV1> {
        let names = super::original_activation_names_v1(2)
            .map_err(|_| NormalRootStartupErrorV1::Activation)?;
        let count = names.len();
        if !matches!(count, 0 | 2) {
            return Err(NormalRootStartupErrorV1::Activation);
        }
        if !root_legacy_roles_match_data_v1(&names) {
            return Err(NormalRootStartupErrorV1::Activation);
        }
        let descriptors = duplicate_initial_activation_table(count)
            .map_err(|_| NormalRootStartupErrorV1::Activation)?;
        if count == 0 {
            return Ok(Self { descriptors: None });
        }
        let mut pid1 = None;
        let mut profile = None;
        for (name, fd) in names.iter().zip(descriptors) {
            match name.as_str() {
                PID1_FD_NAME => pid1 = Some(fd),
                PROFILE_FD_NAME => profile = Some(fd),
                _ => return Err(NormalRootStartupErrorV1::Activation),
            }
        }
        Ok(Self {
            descriptors: Some((
                pid1.ok_or(NormalRootStartupErrorV1::Activation)?,
                profile.ok_or(NormalRootStartupErrorV1::Activation)?,
            )),
        })
    }

    /// Rejects administrative invocations carrying actual normal roles.
    ///
    /// # Errors
    /// Refuses any captured original normal launch descriptors.
    pub fn require_non_normal_invocation(&self) -> Result<(), NormalRootStartupErrorV1> {
        if self.descriptors.is_some() {
            Err(NormalRootStartupErrorV1::Activation)
        } else {
            Ok(())
        }
    }

    /// Runs the same legacy fixed-image/service/confinement comparison once.
    ///
    /// # Errors
    /// Preserves actual original image, identity, profile, unit and policy
    /// classification and the ordinary local resource disposal frontier.
    pub fn admit_normal(
        self,
        identities: [u32; 4],
    ) -> Result<Option<RootStartupNativeOriginalV1>, NormalRootStartupErrorV1> {
        let Some((pid1, profile_fd)) = self.descriptors else {
            // Legacy is never a proof. A labelled normal owner must have its
            // profile; failure to observe SELinux while mounted also closes.
            if Path::new("/sys/fs/selinux/enforce")
                .try_exists()
                .map_err(|_| NormalRootStartupErrorV1::Confinement)?
            {
                let context = read_root_bounded_confinement_data_v1("/proc/thread-self/attr/current", 256)?;
                let context = context.strip_suffix(b"\n").unwrap_or(&context);
                let context = context.strip_suffix(&[0]).unwrap_or(context);
                if context == CONTEXT.as_bytes() {
                    return Err(NormalRootStartupErrorV1::Activation);
                }
            }
            return Ok(None);
        };
        let (profile_file, bytes) = images::retain_profile(File::from(profile_fd))?;
        let profile = NormalRootProfileV1::decode(&bytes)?;
        if profile.identities != identities
            || profile_file.path().parent() != Path::new(&profile.effective_matrix.path).parent()
        {
            return Err(NormalRootStartupErrorV1::Profile);
        }
        let manager = images::retain_pin(&profile.pid1, Some(File::from(pid1)), true)?;
        let executable = images::retain_pin(
            &profile.executable,
            Some(File::open("/proc/self/exe").map_err(|_| NormalRootStartupErrorV1::Image)?),
            true,
        )?;
        let runtime = profile
            .runtime_files
            .iter()
            .map(|pin| {
                let executable =
                    pin.path == profile.executable.path || pin.path == profile.loader.path;
                images::retain_pin(pin, None, executable)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let policy = VerifiedLiveSelinuxPolicy::verify(&profile.canonical_policy.path)
            .map_err(|_| NormalRootStartupErrorV1::Confinement)?;
        if policy.digest() != profile.canonical_policy.sha256 {
            return Err(NormalRootStartupErrorV1::Confinement);
        }
        let evidence = [
            &profile.canonical_policy,
            &profile.source_policy,
            &profile.effective_matrix,
        ]
        .into_iter()
        .map(|pin| images::retain_pin(pin, None, false))
        .collect::<Result<Vec<_>, _>>()?;
        let observed = service::observe(
            profile_file
                .path()
                .to_str()
                .ok_or(NormalRootStartupErrorV1::Profile)?,
        )?;
        let fragment = RetainedImmutableFileV1::observe_fragment(observed.fragment.clone())
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
        require_unit(&fragment, &profile_file, &profile)?;
        let process = PidFd::open(
            NonZeroU32::new(std::process::id()).ok_or(NormalRootStartupErrorV1::Service)?,
        )
        .map_err(|_| NormalRootStartupErrorV1::Service)?;
        if process
            .info()
            .map_err(|_| NormalRootStartupErrorV1::Service)?
            .parent_pid()
            != 1
        {
            return Err(NormalRootStartupErrorV1::Service);
        }
        let identity = aos_sandbox_linux::pidfd::process_identity(&(process))
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
        let cgroup = retain_fixed_cgroup(Path::new(&format!("system.slice/{UNIT}")))?;
        let retained = RootStartupNativeOriginalV1 {
            fields: RootStartupNativeFieldsV1 {
                profile_file,
                profile,
                manager,
                executable,
                runtime,
                evidence,
                fragment,
                policy,
                process,
                identity,
                cgroup,
                observed,
            },
            initial_owner: None,
            selected_permanent: OnceLock::new(),
        };
        retained.recheck_ordinary()?;
        Ok(Some(retained))
    }
}

/// Carries native field DATA without a native adoption constructor.
///
/// Constructing this DATA type cannot construct the sealed original owner.
pub struct RootStartupNativeFieldsV1 {
    /// Retains the actual profile file comparison input.
    pub profile_file: RetainedImmutableFileV1,
    /// Retains the actual profile comparison input.
    pub profile: NormalRootProfileV1,
    /// Retains the actual manager comparison input.
    pub manager: RetainedImmutableFileV1,
    /// Retains the actual executable comparison input.
    pub executable: RetainedImmutableFileV1,
    /// Retains the actual runtime comparison input.
    pub runtime: Vec<RetainedImmutableFileV1>,
    /// Retains the actual evidence comparison input.
    pub evidence: Vec<RetainedImmutableFileV1>,
    /// Retains the actual fragment comparison input.
    pub fragment: RetainedImmutableFileV1,
    /// Retains the actual policy comparison input.
    pub policy: VerifiedLiveSelinuxPolicy,
    /// Retains the actual process comparison input.
    pub process: PidFd,
    /// Retains the actual identity comparison input.
    pub identity: PidFdProcessIdentity,
    /// Retains the actual cgroup comparison input.
    pub cgroup: RetainedCgroupAnchor,
    /// Retains the actual observed comparison input.
    pub observed: service::ServiceObservationV1,
}

/// Owns actual complete native startup originals without semantic authority.
#[must_use = "retain the actual native startup originals through serving"]
pub struct RootStartupNativeOriginalV1 {
    pub(super) fields: RootStartupNativeFieldsV1,
    pub(super) initial_owner: Option<Arc<()>>,
    pub(super) selected_permanent: OnceLock<Arc<super::root_permanent::RootPermanentNativeOriginalV1>>,
}

impl std::ops::Deref for RootStartupNativeOriginalV1 {
    type Target = RootStartupNativeFieldsV1;

    fn deref(&self) -> &Self::Target {
        &self.fields
    }
}

impl RootStartupNativeOriginalV1 {
    /// Borrows actual fields without adopting a replacement or granting a role.
    #[must_use]
    pub fn fields(&self) -> &RootStartupNativeFieldsV1 {
        &self.fields
    }

    /// Rechecks the same local images/process/confinement without a role grant.
    ///
    /// # Errors
    /// Preserves the existing local currentness classifications and order.
    pub(super) fn require_local_current(&self) -> Result<(), NormalRootStartupErrorV1> {
        self.require_local_current_recipe(None)
    }

    /// Rechecks the actual fixed fragment/profile without a role grant.
    ///
    /// # Errors
    /// Preserves the existing fixed unit and profile currentness refusals.
    pub(super) fn require_final_unit_current(&self) -> Result<(), NormalRootStartupErrorV1> {
        self.require_final_unit_current_recipe(None)
    }

    /// Runs the same ordinary local/service/local bookends without receiving.
    ///
    /// # Errors
    /// Refuses selected startups, which must borrow their same enrolled owner;
    /// preserves the ordinary native/image/unit/refusal ordering.
    pub fn recheck_ordinary(&self) -> Result<(), NormalRootStartupErrorV1> {
        if self.initial_owner.is_some() {
            return Err(NormalRootStartupErrorV1::Service);
        }
        self.require_local_current()?;
        let observed = service::observe(
            self.profile_file.path().to_str().ok_or(NormalRootStartupErrorV1::Profile)?,
        )?;
        service::require_same(&self.observed, &observed)?;
        self.require_final_unit_current()
    }

    /// Rechecks this same actual startup through its original native branch.
    ///
    /// # Errors
    /// Refuses unfinished selected handoff or changed native custody. A
    /// selected original never falls back to the ordinary comparison recipe.
    pub fn recheck_actual_v1(&self) -> Result<(), NormalRootStartupErrorV1> {
        if self.initial_owner.is_some() {
            self.borrow_selected_startup_v1()?.recheck_v1()
        } else {
            self.recheck_ordinary()
        }
    }
}

fn require_unit(
    fragment: &RetainedImmutableFileV1,
    profile_file: &RetainedImmutableFileV1,
    profile: &NormalRootProfileV1,
) -> Result<(), NormalRootStartupErrorV1> {
    images::require_unit(fragment, profile_file, profile).map_err(Into::into)
}

/// Checks only the fixed legacy names grammar as nonauthorizing DATA.
#[must_use]
pub fn root_legacy_roles_match_data_v1(names: &[String]) -> bool {
    names.is_empty()
        || names.len() == 2
            && names
                .iter()
                .filter(|name| name.as_str() == PID1_FD_NAME)
                .count()
                == 1
            && names
                .iter()
                .filter(|name| name.as_str() == PROFILE_FD_NAME)
                .count()
                == 1
}

pub(super) fn retain_fixed_cgroup(path: &Path) -> Result<RetainedCgroupAnchor, NormalRootStartupErrorV1> {
    crate::profile_data::native_observation::retain_cgroup_anchor_data_v1(path)
        .map_err(Into::into)
}

/// Reads bounded physical observation DATA without creating role authority.
///
/// # Errors
/// Preserves the existing confinement classification and actual read/disposal
/// order on opening, reading or rejecting an oversized observation.
///
/// # Panics
/// The unchanged byte-limit arithmetic can overflow for `usize::MAX` on a
/// 64-bit target. Actual closed role recipes supply only their fixed small
/// observation bounds; this mechanical DATA helper preserves that arithmetic.
pub fn read_root_bounded_confinement_data_v1(path: &str, maximum: usize) -> Result<Vec<u8>, NormalRootStartupErrorV1> {
    let mut original = crate::profile_data::shared_read::BoundedFileReadOriginalV1::new();
    read_root_bounded_confinement_recipe(path, maximum, &mut original, false)?;
    Ok(std::mem::take(&mut original.bytes))
}

fn read_root_bounded_confinement_recipe(
    path: &str,
    maximum: usize,
    original: &mut crate::profile_data::shared_read::BoundedFileReadOriginalV1,
    retained: bool,
) -> Result<(), NormalRootStartupErrorV1> {
    original.read_once(path, maximum as u64, false, retained)
        .map_err(|_| NormalRootStartupErrorV1::Confinement)?;
    if original.bytes.len() > maximum {
        return Err(NormalRootStartupErrorV1::Confinement);
    }
    Ok(())
}

fn require_status(bytes: &[u8]) -> Result<(), NormalRootStartupErrorV1> {
    crate::profile_data::status::require_status(bytes).map_err(Into::into)
}
