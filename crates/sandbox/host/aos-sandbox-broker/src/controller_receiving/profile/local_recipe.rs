//! Shares the original local profile comparison with optional native custody.
//!
//! Ordinary callers preserve their original temporary disposal. Selected
//! destinations retain the same reached native results in the supplied owner.

use std::fs::File;
use std::io::Read as _;
use aos_linux_descriptors::pidfd::PidFdInfo;
use aos_sandbox_linux::guest_confinement::require_subject;
use aos_sandbox_linux::selinux_policy::PolicyReadbackError;
use crate::immutable_image::ImmutableImageErrorV1;
use crate::controller_receiving::ControllerReceivingErrorV1;
use super::{ControllerSelfProfileOriginalV1, ControllerProfileErrorV1};
use super::status::require_status;

pub(super) struct LocalCurrentness {
    profile: Option<Result<(), ImmutableImageErrorV1>>,
    images: Vec<Result<(), ImmutableImageErrorV1>>,
    images_allocation: Option<Result<(), std::collections::TryReserveError>>,
    nix: Option<Result<(), ImmutableImageErrorV1>>,
    policy: Option<Result<(), PolicyReadbackError>>,
    subject: Option<Result<(), aos_linux_descriptors::Error>>,
    credentials: Option<Result<(), ControllerProfileErrorV1>>,
    status_open: Option<std::io::Result<Option<File>>>,
    status_file_retired: bool,
    status_bytes: Vec<u8>,
    status_read: Option<std::io::Result<usize>>,
    status: Option<Result<(), ControllerProfileErrorV1>>,
    membership: Option<Result<PidFdInfo, aos_linux_descriptors::Error>>,
    alive: Option<Result<bool, aos_linux_descriptors::Error>>,
    fragment: Option<Result<(), ImmutableImageErrorV1>>,
    pub(super) completion: Option<Result<(), ControllerProfileErrorV1>>,
}

impl LocalCurrentness {
    pub(super) fn new() -> Self {
        Self {
            profile: None, images: Vec::new(), images_allocation: None, nix: None, policy: None, subject: None,
            credentials: None, status_open: None, status_file_retired: false, status_bytes: Vec::new(), status_read: None,
            status: None, membership: None, alive: None, fragment: None, completion: None,
        }
    }

    pub(super) fn dominant_bytes(files: usize) -> Result<usize, ControllerReceivingErrorV1> {
        // Status read has a64KiB strict bound plus one byte, including reached
        // Vec old/new realloc. Image Result cells have an actual pin count.
        std::mem::size_of::<Self>().checked_add(3 * (64 * 1024 + 1))
            .and_then(|bytes| bytes.checked_add(32 * 1024))
            .and_then(|bytes| bytes.checked_add(files.checked_mul(
                std::mem::size_of::<Result<(), ImmutableImageErrorV1>>(),
            )?.checked_mul(4)?))
            .ok_or(ControllerReceivingErrorV1::EnrollmentUnavailable)
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.failure_observed(None)
    }

    pub(super) fn failure_observed<'original>(
        &'original self,
        originals: Option<&'original super::local_currentness::LocalCurrentnessOriginalsV1>,
    ) -> Option<&'original (dyn std::error::Error + 'static)> {
        originals.and_then(|originals| originals.profile.failure())
            .or_else(|| retained_error(&self.profile))
            .or_else(|| retained_error(&self.images_allocation))
            .or_else(|| originals.and_then(|originals| retained_error(&originals.images_allocation)))
            .or_else(|| self.images.iter().enumerate().find_map(|(index, result)| {
                originals.and_then(|originals| originals.images.get(index))
                    .and_then(|original| original.failure())
                    .or_else(|| result.as_ref().err()
                        .map(|cause| cause as &(dyn std::error::Error + 'static)))
            }))
            .or_else(|| originals.and_then(|originals| originals.nix.failure()))
            .or_else(|| retained_error(&self.nix))
            .or_else(|| originals.and_then(|originals| originals.policy.failure()))
            .or_else(|| retained_error(&self.policy))
            .or_else(|| originals.and_then(|originals| originals.subject.failure()))
            .or_else(|| retained_error(&self.subject))
            .or_else(|| retained_error(&self.credentials))
            .or_else(|| retained_error(&self.status_open))
            .or_else(|| retained_error(&self.status_read))
            .or_else(|| retained_error(&self.status))
            .or_else(|| originals.and_then(|originals| originals.membership.failure()
                .map(|cause| cause as &(dyn std::error::Error + 'static))))
            .or_else(|| retained_error(&self.membership))
            .or_else(|| retained_error(&self.alive))
            .or_else(|| originals.and_then(|originals| originals.fragment.failure()))
            .or_else(|| retained_error(&self.fragment))
            .or_else(|| retained_error(&self.completion))
    }

    pub(super) fn capture(&mut self, profile: &ControllerSelfProfileOriginalV1) {
        self.capture_observed(profile, None);
    }

    pub(super) fn capture_observed(
        &mut self,
        profile: &ControllerSelfProfileOriginalV1,
        originals: Option<&mut super::local_currentness::LocalCurrentnessOriginalsV1>,
    ) {
        self.completion = Some(self.capture_inner(profile, originals, true));
        if !self.status_file_retired && matches!(self.completion, Some(Ok(()))) && self.failure().is_none() {
            // All local/native/currentness comparisons have completed. No
            // later operation borrows this status File; retain its whole open
            // outcome, bytes and checks while disposing only the descriptor.
            if let Some(Ok(file)) = self.status_open.as_mut() {
                drop(file.take());
                self.status_file_retired = true;
            }
        }
    }

    pub(super) fn is_complete(&self) -> bool {
        matches!(self.completion, Some(Ok(())))
    }

    fn capture_inner(
        &mut self,
        profile: &ControllerSelfProfileOriginalV1,
        mut originals: Option<&mut super::local_currentness::LocalCurrentnessOriginalsV1>,
        include_fragment: bool,
    ) -> Result<(), ControllerProfileErrorV1> {
        self.profile = Some(match originals.as_deref_mut() {
            Some(originals) => profile.profile_file.revalidate_retaining(&mut originals.profile),
            None => profile.profile_file.revalidate(),
        });
        positive(&self.profile)?;
        self.images_allocation = Some(self.images.try_reserve_exact(profile.files.len()));
        positive(&self.images_allocation)?;
        if let Some(originals) = originals.as_deref_mut() {
            originals.images_allocation = Some(originals.images.try_reserve_exact(profile.files.len()));
            positive(&originals.images_allocation)?;
        }
        for file in &profile.files {
            let result = match originals.as_deref_mut() {
                Some(originals) => {
                    originals.images.push(
                        crate::immutable_image::ImmutableFileRevalidationOriginalV1::new(),
                    );
                    let original = originals.images.last_mut()
                        .ok_or(ControllerProfileErrorV1::Service)?;
                    file.revalidate_retaining(original)
                }
                None => file.revalidate(),
            };
            self.images.push(result);
            positive_ref(self.images.last())?;
        }
        if let Some(file) = &profile.nix_delivery {
            self.nix = Some(match originals.as_deref_mut() {
                Some(originals) => file.revalidate_retaining(&mut originals.nix),
                None => file.revalidate(),
            });
            positive(&self.nix)?;
        }
        self.policy = Some(match originals.as_deref_mut() {
            Some(originals) => {
                let verified = originals.policy.verify_once(&profile.profile.canonical_policy.path);
                if verified.is_ok() {
                    let observed = originals.policy.verified()
                        .ok_or(ControllerProfileErrorV1::Confinement)?;
                    profile.policy.require_same_observed_v1(observed)
                } else {
                    verified
                }
            }
            None => profile.policy.revalidate(&profile.profile.canonical_policy.path),
        });
        positive(&self.policy)?;
        if let Some(originals) = originals.as_deref_mut() {
            if !originals.policy.retire_completed_files_once_v1() {
                return Err(ControllerProfileErrorV1::Service);
            }
        }
        self.subject = Some(match originals.as_deref_mut() {
            Some(originals) => originals.subject.observe_once(super::delivery::CONTEXT),
            None => require_subject(super::delivery::CONTEXT),
        });
        positive(&self.subject)?;
        if let Some(originals) = originals.as_deref_mut() {
            if !originals.subject.retire_completed_file_once_v1() {
                return Err(ControllerProfileErrorV1::Service);
            }
        }
        self.credentials = Some(if rustix::process::getuid().as_raw() == profile.profile.identities[0]
            && rustix::process::geteuid().as_raw() == profile.profile.identities[0]
            && rustix::process::getgid().as_raw() == profile.profile.identities[1]
            && rustix::process::getegid().as_raw() == profile.profile.identities[1]
        { Ok(()) } else { Err(ControllerProfileErrorV1::Confinement) });
        positive(&self.credentials)?;
        self.status_open = Some(File::open("/proc/self/status").map(Some));
        self.status_read = Some(match self.status_open.as_mut() {
            Some(Ok(Some(file))) => file.take((64 * 1024 + 1) as u64).read_to_end(&mut self.status_bytes),
            _ => return Err(ControllerProfileErrorV1::Service),
        });
        positive(&self.status_read)?;
        self.status = Some(if self.status_bytes.len() <= 64 * 1024 {
            require_status(&self.status_bytes)
        } else { Err(ControllerProfileErrorV1::Service) });
        positive(&self.status)?;
        if originals.is_some() {
            // The bounded read and exact status predicate have completed. No
            // later primitive borrows this File; retain all original results.
            if let Some(Ok(file)) = self.status_open.as_mut() {
                drop(file.take());
                self.status_file_retired = true;
            }
        }
        self.membership = Some(match originals.as_deref_mut() {
            Some(originals) => {
                let captured = originals.membership.capture_once(&profile.cgroup, &profile.process);
                match (captured, originals.membership.result()) {
                    (Ok(()), Some(Ok(info))) => Ok(*info),
                    _ => Err(aos_linux_descriptors::Error::InvalidInput {
                        field: "Controller profile membership",
                        message: "retained membership observation refused".into(),
                    }),
                }
            }
            None => profile.cgroup.verify_exact_membership(&profile.process),
        });
        let member = positive_ref(self.membership.as_ref())?;
        if member.parent_pid() != 1 {
            return Err(ControllerProfileErrorV1::Service);
        }
        if let Some(originals) = originals.as_deref_mut() {
            if !originals.membership.retire_completed_files_once_v1() {
                return Err(ControllerProfileErrorV1::Service);
            }
        }
        self.alive = Some(profile.process.is_alive());
        if !*positive_ref(self.alive.as_ref())? {
            return Err(ControllerProfileErrorV1::Service);
        }
        if include_fragment {
            self.capture_fragment_observed(profile, originals)
        } else {
            Ok(())
        }
    }

    // The external purpose preserves the existing local → PID1 → fragment
    // order. Its owning receiver installs completion only after the fragment.
    pub(super) fn capture_prefix_observed(
        &mut self,
        profile: &ControllerSelfProfileOriginalV1,
        originals: &mut super::local_currentness::LocalCurrentnessOriginalsV1,
    ) -> Result<(), ControllerProfileErrorV1> {
        self.capture_inner(profile, Some(originals), false)
    }

    pub(super) fn capture_fragment_observed(
        &mut self,
        profile: &ControllerSelfProfileOriginalV1,
        originals: Option<&mut super::local_currentness::LocalCurrentnessOriginalsV1>,
    ) -> Result<(), ControllerProfileErrorV1> {
        self.fragment = Some(match originals {
            Some(originals) => profile.fragment.revalidate_retaining(&mut originals.fragment),
            None => profile.fragment.revalidate(),
        });
        positive(&self.fragment)
    }
}

fn positive<T, E>(result: &Option<Result<T, E>>) -> Result<(), ControllerProfileErrorV1> {
    positive_ref(result.as_ref()).map(|_| ())
}

fn positive_ref<T, E>(result: Option<&Result<T, E>>) -> Result<&T, ControllerProfileErrorV1> {
    result.and_then(|result| result.as_ref().ok()).ok_or(ControllerProfileErrorV1::Service)
}

fn retained_error<T, E: std::error::Error + 'static>(
    result: &Option<Result<T, E>>,
) -> Option<&(dyn std::error::Error + 'static)> {
    result.as_ref().and_then(|result| result.as_ref().err())
        .map(|cause| cause as &(dyn std::error::Error + 'static))
}
