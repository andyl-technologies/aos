//! Fixed owner/helper SID observation for required-mode physical TPM custody.
//!
//! These checks do not authenticate a compiled policy or freeze PID 1 policy.
//! They refuse an init-domain alias, permissive kernel, or substituted procfs
//! observation before credentials cross the private carrier. Installed policy,
//! original launch identity and service crash quiescence remain separate gates.

use std::fs::File;
use std::io::Read as _;

use rustix::fs::{Mode, OFlags, fstatfs, open};

use super::super::FloorErrorV1;
use super::super::provisioning::CredentialReadCustodyV1;
use super::super::format::FloorEndpointV1;

const SELINUXFS_MAGIC: u64 = 0xf97c_ff8c;
const PROCFS_MAGIC: u64 = 0x9fa0;

pub(in crate::recovery::journal::tpm_floor) const fn owner_context(
    endpoint: FloorEndpointV1,
) -> &'static str {
    match endpoint {
        FloorEndpointV1::ControllerStorageClient => "system_u:system_r:aos_sandbox_controller_t",
        FloorEndpointV1::StorageBroker => "system_u:system_r:aos_sandbox_storage_t",
    }
}

pub(super) const fn helper_context(endpoint: FloorEndpointV1) -> &'static str {
    match endpoint {
        FloorEndpointV1::ControllerStorageClient => {
            "system_u:system_r:aos_method46_controller_helper_t"
        }
        FloorEndpointV1::StorageBroker => "system_u:system_r:aos_method46_storage_helper_t",
    }
}

pub(crate) fn require_owner(
    endpoint: FloorEndpointV1,
) -> Result<(), FloorErrorV1> {
    OwnerConfinementOriginalV1::new().capture_once(endpoint, CredentialReadCustodyV1::Ordinary)
}

pub(crate) fn require_helper(endpoint: FloorEndpointV1, pid: u32) -> Result<(), FloorErrorV1> {
    require_helper_preamble(endpoint, pid)?;
    require_context(
        &format!("/proc/{pid}/attr/current"),
        helper_context(endpoint),
    )
}

pub(super) fn require_helper_preamble(endpoint: FloorEndpointV1, pid: u32) -> Result<(), FloorErrorV1> {
    require_owner(endpoint)?;
    if pid == 0 || pid == std::process::id() {
        return Err(FloorErrorV1::Provisioning);
    }
    Ok(())
}

pub(super) fn require_observed_helper_context(
    endpoint: FloorEndpointV1,
    bytes: &[u8],
) -> Result<(), FloorErrorV1> {
    if bytes.len() > 256 || !context_matches(bytes, helper_context(endpoint).as_bytes()) {
        return Err(FloorErrorV1::Provisioning);
    }
    Ok(())
}

fn require_context(path: &str, expected: &str) -> Result<(), FloorErrorV1> {
    let observed = read_bounded(path, PROCFS_MAGIC, 256)?;
    if !context_matches(&observed, expected.as_bytes()) {
        return Err(FloorErrorV1::Provisioning);
    }
    Ok(())
}

fn context_matches(observed: &[u8], expected: &[u8]) -> bool {
    let observed = observed
        .strip_suffix(b"\n")
        .or_else(|| observed.strip_suffix(b"\0"))
        .unwrap_or(observed);
    !expected.is_empty() && observed == expected
}

fn read_bounded(path: &str, magic: u64, maximum: u64) -> Result<Vec<u8>, FloorErrorV1> {
    let mut original = ConfinementReadOriginalV1::new();
    original.capture_once(path, magic, maximum, CredentialReadCustodyV1::Ordinary)?;
    Ok(std::mem::take(&mut original.bytes))
}

/// Keeps the two original owner observations and their exact typed comparisons.
pub(crate) struct OwnerConfinementOriginalV1 {
    enforcement: ConfinementReadOriginalV1,
    enforcement_binding: Option<Result<(), FloorErrorV1>>,
    context: ConfinementReadOriginalV1,
    context_binding: Option<Result<(), FloorErrorV1>>,
    result: Option<Result<(), FloorErrorV1>>,
}

impl OwnerConfinementOriginalV1 {
    /// Captures only the fixed Controller owner through the same bounded reads.
    ///
    /// # Errors
    /// Retains native read, wrong filesystem/context, permissive policy or reentry.
    pub(crate) fn capture_controller_once_v1(&mut self) -> Result<(), FloorErrorV1> {
        self.capture_retained_endpoint_once_v2(FloorEndpointV1::ControllerStorageClient)
    }

    pub(crate) fn capture_floor_owner_once_v2(&mut self, profile: super::super::FloorProfileV1)
        -> Result<(), FloorErrorV1>
    {
        self.capture_retained_endpoint_once_v2(profile.endpoint())
    }

    fn capture_retained_endpoint_once_v2(&mut self, endpoint: FloorEndpointV1)
        -> Result<(), FloorErrorV1>
    {
        self.capture_once(endpoint, CredentialReadCustodyV1::Retained)
    }

    /// Bounds the actual two file/read destinations and bounded byte growth.
    pub(crate) fn receiving_demand_v1() -> Option<aos_sandbox_core::ResourceVector> {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
        let memory = std::mem::size_of::<Self>().checked_mul(2)?.checked_add(4 * 258)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(memory).ok()?)
            // Each completed retained leaf retires before the next one opens.
            .with(D::OpenFiles, 1))
    }

    pub(crate) fn new() -> Self {
        Self {
            enforcement: ConfinementReadOriginalV1::new(),
            enforcement_binding: None,
            context: ConfinementReadOriginalV1::new(),
            context_binding: None,
            result: None,
        }
    }

    pub(in crate::recovery::journal) fn capture_once(
        &mut self,
        endpoint: FloorEndpointV1,
        custody: CredentialReadCustodyV1,
    ) -> Result<(), FloorErrorV1> {
        if self.result.is_some() {
            return Err(FloorErrorV1::Unavailable);
        }
        self.result = Some(self.capture(endpoint, custody));
        match self.result {
            Some(Ok(())) => Ok(()),
            Some(Err(error)) => Err(error),
            None => Err(FloorErrorV1::Unavailable),
        }
    }

    fn capture(
        &mut self,
        endpoint: FloorEndpointV1,
        custody: CredentialReadCustodyV1,
    ) -> Result<(), FloorErrorV1> {
        self.enforcement.capture_once(
            "/sys/fs/selinux/enforce",
            SELINUXFS_MAGIC,
            2,
            custody,
        )?;
        self.enforcement_binding = Some(require(
            self.enforcement.bytes == b"1" || self.enforcement.bytes == b"1\n",
        ));
        completed(&self.enforcement_binding)?;
        if matches!(custody, CredentialReadCustodyV1::Retained)
            && !self.enforcement.retire_completed_reader_once()
        {
            return Err(FloorErrorV1::Unavailable);
        }

        self.context.capture_once(
            "/proc/self/attr/current",
            PROCFS_MAGIC,
            256,
            custody,
        )?;
        self.context_binding = Some(require(context_matches(
            &self.context.bytes,
            owner_context(endpoint).as_bytes(),
        )));
        completed(&self.context_binding)?;
        if matches!(custody, CredentialReadCustodyV1::Retained)
            && !self.context.retire_completed_reader_once()
        {
            return Err(FloorErrorV1::Unavailable);
        }
        Ok(())
    }

    pub(crate) fn failure(
        &self,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        self.enforcement.failure()
            .or_else(|| failure(&self.enforcement_binding))
            .or_else(|| self.context.failure())
            .or_else(|| failure(&self.context_binding))
            .or_else(|| failure(&self.result))
    }
}

struct ConfinementReadOriginalV1 {
    open: Option<Result<rustix::fd::OwnedFd, rustix::io::Errno>>,
    filesystem: Option<Result<rustix::fs::StatFs, rustix::io::Errno>>,
    filesystem_binding: Option<Result<(), FloorErrorV1>>,
    reader: Option<std::io::Take<File>>,
    bytes: Vec<u8>,
    read: Option<std::io::Result<usize>>,
    length: Option<Result<(), FloorErrorV1>>,
    entered: bool,
}

impl ConfinementReadOriginalV1 {
    fn new() -> Self {
        Self {
            open: None,
            filesystem: None,
            filesystem_binding: None,
            reader: None,
            bytes: Vec::new(),
            read: None,
            length: None,
            entered: false,
        }
    }

    fn capture_once(
        &mut self,
        path: &str,
        magic: u64,
        maximum: u64,
        custody: CredentialReadCustodyV1,
    ) -> Result<(), FloorErrorV1> {
        if self.entered {
            return Err(FloorErrorV1::Unavailable);
        }
        self.entered = true;
        self.open = Some(open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        ));
        let descriptor = match &self.open {
            Some(Ok(descriptor)) => descriptor,
            _ => return Err(FloorErrorV1::Unavailable),
        };
        self.filesystem = Some(fstatfs(descriptor));
        let filesystem = match &self.filesystem {
            Some(Ok(filesystem)) => filesystem,
            _ => return Err(FloorErrorV1::Unavailable),
        };
        self.filesystem_binding = Some(require(filesystem.f_type as u64 == magic));
        completed(&self.filesystem_binding)?;

        let descriptor = match self.open.take() {
            Some(Ok(descriptor)) => descriptor,
            original => {
                self.open = original;
                return Err(FloorErrorV1::Unavailable);
            }
        };
        self.reader = Some(File::from(descriptor).take(maximum + 1));
        let reader = self.reader.as_mut().ok_or(FloorErrorV1::Unavailable)?;
        self.read = Some(reader.read_to_end(&mut self.bytes));
        if matches!(custody, CredentialReadCustodyV1::Ordinary) {
            // The original Take<File> expression ended at this exact read,
            // before classifying read failure or the admitted byte count.
            drop(self.reader.take());
        }
        match self.read {
            Some(Ok(_)) => {}
            _ => return Err(FloorErrorV1::Unavailable),
        }
        self.length = Some(require(self.bytes.len() as u64 <= maximum));
        completed(&self.length)
    }

    // The caller has completed the exact enforcement/context binding. This
    // bounded reader is not a later identity anchor. Preserve all bytes/native
    // Results, and never close a failed read, length or filesystem prefix.
    fn retire_completed_reader_once(&mut self) -> bool {
        if !self.entered || self.failure().is_some()
            || !matches!(self.read, Some(Ok(_))) || !matches!(self.length, Some(Ok(())))
            || self.reader.is_none()
        {
            return false;
        }
        drop(self.reader.take());
        true
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        failure(&self.open)
            .or_else(|| failure(&self.filesystem))
            .or_else(|| failure(&self.filesystem_binding))
            .or_else(|| failure(&self.read))
            .or_else(|| failure(&self.length))
    }
}

fn require(condition: bool) -> Result<(), FloorErrorV1> {
    if condition {
        Ok(())
    } else {
        Err(FloorErrorV1::Provisioning)
    }
}

fn completed(slot: &Option<Result<(), FloorErrorV1>>) -> Result<(), FloorErrorV1> {
    match slot {
        Some(Ok(())) => Ok(()),
        Some(Err(error)) => Err(*error),
        None => Err(FloorErrorV1::Unavailable),
    }
}

fn failure<T, E: std::error::Error + 'static>(
    slot: &Option<Result<T, E>>,
) -> Option<&(dyn std::error::Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err())
        .map(|error| error as &dyn std::error::Error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tpm_floor_confinement_context_is_exact_and_role_separated() {
        for endpoint in [
            FloorEndpointV1::ControllerStorageClient,
            FloorEndpointV1::StorageBroker,
        ] {
            let expected = owner_context(endpoint).as_bytes();
            assert!(context_matches(expected, expected));
            assert!(context_matches(&[expected, b"\n"].concat(), expected));
            for invalid in [
                b"system_u:system_r:init_t".as_slice(),
                helper_context(endpoint).as_bytes(),
                b"",
                b"\0",
                b"system_u:system_r:aos_sandbox_controller_t:s0",
            ] {
                assert!(!context_matches(invalid, expected));
            }
            assert!(!context_matches(&[expected, b"\0\n"].concat(), expected));
        }
        assert_ne!(
            owner_context(FloorEndpointV1::ControllerStorageClient),
            owner_context(FloorEndpointV1::StorageBroker)
        );
    }

    #[test]
    fn retained_helper_context_uses_the_same_exact_matcher_and_bound() {
        for endpoint in [FloorEndpointV1::ControllerStorageClient, FloorEndpointV1::StorageBroker] {
            let expected = helper_context(endpoint).as_bytes();
            for observed in [expected.to_vec(), [expected, b"\n"].concat(), [expected, b"\0"].concat()] {
                assert!(require_observed_helper_context(endpoint, &observed).is_ok());
            }
            for observed in [Vec::new(), vec![b'x'; 257], [expected, b"\0\n"].concat()] {
                assert_eq!(
                    require_observed_helper_context(endpoint, &observed),
                    Err(FloorErrorV1::Provisioning),
                );
            }
            assert!(require_observed_helper_context(endpoint, owner_context(endpoint).as_bytes()).is_err());
        }
    }
}

#[cfg(test)]
mod retained_read_tests {
    use super::*;

    #[test]
    fn complete_positive_leaf_disposes_only_its_temporary_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("enforcement-probe");
        std::fs::write(&path, b"1").unwrap();
        let file = File::open(&path).unwrap();
        let magic = fstatfs(&file).unwrap().f_type as u64;
        drop(file);
        let mut original = ConfinementReadOriginalV1::new();
        original.capture_once(path.to_str().unwrap(), magic, 2, CredentialReadCustodyV1::Retained).unwrap();
        let binding = require(original.bytes == b"1");
        assert!(binding.is_ok());

        assert!(original.retire_completed_reader_once());

        assert!(original.reader.is_none());
        assert_eq!(original.bytes, b"1");
        assert!(matches!(original.read, Some(Ok(1))));
        assert!(matches!(original.length, Some(Ok(()))));
        assert!(original.failure().is_none());
        assert!(!original.retire_completed_reader_once());
    }

    #[test]
    fn reached_overlimit_read_retains_selected_file_and_preserves_ordinary_close() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("bounded-observation");
        std::fs::write(&path, b"12345").unwrap();
        let file = File::open(&path).unwrap();
        let magic = fstatfs(&file).unwrap().f_type as u64;
        drop(file);
        let path = path.to_str().unwrap();
        let mut selected = ConfinementReadOriginalV1::new();

        assert!(selected.capture_once(path, magic, 2, CredentialReadCustodyV1::Retained).is_err());
        assert_eq!(selected.bytes, b"123");
        assert!(!selected.retire_completed_reader_once());
        assert!(selected.reader.is_some());
        assert!(matches!(selected.read, Some(Ok(3))));
        let length = selected.length.as_ref().unwrap().as_ref().unwrap_err();
        let length_pointer = length as *const FloorErrorV1;
        assert!(std::ptr::eq(
            selected.failure().unwrap().downcast_ref::<FloorErrorV1>().unwrap(),
            length_pointer,
        ));

        let mut ordinary = ConfinementReadOriginalV1::new();
        assert!(ordinary.capture_once(path, magic, 2, CredentialReadCustodyV1::Ordinary).is_err());
        assert_eq!(ordinary.bytes, selected.bytes);
        assert!(ordinary.reader.is_none());
        assert!(matches!(ordinary.read, Some(Ok(3))));

        std::fs::write(path, b"0").unwrap();
        assert!(matches!(
            selected.capture_once(path, magic, 2, CredentialReadCustodyV1::Retained),
            Err(FloorErrorV1::Unavailable),
        ));
        assert_eq!(selected.bytes, b"123");
        assert!(!selected.retire_completed_reader_once());
        assert!(selected.reader.is_some());
        assert!(std::ptr::eq(
            selected.failure().unwrap().downcast_ref::<FloorErrorV1>().unwrap(),
            length_pointer,
        ));
    }
}
