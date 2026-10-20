//! Retains fresh positional observations of the six original public credentials.
//!
//! The same metadata, exact/trailing read, and snapshot comparison recipe serves
//! ordinary and retained callers. This owner supplies mechanical custody only;
//! the real Host receiver must pay and retain its original authority first.

use std::borrow::Cow;
use std::error::Error;

use aos_sandbox_linux::credential::FixedRoleCredentialReadV1;

use super::*;

pub(super) struct MetadataOriginalV1 {
    native: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    projected: Option<Result<ProtectedCredentialMetadata, BrokerAuthorityConfigError>>,
}

impl MetadataOriginalV1 {
    fn new() -> Self {
        Self { native: None, projected: None }
    }

    pub(super) fn inspect_once_v1(
        &mut self,
        descriptor: BorrowedFd<'_>,
        name: &'static str,
        maximum: usize,
        uid: u32,
    ) -> Result<ProtectedCredentialMetadata, BrokerAuthorityConfigError> {
        if self.native.is_some() {
            return Err(BrokerAuthorityConfigError::Invalid("credential metadata reentry"));
        }
        self.native = Some(fstat(descriptor));
        let stat = match self.native.as_ref() {
            Some(Ok(stat)) => stat,
            _ => return Err(BrokerAuthorityConfigError::Invalid(name)),
        };
        self.projected = Some(protected_metadata(stat, name, maximum, uid));
        match self.projected.as_ref() {
            Some(Ok(metadata)) => Ok(*metadata),
            _ => Err(BrokerAuthorityConfigError::Invalid(name)),
        }
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        failed(&self.native).or_else(|| failed(&self.projected))
    }
}

pub(super) struct CredentialOriginalV1 {
    pub(super) before: MetadataOriginalV1,
    pub(super) first: FixedRoleCredentialReadV1,
    pub(super) second: FixedRoleCredentialReadV1,
    pub(super) after: MetadataOriginalV1,
    pub(super) comparison: Option<Result<(), BrokerAuthorityConfigError>>,
    returned: Option<Result<(), BrokerAuthorityConfigError>>,
}

impl CredentialOriginalV1 {
    fn new() -> Self {
        Self {
            before: MetadataOriginalV1::new(),
            first: FixedRoleCredentialReadV1::prearmed(),
            second: FixedRoleCredentialReadV1::prearmed(),
            after: MetadataOriginalV1::new(),
            comparison: None,
            returned: None,
        }
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.before.failure()
            .or_else(|| self.first.failure())
            .or_else(|| self.second.failure())
            .or_else(|| self.after.failure())
            .or_else(|| failed(&self.comparison))
            .or_else(|| failed(&self.returned))
    }
}

/// Retains one complete six-descriptor revalidation attempt and its first cause.
///
/// Construction performs no I/O. Successful reads dispose their own duplicate
/// only after exact and trailing reads complete; incomplete duplicates, bytes,
/// metadata results and comparisons remain here through the caller's owed posts.
/// This owner cannot construct credentials or establish Host/launch admission.
#[must_use = "retain actual credential failures through the original launch posts"]
pub struct ProtectedBrokerPublicCredentialRevalidationOriginalV1 {
    credentials: [CredentialOriginalV1; 6],
    returned: Option<Result<(), BrokerAuthorityConfigError>>,
    reentry: Option<BrokerAuthorityConfigError>,
}

impl ProtectedBrokerPublicCredentialRevalidationOriginalV1 {
    /// Creates fixed empty destinations without reading or duplicating a file.
    #[must_use]
    pub fn new() -> Self {
        Self {
            credentials: std::array::from_fn(|_| CredentialOriginalV1::new()),
            returned: None,
            reentry: None,
        }
    }

    /// Bounds this attempt's additional bytes, descriptors and namespace entries.
    ///
    /// The caller separately retains and prices its six original credentials.
    /// Two bounded buffers per role remain resident, including earlier successes.
    /// Only one positional duplicate can be live: a complete read closes it and
    /// the first incomplete read stops this attempt before any later duplicate.
    /// These six existing descriptor borrows create no namespace entries.
    #[must_use]
    pub fn receiving_obligations_v1() -> Option<(usize, usize, usize)> {
        let bytes = ProtectedBrokerPublicCredentialRole::ALL.into_iter()
            .try_fold(0_usize, |bytes, role| {
                bytes.checked_add(role.maximum_bytes().checked_mul(2)?)
            })?;
        let bytes = bytes.checked_add(std::mem::size_of::<Self>().checked_mul(2)?)?;
        Some((bytes, 1, 0))
    }

    fn capture_once_v1(
        &mut self,
        credentials: &ProtectedBrokerPublicCredentials,
    ) -> Result<(), BrokerAuthorityConfigError> {
        self.capture_with_v1(credentials, inspect_protected_descriptor_recipe_v1)
    }

    fn capture_with_v1(
        &mut self,
        credentials: &ProtectedBrokerPublicCredentials,
        inspect: impl Copy + Fn(
            BorrowedFd<'_>, &'static str, usize, Option<&mut MetadataOriginalV1>,
        ) -> Result<ProtectedCredentialMetadata, BrokerAuthorityConfigError>,
    ) -> Result<(), BrokerAuthorityConfigError> {
        if self.returned.is_some() || self.reentry.is_some() {
            self.reentry.get_or_insert(BrokerAuthorityConfigError::Invalid("credential revalidation reentry"));
            return Err(BrokerAuthorityConfigError::Invalid("credential revalidation reentry"));
        }
        self.returned = Some((|| {
            for ((role, credential), original) in ProtectedBrokerPublicCredentialRole::ALL
                .into_iter().zip(&credentials.credentials).zip(&mut self.credentials)
            {
                let returned = credential.revalidate_recipe_v1(
                    role.as_str(), role.maximum_bytes(), inspect, Some(original),
                );
                original.returned = Some(returned);
                if !matches!(original.returned, Some(Ok(()))) {
                    return Err(BrokerAuthorityConfigError::Invalid(role.as_str()));
                }
            }
            Ok(())
        })());
        if matches!(self.returned, Some(Ok(()))) { Ok(()) }
        else { Err(BrokerAuthorityConfigError::Invalid("public credential revalidation")) }
    }

    /// Borrows the first reached native/read/comparison cause without copying it.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.credentials.iter().find_map(CredentialOriginalV1::failure)
            .or_else(|| failed(&self.returned))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }
}

impl Default for ProtectedBrokerPublicCredentialRevalidationOriginalV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtectedBrokerPublicCredentials {
    /// Revalidates the same six original descriptors with retained native custody.
    ///
    /// This is the existing repeated-read/snapshot recipe. No alternate file,
    /// parser, credential, Host authority or financial original is accepted.
    /// The genuine caller must admit the passive receiving obligations first.
    ///
    /// # Errors
    /// Refuses reentry or any original metadata, duplicate, read or snapshot
    /// mismatch. The detailed first cause remains borrowed from `original`.
    pub fn revalidated_descriptor_evidence_retaining_v1(
        &self,
        original: &mut ProtectedBrokerPublicCredentialRevalidationOriginalV1,
    ) -> Result<[(
        ProtectedBrokerPublicCredentialRole,
        BorrowedFd<'_>,
        ProtectedBrokerPublicCredentialSnapshot,
    ); 6], BrokerAuthorityConfigError> {
        original.capture_once_v1(self)?;
        Ok(self.descriptor_evidence_v1())
    }
}

pub(super) fn read_bytes_v1<'read>(
    descriptor: BorrowedFd<'_>,
    name: &'static str,
    length: usize,
    original: Option<&'read mut FixedRoleCredentialReadV1>,
) -> Result<Cow<'read, [u8]>, BrokerAuthorityConfigError> {
    match original {
        // Preserve the ordinary allocation, duplicate, native error projection
        // and duplicate disposal at the original immediate reader return.
        None => read_descriptor_exactly(descriptor, name, length).map(Cow::Owned),
        Some(original) => {
            original.read_exact_at_once(descriptor, length);
            match original.outcome() {
                Some(Ok(Some(bytes))) => Ok(Cow::Borrowed(bytes.as_slice())),
                _ => Err(BrokerAuthorityConfigError::Invalid(name)),
            }
        }
    }
}

fn failed<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn credentials() -> (tempfile::TempDir, ProtectedBrokerPublicCredentials) {
        let directory = tempfile::tempdir().unwrap();
        let credentials = std::array::from_fn(|index| {
            let path = directory.path().join(index.to_string());
            let bytes = [index as u8 + 1; 16];
            std::fs::write(&path, bytes).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let descriptor: OwnedFd = std::fs::File::open(path).unwrap().into();
            let stat = fstat(&descriptor).unwrap();
            ProtectedBrokerPublicCredential {
                descriptor,
                snapshot: ProtectedCredentialSnapshot {
                    metadata: protected_metadata(&stat, "test", MAXIMUM_POLICY_BYTES, stat.st_uid).unwrap(),
                    sha256: Sha256::digest(bytes).into(),
                },
            }
        });
        (directory, ProtectedBrokerPublicCredentials { credentials })
    }

    fn inspect(
        descriptor: BorrowedFd<'_>, name: &'static str, maximum: usize,
        original: Option<&mut MetadataOriginalV1>,
    ) -> Result<ProtectedCredentialMetadata, BrokerAuthorityConfigError> {
        let uid = rustix::process::geteuid().as_raw();
        match original {
            Some(original) => original.inspect_once_v1(descriptor, name, maximum, uid),
            None => protected_metadata(&fstat(descriptor).unwrap(), name, maximum, uid),
        }
    }

    #[test]
    fn completed_six_reads_close_each_duplicate_and_cannot_reenter() {
        let (_directory, credentials) = credentials();
        let mut original = ProtectedBrokerPublicCredentialRevalidationOriginalV1::new();

        original.capture_with_v1(&credentials, inspect).unwrap();

        assert!(original.failure().is_none());
        for credential in &original.credentials {
            for read in [&credential.first, &credential.second] {
                assert!(matches!(read.view().positional_open, Some(Ok(None))));
                assert!(matches!(read.outcome(), Some(Ok(Some(_)))));
            }
        }
        assert!(original.capture_with_v1(&credentials, inspect).is_err());
        assert!(original.failure().is_some());
    }

    #[test]
    fn failed_snapshot_keeps_actual_reads_and_stable_first_cause_before_reentry() {
        let (directory, credentials) = credentials();
        std::fs::write(directory.path().join("2"), [99; 16]).unwrap();
        let mut original = ProtectedBrokerPublicCredentialRevalidationOriginalV1::new();

        assert!(original.capture_with_v1(&credentials, inspect).is_err());
        let first = original.failure().unwrap() as *const dyn Error;

        assert!(original.credentials[0].first.outcome().is_some());
        assert!(original.credentials[2].second.outcome().is_some());
        assert!(original.credentials[3].before.native.is_none());
        assert!(original.capture_with_v1(&credentials, inspect).is_err());
        assert!(std::ptr::eq(first, original.failure().unwrap() as *const dyn Error));
    }

    #[test]
    fn positional_read_error_keeps_real_duplicate_and_raw_cause() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("opath-credential");
        std::fs::write(&path, [7; 16]).unwrap();
        let descriptor = rustix::fs::open(&path,
            OFlags::PATH | OFlags::CLOEXEC, Mode::empty()).unwrap();
        let mut read = FixedRoleCredentialReadV1::prearmed();

        assert!(read_bytes_v1(descriptor.as_fd(), "test", 16, Some(&mut read)).is_err());

        let held = match read.view().positional_open {
            Some(Ok(Some(file))) => file,
            _ => panic!("failed positional read lost its original duplicate"),
        };
        assert_eq!(fstat(held).unwrap().st_ino, fstat(&descriptor).unwrap().st_ino);
        let cause = read.failure().unwrap().downcast_ref::<std::io::Error>().unwrap();
        assert_eq!(cause.raw_os_error(), Some(rustix::io::Errno::BADF.raw_os_error()));
        let first = cause as *const std::io::Error;
        assert!(read_bytes_v1(descriptor.as_fd(), "test", 16, Some(&mut read)).is_err());
        assert!(std::ptr::eq(first,
            read.failure().unwrap().downcast_ref::<std::io::Error>().unwrap()));
        assert!(matches!(read.view().positional_open, Some(Ok(Some(_)))));
    }

}
