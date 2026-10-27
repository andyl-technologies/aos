//! Retains the native prefix of the existing public TLS credential recheck.
//!
//! The credential owner supplies its actual path, UID, directory identity and
//! four digests. This destination owns no payer or authorization constructor.
//! The selected caller admits its measured recipe before allocating ancestry.

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use super::*;

/// Owns one credential comparison and every failed native prefix.
///
/// A successful complete digest comparison disposes its scratch immediately.
/// Failure and repeated entry retain every reached file, byte buffer and cause.
pub struct PublicApiCredentialRecheckV1 {
    // Buffers are destroyed before their files; ancestry is last, as in the
    // ordinary reader. Keeping this order also covers partial native failure.
    files: [CredentialReadSlot; 4],
    ancestors: Vec<CredentialDirectorySlot>,
    count: usize,
    result: Option<CredentialResult<()>>,
    repeated: bool,
}

impl PublicApiCredentialRecheckV1 {
    /// Creates vacant slots without allocating, reading or establishing trust.
    #[must_use]
    pub fn new() -> Self {
        Self {
            files: std::array::from_fn(|_| CredentialReadSlot::new()),
            ancestors: Vec::new(),
            count: 0,
            result: None,
            repeated: false,
        }
    }

    /// Borrows the original native cause before any repeated-entry refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.result.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.repeated.then_some(&PublicApiSessionError::Stale as _))
    }
}

impl Credentials {
    /// Measures the actual held path and bounded four-file recheck recipe.
    ///
    /// This is DATA, not admission. The genuine operation owner must pay it
    /// before `recheck_retaining_v1` allocates or performs native IO.
    #[must_use]
    pub fn recheck_receiving_demand_v1(&self) -> Option<ResourceVector> {
        let directories = self.path.components().filter(|part| matches!(part, Component::Normal(_))).count().checked_add(1)?;
        let ancestry = directories.checked_mul(std::mem::size_of::<CredentialDirectorySlot>())?;
        // Each bounded read may retain its old allocation while growing to the
        // next capacity. Three requested ceilings dominate that overlap; these
        // are byte buffers, not guessed complete semantic models per byte.
        let buffers = usize::try_from(MAXIMUM_CREDENTIAL_BYTES).ok()?.checked_add(1)?
            .checked_mul(4)?.checked_mul(3)?;
        let memory = std::mem::size_of::<PublicApiCredentialRecheckV1>().checked_mul(2)?
            .checked_add(ancestry.checked_mul(2)?)?
            .checked_add(buffers)?.checked_add(4 * 256)?;
        let names = directories.checked_add(NAMES.len())?;
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).ok()?)
            .with(D::OpenFiles, u64::try_from(names).ok()?)
            .with(D::MetadataEntries, u64::try_from(names).ok()?))
    }

    /// Runs the same UID, traversal, read and digest engine into a paid sink.
    ///
    /// # Errors
    /// Returns the unchanged legacy class while the destination retains the
    /// actual IO cause and all reached files/partial bytes. Refuses reentry.
    pub fn recheck_retaining_v1(
        &self,
        destination: &mut PublicApiCredentialRecheckV1,
    ) -> Result<(), PublicApiSessionError> {
        if destination.result.is_some() || destination.repeated {
            destination.repeated = true;
            return Err(PublicApiSessionError::Stale);
        }
        let directories = self.path.components().filter(|part| matches!(part, Component::Normal(_))).count().checked_add(1)
            .ok_or(PublicApiSessionError::Configuration)?;
        destination.ancestors = (0..directories).map(|_| CredentialDirectorySlot {
            descriptor: None,
            identity: None,
        }).collect();
        let result = self.recheck_inner(&mut RecheckCustody::Retained(destination));
        destination.result = Some(result);
        let result = destination.result.as_ref().ok_or(PublicApiSessionError::Stale)?;
        if let Err(cause) = result {
            return Err(cause.legacy_projection());
        }
        // This frontier is complete on its own: every exact named input was
        // compared with the held TLS digests. Later certificate/registry work
        // cannot need these successful native scratch owners again.
        destination.files = std::array::from_fn(|_| CredentialReadSlot::new());
        destination.ancestors = Vec::new();
        Ok(())
    }
}

pub(super) enum RecheckCustody<'owner> {
    Ordinary {
        bytes: Option<[Zeroizing<Vec<u8>>; 4]>,
        directory: Option<OwnedFd>,
    },
    Retained(&'owner mut PublicApiCredentialRecheckV1),
}

impl RecheckCustody<'_> {
    pub(super) fn ordinary() -> Self {
        Self::Ordinary { bytes: None, directory: None }
    }

    pub(super) fn open(&mut self, path: &Path, uid: u32) -> CredentialResult<()> {
        match self {
            Self::Ordinary { directory, .. } => {
                let mut custody = DirectoryCustody::Local(None);
                open_directory_with_custody(path, uid, &mut custody)?;
                if let DirectoryCustody::Local(original) = custody {
                    *directory = original;
                }
                Ok(())
            }
            Self::Retained(destination) => open_directory_with_custody(path, uid,
                &mut DirectoryCustody::Borrowed {
                    slots: &mut destination.ancestors,
                    count: &mut destination.count,
                }),
        }
    }

    pub(super) fn directory(&self) -> CredentialResult<&OwnedFd> {
        match self {
            Self::Ordinary { directory, .. } => directory.as_ref()
                .ok_or_else(credential_state_rejected),
            Self::Retained(destination) => destination.ancestors
                .get(destination.count.wrapping_sub(1))
                .and_then(|slot| slot.descriptor.as_ref())
                .ok_or_else(credential_state_rejected),
        }
    }

    pub(super) fn read_all(&mut self, uid: u32) -> CredentialResult<()> {
        match self {
            Self::Ordinary { bytes, directory } => {
                let directory = directory.as_ref().ok_or_else(credential_state_rejected)?;
                // Preserve the ordinary array's original evaluation and drop
                // boundaries. Each file is consumed by its existing adapter.
                *bytes = Some([
                    read_one_with_identity_raw(directory, NAMES[0], uid)?,
                    read_one_with_identity_raw(directory, NAMES[1], uid)?,
                    read_one_with_identity_raw(directory, NAMES[2], uid)?,
                    read_one_with_identity_raw(directory, NAMES[3], uid)?,
                ]);
                Ok(())
            }
            Self::Retained(destination) => {
                let directory = destination.ancestors.get(destination.count.wrapping_sub(1))
                    .and_then(|slot| slot.descriptor.as_ref())
                    .ok_or_else(credential_state_rejected)?;
                for (name, slot) in NAMES.iter().zip(&mut destination.files) {
                    require_present_credential(open_read_credential(
                        directory, name, uid, MAXIMUM_CREDENTIAL_BYTES, slot,
                    )?)?;
                }
                Ok(())
            }
        }
    }

    pub(super) fn bytes(&self, index: usize) -> CredentialResult<&[u8]> {
        match self {
            Self::Ordinary { bytes, .. } => bytes.as_ref().and_then(|bytes| bytes.get(index))
                .map(|bytes| bytes.as_slice()).ok_or_else(credential_state_rejected),
            Self::Retained(destination) => destination.files.get(index)
                .and_then(|slot| slot.bytes.as_ref())
                .map(|bytes| bytes.as_slice()).ok_or_else(credential_state_rejected),
        }
    }
}

// The ordinary projection still destroys this one file at the old file-local
// boundary. The selected route above lends the same engine its resident slot.
fn read_one_with_identity_raw(directory: &OwnedFd, name: &str, uid: u32)
    -> CredentialResult<Zeroizing<Vec<u8>>>
{
    let mut slot = CredentialReadSlot::new();
    require_present_credential(open_read_credential(
        directory, name, uid, MAXIMUM_CREDENTIAL_BYTES, &mut slot,
    )?)?;
    slot.bytes.take().ok_or_else(credential_state_rejected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::PermissionsExt as _;

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "aos-public-credential-prefix-{}-{}", std::process::id(),
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                    .unwrap().as_nanos(),
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn write(&self, name: &str, mode: u32) {
            let path = self.0.join(name);
            std::fs::write(&path, b"actual credential input").unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
    }

    #[test]
    fn failed_second_file_preserves_first_input_and_both_actual_files() {
        let fixture = Fixture::new();
        fixture.write(NAMES[0], 0o600);
        fixture.write(NAMES[1], 0o644);
        let directory = File::open(&fixture.0).unwrap();
        let mut retained = PublicApiCredentialRecheckV1::new();
        retained.ancestors.push(CredentialDirectorySlot {
            descriptor: Some(directory.into()), identity: None,
        });
        retained.count = 1;
        let uid = rustix::process::geteuid().as_raw();

        let result = RecheckCustody::Retained(&mut retained).read_all(uid);
        assert!(result.is_err());
        retained.result = Some(result);
        let file = retained.files[0].file.as_ref().unwrap().as_raw_fd();

        assert_eq!(retained.files[0].bytes.as_ref().unwrap().as_slice(), b"actual credential input");
        assert!(retained.files[1].file.is_some());
        assert!(retained.files[1].bytes.is_none());
        assert!(retained.files[2].file.is_none());
        assert_eq!(retained.failure().unwrap().to_string(),
            "Controller public credential custody failed (FileProvenance)");

        let credentials = Credentials {
            path: fixture.0.clone(), uid, directory_identity: (0, 0), digests: [[0; 32]; 4],
        };
        assert!(credentials.recheck_retaining_v1(&mut retained).is_err());
        assert_eq!(retained.files[0].file.as_ref().unwrap().as_raw_fd(), file);
        assert_eq!(retained.failure().unwrap().to_string(),
            "Controller public credential custody failed (FileProvenance)");
    }

    #[test]
    fn ordinary_and_retained_leaf_reader_keep_the_same_bytes_and_refusal_class() {
        let fixture = Fixture::new();
        fixture.write(NAMES[0], 0o600);
        fixture.write(NAMES[1], 0o644);
        let directory: OwnedFd = File::open(&fixture.0).unwrap().into();
        let uid = rustix::process::geteuid().as_raw();

        let bytes = read_one(&directory, NAMES[0], uid).unwrap();
        let ordinary = read_one(&directory, NAMES[1], uid).unwrap_err();
        let mut selected = CredentialReadSlot::new();
        let observed = open_read_credential(&directory, NAMES[0], uid,
            MAXIMUM_CREDENTIAL_BYTES, &mut selected).unwrap();
        require_present_credential(observed).unwrap();
        let mut rejected = CredentialReadSlot::new();
        let retained = match open_read_credential(&directory, NAMES[1], uid,
            MAXIMUM_CREDENTIAL_BYTES, &mut rejected)
        {
            Err(cause) => cause,
            Ok(_) => panic!("unsafe credential unexpectedly accepted"),
        };

        assert_eq!(bytes.as_slice(), selected.bytes.as_ref().unwrap().as_slice());
        assert_eq!(ordinary.to_string(), retained.legacy_projection().to_string());
        assert!(rejected.file.is_some());
        assert!(rejected.bytes.is_none());
    }
}
