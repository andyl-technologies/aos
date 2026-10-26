//! Retains the actual initial jobs' fixed credential files and independent posts.
//!
//! The enclosing original pays before any path or file IO. Read-only credential
//! objects, native errors and zeroizing readbacks stay resident through held and
//! named posts. Matching these files to the profile's public approval key is
//! comparison only: independent-key provenance, delivery configuration, floor
//! codec admission, writer custody and TPM authority remain separate gates.

use std::fs::File;
use std::os::fd::AsFd as _;

use aos_sandbox_linux::credential::FixedRoleCredentialReadV1;
use rustix::fs::{Mode, OFlags, ResolveFlags};
use zeroize::Zeroizing;

use super::*;

mod entries;
mod observation;
mod provisioning_readback;

pub use provisioning_readback::{
    METHOD46_INITIAL_PROVISION_DECODE_BYTES_V1, Method46InitialProvisionReadbackLoanV1,
};

use entries::Entries;
use observation::Observation;

pub(super) const REQUIRED_CREDENTIALS: usize = 7;
pub(super) const NAMES: [&str; 10] = [
    "broker-method46-tpm-provision-v1",
    "broker-method46-tpm-index-auth-v1",
    "method46-initial-approval-public-key-v1",
    "method46-normal-storage-manifest-v1",
    "method46-normal-host-manifest-v1",
    "method46-normal-mount-manifest-v1",
    "method46-normal-network-manifest-v1",
    "method46-normal-mount-fuse-manifest-v1",
    "method46-normal-nix-manifest-v1",
    "method46-normal-controller-nix-floor-issuer-v1",
];
const MANIFEST_BYTES: usize =
    aos_sandbox_broker_session_protocol::manifest::BROKER_SESSION_MANIFEST_BYTES;
const LENGTHS: [usize; NAMES.len()] = [
    160,
    32,
    32,
    MANIFEST_BYTES,
    MANIFEST_BYTES,
    MANIFEST_BYTES,
    MANIFEST_BYTES,
    MANIFEST_BYTES,
    MANIFEST_BYTES,
    48,
];

struct Credential {
    opened: Option<rustix::io::Result<File>>,
    observations: [Observation; 3],
    readers: [FixedRoleCredentialReadV1; 3],
    bytes: [Option<Zeroizing<Vec<u8>>>; 3],
    named: Option<rustix::io::Result<File>>,
    read_entered: bool,
    read_attempted: [bool; 3],
}

impl Credential {
    fn new() -> Self {
        Self {
            opened: None,
            observations: std::array::from_fn(|_| Observation::new()),
            readers: std::array::from_fn(|_| FixedRoleCredentialReadV1::prearmed()),
            bytes: std::array::from_fn(|_| None),
            named: None,
            read_entered: false,
            read_attempted: [false; 3],
        }
    }

    fn read(&mut self, index: usize, length: usize, named: bool) -> bool {
        let Some(attempted) = self.read_attempted.get_mut(index) else {
            return false;
        };
        if std::mem::replace(attempted, true) {
            return false;
        }
        let file = if named { &self.named } else { &self.opened };
        let Some(Ok(file)) = file else {
            return false;
        };
        self.readers[index].read_exact_at_once(file.as_fd(), length);
        self.bytes[index] = self.readers[index]
            .take_success_bytes_once()
            .map(Zeroizing::new);
        self.bytes[index].is_some()
    }
}

pub(super) struct InitialCredentialsOriginalV1 {
    root: Option<rustix::io::Result<File>>,
    root_metadata: Option<std::io::Result<std::fs::Metadata>>,
    path: Option<String>,
    directory: Option<rustix::io::Result<File>>,
    directory_observations: [Observation; 3],
    entries: [Entries; 2],
    named_directory: Option<rustix::io::Result<File>>,
    credentials: [Credential; NAMES.len()],
    selected: [bool; NAMES.len()],
    paid: bool,
    entered: bool,
    completed: bool,
    post_entered: bool,
    decode_loan_issued: bool,
}

impl InitialCredentialsOriginalV1 {
    pub(super) fn admitted_before_post(&self) -> bool {
        self.completed && !self.post_entered
    }

    pub(super) fn new() -> Self {
        Self {
            root: None,
            root_metadata: None,
            path: None,
            directory: None,
            directory_observations: std::array::from_fn(|_| Observation::new()),
            entries: std::array::from_fn(|_| Entries::new()),
            named_directory: None,
            credentials: std::array::from_fn(|_| Credential::new()),
            selected: [false; NAMES.len()],
            paid: false,
            entered: false,
            completed: false,
            post_entered: false,
            decode_loan_issued: false,
        }
    }

    fn capture(
        &mut self,
        profile: &Method46InitialProfileDataV3,
        selected: [bool; NAMES.len()],
    ) -> bool {
        if self.entered || !self.paid {
            return false;
        }
        self.entered = true;
        self.selected = selected;
        self.root = Some(
            rustix::fs::open(
                "/",
                OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map(File::from),
        );
        let Some(Ok(root)) = &self.root else {
            return false;
        };
        self.root_metadata = Some(root.metadata());
        if !matches!(&self.root_metadata, Some(Ok(metadata))
            if root_is_safe(metadata))
        {
            return false;
        }
        self.path = Some(format!("run/credentials/{}", profile.unit));
        let Some(path) = &self.path else {
            return false;
        };
        self.directory = Some(open_directory(root, path));
        let Some(Ok(directory)) = &self.directory else {
            return false;
        };
        let label = credential_label(profile);
        self.directory_observations[0].observe(directory);
        if !self.directory_observations[0].require(label, None)
            || !self.entries[0].observe(directory, &self.selected)
        {
            return false;
        }

        for (index, credential) in self.credentials.iter_mut().enumerate() {
            if !self.selected[index] {
                continue;
            }
            credential.opened = Some(open_credential(directory, NAMES[index]));
            let Some(Ok(file)) = &credential.opened else {
                return false;
            };
            credential.observations[0].observe(file);
            if !credential.observations[0].require(label, Some(LENGTHS[index] as u64))
                || !credential.observations[0].same_mount(&self.directory_observations[0])
            {
                return false;
            }
            credential.read_entered = true;
            if !credential.read(0, LENGTHS[index], false) {
                return false;
            }
        }
        // This is the actual credential readback, not another supplied key.
        // The profile shape already rejected a malformed or weak public pin.
        if self.credentials[2].bytes[0]
            .as_deref()
            .map(|bytes| bytes.as_slice())
            != Some(profile.approval_public_key.as_slice())
            || !self.credentials[1].bytes[0]
                .as_ref()
                .is_some_and(|bytes| bytes.iter().any(|byte| *byte != 0))
        {
            return false;
        }
        self.completed = true;
        true
    }

    pub(super) fn finish_post(&mut self, profile: Option<&Method46InitialProfileDataV3>) -> bool {
        if !self.paid {
            return true;
        }
        if self.post_entered {
            return false;
        }
        self.post_entered = true;
        let Some(profile) = profile else {
            return false;
        };
        let label = credential_label(profile);

        // Named custody cannot suppress observations on already held objects.
        // Every reached file's paid readback runs even if another post refuses.
        let mut held = self.completed;
        if let Some(Ok(directory)) = &self.directory {
            self.directory_observations[1].observe(directory);
            held &= self.directory_observations[1].require(label, None)
                && self.directory_observations[0].same_object(&self.directory_observations[1]);
        }
        for (index, credential) in self.credentials.iter_mut().enumerate() {
            if let Some(Ok(file)) = &credential.opened {
                credential.observations[1].observe(file);
                held &= credential.observations[1].require(label, Some(LENGTHS[index] as u64))
                    && credential.observations[0].same_object(&credential.observations[1]);
            }
            if credential.read_entered {
                let read = credential.read(1, LENGTHS[index], false);
                held &= read && same_bytes(&credential.bytes[0], &credential.bytes[1]);
            }
        }

        let named = self.finish_named(profile);
        held && named
    }

    fn finish_named(&mut self, profile: &Method46InitialProfileDataV3) -> bool {
        let (Some(Ok(root)), Some(path)) = (&self.root, &self.path) else {
            return false;
        };
        self.named_directory = Some(open_directory(root, path));
        let Some(Ok(directory)) = &self.named_directory else {
            return false;
        };
        let label = credential_label(profile);
        self.directory_observations[2].observe(directory);
        let shape = self.directory_observations[2].require(label, None)
            && self.directory_observations[0].same_object(&self.directory_observations[2]);
        let entries = self.entries[1].observe(directory, &self.selected);
        if !shape || !entries {
            return false;
        }

        let mut result = self.completed;
        for (index, credential) in self.credentials.iter_mut().enumerate() {
            if !self.selected[index] {
                continue;
            }
            credential.named = Some(open_credential(directory, NAMES[index]));
            let shape = if let Some(Ok(file)) = &credential.named {
                credential.observations[2].observe(file);
                credential.observations[2].require(label, Some(LENGTHS[index] as u64))
                    && credential.observations[0].same_object(&credential.observations[2])
            } else {
                false
            };
            result &= shape;
            if credential.read_entered {
                // A foreign replacement is retained, but its bytes are not read.
                let read = shape && credential.read(2, LENGTHS[index], true);
                result &= read && same_bytes(&credential.bytes[0], &credential.bytes[2]);
            }
        }
        result
    }
}

fn same_bytes(left: &Option<Zeroizing<Vec<u8>>>, right: &Option<Zeroizing<Vec<u8>>>) -> bool {
    matches!((left, right), (Some(left), Some(right)) if **left == **right)
}

fn credential_label(profile: &Method46InitialProfileDataV3) -> &'static [u8] {
    match profile.unit.as_str() {
        "aos-sandbox-controller-floor-initialize.service" => {
            b"system_u:object_r:aos_method46_controller_initial_credential_t"
        }
        "aos-sandbox-storage-floor-initialize.service" => {
            b"system_u:object_r:aos_method46_storage_initial_credential_t"
        }
        _ => b"", // A foreign profile has already refused before credential IO.
    }
}

fn root_is_safe(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    metadata.is_dir() && metadata.uid() == 0 && metadata.gid() == 0 && metadata.mode() & 0o022 == 0
}

fn open_directory(root: &File, path: &str) -> rustix::io::Result<File> {
    rustix::fs::openat2(
        root,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map(File::from)
}

fn open_credential(directory: &File, name: &str) -> rustix::io::Result<File> {
    rustix::fs::openat2(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map(File::from)
}

impl Method46InitialStartupOriginalV1 {
    /// Captures the fixed manual job's credential files after original unit admission.
    ///
    /// The same Source prepays retained reads, failed duplicates and independent
    /// held/named posts. The exact public approval bytes must match this image
    /// profile. These observations grant no key independence or floor authority.
    ///
    /// # Errors
    /// Retains native refusal and rejects a missing unit, foreign credential
    /// namespace, unsafe files, changed approval pin, zero auth, or reentry.
    pub fn capture_credential_files_once_v1(
        &mut self,
    ) -> Result<(), Method46InitialStartupClosedV1> {
        let ready = self.body.as_ref().is_some_and(|body| {
            body.unit.initial_admitted()
                && body
                    .credentials
                    .try_borrow()
                    .is_ok_and(|credentials| !credentials.entered)
        });
        if !ready {
            return Err(self.fail(First::Order));
        }
        let selected = self
            .body
            .as_ref()
            .ok_or(self.closed)?
            .unit
            .credential_roster()
            .map_err(|_| self.fail(First::Credentials))?;
        // Startup body already includes all inline originals and buffers. This
        // additional finite allowance covers zeroizing bytes, path/native
        // allocations, kernel FD carriers and every initial/owed-post read.
        self.fund_additional(Some(
            ResourceVector::ZERO
                .with(D::MemoryBytes, 1024 * 1024)
                // Root, both directory names and one spare native carrier,
                // plus held/named files and three failed read duplicates.
                .with(D::OpenFiles, 4 + 5 * NAMES.len() as u64)
                .with(D::OutputBytes, 64 * 1024),
        ))?;
        let body = self.body.as_mut().ok_or(self.closed)?;
        let profile = body
            .profile_decoded
            .as_ref()
            .and_then(|value| value.as_ref().ok());
        let original = body.credentials.get_mut();
        original.paid = true;
        let result = profile.is_some_and(|profile| original.capture(profile, selected));
        if !result {
            return Err(self.fail(First::Credentials));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::mem::ManuallyDrop;

    #[test]
    fn credential_capture_requires_the_completed_original_unit_before_io() {
        for role in [
            Method46InitialServiceRoleV1::ControllerStorageClient,
            Method46InitialServiceRoleV1::StorageBroker,
        ] {
            let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(role));

            assert!(startup.capture_credential_files_once_v1().is_err());

            assert!(startup.body.is_none());
            assert_eq!(startup.receiving.get(), ResourceVector::ZERO);
            assert!(matches!(startup.first.get(), Some(First::Order)));
        }
    }

    #[test]
    fn credential_post_refusal_still_attempts_original_source_after() {
        let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(
            Method46InitialServiceRoleV1::StorageBroker,
        ));
        let mut body = StartupRolesOriginalV1::new();
        body.credentials.get_mut().paid = true;
        startup.body = Some(Box::new(body));

        assert!(startup.finish_source_after_owed_once_v1(Ok(())).is_err());

        assert!(startup.after_attempted.get());
        assert!(matches!(startup.after_result.get(), Some(Err(_))));
        assert!(
            startup
                .body
                .as_ref()
                .unwrap()
                .credentials
                .borrow()
                .post_entered
        );
        assert!(matches!(startup.first.get(), Some(First::Credentials)));
    }

    #[test]
    fn busy_credential_post_cannot_suppress_original_source_after() {
        let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(
            Method46InitialServiceRoleV1::ControllerStorageClient,
        ));
        startup.body = Some(Box::new(StartupRolesOriginalV1::new()));
        let held = startup.body.as_ref().unwrap().credentials.borrow_mut();

        assert!(startup.finish_source_after_owed_once_v1(Ok(())).is_err());

        assert!(startup.after_attempted.get());
        assert!(matches!(startup.after_result.get(), Some(Err(_))));
        assert!(matches!(startup.first.get(), Some(First::Order)));
        drop(held);
    }

    #[test]
    fn successful_later_read_cannot_replace_the_native_failed_prefix() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&[7; 31]).unwrap();
        let mut credential = Credential::new();
        credential.opened = Some(Ok(file));

        assert!(!credential.read(0, 32, false));
        assert!(credential.readers[0].view().exact.unwrap().is_err());
        assert!(matches!(
            credential.readers[0].view().positional_open,
            Some(Ok(Some(_)))
        ));
        credential
            .opened
            .as_mut()
            .unwrap()
            .as_mut()
            .unwrap()
            .write_all(&[7])
            .unwrap();
        assert!(credential.read(1, 32, false));

        assert!(credential.readers[0].view().exact.unwrap().is_err());
        assert!(matches!(
            credential.readers[0].view().positional_open,
            Some(Ok(Some(_)))
        ));
        assert!(credential.bytes[0].is_none());
        assert!(!same_bytes(&credential.bytes[0], &credential.bytes[1]));
    }

    #[test]
    fn positional_credential_read_keeps_original_bytes_on_reentry() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&[7; 32]).unwrap();
        let mut credential = Credential::new();
        credential.opened = Some(Ok(file));

        assert!(credential.read(0, 32, false));
        assert!(!credential.read(0, 32, false));

        assert_eq!(&**credential.bytes[0].as_ref().unwrap(), &[7; 32]);
        assert!(
            credential
                .opened
                .as_ref()
                .unwrap()
                .as_ref()
                .unwrap()
                .metadata()
                .is_ok()
        );
    }
}
