//! Retains the actual fixed Storage configuration acquisition and materialization.
//!
//! Storage has already joined its genuine original's authority-directory argument
//! and admitted the complete configuration demand before entry. These destinations
//! grant no funding, key authority, path replacement or alternate Broker domain.

use std::error::Error;

use aos_sandbox_linux::credential::FixedRoleCredentialReadV1;

use super::materialization::{ConfigurationInputsV1, ConfigurationMaterializationV1};
use super::*;

pub(super) struct ConfigurationCredentialOriginalV1 {
    pub(super) opened: Option<Result<Option<OwnedFd>, rustix::io::Errno>>,
    initial_stat: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    initial: Option<Result<ProtectedCredentialMetadata, BrokerAuthorityConfigError>>,
    length: Option<Result<(), BrokerAuthorityConfigError>>,
    first: FixedRoleCredentialReadV1,
    second: FixedRoleCredentialReadV1,
    pub(super) bytes: Option<Zeroizing<Vec<u8>>>,
    repeated: Option<Zeroizing<Vec<u8>>>,
    final_stat: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    final_metadata: Option<Result<ProtectedCredentialMetadata, BrokerAuthorityConfigError>>,
    pub(super) comparison: Option<Result<Option<ProtectedCredentialSnapshot>, BrokerAuthorityConfigError>>,
}

impl ConfigurationCredentialOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            opened: None,
            initial_stat: None,
            initial: None,
            length: None,
            first: FixedRoleCredentialReadV1::prearmed(),
            second: FixedRoleCredentialReadV1::prearmed(),
            bytes: None,
            repeated: None,
            final_stat: None,
            final_metadata: None,
            comparison: None,
        }
    }

    fn capture_once(
        &mut self,
        directory: &OwnedFd,
        name: &'static str,
        maximum: usize,
        exact: Option<usize>,
        uid: u32,
    ) -> Result<(), BrokerAuthorityConfigError> {
        if self.opened.is_some() {
            return Err(BrokerAuthorityConfigError::Invalid("credential reentry"));
        }
        self.opened = Some(openat(
            directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        ).map(Some));
        self.read_donated_once_v2(name, maximum, exact, uid)
    }

    pub(super) fn read_donated_once_v2(
        &mut self, name: &'static str, maximum: usize, exact: Option<usize>, uid: u32,
    ) -> Result<(), BrokerAuthorityConfigError> {
        let file = match self.opened.as_ref() {
            Some(Ok(Some(file))) => file,
            _ => return Err(BrokerAuthorityConfigError::Invalid(name)),
        };

        self.initial_stat = Some(fstat(file));
        let stat = match self.initial_stat.as_ref() {
            Some(Ok(stat)) => stat,
            _ => return Err(BrokerAuthorityConfigError::Invalid(name)),
        };
        self.initial = Some(protected_metadata(stat, name, maximum, uid));
        let initial = match self.initial.as_ref() {
            Some(Ok(initial)) => *initial,
            _ => return Err(BrokerAuthorityConfigError::Invalid(name)),
        };
        if let Some(exact) = exact {
            self.length = Some(if initial.bytes == exact {
                Ok(())
            } else {
                Err(BrokerAuthorityConfigError::Invalid(name))
            });
            if !matches!(self.length, Some(Ok(()))) {
                return Err(BrokerAuthorityConfigError::Invalid(name));
            }
        }

        // Ordinary Broker allocates, duplicates, preads, checks trailing data
        // then closes that successful duplicate, twice. The shared lower reader
        // keeps only an incomplete duplicate; successful disposal is actual.
        self.first.read_exact_at_once(file.as_fd(), initial.bytes);
        self.bytes = self.first.take_success_bytes_once().map(Zeroizing::new);
        if self.bytes.is_none() {
            return Err(BrokerAuthorityConfigError::Invalid(name));
        }
        self.second.read_exact_at_once(file.as_fd(), initial.bytes);
        self.repeated = self.second.take_success_bytes_once().map(Zeroizing::new);
        if self.repeated.is_none() {
            return Err(BrokerAuthorityConfigError::Invalid(name));
        }

        self.final_stat = Some(fstat(file));
        let stat = match self.final_stat.as_ref() {
            Some(Ok(stat)) => stat,
            _ => return Err(BrokerAuthorityConfigError::Invalid(name)),
        };
        self.final_metadata = Some(protected_metadata(stat, name, maximum, uid));
        let after = match self.final_metadata.as_ref() {
            Some(Ok(after)) => *after,
            _ => return Err(BrokerAuthorityConfigError::Invalid(name)),
        };
        let bytes = self.bytes.as_ref()
            .ok_or(BrokerAuthorityConfigError::Invalid(name))?;
        let repeated = self.repeated.as_ref()
            .ok_or(BrokerAuthorityConfigError::Invalid(name))?;
        self.comparison = Some((|| {
            if bytes != repeated || initial != after {
                return Err(BrokerAuthorityConfigError::Invalid(name));
            }
            if name == JOURNAL_MAC_KEY_FILE {
                return Ok(None);
            }
            let snapshot = ProtectedCredentialSnapshot {
                metadata: initial,
                sha256: Sha256::digest(bytes.as_slice()).into(),
            };
            let observed = ProtectedCredentialSnapshot {
                metadata: after,
                sha256: Sha256::digest(bytes.as_slice()).into(),
            };
            if !retained_snapshot_matches(&snapshot, &observed, &after, bytes, repeated) {
                return Err(BrokerAuthorityConfigError::Invalid(name));
            }
            Ok(Some(snapshot))
        })());
        if matches!(self.comparison, Some(Ok(_))) {
            Ok(())
        } else {
            Err(BrokerAuthorityConfigError::Invalid(name))
        }
    }

    pub(super) fn exact<const N: usize>(&self, name: &'static str) -> Result<[u8; N], BrokerAuthorityConfigError> {
        self.bytes.as_ref()
            .ok_or(BrokerAuthorityConfigError::Invalid(name))?
            .as_slice()
            .try_into()
            .map_err(|_| BrokerAuthorityConfigError::Invalid(name))
    }

    fn retire_secret_file(&mut self) {
        if matches!(self.comparison, Some(Ok(_))) {
            if let Some(Ok(file)) = self.opened.as_mut() {
                drop(file.take());
            }
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        failed(&self.opened)
            .or_else(|| failed(&self.initial_stat))
            .or_else(|| failed(&self.initial))
            .or_else(|| failed(&self.length))
            .or_else(|| self.first.failure())
            .or_else(|| self.second.failure())
            .or_else(|| failed(&self.final_stat))
            .or_else(|| failed(&self.final_metadata))
            .or_else(|| failed(&self.comparison))
    }
}

/// Retains the one native acquisition engine for the three fixed Broker roles.
///
/// Each named facade fixes its domain at construction. The genuine same-role
/// receiving original admits this native/typed graph before contacting it.
#[must_use = "retain partial configuration and actual native causes through original posts"]
struct FixedBrokerConfigurationOriginalV4 {
    domain: BrokerDomain,
    directory: Option<Result<OwnedFd, rustix::io::Errno>>,
    directory_stat: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    directory_validation: Option<Result<(), BrokerAuthorityConfigError>>,
    credentials: [ConfigurationCredentialOriginalV1; 7],
    materialization: Option<ConfigurationMaterializationV1>,
    result: Option<Result<(), BrokerAuthorityConfigError>>,
    reentry: Option<BrokerAuthorityConfigError>,
    entered: bool,
    taken: bool,
}

impl FixedBrokerConfigurationOriginalV4 {
    /// Creates empty fixed destinations without opening or decoding anything.
    #[must_use]
    fn new(domain: BrokerDomain) -> Self {
        Self {
            domain,
            directory: None,
            directory_stat: None,
            directory_validation: None,
            credentials: std::array::from_fn(|_| ConfigurationCredentialOriginalV1::new()),
            materialization: None,
            result: None,
            reentry: None,
            entered: false,
            taken: false,
        }
    }

    /// Captures only the domain fixed by the named facade constructor.
    ///
    /// # Errors
    /// Refuses reentry, unsafe/unavailable fixed inputs or invalid authority.
    /// The detailed actual first cause remains available through failure().
    fn capture_once(&mut self, path: &Path) -> Result<(), BrokerAuthorityConfigError> {
        self.capture_for_uid(path, 0)
    }

    fn capture_for_uid(&mut self, path: &Path, uid: u32) -> Result<(), BrokerAuthorityConfigError> {
        if self.entered || self.taken {
            self.reentry.get_or_insert(BrokerAuthorityConfigError::Invalid("configuration reentry"));
            return Err(BrokerAuthorityConfigError::Invalid("configuration reentry"));
        }
        self.entered = true;
        self.result = Some(self.capture_inner(path, uid));
        if matches!(self.result, Some(Ok(()))) {
            Ok(())
        } else {
            Err(BrokerAuthorityConfigError::Invalid(match self.domain {
                BrokerDomain::Storage => "selected Storage configuration",
                BrokerDomain::Network => "selected Network configuration",
                BrokerDomain::Mount => "selected Mount configuration",
                _ => "selected fixed configuration",
            }))
        }
    }

    fn capture_inner(&mut self, path: &Path, uid: u32) -> Result<(), BrokerAuthorityConfigError> {
        self.directory = Some(open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ));
        let directory = match self.directory.as_ref() {
            Some(Ok(directory)) => directory,
            _ => return Err(BrokerAuthorityConfigError::Invalid("directory")),
        };

        self.directory_stat = Some(fstat(directory));
        let stat = match self.directory_stat.as_ref() {
            Some(Ok(stat)) => stat,
            _ => return Err(BrokerAuthorityConfigError::Invalid("directory")),
        };
        self.directory_validation = Some(validate_directory_metadata(stat, uid));
        if !matches!(self.directory_validation, Some(Ok(()))) {
            return Err(BrokerAuthorityConfigError::Invalid("directory"));
        }

        let recipes = [
            (PLAN_POLICY_FILE, MAXIMUM_POLICY_BYTES, None),
            (PLAN_PUBLIC_KEY_FILE, 32, Some(32)),
            (PLAN_REVOCATION_SCOPE_FILE, 16, Some(16)),
            (LEASE_POLICY_FILE, MAXIMUM_POLICY_BYTES, None),
            (LEASE_PUBLIC_KEY_FILE, 32, Some(32)),
            (NODE_ID_FILE, 16, Some(16)),
            (JOURNAL_MAC_KEY_FILE, 48, Some(48)),
        ];
        for (original, (name, maximum, exact)) in self.credentials.iter_mut().zip(recipes) {
            original.capture_once(directory, name, maximum, exact, uid)?;
        }
        // Ordinary secret-exact construction closes this native File before
        // model/anchor parsing; only the zeroizing key bytes survive that read.
        self.credentials[6].retire_secret_file();

        let input = ConfigurationInputsV1 {
            plan_policy: self.credentials[0].bytes.as_ref()
                .ok_or(BrokerAuthorityConfigError::Invalid(PLAN_POLICY_FILE))?
                .to_vec(),
            plan_public_key: self.credentials[1].exact(PLAN_PUBLIC_KEY_FILE)?,
            revocation_scope: self.credentials[2].exact(PLAN_REVOCATION_SCOPE_FILE)?,
            lease_policy: self.credentials[3].bytes.as_ref()
                .ok_or(BrokerAuthorityConfigError::Invalid(LEASE_POLICY_FILE))?
                .to_vec(),
            lease_public_key: self.credentials[4].exact(LEASE_PUBLIC_KEY_FILE)?,
            node: self.credentials[5].exact(NODE_ID_FILE)?,
            journal_key: Zeroizing::new(self.credentials[6].exact(JOURNAL_MAC_KEY_FILE)?),
        };
        self.materialization = Some(ConfigurationMaterializationV1::new(input, self.domain));
        self.materialization.as_mut()
            .ok_or(BrokerAuthorityConfigError::Invalid("configuration materialization"))?
            .run_once()
    }

    /// Moves the exact completed authority/key and its six original public Files.
    ///
    /// Failure never extracts or substitutes an opened File. Reentry cannot
    /// replay reads or mint a second configuration.
    #[must_use]
    pub fn take_configuration_once(&mut self) -> Option<ProtectedBrokerAuthorityConfiguration> {
        if self.taken || self.reentry.is_some() || !matches!(self.result, Some(Ok(()))) {
            return None;
        }
        if !self.materialization.as_ref()?.is_complete() {
            return None;
        }
        let credentials = self.take_public_credentials()?;
        let completed = self.materialization.as_mut()
            .and_then(ConfigurationMaterializationV1::take_completed);
        let Some((authority, public_binding, journal_key_id, journal_secret)) = completed else {
            for (original, credential) in self.credentials.iter_mut().zip(credentials.credentials) {
                original.opened = Some(Ok(Some(credential.descriptor)));
            }
            return None;
        };
        self.taken = true;
        Some(ProtectedBrokerAuthorityConfiguration {
            authority,
            public_credentials: credentials,
            public_binding,
            journal_key_id,
            journal_secret,
        })
    }

    fn take_public_credentials(&mut self) -> Option<ProtectedBrokerPublicCredentials> {
        take_public_credentials_v2(&mut self.credentials[..6])
    }

    /// Borrows the earliest retained actual native or typed construction cause.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        failed(&self.directory)
            .or_else(|| failed(&self.directory_stat))
            .or_else(|| failed(&self.directory_validation))
            .or_else(|| self.credentials.iter().find_map(ConfigurationCredentialOriginalV1::failure))
            .or_else(|| self.materialization.as_ref().and_then(ConfigurationMaterializationV1::failure))
            .or_else(|| failed(&self.result))
            .or_else(|| self.reentry.as_ref().map(|error| error as _))
    }
}


/// Moves only a complete original public roster; failed extraction restores it.
pub(super) fn take_public_credentials_v2(
    credentials: &mut [ConfigurationCredentialOriginalV1],
) -> Option<ProtectedBrokerPublicCredentials> {
    if credentials.len() != 6 { return None; }
        let snapshots = std::array::from_fn::<_, 6, _>(|index| {
            credentials[index].comparison.as_ref()
                .and_then(|result| result.as_ref().ok())
                .and_then(|snapshot| *snapshot)
        });
        let [
            Some(snapshot0), Some(snapshot1), Some(snapshot2),
            Some(snapshot3), Some(snapshot4), Some(snapshot5),
        ] = snapshots else {
            return None;
        };
        let original_files = (
            credentials[0].opened.take(),
            credentials[1].opened.take(),
            credentials[2].opened.take(),
            credentials[3].opened.take(),
            credentials[4].opened.take(),
            credentials[5].opened.take(),
        );
        match original_files {
            (
                Some(Ok(Some(file0))), Some(Ok(Some(file1))), Some(Ok(Some(file2))),
                Some(Ok(Some(file3))), Some(Ok(Some(file4))), Some(Ok(Some(file5))),
            ) => {
                Some(ProtectedBrokerPublicCredentials {
                    credentials: [
                        ProtectedBrokerPublicCredential { descriptor: file0, snapshot: snapshot0 },
                        ProtectedBrokerPublicCredential { descriptor: file1, snapshot: snapshot1 },
                        ProtectedBrokerPublicCredential { descriptor: file2, snapshot: snapshot2 },
                        ProtectedBrokerPublicCredential { descriptor: file3, snapshot: snapshot3 },
                        ProtectedBrokerPublicCredential { descriptor: file4, snapshot: snapshot4 },
                        ProtectedBrokerPublicCredential { descriptor: file5, snapshot: snapshot5 },
                    ],
                })
            }
            (original0, original1, original2, original3, original4, original5) => {
                credentials[0].opened = original0;
                credentials[1].opened = original1;
                credentials[2].opened = original2;
                credentials[3].opened = original3;
                credentials[4].opened = original4;
                credentials[5].opened = original5;
                None
            }
        }
}

// The domain never comes from a caller or wire enum. These three fixed facades
// share every native read, typed materialization and positive handoff above.
macro_rules! fixed_configuration_facade {
    ($name:ident, $domain:ident, $capture:ident, $description:literal) => {
        #[doc = $description]
        #[must_use = "retain the whole configuration through independently owed posts"]
        pub struct $name(FixedBrokerConfigurationOriginalV4);

        impl $name {
            /// Creates empty destinations for this exact fixed Broker domain.
            #[must_use]
            pub fn new() -> Self {
                Self(FixedBrokerConfigurationOriginalV4::new(BrokerDomain::$domain))
            }

            /// Captures the actual already-funded fixed-role configuration once.
            ///
            /// The same genuine role owner must fund the compiled configuration
            /// demand before entry. This grants no receiving allowance or effect.
            ///
            /// # Errors
            /// Retains unsafe inputs, native reads, typed materialization and
            /// reentry refusals in the original; failure() borrows their cause.
            pub fn $capture(&mut self, path: &Path) -> Result<(), BrokerAuthorityConfigError> {
                self.0.capture_once(path)
            }

            /// Moves the completed authority and its six original public files once.
            ///
            /// No partial or failed configuration can be extracted or replaced.
            #[must_use]
            pub fn take_configuration_once(&mut self) -> Option<ProtectedBrokerAuthorityConfiguration> {
                self.0.take_configuration_once()
            }

            /// Borrows the earliest native or typed construction refusal.
            #[must_use]
            pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
                self.0.failure()
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

fixed_configuration_facade!(ProtectedStorageBrokerConfigurationOriginalV1, Storage,
    capture_storage_once, "Retains the prepaid fixed Storage configuration and all failed prefixes.");
fixed_configuration_facade!(ProtectedNetworkBrokerConfigurationOriginalV4, Network,
    capture_network_once_v4, "Retains the prepaid fixed Network configuration and all failed prefixes.");
fixed_configuration_facade!(ProtectedMountBrokerConfigurationOriginalV4, Mount,
    capture_mount_once_v4, "Retains the prepaid fixed Mount configuration and all failed prefixes.");

fn failed<T, E: Error + 'static>(
    slot: &Option<Result<T, E>>,
) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()
        .and_then(|result| result.as_ref().err())
        .map(|error| error as _)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use super::*;

    fn protected_directory() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }

    fn write(directory: &Path, name: &str, bytes: &[u8]) {
        let path = directory.join(name);
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn configured_policy(purpose: SignaturePurpose, usage: KeyUsage) -> Vec<u8> {
        let signer = KeyReference::new(
            aos_sandbox_model::model::StableKeyId::new("configured".to_owned()).unwrap(),
            1,
            ObjectDigest::from_bytes(Sha256::digest([3_u8; 32]).into()),
            usage,
        );
        let policy = aos_sandbox_model::model::TrustPolicy::new(
            aos_sandbox_model::TrustScopeId::from_bytes([1; 16]),
            purpose,
            vec![signer],
            Vec::new(),
        ).unwrap();
        aos_sandbox_model::format::encode_trust_policy(&policy)
    }

    #[test]
    fn positive_transfer_moves_all_original_public_files_once_and_retains_key_parts() {
        let directory = protected_directory();
        let path = directory.path();
        let uid = path.metadata().unwrap().uid();
        write(path, PLAN_POLICY_FILE, &configured_policy(
            SignaturePurpose::BrokerAuthorization, KeyUsage::BrokerAuthorization,
        ));
        write(path, LEASE_POLICY_FILE, &configured_policy(
            SignaturePurpose::OwnershipLease, KeyUsage::OwnershipLease,
        ));
        for name in [PLAN_PUBLIC_KEY_FILE, LEASE_PUBLIC_KEY_FILE] {
            write(path, name, &[3; 32]);
        }
        for name in [PLAN_REVOCATION_SCOPE_FILE, NODE_ID_FILE] {
            write(path, name, &[1; 16]);
        }
        write(path, JOURNAL_MAC_KEY_FILE, &[5; 48]);
        let mut original = ProtectedStorageBrokerConfigurationOriginalV1::new();

        original.0.capture_for_uid(path, uid).unwrap();
        let expected_inodes: [u64; 6] = std::array::from_fn(|index| {
            original.0.credentials[index].initial.as_ref().unwrap().as_ref().unwrap().inode
        });
        let configuration = original.take_configuration_once().unwrap();
        let (_authority, key_id, secret, public) =
            configuration.into_parts_with_public_credentials();

        assert_eq!(key_id, [5; 16]);
        assert_eq!(*secret, [5; 32]);
        for (credential, expected_inode) in public.credentials.iter().zip(expected_inodes) {
            assert_eq!(fstat(&credential.descriptor).unwrap().st_ino, expected_inode);
        }
        assert!(original.0.credentials[..6].iter().all(|read| read.opened.is_none()));
        assert!(original.0.credentials[..6].iter().all(|read| read.bytes.is_some()));
        assert!(original.take_configuration_once().is_none());
        assert!(original.failure().is_none());
    }

    #[test]
    fn missing_second_public_file_keeps_first_native_original_and_precedes_policy_decode() {
        let directory = protected_directory();
        let path = directory.path();
        let uid = path.metadata().unwrap().uid();
        write(path, PLAN_POLICY_FILE, &[0xff]);
        let mut original = ProtectedStorageBrokerConfigurationOriginalV1::new();

        assert!(original.0.capture_for_uid(path, uid).is_err());

        let first = &original.0.credentials[0];
        assert!(matches!(first.opened, Some(Ok(Some(_)))));
        assert_eq!(first.bytes.as_ref().unwrap().as_slice(), &[0xff]);
        assert!(original.0.materialization.is_none());
        assert!(original.take_configuration_once().is_none());
        let cause = original.failure().unwrap().downcast_ref::<rustix::io::Errno>().unwrap()
            as *const rustix::io::Errno;

        std::fs::rename(path.join(PLAN_POLICY_FILE), path.join("retained-policy")).unwrap();
        write(path, PLAN_POLICY_FILE, &[1]);
        assert!(original.0.capture_for_uid(path, uid).is_err());

        assert_eq!(original.0.credentials[0].bytes.as_ref().unwrap().as_slice(), &[0xff]);
        assert_eq!(original.failure().unwrap().downcast_ref::<rustix::io::Errno>().unwrap()
            as *const rustix::io::Errno, cause);
        assert!(original.0.credentials[2].opened.is_none());
    }

    #[test]
    fn typed_policy_failure_retains_all_six_public_originals_and_actual_decoder_error() {
        let directory = protected_directory();
        let path = directory.path();
        let uid = path.metadata().unwrap().uid();
        for name in [PLAN_POLICY_FILE, LEASE_POLICY_FILE] {
            write(path, name, &[0xff]);
        }
        for name in [PLAN_PUBLIC_KEY_FILE, LEASE_PUBLIC_KEY_FILE] {
            write(path, name, &[3; 32]);
        }
        for name in [PLAN_REVOCATION_SCOPE_FILE, NODE_ID_FILE] {
            write(path, name, &[1; 16]);
        }
        write(path, JOURNAL_MAC_KEY_FILE, &[5; 48]);
        let mut original = ProtectedStorageBrokerConfigurationOriginalV1::new();

        assert!(original.0.capture_for_uid(path, uid).is_err());

        assert!(original.0.credentials[..6].iter()
            .all(|read| matches!(read.opened, Some(Ok(Some(_))))));
        assert!(matches!(original.0.credentials[6].opened, Some(Ok(None))));
        assert!(original.take_configuration_once().is_none());
        let cause = original.failure().unwrap()
            .downcast_ref::<aos_sandbox_model::format::CanonicalCborError>().unwrap()
            as *const aos_sandbox_model::format::CanonicalCborError;
        assert!(original.0.capture_for_uid(path, uid).is_err());
        assert_eq!(original.failure().unwrap()
            .downcast_ref::<aos_sandbox_model::format::CanonicalCborError>().unwrap()
            as *const aos_sandbox_model::format::CanonicalCborError, cause);
    }
}
