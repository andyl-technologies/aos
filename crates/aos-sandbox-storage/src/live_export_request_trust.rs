//! Protected signer pins for Provider-to-Storage LocalLive and native requests.
//!
//! ```text
//! AOSSLT01 | version:u16be=1 | reserved[6]=0 | generation:u64be |
//! provider-signer[112] | provider-ed25519-public[32] |
//! root-mount-signer[112] | root-mount-ed25519-public[32]
//! ```
//!
//! Each signer is authority ID, authority generation, authority digest, key
//! ID, key generation, and SHA-256 public-key digest. The fixed root-owned
//! record is double-read and anchored in a protected journal. Replacement
//! requires exactly one generation step; rollback and same-generation key
//! equivocation fail closed. Keys supplied with a request are never trusted.

use std::fs::File;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::FileExt as _;
use std::path::{Path, PathBuf};

use aos_sandbox::{Journal, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    SignedStorageLiveExportRequestV1, SignedStorageNativeAcceptanceReadbackQueryV1,
    SignedStorageNativeAcquireRequestV2, SourceProviderKeyUsageV1, SourceProviderSigningKeyV1,
};
use ed25519_dalek::VerifyingKey;
use rustix::fs::{FileType, Mode, OFlags};
use sha2::{Digest as _, Sha256};

use crate::live_export_key::{open_protected_directory, same_stable_file_metadata};

const TRUST_FILE: &str = "storage-live-export-request-trust-v1";
const JOURNAL_FILE: &str = "storage-live-export-request-trust.journal";
const JOURNAL_HEAD_KEY: &[u8] = b"live-export-request-trust-head-v1";
const MAGIC: &[u8; 8] = b"AOSSLT01";
const VERSION: u16 = 1;
const SIGNER_BYTES: usize = 112;
const KEY_BYTES: usize = 32;
const RECORD_BYTES: usize = 24 + 2 * (SIGNER_BYTES + KEY_BYTES);
const JOURNAL_DOMAIN: &[u8] = b"aos.sandbox.storage.live-export-request-trust.v1\0";
// Journal record encoding: operation:u8, key-length:u16, value-length:u32.
const JOURNAL_RECORD_FRAMING_BYTES: usize = 1 + 2 + 4;
const JOURNAL_HEAD_RECORD_BYTES: usize =
    JOURNAL_RECORD_FRAMING_BYTES + JOURNAL_HEAD_KEY.len() + RECORD_BYTES;

/// Reports absent, changed, or invalid protected request trust.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum StorageLiveExportRequestTrustErrorV1 {
    /// The root-owned file or durable journal is not current.
    #[error("Storage live-export request trust custody is unavailable")]
    Custody,
    /// Signer metadata, generation, or key material is invalid.
    #[error("Storage live-export request trust record is invalid")]
    InvalidRecord,
    /// The plan does not authenticate under both independently pinned keys.
    #[error("Storage live-export request signers are unauthenticated")]
    Signature,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TrustRecordV1 {
    generation: u64,
    provider_signer: SourceProviderSigningKeyV1,
    provider_public_key: [u8; KEY_BYTES],
    root_signer: SourceProviderSigningKeyV1,
    root_public_key: [u8; KEY_BYTES],
}

/// Retains two independent current signers under Storage-owned custody.
pub(crate) struct StorageLiveExportRequestTrustV1 {
    journal: Journal,
    directory: OwnedFd,
    directory_path: PathBuf,
    directory_device: u64,
    directory_inode: u64,
    file_device: u64,
    file_inode: u64,
    bytes: [u8; RECORD_BYTES],
    record: TrustRecordV1,
    expected_owner: u32,
    #[cfg(test)]
    synthetic_directory: bool,
}

/// Carries native claims authenticated under both current Storage-owned pins.
///
/// This proves signed intent, not Provider completion, a current physical hold,
/// or descriptor custody. Only the trust owner can construct this projection.
pub(crate) struct AuthenticatedStorageNativeRequestV2<'a> {
    request: &'a SignedStorageNativeAcquireRequestV2,
    trust: &'a StorageLiveExportRequestTrustV1,
}

/// Authenticates historical metadata intent under the current Provider pin only.
///
/// This does not reauthorize the original Acquire, establish its currentness,
/// or authenticate the live transport peer. The fixed carrier must do that.
pub(crate) struct AuthenticatedStorageNativeAcceptanceReadbackQueryV1<'a> {
    query: &'a SignedStorageNativeAcceptanceReadbackQueryV1,
    trust: &'a StorageLiveExportRequestTrustV1,
}

impl AuthenticatedStorageNativeAcceptanceReadbackQueryV1<'_> {
    /// Returns exact signed metadata intent, not renewed Acquire intent.
    pub(crate) fn query(&self) -> &SignedStorageNativeAcceptanceReadbackQueryV1 {
        self.query
    }

    /// Rechecks the current Provider pin and its protected physical names.
    ///
    /// # Errors
    ///
    /// Rejects replaced trust custody or a different Provider signer/signature.
    pub(crate) fn recheck(&self) -> Result<(), StorageLiveExportRequestTrustErrorV1> {
        self.trust.verify_native_readback_signature(self.query)
    }
}

impl AuthenticatedStorageNativeRequestV2<'_> {
    pub(crate) fn require_original_root_prepared(
        &self,
        root: &aos_sandbox_source_provider_protocol::native_held_completion::frame::SignedNativeHeldControlV1,
        storage: aos_sandbox_source_provider_protocol::StorageZfsHoldVerifierV1,
    ) -> Result<(), StorageLiveExportRequestTrustErrorV1> {
        self.trust.require_original_root_prepared(root, self.request, storage)
    }

    pub(crate) fn request(&self) -> &SignedStorageNativeAcquireRequestV2 {
        self.request
    }

    /// Rejoins both signed inputs to the same current protected pins.
    ///
    /// # Errors
    ///
    /// Rejects changed trust custody or either signed owner binding.
    pub(crate) fn recheck(&self) -> Result<(), StorageLiveExportRequestTrustErrorV1> {
        self.trust.verify_native_signatures(self.request)
    }

    /// Verifies the shared native graph against independently rejoined evidence.
    ///
    /// This is signature/crosslink validation, not descriptor-send authority.
    ///
    /// # Errors
    ///
    /// Rejects changed pins, any signed graph mismatch, stale time, or root identity.
    pub(crate) fn verify_reply(
        &self,
        reply: &aos_sandbox_source_provider_protocol::StorageNativeAcquireReplyV3,
        verifier: aos_sandbox_source_provider_protocol::StorageZfsHoldVerifierV1,
        expected: &aos_sandbox_source_provider_protocol::StorageZfsHoldReceiptV1,
        descriptor: &aos_sandbox_source_provider_protocol::SourceRootObservationV1,
        now_seconds: i64,
    ) -> Result<(), StorageLiveExportRequestTrustErrorV1> {
        self.trust.validate_current()?;
        reply.verify_for(aos_sandbox_source_provider_protocol::StorageNativeAcquireVerificationV3 {
            request: self.request,
            provider_signer: &self.trust.record.provider_signer,
            provider_key: &self.trust.record.provider_public_key,
            root_signer: &self.trust.record.root_signer,
            root_key: &self.trust.record.root_public_key,
            storage_verifier: verifier, expected_receipt: expected, observed_descriptor: descriptor,
            descriptor_roles: &[aos_sandbox_source_provider_protocol::SourceProviderDescriptorRole::SourceRoot],
            now_seconds,
        }).map_err(|_| StorageLiveExportRequestTrustErrorV1::Signature)?;
        self.trust.validate_current()
    }
}

impl StorageLiveExportRequestTrustV1 {
    // Cold authentication checks eligible independently owned roles, not wall
    // validity. It cannot renew an archive or authorize a current descriptor.
    pub(crate) fn verify_held_archive(
        &self,
        control: &aos_sandbox_source_provider_protocol::native_held_completion::frame::SignedNativeHeldControlV1,
        storage: aos_sandbox_source_provider_protocol::StorageZfsHoldVerifierV1,
    ) -> Result<(), StorageLiveExportRequestTrustErrorV1> {
        self.validate_current()?;
        self.verify_held_archive_at_depth(control, storage, 0)?;
        self.validate_current()
    }

    fn verify_held_archive_at_depth(
        &self,
        control: &aos_sandbox_source_provider_protocol::native_held_completion::frame::SignedNativeHeldControlV1,
        storage: aos_sandbox_source_provider_protocol::StorageZfsHoldVerifierV1,
        depth: usize,
    ) -> Result<(), StorageLiveExportRequestTrustErrorV1> {
        use aos_sandbox_source_provider_protocol::native_held_completion::{
            NativeHeldOwnerV1 as Owner, frame::NativeHeldSignerV1,
        };

        if depth > 4 {
            return Err(StorageLiveExportRequestTrustErrorV1::InvalidRecord);
        }
        let (expected, public) = match control.kind().sender() {
            Owner::Root => (
                NativeHeldSignerV1::SourceProvider(self.record.root_signer.clone()),
                self.record.root_public_key,
            ),
            Owner::Provider => (
                NativeHeldSignerV1::SourceProvider(self.record.provider_signer.clone()),
                self.record.provider_public_key,
            ),
            Owner::Storage => {
                let (signer, public) = storage.projection();
                (NativeHeldSignerV1::Storage(signer), public)
            }
        };
        control.verify_signature_claim(&expected, &public)
            .map_err(|_| StorageLiveExportRequestTrustErrorV1::Signature)?;
        self.verify_held_sections(control.prepared(), storage, depth)
    }

    pub(crate) fn verify_stored_held_preparation(
        &self,
        prepared: &aos_sandbox_source_provider_protocol::native_held_completion::frame::PreparedNativeHeldControlV1,
        storage: aos_sandbox_source_provider_protocol::StorageZfsHoldVerifierV1,
    ) -> Result<(), StorageLiveExportRequestTrustErrorV1> {
        use aos_sandbox_source_provider_protocol::native_held_completion::{
            NativeHeldOwnerV1, frame::NativeHeldSignerV1,
        };
        self.validate_current()?;
        if prepared.kind().sender() != NativeHeldOwnerV1::Storage
            || prepared.signer() != &NativeHeldSignerV1::Storage(storage.projection().0)
        {
            return Err(StorageLiveExportRequestTrustErrorV1::Signature);
        }
        self.verify_held_sections(prepared, storage, 0)?;
        self.validate_current()
    }

    fn verify_held_sections(
        &self,
        prepared: &aos_sandbox_source_provider_protocol::native_held_completion::frame::PreparedNativeHeldControlV1,
        storage: aos_sandbox_source_provider_protocol::StorageZfsHoldVerifierV1,
        depth: usize,
    ) -> Result<(), StorageLiveExportRequestTrustErrorV1> {
        use aos_sandbox_source_provider_protocol::native_held_completion::{
            NativeHeldSectionTagV1 as Tag, frame::SignedNativeHeldControlV1,
        };
        for tag in [Tag::RootPrepared, Tag::StorageHeld, Tag::RootDispositionControl, Tag::RootRecoveryControl] {
            if let Some(bytes) = prepared.section(tag) {
                let nested = SignedNativeHeldControlV1::from_canonical_bytes(bytes)
                    .map_err(|_| StorageLiveExportRequestTrustErrorV1::InvalidRecord)?;
                self.verify_held_archive_at_depth(&nested, storage, depth + 1)?;
            }
        }
        if let Some(bytes) = prepared.section(Tag::NativeReply) {
            let reply = aos_sandbox_source_provider_protocol::StorageNativeAcquireReplyV3::from_canonical_bytes(bytes)
                .map_err(|_| StorageLiveExportRequestTrustErrorV1::InvalidRecord)?;
            reply.acceptance().verify(storage)
                .map_err(|_| StorageLiveExportRequestTrustErrorV1::Signature)?;
            storage.verify_retained_signature_claim(reply.receipt())
                .map_err(|_| StorageLiveExportRequestTrustErrorV1::Signature)?;
        }
        Ok(())
    }

    pub(crate) fn held_trust_cut(&self) -> Result<(u64, u64, ObjectDigest), StorageLiveExportRequestTrustErrorV1> {
        self.validate_current()?;
        Ok((self.journal.snapshot_sequence(), self.record.generation,
            ObjectDigest::from_bytes(Sha256::digest(self.bytes).into())))
    }

    pub(crate) fn require_original_root_prepared(
        &self,
        root: &aos_sandbox_source_provider_protocol::native_held_completion::frame::SignedNativeHeldControlV1,
        request: &SignedStorageNativeAcquireRequestV2,
        storage: aos_sandbox_source_provider_protocol::StorageZfsHoldVerifierV1,
    ) -> Result<(), StorageLiveExportRequestTrustErrorV1> {
        use aos_sandbox_source_provider_protocol::native_held_completion::NativeHeldControlKindV1;
        self.verify_native_signatures(request)?;
        self.verify_held_archive(root, storage)?;
        let claims = request.request().claims();
        if root.kind() != NativeHeldControlKindV1::RootPrepared
            || root.scope().original_source_session != claims.holder_session().1
            || root.scope().provider_acquisition != claims.provider_acquisition().1
            || root.scope().original_root_request != aos_sandbox_source_provider_protocol::digest_signed_request(request.request().signed_root_request())
        {
            return Err(StorageLiveExportRequestTrustErrorV1::Signature);
        }
        Ok(())
    }

    /// Authenticates a metadata query without validating historical Acquire.
    ///
    /// The independent query nonce and sequence correlate one current carrier;
    /// they are not durable admission or latest-state freshness authority.
    ///
    /// # Errors
    ///
    /// Rejects unsafe or changed current pins and an unauthenticated Provider.
    pub(crate) fn verify_native_readback<'a>(
        &'a self,
        query: &'a SignedStorageNativeAcceptanceReadbackQueryV1,
    ) -> Result<
        AuthenticatedStorageNativeAcceptanceReadbackQueryV1<'a>,
        StorageLiveExportRequestTrustErrorV1,
    > {
        self.verify_native_readback_signature(query)?;
        Ok(AuthenticatedStorageNativeAcceptanceReadbackQueryV1 { query, trust: self })
    }

    fn verify_native_readback_signature(
        &self,
        query: &SignedStorageNativeAcceptanceReadbackQueryV1,
    ) -> Result<(), StorageLiveExportRequestTrustErrorV1> {
        self.validate_current()?;
        query
            .verify(
                &self.record.provider_signer,
                &self.record.provider_public_key,
            )
            .map_err(|_| StorageLiveExportRequestTrustErrorV1::Signature)?;
        self.validate_current()
    }

    /// Opens current root-owned trust without accepting caller-supplied keys.
    ///
    /// # Errors
    ///
    /// Returns custody or record errors for unsafe paths, files, journal
    /// rollback, weak keys, or inconsistent fingerprints.
    pub(crate) fn open_root_owned(
        directory_path: &Path,
    ) -> Result<Self, StorageLiveExportRequestTrustErrorV1> {
        Self::open_for_owner(directory_path, 0)
    }

    fn open_for_owner(
        directory_path: &Path,
        expected_owner: u32,
    ) -> Result<Self, StorageLiveExportRequestTrustErrorV1> {
        let directory = open_protected_directory(directory_path, expected_owner)
            .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
        Self::open_with_directory(directory_path, expected_owner, directory)
    }

    fn open_with_directory(
        directory_path: &Path,
        expected_owner: u32,
        directory: OwnedFd,
    ) -> Result<Self, StorageLiveExportRequestTrustErrorV1> {
        let directory_identity = rustix::fs::fstat(&directory)
            .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
        let (bytes, file_device, file_inode) = read_trust(&directory, expected_owner)?;
        let record = parse_trust(&bytes)?;
        let opened = if expected_owner == 0 {
            Journal::open_protected_at(directory_path, JOURNAL_FILE, journal_limits())
        } else {
            #[cfg(test)]
            {
                Journal::open_protected_at_uid(
                    directory_path,
                    JOURNAL_FILE,
                    journal_limits(),
                    expected_owner,
                )
            }
            #[cfg(not(test))]
            {
                return Err(StorageLiveExportRequestTrustErrorV1::Custody);
            }
        };
        let mut journal = opened
            .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?
            .0;
        reconcile_head(&mut journal, &bytes, record.generation)?;

        Ok(Self {
            journal,
            directory,
            directory_path: directory_path.to_path_buf(),
            directory_device: directory_identity.st_dev,
            directory_inode: directory_identity.st_ino,
            file_device,
            file_inode,
            bytes,
            record,
            expected_owner,
            #[cfg(test)]
            synthetic_directory: false,
        })
    }

    /// Verifies the complete signed plan against both current protected pins.
    ///
    /// # Errors
    ///
    /// Returns custody errors when the trust record changed or signature
    /// errors when either independent signer fails strict verification.
    pub(crate) fn verify(
        &self,
        request: &SignedStorageLiveExportRequestV1,
    ) -> Result<(), StorageLiveExportRequestTrustErrorV1> {
        self.validate_current()?;
        request
            .verify(
                &self.record.provider_signer,
                &self.record.provider_public_key,
                &self.record.root_signer,
                &self.record.root_public_key,
            )
            .map_err(|_| StorageLiveExportRequestTrustErrorV1::Signature)?;
        self.validate_current()
    }

    /// Authenticates a native request without borrowing LocalLive grant semantics.
    ///
    /// # Errors
    ///
    /// Rejects changed protected trust or either unauthenticated request signer.
    pub(crate) fn verify_native<'a>(
        &'a self,
        request: &'a SignedStorageNativeAcquireRequestV2,
    ) -> Result<AuthenticatedStorageNativeRequestV2<'a>, StorageLiveExportRequestTrustErrorV1> {
        self.verify_native_signatures(request)?;
        Ok(AuthenticatedStorageNativeRequestV2 {
            request,
            trust: self,
        })
    }

    fn verify_native_signatures(
        &self,
        request: &SignedStorageNativeAcquireRequestV2,
    ) -> Result<(), StorageLiveExportRequestTrustErrorV1> {
        self.validate_current()?;
        request
            .verify(
                &self.record.provider_signer,
                &self.record.provider_public_key,
                &self.record.root_signer,
                &self.record.root_public_key,
            )
            .map_err(|_| StorageLiveExportRequestTrustErrorV1::Signature)?;
        self.validate_current()
    }

    pub(crate) fn validate_current(&self) -> Result<(), StorageLiveExportRequestTrustErrorV1> {
        let current_directory = self.reopen_directory()?;
        let identity = rustix::fs::fstat(&current_directory)
            .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
        if (identity.st_dev, identity.st_ino) != (self.directory_device, self.directory_inode) {
            return Err(StorageLiveExportRequestTrustErrorV1::Custody);
        }
        self.journal
            .validate_held_protected_names()
            .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
        let (bytes, device, inode) = read_trust(&self.directory, self.expected_owner)?;
        if (device, inode) != (self.file_device, self.file_inode)
            || bytes != self.bytes
            || parse_trust(&bytes)? != self.record
            || self
                .journal
                .get(RecordNamespace::AuthorityPublication, JOURNAL_HEAD_KEY)
                != Some(self.bytes.as_slice())
        {
            return Err(StorageLiveExportRequestTrustErrorV1::Custody);
        }
        Ok(())
    }

    fn reopen_directory(&self) -> Result<OwnedFd, StorageLiveExportRequestTrustErrorV1> {
        #[cfg(test)]
        if self.synthetic_directory {
            return open_fixture_directory(&self.directory_path, self.expected_owner);
        }
        open_protected_directory(&self.directory_path, self.expected_owner)
            .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)
    }

    #[cfg(test)]
    pub(crate) fn native_fixture_for_test(directory: &Path) -> Self {
        Self::native_provider_fixture_for_test(directory, [32; 32], 1)
    }

    #[cfg(test)]
    pub(crate) fn native_provider_fixture_for_test(
        directory: &Path,
        provider_seed: [u8; 32],
        provider_key_generation: u64,
    ) -> Self {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut bytes = tests::fixture();
        for (offset, authority, authority_digest, key_id, seed, key_generation) in [
            (24, 30, 33, 34, provider_seed, provider_key_generation),
            (168, 22, 23, 29, [28; 32], 1),
        ] {
            let key = ed25519_dalek::SigningKey::from_bytes(&seed);
            bytes[offset..offset + 16].fill(authority);
            bytes[offset + 24..offset + 56].fill(authority_digest);
            bytes[offset + 56..offset + 72].fill(key_id);
            bytes[offset + 72..offset + 80].copy_from_slice(&key_generation.to_be_bytes());
            bytes[offset + 80..offset + 112]
                .copy_from_slice(&Sha256::digest(key.verifying_key().as_bytes()));
            bytes[offset + 112..offset + 144].copy_from_slice(key.verifying_key().as_bytes());
        }
        std::fs::write(directory.join(TRUST_FILE), bytes).unwrap();
        std::fs::set_permissions(
            directory.join(TRUST_FILE),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let owner = std::fs::metadata(directory).unwrap().uid();
        let descriptor = open_fixture_directory(directory, owner).unwrap();
        let mut trust = Self::open_with_directory(directory, owner, descriptor).unwrap();
        trust.synthetic_directory = true;
        trust.validate_current().unwrap();
        trust
    }
}

// A temporary test directory cannot provide production root-owned ancestry.
// The fixture still retains the exact private UID/mode leaf and protected
// journal names; only cfg(test) can select this synthetic ancestry boundary.
#[cfg(test)]
fn open_fixture_directory(
    directory: &Path,
    owner: u32,
) -> Result<OwnedFd, StorageLiveExportRequestTrustErrorV1> {
    let descriptor = rustix::fs::open(
        directory,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
    let identity = rustix::fs::fstat(&descriptor)
        .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
    if FileType::from_raw_mode(identity.st_mode) != FileType::Directory
        || identity.st_uid != owner
        || identity.st_mode & 0o777 != 0o700
    {
        return Err(StorageLiveExportRequestTrustErrorV1::Custody);
    }
    Ok(descriptor)
}

fn read_trust(
    directory: &OwnedFd,
    expected_owner: u32,
) -> Result<([u8; RECORD_BYTES], u64, u64), StorageLiveExportRequestTrustErrorV1> {
    let descriptor = rustix::fs::openat(
        directory.as_fd(),
        TRUST_FILE,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
    let before = rustix::fs::fstat(&descriptor)
        .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != expected_owner
        || before.st_mode & 0o777 != 0o600
        || before.st_nlink != 1
        || before.st_size != RECORD_BYTES as i64
        || before.st_dev == 0
        || before.st_ino == 0
    {
        return Err(StorageLiveExportRequestTrustErrorV1::Custody);
    }

    let file = File::from(descriptor);
    let mut bytes = [0; RECORD_BYTES];
    let mut repeated = [0; RECORD_BYTES];
    file.read_exact_at(&mut bytes, 0)
        .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
    file.read_exact_at(&mut repeated, 0)
        .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
    let after =
        rustix::fs::fstat(&file).map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
    if !same_stable_file_metadata(&before, &after) || bytes != repeated {
        return Err(StorageLiveExportRequestTrustErrorV1::Custody);
    }
    Ok((bytes, before.st_dev, before.st_ino))
}

fn parse_trust(
    bytes: &[u8; RECORD_BYTES],
) -> Result<TrustRecordV1, StorageLiveExportRequestTrustErrorV1> {
    if &bytes[..8] != MAGIC || bytes[8..10] != VERSION.to_be_bytes() || bytes[10..16] != [0; 6] {
        return Err(StorageLiveExportRequestTrustErrorV1::InvalidRecord);
    }
    let generation = u64::from_be_bytes(
        bytes[16..24]
            .try_into()
            .map_err(|_| StorageLiveExportRequestTrustErrorV1::InvalidRecord)?,
    );
    if generation == 0 {
        return Err(StorageLiveExportRequestTrustErrorV1::InvalidRecord);
    }
    let (provider_signer, provider_public_key) =
        parse_signer(&bytes[24..168], SourceProviderKeyUsageV1::ProviderOutcome)?;
    let (root_signer, root_public_key) =
        parse_signer(&bytes[168..312], SourceProviderKeyUsageV1::RootMountRecord)?;
    if provider_signer.authority_id() == root_signer.authority_id()
        || provider_public_key == root_public_key
    {
        return Err(StorageLiveExportRequestTrustErrorV1::InvalidRecord);
    }
    Ok(TrustRecordV1 {
        generation,
        provider_signer,
        provider_public_key,
        root_signer,
        root_public_key,
    })
}

fn parse_signer(
    bytes: &[u8],
    usage: SourceProviderKeyUsageV1,
) -> Result<(SourceProviderSigningKeyV1, [u8; KEY_BYTES]), StorageLiveExportRequestTrustErrorV1> {
    if bytes.len() != SIGNER_BYTES + KEY_BYTES {
        return Err(StorageLiveExportRequestTrustErrorV1::InvalidRecord);
    }
    let public_key = field::<KEY_BYTES>(bytes, 112)?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| StorageLiveExportRequestTrustErrorV1::InvalidRecord)?;
    if verifying_key.is_weak() {
        return Err(StorageLiveExportRequestTrustErrorV1::InvalidRecord);
    }
    let signer = SourceProviderSigningKeyV1::new(
        field(bytes, 0)?,
        u64::from_be_bytes(field(bytes, 16)?),
        ObjectDigest::from_bytes(field(bytes, 24)?),
        field(bytes, 56)?,
        u64::from_be_bytes(field(bytes, 72)?),
        ObjectDigest::from_bytes(field(bytes, 80)?),
        usage,
    )
    .map_err(|_| StorageLiveExportRequestTrustErrorV1::InvalidRecord)?;
    if signer.public_key_digest() != ObjectDigest::from_bytes(Sha256::digest(public_key).into()) {
        return Err(StorageLiveExportRequestTrustErrorV1::InvalidRecord);
    }
    Ok((signer, public_key))
}

fn field<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], StorageLiveExportRequestTrustErrorV1> {
    bytes
        .get(offset..offset + N)
        .ok_or(StorageLiveExportRequestTrustErrorV1::InvalidRecord)?
        .try_into()
        .map_err(|_| StorageLiveExportRequestTrustErrorV1::InvalidRecord)
}

fn reconcile_head(
    journal: &mut Journal,
    bytes: &[u8; RECORD_BYTES],
    generation: u64,
) -> Result<(), StorageLiveExportRequestTrustErrorV1> {
    let mut authority = journal
        .claim_protected_authority(RecordNamespace::AuthorityPublication)
        .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
    let previous = authority
        .get(JOURNAL_HEAD_KEY)
        .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?
        .map(ToOwned::to_owned);
    let needs_commit = match previous {
        None => {
            if !authority
                .is_materialized_empty()
                .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?
                || generation != 1
            {
                return Err(StorageLiveExportRequestTrustErrorV1::Custody);
            }
            true
        }
        Some(previous) if previous == bytes => false,
        Some(previous) => {
            let previous: [u8; RECORD_BYTES] = previous
                .try_into()
                .map_err(|_| StorageLiveExportRequestTrustErrorV1::InvalidRecord)?;
            validate_transition(&previous, generation)?;
            true
        }
    };
    if needs_commit {
        let hash = Sha256::new()
            .chain_update(JOURNAL_DOMAIN)
            .chain_update(bytes)
            .finalize();
        let transaction_id: [u8; 16] = hash[..16]
            .try_into()
            .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(
                RecordNamespace::AuthorityPublication,
                JOURNAL_HEAD_KEY.to_vec(),
                bytes.to_vec(),
            )],
        )
        .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
        authority
            .commit(&transaction)
            .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
    }
    if authority
        .records()
        .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?
        .collect::<Vec<_>>()
        != vec![(JOURNAL_HEAD_KEY, bytes.as_slice())]
    {
        return Err(StorageLiveExportRequestTrustErrorV1::Custody);
    }
    Ok(())
}

fn validate_transition(
    previous: &[u8; RECORD_BYTES],
    next_generation: u64,
) -> Result<(), StorageLiveExportRequestTrustErrorV1> {
    let old = parse_trust(previous)?;
    if next_generation
        != old
            .generation
            .checked_add(1)
            .ok_or(StorageLiveExportRequestTrustErrorV1::InvalidRecord)?
    {
        return Err(StorageLiveExportRequestTrustErrorV1::Custody);
    }
    Ok(())
}

const fn journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 1024 * 1024,
        // Journal's record bound includes its seven-byte framing and the
        // fixed head key, not only the canonical trust value.
        maximum_record_bytes: JOURNAL_HEAD_RECORD_BYTES,
        maximum_key_bytes: 64,
        maximum_records_per_transaction: 1,
        maximum_transaction_bytes: 1024,
        maximum_transactions: 256,
        maximum_materialized_bytes: RECORD_BYTES + 64,
        maximum_materialized_records: 1,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use ed25519_dalek::SigningKey;

    use super::*;

    pub(super) fn fixture() -> [u8; RECORD_BYTES] {
        let provider_key = SigningKey::from_bytes(&[17; 32]);
        let root_key = SigningKey::from_bytes(&[18; 32]);
        let mut bytes = [0; RECORD_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
        bytes[16..24].copy_from_slice(&1_u64.to_be_bytes());
        for (offset, authority, key, seed) in
            [(24, 21, &provider_key, 25), (168, 31, &root_key, 35)]
        {
            bytes[offset..offset + 16].fill(authority);
            bytes[offset + 16..offset + 24].copy_from_slice(&1_u64.to_be_bytes());
            bytes[offset + 24..offset + 56].fill(authority + 1);
            bytes[offset + 56..offset + 72].fill(seed);
            bytes[offset + 72..offset + 80].copy_from_slice(&1_u64.to_be_bytes());
            bytes[offset + 80..offset + 112]
                .copy_from_slice(&Sha256::digest(key.verifying_key().as_bytes()));
            bytes[offset + 112..offset + 144].copy_from_slice(key.verifying_key().as_bytes());
        }
        bytes
    }

    #[test]
    fn trust_record_pins_distinct_root_and_provider_keys() {
        let bytes = fixture();
        let trust = parse_trust(&bytes).unwrap();
        assert_eq!(trust.generation, 1);
        assert_ne!(trust.provider_public_key, trust.root_public_key);
        assert_eq!(
            trust.provider_signer.usage(),
            SourceProviderKeyUsageV1::ProviderOutcome
        );
        assert_eq!(
            trust.root_signer.usage(),
            SourceProviderKeyUsageV1::RootMountRecord
        );
    }

    #[test]
    fn malformed_or_substituted_trust_fails_closed() {
        let original = fixture();
        for index in [0, 9, 10, 23, 104, 136, 248, 280] {
            let mut changed = original;
            changed[index] ^= 1;
            assert!(parse_trust(&changed).is_err(), "changed byte {index}");
        }
        let mut same_authority = original;
        same_authority[168..184].copy_from_slice(&original[24..40]);
        assert!(parse_trust(&same_authority).is_err());
    }

    #[test]
    fn trust_generation_requires_one_step_and_rejects_rollback() {
        let original = fixture();
        assert!(validate_transition(&original, 2).is_ok());
        assert!(validate_transition(&original, 1).is_err());
        assert!(validate_transition(&original, 3).is_err());

        let mut successor = original;
        successor[16..24].copy_from_slice(&2_u64.to_be_bytes());
        assert!(validate_transition(&successor, 1).is_err());
    }

    #[test]
    fn protected_trust_readback_rejects_mode_and_replacement() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let trust_path = directory.path().join(TRUST_FILE);
        fs::write(&trust_path, fixture()).unwrap();
        fs::set_permissions(&trust_path, fs::Permissions::from_mode(0o600)).unwrap();

        let descriptor = rustix::fs::open(
            directory.path(),
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let owner = rustix::fs::fstat(&descriptor).unwrap().st_uid;
        let (bytes, device, inode) = read_trust(&descriptor, owner).unwrap();
        assert_eq!(bytes, fixture());

        fs::set_permissions(&trust_path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            read_trust(&descriptor, owner),
            Err(StorageLiveExportRequestTrustErrorV1::Custody)
        ));

        let replacement = directory.path().join("replacement");
        fs::write(&replacement, fixture()).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(&replacement, &trust_path).unwrap();
        let (_, replaced_device, replaced_inode) = read_trust(&descriptor, owner).unwrap();
        assert_ne!((device, inode), (replaced_device, replaced_inode));
    }

    #[test]
    fn native_trust_journal_admits_exact_head_record_and_replays() {
        let directory = tempfile::tempdir().unwrap();
        let trust = StorageLiveExportRequestTrustV1::native_fixture_for_test(directory.path());
        trust.validate_current().unwrap();
        assert_eq!(
            journal_limits().maximum_record_bytes,
            JOURNAL_RECORD_FRAMING_BYTES + JOURNAL_HEAD_KEY.len() + trust.bytes.len()
        );
        let original = trust.bytes;
        drop(trust);

        let recovered = StorageLiveExportRequestTrustV1::native_fixture_for_test(directory.path());
        recovered.validate_current().unwrap();
        assert_eq!(recovered.bytes, original);
    }

    #[test]
    fn native_trust_one_byte_short_record_budget_refuses_first_head() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let owner = fs::metadata(directory.path()).unwrap().uid();
        let mut too_short = journal_limits();
        too_short.maximum_record_bytes -= 1;
        let (mut journal, _) =
            Journal::open_protected_at_uid(directory.path(), JOURNAL_FILE, too_short, owner)
                .unwrap();
        let bytes = fixture();

        assert_eq!(
            reconcile_head(&mut journal, &bytes, 1),
            Err(StorageLiveExportRequestTrustErrorV1::Custody)
        );
        assert!(
            journal
                .get(RecordNamespace::AuthorityPublication, JOURNAL_HEAD_KEY)
                .is_none()
        );
        drop(journal);

        let (mut reopened, _) =
            Journal::open_protected_at_uid(directory.path(), JOURNAL_FILE, journal_limits(), owner)
                .unwrap();
        reconcile_head(&mut reopened, &bytes, 1).unwrap();
        assert_eq!(
            reopened.get(RecordNamespace::AuthorityPublication, JOURNAL_HEAD_KEY),
            Some(bytes.as_slice())
        );
    }
}
