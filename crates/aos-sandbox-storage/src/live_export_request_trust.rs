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

use std::os::fd::{AsFd as _, OwnedFd};
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

use crate::live_export_key::open_protected_directory;
use crate::live_export_key::initial_read::{
    ProtectedExportDirectoryOriginalV1, ProtectedExportFileOriginalV1,
};

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
        self.validate_current_with_originals(None)
    }

    fn validate_current_with_originals(
        &self,
        mut originals: Option<&mut TrustCurrentOriginalV1>,
    ) -> Result<(), StorageLiveExportRequestTrustErrorV1> {
        // Keep ordinary fresh-directory custody through the entire method, as
        // before. The selected destination retains the same native recipe.
        let mut ordinary_directory = None;
        let identity = if let Some(originals) = originals.as_deref_mut() {
            originals.directory.capture_once(&self.directory_path, self.expected_owner)
                .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
            let directory = originals.directory.descriptor()
                .ok_or(StorageLiveExportRequestTrustErrorV1::Custody)?;
            originals.identity = Some(rustix::fs::fstat(directory));
            *originals.identity.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(StorageLiveExportRequestTrustErrorV1::Custody)?
        } else {
            ordinary_directory = Some(self.reopen_directory()?);
            rustix::fs::fstat(ordinary_directory.as_ref()
                .ok_or(StorageLiveExportRequestTrustErrorV1::Custody)?)
                .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?
        };
        if (identity.st_dev, identity.st_ino) != (self.directory_device, self.directory_inode) {
            return Err(StorageLiveExportRequestTrustErrorV1::Custody);
        }
        if let Some(originals) = originals.as_deref_mut() {
            originals.names = Some(self.journal.validate_held_protected_names_retaining(
                &mut originals.names_originals,
            ));
            originals.names.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(StorageLiveExportRequestTrustErrorV1::Custody)?;
        } else {
            self.journal.validate_held_protected_names()
                .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
        }
        let (bytes, device, inode) = if let Some(originals) = originals.as_deref_mut() {
            originals.file.capture_once(self.directory.as_fd(), TRUST_FILE, self.expected_owner)
                .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
            originals.file.record().map(|(bytes, device, inode)| (*bytes, device, inode))
                .ok_or(StorageLiveExportRequestTrustErrorV1::Custody)?
        } else {
            read_trust(&self.directory, self.expected_owner)?
        };
        if (device, inode) != (self.file_device, self.file_inode)
            || bytes != self.bytes
            || parse_trust(&bytes)? != self.record
            || self.journal.get(RecordNamespace::AuthorityPublication, JOURNAL_HEAD_KEY)
                != Some(self.bytes.as_slice())
        {
            return Err(StorageLiveExportRequestTrustErrorV1::Custody);
        }
        // Explicitly keep the ordinary directory until the old success boundary.
        drop(ordinary_directory);
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
    let mut original = ProtectedExportFileOriginalV1::<RECORD_BYTES>::new();
    original.capture_once(directory.as_fd(), TRUST_FILE, expected_owner)
        .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
    original.record().map(|(bytes, device, inode)| (*bytes, device, inode))
        .ok_or(StorageLiveExportRequestTrustErrorV1::Custody)
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

/// Retains the selected Trust opening and every reached initialization result.
///
/// The actual Construction keeps this attempt on failure. Only a complete
/// positive result can move its Journal into the ordinary Trust owner.
pub(crate) struct StorageLiveExportRequestTrustOpenV1 {
    native: Option<aos_sandbox::journal::StorageRequestTrustCapturedJournalOpenV1>,
    opened: Option<(Journal, aos_sandbox::RecoveryReport)>,
    directory: ProtectedExportDirectoryOriginalV1,
    identity: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    file: ProtectedExportFileOriginalV1<RECORD_BYTES>,
    directory_post: ProtectedExportDirectoryOriginalV1,
    directory_post_identity: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    current_originals: TrustCurrentOriginalV1,
    read: Option<Result<([u8; RECORD_BYTES], u64, u64), StorageLiveExportRequestTrustErrorV1>>,
    record: Option<Result<TrustRecordV1, StorageLiveExportRequestTrustErrorV1>>,
    fixed_demand: Option<Result<aos_sandbox_core::ResourceVector, aos_sandbox_core::AccountingError>>,
    schema_demand: Option<Result<aos_sandbox_core::ResourceVector, aos_sandbox_core::AccountingError>>,
    initialization_demand: Option<Result<aos_sandbox_core::ResourceVector, aos_sandbox_core::AccountingError>>,
    receiving: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
    directory_current: Option<Result<(), StorageLiveExportRequestTrustErrorV1>>,
    writer_directory: Option<Result<
        aos_sandbox_journal::protected_storage::OriginalFileMetadataV1, aos_sandbox::JournalError,
    >>,
    head: TrustHeadReconciliationV1,
    current: Option<Result<(), StorageLiveExportRequestTrustErrorV1>>,
    result: Option<Result<(), StorageLiveExportRequestTrustErrorV1>>,
    ready: Option<StorageLiveExportRequestTrustV1>,
    attempted: bool,
    taken: bool,
    closed: Option<StorageLiveExportRequestTrustErrorV1>,
}

impl StorageLiveExportRequestTrustOpenV1 {
    /// Creates empty custody without a path, descriptor or receiving grant.
    pub(crate) fn new() -> Self {
        Self {
            native: Some(aos_sandbox::journal::StorageRequestTrustCapturedJournalOpenV1::new()),
            opened: None,
            directory: ProtectedExportDirectoryOriginalV1::new(),
            identity: None,
            file: ProtectedExportFileOriginalV1::new(),
            directory_post: ProtectedExportDirectoryOriginalV1::new(),
            directory_post_identity: None,
            current_originals: TrustCurrentOriginalV1::new(),
            read: None,
            record: None,
            fixed_demand: None,
            schema_demand: None,
            initialization_demand: None,
            receiving: None,
            directory_current: None,
            writer_directory: None,
            head: TrustHeadReconciliationV1::new(),
            current: None,
            result: None,
            ready: None,
            attempted: false,
            taken: false,
            closed: None,
        }
    }

    /// Opens only the same original Storage authority directory once.
    ///
    /// # Errors
    /// Retains original receiving, native, schema and initialization failures.
    /// A refusal never falls back to the ordinary unpriced opener.
    pub(crate) fn open_once_v1(
        &mut self,
        receiving: &mut aos_sandbox::StoragePrepareReceivingLoanV1<'_>,
        directory_path: &Path,
    ) -> Result<(), StorageLiveExportRequestTrustErrorV1> {
        if self.attempted {
            self.closed.get_or_insert(StorageLiveExportRequestTrustErrorV1::Custody);
            return Err(StorageLiveExportRequestTrustErrorV1::Custody);
        }
        self.attempted = true;
        self.result = Some(self.open_selected(receiving, directory_path));
        self.result
            .as_ref()
            .copied()
            .ok_or(StorageLiveExportRequestTrustErrorV1::Custody)?
    }

    fn open_selected(
        &mut self,
        receiving: &mut aos_sandbox::StoragePrepareReceivingLoanV1<'_>,
        directory_path: &Path,
    ) -> Result<(), StorageLiveExportRequestTrustErrorV1> {
        use aos_sandbox::journal::CapturedJournalOpenModeV1;

        self.fixed_demand = Some(Self::fixed_demand(directory_path));
        let fixed = *self.fixed_demand.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(StorageLiveExportRequestTrustErrorV1::Custody)?;
        self.receiving = Some(receiving.require_storage_authority_directory_v1(directory_path));
        require_receiving(self.receiving.as_ref())?;
        self.receiving = Some(receiving.reserve_trust_configuration_once_v1(fixed));
        require_receiving(self.receiving.as_ref())?;

        // Preserve the old fixed-file/parse-before-Journal preparation order.
        // This record has no repeated or unbounded semantic carrier.
        self.directory.capture_once(directory_path, 0)
            .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
        let directory = self.directory.descriptor()
            .ok_or(StorageLiveExportRequestTrustErrorV1::Custody)?;
        self.identity = Some(rustix::fs::fstat(directory));
        let identity = self.identity.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(StorageLiveExportRequestTrustErrorV1::Custody)?;
        let directory_identity = (identity.st_dev, identity.st_ino);
        self.file.capture_once(directory.as_fd(), TRUST_FILE, 0)
            .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
        self.read = Some(self.file.record().map(|(bytes, device, inode)| (*bytes, device, inode))
            .ok_or(StorageLiveExportRequestTrustErrorV1::Custody));
        let (bytes, file_device, file_inode) = *self.read.as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(StorageLiveExportRequestTrustErrorV1::Custody)?;
        self.record = Some(parse_trust(&bytes));
        let generation = self.record.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(StorageLiveExportRequestTrustErrorV1::InvalidRecord)?.generation;

        // End the complete borrowed Result reservoir with its actual guard
        // before later independent currentness borrows the same receiving loan.
        {
            let native = self.native.as_mut().ok_or(StorageLiveExportRequestTrustErrorV1::Custody)?;
            let borrowed = receiving.borrow_trust_startup_once_v1(native);
            let mut guard = match borrowed {
                Ok(guard) => guard,
                Err(error) => {
                    self.receiving = Some(Err(error));
                    return Err(StorageLiveExportRequestTrustErrorV1::Custody);
                }
            };
            self.receiving = Some(guard.prepare_once_v1(
                journal_limits(), CapturedJournalOpenModeV1::CreateAndRepair,
            ));
            require_receiving(self.receiving.as_ref())?;
            let extent = guard.captured_extent_v1().copied()
                .ok_or(StorageLiveExportRequestTrustErrorV1::Custody)?;

            // Both results are parked while this same prefix is still borrowable.
            // Native replay/semantic demand is paid separately inside the guard.
            self.schema_demand = Some(trust_schema_demand(&extent));
            self.initialization_demand = Some(trust_initialization_demand(&extent));
            let schema = *self.schema_demand.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(StorageLiveExportRequestTrustErrorV1::Custody)?;
            let initialization = *self.initialization_demand.as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(StorageLiveExportRequestTrustErrorV1::Custody)?;
            self.receiving = Some(guard.reserve_schema_once_v1(schema));
            require_receiving(self.receiving.as_ref())?;
            self.receiving = Some(guard.replay_once_v1());
            require_receiving(self.receiving.as_ref())?;
            self.receiving = Some(guard.reserve_initialization_once_v1(initialization));
            require_receiving(self.receiving.as_ref())?;
            match guard.take_opened_once_v1() {
                Ok(opened) => self.opened = Some(opened),
                Err(error) => {
                    self.receiving = Some(Err(error));
                    return Err(StorageLiveExportRequestTrustErrorV1::Custody);
                }
            }
            drop(guard);
        }

        // Join the earlier Trust-file directory to the Native writer's current
        // named directory before initialization. Its own append names still
        // perform their independent final check.
        self.directory_current = Some(require_original_trust_directory(
            directory_path, directory_identity, &mut self.directory_post,
            &mut self.directory_post_identity,
        ));
        self.directory_current.as_ref().copied()
            .ok_or(StorageLiveExportRequestTrustErrorV1::Custody)??;
        let journal = &mut self.opened.as_mut()
            .ok_or(StorageLiveExportRequestTrustErrorV1::Custody)?.0;
        // Compare the two actual held owners directly. A pathname can move
        // A-to-B-to-A between independent observations; matching fresh paths alone
        // cannot join the initial Trust File to this Native Journal directory.
        require_same_trust_writer_directory(journal, directory_identity, &mut self.writer_directory)?;
        let initialized = self.head.run_once(journal, &bytes, generation, true);
        self.receiving = Some(receiving.require_storage_authority_directory_v1(directory_path));
        initialized?;
        require_receiving(self.receiving.as_ref())?;

        let directory = self.directory.take_descriptor()
            .ok_or(StorageLiveExportRequestTrustErrorV1::Custody)?;
        let record = self.record.take().and_then(Result::ok)
            .ok_or(StorageLiveExportRequestTrustErrorV1::InvalidRecord)?;
        let (journal, _) = self.opened.take()
            .ok_or(StorageLiveExportRequestTrustErrorV1::Custody)?;
        self.ready = Some(StorageLiveExportRequestTrustV1 {
            journal,
            directory,
            directory_path: directory_path.to_path_buf(),
            directory_device: directory_identity.0,
            directory_inode: directory_identity.1,
            file_device,
            file_inode,
            bytes,
            record,
            expected_owner: 0,
            #[cfg(test)]
            synthetic_directory: false,
        });
        self.current = Some(self.ready.as_ref()
            .ok_or(StorageLiveExportRequestTrustErrorV1::Custody)?
            .validate_current_with_originals(Some(&mut self.current_originals)));
        self.receiving = Some(receiving.require_storage_authority_directory_v1(directory_path));
        self.current.as_ref().copied()
            .ok_or(StorageLiveExportRequestTrustErrorV1::Custody)??;
        require_receiving(self.receiving.as_ref())
    }

    /// Disposes only this same completed facade after the real Trust posts.
    pub(crate) fn settle_native_once_v1(
        &mut self,
        receiving: &mut aos_sandbox::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<(), StorageLiveExportRequestTrustErrorV1> {
        if self.taken || self.closed.is_some() || !matches!(self.result, Some(Ok(()))) {
            return Err(StorageLiveExportRequestTrustErrorV1::Custody);
        }
        let native = self.native.take().ok_or(StorageLiveExportRequestTrustErrorV1::Custody)?;
        if let Err(native) = receiving.settle_trust_native_opening_once_v1(native) {
            self.native = Some(native);
            self.closed = Some(StorageLiveExportRequestTrustErrorV1::Custody);
            return Err(StorageLiveExportRequestTrustErrorV1::Custody);
        }
        self.directory.settle_positive();
        self.file.settle_positive();
        self.directory_post.settle_positive();
        self.current_originals.settle_positive();
        Ok(())
    }

    /// Moves only the complete same-original positive Trust owner once.
    pub(crate) fn take_trust_once_v1(&mut self) -> Option<StorageLiveExportRequestTrustV1> {
        if self.taken || self.closed.is_some() || self.native.is_some()
            || !matches!(self.result, Some(Ok(())))
        {
            return None;
        }
        self.taken = true;
        self.ready.take()
    }

    /// Borrows the original first cause while all later reached debt stays held.
    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.fixed_demand.as_ref().and_then(|value| value.as_ref().err())
            .map(|error| error as &(dyn std::error::Error + 'static))
            .or_else(|| self.directory.failure())
            .or_else(|| self.identity.as_ref().and_then(|value| value.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.file.failure())
            .or_else(|| self.read.as_ref().and_then(|value| value.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.record.as_ref().and_then(|value| value.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.native.as_ref().and_then(|native| native.failure()))
            .or_else(|| self.schema_demand.as_ref().and_then(|value| value.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.initialization_demand.as_ref().and_then(|value| value.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.directory_post.failure())
            .or_else(|| self.directory_post_identity.as_ref().and_then(|value| value.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.directory_current.as_ref().and_then(|value| value.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.writer_directory.as_ref().and_then(|value| value.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.head.failure())
            .or_else(|| self.current_originals.failure())
            .or_else(|| self.current.as_ref().and_then(|value| value.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.receiving.as_ref().and_then(|value| value.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.result.as_ref().and_then(|value| value.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.closed.as_ref()
                .map(|error| error as &(dyn std::error::Error + 'static)))
    }

    fn fixed_demand(directory: &Path)
        -> Result<aos_sandbox_core::ResourceVector, aos_sandbox_core::AccountingError>
    {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
        use crate::receiving_demand::{add, count, multiply};

        let ancestors = count(directory.ancestors().count())?;
        let paths = multiply(count(directory.as_os_str().len())?, 4)?;
        let step = count(ProtectedExportDirectoryOriginalV1::step_memory_bytes())?;
        let carriers = multiply(ancestors, add(multiply(6, step)?,
            multiply(6, count(std::mem::size_of::<&Path>())?)?)?)?;
        let crypto = multiply(8, count(std::mem::size_of::<TrustRecordV1>()
            + std::mem::size_of::<VerifyingKey>())?)?;
        let memory = add(count(std::mem::size_of::<Self>())?, add(paths, add(carriers, crypto)?)?)?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, add(memory, 64 * 1024)?)
            .with(D::OpenFiles, add(multiply(3, ancestors)?, 4)?)
            .with(D::MetadataEntries, add(multiply(9, ancestors)?, 26)?))
    }
}

fn require_receiving(
    result: Option<&Result<(), aos_sandbox::StorageReceivingClosedV1>>,
) -> Result<(), StorageLiveExportRequestTrustErrorV1> {
    if matches!(result, Some(Ok(()))) {
        Ok(())
    } else {
        Err(StorageLiveExportRequestTrustErrorV1::Custody)
    }
}

fn trust_schema_demand(
    extent: &aos_sandbox::journal::ProtectedJournalPreopenReplayExtentV1,
) -> Result<aos_sandbox_core::ResourceVector, aos_sandbox_core::AccountingError> {
    use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
    use crate::receiving_demand::{add, count, multiply};

    // The actual supplied limits admit one materialized record. The selected
    // head has exactly 312 bytes; no protobuf/JSON model is decoded here.
    let previous = extent.native_bytes.min(count(RECORD_BYTES)?);
    let models = multiply(4, count(std::mem::size_of::<TrustRecordV1>())?)?;
    let records = multiply(16, count(std::mem::size_of::<(&[u8], &[u8])>())?)?;
    Ok(ResourceVector::ZERO
        .with(D::MemoryBytes, add(multiply(previous, 4)?, add(models, records)?)?)
        .with(D::MetadataEntries, 4))
}

fn trust_initialization_demand(
    extent: &aos_sandbox::journal::ProtectedJournalPreopenReplayExtentV1,
) -> Result<aos_sandbox_core::ResourceVector, aos_sandbox_core::AccountingError> {
    use aos_sandbox_core::{AccountingError, ResourceDimension as D, ResourceVector};
    use aos_sandbox_journal::geometry::{RecordShape, encoded_transaction_append_bytes};
    use crate::receiving_demand::{add, count, multiply};

    // Measure lengths only. A pretend transaction must not allocate before
    // the real receiving debit. Reconciliation can append at most this head.
    let append = encoded_transaction_append_bytes([RecordShape {
        key_bytes: JOURNAL_HEAD_KEY.len(),
        value_bytes: Some(RECORD_BYTES),
    }].into_iter()).map_err(|_| AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
    let cells = count(std::mem::size_of::<JournalRecord>()
        + std::mem::size_of::<JournalTransaction>())?;
    let memory = add(multiply(extent.native_bytes, 16)?,
        add(multiply(append, 16)?, add(multiply(cells, 8)?, 64 * 1024)?)?)?;
    Ok(ResourceVector::ZERO.with(D::MemoryBytes, memory)
        .with(D::StorageBytes, append).with(D::MetadataEntries, 32))
}

fn require_original_trust_directory(
    directory_path: &Path,
    expected: (u64, u64),
    original: &mut ProtectedExportDirectoryOriginalV1,
    identity: &mut Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
) -> Result<(), StorageLiveExportRequestTrustErrorV1> {
    original.capture_once(directory_path, 0)
        .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
    let directory = original.descriptor().ok_or(StorageLiveExportRequestTrustErrorV1::Custody)?;
    *identity = Some(rustix::fs::fstat(directory));
    let identity = identity.as_ref().and_then(|result| result.as_ref().ok())
        .ok_or(StorageLiveExportRequestTrustErrorV1::Custody)?;
    if (identity.st_dev, identity.st_ino) != expected {
        return Err(StorageLiveExportRequestTrustErrorV1::Custody);
    }
    Ok(())
}

fn require_same_trust_writer_directory(
    journal: &Journal,
    expected: (u64, u64),
    original: &mut Option<Result<
        aos_sandbox_journal::protected_storage::OriginalFileMetadataV1, aos_sandbox::JournalError,
    >>,
) -> Result<(), StorageLiveExportRequestTrustErrorV1> {
    if original.is_some() {
        return Err(StorageLiveExportRequestTrustErrorV1::Custody);
    }
    *original = Some(journal.observe_held_protected_directory_metadata_v1());
    let actual = original.as_ref().and_then(|result| result.as_ref().ok())
        .ok_or(StorageLiveExportRequestTrustErrorV1::Custody)?;
    if (actual.0, actual.1) != expected {
        return Err(StorageLiveExportRequestTrustErrorV1::Custody);
    }
    Ok(())
}

struct TrustCurrentOriginalV1 {
    directory: ProtectedExportDirectoryOriginalV1,
    identity: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    names_originals: aos_sandbox::journal::ProtectedJournalCurrentnessOriginalsV1,
    names: Option<Result<(), aos_sandbox::JournalError>>,
    file: ProtectedExportFileOriginalV1<RECORD_BYTES>,
}

impl TrustCurrentOriginalV1 {
    fn new() -> Self {
        Self {
            directory: ProtectedExportDirectoryOriginalV1::new(),
            identity: None,
            names_originals: aos_sandbox::journal::ProtectedJournalCurrentnessOriginalsV1::new(),
            names: None,
            file: ProtectedExportFileOriginalV1::new(),
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.directory.failure()
            .or_else(|| self.identity.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.names_originals.failure())
            .or_else(|| self.names.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.file.failure())
    }

    fn settle_positive(&mut self) {
        self.directory.settle_positive();
        self.names_originals.settle_positive_once_v1();
        self.file.settle_positive();
    }
}

// One initializer serves the ordinary short-lived sink and the selected
// retained attempt. The selected path keeps actual append/readback debt.
struct TrustHeadReconciliationV1 {
    before_error: Option<aos_sandbox::JournalError>,
    transaction: Option<Result<JournalTransaction,
        aos_sandbox_protocol::domain_ledger::JournalTransactionDataError>>,
    native: Option<Result<aos_sandbox::CommitResult, aos_sandbox::JournalError>>,
    readback: Option<Result<bool, aos_sandbox::JournalError>>,
    result: Option<Result<(), StorageLiveExportRequestTrustErrorV1>>,
}

impl TrustHeadReconciliationV1 {
    fn new() -> Self {
        Self {
            before_error: None,
            transaction: None,
            native: None,
            readback: None,
            result: None,
        }
    }

    fn run_once(
        &mut self,
        journal: &mut Journal,
        bytes: &[u8; RECORD_BYTES],
        generation: u64,
        readback_after_native_failure: bool,
    ) -> Result<(), StorageLiveExportRequestTrustErrorV1> {
        if self.result.is_some() {
            return Err(StorageLiveExportRequestTrustErrorV1::Custody);
        }
        self.result = Some(self.reconcile(journal, bytes, generation, readback_after_native_failure));
        self.result.as_ref().copied()
            .ok_or(StorageLiveExportRequestTrustErrorV1::Custody)?
    }

    fn reconcile(
        &mut self,
        journal: &mut Journal,
        bytes: &[u8; RECORD_BYTES],
        generation: u64,
        readback_after_native_failure: bool,
    ) -> Result<(), StorageLiveExportRequestTrustErrorV1> {
        let mut authority = match journal.claim_protected_authority(RecordNamespace::AuthorityPublication) {
            Ok(authority) => authority,
            Err(error) => {
                if readback_after_native_failure {
                    self.before_error = Some(error);
                }
                return Err(StorageLiveExportRequestTrustErrorV1::Custody);
            }
        };
        let previous = match authority.get(JOURNAL_HEAD_KEY) {
            Ok(previous) => previous.map(ToOwned::to_owned),
            Err(error) => {
                if readback_after_native_failure {
                    self.before_error = Some(error);
                }
                return Err(StorageLiveExportRequestTrustErrorV1::Custody);
            }
        };
        let needs_commit = match previous {
            None => {
                let empty = match authority.is_materialized_empty() {
                    Ok(empty) => empty,
                    Err(error) => {
                        if readback_after_native_failure {
                            self.before_error = Some(error);
                        }
                        return Err(StorageLiveExportRequestTrustErrorV1::Custody);
                    }
                };
                if !empty || generation != 1 {
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
            self.transaction = Some(JournalTransaction::new(
                transaction_id,
                vec![JournalRecord::put(
                    RecordNamespace::AuthorityPublication,
                    JOURNAL_HEAD_KEY.to_vec(),
                    bytes.to_vec(),
                )],
            ));
            if !readback_after_native_failure
                && self.transaction.as_ref().is_some_and(Result::is_err)
            {
                drop(self.transaction.take());
                return Err(StorageLiveExportRequestTrustErrorV1::Custody);
            }
            let transaction = self.transaction.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(StorageLiveExportRequestTrustErrorV1::Custody)?;
            self.native = Some(authority.commit(transaction));
            if !readback_after_native_failure {
                // The ordinary sink keeps its former short-lived transaction
                // and coarse error projection before the readback frontier.
                let result = self.native.take()
                    .ok_or(StorageLiveExportRequestTrustErrorV1::Custody)?
                    .map(|_| ())
                    .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody);
                drop(self.transaction.take());
                result?;
            }
        }

        // In the selected attempt this is independent even after append error.
        // The earlier whole native result remains the first cause.
        self.readback = Some(authority.records().map(|records| {
            records.collect::<Vec<_>>() == vec![(JOURNAL_HEAD_KEY, bytes.as_slice())]
        }));
        if !readback_after_native_failure {
            let exact = self.readback.take()
                .ok_or(StorageLiveExportRequestTrustErrorV1::Custody)?
                .map_err(|_| StorageLiveExportRequestTrustErrorV1::Custody)?;
            return if exact { Ok(()) } else { Err(StorageLiveExportRequestTrustErrorV1::Custody) };
        }
        if self.native.as_ref().is_some_and(Result::is_err)
            || !matches!(self.readback, Some(Ok(true)))
        {
            return Err(StorageLiveExportRequestTrustErrorV1::Custody);
        }
        Ok(())
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.before_error.as_ref()
            .map(|error| error as &(dyn std::error::Error + 'static))
            .or_else(|| self.transaction.as_ref().and_then(|value| value.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.native.as_ref().and_then(|value| value.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.readback.as_ref().and_then(|value| value.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.result.as_ref().and_then(|value| value.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
    }
}

fn reconcile_head(
    journal: &mut Journal,
    bytes: &[u8; RECORD_BYTES],
    generation: u64,
) -> Result<(), StorageLiveExportRequestTrustErrorV1> {
    TrustHeadReconciliationV1::new().run_once(journal, bytes, generation, false)
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

#[cfg(test)]
mod held_directory_join_tests {
    use super::*;

    #[test]
    fn distinct_actual_trust_and_journal_directories_cannot_join() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let trust = StorageLiveExportRequestTrustV1::native_fixture_for_test(first.path());
        let other = StorageLiveExportRequestTrustV1::native_fixture_for_test(second.path());
        let expected = (trust.directory_device, trust.directory_inode);
        let mut rejected = None;
        let before = std::fs::read(second.path().join(JOURNAL_FILE)).unwrap();

        assert!(require_same_trust_writer_directory(&other.journal, expected, &mut rejected).is_err());
        let observed = rejected.as_ref().unwrap().as_ref().unwrap();
        assert_ne!((observed.0, observed.1), expected);
        assert_eq!(std::fs::read(second.path().join(JOURNAL_FILE)).unwrap(), before);

        let mut matched = None;
        require_same_trust_writer_directory(&trust.journal, expected, &mut matched).unwrap();
        let original = matched.as_ref().unwrap().as_ref().unwrap();
        assert_eq!((original.0, original.1), expected);
        assert!(require_same_trust_writer_directory(&other.journal, expected, &mut matched).is_err());
        assert_eq!((matched.as_ref().unwrap().as_ref().unwrap().0,
            matched.as_ref().unwrap().as_ref().unwrap().1), expected);
    }
}
