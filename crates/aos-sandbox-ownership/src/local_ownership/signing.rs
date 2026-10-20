//! Holds the fixed daemon credential and signs only a borrowed durable intent.
//!
//! There is no key, descriptor, path or signing callback supplied by a request.
//! The parent joins the retained credential with its same protected bootstrap.

use std::fs::File;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use aos_sandbox_core::format::{encode_ownership_lease, encode_signature};
use aos_sandbox_core::model::{KeyReference, SignatureStatement};
use aos_sandbox_core::{
    ObjectDescriptor, OwnershipLease, SignatureVerificationError, TrustScopeId,
    sign_statement,
};
use crate::PendingOwnershipCompletion;
use ed25519_dalek::SigningKey;
use rustix::fs::{Stat, fstat};

use super::*;

#[derive(Clone, Copy)]
enum CredentialRole {
    SigningKey,
    Node,
}

impl CredentialRole {
    fn name(self) -> &'static str {
        match self {
            Self::SigningKey => "ownership-signing-key",
            Self::Node => "node-id",
        }
    }

    fn bytes(self) -> usize {
        match self {
            Self::SigningKey => 32,
            Self::Node => 16,
        }
    }
}

struct FixedCredential<const BYTES: usize> {
    read: aos_sandbox_linux::credential::FixedRoleCredentialReadV1,
    before_binding: Result<(), LocalSigningUnavailable>,
    after: Option<Result<Stat, rustix::io::Errno>>,
    binding: Result<(), LocalSigningUnavailable>,
}

impl<const BYTES: usize> FixedCredential<BYTES> {
    fn capture(role: CredentialRole) -> Self {
        use aos_sandbox_linux::credential::{CredentialOwnerPolicyV1, FixedRoleCredentialReadV1};

        let mut original = Self {
            read: FixedRoleCredentialReadV1::prearmed(),
            before_binding: Err(LocalSigningUnavailable),
            after: None,
            binding: Err(LocalSigningUnavailable),
        };
        original.read.read_once(
            Path::new("/run/credentials/aos-sandbox-ownershipd.service"),
            role.name(), role.bytes(), role.bytes(), true, CredentialOwnerPolicyV1::Root,
        );
        let view = original.read.view();
        original.before_binding = if BYTES == role.bytes()
            && view.metadata.and_then(|result| result.as_ref().ok())
                .is_some_and(|metadata| metadata.uid() == 0)
            && matches!(original.read.outcome(), Some(Ok(Some(_))))
        { Ok(()) } else { Err(LocalSigningUnavailable) };
        if let Some(Ok(file)) = view.open {
            original.after = Some(fstat(file));
        }
        original.binding = if original.before_binding.is_ok()
            && view.metadata.and_then(|result| result.as_ref().ok())
                .zip(original.after.as_ref().and_then(|result| result.as_ref().ok()))
                .is_some_and(|(before, after)| credential_stat(after, BYTES)
                    && same_metadata(before, after))
        { Ok(()) } else { Err(LocalSigningUnavailable) };
        original
    }

    fn bytes(&self) -> Option<&[u8; BYTES]> {
        self.binding.as_ref().ok()?;
        self.read.outcome()?.ok()??.as_slice().try_into().ok()
    }

    fn file(&self) -> Option<&File> {
        self.read.view().open?.as_ref().ok()
    }

    fn metadata(&self) -> Option<&std::fs::Metadata> {
        self.read.view().metadata?.as_ref().ok()
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.read.failure()
            .or_else(|| self.before_binding.as_ref().err()
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.after.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.binding.as_ref().err()
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
    }
}

pub(crate) struct LocalOwnershipSigningOriginalV1 {
    credential: FixedCredential<32>,
    node_credential: FixedCredential<16>,
    binding: Result<(), LocalSigningUnavailable>,
    key: Option<SigningKey>,
    authority: KeyReference,
    scope: TrustScopeId,
    policy: ObjectDescriptor,
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("the original local ownership signing credential is unavailable")]
pub(crate) struct LocalSigningUnavailable;

impl LocalOwnershipSigningOriginalV1 {
    pub(super) fn capture(
        public_key: [u8; 32],
        authority: KeyReference,
        scope: TrustScopeId,
        policy: ObjectDescriptor,
    ) -> Self {
        let mut original = Self {
            credential: FixedCredential::capture(CredentialRole::SigningKey),
            node_credential: FixedCredential::capture(CredentialRole::Node),
            binding: Err(LocalSigningUnavailable), key: None, authority, scope, policy,
        };
        let positive = original.credential.bytes().zip(original.node_credential.bytes())
            .and_then(|(seed, node)| {
                if *seed == [0; 32] || *node == [0; 16] { return None; }
                let key = SigningKey::from_bytes(seed);
                (key.verifying_key().to_bytes() == public_key).then_some(key)
            });
        if let Some(key) = positive {
            original.key = Some(key);
            original.binding = Ok(());
        }
        original
    }

    pub(super) fn require_open(&self) -> Result<(), LocalSigningUnavailable> {
        self.binding
    }

    pub(super) fn require_local_claim(&self, claim: &OwnershipClaimV1) -> Result<(), LocalSigningUnavailable> {
        self.require_open()?;
        if original_node(self) != Some(*claim.node().as_bytes()) {
            return Err(LocalSigningUnavailable);
        }
        Ok(())
    }

    pub(crate) fn sign_pending(
        &self,
        pending: &PendingOwnershipCompletion<'_>,
        clock: RawPairedClockSample,
        nonce: [u8; 16],
    ) -> Result<UnverifiedOwnershipLeaseResponse, LocalSigningError> {
        self.require_open()?;
        let key = self.key.as_ref().ok_or(LocalSigningUnavailable)?;
        let claim = pending.claim();
        self.require_local_claim(claim)?;
        let generation = match claim.expected_prior() {
            None if claim.action() == aos_sandbox_ownership_protocol::OwnershipClaimAction::Acquire => 1,
            Some(prior) => prior.generation().checked_add(1).ok_or(LocalSigningUnavailable)?,
            None => return Err(LocalSigningUnavailable.into()),
        };
        let duration = i64::try_from(claim.requested_maximum_seconds())
            .map_err(|_| LocalSigningUnavailable)?;
        let expires = clock.wall_seconds().checked_add(duration).ok_or(LocalSigningUnavailable)?;
        let lease = OwnershipLease::new(claim.assignment(), claim.node(), generation,
            clock.wall_seconds(), expires, 0, nonce)?;
        let bytes = encode_ownership_lease(&lease);
        let signature = self.sign_bytes(&bytes, PortableMediaType::OwnershipLease,
            clock.wall_seconds(), expires, key)?;
        let receipt = aos_sandbox_ownership_protocol::OwnershipTransactionReceiptV1::new(
            self.authority.clone(), claim, &bytes)?;
        let receipt_signature = self.sign_bytes(receipt.canonical_bytes(),
            PortableMediaType::OwnershipTransactionReceipt, clock.wall_seconds(), expires, key)?;
        UnverifiedOwnershipLeaseResponse::from_transport(bytes, signature,
            receipt.canonical_bytes().to_vec(), receipt_signature)
            .map_err(LocalSigningError::Response)
    }

    fn sign_bytes(
        &self,
        bytes: &[u8],
        media: PortableMediaType,
        issued: i64,
        expires: i64,
        key: &SigningKey,
    ) -> Result<Vec<u8>, LocalSigningError> {
        let media = MediaType::new(media.as_str().to_owned()).map_err(|_| LocalSigningUnavailable)?;
        let statement = SignatureStatement::new(descriptor_for_bytes(media, bytes), self.scope,
            self.authority.clone(), SignaturePurpose::OwnershipLease, issued, Some(expires),
            self.policy.clone())?;
        Ok(encode_signature(&sign_statement(statement, key)?))
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum LocalSigningError {
    #[error(transparent)]
    Original(#[from] LocalSigningUnavailable),
    #[error(transparent)]
    Signature(#[from] SignatureVerificationError),
    #[error(transparent)]
    Lease(#[from] aos_sandbox_core::InvalidOwnershipLease),
    #[error(transparent)]
    Receipt(#[from] aos_sandbox_ownership_protocol::OwnershipReceiptError),
    #[error(transparent)]
    Trust(#[from] aos_sandbox_core::model::InvalidTrustModel),
    #[error(transparent)]
    Response(aos_sandbox_ownership_protocol::OwnershipLeaseAcquisitionError),
}

fn credential_stat(stat: &Stat, bytes: usize) -> bool {
    rustix::fs::FileType::from_raw_mode(stat.st_mode) == rustix::fs::FileType::RegularFile
        && stat.st_uid == 0 && stat.st_nlink == 1 && usize::try_from(stat.st_size).ok() == Some(bytes)
        && stat.st_mode & 0o7777 & !0o600 == 0
}

fn same_metadata(before: &std::fs::Metadata, after: &Stat) -> bool {
    before.dev() == after.st_dev && before.ino() == after.st_ino
        && before.mode() == after.st_mode && before.uid() == after.st_uid
        && before.gid() == after.st_gid && before.len() == u64::try_from(after.st_size).unwrap_or(u64::MAX)
        && i128::from(before.mtime()) == i128::from(after.st_mtime) && i128::from(before.mtime_nsec()) == i128::from(after.st_mtime_nsec)
        && i128::from(before.ctime()) == i128::from(after.st_ctime) && i128::from(before.ctime_nsec()) == i128::from(after.st_ctime_nsec)
}

fn same_file(before: &Stat, after: &Stat) -> bool {
    before.st_dev == after.st_dev && before.st_ino == after.st_ino
        && before.st_mode == after.st_mode && before.st_uid == after.st_uid
        && before.st_gid == after.st_gid && before.st_size == after.st_size
        && before.st_mtime == after.st_mtime && before.st_mtime_nsec == after.st_mtime_nsec
        && before.st_ctime == after.st_ctime && before.st_ctime_nsec == after.st_ctime_nsec
}

impl std::fmt::Debug for LocalOwnershipSigningOriginalV1 {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.debug_struct("LocalOwnershipSigningOriginalV1")
            .field("opened", &self.binding.is_ok()).finish_non_exhaustive()
    }
}

impl std::fmt::Display for LocalOwnershipSigningOriginalV1 {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("fixed local ownership signing credential failed")
    }
}

impl std::error::Error for LocalOwnershipSigningOriginalV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.credential.failure().or_else(|| self.node_credential.failure())
            .or_else(|| self.binding.as_ref().err()
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
    }
}

fn original_node(original: &LocalOwnershipSigningOriginalV1) -> Option<[u8; 16]> {
    original.node_credential.bytes().copied()
}

/// Parks one pending claim's actual signing and independent post observations.
pub(crate) struct LocalOwnershipSigningAttemptV1 {
    attempted: bool,
    native_history: Option<Result<(), crate::journal::LocalOwnershipNativeHistoryErrorV1>>,
    native_names: crate::ProtectedJournalCurrentnessOriginalsV1,
    before_clock: Option<Result<RawPairedClockSample, ProtectedOwnershipClockError>>,
    before_file: [Option<Result<Stat, rustix::io::Errno>>; 2],
    before_binding: Option<Result<(), LocalSigningUnavailable>>,
    entropy: Option<Result<usize, rustix::io::Errno>>,
    entropy_binding: Option<Result<(), LocalSigningUnavailable>>,
    nonce: [u8; 16],
    signed: Option<Result<UnverifiedOwnershipLeaseResponse, LocalSigningError>>,
    after_file: [Option<Result<Stat, rustix::io::Errno>>; 2],
    after_binding: Option<Result<(), LocalSigningUnavailable>>,
    after_clock: Option<Result<RawPairedClockSample, ProtectedOwnershipClockError>>,
    clock_join: Option<Result<(), aos_sandbox_core::OwnershipLeaseVerificationError>>,
    checked: Result<(), LocalSigningUnavailable>,
    pub(super) completion: Option<Result<UnverifiedOwnershipLeaseResponse, DurableOwnershipAuthorityError>>,
}

impl LocalOwnershipSigningAttemptV1 {
    pub(super) fn new() -> Self {
        Self {
            attempted: false, native_history: None, native_names: Default::default(), before_clock: None, before_file: [None, None],
            before_binding: None, entropy: None, entropy_binding: None,
            nonce: [0; 16], signed: None, after_file: [None, None], after_binding: None,
            after_clock: None, clock_join: None,
            checked: Err(LocalSigningUnavailable), completion: None,
        }
    }

    pub(crate) fn observe_native_once(&mut self, journal: &crate::journal::Journal) -> Result<(), DurableOwnershipAuthorityError> {
        if self.native_history.is_none() {
            self.native_history = Some(journal.observe_local_ownership_native_history_v1(&mut self.native_names));
        }
        match self.native_history {
            Some(Ok(())) => Ok(()),
            _ => Err(DurableOwnershipAuthorityError::LocalNativeClosed),
        }
    }

    pub(crate) fn capture_once(
        &mut self,
        original: &LocalOwnershipSigningOriginalV1,
        pending: &PendingOwnershipCompletion<'_>,
        clock: &mut ProtectedLeaseClockV1,
    ) {
        if self.attempted || !matches!(self.native_history, Some(Ok(()))) {
            return;
        }
        self.attempted = true;
        self.before_clock = Some(clock.sample());
        let credentials = [
            (original.credential.file(), original.credential.metadata(), 32),
            (original.node_credential.file(), original.node_credential.metadata(), 16),
        ];
        for (index, (file, _, _)) in credentials.iter().enumerate() {
            if let Some(file) = file { self.before_file[index] = Some(fstat(file)); }
        }
        let before_matches = credentials.iter().enumerate().all(|(index, (_, initial, bytes))| {
            initial.zip(self.before_file[index].as_ref().and_then(|value| value.as_ref().ok()))
                .is_some_and(|(before, current)| credential_stat(current, *bytes) && same_metadata(before, current))
        });
        self.before_binding = Some(if before_matches && original.require_open().is_ok() {
            Ok(())
        } else { Err(LocalSigningUnavailable) });
        if matches!(self.before_binding, Some(Ok(()))) {
            if let Some(Ok(before)) = self.before_clock {
                self.entropy = Some(rustix::rand::getrandom(&mut self.nonce,
                    rustix::rand::GetRandomFlags::empty()));
                self.entropy_binding = Some(if matches!(self.entropy, Some(Ok(16)))
                    && self.nonce != [0; 16] { Ok(()) } else { Err(LocalSigningUnavailable) });
                if matches!(self.entropy_binding, Some(Ok(()))) {
                    self.signed = Some(original.sign_pending(pending, before, self.nonce));
                }
            }
        }
        // These remain independent even after signing or entropy refusal.
        for (index, (file, _, _)) in credentials.iter().enumerate() {
            if let Some(file) = file { self.after_file[index] = Some(fstat(file)); }
        }
        self.after_binding = Some(if credentials.iter().enumerate().all(|(index, (_, _, bytes))| {
            self.before_file[index].as_ref().and_then(|value| value.as_ref().ok())
                .zip(self.after_file[index].as_ref().and_then(|value| value.as_ref().ok()))
                .is_some_and(|(before, after)| credential_stat(after, *bytes) && same_file(before, after))
        }) { Ok(()) } else { Err(LocalSigningUnavailable) });
        self.after_clock = Some(clock.sample());
        if let (Some(Ok(start)), Some(Ok(end))) = (&self.before_clock, &self.after_clock) {
            self.clock_join = Some(start.validate_later_sample(*end));
        }
        self.checked = if matches!(self.before_binding, Some(Ok(())))
            && matches!(self.entropy_binding, Some(Ok(())))
            && matches!(self.signed, Some(Ok(_)))
            && matches!(self.after_binding, Some(Ok(())))
            && matches!(self.clock_join, Some(Ok(())))
        { Ok(()) } else { Err(LocalSigningUnavailable) };
    }

    pub(crate) fn retire_committed_native_names_v1(&mut self) {
        if matches!(self.native_history, Some(Ok(()))) {
            self.native_names.settle_positive_once_v1();
        }
    }

    pub(crate) fn response(&self) -> Result<UnverifiedOwnershipLeaseResponse, DurableOwnershipAuthorityError> {
        if self.checked.is_err() {
            return Err(DurableOwnershipAuthorityError::LocalNativeClosed);
        }
        self.signed.as_ref().and_then(|value| value.as_ref().ok()).cloned()
            .ok_or(DurableOwnershipAuthorityError::LocalNativeClosed)
    }

    pub(crate) fn after_clock(&self) -> Result<&RawPairedClockSample, DurableOwnershipAuthorityError> {
        self.after_clock.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(DurableOwnershipAuthorityError::LocalNativeClosed)
    }
}

impl LocalOwnershipSigningAttemptV1 {
    pub(super) fn failure<'failure>(&'failure self, clock: &'failure ProtectedLeaseClockV1) -> Option<&'failure (dyn std::error::Error + 'static)> {
        self.native_history.as_ref().and_then(|value| value.as_ref().err())
            .map(|cause| cause.first_cause(&self.native_names))
            .or_else(|| self.before_clock.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| clock.failure().unwrap_or(cause)))
            .or_else(|| self.before_file.iter().find_map(|value| value.as_ref().and_then(|result| result.as_ref().err()))
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.before_binding.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.entropy.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.entropy_binding.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.signed.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.after_file.iter().find_map(|value| value.as_ref().and_then(|result| result.as_ref().err()))
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.after_binding.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.after_clock.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| clock.failure().unwrap_or(cause)))
            .or_else(|| self.clock_join.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.attempted.then_some(&self.checked).and_then(|value| value.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.completion.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
    }
}
