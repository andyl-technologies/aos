//! Closed Controller receipt for one protected runtime-authority head.
//!
//! This packet signs Controller-local structural currentness only. Its signer
//! is deliberately supplied by an internal caller: no deployment credential,
//! Host audience, effect handoff, or AOSRBM01 publisher consumes it yet.
//! Cold verification replays the complete runtime-authority namespace and
//! requires the original journal sequence and exact current head at the fixed
//! Controller root.
//!
//! ```text
//! AOSRCR01 || version:u16be=1 || reserved[6]=0
//! || signer_generation:u64be || journal_sequence:u64be
//! || sandbox[16] || incarnation[16] || node[16]
//! || assignment_epoch:u64be || assignment_digest[32]
//! || desired_generation:u64be || namespace_generation:u64be
//! || binding_revision:u64be || binding_digest[32]
//! || current_head_sha256[32] || signature[64]
//! ```

use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;

use aos_sandbox_core::SandboxId;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

use super::{
    RuntimeAuthorityError, RuntimeAuthorityLimits, RuntimeAuthorityStateV1, RuntimeAuthorityStore,
    current_key,
};
use crate::{Journal, JournalError, RecordNamespace};

const MAGIC: &[u8; 8] = b"AOSRCR01";
const VERSION: u16 = 1;
const SIGNED_BYTES: usize = 208;
const RECEIPT_BYTES: usize = SIGNED_BYTES + 64;
const SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.controller-runtime-currentness.v1\0";
const CONTROLLER_ROOT: &str = "/var/lib/aos/sandboxd";
const CONTROLLER_JOURNAL: &str = "controller.journal";

enum ControllerRoot {
    Production,
    #[cfg(test)]
    Test(PathBuf),
}

/// Reports a malformed, stale, or unauthenticated closed Controller receipt.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ControllerRuntimeCurrentnessReceiptErrorV1 {
    #[error("Controller runtime-currentness receipt is malformed")]
    Malformed,
    #[error("Controller runtime-currentness receipt is stale")]
    Stale,
    #[error("Controller runtime-currentness signature is invalid")]
    Signature,
    #[error(transparent)]
    RuntimeAuthority(#[from] RuntimeAuthorityError),
    #[error(transparent)]
    Journal(#[from] JournalError),
}

/// Retains exact signed bytes without conferring Host or effect authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControllerRuntimeCurrentnessReceiptV1 {
    bytes: [u8; RECEIPT_BYTES],
}

impl ControllerRuntimeCurrentnessReceiptV1 {
    /// Signs the current Controller head under one already-held journal writer.
    ///
    /// The caller must independently own the dedicated signing credential.
    /// This closed entry point has no production caller or effect consumer.
    ///
    /// # Errors
    ///
    /// Rejects zero signer generation, absent or revoked current assignment,
    /// malformed protected replay, or lost journal custody.
    pub(crate) fn issue(
        journal: &mut Journal,
        sandbox: SandboxId,
        signer_generation: u64,
        signer: &SigningKey,
    ) -> Result<Self, ControllerRuntimeCurrentnessReceiptErrorV1> {
        Self::issue_at_root(
            journal,
            sandbox,
            signer_generation,
            signer,
            &ControllerRoot::Production,
        )
    }

    /// Signs from a private test-owned root using the same fixed journal name.
    ///
    /// # Errors
    ///
    /// Rejects a replaced test root or journal and the production method's
    /// invalid currentness and signing inputs.
    #[cfg(test)]
    pub(crate) fn issue_at_uid_for_test(
        journal: &mut Journal,
        root: &Path,
        sandbox: SandboxId,
        signer_generation: u64,
        signer: &SigningKey,
    ) -> Result<Self, ControllerRuntimeCurrentnessReceiptErrorV1> {
        Self::issue_at_root(
            journal,
            sandbox,
            signer_generation,
            signer,
            &ControllerRoot::Test(root.to_path_buf()),
        )
    }

    fn issue_at_root(
        journal: &mut Journal,
        sandbox: SandboxId,
        signer_generation: u64,
        signer: &SigningKey,
        root: &ControllerRoot,
    ) -> Result<Self, ControllerRuntimeCurrentnessReceiptErrorV1> {
        if signer_generation == 0 {
            return Err(ControllerRuntimeCurrentnessReceiptErrorV1::Malformed);
        }

        let signed = current_cut(journal, sandbox, signer_generation, root)?;
        let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + SIGNED_BYTES);
        message.extend_from_slice(SIGNATURE_DOMAIN);
        message.extend_from_slice(&signed);

        let mut bytes = [0; RECEIPT_BYTES];
        bytes[..SIGNED_BYTES].copy_from_slice(&signed);
        bytes[SIGNED_BYTES..].copy_from_slice(&signer.sign(&message).to_bytes());
        validate_root(journal, root)?;
        Ok(Self { bytes })
    }

    /// Decodes exact packet framing without trusting its signer or currentness.
    ///
    /// # Errors
    ///
    /// Rejects a wrong length, version, reserved field, or zero generation.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, ControllerRuntimeCurrentnessReceiptErrorV1> {
        let bytes: [u8; RECEIPT_BYTES] = bytes
            .try_into()
            .map_err(|_| ControllerRuntimeCurrentnessReceiptErrorV1::Malformed)?;
        if &bytes[..8] != MAGIC
            || bytes[8..10] != VERSION.to_be_bytes()
            || bytes[10..16] != [0; 6]
            || read_u64(&bytes, 16) == 0
            || read_u64(&bytes, 24) == 0
        {
            return Err(ControllerRuntimeCurrentnessReceiptErrorV1::Malformed);
        }
        Ok(Self { bytes })
    }

    /// Verifies the independent key pin, signature, and exact cold-replayed head.
    ///
    /// The verifier key and generation must come from outside this journal and
    /// packet. Exact journal-sequence matching conservatively expires receipts
    /// after any later Controller append. A compaction must still replay to the
    /// same complete namespace and exact sequence to preserve one.
    ///
    /// # Errors
    ///
    /// Rejects a stale signer generation, invalid signature, changed journal
    /// sequence or current head, revoked assignment, or failed protected replay.
    pub(crate) fn verify_replayed(
        &self,
        journal: &mut Journal,
        pinned_generation: u64,
        pinned_verifier: &VerifyingKey,
    ) -> Result<(), ControllerRuntimeCurrentnessReceiptErrorV1> {
        self.verify_replayed_at_root(
            journal,
            pinned_generation,
            pinned_verifier,
            &ControllerRoot::Production,
        )
    }

    /// Replays a receipt against one private test-owned Controller root.
    ///
    /// # Errors
    ///
    /// Rejects changed test custody or any signature or current-head mismatch.
    #[cfg(test)]
    pub(crate) fn verify_replayed_at_uid_for_test(
        &self,
        journal: &mut Journal,
        root: &Path,
        pinned_generation: u64,
        pinned_verifier: &VerifyingKey,
    ) -> Result<(), ControllerRuntimeCurrentnessReceiptErrorV1> {
        self.verify_replayed_at_root(
            journal,
            pinned_generation,
            pinned_verifier,
            &ControllerRoot::Test(root.to_path_buf()),
        )
    }

    fn verify_replayed_at_root(
        &self,
        journal: &mut Journal,
        pinned_generation: u64,
        pinned_verifier: &VerifyingKey,
        root: &ControllerRoot,
    ) -> Result<(), ControllerRuntimeCurrentnessReceiptErrorV1> {
        if pinned_generation == 0 || read_u64(&self.bytes, 16) != pinned_generation {
            return Err(ControllerRuntimeCurrentnessReceiptErrorV1::Stale);
        }

        let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + SIGNED_BYTES);
        message.extend_from_slice(SIGNATURE_DOMAIN);
        message.extend_from_slice(&self.bytes[..SIGNED_BYTES]);
        let signature_bytes: [u8; 64] = self.bytes[SIGNED_BYTES..]
            .try_into()
            .map_err(|_| ControllerRuntimeCurrentnessReceiptErrorV1::Malformed)?;
        pinned_verifier
            .verify_strict(&message, &Signature::from_bytes(&signature_bytes))
            .map_err(|_| ControllerRuntimeCurrentnessReceiptErrorV1::Signature)?;

        let sandbox_bytes: [u8; 16] = self.bytes[32..48]
            .try_into()
            .map_err(|_| ControllerRuntimeCurrentnessReceiptErrorV1::Malformed)?;
        let current = current_cut(
            journal,
            SandboxId::from_bytes(sandbox_bytes),
            pinned_generation,
            root,
        )?;
        if self.bytes[..SIGNED_BYTES] != current {
            return Err(ControllerRuntimeCurrentnessReceiptErrorV1::Stale);
        }
        validate_root(journal, root)?;
        Ok(())
    }

    /// Returns the exact nonauthorizing packet for protected transfer or replay.
    pub(crate) fn as_bytes(&self) -> &[u8; RECEIPT_BYTES] {
        &self.bytes
    }
}

fn current_cut(
    journal: &mut Journal,
    sandbox: SandboxId,
    signer_generation: u64,
    root: &ControllerRoot,
) -> Result<[u8; SIGNED_BYTES], ControllerRuntimeCurrentnessReceiptErrorV1> {
    validate_root(journal, root)?;
    let binding = RuntimeAuthorityStore::load(journal, RuntimeAuthorityLimits::default())?
        .current(sandbox)?
        .filter(|binding| binding.state() == RuntimeAuthorityStateV1::Bound)
        .ok_or(ControllerRuntimeCurrentnessReceiptErrorV1::Stale)?;
    let manifest = binding.manifest().manifest();

    // Controller shares one protected writer across namespaces. Its exclusive
    // borrow and fixed-root check fence this structural read; the sequence is
    // deliberately diagnostic and grants no effect authority.
    let sequence = journal.snapshot_sequence();
    let head = journal
        .get(RecordNamespace::RuntimeAuthority, &current_key(sandbox))
        .ok_or(ControllerRuntimeCurrentnessReceiptErrorV1::Stale)?;
    let head_digest = Sha256::digest(head);
    validate_root(journal, root)?;
    if journal.snapshot_sequence() != sequence {
        return Err(ControllerRuntimeCurrentnessReceiptErrorV1::Stale);
    }

    let mut signed = Vec::with_capacity(SIGNED_BYTES);
    signed.extend_from_slice(MAGIC);
    signed.extend_from_slice(&VERSION.to_be_bytes());
    signed.extend_from_slice(&[0; 6]);
    signed.extend_from_slice(&signer_generation.to_be_bytes());
    signed.extend_from_slice(&sequence.to_be_bytes());
    signed.extend_from_slice(sandbox.as_bytes());
    signed.extend_from_slice(manifest.incarnation().as_bytes());
    signed.extend_from_slice(manifest.node().as_bytes());
    signed.extend_from_slice(&manifest.epoch().get().to_be_bytes());
    signed.extend_from_slice(binding.assignment_digest().as_bytes());
    signed.extend_from_slice(&manifest.desired_generation().get().to_be_bytes());
    signed.extend_from_slice(&manifest.namespace_generation().get().to_be_bytes());
    signed.extend_from_slice(&binding.revision().to_be_bytes());
    signed.extend_from_slice(binding.digest().as_bytes());
    signed.extend_from_slice(&head_digest);
    signed
        .try_into()
        .map_err(|_| ControllerRuntimeCurrentnessReceiptErrorV1::Malformed)
}

fn validate_root(
    journal: &Journal,
    root: &ControllerRoot,
) -> Result<(), ControllerRuntimeCurrentnessReceiptErrorV1> {
    let owner_uid = journal.protected_owner_uid()?;
    match root {
        ControllerRoot::Production => journal.require_protected_named_location(
            Path::new(CONTROLLER_ROOT),
            CONTROLLER_JOURNAL,
            owner_uid,
            crate::controller_service::journal::production_journal_limits(),
        )?,
        #[cfg(test)]
        ControllerRoot::Test(directory) => journal
            .require_protected_named_location_at_uid_for_test(
                directory,
                CONTROLLER_JOURNAL,
                owner_uid,
                crate::JournalLimits::default(),
            )?,
    }
    Ok(())
}

fn read_u64(bytes: &[u8; RECEIPT_BYTES], offset: usize) -> u64 {
    let mut value = [0; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_be_bytes(value)
}
