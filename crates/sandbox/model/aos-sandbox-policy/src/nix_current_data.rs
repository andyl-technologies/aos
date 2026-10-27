//! Checks current-Nix signature and context DATA without a native owner.
//!
//! Exact bytes and original clock fields are comparison inputs. Decoding or
//! verifying these packets cannot create a Root, Source, Controller or Session
//! loan, change a deadline, or permit publication.
//!
//! ```text
//! AOSNCP01[280] | original Start tuple | boot/clock/D | Root floor | watermarks
//! AOSNCR01[552] | distinct Controller signature | context | names | lease
//! AOSSSP16 | context | existing strict/mixed Source observation | signature
//! ```

use aos_sandbox_model::bounded_codec::checked_byte_region;
use aos_sandbox_model::ownership_lease::{
    OwnershipLeaseVerificationError, RawClockProvenance, RawPairedClockSample,
};
use aos_sandbox_model::{ObjectDigest, OperationId, ProjectId, SandboxId};
use aos_sandbox_ledger_replay::source_signer_data::{
    PinnedSourceHoldReadbackSignerV1, VerifiedSourceFirstSuccessorReadbackV2,
    VerifiedSourceProjectContinuationReadbackV3,
};
use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;
use ed25519_dalek::Signature;

use crate::controller_readback::PinnedControllerHoldSignerV1;

/// Bounds the original current-Nix challenge, not an authority or funding token.
pub const CURRENT_NIX_PREFLIGHT_CONTEXT_BYTES_V1: usize = 280;

/// Bounds one distinct Controller-current-Start receipt including its signature.
pub const CURRENT_NIX_CONTROLLER_RECEIPT_BYTES_V1: usize = 552;

/// Bounds the closed Source16 request including its fixed original-intent slot.
pub const CURRENT_NIX_SOURCE_REQUEST_BYTES_V1: usize = 1712;

/// Bounds a Source16 legacy observation with the distinct current-Nix signature.
pub const CURRENT_NIX_SOURCE_LEGACY_REPLY_BYTES_V1: usize = 3140;

/// Bounds a resource Source16 observation retaining historical legacy genesis.
pub const CURRENT_NIX_SOURCE_LEGACY_GENESIS_REPLY_BYTES_V1: usize = 3316;

/// Bounds a resource Source16 observation retaining full-resource genesis.
pub const CURRENT_NIX_SOURCE_RESOURCE_REPLY_BYTES_V1: usize = 3492;

const CONTEXT_MAGIC: &[u8; 8] = b"AOSNCP01";
const CONTROLLER_MAGIC: &[u8; 8] = b"AOSNCR01";
/// Names the existing Controller receipt signature preimage purpose.
pub const CONTROLLER_SIGNATURE_DOMAIN: &[u8] =
    b"aos.sandbox.nix-current-preflight.controller.signature.v1\0";
pub const SOURCE_SIGNATURE_DOMAIN: &[u8] =
    b"aos.sandbox.nix-current-preflight.source.signature.v1\0";
pub const SOURCE_REPLY_MAGIC: &[u8; 8] = b"AOSSSP16";
/// Bounds the exact existing Controller receipt body before its signature.
pub const CONTROLLER_BODY_BYTES: usize = CURRENT_NIX_CONTROLLER_RECEIPT_BYTES_V1 - 64;
/// Labels the existing raw comparison clock format without authenticating it.
pub const CONTROLLER_CLOCK_PROVENANCE: [u8; 16] = *b"aos-cli-clock-v1";

/// Reports a malformed or changed current-Nix comparison, never a paid refusal.
#[derive(Debug, thiserror::Error)]
pub enum CurrentNixPreflightDataErrorV1 {
    /// The fixed format, purpose, reserved bytes or original association differs.
    #[error("invalid current Nix preflight comparison")]
    Changed,
    /// The same once-only attempt was already entered or closed.
    #[error("current Nix preflight attempt was already entered")]
    Repeated,
    /// The independently obtained clock cannot join the original pair and D.
    #[error(transparent)]
    Clock(#[from] OwnershipLeaseVerificationError),
    /// The complete physical names are malformed or changed.
    #[error(transparent)]
    Journal(#[from] aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1),
    /// A Source/Controller role signature does not cover the exact complete body.
    #[error("current Nix preflight role signature is invalid")]
    Signature,
    /// The original bounded allocation could not be reserved.
    #[error(transparent)]
    Allocation(#[from] std::collections::TryReserveError),
    /// The existing whole native Source observation could not be authenticated.
    #[error(transparent)]
    Source(#[from] aos_sandbox_ledger_replay::source_signer_data::SourceSignerGenesisDataErrorV1),
}

/// Retains a canonical original-Start challenge as explicitly nonauthorizing DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CurrentNixPreflightContextV1 {
    bytes: [u8; CURRENT_NIX_PREFLIGHT_CONTEXT_BYTES_V1],
}

impl CurrentNixPreflightContextV1 {
    /// Decodes only the closed context format without admitting its peer claims.
    ///
    /// # Errors
    /// Rejects other purposes/versions, unknown recipes, reserved/trailing bytes,
    /// zero identities, an unknown clock format or an already expired pair.
    pub fn decode(bytes: &[u8]) -> Result<Self, CurrentNixPreflightDataErrorV1> {
        if bytes.len() != CURRENT_NIX_PREFLIGHT_CONTEXT_BYTES_V1
            || bytes[..8] != *CONTEXT_MAGIC
            || bytes[8..10] != 1_u16.to_be_bytes()
            || !(1..=4).contains(&bytes[10])
            || bytes[11..16] != [0; 5]
            || bytes[176..178] != 1_u16.to_be_bytes()
            || bytes[178..184] != [0; 6]
            || bytes[272..280] != [0; 8]
            || [16, 32, 48, 64, 184]
                .into_iter()
                .any(|offset| bytes[offset..offset + 16] == [0; 16])
            || [80, 112, 144, 224]
                .into_iter()
                .any(|offset| bytes[offset..offset + 32] == [0; 32])
        {
            return Err(CurrentNixPreflightDataErrorV1::Changed);
        }
        let context = Self {
            bytes: take(bytes, 0)?,
        };
        if context.original_deadline_data() <= context.original_clock_data()?.boottime_nanoseconds()
            || context.source_sequence_data() == 0
            || context.root_sequence_data() == 0
        {
            return Err(CurrentNixPreflightDataErrorV1::Changed);
        }
        Ok(context)
    }

    /// Borrows the whole canonical comparison context, not a live owner token.
    pub const fn bytes(&self) -> &[u8; CURRENT_NIX_PREFLIGHT_CONTEXT_BYTES_V1] {
        &self.bytes
    }

    /// Returns the fresh Root challenge as comparison DATA.
    pub fn root_nonce_data(&self) -> [u8; 16] {
        // The fixed array was checked at construction; no slice arithmetic is
        // delegated to an untrusted caller or used as an authority predicate.
        let mut nonce = [0; 16];
        nonce.copy_from_slice(&self.bytes[16..32]);
        nonce
    }

    /// Returns the original operation identity as comparison DATA.
    pub fn operation_data(&self) -> OperationId {
        OperationId::from_bytes(self.identity_at(32))
    }

    /// Returns the original project identity as comparison DATA.
    pub fn project_data(&self) -> ProjectId {
        ProjectId::from_bytes(self.identity_at(48))
    }

    /// Returns the original sandbox identity as comparison DATA.
    pub fn sandbox_data(&self) -> SandboxId {
        SandboxId::from_bytes(self.identity_at(64))
    }

    /// Returns the full original canonical Start commitment as comparison DATA.
    pub fn start_digest_data(&self) -> ObjectDigest {
        self.digest_at(80)
    }

    /// Returns the full canonical assignment commitment as comparison DATA.
    pub fn assignment_digest_data(&self) -> ObjectDigest {
        self.digest_at(112)
    }

    /// Returns the original durable specification commitment as comparison DATA.
    pub fn specification_digest_data(&self) -> ObjectDigest {
        self.digest_at(144)
    }

    /// Returns the independently observed Root floor commitment as DATA.
    pub fn root_floor_digest_data(&self) -> ObjectDigest {
        self.digest_at(224)
    }

    /// Returns the unchanged signed Start cutoff, not a renewed deadline.
    pub fn original_deadline_data(&self) -> u64 {
        self.u64_at(216)
    }

    /// Returns the original held Source watermark as comparison DATA.
    pub fn source_sequence_data(&self) -> u64 {
        self.u64_at(256)
    }

    /// Returns the original held Root watermark as comparison DATA.
    pub fn root_sequence_data(&self) -> u64 {
        self.u64_at(264)
    }

    /// Reconstructs the format-labelled pair as raw, explicitly untrusted DATA.
    ///
    /// # Errors
    /// Rejects invalid raw boot/provenance fields. This never supplies a protected
    /// clock owner or a NativeCrossing sample to a production effect.
    pub fn original_clock_data(
        &self,
    ) -> Result<RawPairedClockSample, CurrentNixPreflightDataErrorV1> {
        Ok(RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(CONTROLLER_CLOCK_PROVENANCE)?,
            self.identity_at(184),
            i64::from_be_bytes(take(&self.bytes, 200)?),
            self.u64_at(208),
        )?)
    }

    /// Compares a separately obtained kernel pair with the unchanged original D.
    ///
    /// Only the comparison copy normalizes provenance. Neither raw value is
    /// promoted to a protected clock owner or used to renew a native deadline.
    ///
    /// # Errors
    /// Rejects changed boot, rollback, pair divergence or the original expiry.
    pub fn require_original_kernel_sample_data_v1(
        &self,
        native: RawPairedClockSample,
    ) -> Result<(), CurrentNixPreflightDataErrorV1> {
        let comparison = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(CONTROLLER_CLOCK_PROVENANCE)?,
            native.host_boot_id(),
            native.wall_seconds(),
            native.boottime_nanoseconds(),
        )?;
        self.original_clock_data()?
            .validate_later_sample(comparison)?;
        if native.boottime_nanoseconds() >= self.original_deadline_data() {
            return Err(CurrentNixPreflightDataErrorV1::Changed);
        }
        Ok(())
    }

    /// Returns the fixed comparison grammar without granting its native purpose.
    pub fn recipe_data(&self) -> u8 {
        self.bytes[10]
    }

    fn identity_at(&self, offset: usize) -> [u8; 16] {
        let mut bytes = [0; 16];
        bytes.copy_from_slice(&self.bytes[offset..offset + 16]);
        bytes
    }

    fn digest_at(&self, offset: usize) -> ObjectDigest {
        let mut bytes = [0; 32];
        bytes.copy_from_slice(&self.bytes[offset..offset + 32]);
        ObjectDigest::from_bytes(bytes)
    }

    fn u64_at(&self, offset: usize) -> u64 {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&self.bytes[offset..offset + 8]);
        u64::from_be_bytes(bytes)
    }
}

/// Retains a distinct Controller receipt as signature-checked comparison DATA.
pub struct VerifiedCurrentNixControllerReceiptV1 {
    bytes: [u8; CURRENT_NIX_CONTROLLER_RECEIPT_BYTES_V1],
    context: CurrentNixPreflightContextV1,
    controller_names: ProtectedJournalNamesV1,
    source_names: ProtectedJournalNamesV1,
}

impl VerifiedCurrentNixControllerReceiptV1 {
    /// Verifies the separate current-Start purpose against the pinned role key.
    ///
    /// # Errors
    /// Rejects malformed framing, unknown/reserved fields, foreign context/UIDs,
    /// names/sequence disagreement, zero publisher/lease commitments or an invalid
    /// signature. Success cannot substitute for the same live writer conjunction.
    pub fn verify_data(
        bytes: &[u8],
        context: &CurrentNixPreflightContextV1,
        signer: &PinnedControllerHoldSignerV1,
        controller_uid: u32,
        source_uid: u32,
    ) -> Result<Self, CurrentNixPreflightDataErrorV1> {
        if bytes.len() != CURRENT_NIX_CONTROLLER_RECEIPT_BYTES_V1
            || bytes[..8] != *CONTROLLER_MAGIC
            || bytes[8..10] != 1_u16.to_be_bytes()
            || bytes[10..16] != [0; 6]
            || u64::from_be_bytes(take(bytes, 16)?) != signer.generation()
            || controller_uid == 0
            || source_uid == 0
            || u32::from_be_bytes(take(bytes, 24)?) != controller_uid
            || u32::from_be_bytes(take(bytes, 28)?) != source_uid
            || &bytes[32..312] != context.bytes()
            || u64::from_be_bytes(take(bytes, 416)?) != context.source_sequence_data()
            || bytes[424..456] == [0; 32]
            || bytes[456..488] == [0; 32]
        {
            return Err(CurrentNixPreflightDataErrorV1::Changed);
        }
        let controller_names = ProtectedJournalNamesV1::from_bytes(&bytes[312..360]).map_err(
            aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::from,
        )?;
        let source_names = ProtectedJournalNamesV1::from_bytes(&bytes[360..408]).map_err(
            aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::from,
        )?;
        let mut message = [0; CONTROLLER_SIGNATURE_DOMAIN.len() + CONTROLLER_BODY_BYTES];
        message[..CONTROLLER_SIGNATURE_DOMAIN.len()].copy_from_slice(CONTROLLER_SIGNATURE_DOMAIN);
        message[CONTROLLER_SIGNATURE_DOMAIN.len()..]
            .copy_from_slice(&bytes[..CONTROLLER_BODY_BYTES]);
        signer
            .verifying_key()
            .verify_strict(
                &message,
                &Signature::from_bytes(&take(bytes, CONTROLLER_BODY_BYTES)?),
            )
            .map_err(|_| CurrentNixPreflightDataErrorV1::Signature)?;
        Ok(Self {
            bytes: take(bytes, 0)?,
            context: *context,
            controller_names,
            source_names,
        })
    }

    /// Borrows the complete signature-checked receipt as DATA.
    pub const fn bytes(&self) -> &[u8; CURRENT_NIX_CONTROLLER_RECEIPT_BYTES_V1] {
        &self.bytes
    }

    /// Returns the exact receipt context as comparison DATA.
    pub const fn context_data(&self) -> &CurrentNixPreflightContextV1 {
        &self.context
    }

    /// Returns the original Controller physical-name observation as DATA.
    pub const fn controller_names_data(&self) -> ProtectedJournalNamesV1 {
        self.controller_names
    }

    /// Returns the original Source physical-name observation as DATA.
    pub const fn source_names_data(&self) -> ProtectedJournalNamesV1 {
        self.source_names
    }

    /// Returns the signed original Controller watermark as comparison DATA.
    pub fn controller_sequence_data(&self) -> u64 {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&self.bytes[408..416]);
        u64::from_be_bytes(bytes)
    }
}

// This private prepared body is built only at the real CurrentStart handoff.
enum CurrentNixSourceNativeDataV1 {
    Strict(VerifiedSourceFirstSuccessorReadbackV2),
    Mixed(VerifiedSourceProjectContinuationReadbackV3),
}

/// Retains a purpose-checked Source16 signature and the sole native decoder output.
///
/// This observation is DATA, including its authenticated current Tree fields.
/// Its original bytes stay in the surrounding receive attempt; its native
/// decoded owners stay here. Neither representation is a Root/current loan.
pub struct VerifiedCurrentNixSourceObservationV1 {
    context: CurrentNixPreflightContextV1,
    native: CurrentNixSourceNativeDataV1,
}

impl VerifiedCurrentNixSourceObservationV1 {
    /// Verifies both the distinct current-Nix purpose and existing native recipe.
    ///
    /// # Errors
    /// Rejects foreign widths, context, intent, recipe, reserved/native joins or
    /// either role signature. It decodes the native observation exactly once
    /// through the existing strict/mixed engine, with no alternate fallback.
    pub fn verify_data(
        bytes: &[u8],
        context: &CurrentNixPreflightContextV1,
        original: &aos_sandbox_ledger_replay::replay::phase_records::RootFirstSourceSuccessorIntentV2,
        signer: &PinnedSourceHoldReadbackSignerV1,
    ) -> Result<Self, CurrentNixPreflightDataErrorV1> {
        if !matches!(bytes.len(), 3140 | 3316 | 3492)
            || bytes[..8] != *SOURCE_REPLY_MAGIC
            || &bytes[8..288] != context.bytes()
            || context.project_data() != original.project()
        {
            return Err(CurrentNixPreflightDataErrorV1::Changed);
        }
        let native_len = u32::from_be_bytes(take(bytes, 288)?) as usize;
        if native_len.checked_add(356) != Some(bytes.len()) {
            return Err(CurrentNixPreflightDataErrorV1::Changed);
        }
        let body_len = bytes.len() - 64;
        let mut message =
            [0; SOURCE_SIGNATURE_DOMAIN.len() + CURRENT_NIX_SOURCE_RESOURCE_REPLY_BYTES_V1 - 64];
        message[..SOURCE_SIGNATURE_DOMAIN.len()].copy_from_slice(SOURCE_SIGNATURE_DOMAIN);
        message[SOURCE_SIGNATURE_DOMAIN.len()..SOURCE_SIGNATURE_DOMAIN.len() + body_len]
            .copy_from_slice(&bytes[..body_len]);
        signer
            .verifying_key()
            .verify_strict(
                &message[..SOURCE_SIGNATURE_DOMAIN.len() + body_len],
                &Signature::from_bytes(&take(bytes, body_len)?),
            )
            .map_err(|_| CurrentNixPreflightDataErrorV1::Signature)?;

        let native = &bytes[292..body_len];
        let nonce = context.root_nonce_data();
        let native = match context.recipe_data() {
            1 => CurrentNixSourceNativeDataV1::Strict(
                aos_sandbox_ledger_replay::source_signer_data::source_successor_readback::verify_source_first_successor_readback_v2(
                    native, signer, nonce, original,
                )?,
            ),
            2 => CurrentNixSourceNativeDataV1::Mixed(
                aos_sandbox_ledger_replay::source_signer_data::source_successor_readback::verify_source_project_continuation_readback_v3(
                    native, signer, nonce, original,
                )?,
            ),
            3 => CurrentNixSourceNativeDataV1::Strict(
                aos_sandbox_ledger_replay::source_signer_data::source_successor_readback::verify_source_resource_first_successor_readback_v4(
                    native, signer, nonce, original,
                )?,
            ),
            4 => CurrentNixSourceNativeDataV1::Mixed(
                aos_sandbox_ledger_replay::source_signer_data::source_successor_readback::verify_source_resource_project_continuation_readback_v5(
                    native, signer, nonce, original,
                )?,
            ),
            _ => return Err(CurrentNixPreflightDataErrorV1::Changed),
        };
        Ok(Self {
            context: *context,
            native,
        })
    }

    /// Compares the complete independently held Source cut as nonauthorizing DATA.
    ///
    /// # Errors
    /// Rejects different names/watermark or either Tree/lineage envelope head.
    /// Actual owner/currentness and Root-floor checks remain separate obligations.
    pub fn require_original_source_cut_data(
        &self,
        names: ProtectedJournalNamesV1,
        sequence: u64,
        tree: ObjectDigest,
        lineage: ObjectDigest,
    ) -> Result<(), CurrentNixPreflightDataErrorV1> {
        let (actual_names, actual_sequence, actual_tree, actual_lineage) = match &self.native {
            CurrentNixSourceNativeDataV1::Strict(data) => (
                data.names(),
                data.sequence(),
                data.current_tree_head(),
                data.current_lineage_head(),
            ),
            CurrentNixSourceNativeDataV1::Mixed(data) => (
                data.names(),
                data.sequence(),
                data.current_tree_head(),
                data.current_lineage_head(),
            ),
        };
        if names != actual_names
            || sequence != actual_sequence
            || sequence != self.context.source_sequence_data()
            || tree != actual_tree
            || lineage != actual_lineage
        {
            return Err(CurrentNixPreflightDataErrorV1::Changed);
        }
        Ok(())
    }

    /// Compares complete archive fields with the original signed observation.
    ///
    /// The caller must separately retain and revalidate its genuine Root
    /// writer. These supplied archive fields and nonce remain comparison DATA;
    /// this method neither opens that writer nor establishes its currentness.
    ///
    /// # Errors
    /// Refuses a different context, nonce, watermark, recipe, floor, project,
    /// anchored phase, generation, receipt or semantic ACK association.
    pub fn require_original_root_archive_data_v1(
        &self,
        context: &CurrentNixPreflightContextV1,
        nonce: [u8; 16],
        sequence: u64,
        recipe: u8,
        floor: &aos_sandbox_ledger_replay::replay::phase_records::RootFirstSourceSuccessorFloorV2,
        original: &aos_sandbox_ledger_replay::replay::phase_records::RootFirstSourceSuccessorIntentV2,
    ) -> Result<(), CurrentNixPreflightDataErrorV1> {
        let (phase, receipt, ack, intent, generation) = match &self.native {
            CurrentNixSourceNativeDataV1::Strict(data) => (
                data.phase(),
                data.receipt(),
                data.ack(),
                data.root_intent(),
                data.current_generation(),
            ),
            CurrentNixSourceNativeDataV1::Mixed(data) => (
                data.phase(),
                data.receipt(),
                data.ack(),
                data.root_intent(),
                data.current_generation(),
            ),
        };
        if &self.context != context || context.root_nonce_data() != nonce
            || context.root_sequence_data() != sequence || context.recipe_data() != recipe
            || context.root_floor_digest_data() != floor.digest()
            || context.project_data() != original.project() || intent != original.digest()
            || phase != aos_sandbox_ledger_replay::source_signer_data::SourceFirstSuccessorReadbackPhaseV2::Anchored
            || generation != 2 || receipt != Some(floor.receipt())
            || !ack.is_some_and(|ack| {
                ack.receipt() == floor.receipt().digest() && ack.root_floor() == floor.digest()
            })
        {
            return Err(CurrentNixPreflightDataErrorV1::Changed);
        }
        Ok(())
    }
}

fn take<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], CurrentNixPreflightDataErrorV1> {
    let (value, _) = checked_byte_region(bytes, offset, N)
        .map_err(|_| CurrentNixPreflightDataErrorV1::Changed)?;
    value
        .try_into()
        .map_err(|_| CurrentNixPreflightDataErrorV1::Changed)
}
