//! Verifies the whole historical completed055 preparation and target receipt.
//!
//! This comparison codec does not grant completion or assert future Source
//! posts. The real producer issues it only from its completed native target;
//! Host separately requires the CURRENT immutable oneshot's successful exit,
//! current boot/invocation and exact JSON bytes. Target NV is historical DATA,
//! not a claim that a consumer freshly read NV or that later055 cannot advance.
//!
//! ```text
//! AOSRDBC1 | version:u32be | reserved:4 | target_HEAD:32 | target_NV:32
//! | native_TX_UUID:16 | full_signed_AOSRDBR1:728 | publisher_signature:64
//! ```

use super::*;

/// Exact protected companion filename in the fixed readiness directory.
pub const BOOT_PREPARATION_COMPLETION_FILE_V1: &str = "backend-readiness-completion-v1";
/// Exact complete target body, including the original full signed record.
pub const BOOT_PREPARATION_COMPLETION_BODY_BYTES_V1: usize = 96 + BOOT_PREPARATION_RECORD_BYTES_V1;
/// Exact signed protected companion size; there is no trailing framing.
pub const BOOT_PREPARATION_COMPLETION_BYTES_V1: usize =
    BOOT_PREPARATION_COMPLETION_BODY_BYTES_V1 + 64;

const COMPLETION_DOMAIN: &[u8] = b"aos.runtime-deployment.boot-completion.v1\0";

/// Carries target DATA copied only by the actual issuer from completed055.
///
/// Public encoding of these fields authenticates no native commit or Source.
/// The original ordinal/NEXT/JSON/boot/invocation/purpose remain in the FULL
/// signed record; duplicating them here could introduce inconsistent selectors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootPreparationCompletionFieldsDataV1 {
    /// Complete target protected-main HEAD, not a selected-row surrogate.
    pub target_head: [u8; 32],
    /// Actual fresh authenticated NV at the completed target.
    pub target_nv: [u8; 32],
    /// Actual native UUID of the same full signed record's single PUT.
    pub native_transaction: [u8; 16],
}

impl BootPreparationCompletionFieldsDataV1 {
    /// Encodes the full completed-target signing body as comparison DATA.
    ///
    /// # Errors
    /// Rejects sentinel targets or a UUID other than the sole full-record recipe.
    pub fn encode_body_v1(
        self,
        record: &SignedBootPreparationRecordDataV1,
    ) -> Result<[u8; BOOT_PREPARATION_COMPLETION_BODY_BYTES_V1], DeploymentWireErrorV1> {
        if self.target_head == [0; 32]
            || self.target_nv == [0; 32]
            || self.native_transaction != boot_preparation_transaction_data_v1(record.fields_v1())?
        {
            return Err(DeploymentWireErrorV1);
        }
        let mut bytes = [0; BOOT_PREPARATION_COMPLETION_BODY_BYTES_V1];
        header(&mut bytes, b"AOSRDBC1");
        bytes[16..48].copy_from_slice(&self.target_head);
        bytes[48..80].copy_from_slice(&self.target_nv);
        bytes[80..96].copy_from_slice(&self.native_transaction);
        bytes[96..].copy_from_slice(record.bytes_v1());
        Ok(bytes)
    }

    /// Constructs the bounded domain-separated preimage without signing it.
    ///
    /// # Errors
    /// Rejects the same full-target/native-record mismatch as the body encoder.
    pub fn signing_bytes_v1(
        self,
        record: &SignedBootPreparationRecordDataV1,
    ) -> Result<Vec<u8>, DeploymentWireErrorV1> {
        let mut bytes =
            Vec::with_capacity(COMPLETION_DOMAIN.len() + BOOT_PREPARATION_COMPLETION_BODY_BYTES_V1);
        bytes.extend_from_slice(COMPLETION_DOMAIN);
        bytes.extend_from_slice(&self.encode_body_v1(record)?);
        Ok(bytes)
    }
}

/// Retains authenticated historical target DATA with its FULL signed preimage.
///
/// This type cannot create BackendReadiness, a current NV borrower, a Source
/// scope or successful PID1 status. No verification key is taken from a receipt.
pub struct SignedBootPreparationCompletionDataV1 {
    fields: BootPreparationCompletionFieldsDataV1,
    record: SignedBootPreparationRecordDataV1,
    bytes: [u8; BOOT_PREPARATION_COMPLETION_BYTES_V1],
}

impl SignedBootPreparationCompletionDataV1 {
    /// Verifies both complete signatures under the independently admitted purpose.
    ///
    /// # Errors
    /// Rejects any wrong size/version/reserved byte, target/native mismatch,
    /// substituted full record/purpose or invalid strict publisher signature.
    pub fn verify_v1(
        bytes: &[u8],
        purpose: &SignedBootPreparationPurposeDataV1,
    ) -> Result<Self, DeploymentWireErrorV1> {
        require_header(bytes, BOOT_PREPARATION_COMPLETION_BYTES_V1, b"AOSRDBC1")?;
        let record = SignedBootPreparationRecordDataV1::verify_v1(
            &bytes[96..BOOT_PREPARATION_COMPLETION_BODY_BYTES_V1],
            purpose,
        )?;
        let fields = BootPreparationCompletionFieldsDataV1 {
            target_head: take(bytes, 16)?,
            target_nv: take(bytes, 48)?,
            native_transaction: take(bytes, 80)?,
        };
        if fields.encode_body_v1(&record)?.as_slice()
            != &bytes[..BOOT_PREPARATION_COMPLETION_BODY_BYTES_V1]
        {
            return Err(DeploymentWireErrorV1);
        }
        let key = VerifyingKey::from_bytes(&purpose.fields_v1().publisher)
            .map_err(|_| DeploymentWireErrorV1)?;
        verify_signature(
            bytes,
            BOOT_PREPARATION_COMPLETION_BODY_BYTES_V1,
            COMPLETION_DOMAIN,
            &key,
        )?;
        Ok(Self {
            fields,
            record,
            bytes: bytes.try_into().map_err(|_| DeploymentWireErrorV1)?,
        })
    }

    /// Borrows exact authenticated target DATA without a currentness claim.
    #[must_use]
    pub const fn fields_v1(&self) -> &BootPreparationCompletionFieldsDataV1 {
        &self.fields
    }

    /// Borrows the original complete signed record used in the native append.
    #[must_use]
    pub const fn record_v1(&self) -> &SignedBootPreparationRecordDataV1 {
        &self.record
    }

    /// Derives the completed NEXT from the sole one-PUT native record relation.
    #[must_use]
    pub fn target_next_sequence_v1(&self) -> u64 {
        // The full record verifier rejected overflow before constructing Self.
        self.record.fields_v1().predecessor_sequence + 3
    }

    /// Borrows the complete exact companion, including both original signatures.
    #[must_use]
    pub const fn bytes_v1(&self) -> &[u8; BOOT_PREPARATION_COMPLETION_BYTES_V1] {
        &self.bytes
    }

    /// Commits all authenticated receipt bytes without granting a floor.
    #[must_use]
    pub fn digest_v1(&self) -> [u8; 32] {
        Sha256::new()
            .chain_update(COMPLETION_DOMAIN)
            .chain_update(self.bytes)
            .finalize()
            .into()
    }
}
