//! Frames preparatory26 signing and acceptance DATA on the same Delete stream.
//!
//! ```text
//! context232 = AOSDPC03/version3/reserved | open32/challenge32/fresh45632 |
//!              fresh-six32/current-lease32/policy-expiry8/actual-Root-paired-clock48
//! draft = AOSDPD03 | four:u32be lengths | context232 | plan | statement | body
//! signed = AOSDPS03 | two:u32be lengths | whole-draft32 | canonical-signature
//! ```
//!
//! The shared finite field decoder rejects trailing bytes, empty/oversized
//! fields and another purpose. Announced widths describe cost only; receivers
//! pay before growth. No decoded value grants signing, acceptance, native
//! currentness, catalog resolution or destructive authority. The same held D
//! remains occupied after preparatory acceptance through actual finalization.

use aos_sandbox_model::RawPairedClockSample;
use crate::authorization_artifact::delete_resource_plan::DeleteResourcePlanPreparationDataV2;
use crate::domain_ledger::create_storage_history::{HistoryErrorV1, continuation::framing};
use super::final_inventory::DeleteRootFreshFrameDataV2;
use super::inventory_cuts::fresh_six_cut_data_v2;
use super::transport::{DeleteRootWireErrorV2, array, decode_clock, encode_clock, encode_header_v3, header_v3};

/// Holds the full fixed preparatory-plan context width.
pub const DELETE_ROOT_RESOURCE_CONTEXT_BYTES_V2: usize = 232;
/// Holds the exact unsigned draft length-prefix width before variable receipt.
pub const DELETE_ROOT_RESOURCE_DRAFT_HEADER_BYTES_V2: usize = 24;
/// Holds the exact signed-result length-prefix width before variable receipt.
pub const DELETE_ROOT_RESOURCE_SIGNED_HEADER_BYTES_V2: usize = 16;
const CONTEXT_MAGIC: &[u8; 8] = b"AOSDPC03";
const DRAFT_MAGIC: &[u8; 8] = b"AOSDPD03";
const SIGNED_MAGIC: &[u8; 8] = b"AOSDPS03";
const DRAFT_DOMAIN: &[u8] = b"aos.sandbox.delete.preparatory-plan-draft.v3\0";
const SIGNED_DOMAIN: &[u8] = b"aos.sandbox.delete.preparatory-plan-acceptance.v3\0";

/// Selects one finite resource exchange on the same retained Delete original.
///
/// The Apply purpose binds the actual completed post26 comparison. It cannot
/// decode preparatory bytes as destruction approval or extend any horizon.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeleteRootResourcePurposeDataV3 {
    /// Prepares a catalog without destroying a resource.
    Preparation26,
    /// Applies the actual newly returned and independently checked catalog.
    Apply7,
    /// Destroys the selected existing Network after actual signed7 approval.
    Network9,
    /// Reaps the exact Ready namespace after genuine Destroy9 and fresh Host3.
    MountReap62,
}

impl DeleteRootResourcePurposeDataV3 {
    fn context_magic(self) -> &'static [u8;8] { match self {
        Self::Preparation26 => CONTEXT_MAGIC, Self::Apply7 => b"AOSDAC03", Self::Network9 => b"AOSDNC04", Self::MountReap62 => b"AOSDMC04",
    } }
    fn draft_magic(self) -> &'static [u8;8] { match self {
        Self::Preparation26 => DRAFT_MAGIC, Self::Apply7 => b"AOSDAD03", Self::Network9 => b"AOSDND04", Self::MountReap62 => b"AOSDMD04",
    } }
    fn signed_magic(self) -> &'static [u8;8] { match self {
        Self::Preparation26 => SIGNED_MAGIC, Self::Apply7 => b"AOSDAS03", Self::Network9 => b"AOSDNS04", Self::MountReap62 => b"AOSDMS04",
    } }
    fn draft_domain(self) -> &'static [u8] { match self {
        Self::Preparation26 => DRAFT_DOMAIN,
        Self::Apply7 => b"aos.sandbox.delete.apply-plan-draft.v3\0",
        Self::Network9 => b"aos.sandbox.delete.network-plan-draft.v4\0",
        Self::MountReap62 => b"aos.sandbox.delete.mount-reap-plan-draft.v4\0",
    } }
    fn signed_domain(self) -> &'static [u8] { match self {
        Self::Preparation26 => SIGNED_DOMAIN,
        Self::Apply7 => b"aos.sandbox.delete.apply-plan-approval.v3\0",
        Self::Network9 => b"aos.sandbox.delete.network-plan-approval.v4\0",
        Self::MountReap62 => b"aos.sandbox.delete.mount-reap-plan-approval.v4\0",
    } }
}


/// Reports malformed framing or a changed same-flight comparison association.
#[derive(Debug, thiserror::Error)]
pub enum DeleteRootResourceWireErrorV2 {
    /// The sole existing bounded field grammar refused its input.
    #[error(transparent)]
    Frame(#[from] HistoryErrorV1),
    /// The fixed Delete context or association was malformed.
    #[error(transparent)]
    Context(#[from] DeleteRootWireErrorV2),
    /// The original initial comparison frame or its full planning data refused.
    #[error(transparent)]
    Initial(#[from] super::initial_inventory::DeleteRootInitialDataErrorV3),
}

type Result<T> = std::result::Result<T, DeleteRootResourceWireErrorV2>;

/// Carries nonauthorizing association DATA from the actual Root plan interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteRootResourceContextDataV2 {
    /// Commits the complete original pending opening.
    pub open: [u8; 32],
    /// Commits its unchanged Root challenge.
    pub challenge: [u8; 32],
    /// Commits every byte of the actual late fresh456 frame.
    pub frame: [u8; 32],
    /// Commits Root's independently verified fresh six preimages.
    pub fresh_six: [u8; 32],
    /// Names the actual current verified lease used by this cleanup scope.
    pub lease: [u8; 32],
    /// Gives the minimum expiry of Root's actual current signed policy pair.
    /// This is supplied only by the real policy159 owner at the native sender;
    /// a DATA value alone grants neither current policy nor signing authority.
    pub policy_expires_seconds: i64,
    /// Gives the actual completed Root plan interval's paid paired sample.
    pub clock: RawPairedClockSample,
}

impl DeleteRootResourceContextDataV2 {
    /// Compares Mount62 context with actual completed9/freshHost3 receipt DATA.
    ///
    /// # Errors
    /// Rejects another opening, strict9 approval, receipt frame, fresh-six or
    /// lease. Native histories and currentness are separate caller obligations.
    pub fn require_cleanup_current_v4(self, original: DeleteRootFreshFrameDataV2,
        current: super::cleanup_current::DeleteRootCleanupCurrentDataV4,
        approved9: super::final_inventory::DeleteRootPreparatoryApprovalDataV3,
        lease: [u8; 32],
    ) -> Result<()> {
        self.require_canonical_v2()?;
        if self.open != original.open || self.challenge != original.challenge
            || current.opening != self.open || approved9.open != self.open
            || approved9.challenge != self.challenge
            || current.approved9 != super::cleanup_current::cleanup_approval_commitment_data_v4(approved9)?
            || self.frame != current.commitment_v4().map_err(|_| DeleteRootWireErrorV2::Association)?
            || self.fresh_six != fresh_six_cut_data_v2(&original.owners).map_err(DeleteRootWireErrorV2::from)?
            || self.lease != lease {
            return Err(DeleteRootWireErrorV2::Association.into());
        }
        Ok(())
    }

    /// Encodes only the distinct preparatory-plan context purpose.
    ///
    /// # Errors
    /// Rejects a zero identity, digest or invalid clock representation.
    pub fn encode_v2(self) -> Result<[u8; DELETE_ROOT_RESOURCE_CONTEXT_BYTES_V2]> { self.encode_for_purpose_v3(DeleteRootResourcePurposeDataV3::Preparation26) }

    /// Uses the same strict codec for the explicit finite resource purpose.
    ///
    /// # Errors
    /// Rejects another purpose or the same malformed fields as the original codec.
    pub fn encode_for_purpose_v3(self, purpose: DeleteRootResourcePurposeDataV3) -> Result<[u8; DELETE_ROOT_RESOURCE_CONTEXT_BYTES_V2]> {
        self.require_canonical_v2()?;
        let mut bytes = [0; DELETE_ROOT_RESOURCE_CONTEXT_BYTES_V2];
        encode_header_v3(&mut bytes, purpose.context_magic());
        for (index, digest) in [self.open, self.challenge, self.frame, self.fresh_six, self.lease].iter().enumerate() {
            bytes[16 + index * 32..48 + index * 32].copy_from_slice(digest);
        }
        bytes[176..184].copy_from_slice(&self.policy_expires_seconds.to_be_bytes());
        encode_clock(&mut bytes, 184, self.clock);
        Ok(bytes)
    }

    /// Decodes the complete exact fixed context without adopting any original.
    ///
    /// # Errors
    /// Rejects another purpose/version, reserved data, width or zero fields.
    pub fn decode_v2(bytes: &[u8]) -> Result<Self> { Self::decode_for_purpose_v3(bytes, DeleteRootResourcePurposeDataV3::Preparation26) }

    /// Uses the same strict codec for the explicit finite resource purpose.
    ///
    /// # Errors
    /// Rejects another purpose or the same malformed fields as the original codec.
    pub fn decode_for_purpose_v3(bytes: &[u8], purpose: DeleteRootResourcePurposeDataV3) -> Result<Self> {
        header_v3(bytes, DELETE_ROOT_RESOURCE_CONTEXT_BYTES_V2, purpose.context_magic())?;
        let value = Self { open: array(bytes, 16)?, challenge: array(bytes, 48)?, frame: array(bytes, 80)?,
            fresh_six: array(bytes, 112)?, lease: array(bytes, 144)?,
            policy_expires_seconds: i64::from_be_bytes(array(bytes, 176)?), clock: decode_clock(bytes, 184)? };
        value.require_canonical_v2()?;
        Ok(value)
    }

    /// Compares this context to supplied complete frame and lease DATA.
    ///
    /// Genuine callers separately retain the actual native Root/Source/C,
    /// current lease verification and unchanged accepted authorization horizon.
    ///
    /// # Errors
    /// Rejects a changed frame, six preimages, lease or original association.
    pub fn require_frame_v2(self, frame: DeleteRootFreshFrameDataV2, lease: [u8; 32]) -> Result<()> {
        self.require_canonical_v2()?;
        if self.open != frame.open || self.challenge != frame.challenge || self.frame != frame.digest_v2()?
            || self.fresh_six != fresh_six_cut_data_v2(&frame.owners).map_err(DeleteRootWireErrorV2::from)? || self.lease != lease {
            return Err(DeleteRootWireErrorV2::Association.into());
        }
        Ok(())
    }

    /// Compares the Apply context with the genuine caller's complete post26 DATA.
    ///
    /// This is a pure comparison. The actual native borrower must separately
    /// prove both completions, same D, current lease, and original horizon.
    ///
    /// # Errors
    /// Rejects a changed original fresh-six, post26 frame or lease.
    pub fn require_preparation_current_v3(self, original: DeleteRootFreshFrameDataV2,
        current: super::preparation_current::DeleteRootPreparationCurrentDataV3,
        preparatory_draft: [u8; 32], lease: [u8;32],
    ) -> Result<()> {
        self.require_canonical_v2()?;
        if self.open != original.open || self.challenge != original.challenge
            || self.open != current.opening || current.draft != preparatory_draft
            || self.frame != current.commitment_v3().map_err(|_| DeleteRootWireErrorV2::Association)?
            || self.fresh_six != fresh_six_cut_data_v2(&original.owners).map_err(DeleteRootWireErrorV2::from)?
            || self.lease != lease {
            return Err(DeleteRootWireErrorV2::Association.into());
        }
        Ok(())
    }

    /// Compares Network9 with the actual caller's full approved7 predecessor.
    ///
    /// # Errors
    /// Rejects altered352, strict7 approval, original fresh cuts or current lease.
    pub fn require_network_predecessor_v4(self, original: DeleteRootFreshFrameDataV2,
        predecessor: DeleteRootNetworkPredecessorDataV4, prior26_draft: [u8; 32], lease: [u8; 32],
    ) -> Result<()> {
        self.require_canonical_v2()?;
        if self.open != original.open || self.challenge != original.challenge
            || self.open != predecessor.current.opening || predecessor.current.draft != prior26_draft
            || predecessor.approval.open != original.open || predecessor.approval.challenge != original.challenge
            || self.frame != predecessor.commitment_v4()?
            || self.fresh_six != fresh_six_cut_data_v2(&original.owners).map_err(DeleteRootWireErrorV2::from)?
            || self.lease != lease {
            return Err(DeleteRootWireErrorV2::Association.into());
        }
        Ok(())
    }

    fn require_canonical_v2(self) -> Result<()> {
        if [self.open, self.challenge, self.frame, self.fresh_six, self.lease].into_iter().any(|value| value == [0; 32])
            || self.clock.boottime_nanoseconds() == 0 {
            return Err(DeleteRootWireErrorV2::Format.into());
        }
        if self.clock.wall_seconds() >= self.policy_expires_seconds {
            return Err(DeleteRootWireErrorV2::Clock.into());
        }
        Ok(())
    }
}

/// Carries passive full352 and strict7-approval comparison bytes for Network9.
///
/// Genuine constructors separately retain the actual completed7/26 and same-D
/// owners. These public DATA cannot create a signer, worker or native loan.
#[derive(Clone, Copy)]
pub struct DeleteRootNetworkPredecessorDataV4 {
    /// Carries the exact independently verified post26 comparison.
    pub current: super::preparation_current::DeleteRootPreparationCurrentDataV3,
    /// Carries the exact completed strict7 approval from that same D.
    pub approval: super::final_inventory::DeleteRootPreparatoryApprovalDataV3,
}

impl DeleteRootNetworkPredecessorDataV4 {
    /// Commits every predecessor coordinate under a distinct Network9 domain.
    ///
    /// # Errors
    /// Refuses malformed or mutually inconsistent352 and7 approval DATA.
    pub fn commitment_v4(self) -> Result<[u8; 32]> {
        use sha2::{Digest as _, Sha256};

        let current = self.current.commitment_v3().map_err(|_| DeleteRootWireErrorV2::Association)?;
        if self.current.opening != self.approval.open || self.approval.frame != current {
            return Err(DeleteRootWireErrorV2::Association.into());
        }
        let approval = self.approval.encode_for_purpose_v3(DeleteRootResourcePurposeDataV3::Apply7)?;
        Ok(Sha256::new().chain_update(b"aos.sandbox.delete.network-predecessor.v4\0")
            .chain_update(current).chain_update(approval).finalize().into())
    }
}

/// Borrows exact unarmed preparatory26 output from independently verified owners.
#[derive(Clone, Copy)]
pub struct DeleteRootResourceDraftDataV2<'bytes> {
    /// Borrows the exact fixed context above, including the current lease hash.
    pub context: &'bytes [u8],
    /// Borrows the actual complete canonical unsigned broker plan.
    pub canonical_plan: &'bytes [u8],
    /// Borrows the exact prepared signing statement.
    pub canonical_statement: &'bytes [u8],
    /// Borrows the exact deadline-free existing Prepare26 request body.
    pub deadline_free_body: &'bytes [u8],
}

impl<'bytes> DeleteRootResourceDraftDataV2<'bytes> {
    fn fields_v2(self) -> [&'bytes [u8]; 4] {
        [self.context, self.canonical_plan, self.canonical_statement, self.deadline_free_body]
    }

    fn maxima_v2() -> [usize; 4] {
        [DELETE_ROOT_RESOURCE_CONTEXT_BYTES_V2,
            DeleteResourcePlanPreparationDataV2::maximum_artifact_bytes_v2(),
            DeleteResourcePlanPreparationDataV2::maximum_artifact_bytes_v2(), crate::MAXIMUM_REQUEST_BYTES]
    }

    /// Measures the actual producer's three retained fields before context IO.
    ///
    /// The context always has its exact fixed232 width. The actual context is
    /// subsequently encoded from paid native samples; no placeholder context
    /// or supplied clock participates in this cost-only measurement.
    ///
    /// # Errors
    /// Rejects an empty/oversized artifact or checked length overflow.
    pub fn preparation_encoded_bytes_v2(prepared: &DeleteResourcePlanPreparationDataV2) -> Result<usize> {
        let fields = [prepared.preparation_v2().canonical_plan(),
            prepared.preparation_v2().signing_request().canonical_statement(), prepared.deadline_free_body_v2()];
        let mut total = DELETE_ROOT_RESOURCE_DRAFT_HEADER_BYTES_V2
            .checked_add(DELETE_ROOT_RESOURCE_CONTEXT_BYTES_V2).ok_or(HistoryErrorV1::Extent)?;
        for (field, maximum) in fields.into_iter().zip(Self::maxima_v2().into_iter().skip(1)) {
            if field.is_empty() || field.len() > maximum { return Err(HistoryErrorV1::Extent.into()); }
            total = total.checked_add(field.len()).ok_or(HistoryErrorV1::Extent)?;
        }
        Ok(total)
    }

    /// Bounds the actual borrowed comparison and canonical field-hash scratch.
    ///
    /// This prices passive layouts only and creates no native or signing loan.
    ///
    /// # Errors
    /// Rejects unrepresentable compiled layout arithmetic.
    pub fn comparison_receiving_memory_bytes_v2() -> Result<usize> {
        std::mem::size_of::<Self>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(framing::hash_fields_receiving_bytes()?))
            .ok_or(HistoryErrorV1::Extent.into())
    }

    /// Bounds its actual encoded output and shared commitment scratch as DATA.
    ///
    /// The genuine sender separately prices all native posts, paired samples,
    /// fixed carrier layouts and the complete cumulative stream traffic.
    ///
    /// # Errors
    /// Rejects malformed producer extents or checked memory overflow.
    pub fn preparation_receiving_memory_bytes_v2(prepared: &DeleteResourcePlanPreparationDataV2) -> Result<usize> {
        Self::preparation_encoded_bytes_v2(prepared)?.checked_mul(2)
            .and_then(|bytes| bytes.checked_add(framing::hash_fields_receiving_bytes()?))
            .ok_or(HistoryErrorV1::Extent.into())
    }

    /// Reads bounded announced widths before allocation, through the sole grammar.
    ///
    /// # Errors
    /// Rejects another purpose, empty or oversized fields or checked overflow.
    pub fn declared_bytes_v2(header: &[u8]) -> Result<usize> { Self::declared_bytes_for_purpose_v3(header, DeleteRootResourcePurposeDataV3::Preparation26) }

    /// Uses the same strict codec for the explicit finite resource purpose.
    ///
    /// # Errors
    /// Rejects another purpose or the same malformed fields as the original codec.
    pub fn declared_bytes_for_purpose_v3(header: &[u8], purpose: DeleteRootResourcePurposeDataV3) -> Result<usize> {
        Ok(framing::declared_fields_bytes(header, purpose.draft_magic(), Self::maxima_v2())?)
    }

    /// Decodes the exact full borrowed draft without parsing another plan model.
    ///
    /// # Errors
    /// Rejects another purpose, partial/trailing input, extents or fixed context.
    pub fn decode_v2(bytes: &'bytes [u8]) -> Result<Self> { Self::decode_for_purpose_v3(bytes, DeleteRootResourcePurposeDataV3::Preparation26) }

    /// Uses the same strict codec for the explicit finite resource purpose.
    ///
    /// # Errors
    /// Rejects another purpose or the same malformed fields as the original codec.
    pub fn decode_for_purpose_v3(bytes: &'bytes [u8], purpose: DeleteRootResourcePurposeDataV3) -> Result<Self> {
        let [context, canonical_plan, canonical_statement, deadline_free_body] =
            framing::decode_fields(bytes, purpose.draft_magic(), Self::maxima_v2())?;
        let value = Self { context, canonical_plan, canonical_statement, deadline_free_body };
        value.encoded_bytes_for_purpose_v3(purpose)?;
        Ok(value)
    }

    /// Measures all source-bound fields before a producer or receiver grows.
    ///
    /// # Errors
    /// Rejects invalid context, empty or oversized fields and checked overflow.
    pub fn encoded_bytes_v2(self) -> Result<usize> { self.encoded_bytes_for_purpose_v3(DeleteRootResourcePurposeDataV3::Preparation26) }

    /// Uses the same strict codec for the explicit finite resource purpose.
    ///
    /// # Errors
    /// Rejects another purpose or the same malformed fields as the original codec.
    pub fn encoded_bytes_for_purpose_v3(self, purpose: DeleteRootResourcePurposeDataV3) -> Result<usize> {
        DeleteRootResourceContextDataV2::decode_for_purpose_v3(self.context, purpose)?;
        for (field, maximum) in self.fields_v2().into_iter().zip(Self::maxima_v2()) {
            if field.is_empty() || field.len() > maximum { return Err(HistoryErrorV1::Extent.into()); }
        }
        Ok(framing::fields_bytes(self.fields_v2())?)
    }

    /// Copies a paid range through the same complete finite-field encoder.
    ///
    /// # Errors
    /// Rejects invalid fields, extent overflow or an out-of-range destination.
    pub fn encode_range_v2(self, offset: usize, output: &mut [u8]) -> Result<()> { self.encode_range_for_purpose_v3(offset, output, DeleteRootResourcePurposeDataV3::Preparation26) }

    /// Uses the same strict codec for the explicit finite resource purpose.
    ///
    /// # Errors
    /// Rejects another purpose or the same malformed fields as the original codec.
    pub fn encode_range_for_purpose_v3(self, offset: usize, output: &mut [u8], purpose: DeleteRootResourcePurposeDataV3) -> Result<()> {
        self.encoded_bytes_for_purpose_v3(purpose)?;
        Ok(framing::encode_fields_range(purpose.draft_magic(), self.fields_v2(), offset, output)?)
    }

    /// Commits the exact draft without aggregating or cloning its borrowed fields.
    ///
    /// # Errors
    /// Rejects the same malformed context, field and extent conditions as encoding.
    pub fn digest_v2(self) -> Result<[u8; 32]> { self.digest_for_purpose_v3(DeleteRootResourcePurposeDataV3::Preparation26) }

    /// Uses the same strict codec for the explicit finite resource purpose.
    ///
    /// # Errors
    /// Rejects another purpose or the same malformed fields as the original codec.
    pub fn digest_for_purpose_v3(self, purpose: DeleteRootResourcePurposeDataV3) -> Result<[u8;32]> {
        self.encoded_bytes_for_purpose_v3(purpose)?;
        Ok(framing::hash_fields(purpose.draft_domain(), purpose.draft_magic(), self.fields_v2())?)
    }
}

/// Borrows a signature returned for this exact draft on the same retained D.
#[derive(Clone, Copy)]
pub struct DeleteRootResourceSignedDataV2<'bytes> {
    /// Borrows the complete earlier draft commitment, never a new nonce.
    pub draft: &'bytes [u8],
    /// Borrows the actual canonical detached broker-plan signature.
    pub canonical_signature: &'bytes [u8],
}

impl<'bytes> DeleteRootResourceSignedDataV2<'bytes> {
    /// Bounds this finite response by the existing canonical artifact ceiling.
    ///
    /// This passive extent never admits input, signs a plan or creates a loan.
    ///
    /// # Errors
    /// Rejects checked extent overflow.
    pub fn maximum_encoded_bytes_v2() -> Result<usize> {
        DELETE_ROOT_RESOURCE_SIGNED_HEADER_BYTES_V2.checked_add(32)
            .and_then(|bytes| bytes.checked_add(DeleteResourcePlanPreparationDataV2::maximum_artifact_bytes_v2()))
            .ok_or(HistoryErrorV1::Extent.into())
    }

    fn fields_v2(self) -> [&'bytes [u8]; 2] { [self.draft, self.canonical_signature] }
    fn maxima_v2() -> [usize; 2] { [32, DeleteResourcePlanPreparationDataV2::maximum_artifact_bytes_v2()] }

    /// Reads bounded announced signature widths before allocation.
    ///
    /// # Errors
    /// Rejects another purpose, empty/oversized fields or extent overflow.
    pub fn declared_bytes_v2(header: &[u8]) -> Result<usize> { Self::declared_bytes_for_purpose_v3(header, DeleteRootResourcePurposeDataV3::Preparation26) }

    /// Uses the same strict codec for the explicit finite resource purpose.
    ///
    /// # Errors
    /// Rejects another purpose or the same malformed fields as the original codec.
    pub fn declared_bytes_for_purpose_v3(header: &[u8], purpose: DeleteRootResourcePurposeDataV3) -> Result<usize> {
        Ok(framing::declared_fields_bytes(header, purpose.signed_magic(), Self::maxima_v2())?)
    }

    /// Borrows the exact complete signed-result frame without verifying a key.
    ///
    /// # Errors
    /// Rejects another purpose, partial/trailing input or wrong field widths.
    pub fn decode_v2(bytes: &'bytes [u8]) -> Result<Self> { Self::decode_for_purpose_v3(bytes, DeleteRootResourcePurposeDataV3::Preparation26) }

    /// Uses the same strict codec for the explicit finite resource purpose.
    ///
    /// # Errors
    /// Rejects another purpose or the same malformed fields as the original codec.
    pub fn decode_for_purpose_v3(bytes: &'bytes [u8], purpose: DeleteRootResourcePurposeDataV3) -> Result<Self> {
        let [draft, canonical_signature] = framing::decode_fields(bytes, purpose.signed_magic(), Self::maxima_v2())?;
        let value = Self { draft, canonical_signature };
        value.encoded_bytes_v2()?;
        Ok(value)
    }

    /// Measures this exact nonauthorizing signed-result frame before growth.
    ///
    /// # Errors
    /// Rejects a zero/incorrect draft digest or empty/oversized signature.
    pub fn encoded_bytes_v2(self) -> Result<usize> {
        if self.draft.len() != 32 || self.draft.iter().all(|byte| *byte == 0)
            || self.canonical_signature.is_empty() || self.canonical_signature.len() > Self::maxima_v2()[1] {
            return Err(HistoryErrorV1::Extent.into());
        }
        Ok(framing::fields_bytes(self.fields_v2())?)
    }

    /// Copies a paid signature range with the same bounded field encoder.
    ///
    /// # Errors
    /// Rejects malformed fields or an out-of-range destination.
    pub fn encode_range_v2(self, offset: usize, output: &mut [u8]) -> Result<()> { self.encode_range_for_purpose_v3(offset, output, DeleteRootResourcePurposeDataV3::Preparation26) }

    /// Uses the same strict codec for the explicit finite resource purpose.
    ///
    /// # Errors
    /// Rejects another purpose or the same malformed fields as the original codec.
    pub fn encode_range_for_purpose_v3(self, offset: usize, output: &mut [u8], purpose: DeleteRootResourcePurposeDataV3) -> Result<()> {
        self.encoded_bytes_v2()?;
        Ok(framing::encode_fields_range(purpose.signed_magic(), self.fields_v2(), offset, output)?)
    }

    /// Compares only the complete same-draft association, without effect authority.
    ///
    /// # Errors
    /// Rejects malformed fields or another actual unsigned draft commitment.
    pub fn require_draft_v2(self, draft: DeleteRootResourceDraftDataV2<'_>) -> Result<()> { self.require_draft_for_purpose_v3(draft, DeleteRootResourcePurposeDataV3::Preparation26) }

    /// Uses the same strict codec for the explicit finite resource purpose.
    ///
    /// # Errors
    /// Rejects another purpose or the same malformed fields as the original codec.
    pub fn require_draft_for_purpose_v3(self, draft: DeleteRootResourceDraftDataV2<'_>, purpose: DeleteRootResourcePurposeDataV3) -> Result<()> {
        self.encoded_bytes_v2()?;
        if self.draft != draft.digest_for_purpose_v3(purpose)?.as_slice() { return Err(DeleteRootWireErrorV2::Association.into()); }
        Ok(())
    }

    /// Commits the exact draft and returned signature for bounded acceptance192.
    ///
    /// The genuine Root borrower must independently verify this signature and
    /// all native posts. This DATA hash never supplies such a borrower.
    ///
    /// # Errors
    /// Rejects malformed signature framing or a changed draft association.
    pub fn acceptance_commitment_v2(self, draft: DeleteRootResourceDraftDataV2<'_>) -> Result<[u8; 32]> { self.acceptance_commitment_for_purpose_v3(draft, DeleteRootResourcePurposeDataV3::Preparation26) }

    /// Uses the same strict codec for the explicit finite resource purpose.
    ///
    /// # Errors
    /// Rejects another purpose or the same malformed fields as the original codec.
    pub fn acceptance_commitment_for_purpose_v3(self, draft: DeleteRootResourceDraftDataV2<'_>, purpose: DeleteRootResourcePurposeDataV3) -> Result<[u8;32]> {
        self.require_draft_for_purpose_v3(draft, purpose)?;
        Ok(framing::hash_fields(purpose.signed_domain(), purpose.signed_magic(), self.fields_v2())?)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_model::{RawClockProvenance, RawPairedClockSample};

    fn context() -> [u8; DELETE_ROOT_RESOURCE_CONTEXT_BYTES_V2] {
        DeleteRootResourceContextDataV2 { open: [1; 32], challenge: [2; 32], frame: [3; 32],
            fresh_six: [4; 32], lease: [5; 32], policy_expires_seconds: 10, clock: RawPairedClockSample::new_untrusted(
                RawClockProvenance::new_untrusted([6; 16]).unwrap(), [7; 16], 8, 9).unwrap(),
        }.encode_v2().unwrap()
    }

    #[test]
    fn apply_and_preparation_purposes_cannot_decode_or_relabel_each_other() {
        let ordinary = context();
        let context = DeleteRootResourceContextDataV2::decode_v2(&ordinary).unwrap();
        let apply = context.encode_for_purpose_v3(DeleteRootResourcePurposeDataV3::Apply7).unwrap();
        assert!(DeleteRootResourceContextDataV2::decode_v2(&apply).is_err());
        assert!(DeleteRootResourceContextDataV2::decode_for_purpose_v3(
            &ordinary, DeleteRootResourcePurposeDataV3::Apply7).is_err());

        let draft = DeleteRootResourceDraftDataV2 { context: &apply,
            canonical_plan: b"passive Apply7 plan", canonical_statement: b"passive statement",
            deadline_free_body: b"passive Apply7 body" };
        assert!(draft.encoded_bytes_v2().is_err());
        let mut bytes = vec![0; draft.encoded_bytes_for_purpose_v3(DeleteRootResourcePurposeDataV3::Apply7).unwrap()];
        draft.encode_range_for_purpose_v3(0, &mut bytes, DeleteRootResourcePurposeDataV3::Apply7).unwrap();
        assert!(DeleteRootResourceDraftDataV2::decode_v2(&bytes).is_err());
        let decoded = DeleteRootResourceDraftDataV2::decode_for_purpose_v3(
            &bytes, DeleteRootResourcePurposeDataV3::Apply7).unwrap();
        assert_eq!(decoded.digest_for_purpose_v3(DeleteRootResourcePurposeDataV3::Apply7).unwrap(),
            draft.digest_for_purpose_v3(DeleteRootResourcePurposeDataV3::Apply7).unwrap());

        let digest = draft.digest_for_purpose_v3(DeleteRootResourcePurposeDataV3::Apply7).unwrap();
        let signed = DeleteRootResourceSignedDataV2 { draft: &digest, canonical_signature: b"passive signature" };
        let mut reply = vec![0; signed.encoded_bytes_v2().unwrap()];
        signed.encode_range_for_purpose_v3(0, &mut reply, DeleteRootResourcePurposeDataV3::Apply7).unwrap();
        assert!(DeleteRootResourceSignedDataV2::decode_v2(&reply).is_err());
        let decoded = DeleteRootResourceSignedDataV2::decode_for_purpose_v3(
            &reply, DeleteRootResourcePurposeDataV3::Apply7).unwrap();
        decoded.require_draft_for_purpose_v3(draft, DeleteRootResourcePurposeDataV3::Apply7).unwrap();
        assert!(decoded.require_draft_v2(draft).is_err());
    }

    #[test]
    fn network_and_mount_context_draft_signature_and_approval_purposes_are_distinct() {
        use DeleteRootResourcePurposeDataV3 as P;
        for purpose in [P::Network9, P::MountReap62] {
        let context = DeleteRootResourceContextDataV2::decode_v2(&context()).unwrap();
        let context_bytes = context.encode_for_purpose_v3(purpose).unwrap();
        let draft = DeleteRootResourceDraftDataV2 { context: &context_bytes,
            canonical_plan: b"passive network plan", canonical_statement: b"passive statement",
            deadline_free_body: b"passive network body" };
        let mut bytes = vec![0; draft.encoded_bytes_for_purpose_v3(purpose).unwrap()];
        draft.encode_range_for_purpose_v3(0, &mut bytes, purpose).unwrap();
        let digest = draft.digest_for_purpose_v3(purpose).unwrap();
        let signed = DeleteRootResourceSignedDataV2 { draft: &digest, canonical_signature: b"passive signature" };
        let mut signature = vec![0; signed.encoded_bytes_v2().unwrap()];
        signed.encode_range_for_purpose_v3(0, &mut signature, purpose).unwrap();
        let approval = super::super::final_inventory::DeleteRootPreparatoryApprovalDataV3 {
            open: [1; 32], challenge: [2; 32], frame: [3; 32], preparation: [4; 32], clock: context.clock,
        }.encode_for_purpose_v3(purpose).unwrap();
        for other in [P::Preparation26, P::Apply7, P::Network9, P::MountReap62]
            .into_iter().filter(|other| *other != purpose) {
            assert!(DeleteRootResourceContextDataV2::decode_for_purpose_v3(&context_bytes, other).is_err());
            assert!(DeleteRootResourceDraftDataV2::decode_for_purpose_v3(&bytes, other).is_err());
            assert!(DeleteRootResourceSignedDataV2::decode_for_purpose_v3(&signature, other).is_err());
            assert!(super::super::final_inventory::DeleteRootPreparatoryApprovalDataV3::decode_for_purpose_v3(&approval, other).is_err());
        }
        }
    }

    #[test]
    fn network_predecessor_commits_actual352_and_every_strict7_approval_field() {
        let native = crate::domain_ledger::delete_batch::encode_native_commit_data_v1(
            [4; 16], 7, 512, &[5; 32]).unwrap();
        let current = super::super::preparation_current::DeleteRootPreparationCurrentDataV3 {
            challenge: [1; 16], opening: [2; 32], draft: [3; 32], controller: native,
            source: native, session: native, request: [6; 32], outcome: [7; 32],
        };
        let clock = DeleteRootResourceContextDataV2::decode_v2(&context()).unwrap().clock;
        let original = DeleteRootNetworkPredecessorDataV4 { current,
            approval: super::super::final_inventory::DeleteRootPreparatoryApprovalDataV3 {
                open: current.opening, challenge: [8; 32], frame: current.commitment_v3().unwrap(),
                preparation: [9; 32], clock,
            } };
        let commitment = original.commitment_v4().unwrap();
        let mut changed = original;
        changed.current.session[63] ^= 1;
        assert!(changed.commitment_v4().is_err());
        changed.approval.frame = changed.current.commitment_v3().unwrap();
        assert_ne!(changed.commitment_v4().unwrap(), commitment);
        let mut changed = original;
        changed.approval.preparation[0] ^= 1;
        assert_ne!(changed.commitment_v4().unwrap(), commitment);
        let mut changed = original;
        changed.approval.challenge[31] ^= 1;
        assert_ne!(changed.commitment_v4().unwrap(), commitment);
        let mut changed = original;
        changed.approval.open[0] ^= 1;
        assert!(changed.commitment_v4().is_err());
    }

    #[test]
    fn exact_draft_and_signature_use_the_shared_range_encoder_and_bind_all_fields() {
        let context = context();
        let draft = DeleteRootResourceDraftDataV2 { context: &context,
            canonical_plan: b"bounded passive plan fixture", canonical_statement: b"passive statement",
            deadline_free_body: b"passive body" };
        let mut bytes = vec![0; draft.encoded_bytes_v2().unwrap()];
        draft.encode_range_v2(0, &mut bytes).unwrap();
        let decoded = DeleteRootResourceDraftDataV2::decode_v2(&bytes).unwrap();
        assert_eq!(decoded.digest_v2().unwrap(), draft.digest_v2().unwrap());
        assert_eq!(DeleteRootResourceDraftDataV2::declared_bytes_v2(
            &bytes[..DELETE_ROOT_RESOURCE_DRAFT_HEADER_BYTES_V2]).unwrap(), bytes.len());
        let mut segmented = vec![0; bytes.len()];
        for (index, chunk) in segmented.chunks_mut(17).enumerate() {
            draft.encode_range_v2(index * 17, chunk).unwrap();
        }
        assert_eq!(segmented, bytes);

        let mut later_policy = context;
        later_policy[176..184].copy_from_slice(&11i64.to_be_bytes());
        let later = DeleteRootResourceDraftDataV2 { context: &later_policy, ..draft };
        assert_ne!(later.digest_v2().unwrap(), draft.digest_v2().unwrap());
        let digest = draft.digest_v2().unwrap();
        let signed = DeleteRootResourceSignedDataV2 { draft: &digest, canonical_signature: &[10; 64] };
        let accepted = signed.acceptance_commitment_v2(draft).unwrap();
        let changed = DeleteRootResourceDraftDataV2 { deadline_free_body: b"another body", ..draft };
        assert!(signed.require_draft_v2(changed).is_err());
        let changed = DeleteRootResourceSignedDataV2 { canonical_signature: &[11; 64], ..signed };
        assert_ne!(changed.acceptance_commitment_v2(draft).unwrap(), accepted);
        let mut signed_bytes = vec![0; signed.encoded_bytes_v2().unwrap()];
        signed.encode_range_v2(0, &mut signed_bytes).unwrap();
        assert_eq!(DeleteRootResourceSignedDataV2::decode_v2(&signed_bytes).unwrap()
            .acceptance_commitment_v2(draft).unwrap(), accepted);
        assert!(DeleteRootResourceDraftDataV2::decode_v2(&signed_bytes).is_err());
        assert!(DeleteRootResourceSignedDataV2::decode_v2(&bytes).is_err());
    }

    #[test]
    fn context_and_nested_extent_refusals_have_no_old_or_trailing_alias() {
        let context = context();
        let draft = DeleteRootResourceDraftDataV2 { context: &context, canonical_plan: &[1],
            canonical_statement: &[2], deadline_free_body: &[3] };
        let mut bytes = vec![0; draft.encoded_bytes_v2().unwrap()];
        draft.encode_range_v2(0, &mut bytes).unwrap();
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(DeleteRootResourceDraftDataV2::decode_v2(&trailing).is_err());
        let mut wrong_version = context;
        wrong_version[8..10].copy_from_slice(&1u16.to_be_bytes());
        assert!(DeleteRootResourceContextDataV2::decode_v2(&wrong_version).is_err());
        let mut old = context[..176].to_vec();
        old.extend_from_slice(&context[184..]);
        assert_eq!(old.len(), 224);
        old[..8].copy_from_slice(b"AOSDPC02");
        old[8..10].copy_from_slice(&2u16.to_be_bytes());
        assert!(DeleteRootResourceContextDataV2::decode_v2(&old).is_err());
        let mut expired = context;
        expired[176..184].copy_from_slice(&8i64.to_be_bytes());
        assert!(DeleteRootResourceContextDataV2::decode_v2(&expired).is_err());
        let mut wrong_reserved = context;
        wrong_reserved[10] = 1;
        assert!(DeleteRootResourceContextDataV2::decode_v2(&wrong_reserved).is_err());
        let mut old_draft = bytes.clone();
        old_draft[..8].copy_from_slice(b"AOSDPD02");
        assert!(DeleteRootResourceDraftDataV2::decode_v2(&old_draft).is_err());
        let mut wrong_lease = context;
        wrong_lease[144..176].fill(0);
        assert!(DeleteRootResourceContextDataV2::decode_v2(&wrong_lease).is_err());
        let mut header = bytes[..DELETE_ROOT_RESOURCE_DRAFT_HEADER_BYTES_V2].to_vec();
        header[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(DeleteRootResourceDraftDataV2::declared_bytes_v2(&header).is_err());
        assert!(DeleteRootResourceDraftDataV2::decode_v2(&bytes[..bytes.len() - 1]).is_err());
    }
}
