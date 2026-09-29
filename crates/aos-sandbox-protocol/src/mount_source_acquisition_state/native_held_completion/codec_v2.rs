//! Explicit native Root v2 framing with two immutable historical cuts.
//!
//! No v1 row is upgraded or rewritten by this codec.
//!
//! ```text
//! AOSMHC02 | version:u16=2 | flags0 | reserved[4] | original_scope[224] |
//! CAS_id[16] | lengths:u32[7] | R | S | verifier | suffix |
//! AdmissionCut | DispositionCut | NoInterestTerminal
//! ```

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::native_held_completion::{
    MAXIMUM_NATIVE_HELD_SUFFIX_BYTES_V1, NativeHeldControlKindV1 as Kind, NativeHeldScopeV1,
    assertion::{
        NativeHeldDispositionV1, NativeHeldSettlementV1, RootNativeDispositionAssertionV1,
    },
    suffix::NativeHeldCompletionSuffixV1,
};

use super::{
    MAXIMUM_ROOT_NATIVE_VERIFIER_BYTES_V1, RootNativeHeldSidecarV1, RootNativeTerminalVerifierV1,
    codec::Reader,
    cut::{MAXIMUM_ROOT_NATIVE_CUT_BYTES_V1, RootNativeCutKindV1, RootNativeCutV1},
};
use crate::mount_source_acquisition_state::{RecordRefV2, Result, format::state_error};

const PREFIX: &[u8] = b"aos.mount.native-held-completion.v2\0";

/// Fixes the explicit v2 original Mount-attempt sidecar key width.
pub const ROOT_NATIVE_HELD_KEY_BYTES_V2: usize = 68;

/// Bounds v2 while preserving the frozen v1 maximum separately.
pub const MAXIMUM_ROOT_NATIVE_HELD_SIDECAR_BYTES_V2: usize = 159_642;

/// Fixes the native local no-interest terminal width.
pub const ROOT_NATIVE_NO_INTEREST_TERMINAL_BYTES_V1: usize = 272;

const _: () = assert!(PREFIX.len() + 32 == ROOT_NATIVE_HELD_KEY_BYTES_V2);
const _: () = assert!(
    MAXIMUM_ROOT_NATIVE_HELD_SIDECAR_BYTES_V2
        == super::MAXIMUM_ROOT_NATIVE_HELD_SIDECAR_BYTES_V1
            + 12
            + 2 * MAXIMUM_ROOT_NATIVE_CUT_BYTES_V1
            + ROOT_NATIVE_NO_INTEREST_TERMINAL_BYTES_V1
);

/// Returns the distinct v2 key for one nonzero original Mount attempt.
///
/// # Errors
///
/// Rejects a sentinel attempt; this establishes no protected mutation scope.
pub fn native_root_sidecar_key_v2(attempt: [u8; 32]) -> Result<Vec<u8>> {
    if attempt == [0; 32] {
        return Err(state_error("native Root v2 sentinel attempt"));
    }
    let mut key = PREFIX.to_vec();
    key.extend_from_slice(&attempt);
    Ok(key)
}

pub(super) fn is_sidecar_key_v2(key: &[u8]) -> bool {
    key.len() == ROOT_NATIVE_HELD_KEY_BYTES_V2 && key.starts_with(PREFIX)
}

/// Retains exact local terminal cleanup data, never dispatch-exclusion authority.
///
/// ```text
/// AOSMNT01 | version:u16=1 | kind:u8=1 | reserved[5] |
/// cleanup_TX[16] | Closed_R_digest[32] | settled_Attempt_ref[72] |
/// Faulted_Acquisition_ref[72] | retired_Root8_ID[32] | retired_Root8_digest[32]
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootNativeNoInterestTerminalV1 {
    pub(super) cleanup_transaction: [u8; 16],
    pub(super) closed_disposition: ObjectDigest,
    pub(super) settled_attempt: RecordRefV2,
    pub(super) faulted_acquisition: RecordRefV2,
    pub(super) retired_capacity_id: [u8; 32],
    pub(super) retired_capacity_digest: [u8; 32],
}

impl RootNativeNoInterestTerminalV1 {
    /// Constructs structurally valid local terminal DATA without proving cleanup.
    ///
    /// Authenticated settlement, complete current-owner graph validation and
    /// exact old-floor ID/value-digest deletion remain separate responsibilities.
    /// No marker data grants no-dispatch, signing or protected journal authority.
    ///
    /// # Errors
    ///
    /// Rejects the existing fixed-format sentinel and terminal revision errors.
    pub fn new(
        cleanup_transaction: [u8; 16],
        closed_disposition: ObjectDigest,
        settled_attempt: RecordRefV2,
        faulted_acquisition: RecordRefV2,
        retired_capacity_id: [u8; 32],
        retired_capacity_digest: [u8; 32],
    ) -> Result<Self> {
        let value = Self {
            cleanup_transaction,
            closed_disposition,
            settled_attempt,
            faulted_acquisition,
            retired_capacity_id,
            retired_capacity_digest,
        };
        value.to_canonical_bytes()?;
        Ok(value)
    }

    /// Returns the exact cleanup append identity as nonauthorizing data.
    #[must_use]
    pub const fn cleanup_transaction(&self) -> [u8; 16] {
        self.cleanup_transaction
    }

    /// Returns the immutable original Closed R identity.
    #[must_use]
    pub const fn closed_disposition(&self) -> ObjectDigest {
        self.closed_disposition
    }

    /// Returns the exact authenticated terminal wrapper reference.
    #[must_use]
    pub const fn settled_attempt(&self) -> RecordRefV2 {
        self.settled_attempt
    }

    /// Returns the exact no-evidence faulted acquisition reference.
    #[must_use]
    pub const fn faulted_acquisition(&self) -> RecordRefV2 {
        self.faulted_acquisition
    }

    /// Returns the exact retired Root8 reservation identity and digest.
    #[must_use]
    pub const fn retired_capacity(&self) -> ([u8; 32], [u8; 32]) {
        (self.retired_capacity_id, self.retired_capacity_digest)
    }

    /// Encodes the exact 272-byte local terminal data.
    ///
    /// # Errors
    ///
    /// Rejects sentinel identities or unsupported terminal revisions.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        if self.cleanup_transaction == [0; 16]
            || self.closed_disposition.as_bytes() == &[0; 32]
            || self.settled_attempt.id == [0; 32]
            || !matches!(self.settled_attempt.revision, 3 | 4)
            || self.settled_attempt.record_digest == [0; 32]
            || self.faulted_acquisition.id == [0; 32]
            || self.faulted_acquisition.revision == 0
            || self.faulted_acquisition.record_digest == [0; 32]
            || self.retired_capacity_id == [0; 32]
            || self.retired_capacity_digest == [0; 32]
        {
            return Err(state_error(
                "native no-interest terminal sentinel or revision",
            ));
        }
        let mut bytes = b"AOSMNT01".to_vec();
        bytes.extend_from_slice(&[0, 1, 1, 0, 0, 0, 0, 0]);
        bytes.extend_from_slice(&self.cleanup_transaction);
        bytes.extend_from_slice(self.closed_disposition.as_bytes());
        for record in [self.settled_attempt, self.faulted_acquisition] {
            bytes.extend_from_slice(&record.id);
            bytes.extend_from_slice(&record.revision.to_be_bytes());
            bytes.extend_from_slice(&record.record_digest);
        }
        bytes.extend_from_slice(&self.retired_capacity_id);
        bytes.extend_from_slice(&self.retired_capacity_digest);
        if bytes.len() != ROOT_NATIVE_NO_INTEREST_TERMINAL_BYTES_V1 {
            return Err(state_error("native no-interest terminal fixed width"));
        }
        Ok(bytes)
    }

    /// Decodes only canonical local terminal data, without proving old-floor deletion.
    ///
    /// # Errors
    ///
    /// Rejects wrong framing, reserved bytes, width, sentinels or revisions.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ROOT_NATIVE_NO_INTEREST_TERMINAL_BYTES_V1 {
            return Err(state_error("native no-interest terminal fixed width"));
        }
        let mut reader = Reader::new(bytes);
        if reader.bytes(8)? != b"AOSMNT01" || reader.bytes(8)? != [0, 1, 1, 0, 0, 0, 0, 0] {
            return Err(state_error("native no-interest terminal header"));
        }
        let value = Self {
            cleanup_transaction: reader.array()?,
            closed_disposition: ObjectDigest::from_bytes(reader.array()?),
            settled_attempt: read_reference(&mut reader)?,
            faulted_acquisition: read_reference(&mut reader)?,
            retired_capacity_id: reader.array()?,
            retired_capacity_digest: reader.array()?,
        };
        reader.finish()?;
        if value.to_canonical_bytes()? != bytes {
            return Err(state_error("native no-interest terminal canonical bytes"));
        }
        Ok(value)
    }
}

/// Retains native v2 claims and two independently immutable historical cuts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootNativeHeldSidecarV2 {
    pub(super) claims: RootNativeHeldSidecarV1,
    pub(super) admission_cut: RootNativeCutV1,
    pub(super) disposition_cut: Option<RootNativeCutV1>,
    pub(super) no_interest_terminal: Option<RootNativeNoInterestTerminalV1>,
}

impl RootNativeHeldSidecarV2 {
    /// Collects explicit v2 data with mandatory original admission lineage.
    ///
    /// Existing claims are reused as typed data only. A legacy row cannot be
    /// migrated by supplying today's values as its missing historical cuts.
    ///
    /// # Errors
    ///
    /// Rejects phase/cut/terminal presence, original lineage or byte bounds.
    pub fn new(
        original_scope: NativeHeldScopeV1,
        response_transaction: [u8; 16],
        disposition: Option<RootNativeDispositionAssertionV1>,
        settlement: Option<NativeHeldSettlementV1>,
        terminal_verifier: Option<RootNativeTerminalVerifierV1>,
        suffix: NativeHeldCompletionSuffixV1,
        admission_cut: RootNativeCutV1,
        disposition_cut: Option<RootNativeCutV1>,
        no_interest_terminal: Option<RootNativeNoInterestTerminalV1>,
    ) -> Result<Self> {
        let value = Self {
            claims: RootNativeHeldSidecarV1::new(
                original_scope,
                response_transaction,
                disposition,
                settlement,
                terminal_verifier,
                suffix,
            )?,
            admission_cut,
            disposition_cut,
            no_interest_terminal,
        };
        value.validate()?;
        Ok(value)
    }

    /// Returns the immutable original Root-only scope.
    #[must_use]
    pub const fn original_scope(&self) -> &NativeHeldScopeV1 {
        self.claims.original_scope()
    }

    /// Returns the original response CAS transaction identity.
    #[must_use]
    pub const fn response_transaction(&self) -> [u8; 16] {
        self.claims.response_transaction()
    }

    /// Returns the irreversible original Root disposition.
    #[must_use]
    pub const fn disposition(&self) -> Option<&RootNativeDispositionAssertionV1> {
        self.claims.disposition()
    }

    /// Returns the immutable terminal interest settlement tuple.
    #[must_use]
    pub const fn settlement(&self) -> Option<&NativeHeldSettlementV1> {
        self.claims.settlement()
    }

    /// Returns the original recovery-terminal verifier projection.
    #[must_use]
    pub const fn terminal_verifier(&self) -> Option<&RootNativeTerminalVerifierV1> {
        self.claims.terminal_verifier()
    }

    /// Returns all append-once signed archives and the unescaped preparation.
    #[must_use]
    pub const fn suffix(&self) -> &NativeHeldCompletionSuffixV1 {
        self.claims.suffix()
    }

    /// Returns the mandatory post-admission historical cut.
    #[must_use]
    pub const fn admission_cut(&self) -> &RootNativeCutV1 {
        &self.admission_cut
    }

    /// Returns the independently captured first-R historical cut.
    #[must_use]
    pub const fn disposition_cut(&self) -> Option<&RootNativeCutV1> {
        self.disposition_cut.as_ref()
    }

    /// Returns genuine local no-interest terminal data when retained.
    #[must_use]
    pub const fn no_interest_terminal(&self) -> Option<&RootNativeNoInterestTerminalV1> {
        self.no_interest_terminal.as_ref()
    }

    /// Encodes v2 with seven independently checked component lengths.
    ///
    /// # Errors
    ///
    /// Rejects invalid claims/cuts or any fixed component/complete byte bound.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let r = self
            .disposition()
            .map(RootNativeDispositionAssertionV1::to_canonical_bytes)
            .transpose()
            .map_err(|_| state_error("native Root v2 R"))?
            .map(|b| b.to_vec())
            .unwrap_or_default();
        let s = self
            .settlement()
            .map(NativeHeldSettlementV1::to_canonical_bytes)
            .transpose()
            .map_err(|_| state_error("native Root v2 S"))?
            .map(|b| b.to_vec())
            .unwrap_or_default();
        let verifier = self
            .terminal_verifier()
            .map(RootNativeTerminalVerifierV1::to_canonical_bytes)
            .transpose()?
            .unwrap_or_default();
        let suffix = self
            .suffix()
            .to_canonical_bytes()
            .map_err(|_| state_error("native Root v2 suffix"))?;
        let admission = self.admission_cut.to_canonical_bytes()?;
        let disposition = self
            .disposition_cut
            .as_ref()
            .map(RootNativeCutV1::to_canonical_bytes)
            .transpose()?
            .unwrap_or_default();
        let terminal = self
            .no_interest_terminal
            .as_ref()
            .map(RootNativeNoInterestTerminalV1::to_canonical_bytes)
            .transpose()?
            .unwrap_or_default();
        let fields = [
            &r,
            &s,
            &verifier,
            &suffix,
            &admission,
            &disposition,
            &terminal,
        ];
        let mut bytes = b"AOSMHC02".to_vec();
        bytes.extend_from_slice(&[0, 2, 0, 0, 0, 0, 0, 0]);
        bytes.extend_from_slice(&self.original_scope().to_canonical_bytes());
        bytes.extend_from_slice(&self.response_transaction());
        for field in fields {
            bytes.extend_from_slice(&(field.len() as u32).to_be_bytes());
        }
        for field in fields {
            bytes.extend_from_slice(field);
        }
        if bytes.len() > MAXIMUM_ROOT_NATIVE_HELD_SIDECAR_BYTES_V2 {
            return Err(state_error("native Root v2 complete byte bound"));
        }
        Ok(bytes)
    }

    /// Decodes only the exact v2 key, header and canonical nested bodies.
    ///
    /// # Errors
    ///
    /// Rejects v1/near-prefix keys, unsupported versions, reserved bytes,
    /// overflowing component lengths, malformed cuts and trailing data.
    pub fn from_canonical_bytes(key: &[u8], bytes: &[u8]) -> Result<Self> {
        if !is_sidecar_key_v2(key) || bytes.len() > MAXIMUM_ROOT_NATIVE_HELD_SIDECAR_BYTES_V2 {
            return Err(state_error("native Root v2 key or complete byte bound"));
        }
        let mut reader = Reader::new(bytes);
        if reader.bytes(8)? != b"AOSMHC02" || reader.bytes(8)? != [0, 2, 0, 0, 0, 0, 0, 0] {
            return Err(state_error("native Root v2 magic/version/reserved"));
        }
        let original_scope = NativeHeldScopeV1 {
            flight: ObjectDigest::from_bytes(reader.array()?),
            original_source_session: ObjectDigest::from_bytes(reader.array()?),
            mount_attempt: ObjectDigest::from_bytes(reader.array()?),
            provider_attempt: ObjectDigest::from_bytes(reader.array()?),
            provider_acquisition: ObjectDigest::from_bytes(reader.array()?),
            original_root_request: ObjectDigest::from_bytes(reader.array()?),
            original_native_request: ObjectDigest::from_bytes(reader.array()?),
        };
        let response_transaction = reader.array()?;
        let lengths = [
            reader.u32()?,
            reader.u32()?,
            reader.u32()?,
            reader.u32()?,
            reader.u32()?,
            reader.u32()?,
            reader.u32()?,
        ];
        let caps = [
            722,
            104,
            MAXIMUM_ROOT_NATIVE_VERIFIER_BYTES_V1,
            MAXIMUM_NATIVE_HELD_SUFFIX_BYTES_V1,
            MAXIMUM_ROOT_NATIVE_CUT_BYTES_V1,
            MAXIMUM_ROOT_NATIVE_CUT_BYTES_V1,
            ROOT_NATIVE_NO_INTEREST_TERMINAL_BYTES_V1,
        ];
        if lengths
            .into_iter()
            .zip(caps)
            .any(|(length, maximum)| length > maximum)
        {
            return Err(state_error("native Root v2 component bound"));
        }
        let r = reader.bytes(lengths[0])?;
        let disposition = if r.is_empty() {
            None
        } else {
            Some(
                RootNativeDispositionAssertionV1::from_canonical_bytes(r)
                    .map_err(|_| state_error("native Root v2 R bytes"))?,
            )
        };
        let s = reader.bytes(lengths[1])?;
        let settlement = if s.is_empty() {
            None
        } else {
            Some(
                NativeHeldSettlementV1::from_canonical_bytes(s)
                    .map_err(|_| state_error("native Root v2 S bytes"))?,
            )
        };
        let verifier = reader.bytes(lengths[2])?;
        let terminal_verifier = if verifier.is_empty() {
            None
        } else {
            Some(RootNativeTerminalVerifierV1::from_canonical_bytes(
                verifier,
            )?)
        };
        let suffix = NativeHeldCompletionSuffixV1::from_canonical_bytes(reader.bytes(lengths[3])?)
            .map_err(|_| state_error("native Root v2 suffix bytes"))?;
        let admission_cut = RootNativeCutV1::from_canonical_bytes(reader.bytes(lengths[4])?)?;
        let cut = reader.bytes(lengths[5])?;
        let disposition_cut = if cut.is_empty() {
            None
        } else {
            Some(RootNativeCutV1::from_canonical_bytes(cut)?)
        };
        let marker = reader.bytes(lengths[6])?;
        let no_interest_terminal = if marker.is_empty() {
            None
        } else {
            Some(RootNativeNoInterestTerminalV1::from_canonical_bytes(
                marker,
            )?)
        };
        reader.finish()?;
        let value = Self::new(
            original_scope,
            response_transaction,
            disposition,
            settlement,
            terminal_verifier,
            suffix,
            admission_cut,
            disposition_cut,
            no_interest_terminal,
        )?;
        if native_root_sidecar_key_v2(*value.original_scope().mount_attempt.as_bytes())? != key
            || value.to_canonical_bytes()? != bytes
        {
            return Err(state_error("native Root v2 canonical/key mismatch"));
        }
        Ok(value)
    }

    pub(super) fn validate(&self) -> Result<()> {
        self.claims.validate()?;
        self.admission_cut.to_canonical_bytes()?;
        if self.admission_cut.kind() != RootNativeCutKindV1::Admission
            || self.disposition_cut.is_some() != self.disposition().is_some()
            || self.disposition_cut.as_ref().is_some_and(|cut| {
                cut.kind() != RootNativeCutKindV1::Disposition
                    || cut.original_session() != self.admission_cut.original_session()
            })
        {
            return Err(state_error(
                "native Root v2 exact cut presence/kind/Session",
            ));
        }
        if let Some(cut) = &self.disposition_cut {
            cut.to_canonical_bytes()?;
        }
        if let Some(marker) = &self.no_interest_terminal {
            marker.to_canonical_bytes()?;
            if !matches!(self.suffix().phase(), 10 | 11)
                || self.disposition().is_none_or(|r| {
                    r.disposition != NativeHeldDispositionV1::Closed
                        || r.digest().ok() != Some(marker.closed_disposition)
                })
                || self.settlement().is_some()
                || self.terminal_verifier().is_some()
                || self.suffix().prepared().is_some()
                || self
                    .suffix()
                    .controls()
                    .iter()
                    .any(|control| !matches!(control.kind(), Kind::RootPrepared | Kind::RootClosed))
            {
                return Err(state_error("native Root local no-interest terminal shape"));
            }
        }
        Ok(())
    }
}

fn read_reference(reader: &mut Reader<'_>) -> Result<RecordRefV2> {
    Ok(RecordRefV2 {
        id: reader.array()?,
        revision: u64::from_be_bytes(reader.array()?),
        record_digest: reader.array()?,
    })
}
