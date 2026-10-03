//! Pure native held-issuance values, exact replay reductions and capacity data.
//!
//! ```text
//! AOSNSI02 | version:u16be=2 | reserved[6] | retirement[64] |
//! request_length:u32be | acceptance_length:u32be |
//! original_signed_request | original_unsigned_acceptance | AOSNHS01_suffix
//! ```
//!
//! This separate codec does not widen the live ledger's legacy decoder. Parsing,
//! reducing or measuring these values supplies no authenticated peer, signer,
//! descriptor custody, retained writer, admission or permission to send. In
//! particular, the live 1024*2 transaction ceiling is not this eight-write floor.

use aos_sandbox::journal::{JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::native_held_completion::assertion::{
    NativeHeldDispositionV1, RootNativeDispositionAssertionV1, StorageNativeSettlementAssertionV1,
};
use aos_sandbox_source_provider_protocol::native_held_completion::frame::{
    NativeHeldSignerV1, PreparedNativeHeldControlV1, SignedNativeHeldControlV1,
};
use aos_sandbox_source_provider_protocol::native_held_completion::recovery::RootNativeRecoveryAssertionV1;
use aos_sandbox_source_provider_protocol::native_held_completion::suffix::NativeHeldCompletionSuffixV1;
use aos_sandbox_source_provider_protocol::native_held_completion::{
    NativeHeldCompletionErrorV1, NativeHeldControlKindV1 as Kind, NativeHeldOwnerV1 as Owner,
    NativeHeldScopeV1, NativeHeldSectionTagV1 as Tag,
};
use aos_sandbox_source_provider_protocol::{
    SignedStorageNativeAcquireRequestV2, StorageNativeAcceptanceV3, digest_signed_request,
};
use sha2::{Digest as _, Sha256};

use super::{HEADER_BYTES, NativeIssuanceRowV1, StorageNativeIssuanceErrorV1, TRANSACTION_DOMAIN};

mod codec;
mod profile;
mod reducer;

pub(crate) use profile::{StorageHeldCapacityProfileV1, remaining_capacity_profile};
pub(crate) use reducer::{
    StorageHeldReductionV1, StorageHeldStepV1, reduce, require_native_replayed_edge,
};

// These projections remain inside the native issuance owner. Sibling custody
// code uses the sole mixed decoder and original-row policy, not a second codec.
pub(super) fn decoded_native_rows(
    values: &std::collections::BTreeMap<[u8; 48], Vec<u8>>,
) -> Result<std::collections::BTreeMap<[u8; 48], StorageIssuanceValueV1>> {
    reducer::decode_state(values)
}

pub(super) fn original_native_row(value: &StorageIssuanceValueV1) -> &NativeIssuanceRowV1 {
    value.original()
}

/// Bounds the complete held value, excluding actual Journal append framing.
pub(crate) const MAXIMUM_STORAGE_HELD_ISSUANCE_VALUE_BYTES_V2: usize = 1_177_050;

/// Reports only invalid data or arithmetic, never a failed authority acquisition.
#[derive(Debug, thiserror::Error)]
pub(crate) enum StorageHeldCompletionErrorV1 {
    /// The exact original row, archive or transition does not match.
    #[error("invalid Storage held-completion data: {0}")]
    Invalid(&'static str),
    /// A shared canonical data contract was violated.
    #[error(transparent)]
    Schema(#[from] NativeHeldCompletionErrorV1),
    /// An unchanged legacy identity or record contract was violated.
    #[error(transparent)]
    Issuance(#[from] StorageNativeIssuanceErrorV1),
}

type Result<T> = std::result::Result<T, StorageHeldCompletionErrorV1>;

fn invalid(reason: &'static str) -> StorageHeldCompletionErrorV1 {
    StorageHeldCompletionErrorV1::Invalid(reason)
}

/// Retains the actual immutable legacy fields with a separately typed held suffix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StorageHeldIssuanceRowV2 {
    original: NativeIssuanceRowV1,
    suffix: NativeHeldCompletionSuffixV1,
}

impl StorageHeldIssuanceRowV2 {
    /// Collects and joins inert row data without admitting an issuance.
    ///
    /// # Errors
    ///
    /// Rejects wrong owner/phase, original correlation, assertion or archive joins.
    pub(crate) fn new(
        request: SignedStorageNativeAcquireRequestV2,
        acceptance: StorageNativeAcceptanceV3,
        retirement: Option<(ObjectDigest, ObjectDigest)>,
        suffix: NativeHeldCompletionSuffixV1,
    ) -> Result<Self> {
        let value = Self {
            original: NativeIssuanceRowV1 {
                request,
                acceptance,
                retirement,
            },
            suffix,
        };
        value.validate()?;
        Ok(value)
    }

    /// Returns the independently derived original namespace6/key48 subject.
    pub(crate) fn key(&self) -> [u8; 48] {
        self.original.key()
    }

    /// Returns the canonical nonauthorizing held prefix.
    pub(crate) fn suffix(&self) -> &NativeHeldCompletionSuffixV1 {
        &self.suffix
    }

    fn scope(&self) -> Result<NativeHeldScopeV1> {
        let root = self
            .suffix
            .control(Kind::RootPrepared)
            .ok_or_else(|| invalid("missing original RootPrepared"))?;
        let claims = self.original.request.request().claims();
        let full = NativeHeldScopeV1 {
            provider_attempt: claims.attempt().1,
            original_native_request: self.original.request.digest(),
            ..*root.scope()
        };
        full.validate_full()?;
        if root.scope().original_source_session != claims.holder_session().1
            || root.scope().provider_acquisition != claims.provider_acquisition().1
            || root.scope().original_root_request
                != digest_signed_request(self.original.request.request().signed_root_request())
            || root.scope().flight != self.suffix.flight()
            || root.prepared().signer()
                != &NativeHeldSignerV1::SourceProvider(
                    self.original
                        .request
                        .request()
                        .signed_root_request()
                        .signer()
                        .clone(),
                )
        {
            return Err(invalid("original signed request scope"));
        }
        Ok(full)
    }

    fn root_disposition(&self) -> Result<Option<RootNativeDispositionAssertionV1>> {
        let mut retained = None;
        for control in self.suffix.controls() {
            let assertion = match control.kind() {
                Kind::ProviderRelay => {
                    let root = SignedNativeHeldControlV1::from_canonical_bytes(required(
                        control,
                        Tag::RootDispositionControl,
                    )?)?;
                    if let Some(prepared) = root.section(Tag::RootPrepared) {
                        if self
                            .suffix
                            .control(Kind::RootPrepared)
                            .map(SignedNativeHeldControlV1::to_canonical_bytes)
                            .as_deref()
                            != Some(prepared)
                        {
                            return Err(invalid("exact nested original RootPrepared"));
                        }
                    }
                    Some(RootNativeDispositionAssertionV1::from_canonical_bytes(
                        required(&root, Tag::RootDispositionAssertion)?,
                    )?)
                }
                Kind::ProviderStorageRecoveryQuery => {
                    let root = SignedNativeHeldControlV1::from_canonical_bytes(required(
                        control,
                        Tag::RootRecoveryControl,
                    )?)?;
                    let state = RootNativeRecoveryAssertionV1::from_canonical_bytes(required(
                        &root,
                        Tag::RootRecoveryAssertion,
                    )?)?;
                    state.disposition
                }
                _ => None,
            };
            if let Some(assertion) = assertion {
                if retained.as_ref().is_some_and(|old| old != &assertion) {
                    return Err(invalid("immutable full Root disposition"));
                }
                retained = Some(assertion);
            }
        }
        Ok(retained)
    }

    fn settlement(&self) -> Result<Option<StorageNativeSettlementAssertionV1>> {
        let Some(root) = self.root_disposition()? else {
            return Ok(None);
        };
        let scope = self.scope()?;
        scope.require_root_prefix(&root.scope).or_else(|_| {
            if root.scope == scope {
                Ok(())
            } else {
                Err(NativeHeldCompletionErrorV1::Invalid(
                    "Root disposition scope",
                ))
            }
        })?;
        if root.disposition == NativeHeldDispositionV1::Accepted
            && root.descriptor_commitment != self.original.acceptance.descriptor_commitment()
        {
            return Err(invalid("original accepted descriptor"));
        }
        let assertion = StorageNativeSettlementAssertionV1 {
            disposition: root.disposition,
            scope,
            root_disposition: root.digest()?,
            acceptance: self.original.acceptance.clone(),
        };
        assertion.to_canonical_bytes()?;
        Ok(Some(assertion))
    }

    fn validate(&self) -> Result<()> {
        self.original.validate()?;
        if self.suffix.owner() != Owner::Storage
            || (self.suffix.phase() == 5) != self.original.retirement.is_some()
        {
            return Err(invalid("Storage owner/retirement phase"));
        }
        self.suffix.to_canonical_bytes()?;
        self.scope()?;
        reducer::validate_prefix(self)
    }

    fn transaction(&self) -> Result<JournalTransaction> {
        let value = self.to_canonical_bytes()?;
        let key = self.key();
        let digest = Sha256::new()
            .chain_update(TRANSACTION_DOMAIN)
            .chain_update(key)
            .chain_update(&value)
            .finalize();
        let mut identity = [0; 16];
        identity.copy_from_slice(&digest[..16]);
        JournalTransaction::new(
            identity,
            vec![JournalRecord::put(
                RecordNamespace::AuthorityPublication,
                key.to_vec(),
                value,
            )],
        )
        .map_err(|_| invalid("derived issuance transaction"))
    }
}

fn required(control: &SignedNativeHeldControlV1, tag: Tag) -> Result<&[u8]> {
    control
        .section(tag)
        .ok_or_else(|| invalid("missing assigned section"))
}

/// Distinguishes legacy and held encodings without upgrading either identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum StorageIssuanceValueV1 {
    /// An unchanged original AOSNSI01 value.
    Legacy(NativeIssuanceRowV1),
    /// An explicitly selected AOSNSI02 held value.
    Held(StorageHeldIssuanceRowV2),
}

#[cfg(test)]
mod tests;
