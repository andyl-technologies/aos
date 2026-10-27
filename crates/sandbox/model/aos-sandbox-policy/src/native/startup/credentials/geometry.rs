//! Quotes the same held-prefix and five finite credential append overlap.
//!
//! This receiver reads only its actual captured selected extent. Canonical
//! framing/index demand is distinct from the full all-family semantic donor.

use super::super::{RootStartupJournalErrorV1, RootStartupJournalOriginalV1};
use super::{RootStartupCredentialErrorV1, RootStartupCredentialWriterV1, StartupSignerPinsV1};
use crate::journal_keys::{
    CACHE_PIN_KEY, CONTROLLER_HOLD_PIN_KEY, HEAD_KEY, SIGNER_PINS_KEY, SOURCE_HOLD_PIN_KEY,
};
use crate::native::PolicyNativeJournalErrorV1;
use crate::signed_inputs::DEPLOYMENT_PACKET_BYTES;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::geometry::{RecordShape, encoded_transaction_append_bytes};
use aos_sandbox_protocol::domain_ledger::transaction::{JournalRecord, JournalTransaction};
use std::mem::size_of;

impl RootStartupJournalOriginalV1 {
    /// Quotes the original five appends over this same selected captured prefix.
    ///
    /// # Errors
    /// Refuses absent selected extent, full-family representation or checked overflow.
    pub fn selected_credential_append_peak_v1(
        &self,
    ) -> Result<ResourceVector, PolicyNativeJournalErrorV1> {
        let invalid = || PolicyNativeJournalErrorV1::geometry();
        let held = self.selected_extent_v1().ok_or_else(invalid)?;
        let shapes = [
            RecordShape { key_bytes: SIGNER_PINS_KEY.len(), value_bytes: Some(aos_sandbox_ledger_replay::replay::root_genesis_pins::POLICY_SIGNER_PINS_BYTES_V1) },
            RecordShape { key_bytes: HEAD_KEY.len(), value_bytes: Some(DEPLOYMENT_PACKET_BYTES) },
            RecordShape { key_bytes: CACHE_PIN_KEY.len(), value_bytes: Some(80) },
            RecordShape { key_bytes: CONTROLLER_HOLD_PIN_KEY.len(), value_bytes: Some(80) },
            RecordShape { key_bytes: SOURCE_HOLD_PIN_KEY.len(), value_bytes: Some(80) },
        ];
        let mut encoded = 0u64;
        for shape in shapes {
            let append =
                encoded_transaction_append_bytes(std::iter::once(shape)).map_err(|_| invalid())?;
            encoded = encoded.checked_add(append).ok_or_else(invalid)?;
        }
        let cells = 5 * 16u64;
        let cell = size_of::<(JournalRecord, [u8; 16], [usize; 3])>() as u64;
        let memory = encoded
            .checked_mul(16)
            .and_then(|bytes| bytes.checked_add(cells.checked_mul(cell)?))
            .and_then(|bytes| bytes.checked_add(64 * 1024))
            .and_then(|bytes| {
                bytes.checked_add(u64::try_from(credential_semantic_control_bytes_v1()?).ok()?)
            })
            .ok_or_else(invalid)?;
        let fixed = ResourceVector::ZERO
            .with(D::MemoryBytes, memory)
            .with(D::StorageBytes, encoded)
            .with(D::MetadataEntries, cells)
            .with(D::PublicationStagingBytes, memory)
            .with(D::OutputBytes, memory);
        let physical = usize::try_from(held.native_bytes()).map_err(|_| invalid())?;
        let rows = physical / aos_sandbox_journal::framing::HEADER_BYTES;
        let full_semantic =
            aos_sandbox_ledger_replay::geometry::semantic_rows::semantic_representation_demand_v1(
                physical, rows,
            )
            .map_err(PolicyNativeJournalErrorV1::from)?;
        held.dominant_native_receiving_demand_v1()
            .map_err(|cause| {
                PolicyNativeJournalErrorV1::from(
                    aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::
                        from_ordinary_native_v1(cause),
                )
            })?
            .checked_add(full_semantic)
            .and_then(|value| value.checked_add(fixed))
            .map_err(|_| invalid())
    }
}

// Five actual selected methods have distinct returned results. Their inner
// namespace/gate/opaque iterator interfaces are separately named by the real
// startup scope supplier; no 64KiB padding or unrelated Journal header pays them.
fn credential_semantic_control_bytes_v1() -> Option<usize> {
    size_of::<RootStartupCredentialWriterV1<'_>>()
        .checked_mul(2)?
        .checked_add(
            size_of::<Option<&aos_sandbox_broker::receiving::RootJournalFinancialBorrowV1<'_>>>()
                .checked_mul(2)?,
        )?
        .checked_add(size_of::<Result<(), RootStartupCredentialErrorV1>>().checked_mul(12)?)?
        .checked_add(
            size_of::<
                Result<crate::signed_inputs::PolicyDeploymentHeadV1, RootStartupCredentialErrorV1>,
            >()
            .checked_mul(3)?,
        )?
        .checked_add(
            size_of::<(
                &mut RootStartupJournalOriginalV1,
                u64,
                &ed25519_dalek::VerifyingKey,
                u64,
                &ed25519_dalek::VerifyingKey,
            )>()
            .checked_mul(2)?,
        )?
        .checked_add(
            size_of::<(
                &mut RootStartupJournalOriginalV1,
                Option<&[u8]>,
                u64,
                &ed25519_dalek::VerifyingKey,
                u64,
                &ed25519_dalek::VerifyingKey,
            )>()
            .checked_mul(6)?,
        )?
        .checked_add(
            size_of::<(
                &mut RootStartupJournalOriginalV1,
                &[u8],
                crate::signed_inputs::PolicyDeploymentHeadV1,
                &ed25519_dalek::VerifyingKey,
            )>()
            .checked_mul(2)?,
        )?
        .checked_add(size_of::<Option<StartupSignerPinsV1>>().checked_mul(2)?)?
        .checked_add(size_of::<JournalTransaction>().checked_mul(3)?)?
        .checked_add(
            size_of::<Result<JournalTransaction, RootStartupCredentialErrorV1>>().checked_mul(3)?,
        )?
        .checked_add(size_of::<Result<Vec<u8>, RootStartupCredentialErrorV1>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<u64, RootStartupCredentialErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), RootStartupJournalErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Option<usize>>().checked_mul(2)?)
}

impl RootStartupJournalOriginalV1 {
    // The genuine ordinary fixed opener consumes this added envelope once.
    // Opening failure boxes the actual whole diagnostic; selected methods
    // never construct that ordinary-only payload or gain its allocation policy.
    pub(in crate::native) fn fixed_admission_control_bytes_v1() -> Option<usize> {
        size_of::<Self>()
            .checked_mul(3)?
            .checked_add(size_of::<super::super::RootStartupJournalFailureOriginalV1>())?
            .checked_add(
                size_of::<Box<super::super::RootStartupJournalFailureOriginalV1>>()
                    .checked_mul(2)?,
            )?
            .checked_add(size_of::<Result<(), RootStartupJournalErrorV1>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<(), RootStartupCredentialErrorV1>>().checked_mul(3)?)?
            .checked_add(
                size_of::<
                    Result<
                        crate::signed_inputs::PolicyDeploymentHeadV1,
                        RootStartupCredentialErrorV1,
                    >,
                >()
                .checked_mul(3)?,
            )?
            .checked_add(
                size_of::<(
                    u64,
                    &ed25519_dalek::VerifyingKey,
                    u64,
                    &ed25519_dalek::VerifyingKey,
                )>()
                .checked_mul(2)?,
            )?
            .checked_add(
                size_of::<(
                    Option<&[u8]>,
                    u64,
                    &ed25519_dalek::VerifyingKey,
                    u64,
                    &ed25519_dalek::VerifyingKey,
                )>()
                .checked_mul(2)?,
            )?
            .checked_add(
                size_of::<(
                    &[u8],
                    &crate::signed_inputs::PolicyDeploymentInputsV1<'_>,
                    &ed25519_dalek::VerifyingKey,
                    i64,
                )>()
                .checked_mul(2)?,
            )?
            .checked_add(
                size_of::<
                    Result<
                        crate::signed_inputs::PolicyDeploymentHeadV1,
                        crate::signed_inputs::SignedPolicyInputDataErrorV1,
                    >,
                >()
                .checked_mul(3)?,
            )?
            .checked_add(super::super::credential_authority::control_bytes_v1()?)?
            .checked_add(size_of::<Option<usize>>().checked_mul(2)?)
    }
}

impl RootStartupJournalOriginalV1 {
    // The ordinary FixedAdmission envelope includes its fixed-profile variant;
    // all quantities name reached owners rather than reusing a byte allowance.
    pub(in crate::native) fn fixed_admission_additional_demand_v1()
    -> Result<ResourceVector, PolicyNativeJournalErrorV1> {
        use crate::native::journal::names::{
            RootFixedNameRecipeV1 as Recipe, RootFixedNameRoleV1 as Role,
            RootPolicyNameObservationOriginalV1 as Names,
        };
        let invalid = || PolicyNativeJournalErrorV1::geometry();
        let location = Names::additional_demand_v1(Role::Authority, Recipe::Location)?;
        let plain = Names::additional_demand_v1(Role::Authority, Recipe::PlainNames)?;
        let pair = location.checked_add(plain).map_err(|_| invalid())?;
        let backing = pair.checked_add(pair).map_err(|_| invalid())?;
        let controls = Self::fixed_admission_control_bytes_v1()
            .and_then(|bytes| bytes.checked_add(size_of::<Names>().checked_mul(8)?))
            .and_then(|bytes| bytes.checked_add(size_of::<Option<Names>>().checked_mul(8)?))
            .and_then(|bytes| bytes.checked_add(size_of::<&mut Names>().checked_mul(8)?))
            .and_then(|bytes| {
                bytes.checked_add(
                    size_of::<Result<(), RootStartupJournalErrorV1>>().checked_mul(12)?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    size_of::<
                        Result<(ed25519_dalek::VerifyingKey, u64), RootStartupCredentialErrorV1>,
                    >()
                    .checked_mul(3)?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    size_of::<
                        Result<
                            crate::signed_inputs::PolicyDeploymentHeadV1,
                            crate::signed_inputs::SignedPolicyInputDataErrorV1,
                        >,
                    >()
                    .checked_mul(3)?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    size_of::<(
                        &[u8],
                        &crate::signed_inputs::PolicyDeploymentInputsV1<'_>,
                        &crate::signed_inputs::PolicyDeploymentInputProfileV2,
                        &ed25519_dalek::VerifyingKey,
                        i64,
                    )>()
                    .checked_mul(2)?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    size_of::<Result<ResourceVector, PolicyNativeJournalErrorV1>>()
                        .checked_mul(3)?,
                )
            })
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(invalid)?;
        // Four actual observation owners each introduce the canonical eight
        // retained control identities, independently of namespace/FD backing.
        let fixed = ResourceVector::ZERO
            .with(D::MemoryBytes, controls)
            .with(D::MetadataEntries, 4 * Names::retained_control_cells_v1());
        backing.checked_add(fixed).map_err(|_| invalid())
    }
}
