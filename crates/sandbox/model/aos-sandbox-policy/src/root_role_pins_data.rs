//! Constructs the complete saved Root role tuple as nonauthorizing DATA.
//!
//! Callers retain their actual fixed journals and independent credential
//! originals. This comparison neither opens a credential nor certifies its
//! native custody, currentness or permission to append a Root floor.

use aos_sandbox_model::RecordNamespace;
use aos_sandbox_ledger_replay::replay::root_genesis_pins;
use aos_sandbox_ledger_replay::source_signer_data::{
    PinnedSourceHoldReadbackSignerV1, SourceHoldReadbackErrorV1,
};
use aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerReadViewV1;

use crate::controller_readback::{ControllerHoldReadbackDataErrorV1, PinnedControllerHoldSignerV1};
use crate::journal_keys::{CONTROLLER_HOLD_PIN_KEY, SIGNER_PINS_KEY, SOURCE_HOLD_PIN_KEY};

/// Preserves the exact leaf of a refused saved-role comparison.
#[derive(Debug, thiserror::Error)]
pub enum RootRolePinsDataErrorV1 {
    /// A fixed member has the wrong canonical width.
    #[error("invalid Source genesis record or exact owner join")]
    NonCanonical,
    /// A required independently retained role row is absent.
    #[error("Source genesis owner or credential is not current")]
    Stale,
    /// The canonical saved-role encoder refused an original member.
    #[error(transparent)]
    Data(#[from] aos_sandbox_ledger_replay::data::SourceSuccessorDataErrorV2),
    /// The sole Controller public-credential decoder refused its DATA.
    #[error(transparent)]
    Controller(#[from] ControllerHoldReadbackDataErrorV1),
    /// The sole Source public-credential decoder refused its DATA.
    #[error(transparent)]
    Source(#[from] SourceHoldReadbackErrorV1),
}

/// Keeps one whole saved tuple beside its canonical public verifier DATA.
///
/// Private fields prevent partial replacement of a decoded tuple. These public
/// keys remain DATA; only native role owners retain credential custody.
pub struct RootRolePinsDataV1 {
    pub(crate) encoded: [u8; 488],
    pub(crate) controller: PinnedControllerHoldSignerV1,
    pub(crate) source: PinnedSourceHoldReadbackSignerV1,
}

impl RootRolePinsDataV1 {
    /// Borrows the complete canonical comparison tuple.
    #[must_use]
    pub const fn encoded_data_v1(&self) -> &[u8; 488] {
        &self.encoded
    }

    /// Borrows the canonical Controller public verifier without native authority.
    #[must_use]
    pub const fn controller_data_v1(&self) -> &PinnedControllerHoldSignerV1 {
        &self.controller
    }

    /// Borrows the canonical Source public verifier without native authority.
    #[must_use]
    pub const fn source_data_v1(&self) -> &PinnedSourceHoldReadbackSignerV1 {
        &self.source
    }
}

/// Compares complete saved role rows with separately supplied credential DATA.
///
/// # Errors
/// Rejects absent rows, wrong member widths, foreign public credentials or any
/// noncanonical canonical-tuple member. No native observation is performed.
pub fn role_pins_from_rows_v1(
    rows: HistoricalLedgerReadViewV1<'_>,
    seed: &[u8],
    authorization: &[u8],
) -> Result<RootRolePinsDataV1, RootRolePinsDataErrorV1> {
    let width = || RootRolePinsDataErrorV1::NonCanonical;
    let seed = seed.try_into().map_err(|_| width())?;
    let authorization = authorization.try_into().map_err(|_| width())?;
    let exact = |key| {
        rows.get(RecordNamespace::DesiredState, key)
            .ok_or(RootRolePinsDataErrorV1::Stale)
    };
    let controller: &[u8; 80] = exact(CONTROLLER_HOLD_PIN_KEY)?.try_into().map_err(|_| width())?;
    let source: &[u8; 80] = exact(SOURCE_HOLD_PIN_KEY)?.try_into().map_err(|_| width())?;
    let deployment = exact(SIGNER_PINS_KEY)?.try_into().map_err(|_| width())?;
    Ok(RootRolePinsDataV1 {
        encoded: root_genesis_pins::encode(seed, authorization, controller, source, deployment)?,
        controller: PinnedControllerHoldSignerV1::decode(controller)?,
        source: PinnedSourceHoldReadbackSignerV1::decode(source)?,
    })
}
