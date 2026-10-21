//! Checks Root's historical accepted Create through the existing Q04 row relation.
//!
//! B and the protected Controller replay retain the original input. These
//! comparison results issue no admission, currentness or resource use.

use super::{Q04OriginalRowDataV1, Q04OriginalRowBindingV1,
    Q04OriginalRowsDataErrorV1, read_original_q04_rows_v1};
use crate::domain_ledger::create_q04_history::{Q04CutIdentityV1, Q04EffectSubgateV1};
use aos_sandbox_model::ObjectDigest;

/// Names the exact existing Create request and Sandbox protobuf model DATA.
pub use aos_sandbox_api::aos::sandbox::v1::{CreateSandboxRequest, Sandbox};

/// Reexports the existing pure protobuf receiving geometry without a wrapper.
pub use aos_sandbox_broker_session_protocol::receiving_geometry::protobuf_carriers_v1;

/// Retains the exact original-row decoder failure or changed comparison marker.
#[derive(Debug, thiserror::Error)]
pub enum AcceptedCreateRowsDataErrorV1 {
    /// A comparison, completion or reentry does not match the original row recipe.
    #[error("the original Q04 continuation cut changed")]
    ChangedCut,
    /// The existing original-row decoder, model encoder or digest failed.
    #[error(transparent)]
    Original(#[from] Q04OriginalRowsDataErrorV1),
}

/// Retains historical accepted-row comparisons and their first diagnostic causes.
///
/// Completion establishes DATA consistency only, never native membership or a loan.
#[derive(Default)]
pub struct AcceptedCreateRowsDataV1 {
    rows: Option<Result<Q04OriginalRowDataV1, AcceptedCreateRowsDataErrorV1>>,
    current_encoding: Option<Result<Vec<u8>, AcceptedCreateRowsDataErrorV1>>,
    plan_digest: Option<Result<ObjectDigest, AcceptedCreateRowsDataErrorV1>>,
    result: Option<Result<(), AcceptedCreateRowsDataErrorV1>>,
    entered: bool,
    closed: Option<AcceptedCreateRowsDataErrorV1>,
}

impl AcceptedCreateRowsDataV1 {
    /// Runs the original row, applying-effect and consuming digest comparisons once.
    pub fn observe_once(
        &mut self,
        operation: &[u8],
        desired: &[u8],
        original_effect: &[u8],
        accepted_context: &[u8],
        current_effect: &[u8],
        identity: &Q04CutIdentityV1,
        gate: &Q04EffectSubgateV1,
    ) {
        if self.entered {
            self.closed.get_or_insert(AcceptedCreateRowsDataErrorV1::ChangedCut);
            return;
        }
        self.entered = true;
        self.result = Some(self.compare_inner(
            operation, desired, original_effect, accepted_context, current_effect, identity, gate,
        ));
    }

    fn compare_inner(
        &mut self,
        operation: &[u8],
        desired: &[u8],
        original_effect: &[u8],
        accepted_context: &[u8],
        current_effect: &[u8],
        identity: &Q04CutIdentityV1,
        gate: &Q04EffectSubgateV1,
    ) -> Result<(), AcceptedCreateRowsDataErrorV1> {
        self.rows = Some(read_original_q04_rows_v1(
            operation, desired, original_effect,
            Q04OriginalRowBindingV1 {
                operation: identity.operation(), sandbox: identity.sandbox(),
                project: identity.project(), accepted_generation: identity.accepted_generation(),
                desired_precondition: identity.desired_precondition(),
            },
        ).map_err(AcceptedCreateRowsDataErrorV1::from));
        let rows = self.rows.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(AcceptedCreateRowsDataErrorV1::ChangedCut)?;
        if rows.before != identity.before_controller_rows()
            || rows.effect.plan().request() != accepted_context
        {
            return Err(AcceptedCreateRowsDataErrorV1::ChangedCut);
        }

        self.current_encoding = Some(rows.applying_effect_with_gate(gate).map_err(AcceptedCreateRowsDataErrorV1::from));
        let encoded = self.current_encoding.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(AcceptedCreateRowsDataErrorV1::ChangedCut)?;
        if encoded.as_slice() != current_effect {
            return Err(AcceptedCreateRowsDataErrorV1::ChangedCut);
        }

        // The consuming validator disposes its successful historical model at
        // its last use. The complete original input remains on B throughout.
        let rows = self.rows.take().ok_or(AcceptedCreateRowsDataErrorV1::ChangedCut)?;
        let rows = match rows {
            Ok(rows) => rows,
            Err(error) => {
                self.rows = Some(Err(error));
                return Err(AcceptedCreateRowsDataErrorV1::ChangedCut);
            }
        };
        self.plan_digest = Some(rows.effect_plan_digest().map_err(AcceptedCreateRowsDataErrorV1::from));
        let digest = self.plan_digest.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(AcceptedCreateRowsDataErrorV1::ChangedCut)?;
        if *digest != identity.effect_plan_digest() {
            return Err(AcceptedCreateRowsDataErrorV1::ChangedCut);
        }
        Ok(())
    }

    /// Checks that the one historical comparison completed without refusal.
    ///
    /// # Errors
    /// Returns ChangedCut after incomplete, failed or repeated observation.
    pub fn require_complete(&self) -> Result<(), AcceptedCreateRowsDataErrorV1> {
        if self.closed.is_none() && matches!(self.result, Some(Ok(()))) {
            Ok(())
        } else {
            Err(AcceptedCreateRowsDataErrorV1::ChangedCut)
        }
    }

    /// Borrows the first retained decoder, encoding, digest or reentry error.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn cause<T>(result: &Option<Result<T, AcceptedCreateRowsDataErrorV1>>)
            -> Option<&(dyn std::error::Error + 'static)>
        {
            result.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
        }
        cause(&self.rows).or_else(|| cause(&self.current_encoding))
            .or_else(|| cause(&self.plan_digest)).or_else(|| cause(&self.result))
            .or_else(|| self.closed.as_ref().map(|error| error as _))
    }
}
