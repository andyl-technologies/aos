//! Checks Root's historical accepted Create through the existing Q04 row relation.
//!
//! B and the protected Controller replay retain the original input. These
//! comparison results issue no admission, currentness or resource use.

use super::*;
use crate::journal::JournalError;

#[derive(Default)]
pub(crate) struct RootAcceptedCreateRowsV1 {
    rows: Option<Result<Q04OriginalRowDataV1, CreateQ04ErrorV1>>,
    current_encoding: Option<Result<Vec<u8>, CreateQ04ErrorV1>>,
    plan_digest: Option<Result<ObjectDigest, CreateQ04ErrorV1>>,
    result: Option<Result<(), CreateQ04ErrorV1>>,
    entered: bool,
    closed: Option<CreateQ04ErrorV1>,
}

impl RootAcceptedCreateRowsV1 {
    pub(crate) fn observe_once(
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
            self.closed.get_or_insert(CreateQ04ErrorV1::ChangedCut);
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
    ) -> Result<(), CreateQ04ErrorV1> {
        self.rows = Some(read_original_q04_rows_v1(
            operation, desired, original_effect,
            Q04OriginalRowBindingV1 {
                operation: identity.operation(), sandbox: identity.sandbox(),
                project: identity.project(), accepted_generation: identity.accepted_generation(),
                desired_precondition: identity.desired_precondition(),
            },
        ));
        let rows = self.rows.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        if rows.before != identity.before_controller_rows()
            || rows.effect.plan().request() != accepted_context
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }

        self.current_encoding = Some(rows.applying_effect_with_gate(gate));
        let encoded = self.current_encoding.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        if encoded.as_slice() != current_effect {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }

        // The consuming validator disposes its successful historical model at
        // its last use. The complete original input remains on B throughout.
        let rows = self.rows.take().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let rows = match rows {
            Ok(rows) => rows,
            Err(error) => {
                self.rows = Some(Err(error));
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
        };
        self.plan_digest = Some(rows.effect_plan_digest());
        let digest = self.plan_digest.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        if *digest != identity.effect_plan_digest() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        Ok(())
    }

    pub(crate) fn require_complete(&self) -> Result<(), JournalError> {
        if self.closed.is_none() && matches!(self.result, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn cause<T>(result: &Option<Result<T, CreateQ04ErrorV1>>)
            -> Option<&(dyn std::error::Error + 'static)>
        {
            result.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
        }
        cause(&self.rows).or_else(|| cause(&self.current_encoding))
            .or_else(|| cause(&self.plan_digest)).or_else(|| cause(&self.result))
            .or_else(|| self.closed.as_ref().map(|error| error as _))
    }
}
