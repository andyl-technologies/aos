//! Retains Source-funded helper preparation behind the original durable approval.
//!
//! Security keeps the semantic decision; the Source owns native custody. No
//! copied intent, role, descriptor or resource amount can select this operation.

use super::*;

impl<'owner> Method46InitialProvisionDecodeOriginalV1<'owner> {
    /// Retains the same Source's fixed helper birth loan after approved intent.
    ///
    /// The canonical request is rederived from the genuine main and compared
    /// with the resident verified approval. Both original lock descriptions and
    /// completed native intent publication are required. Preparation retains
    /// the Source borrow but launches no child and transfers no private auth.
    ///
    /// # Errors
    /// Refuses foreign or ended originals, missing durable approval or locks,
    /// reentry, changed Source, insufficient funding or failed native custody.
    /// A refusal releases temporary borrows before servicing independent posts;
    /// reached native owners remain resident in the same Source.
    pub fn prepare_approved_initial_tpm_helper_once_v1(
        &self,
        main: &Method46InitialMainCutOriginalV1<'_>,
    ) -> Result<(), Method46InitialDataErrorV1> {
        let result = (|| {
            let mut intent = self
                .intent
                .try_borrow_mut()
                .map_err(|_| Method46InitialDataErrorV1::Conflict)?;
            if std::mem::replace(&mut intent.helper_entered, true) {
                return Err(Method46InitialDataErrorV1::Conflict);
            }

            let result = (|| {
                let request = self.request_for_main_original_data_v1(main)?;
                if !matches!(intent.result, Some(Ok(())))
                    || !matches!(intent.native, Some(Ok(())))
                    || !matches!(intent.after, Some(Ok(())))
                    || !matches!(intent.locks_result, Some(Ok(())))
                    || intent.locks_after.is_some()
                    || self
                        .approval
                        .try_borrow()
                        .map_err(|_| Method46InitialDataErrorV1::Conflict)?
                        .verified_intent()?
                        .request()
                        != request
                {
                    return Err(Method46InitialDataErrorV1::Conflict);
                }

                intent.helper = Some(
                    intent
                        .locks
                        .as_ref()
                        .ok_or(Method46InitialDataErrorV1::Conflict)?
                        .lend_initial_helper_birth_once_v1()
                        .map_err(|_| Method46InitialDataErrorV1::Conflict)?,
                );
                Ok(())
            })();
            intent.helper_result = Some(result);
            result
        })();
        if result.is_err() {
            self.refuse_intent_and_finish_after();
        }
        result
    }
}
