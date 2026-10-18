//! Joins genuine SDK pairs to retained native signed-lineage fields.

use super::*;
use crate::protocol_snapshot::{
    current_controller17::ValidatedHistoricalRestorationAssociation17,
    restored_settled17::historical_auth::{
        HistoricalAck17, HistoricalAckBindings17, HistoricalCommit17, HistoricalCompletedPair17,
        HistoricalPrepare17, HistoricalRestoration17,
    },
};

impl NativeCurrentGraph17Data {
    /// Borrows required native lineage after exact association with real SDK pairs.
    ///
    /// The association owns the independently funded parsed SDK pair records.
    /// Each original also equals this native cache, and every terminal belongs
    /// to the actual complete native send history and current Control cache.
    /// This loan supplies neither ancestry nor a native token or allocation.
    ///
    /// # Errors
    /// Refuses missing signed fields, changed SDK/native originals or terminals,
    /// incomplete native send history, or absent required Hello/mapping evidence.
    pub(crate) fn historical_restoration17_data<'a>(
        &'a self,
        association: &'a ValidatedHistoricalRestorationAssociation17,
    ) -> Result<HistoricalRestoration17<'a>, ProviderError> {
        self.validate_data()?;
        let boot = self.lineage.boot_data();
        let prepare = self.lineage.prepare_data();
        let commit = self.lineage.commit_data();
        let (ack_original, ack_terminal) = association.ack_pair_data();
        let (prepare_original, prepare_terminal) = association.prepare_pair_data();
        let (commit_original, commit_terminal) = association.commit_pair_data();
        if boot.ack_original.value_data()?.as_ref() != Some(ack_original)
            || prepare.original.value_data()?.as_ref() != Some(prepare_original)
            || commit.original.value_data()?.as_ref() != Some(commit_original)
        {
            return Err(invalid());
        }
        for (original, terminal) in [
            (ack_original, ack_terminal),
            (prepare_original, prepare_terminal),
            (commit_original, commit_terminal),
        ] {
            original.matches_response(terminal)?;
            crate::reference_packet::endpoint::authenticate_native17_retained_terminal_data(
                self, original, terminal,
            )?;
        }
        Ok(HistoricalRestoration17 {
            ack: HistoricalAck17 {
                context: &boot
                    .ack_context
                    .value_data()?
                    .as_ref()
                    .ok_or_else(invalid)?
                    .0,
                proof: &boot.ack_proof.value_data()?.as_ref().ok_or_else(invalid)?.0,
                pair: HistoricalCompletedPair17 {
                    original: ack_original,
                    terminal: ack_terminal,
                },
                selection: self.control.selection_data(),
                native_pid: U64::new(u64::from(self.creator)),
                bindings: HistoricalAckBindings17 {
                    birth_association: boot
                        .normalized_0
                        .value_data()?
                        .as_ref()
                        .ok_or_else(invalid)?,
                    kernel_binding: boot
                        .normalized_1
                        .value_data()?
                        .as_ref()
                        .ok_or_else(invalid)?,
                    policy_binding: boot
                        .normalized_2
                        .value_data()?
                        .as_ref()
                        .ok_or_else(invalid)?,
                    host_registration: boot.host_registration.value_data()?,
                    native_registration: boot
                        .normalized_3
                        .value_data()?
                        .as_ref()
                        .ok_or_else(invalid)?,
                    authority: &self.authority.data,
                    controller_pid: *commit.controller_pid.value_data()?,
                    controller_uid: *commit.controller_uid.value_data()?,
                    controller_executable: commit.controller_executable.value_data()?,
                    hello_request_literal: self.hello.request_data(),
                    hello_response_literal: self.hello.response_data(),
                },
            },
            prepare: HistoricalPrepare17 {
                request: &prepare
                    .request
                    .value_data()?
                    .as_ref()
                    .ok_or_else(invalid)?
                    .0,
                context: &prepare
                    .context
                    .value_data()?
                    .as_ref()
                    .ok_or_else(invalid)?
                    .0,
                proof: &prepare.proof.value_data()?.as_ref().ok_or_else(invalid)?.0,
                pair: HistoricalCompletedPair17 {
                    original: prepare_original,
                    terminal: prepare_terminal,
                },
            },
            commit: HistoricalCommit17 {
                request: &commit.request.value_data()?.as_ref().ok_or_else(invalid)?.0,
                context: &commit.context.value_data()?.as_ref().ok_or_else(invalid)?.0,
                proof: &commit.proof.value_data()?.as_ref().ok_or_else(invalid)?.0,
                pair: HistoricalCompletedPair17 {
                    original: commit_original,
                    terminal: commit_terminal,
                },
                held: &commit.hold.value_data()?.as_ref().ok_or_else(invalid)?.0,
            },
            canonical_mapping: self.normalization.bytes_data(),
            control: &self.control,
        })
    }
}
