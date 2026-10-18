//! Replays the same complete wire while owning only the current Control/model.

use super::super::hello::NativeHello17Data;
use super::*;
use crate::handshake::HistoricalAuthority17;
use crate::protocol_snapshot::owned11::typed::Native17Build;
use crate::protocol_snapshot::restored_settled17::current_lineage17::{
    CurrentNativeLineage17ReadAttempt, NativeMappingNormalization17ReadAttempt,
};
use crate::reference_packet::control::{
    CurrentControl17ReadAttempt, preflight_current_rooted_control17_fields_data,
    read_current_rooted_control17_into_data,
};
use crucible_node_contract::ExtensionSelection;
use std::sync::Arc;

pub(in super::super) enum SelectedControl17Pass<'attempt> {
    Preflight,
    Build(
        &'attempt mut CurrentControl17ReadAttempt,
        &'attempt mut CurrentNativeLineage17ReadAttempt,
        &'attempt mut <HistoricalAuthority17 as Native17Build>::Attempt,
        &'attempt mut NativeMappingNormalization17ReadAttempt,
        &'attempt mut NativeHello17Data,
    ),
}

impl BorrowedNativeCurrentGraph17Plan<'_, '_> {
    /// Replays complete immutable source validation with one selected owner.
    ///
    /// Target suppression is a private same-ledger token. Every immutable source
    /// row and alias is still consumed, including full repeated views. Only the
    /// actual current Control/model parser runs with target construction enabled.
    pub(in super::super) fn replay_selected_control17_data(
        &mut self,
        limits: NativeCurrentGraph17ReadLimits,
        mut pass: SelectedControl17Pass<'_>,
        target_groups: &mut [bool],
        selected_groups: &mut [Option<Arc<[ExtensionSelection]>>],
    ) -> Result<usize, ProviderError> {
        let hello =
            crate::reference_packet::endpoint::borrow_native17_endpoint_logical_data(self)?.hello;
        let hello_request = hello.request_literal_data()?;
        let hello_response = hello.response_literal_data()?;
        let roots = &self.roots;
        let mut ledger = make_ledger(&self.records, self.input_length, limits);
        ledger.settled_aliases = Some(self.aliases.views()?);
        ledger.begin_native17_targets_data(
            limits
                .maximum_requested
                .min(limits.maximum_target_requested),
        )?;
        ledger.native17_target_embedded_root_data()?;
        ledger.bind_native17_target_groups_data(target_groups)?;
        ledger.selected_groups = Some(selected_groups);
        let paused = ledger.suspend_native17_targets_data()?;

        let (_, registrar) =
            read_current_native17_registrar_root_data(roots.registrar, &mut ledger, false)?;
        let (_, actor) = read_actor17_data(roots.actor, &mut ledger, false)?;
        let (_, supervisor) =
            read_current_native17_supervisor_root_data(roots.supervisor, &mut ledger, false)?;
        let (_, codec, policy) = read_native17_codec_root_data(roots.codec, &mut ledger, false)?;
        let control_identity =
            read_current_control_identity17_data(roots.control_identity, &mut ledger)?;
        let hold = if roots.hold == b"null" {
            None
        } else {
            let (_, hold) =
                read_current_control_hold_root17_fields_data(roots.hold, &mut ledger, false)?;
            if hold.capture_identity != control_identity {
                return Err(invalid());
            }
            Some(hold.hold)
        };
        let (_, frames) = read_native17_frame_root_data(roots.frames, &mut ledger, false)?;
        let deadline = read_deadline(roots.deadline, &mut ledger)?;
        let mapping = read_shared_current_mapping_lineage17_data(roots.mapping, &mut ledger)?;
        let (_, receiver) = read_native17_blob_receiver_data(roots.receiver, &mut ledger, false)?;
        let boot = read_shared_current_boot_lineage17_data(roots.boot, &mut ledger)?;
        ledger.resume_native17_targets_data(paused)?;
        let connection = match &mut pass {
            SelectedControl17Pass::Preflight => {
                crate::connection::preflight_rooted_native17_connection_authority_data(
                    roots,
                    &mut ledger,
                )?
            }
            SelectedControl17Pass::Build(_, _, attempt, _, _) => {
                crate::connection::read_rooted_native17_connection_authority_into_data(
                    roots,
                    &mut ledger,
                    attempt,
                )?
            }
        };
        let paused = ledger.suspend_native17_targets_data()?;
        let (_, endpoint) = read_rooted_endpoint17_fields_data(roots, &mut ledger, false)?;

        ledger.resume_native17_targets_data(paused)?;
        let control = match &mut pass {
            SelectedControl17Pass::Preflight => {
                preflight_current_rooted_control17_fields_data(roots, &mut ledger)?
            }
            SelectedControl17Pass::Build(attempt, _, _, _, _) => {
                read_current_rooted_control17_into_data(roots, &mut ledger, attempt)?
            }
        };
        let paused = ledger.suspend_native17_targets_data()?;
        let (_, service) =
            read_rooted_current_native17_service_fields_data(roots, &mut ledger, false)?;
        if ledger.rows.next().is_some() {
            return Err(invalid());
        }
        ledger.finish_aliases()?;
        ledger.resume_native17_targets_data(paused)?;
        let groups = NativeCurrentGraph17Groups {
            registrar,
            actor,
            supervisor,
            codec,
            policy,
            control_identity,
            hold,
            frames,
            deadline,
            mapping: mapping.group_data(),
            receiver,
            boot: boot.group_data(),
            connection,
            endpoint,
            control,
            service,
        };
        self.groups.authenticate_same_roots_data(groups)?;
        if control != self.groups.control {
            return Err(invalid());
        }
        match pass {
            SelectedControl17Pass::Preflight => {
                boot.preflight_owned_lineage17_data(&mut ledger)?;
                mapping.normalization.preflight_target17_data(&mut ledger)?;
                NativeHello17Data::preflight_data(hello_request, hello_response, &mut ledger)?;
            }
            SelectedControl17Pass::Build(_, attempt, _, normalization, hello) => {
                boot.read_owned_lineage17_into_data(&mut ledger, attempt)?;
                mapping
                    .normalization
                    .read_target17_into_data(&mut ledger, normalization)?;
                hello.read_into_data(hello_request, hello_response, &mut ledger)?;
            }
        }
        ledger.finish_native17_targets_data()
    }
}
