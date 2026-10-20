//! Retains the explicit authorization witness beside Root's same held C replay.
//!
//! The header bounds the next allocation. The real parent prepays complete
//! request/model geometry from its actual input length and replayed C rows
//! before receiving the body or decoding saved models. No decision is adopted.

use super::super::body::message::RootDeleteMessageReceivingV2;
use super::*;
use aos_sandbox_protocol::domain_ledger::delete_root::{
    authorization::{
        DELETE_ROOT_AUTHORIZATION_CHECKSUM_BYTES_V2, DELETE_ROOT_AUTHORIZATION_HEADER_BYTES_V2,
        DeleteRootAuthorizationFieldsV2, authorization_witness_checksum_data_v2,
    },
    transport::{DeleteRootOpenDataV2, DeleteRootWireErrorV2},
};

#[derive(Clone, Copy)]
enum AuthorizationFirst {
    Header,
    Decode,
    Association,
    Geometry,
    Body,
    Checksum,
    Models,
    Reentry,
}

#[derive(Debug, thiserror::Error)]
enum AuthorizationError {
    #[error(transparent)]
    Original(#[from] RootDeleteErrorV1),
    #[error(transparent)]
    Wire(#[from] DeleteRootWireErrorV2),
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Models(#[from] crate::cli_model::authorization_adapter::CliAuthorizationAdapterError),
}

#[derive(Default)]
pub(super) struct RootDeleteControllerAuthorizationOriginalV2 {
    header: RootDeleteMessageReceivingV2,
    fields: Option<Result<DeleteRootAuthorizationFieldsV2, DeleteRootWireErrorV2>>,
    association: Option<Result<(), DeleteRootWireErrorV2>>,
    pub(super) dynamic: Option<Result<ResourceVector, JournalError>>,
    body: RootDeleteMessageReceivingV2,
    checksum: Option<Result<(), AuthorizationError>>,
    recomputed: Option<Result<[u8; 32], AuthorizationError>>,
    first: Option<AuthorizationFirst>,
    entered: bool,
    complete: bool,
    closed: Option<RootDeleteErrorV1>,
}

impl RootDeleteControllerCurrentOriginalV1 {
    pub(in crate::policy_compiler::delete_root) fn observe_authorization_once_v2(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &UnixStream,
        challenge: &RootDeleteChallengeOriginalsV1,
        open: DeleteRootOpenDataV2,
    ) -> Result<(), RootDeleteErrorV1> {
        if !self.complete || self.first.is_some() || self.authorization.entered {
            self.authorization
                .first
                .get_or_insert(AuthorizationFirst::Reentry);
            self.authorization
                .closed
                .get_or_insert(RootDeleteErrorV1::Original);
            self.first.get_or_insert(First::Authorization);
            return Err(RootDeleteErrorV1::Original);
        }
        self.authorization.entered = true;
        // Admission sees the whole same Controller owner. Every native leaf's
        // independent after is supplied by the shared strict message engine.
        let result = self.observe_authorization_inner(flight, original, challenge, open);
        if result.is_err() || self.authorization.failure().is_some() {
            self.first.get_or_insert(First::Authorization);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.authorization.complete = true;
        Ok(())
    }

    fn observe_authorization_inner(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &UnixStream,
        challenge: &RootDeleteChallengeOriginalsV1,
        open: DeleteRootOpenDataV2,
    ) -> Result<(), RootDeleteErrorV1> {
        self.admit(
            flight,
            challenge,
            RootDeleteControllerAdmissionPhaseV1::AuthorizationHeader,
        )?;
        if self
            .authorization
            .header
            .receive_continuation_once_v2(
                flight,
                original,
                challenge,
                DELETE_ROOT_AUTHORIZATION_HEADER_BYTES_V2,
            )
            .is_err()
        {
            self.authorization.first = Some(AuthorizationFirst::Header);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.authorization.fields = Some(DeleteRootAuthorizationFieldsV2::decode_v2(
            self.authorization.header.bytes_v2()?,
        ));
        let Some(fields) = self
            .authorization
            .fields
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
        else {
            self.authorization.first = Some(AuthorizationFirst::Decode);
            return Err(RootDeleteErrorV1::Opening);
        };
        self.authorization.association = Some(
            DeleteRootChallengeDataV2::decode_v2(
                challenge
                    .challenge_bytes_v1()
                    .map_err(|_| RootDeleteErrorV1::Opening)?,
            )
            .and_then(|own| fields.require_exchange_v2(open, own)),
        );
        if !matches!(self.authorization.association, Some(Ok(()))) {
            self.authorization.first = Some(AuthorizationFirst::Association);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.authorization.dynamic = Some((|| {
            let actual = self.readback_v2()?;
            let input =
                usize::try_from(fields.input_bytes).map_err(|_| JournalError::JournalTooLarge)?;
            let encoded = actual
                .state
                .iter()
                .try_fold(0usize, |total, ((_, key), value)| {
                    total.checked_add(key.len())?.checked_add(value.len())
                })
                .ok_or(JournalError::JournalTooLarge)?;
            let bytes = crate::public_mutation_compiler::delete_admission::geometry::delete_decode_bytes_v1(input)
                .and_then(|bytes| bytes.checked_add(
                    crate::public_mutation_compiler::delete_admission::geometry::authorization_model_bytes_v1(
                        encoded, actual.state.len())?))
                .and_then(|bytes| bytes.checked_add(input.checked_add(DELETE_ROOT_AUTHORIZATION_CHECKSUM_BYTES_V2)?.checked_mul(3)?))
                .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
            Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
        })());
        if !matches!(self.authorization.dynamic, Some(Ok(_))) {
            self.authorization.first = Some(AuthorizationFirst::Geometry);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.admit(
            flight,
            challenge,
            RootDeleteControllerAdmissionPhaseV1::AuthorizationBody,
        )?;
        let length = usize::try_from(fields.input_bytes)
            .ok()
            .and_then(|input| input.checked_add(DELETE_ROOT_AUTHORIZATION_CHECKSUM_BYTES_V2))
            .ok_or(RootDeleteErrorV1::Opening)?;
        if self
            .authorization
            .body
            .receive_continuation_once_v2(flight, original, challenge, length)
            .is_err()
        {
            self.authorization.first = Some(AuthorizationFirst::Body);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.authorization.checksum = Some((|| {
            let header: &[u8; DELETE_ROOT_AUTHORIZATION_HEADER_BYTES_V2] = self
                .authorization
                .header
                .bytes_v2()?
                .try_into()
                .map_err(|_| DeleteRootWireErrorV2::Format)?;
            let body = self.authorization.body.bytes_v2()?;
            let input_length =
                usize::try_from(fields.input_bytes).map_err(|_| DeleteRootWireErrorV2::Format)?;
            let (input, checksum) = body.split_at(input_length);
            if checksum != authorization_witness_checksum_data_v2(header, input) {
                return Err(DeleteRootWireErrorV2::Association.into());
            }
            Ok(())
        })());
        if !matches!(self.authorization.checksum, Some(Ok(()))) {
            self.authorization.first = Some(AuthorizationFirst::Checksum);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.authorization.recomputed = Some((|| {
            let actual = self.readback_v2()?;
            let body = self.authorization.body.bytes_v2()?;
            let length =
                usize::try_from(fields.input_bytes).map_err(|_| DeleteRootWireErrorV2::Format)?;
            Ok(crate::cli_model::authorization_adapter::recompute_delete_authorization_cut_from_records_v2(
                crate::publisher_admin::PublisherReadDataV2::from_state_v2(actual.state), &body[..length], fields, open)?)
        })());
        if !matches!(self.authorization.recomputed, Some(Ok(_))) {
            self.authorization.first = Some(AuthorizationFirst::Models);
            return Err(RootDeleteErrorV1::Opening);
        }
        Ok(())
    }

    pub(in crate::policy_compiler::delete_root) fn verified_authorization_fields_v3(&self)
        -> Result<DeleteRootAuthorizationFieldsV2, RootDeleteErrorV1> {
        self.verified_authorization_cut_data_v2()?;
        self.authorization.fields.as_ref().and_then(|result| result.as_ref().ok()).copied()
            .ok_or(RootDeleteErrorV1::Original)
    }

    pub(in crate::policy_compiler::delete_root) fn verified_authorized_input_v2(
        &self,
    ) -> Result<&[u8], RootDeleteErrorV1> {
        self.verified_authorization_cut_data_v2()?;
        let fields = self.authorization.fields.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(RootDeleteErrorV1::Original)?;
        let input = self.authorization.body.bytes_v2()?;
        usize::try_from(fields.input_bytes).ok().and_then(|length| input.get(..length))
            .ok_or(RootDeleteErrorV1::Original)
    }

    pub(in crate::policy_compiler::delete_root) fn verified_planning_predecessor_v2(&self)
        -> Result<(aos_sandbox_protocol::domain_ledger::resource_bank::OperationIntakeFundingDataV1, u64, u64,
            [u8; 16], [u8; 32]), RootDeleteErrorV1> {
        self.verified_authorization_cut_data_v2()?;
        let fields = self.authorization.fields.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(RootDeleteErrorV1::Original)?;
        let frame = self.frame.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(RootDeleteErrorV1::Original)?;
        let body = self.authorization.body.bytes_v2()?;
        let input = usize::try_from(fields.input_bytes).ok()
            .and_then(|length| body.get(..length)).ok_or(RootDeleteErrorV1::Original)?;
        let input = aos_sandbox_protocol::domain_ledger::delete_root::named_cuts::
            planning_authorized_input_cut_data_v2(input);
        Ok((frame.funding, frame.next, frame.end, fields.caller, input))
    }

    pub(in crate::policy_compiler::delete_root) fn verified_authorization_cut_data_v2(&self) -> Result<[u8; 32], RootDeleteErrorV1> {
        if !self.complete
            || self.first.is_some()
            || !self.authorization.complete
            || self.failure().is_some()
        {
            return Err(RootDeleteErrorV1::Original);
        }
        self.readback_v2()
            .map_err(|_| RootDeleteErrorV1::Original)?;
        self.authorization
            .recomputed
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(RootDeleteErrorV1::Original)
    }
}

impl RootDeleteControllerAuthorizationOriginalV2 {
    pub(super) fn body_wire_bytes(&self) -> Result<u64, ResourceReservationErrorV1> {
        let fields = self
            .fields
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        fields
            .input_bytes
            .checked_add(DELETE_ROOT_AUTHORIZATION_CHECKSUM_BYTES_V2 as u64)
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            AuthorizationFirst::Header => self.header.failure(),
            AuthorizationFirst::Decode => cause(&self.fields),
            AuthorizationFirst::Association => cause(&self.association),
            AuthorizationFirst::Geometry => cause(&self.dynamic),
            AuthorizationFirst::Body => self.body.failure(),
            AuthorizationFirst::Checksum => cause(&self.checksum),
            AuthorizationFirst::Models => cause(&self.recomputed),
            AuthorizationFirst::Reentry => self.closed.as_ref().map(|cause| cause as _),
        }
    }

    pub(super) fn funding_failed(&self) -> bool {
        matches!(self.first, Some(AuthorizationFirst::Header))
            && self.header.financial_failure_is_selected_v1()
            || matches!(self.first, Some(AuthorizationFirst::Body))
                && self.body.financial_failure_is_selected_v1()
    }

    pub(super) fn property_failure_view(
        &self,
    ) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        match self.first? {
            AuthorizationFirst::Header => self.header.property_failure_view_v1(),
            AuthorizationFirst::Body => self.body.property_failure_view_v1(),
            _ => None,
        }
    }
}
