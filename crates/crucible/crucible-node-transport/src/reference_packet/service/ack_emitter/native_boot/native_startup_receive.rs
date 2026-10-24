//! Restricts the same actual boot6 baseline to its three original requests.
//!
//! The scope borrows real boot and Control owners and has no public constructor.
//! Neither a method label nor parsed request body can issue this read scope.

use super::*;
use crate::reference_packet::{
    control::{PacketControl, PacketControlSelection},
    service::native_startup::data_equality,
};
use crate::{
    connection::{Connection, ProviderStream},
    envelope::{Envelope, MessageKind, Method},
};

pub(crate) struct OriginalNativeBirthReadScope<'a> {
    boot: &'a Rc<RefCell<NativeAckBoot>>,
    selection: &'a PacketControlSelection,
    method: Method,
}

impl NativeAckBoot {
    pub(crate) fn original_birth_read_scope<'a>(
        boot: &'a Rc<RefCell<Self>>,
        control: &'a PacketControl,
        completed: usize,
    ) -> Result<Option<OriginalNativeBirthReadScope<'a>>, ProviderError> {
        Self::original_birth_scope(boot, control, completed, false)
    }

    pub(crate) fn original_birth_publication_scope<'a>(
        boot: &'a Rc<RefCell<Self>>,
        control: &'a PacketControl,
        completed: usize,
    ) -> Result<Option<OriginalNativeBirthReadScope<'a>>, ProviderError> {
        Self::original_birth_scope(boot, control, completed, true)
    }

    fn original_birth_scope<'a>(
        boot: &'a Rc<RefCell<Self>>,
        control: &'a PacketControl,
        completed: usize,
        publication: bool,
    ) -> Result<Option<OriginalNativeBirthReadScope<'a>>, ProviderError> {
        let owner = boot.try_borrow().map_err(|_| refused())?;
        owner.ensure_origin()?;
        let Some(startup) = owner.startup.as_ref() else {
            return Ok(None);
        };
        if startup.baseline_complete {
            return Ok(None);
        }
        if owner.data.schema == crate::reference_packet::service::native_startup::PACKET_NATIVE_INVOCATION_PRIVATE_BOOT_SCHEMA {
            owner.authenticate_original_invocation_birth_data()?;
        } else if owner.data.schema != PACKET_NATIVE_STARTUP_PRIVATE_BOOT_SCHEMA {
            return Err(refused());
        }
        if !owner.ready
            || !startup.native_birth_issued
            || completed > 2
            || (owner.verified && !(publication && completed == 2))
        {
            return Err(refused());
        }
        // Completed/legacy boots return above before a phase-specific Control
        // loan. Ordinary later dispatch still keeps its own original guards.
        let selection = control.original_native_birth_selection_data(completed, publication)?;
        owner
            .policy
            .as_ref()
            .ok_or_else(refused)?
            .authenticate_original_control_selection(selection)?;
        Ok(Some(OriginalNativeBirthReadScope {
            boot,
            selection,
            method: [Method::Discover, Method::Realize, Method::Admit][completed],
        }))
    }
}

impl OriginalNativeBirthReadScope<'_> {
    pub(crate) fn authenticate_connection<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        connection.authenticate_native5_source_codec()?;
        let owner = self.boot.try_borrow().map_err(|_| refused())?;
        owner.ensure_origin()?;
        let startup = owner.startup.as_ref().ok_or_else(refused)?;
        if owner.data.schema == crate::reference_packet::service::native_startup::PACKET_NATIVE_INVOCATION_PRIVATE_BOOT_SCHEMA {
            owner.authenticate_original_invocation_birth_data()?;
        } else if owner.data.schema != PACKET_NATIVE_STARTUP_PRIVATE_BOOT_SCHEMA
            || owner.data.source_birth.get("schema").and_then(serde_json::Value::as_str)
                != Some(PACKET_NATIVE_STARTUP_SOURCE_BINDING_SCHEMA)
        {
            return Err(refused());
        }
        if !owner.ready || !startup.native_birth_issued || startup.baseline_complete {
            return Err(refused());
        }
        let actual = owner.policy.as_ref().ok_or_else(refused)?;
        connection.authenticate_original_native_birth_policy_data(actual)?;
        actual.authenticate_original_control_selection(self.selection)
    }

    pub(crate) fn authenticate_proof_data(
        &self,
        original: &Envelope,
        response: &Envelope,
        record: &crate::connection::ExchangeRecord,
    ) -> Result<(), ProviderError> {
        original.matches_response(response)?;
        if !response.extensions.is_empty()
            || response.body.len() != 4
            || response
                .body
                .get("status")
                .and_then(serde_json::Value::as_str)
                != Some("completed")
            || response
                .body
                .get("operation_state")
                .and_then(serde_json::Value::as_str)
                != Some("completed")
            || response
                .body
                .get("extensions")
                .and_then(serde_json::Value::as_object)
                .is_none_or(|fields| !fields.is_empty())
        {
            return Err(refused());
        }
        let result = response
            .body
            .get("result")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(refused)?;
        if result.get("transfer_id") != original.body.get("transfer_id") {
            return Err(refused());
        }
        match original.method {
            Method::BlobBegin => {
                if result.len() != 3
                    || decimal(result.get("next_offset"))? != 0
                    || !(1..=1_048_576).contains(&decimal(result.get("maximum_chunk_bytes"))?)
                {
                    return Err(refused());
                }
            }
            Method::BlobChunk => {
                if result.len() != 2 {
                    return Err(refused());
                }
                decimal(result.get("next_offset"))?;
            }
            Method::BlobFinish => {
                let begun = record
                    .originals()
                    .iter()
                    .find(|frame| {
                        frame.method == Method::BlobBegin
                            && frame.body.get("transfer_id") == original.body.get("transfer_id")
                    })
                    .ok_or_else(refused)?;
                if result.len() != 2 || result.get("content") != begun.body.get("content") {
                    return Err(refused());
                }
            }
            _ => return Err(refused()),
        }
        Ok(())
    }

    pub(crate) fn authenticate_body_data(
        &self,
        body: &serde_json::Value,
    ) -> Result<(), ProviderError> {
        let fields = body.as_object().ok_or_else(refused)?;
        if fields
            .get("extensions")
            .and_then(serde_json::Value::as_object)
            .is_none_or(|extensions| !extensions.is_empty())
        {
            return Err(refused());
        }
        let matched = match self.method {
            Method::Discover => {
                let [profile] = self.selection.provider.supported_profiles.as_slice() else {
                    return Err(refused());
                };
                let ids = fields
                    .get("profile_ids")
                    .and_then(serde_json::Value::as_array)
                    .ok_or_else(refused)?;
                fields.len() == 2
                    && ids.len() == 1
                    && ids[0].as_str() == Some(profile.profile_id.as_str())
            }
            Method::Realize => data_equality::matches(body, &self.selection.realize),
            Method::Admit => {
                #[derive(serde::Serialize)]
                struct OriginalAdmit<'a> {
                    bindings: &'a [crucible_node_format::NodeBinding],
                    world_binding_hash: &'a crucible_node_format::HashRef,
                    admission_receipt: &'a crucible_node_format::ContentRef,
                    extensions: &'a crucible_node_format::Extensions,
                }
                let empty = crucible_node_format::Extensions::new();
                data_equality::matches(
                    body,
                    &OriginalAdmit {
                        bindings: &self.selection.realization.bindings,
                        world_binding_hash: &self.selection.world,
                        admission_receipt: &self.selection.admission_receipt,
                        extensions: &empty,
                    },
                )
            }
            _ => false,
        };
        if !matched {
            return Err(refused());
        }
        Ok(())
    }

    pub(crate) fn authenticate_header_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        request: &Envelope,
    ) -> Result<(), ProviderError> {
        self.authenticate_connection(connection)?;
        let [binding] = self.selection.realization.bindings.as_slice() else {
            return Err(refused());
        };
        if request.protocol != "CNP/1"
            || request.method != self.method
            || request.message != MessageKind::Request
            || request.session_id.0.as_ref() != Some(&binding.authority.session_id)
            || request.incarnation_id.0.as_ref() != Some(&binding.authority.incarnation_id)
            || request
                .request_id
                .0
                .as_ref()
                .is_none_or(|id| id.as_str().len() > 128)
            || request.operation_id.0.is_some()
            || request.capture_owner_id.0.is_some()
            || request.sequence.get() == 0
        {
            return Err(refused());
        }
        if self.method == Method::Admit {
            if request.node_id.0.as_ref()!=Some(&binding.compatibility.node_id)
                || request.execution_owner_id.0.as_ref()!=Some(&binding.compatibility.execution_owner.id)
                || request.extensions.len()!=1
                || !request.extensions.contains_key(crate::reference_packet::service::ack_emitter::PACKET_CANONICAL_ACK_ADMISSION_FEATURE)
            {return Err(refused());}
        } else if request.node_id.0.is_some()
            || request.execution_owner_id.0.is_some()
            || !request.extensions.is_empty()
        {
            return Err(refused());
        }
        Ok(())
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original native birth receive scope")
}

fn decimal(value: Option<&serde_json::Value>) -> Result<u64, ProviderError> {
    let text = value
        .and_then(serde_json::Value::as_str)
        .ok_or_else(refused)?;
    if text.is_empty() || text.len() > 20 || (text.len() > 1 && text.starts_with('0')) {
        return Err(refused());
    }
    text.bytes().try_fold(0u64, |number, digit| {
        if !digit.is_ascii_digit() {
            return Err(refused());
        }
        number
            .checked_mul(10)
            .and_then(|number| number.checked_add(u64::from(digit - b'0')))
            .ok_or_else(refused)
    })
}

impl NativeAckBoot {
    pub(crate) fn complete_original_native_birth<S: ProviderStream>(
        boot: &Rc<RefCell<Self>>,
        connection: &Connection<S>,
        records: &[crate::connection::ExchangeRecord],
    ) -> Result<(), ProviderError> {
        {
            let owner = boot.try_borrow().map_err(|_| refused())?;
            owner.ensure_origin()?;
            if owner.startup.is_none() {
                return Ok(());
            }
            if owner
                .startup
                .as_ref()
                .is_none_or(|startup| startup.baseline_complete)
                || records.len() != 3
            {
                return Err(refused());
            }
        }
        let actual = connection.original_native_owned11_admission()?;
        if !Rc::ptr_eq(&actual.boot, boot) {
            return Err(refused());
        }
        for (record, method) in
            records
                .iter()
                .zip([Method::Discover, Method::Realize, Method::Admit])
        {
            if record.sent() != record.originals().len()
                || record.originals().is_empty()
                || record.acknowledgements().len() != record.originals().len() - 1
            {
                return Err(refused());
            }
            let sent = record.original_sent_frame(connection, 0)?;
            let terminal = sent.original();
            if terminal.method != method
                || terminal.message != MessageKind::Response
                || terminal
                    .body
                    .get("status")
                    .and_then(serde_json::Value::as_str)
                    != Some("completed")
                || terminal
                    .body
                    .get("operation_state")
                    .and_then(serde_json::Value::as_str)
                    != Some("completed")
            {
                return Err(refused());
            }
            if method == Method::Admit {
                actual.original.matches_response(terminal)?;
            }
            for index in 1..record.originals().len() {
                record.original_sent_frame(connection, index)?;
            }
        }
        let mut owner = boot.try_borrow_mut().map_err(|_| refused())?;
        owner.ensure_origin()?;
        if !owner.ready
            || !owner.verified
            || owner.original.as_ref() != Some(&actual.original)
            || owner
                .policy
                .as_ref()
                .is_none_or(|policy| !Rc::ptr_eq(policy, &actual.policy))
        {
            return Err(refused());
        }
        let startup = owner.startup.as_mut().ok_or_else(refused)?;
        if !startup.native_birth_issued || startup.baseline_complete {
            return Err(refused());
        }
        startup.baseline_complete = true;
        if owner.data.schema == crate::reference_packet::service::native_startup::PACKET_NATIVE_INVOCATION_PRIVATE_BOOT_SCHEMA {
            owner.authenticate_original_invocation_baseline_data()
        } else {
            owner.authenticate_original_native_baseline_data()
        }
    }
}
