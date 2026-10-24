//! Closed packet-source input context with an exclusive superdense cut.
//!
//! The baseline CNP/1 Input body is unchanged. This source-specific negotiated
//! envelope extension separates original byte staging from later coordinator
//! consumption. It preserves every phase and microstep and grants no public
//! authority merely by decoding its fields.
//!
//! ```text
//! extensions = {"source-owned.packet-input/4":
//!   {"action":"stage","cut":{"schema_version":4,...,"cutoff":{...}}}}
//! extensions = {"source-owned.packet-input/4":
//!   {"action":"commit","cut":{...},"input_request_id":"original",
//!    "staging_receipt":{...}}}
//! ```

pub use crucible_source_birth_data::profile::reference_packet::input::PACKET_INPUT_FEATURE;

use crucible_node_format::*;
use serde::{Deserialize, Serialize};

use crate::{ProviderError, bodies::*, envelope::*};

use super::control::PacketControlSelection;

/// Binds a complete source-specific input cut to its original activated owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketInputCut {
    /// Selects the closed packet source edition, four.
    pub schema_version: u16,
    /// Names the authenticated original provider session.
    pub session_id: Id,
    /// Names the actual original provider incarnation.
    pub incarnation_id: Id,
    /// Names the complete admitted target node.
    pub node_id: Id,
    /// Names the indivisible native execution owner.
    pub execution_owner_id: Id,
    /// Fences an earlier realization of that owner.
    pub owner_generation: U64,
    /// Names the original complete durable world activation.
    pub activation_id: Id,
    /// Fences an earlier whole-world activation.
    pub world_generation: U64,
    /// Binds the independently installed complete world.
    pub world_binding_hash: HashRef,
    /// Names the immutable coordinator staging operation.
    pub stage_operation_id: Id,
    /// Names the original complete public input batch.
    pub batch_id: Id,
    /// Retains the actual original receiving stream position.
    pub batch_sequence: U64,
    /// Retains the receiving owner's original input epoch.
    pub input_epoch: Id,
    /// Binds the complete unchanged baseline InputBatch.
    pub batch_hash: HashRef,
    /// Binds every canonical delivery and causal association in original order.
    pub delivery_inventory: ContentRef,
    /// Retains the exclusive full cut, including Reaction and nonzero microsteps.
    pub cutoff: Position,
}

impl Validate for PacketInputCut {
    fn validate(&self) -> Result<(), ContractError> {
        self.world_binding_hash.validate()?;
        self.batch_hash.validate()?;
        self.delivery_inventory.validate()?;
        self.cutoff.validate()?;
        if self.schema_version != 4
            || self.owner_generation.get() == 0
            || self.world_generation.get() == 0
            || self.batch_sequence.get() == 0
            || self.world_binding_hash.domain != "cnp.world-binding.v1"
            || self.batch_hash.domain != "cnp.input-batch.v1"
            || self.delivery_inventory.media_type != "application/vnd.crucible.input-inventory+json"
        {
            return Err(crate::bodies::invalid(
                "packet_input_cut",
                "foreign original packet input cut",
            ));
        }
        Ok(())
    }
}

/// Separates nonexecuting byte staging from the original later consumption.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum PacketInputContext {
    /// Retains complete original byte custody without running reactions.
    Stage {
        /// Carries the immutable coordinator-authenticated cut.
        cut: PacketInputCut,
    },
    /// Makes the same original staged cut eligible under later native grants.
    Commit {
        /// Retains the exact original staging cut without reconstruction.
        cut: PacketInputCut,
        /// Names the actual completed original native Input request.
        input_request_id: Id,
        /// Names the native source's actual retained staging receipt.
        staging_receipt: ContentRef,
    },
}

impl PacketInputContext {
    /// Borrows the complete unchanged original staging cut.
    pub fn cut(&self) -> &PacketInputCut {
        match self {
            Self::Stage { cut } | Self::Commit { cut, .. } => cut,
        }
    }

    /// Decodes the one closed feature without substituting generic input grammar.
    ///
    /// # Errors
    /// Refuses absent/foreign features, oversized context or malformed source fields.
    pub fn decode(extensions: &Extensions) -> Result<Self, ProviderError> {
        crate::connection::serialized_credit(extensions, 16_384)?;
        if extensions.len() != 1 {
            return Err(ProviderError::Correlation(
                "packet input requires its one original feature",
            ));
        }
        let value = extensions
            .get(PACKET_INPUT_FEATURE)
            .ok_or(ProviderError::Correlation("packet input feature absent"))?;
        let context: Self = serde_json::from_value(value.clone()).map_err(ContractError::from)?;
        context.cut().validate()?;
        if let Self::Commit {
            staging_receipt, ..
        } = &context
        {
            staging_receipt.validate()?;
        }
        Ok(context)
    }

    /// Checks correlation against the actual installed source and activated native owner.
    ///
    /// This does not replace kernel peer authentication or source-owned retained
    /// bytes. The dispatcher must use its actual original installation and gate.
    ///
    /// # Errors
    /// Refuses changed envelope, owner, world, batch, epoch or full input cut.
    pub fn authenticate(
        &self,
        envelope: &Envelope,
        request: &InputRequest,
        selection: &PacketControlSelection,
        active: &WorldActivateRequest,
    ) -> Result<(), ProviderError> {
        crate::connection::serialized_credit(envelope, 65_536)?;
        envelope.validate()?;
        selection.provider.validate()?;
        selection.realization.validate()?;
        active.validate()?;
        crate::connection::serialized_credit(request, 65_536)?;
        if Self::decode(&envelope.extensions)? != *self
            || decode_request(Method::Input, &envelope.body)? != RequestBody::Input(request.clone())
        {
            return Err(ProviderError::Correlation(
                "packet original input context/body changed",
            ));
        }
        let cut = self.cut();
        cut.validate()?;
        request.validate()?;
        let binding = selection
            .realization
            .bindings
            .first()
            .ok_or(ProviderError::Correlation(
                "packet input original binding absent",
            ))?;
        let owner =
            selection
                .realization
                .owner_bindings
                .first()
                .ok_or(ProviderError::Correlation(
                    "packet input original owner absent",
                ))?;
        if selection.realization.bindings.len() != 1
            || selection.realization.owner_bindings.len() != 1
            || envelope.message != MessageKind::Request
            || envelope.method != Method::Input
            || envelope.session_id.0.as_ref() != Some(&cut.session_id)
            || envelope.incarnation_id.0.as_ref() != Some(&cut.incarnation_id)
            || envelope.node_id.0.as_ref() != Some(&cut.node_id)
            || envelope.execution_owner_id.0.as_ref() != Some(&cut.execution_owner_id)
            || envelope.capture_owner_id.0.is_some()
            || envelope.operation_id.0.is_some()
            || cut.session_id != binding.authority.session_id
            || cut.incarnation_id != binding.authority.incarnation_id
            || cut.node_id != binding.compatibility.node_id
            || cut.execution_owner_id != owner.owner.id
            || cut.owner_generation != binding.authority.owner_generation
            || cut.activation_id != active.activation_id
            || cut.world_generation != active.world_generation
            || cut.world_binding_hash != selection.world
            || active.world_binding_hash != selection.world
            || active.transaction_id != selection.transaction
            || active.prepared_token != selection.prepared_token
            || active.gate_id != selection.gate
            || request.binding_hash != owner.identity()?
            || request.owner_generation != cut.owner_generation
            || request.input_epoch != cut.input_epoch
            || cut.input_epoch != binding.authority.input_epoch
            || request.batch_id != cut.batch_id
            || request.batch_sequence != cut.batch_sequence
            || request.batch_hash != cut.batch_hash
            || !request.extensions.is_empty()
        {
            return Err(ProviderError::Correlation(
                "packet input original source scope changed",
            ));
        }
        let batch = InputBatch {
            schema_version: 1,
            execution_owner_id: cut.execution_owner_id.clone(),
            input_epoch: request.input_epoch.clone(),
            batch_id: request.batch_id.clone(),
            batch_sequence: request.batch_sequence,
            events: request.events.clone(),
            extensions: Extensions::new(),
        };
        if batch.identity()? != cut.batch_hash {
            return Err(ProviderError::Correlation(
                "packet input original complete batch changed",
            ));
        }
        Ok(())
    }
}
