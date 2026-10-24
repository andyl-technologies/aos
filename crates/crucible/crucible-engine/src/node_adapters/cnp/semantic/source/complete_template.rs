//! Copies only immutable installation declarations for a distinct fresh Source.
//!
//! No process, current read, once occurrence, receiver or native handle is part
//! of this DATA type. The defining fresh Source constructor independently quotes
//! these cloned containers while retaining the original installed code owner.

use super::*;

impl CnpSemanticInstallation {
    pub(in crate::node_adapters::cnp::semantic) fn cloned_complete_template_data(&self) -> Self {
        let Self {
            provider,
            profile,
            descriptor,
            binding,
            capabilities,
            exact_facet,
            guarantees,
            owner,
            realize,
            admission,
            transaction,
            gate,
            admission_receipt,
            world_binding_hash,
            facets,
            receipt_schema,
            maximum_operations,
            maximum_result_bytes,
            maximum_authorization_bytes,
            maximum_semantic_bytes,
        } = self;
        Self {
            provider: provider.clone(),
            profile: profile.clone(),
            descriptor: descriptor.clone(),
            binding: binding.clone(),
            capabilities: capabilities.clone(),
            exact_facet: exact_facet.clone(),
            guarantees: guarantees.clone(),
            owner: owner.clone(),
            realize: realize.clone(),
            admission: admission.clone(),
            transaction: transaction.clone(),
            gate: gate.clone(),
            admission_receipt: admission_receipt.clone(),
            world_binding_hash: world_binding_hash.clone(),
            facets: facets.clone(),
            receipt_schema: receipt_schema.clone(),
            maximum_operations: *maximum_operations,
            maximum_result_bytes: *maximum_result_bytes,
            maximum_authorization_bytes: *maximum_authorization_bytes,
            maximum_semantic_bytes: *maximum_semantic_bytes,
        }
    }
}

#[path = "complete_template/clone_storage.rs"]
mod clone_storage;

pub(in crate::node_adapters::cnp::semantic) use clone_storage::{
    private_birth_clone_construction_data, private_birth_clone_counter_scratch_data,
};
