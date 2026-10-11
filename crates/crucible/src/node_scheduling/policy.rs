//! Closed operating policies resolved and qualified during graph admission.

use crucible_node_contract::{ContentRef, U64};
use serde::{Deserialize, Serialize};

/// Selects a qualified representation of an unresolved exact input boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExactCeiling {
    /// Stops at the greatest representable position strictly before arrival.
    StrictPredecessor,
    /// Parks at arrival without consuming any semantic transition there.
    InputBlocked {
        /// Binds accepted evidence for the input-blocked park mechanism.
        proof_ref: ContentRef,
    },
}

/// Binds the closed scheduler policy of one selected operating contract.
///
/// These records are claims until graph admission resolves their content and
/// qualification. Constructing a record never grants execution authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutionPolicy {
    /// Selects regular exact boundaries from the operating contract.
    Exact {
        /// Selects edition one of this closed policy schema.
        #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
        schema_version: u16,
        /// Binds the complete modeled ceiling mechanism qualification.
        execution_proof_ref: ContentRef,
        /// Selects the qualified handling of unresolved possible arrival.
        ceiling: ExactCeiling,
        /// Qualifies phase-complete boundary reactions, or explicitly null.
        #[serde(deserialize_with = "required_nullable")]
        boundary_settlement_ref: Option<ContentRef>,
    },
    /// Selects fixed complete input batches and end-window output publication.
    Quantized {
        /// Selects edition one of this closed policy schema.
        #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
        schema_version: u16,
        /// Gives positive logical quantum duration in picoseconds.
        quantum_ps: U64,
        /// Gives the grid phase, strictly smaller than its duration.
        phase_ps: U64,
        /// Gives the operational execution budget in nanoseconds.
        host_budget_ns: U64,
        /// Binds staging, closure, custody and mediated-clock qualification.
        window_proof_ref: ContentRef,
    },
}

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

impl ExecutionPolicy {
    /// Returns all evidence objects which admission must resolve and qualify.
    pub fn proof_refs(&self) -> Vec<&ContentRef> {
        match self {
            Self::Exact {
                execution_proof_ref,
                ceiling,
                boundary_settlement_ref,
                ..
            } => {
                let mut refs = vec![execution_proof_ref];
                if let ExactCeiling::InputBlocked { proof_ref } = ceiling {
                    refs.push(proof_ref);
                }
                refs.extend(boundary_settlement_ref.iter());
                refs
            }
            Self::Quantized {
                window_proof_ref, ..
            } => vec![window_proof_ref],
        }
    }
}
