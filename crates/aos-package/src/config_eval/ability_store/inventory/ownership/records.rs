//! Canonical durable provider ownership records.
//!
//! An owner row binds one persistent logical resource and physical host object
//! to the exact stateful provider and stable terminal handler selected by a
//! checked plan. Claims fence admitted writes until an exact successful write
//! becomes the establishment. During adoption, the receipt retains the prior
//! establishment and its recovery artifacts until the candidate settles.
//!
//! The ownership-bearing portion of the version-1 native resource ledger has
//! the following shape. Digest and identity placeholders stand for their full
//! canonical model encodings.
//!
//! ```json
//! {
//!   "schema": "aos.ability.native-resource-ledger/v1",
//!   "owners": [{
//!     "resource": { "provider": "<owner-instance>", "key": "data" },
//!     "physical": {
//!       "class": "managed-configuration",
//!       "authority": "configuration-generation",
//!       "object": "/var/lib/example/data"
//!     },
//!     "identity": {
//!       "provider": "<owner-instance>",
//!       "package": "sha256:<owner-package>",
//!       "interface": "<owner-interface>",
//!       "implementation": "<owner-implementation>",
//!       "state_format": "<state-format>"
//!     },
//!     "handler": {
//!       "package": "sha256:<handler-package>",
//!       "provider": "<handler-instance>",
//!       "interface": "<handler-interface>",
//!       "implementation": "<handler-implementation>"
//!     },
//!     "generation": "gen-2",
//!     "transaction": "activate",
//!     "plan": "sha256:<candidate-plan>",
//!     "artifacts": ["<candidate-runtime-artifact>"],
//!     "claim_by": [{
//!       "generation": "gen-2",
//!       "transaction": "activate",
//!       "plan": "sha256:<candidate-plan>",
//!       "operation": "<candidate-write>",
//!       "attempt": 1,
//!       "artifacts": ["<candidate-runtime-artifact>"]
//!     }],
//!     "established_by": {
//!       "generation": "gen-2",
//!       "transaction": "activate",
//!       "plan": "sha256:<candidate-plan>",
//!       "operation": "<candidate-write>",
//!       "attempt": 1,
//!       "artifacts": ["<candidate-runtime-artifact>"]
//!     },
//!     "adoption": {
//!       "authority": "sha256:<transition-authority>",
//!       "source": "<source-owner-identity>",
//!       "source_handler": "<source-handler-identity>",
//!       "source_generation": "gen-1",
//!       "source_transaction": "activate",
//!       "source_plan": "sha256:<source-plan>",
//!       "source_artifacts": ["<source-runtime-artifact>"],
//!       "source_establishment": {
//!         "generation": "gen-1",
//!         "transaction": "activate",
//!         "plan": "sha256:<source-plan>",
//!         "operation": "<source-write>",
//!         "attempt": 1,
//!         "artifacts": ["<source-runtime-artifact>"]
//!       },
//!       "consumer_requirement": "required",
//!       "linked_verification": {
//!         "generation": "gen-2",
//!         "transaction": "repair",
//!         "plan": "sha256:<repair-plan>",
//!         "plan_bundle": "sha256:<repair-bundle>",
//!         "authority_publication": "sha256:<current-authority>"
//!       }
//!     }
//!   }],
//!   "consumers": [{
//!     "physical": "<qualified-physical-resource>",
//!     "logical": { "provider": "<owner-instance>", "key": "data" },
//!     "generation": "gen-2",
//!     "transaction": "activate",
//!     "plan": "sha256:<candidate-plan>",
//!     "binding": "<terminal-binding>",
//!     "consumer": "<owner-instance>",
//!     "provider": "<handler-instance>",
//!     "owner": "<candidate-owner-identity>",
//!     "desired_revision": "sha256:<desired-revision>",
//!     "artifacts": ["<candidate-runtime-artifact>"],
//!     "operation": "<candidate-write>",
//!     "attempt": 1
//!   }]
//! }
//! ```

use aos_ability_model::{
    ArtifactReference, InstanceId, InterfaceKey, OperationId, PlanId,
    ProviderImplementationReference, ProviderStateFormat, ResourceId, TransactionId,
};
use serde::{Deserialize, Serialize};

use super::super::{NativeConsumerRequirement, NativePhysicalResource};

/// Identifies the implementation that owns persistent native state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::config_eval::ability_store) struct NativeProviderIdentity {
    /// Names the provider instance that owns the logical resource.
    pub(in crate::config_eval::ability_store::inventory) provider: InstanceId,
    /// Identifies the package that declared the owning implementation.
    pub(in crate::config_eval::ability_store::inventory) package: aos_contract::Sha256Digest,
    /// Pins the public owner/provider interface selected for the owning implementation.
    pub(in crate::config_eval::ability_store::inventory) interface: InterfaceKey,
    /// Pins the exact owning implementation and its artifact.
    pub(in crate::config_eval::ability_store::inventory) implementation:
        ProviderImplementationReference,
    /// Pins the compatible durable state representation.
    pub(in crate::config_eval::ability_store::inventory) state_format: ProviderStateFormat,
}

/// Identifies the stable checked handler authorized to affect a resource.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::config_eval::ability_store) struct NativeProviderHandlerIdentity {
    /// Pins the package that authenticated the terminal implementation.
    pub(in crate::config_eval::ability_store::inventory) package: aos_contract::Sha256Digest,
    /// Names the stable provider instance selected for the handler.
    pub(in crate::config_eval::ability_store::inventory) provider: InstanceId,
    /// Pins the handler interface independently from plan-local bindings.
    pub(in crate::config_eval::ability_store::inventory) interface: InterfaceKey,
    /// Pins the exact handler implementation and artifact.
    pub(in crate::config_eval::ability_store::inventory) implementation:
        ProviderImplementationReference,
}

/// Retains exact source evidence until an adopted generation becomes terminal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::config_eval::ability_store) struct NativeProviderAdoptionReceipt {
    /// Binds the transfer to one sealed transition authority.
    pub(in crate::config_eval::ability_store::inventory) authority: aos_contract::Sha256Digest,
    /// Retains the complete identity that previously owned the resource.
    pub(in crate::config_eval::ability_store::inventory) source: NativeProviderIdentity,
    /// Retains the source's exact checked terminal handler authority.
    pub(in crate::config_eval::ability_store::inventory) source_handler:
        NativeProviderHandlerIdentity,
    /// Names the generation that last held source ownership.
    pub(in crate::config_eval::ability_store) source_generation: String,
    /// Names the transaction that last held source ownership.
    pub(in crate::config_eval::ability_store::inventory) source_transaction: TransactionId,
    /// Pins the plan that last held source ownership.
    pub(in crate::config_eval::ability_store::inventory) source_plan: PlanId,
    /// Retains every source artifact needed to recover the transfer.
    pub(in crate::config_eval::ability_store::inventory) source_artifacts: Vec<ArtifactReference>,
    /// Authenticates the successful source write whose ownership is transferred.
    pub(in crate::config_eval::ability_store) source_establishment: NativeProviderEstablishment,
    /// Pins the authenticated consumer cardinality for linked settlement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::config_eval::ability_store::inventory) consumer_requirement:
        Option<NativeConsumerRequirement>,
    /// Commits a recorded linked check to the exact recovery graph and authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::config_eval::ability_store) linked_verification:
        Option<NativeLinkedAdoptionVerification>,
}

/// Binds a durable linked-adoption check to one exact recovery transaction.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::config_eval::ability_store) struct NativeLinkedAdoptionVerification {
    /// Names the generation containing the recovery graph.
    pub(in crate::config_eval::ability_store) generation: String,
    /// Names the transaction containing the recovery graph.
    pub(in crate::config_eval::ability_store::inventory) transaction: TransactionId,
    /// Pins the checked recovery plan.
    pub(in crate::config_eval::ability_store::inventory) plan: PlanId,
    /// Pins the canonical retained recovery bundle.
    pub(in crate::config_eval::ability_store::inventory) plan_bundle: aos_contract::Sha256Digest,
    /// Pins the independently authenticated reconciliation publication.
    pub(in crate::config_eval::ability_store::inventory) authority_publication:
        aos_contract::Sha256Digest,
}

/// Binds one persistent resource to its provider and sealed handler authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::config_eval::ability_store) struct NativeProviderOwner {
    /// Identifies the sole logical resource covered by this record.
    pub(in crate::config_eval::ability_store::inventory) resource: ResourceId,
    /// Pins the catalog-qualified host object independently of active consumers.
    pub(in crate::config_eval::ability_store::inventory) physical: NativePhysicalResource,
    /// Pins the implementation that owns the resource's durable state.
    pub(in crate::config_eval::ability_store::inventory) identity: NativeProviderIdentity,
    /// Pins the complete handler endpoint authenticated by the checked plan.
    pub(in crate::config_eval::ability_store::inventory) handler: NativeProviderHandlerIdentity,
    /// Names the generation that established this ownership record.
    pub(in crate::config_eval::ability_store) generation: String,
    /// Names the transaction that established this ownership record.
    pub(in crate::config_eval::ability_store::inventory) transaction: TransactionId,
    /// Pins the checked plan that established this ownership record.
    pub(in crate::config_eval::ability_store::inventory) plan: PlanId,
    /// Retains every artifact required by the current owner.
    pub(in crate::config_eval::ability_store::inventory) artifacts: Vec<ArtifactReference>,
    /// Authenticates every unsettled attempt that fenced this owner row.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(in crate::config_eval::ability_store) claim_by: Vec<NativeProviderClaim>,
    /// Authenticates the exact successful write that established this owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::config_eval::ability_store) established_by: Option<NativeProviderEstablishment>,
    /// Retains source authority while an atomic adoption is recoverable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::config_eval::ability_store) adoption: Option<NativeProviderAdoptionReceipt>,
}

/// Identifies the exact successful operation that established durable ownership.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::config_eval::ability_store) struct NativeProviderEstablishment {
    /// Names the generation containing the successful write.
    pub(in crate::config_eval::ability_store) generation: String,
    /// Names the transaction containing the successful write.
    pub(in crate::config_eval::ability_store) transaction: TransactionId,
    /// Pins the checked plan that authorized the successful write.
    pub(in crate::config_eval::ability_store) plan: PlanId,
    /// Identifies the exact successful persistent owner write.
    pub(in crate::config_eval::ability_store) operation: OperationId,
    /// Identifies the successful operation attempt.
    pub(in crate::config_eval::ability_store) attempt: u32,
    /// Retains the runtime artifacts authenticated by the checked plan.
    pub(in crate::config_eval::ability_store) artifacts: Vec<ArtifactReference>,
}

/// Identifies one admitted operation attempt that fences an owner row.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::config_eval::ability_store) struct NativeProviderClaim {
    /// Names the generation containing the admitted write.
    pub(in crate::config_eval::ability_store) generation: String,
    /// Names the transaction containing the admitted write.
    pub(in crate::config_eval::ability_store) transaction: TransactionId,
    /// Pins the checked plan that authorized the admitted write.
    pub(in crate::config_eval::ability_store) plan: PlanId,
    /// Identifies the exact persistent owner write.
    pub(in crate::config_eval::ability_store) operation: OperationId,
    /// Identifies the admitted operation attempt.
    pub(in crate::config_eval::ability_store) attempt: u32,
    /// Retains the runtime artifacts authenticated by the checked plan.
    pub(in crate::config_eval::ability_store) artifacts: Vec<ArtifactReference>,
}
