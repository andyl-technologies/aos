//! Defines host-installed source authority for original-lineage model preparation.
//!
//! The policy object belongs to daemon configuration. Signed source bodies and
//! portable requests cannot construct it or replace behavioral acceptance.

use std::collections::BTreeMap;

use crucible::{
    node_adapters::transcript::{AuthenticatedTranscript, InstalledReplayPolicy},
    node_admission::AdmissionEvidence,
    node_contract::ActivationRecord,
    node_scheduling::InputPayload,
};
use crucible_node_contract::{ContentRef, Id};

use crate::{
    node_observed_executor::NodeObservedError,
    node_scenario::{NodeRunConfiguration, NodeScenario},
};

/// Authenticates one immutable original-source scope configured by the host.
///
/// Implementations independently validate the original package, namespace,
/// selected definition and handler, complete native journals, ordered inputs,
/// original acknowledgements and typed body closure. This is a trusted host
/// interface; matching portable metadata is insufficient.
pub trait InstalledOriginalLineageSourcePolicy: Send {
    /// Borrows the exact immutable policy body pinned by host configuration.
    fn immutable_policy(&self) -> &InputPayload;

    /// Inspects authenticated originals without constructing or advancing models.
    ///
    /// The original map remains owned by the caller on refusal. A returned plan
    /// must retain all source evidence needed by its later callbacks; it cannot
    /// reopen retired source namespaces during model restoration.
    ///
    /// # Errors
    /// Refuses an unknown package or namespace, incomplete native evidence,
    /// changed source scope, unsupported configuration or exhausted finite credit.
    fn inspect(
        &self,
        originals: &BTreeMap<Id, AuthenticatedTranscript>,
        configuration: &NodeRunConfiguration,
        actual_host: &ContentRef,
        execution: crucible_campaign::ExecutionId,
    ) -> Result<Box<dyn InstalledOriginalLineagePlan>, NodeObservedError>;
}

/// Owns the inspected source and complete target definition before preparation.
///
/// Its admission evidence authenticates source support and actual target owners.
/// The catalog separately applies its independently installed behavioral
/// acceptance policy for the exact regenerated target binding and guarantees.
pub trait InstalledOriginalLineagePlan: AdmissionEvidence {
    /// Borrows the independently installed three-facet replay qualification.
    fn replay_policy(&self) -> &dyn InstalledReplayPolicy;

    /// Borrows the complete source-regenerated target scenario.
    fn scenario(&self) -> &NodeScenario;

    /// Borrows the exact actual live target bindings.
    fn bindings(&self) -> &[crucible_node_contract::NodeBinding];

    /// Borrows the activation planned for these actual target owners.
    fn activation(&self) -> &ActivationRecord;

    /// Borrows the unchanged original run configuration.
    fn configuration(&self) -> &NodeRunConfiguration;

    /// Borrows the exact original transcript commitments retained by this plan.
    fn original_references(&self) -> &BTreeMap<Id, ContentRef>;
}
