//! Predeclares provider-facing retransmissions of exact not-started originals.
//!
//! This first cohort resends the three actual pre-realization refusals. It does
//! not claim mutating duplicate, reconnect, or ambiguous-effect recovery. The
//! original requests and their responses remain unchanged in native journals.

use std::collections::BTreeMap;

use crucible_node_contract::{ContentRef, Id, canonical};
use crucible_node_provider::{ProviderError, client::TransmissionLimits};
use serde_json::json;

use super::{installation::SourcePublicReferenceInstallation, source_probe::SourceProbePlan};

pub(super) const LIMITS: TransmissionLimits = TransmissionLimits {
    maximum_transmissions: 3,
    maximum_bytes: 4 * 1024 * 1024,
};

/// Retains the reusable cohort and the exact source-generated original IDs.
pub(super) struct SourceResendPlan {
    pub(super) reference: ContentRef,
    pub(super) bytes: Vec<u8>,
    pub(super) objects: BTreeMap<ContentRef, Vec<u8>>,
    pub(super) originals: SourceProbePlan,
    requests: Vec<Id>,
}

impl SourceResendPlan {
    /// Materializes the complete source fixture before any original Child.
    ///
    /// # Errors
    /// Refuses source fixture unavailability, changed population or encoding.
    pub(super) fn build(
        installed: &SourcePublicReferenceInstallation,
    ) -> Result<Self, ProviderError> {
        let originals = SourceProbePlan::build(installed)?;
        let bytes = canonical::canonical_json(&json!({
            "schema":"crucible.reference.source-original-resend-plan.v1",
            "original_probe_fixture":originals.reference,
            "case_scope":"pre-realization-conflict-not-started-only-v1",
            "ordered_cases":["configuration-mismatch","node-roster-mismatch","admit-before-realize"],
            "maximum_transmissions":LIMITS.maximum_transmissions,
            "maximum_transmission_bytes":LIMITS.maximum_bytes,
            "control_budget_ns":"3000000000",
            "reply_per_frame_bytes":"1048576",
            "connection":"original-live-connection-next-sequence-only-v1",
            "source_controls":"immutable-origin-controller-request-body-and-identity-v1",
            "native_premise":"actual-original-provider-only-census-before-each-send-and-after-v1",
            "oracle":"same-original-semantic-response-except-transport-sequence-v1",
            "privacy":"private-bootstrap-and-admission-token-excluded-v1",
            "failure":"unknown-fenced-original-transmission-and-journals-retained-v1",
            "exclusions":["mutating-duplicate","conflicting-body","reconnect","complete-no-effects","whole-clause-verdict"]
        }))?;
        let reference = canonical::content_ref(&bytes, "application/json")?;
        let mut objects = originals.objects.clone();
        objects.insert(reference.clone(), bytes.clone());
        let requests = originals
            .cases()
            .iter()
            .map(|case| case.request_id.clone())
            .collect::<Vec<_>>();
        if requests.len() != LIMITS.maximum_transmissions {
            return Err(ProviderError::Correlation(
                "source original resend population differs",
            ));
        }
        Ok(Self {
            reference,
            bytes,
            objects,
            originals,
            requests,
        })
    }

    pub(super) fn requests(&self) -> &[Id] {
        &self.requests
    }
}
