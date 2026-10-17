//! Predeclares exact original controls for the first two native checksum windows.
//!
//! The reusable fixture names source recipes and finite controls; fresh original
//! request IDs and grants are retained separately before Child. No native event
//! or publication ID is guessed from a coordinator position.

use std::collections::BTreeMap;

use crucible::node_adapters::cnp::CnpCompletedLifecyclePhase;
use crucible::node_contract::ActivationRecord;
use crucible_node_contract::{ContentRef, Id, Position, U64, canonical};
use crucible_node_provider::{ProviderError, envelope::Method, reference_device::DeviceGrant};

use super::installation::SourcePublicReferenceInstallation;
use crate::node_qualification::ReferenceWindowCase;

pub(super) const MAXIMUM_SELECTED_CONTROLS: usize = 10;

pub(super) struct OriginalLifecycleTarget {
    pub(super) request: Id,
    pub(super) phase: CnpCompletedLifecyclePhase,
    pub(super) operation: Option<Id>,
    pub(super) method: Method,
    pub(super) grant: Option<DeviceGrant>,
    pub(super) selected: bool,
    pub(super) window: Option<OriginalLifecycleWindow>,
}

#[derive(Clone)]
pub(super) struct OriginalLifecycleWindow {
    pub(super) grant: DeviceGrant,
    pub(super) input_cut: Position,
    pub(super) input_sequence: U64,
    pub(super) expected_input: ContentRef,
}

pub(super) struct SourceLifecycleResendPlan {
    pub(super) fixture: ContentRef,
    pub(super) bytes: Vec<u8>,
    pub(super) objects: BTreeMap<ContentRef, Vec<u8>>,
    pub(super) activation: ActivationRecord,
    pub(super) targets: Vec<OriginalLifecycleTarget>,
}

impl SourceLifecycleResendPlan {
    /// Materializes selected and unselected originals before native allocation.
    ///
    /// # Errors
    /// Refuses changed source window population, identity scope or encoding.
    pub(super) fn build(
        installed: &SourcePublicReferenceInstallation,
        activation: &ActivationRecord,
        cases: &[ReferenceWindowCase],
    ) -> Result<Self, ProviderError> {
        let bootstrap = &installed.bootstrap;
        if cases.len() != 3
            || activation.activation_id != bootstrap.activation_id
            || activation.generation != bootstrap.world_generation
            || activation.world_binding_hash != bootstrap.world_binding_hash
            || activation.owners.len() != 2
            || !activation.owners.iter().any(|owner| {
                owner.owner == bootstrap.owner_id
                    && owner.incarnation == bootstrap.authority.incarnation_id
                    && owner.generation == bootstrap.authority.owner_generation
            })
        {
            return Err(ProviderError::Correlation(
                "lifecycle fixture original world differs",
            ));
        }
        let bytes = canonical::canonical_json(&serde_json::json!({
            "schema":"crucible.reference.source-completed-resend-plan.v1",
            "source_package":installed.package.identity(),
            "selected_phases":["prepared","world-activated","input","begin","close","consumed"],
            "selected_windows":["0","1"],
            "unselected_windows":["2"],
            "maximum_selected_controls":MAXIMUM_SELECTED_CONTROLS,
            "transmission_archive":{"maximum_transmissions":13,"maximum_bytes":16777216},
            "typed_role_reader":{"maximum_objects":1024,"maximum_body_bytes":8388608,"maximum_metadata_bytes":1048576},
            "source_archives":{"peers":2,"maximum_requests_each":1024,"maximum_objects_each":1024,"maximum_bytes_each":8388608},
            "original_request_recipe":"cnp.installed-reference-request.v1-domain-commitment-v1",
            "original_result":"known-completed-full-codec-closure-before-actual-resend-v1",
            "owner_census":"original-provider-and-exact-one-companion-pid-startticks-group-maps-limits-equal-original-realization-before-each-selected-send-v1",
            "oracle":"unchanged-original-control-response-and-three-independent-native-checksum-windows-v1",
            "uncertainty":"sticky-original-custody-no-cache-promotion-v1",
            "inert_reader_controls":[
                "reference/lifecycle-reader/wrong-stop-native-grant",
                "reference/lifecycle-reader/foreign-observation-measurement",
                "reference/lifecycle-reader/foreign-observation-owner",
                "reference/lifecycle-reader/missing-foreign-ready",
                "reference/lifecycle-reader/incompatible-codec-role",
                "reference/lifecycle-reader/typed-root-media-retag"
            ],
            "exclusions":["conflicting-body","reconnect","whole-clause-credit","complete-no-effects"]
        }))?;
        let fixture = canonical::content_ref(&bytes, "application/json")?;
        let mut targets = Vec::new();
        targets
            .try_reserve_exact(14)
            .map_err(|_| ProviderError::ResourceExhausted("lifecycle target slots"))?;
        targets.push(OriginalLifecycleTarget {
            request: original_id("prepare-activate", &activation.activation_id)?,
            phase: CnpCompletedLifecyclePhase::Prepared,
            operation: None,
            method: Method::Activate,
            grant: None,
            selected: true,
            window: None,
        });
        targets.push(OriginalLifecycleTarget {
            request: original_id("world-activate", &activation.activation_id)?,
            phase: CnpCompletedLifecyclePhase::WorldActivated,
            operation: None,
            method: Method::WorldActivate,
            grant: None,
            selected: true,
            window: None,
        });
        for (index, case) in cases.iter().enumerate() {
            if case.node != installed.profile.descriptor.id
                || case.grant.quantum.get() != index as u64
                || case.grant.owner_id != installed.bootstrap.owner_id
                || case.grant.incarnation_id != installed.bootstrap.authority.incarnation_id
                || case.grant.generation != installed.bootstrap.authority.owner_generation
                || case.batch != case.grant.input_batch_id
            {
                return Err(ProviderError::Correlation(
                    "lifecycle original window differs",
                ));
            }
            let input_bytes: &[u8] =
                if installed.profile.descriptor.id.as_str() == "consumer" && index >= 1 {
                    br#"{"bytes_processed":"0","checksum":"0"}"#
                } else {
                    b""
                };
            let window = OriginalLifecycleWindow {
                grant: case.grant.clone(),
                input_cut: case.input_cut,
                input_sequence: case.grant.quantum.checked_add(U64::new(1))?,
                expected_input: canonical::content_ref(input_bytes, "application/octet-stream")?,
            };
            for (kind, phase, method, semantic, operation, grant) in [
                (
                    "input",
                    CnpCompletedLifecyclePhase::InputAccepted,
                    Method::Input,
                    &case.stage,
                    None,
                    None,
                ),
                (
                    "begin",
                    CnpCompletedLifecyclePhase::WindowCompleted,
                    Method::Begin,
                    &case.operation,
                    Some(case.operation.clone()),
                    Some(case.grant.clone()),
                ),
                (
                    "close",
                    CnpCompletedLifecyclePhase::PublicationClosed,
                    Method::QuantumClose,
                    &case.operation,
                    Some(case.operation.clone()),
                    Some(case.grant.clone()),
                ),
                (
                    "consume",
                    CnpCompletedLifecyclePhase::PublicationConsumed,
                    Method::Retire,
                    &case.operation,
                    Some(case.operation.clone()),
                    Some(case.grant.clone()),
                ),
            ] {
                targets.push(OriginalLifecycleTarget {
                    request: original_id(kind, semantic)?,
                    phase,
                    operation,
                    method,
                    grant,
                    selected: index < 2,
                    window: Some(window.clone()),
                });
            }
        }
        Ok(Self {
            objects: BTreeMap::from([(fixture.clone(), bytes.clone())]),
            fixture,
            bytes,
            activation: activation.clone(),
            targets,
        })
    }
}

pub(super) fn original_id(kind: &str, semantic: &Id) -> Result<Id, ProviderError> {
    let hash = canonical::hash(
        "cnp.installed-reference-request.v1",
        semantic.as_str().as_bytes(),
    )?;
    Ok(Id::new(format!("{kind}-{}", hash.digest))?)
}
