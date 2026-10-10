//! Drives independent real CNP probes under a complete installed witness plan.
//!
//! Protocol observations retain their narrow `IndependentProtocol` kind. They
//! cannot replace realized timing, state, role semantics or native custody
//! witnesses. Missing cases remain `NotExecuted` in the existing complete
//! witness ledger. Collection never changes a refused acceptance decision.

use std::collections::BTreeMap;

use crucible_node_contract::{ContentRef, HashRef, Id, canonical};
use crucible_node_provider::conformance::{ConformanceReport, ProbePlan, UnixProbeConnector};
use serde::Serialize;
use serde_json::Value;

use super::{
    CaseKind, CaseVerdict, InstalledAcceptancePolicy, InstalledWitnessAuthority,
    IssuedQualification, QualificationClass, QualificationError, QualificationLimits,
    QualificationUnit, WitnessPlan, WitnessPopulation,
};

mod attempts;
mod exact;
mod fixture_audit;
mod protocol;
mod protocol_witness;
mod quantized;
mod runtime_reports;
mod runtime_witness;
mod staging;

pub use attempts::OriginalCollectionAttempts;
pub use exact::{ExactCompletionCase, ExactCompletionObservation};
pub use fixture_audit::PlannedFixtureAudit;
pub use protocol_witness::OriginalProtocolWitness;
pub use quantized::{QuantizedCompletionCase, QuantizedCompletionObservation};
pub use runtime_reports::{InstalledRuntimeWitnessOracle, OriginalRuntimeReportStore};
pub use runtime_witness::{OriginalCompletionObservation, OriginalCompletionWitness};

#[cfg(test)]
mod tests;

/// Supplies independently installed collection and current acceptance scope.
///
/// Implementations must authenticate actual original observations and complete
/// case populations. A provider plan or parsed report cannot install this trait.
pub trait InstalledConformanceAuthority:
    InstalledAcceptancePolicy + InstalledWitnessAuthority
{
    /// Authenticates the exact source fixture, protocol oracle and actual peer.
    ///
    /// # Errors
    /// The default refuses. A production installer must join the selected peer
    /// executable and plan to the complete unit before any socket is opened.
    fn authenticate_protocol_fixture(
        &self,
        _population: &WitnessPlan,
        _case: &ProtocolCase,
    ) -> Result<(), QualificationError> {
        Err(QualificationError::Refused(
            "no installed protocol fixture authority",
        ))
    }

    /// Retains the actual original socket observation before result authentication.
    ///
    /// The runner alone constructs this borrowed witness after its real Unix
    /// exchanges. An installed policy must independently inspect the complete
    /// original report, source fixture and oracle, then retain their exact case
    /// and body identity for its later `authenticate_result` callback.
    ///
    /// # Errors
    /// The default refuses. A serialized passed report cannot supply original
    /// observation custody or replace this independently installed callback.
    fn retain_original_protocol_witness(
        &self,
        _population: &WitnessPlan,
        _case: &ProtocolCase,
        _original: &OriginalProtocolWitness<'_>,
    ) -> Result<(), QualificationError> {
        Err(QualificationError::Refused(
            "no installed original protocol observation sink",
        ))
    }

    /// Retains actual same-token runtime custody before authenticating its report.
    ///
    /// The runner alone constructs this borrowed witness from the fresh original
    /// completion and the same full native input evidence used in its snapshot.
    /// Installed policy must join independent expected oracles and source seals,
    /// then retain exact report/case identities for `authenticate_result`.
    ///
    /// # Errors
    /// Defaults to refusal. Serialized reports, matching hashes or changed
    /// originals cannot supply authenticated runtime observation custody.
    fn retain_original_runtime_witness(
        &self,
        _population: &WitnessPlan,
        _case: &str,
        _oracle: &ContentRef,
        _original: &OriginalCompletionWitness<'_, '_>,
    ) -> Result<(), QualificationError> {
        Err(QualificationError::Refused(
            "no installed original runtime observation sink",
        ))
    }

    /// Authenticates an independent exact oracle against the actual source scope.
    ///
    /// # Errors
    /// The default refuses. Production policy must bind the expected request,
    /// full outcome, input view and ACK state to the original fixture/oracle.
    fn authenticate_exact_fixture(
        &self,
        _population: &WitnessPlan,
        _case: &ExactCompletionCase,
    ) -> Result<(), QualificationError> {
        Err(QualificationError::Refused(
            "no installed exact fixture authority",
        ))
    }

    /// Authenticates complete quantized, producer and native staging oracles.
    ///
    /// # Errors
    /// The default refuses. Production policy must bind the original request,
    /// full closure, all producer bodies and ACK state to this exact population.
    fn authenticate_quantized_fixture(
        &self,
        _population: &WitnessPlan,
        _case: &QuantizedCompletionCase,
    ) -> Result<(), QualificationError> {
        Err(QualificationError::Refused(
            "no installed quantized fixture authority",
        ))
    }
}

/// Binds one predeclared protocol case to its exact oracle and selected peer.
pub struct ProtocolCase {
    /// Names the original case in the authenticated complete witness plan.
    pub case: String,
    /// Contains the finite actual exchanges and independent field oracles.
    pub plan: ProbePlan,
    /// Binds canonical plan bytes through the original case oracle reference.
    pub oracle: ContentRef,
    /// Identifies independently selected actual peer executable bytes.
    pub peer_executable: ContentRef,
    /// Requires the actual transport peer user, without exporting credentials.
    pub peer_uid: u64,
}

/// Retains the original protocol report and its immutable installed scope.
#[derive(Serialize)]
pub struct ProtocolObservation {
    /// Selects this collection format rather than a behavioral certificate.
    pub schema: &'static str,
    /// Binds the original complete predeclared coverage population.
    pub population: ContentRef,
    /// Identifies the original case without a replacement retry.
    pub case: String,
    /// Retains the exact current independently installed unit.
    pub unit: QualificationUnit,
    /// Binds the independently installed durable node compatibility.
    pub binding: HashRef,
    /// Retains actual exchange results, failures and dependent omissions.
    pub report: ConformanceReport,
}

/// Owns finite original observations while their provider retains native custody.
pub struct ProductionConformanceRunner<'a> {
    authority: &'a dyn InstalledConformanceAuthority,
    node: Id,
    binding: HashRef,
    plan: WitnessPlan,
    population_reference: ContentRef,
    population: WitnessPopulation,
    attempts: OriginalCollectionAttempts,
    observations: BTreeMap<String, ProtocolObservation>,
    exact_observations: BTreeMap<String, ExactCompletionObservation>,
    quantized_observations: BTreeMap<String, QuantizedCompletionObservation>,
    limits: QualificationLimits,
    reserved_bytes: u64,
}

/// Retains complete issued coverage and every actual attempted observation.
pub struct CollectedConformance {
    /// Retains every actual attempt and separately authenticated original case.
    pub attempts: OriginalCollectionAttempts,
    /// Contains complete data, including all unexecuted behavioral witnesses.
    pub issued: Result<IssuedQualification, QualificationError>,
    /// Retains original reports even when evidence authentication refused them.
    pub observations: BTreeMap<String, ProtocolObservation>,
    /// Retains actual completed runtime witnesses without promoting their kind.
    pub exact_observations: BTreeMap<String, ExactCompletionObservation>,
    /// Retains complete original quantized closure and staged producer witnesses.
    pub quantized_observations: BTreeMap<String, QuantizedCompletionObservation>,
}

impl<'a> ProductionConformanceRunner<'a> {
    /// Authenticates complete coverage and current scope before opening a peer.
    ///
    /// A retained refused audit may supply a collection scope; every execution
    /// command still faces normal production acceptance and native admission.
    /// This constructor grants neither admission nor an exception to that gate.
    ///
    /// # Errors
    /// Refuses missing installed authority, changed bindings/unit/classes,
    /// malformed coverage or exhausted predeclared population credits.
    pub fn new(
        authority: &'a dyn InstalledConformanceAuthority,
        node: Id,
        binding: HashRef,
        plan_bytes: &[u8],
        plan_reference: &ContentRef,
        limits: QualificationLimits,
    ) -> Result<Self, QualificationError> {
        if plan_bytes.len() > limits.maximum_claim_bytes {
            return Err(QualificationError::Refused("collection plan byte ceiling"));
        }
        let population = WitnessPopulation::install(plan_bytes, plan_reference, authority, limits)?;
        let plan: WitnessPlan = serde_json::from_slice(plan_bytes)
            .map_err(crucible_node_contract::ContractError::from)?;
        protocol::current_scope(authority, &node, &binding, &plan.unit, &plan.classes)?;
        protocol::check_applicability(authority, &plan, plan_reference)?;

        Ok(Self {
            authority,
            node,
            binding,
            plan,
            population_reference: plan_reference.clone(),
            population,
            attempts: OriginalCollectionAttempts::default(),
            observations: BTreeMap::new(),
            exact_observations: BTreeMap::new(),
            quantized_observations: BTreeMap::new(),
            limits,
            reserved_bytes: plan_reference.length.get(),
        })
    }

    /// Executes one original protocol case with actual Unix peer measurements.
    ///
    /// The standard runner checks real handshake/sequence/correlation and closed
    /// response schemas. Native custody remains with the original external
    /// supervisor; disconnecting a probe never proves operation retirement.
    /// Original reports remain owned here even if later authentication refuses.
    ///
    /// # Errors
    /// Refuses unknown, replaced or behavioral cases, altered plan/peer identity,
    /// changed installed scope or rejected original evidence. An attempted case
    /// cannot be retried under the same ID, including after a failed exchange.
    pub fn run_protocol(
        &mut self,
        case: ProtocolCase,
        connector: &mut UnixProbeConnector,
        private_bindings: BTreeMap<String, Value>,
    ) -> Result<&ProtocolObservation, QualificationError> {
        let planned = self
            .plan
            .cases
            .iter()
            .find(|planned| planned.id == case.case)
            .ok_or(QualificationError::Refused("unplanned protocol collection"))?;
        if planned.kind != CaseKind::IndependentProtocol
            || planned
                .classes
                .iter()
                .any(|class| *class != QualificationClass::BaseProvider)
            || planned.oracle != case.oracle
            || self.attempts.attempted(&case.case)
        {
            return Err(QualificationError::Refused(
                "protocol case kind, scope or original differs",
            ));
        }
        protocol::check_plan(&case, self.limits)?;
        self.authority
            .authenticate_protocol_fixture(&self.plan, &case)?;
        protocol::current_scope(
            self.authority,
            &self.node,
            &self.binding,
            &self.plan.unit,
            &self.plan.classes,
        )?;
        let header = protocol::encoded_size(
            &(
                &self.plan.unit,
                &self.binding,
                &self.population_reference,
                &case.case,
            ),
            self.limits.maximum_claim_bytes,
        )?;
        let credit = protocol::report_credit(&case.plan)?
            .checked_add(header)
            .and_then(|n| n.checked_add(1024))
            .ok_or(QualificationError::Refused("observation credit overflow"))?;
        let reserved =
            self.reserved_bytes
                .checked_add(credit as u64)
                .ok_or(QualificationError::Refused(
                    "collection total credit overflow",
                ))?;
        if credit > self.limits.maximum_claim_bytes
            || credit as u64 > self.limits.maximum_evidence_bytes
            || reserved > self.limits.maximum_total_evidence_bytes
        {
            return Err(QualificationError::Refused(
                "complete observation pre-effect credit",
            ));
        }
        self.reserved_bytes = reserved;
        // Reserve the original attempt before connecting. Refused evidence
        // authentication cannot turn an earlier failed physical attempt into a
        // fresh successful retry under the same predeclared case.
        self.attempts.begin(case.case.clone());
        let mut scoped = protocol::ScopedConnector {
            underlying: connector,
            authority: self.authority,
            node: &self.node,
            binding: &self.binding,
            unit: &self.plan.unit,
            classes: &self.plan.classes,
            peer_executable: &case.peer_executable,
            peer_uid: case.peer_uid,
        };
        let report =
            crucible_node_provider::conformance::run(&case.plan, &mut scoped, private_bindings)
                .map_err(|error| QualificationError::Evidence(error.to_string()))?;
        let report_matches =
            protocol::check_report(&case.plan, &report, &case.peer_executable, case.peer_uid)
                .is_ok()
                && protocol::current_scope(
                    self.authority,
                    &self.node,
                    &self.binding,
                    &self.plan.unit,
                    &self.plan.classes,
                )
                .is_ok();
        let verdict = if report_matches && report.passed() {
            CaseVerdict::Passed
        } else {
            CaseVerdict::Failed
        };
        let observation = ProtocolObservation {
            schema: "crucible.original-protocol-witness.v1",
            population: self.population_reference.clone(),
            case: case.case.clone(),
            unit: self.plan.unit.clone(),
            binding: self.binding.clone(),
            report,
        };
        self.observations.insert(case.case.clone(), observation);
        let retained = self
            .observations
            .get(&case.case)
            .ok_or(QualificationError::Refused(
                "original protocol observation unavailable",
            ))?;
        protocol::precharge(retained, self.limits.maximum_claim_bytes)?;
        let bytes = canonical::canonical_json(
            &serde_json::to_value(retained).map_err(crucible_node_contract::ContractError::from)?,
        )?;
        let reference = canonical::content_ref(&bytes, "application/json")?;
        let original = OriginalProtocolWitness::new(retained, &reference, &bytes);
        self.authority
            .retain_original_protocol_witness(&self.plan, &case, &original)?;
        self.population
            .record(&case.case, verdict, &reference, &bytes, self.authority)?;
        self.attempts.authenticate(&case.case)?;
        Ok(retained)
    }

    /// Borrows every original observed report, including rejected authentication.
    pub fn observations(&self) -> &BTreeMap<String, ProtocolObservation> {
        &self.observations
    }

    /// Collects an original exact witness from the ordinary retained runtime.
    ///
    /// This method delegates through the same weaker original-evidence facade
    /// used by opaque conformance lifecycles, without running or acknowledging.
    ///
    /// # Errors
    /// Refuses foreign or unavailable originals, changed installed fixture or
    /// scope, missing complete evidence, duplicate attempts or credit overruns.
    pub fn collect_exact(
        &mut self,
        case: ExactCompletionCase,
        runtime: &mut crucible::node_contract::NodeRuntime,
        activation: &crucible::node_contract::WorldActivation,
        token: &crucible::node_contract::OperationToken,
    ) -> Result<&ExactCompletionObservation, QualificationError> {
        self.collect_exact_original(
            case,
            &mut runtime.original_witness(),
            Some(activation),
            token,
        )
    }

    /// Inspects an original exact completion without running or acknowledging it.
    ///
    /// Collection borrows real runtime permission/custody and reads the complete
    /// source-authenticated evidence closure. A full-outcome oracle mismatch is
    /// retained as a failed case. Actual class authentication remains installed.
    ///
    /// # Errors
    /// Refuses missing installed authority, changed scope, foreign/pending
    /// tokens, unsupported evidence readers, nonempty input without the complete
    /// original producer-lineage witness, duplicate attempts or byte limits.
    /// The caller keeps the original runtime/native custody on every refusal.
    pub fn collect_exact_witness(
        &mut self,
        case: ExactCompletionCase,
        runtime: &mut crucible::node_contract::OriginalRuntimeWitness<'_>,
        token: &crucible::node_contract::OperationToken,
    ) -> Result<&ExactCompletionObservation, QualificationError> {
        self.collect_exact_original(case, runtime, None, token)
    }

    fn collect_exact_original(
        &mut self,
        case: ExactCompletionCase,
        runtime: &mut crucible::node_contract::OriginalRuntimeWitness<'_>,
        activation: Option<&crucible::node_contract::WorldActivation>,
        token: &crucible::node_contract::OperationToken,
    ) -> Result<&ExactCompletionObservation, QualificationError> {
        let planned = self
            .plan
            .cases
            .iter()
            .find(|planned| planned.id == case.case)
            .ok_or(QualificationError::Refused("unplanned exact collection"))?;
        if planned.kind != CaseKind::RealizedProvider
            || planned.oracle != case.oracle
            || self.attempts.attempted(&case.case)
        {
            return Err(QualificationError::Refused("changed original exact case"));
        }
        protocol::current_scope(
            self.authority,
            &self.node,
            &self.binding,
            &self.plan.unit,
            &self.plan.classes,
        )?;
        self.authority
            .authenticate_exact_fixture(&self.plan, &case)?;
        // JSON byte arrays/escaped snapshot bytes and duplicate reference
        // metadata must fit the final evidence credit before body retrieval.
        let encoded_credit = case
            .maximum_bytes
            .checked_mul(6)
            .and_then(|n| n.checked_add(16_384))
            .ok_or(QualificationError::Refused(
                "exact encoding credit overflow",
            ))?;
        let reserved =
            self.reserved_bytes
                .checked_add(encoded_credit)
                .ok_or(QualificationError::Refused(
                    "exact collection credit overflow",
                ))?;
        if case.maximum_bytes == 0
            || encoded_credit > self.limits.maximum_evidence_bytes
            || encoded_credit > self.limits.maximum_claim_bytes as u64
            || reserved > self.limits.maximum_total_evidence_bytes
        {
            return Err(QualificationError::Refused(
                "exact collection pre-read credit",
            ));
        }
        self.reserved_bytes = reserved;
        self.attempts.begin(case.case.clone());
        let (observation, matches) = exact::collect(runtime, activation, token, &case)?;
        self.exact_observations
            .insert(case.case.clone(), observation);
        let retained =
            self.exact_observations
                .get(&case.case)
                .ok_or(QualificationError::Refused(
                    "original exact observation unavailable",
                ))?;
        let current = protocol::current_scope(
            self.authority,
            &self.node,
            &self.binding,
            &self.plan.unit,
            &self.plan.classes,
        )
        .is_ok();
        let verdict = if matches && current {
            CaseVerdict::Passed
        } else {
            CaseVerdict::Failed
        };
        protocol::precharge(retained, self.limits.maximum_claim_bytes)?;
        let bytes = canonical::canonical_json(
            &serde_json::to_value(retained).map_err(crucible_node_contract::ContractError::from)?,
        )?;
        let reference = canonical::content_ref(&bytes, "application/json")?;
        let completion = runtime
            .original_completed_operation(token)
            .map_err(|error| QualificationError::Evidence(error.to_string()))?;
        let original = OriginalCompletionWitness::exact(&completion, retained, &reference, &bytes)?;
        self.authority.retain_original_runtime_witness(
            &self.plan,
            &case.case,
            &case.oracle,
            &original,
        )?;
        self.population
            .record(&case.case, verdict, &reference, &bytes, self.authority)?;
        self.attempts.authenticate(&case.case)?;
        Ok(retained)
    }

    /// Collects an original quantized witness from the ordinary retained runtime.
    ///
    /// This method delegates through the same weaker original-evidence facade
    /// used by opaque conformance lifecycles, without running or acknowledging.
    ///
    /// # Errors
    /// Refuses foreign or unavailable originals, changed installed fixture or
    /// scope, missing complete evidence, duplicate attempts or credit overruns.
    pub fn collect_quantized(
        &mut self,
        case: QuantizedCompletionCase,
        runtime: &mut crucible::node_contract::NodeRuntime,
        activation: &crucible::node_contract::WorldActivation,
        token: &crucible::node_contract::OperationToken,
    ) -> Result<&QuantizedCompletionObservation, QualificationError> {
        self.collect_quantized_original(
            case,
            &mut runtime.original_witness(),
            Some(activation),
            token,
        )
    }

    /// Collects an original quantized completion and complete staged producer custody.
    ///
    /// Collection neither closes nor acknowledges the window. Complete source
    /// Stage receipt bodies and direct codec rows must survive independently of
    /// producer payloads. Exact timing cases use their separate collector.
    ///
    /// # Errors
    /// Refuses missing installed authority, changed population or source scope,
    /// pending/foreign tokens, unsupported complete native evidence, duplicate
    /// original attempts or exceeded predeclared snapshot/body credits. The
    /// caller retains its original runtime and native resources on refusal.
    pub fn collect_quantized_witness(
        &mut self,
        case: QuantizedCompletionCase,
        runtime: &mut crucible::node_contract::OriginalRuntimeWitness<'_>,
        token: &crucible::node_contract::OperationToken,
    ) -> Result<&QuantizedCompletionObservation, QualificationError> {
        self.collect_quantized_original(case, runtime, None, token)
    }

    fn collect_quantized_original(
        &mut self,
        case: QuantizedCompletionCase,
        runtime: &mut crucible::node_contract::OriginalRuntimeWitness<'_>,
        activation: Option<&crucible::node_contract::WorldActivation>,
        token: &crucible::node_contract::OperationToken,
    ) -> Result<&QuantizedCompletionObservation, QualificationError> {
        let planned = self
            .plan
            .cases
            .iter()
            .find(|planned| planned.id == case.case)
            .ok_or(QualificationError::Refused(
                "unplanned quantized collection",
            ))?;
        if planned.kind != CaseKind::RealizedProvider
            || planned.oracle != case.oracle
            || self.attempts.attempted(&case.case)
        {
            return Err(QualificationError::Refused(
                "changed original quantized case",
            ));
        }
        protocol::current_scope(
            self.authority,
            &self.node,
            &self.binding,
            &self.plan.unit,
            &self.plan.classes,
        )?;
        self.authority
            .authenticate_quantized_fixture(&self.plan, &case)?;
        let encoded_credit = case
            .maximum_bytes
            .checked_mul(6)
            .and_then(|n| n.checked_add(16_384))
            .ok_or(QualificationError::Refused(
                "quantized encoding credit overflow",
            ))?;
        let reserved =
            self.reserved_bytes
                .checked_add(encoded_credit)
                .ok_or(QualificationError::Refused(
                    "quantized collection credit overflow",
                ))?;
        if case.maximum_bytes == 0
            || encoded_credit > self.limits.maximum_evidence_bytes
            || encoded_credit > self.limits.maximum_claim_bytes as u64
            || reserved > self.limits.maximum_total_evidence_bytes
        {
            return Err(QualificationError::Refused(
                "quantized collection pre-read credit",
            ));
        }
        self.reserved_bytes = reserved;
        self.attempts.begin(case.case.clone());
        let (observation, matches, native_input) =
            quantized::collect(runtime, activation, token, &case)?;
        self.quantized_observations
            .insert(case.case.clone(), observation);
        let retained =
            self.quantized_observations
                .get(&case.case)
                .ok_or(QualificationError::Refused(
                    "original quantized observation unavailable",
                ))?;
        let current = protocol::current_scope(
            self.authority,
            &self.node,
            &self.binding,
            &self.plan.unit,
            &self.plan.classes,
        )
        .is_ok();
        let verdict = if matches && current {
            CaseVerdict::Passed
        } else {
            CaseVerdict::Failed
        };
        protocol::precharge(retained, self.limits.maximum_claim_bytes)?;
        let bytes = canonical::canonical_json(
            &serde_json::to_value(retained).map_err(crucible_node_contract::ContractError::from)?,
        )?;
        let reference = canonical::content_ref(&bytes, "application/json")?;
        let completion = runtime
            .original_completed_operation(token)
            .map_err(|error| QualificationError::Evidence(error.to_string()))?;
        let original = OriginalCompletionWitness::quantized(
            &completion,
            retained,
            native_input.as_ref(),
            &reference,
            &bytes,
        )?;
        self.authority.retain_original_runtime_witness(
            &self.plan,
            &case.case,
            &case.oracle,
            &original,
        )?;
        self.population
            .record(&case.case, verdict, &reference, &bytes, self.authority)?;
        self.attempts.authenticate(&case.case)?;
        Ok(retained)
    }

    /// Issues complete coverage data with all missing native cases unexecuted.
    ///
    /// An actual attempt without authenticated evidence refuses issuance instead
    /// of being rewritten as an unexecuted case. Never-attempted obligations
    /// remain unexecuted in the complete population.
    ///
    /// A final encoding refusal is retained alongside the original observations;
    /// it cannot discard them or become a partial accepted claim. Acceptance
    /// remains a separate fresh installed-policy evaluation.
    pub fn finish(self) -> CollectedConformance {
        let (attempts, issued) = self.attempts.finish(|| self.population.finish());
        CollectedConformance {
            issued,
            attempts,
            observations: self.observations,
            exact_observations: self.exact_observations,
            quantized_observations: self.quantized_observations,
        }
    }
}
