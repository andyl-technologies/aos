//! Joins original native receipts with an independently owned packet-effect socket.
//!
//! Native receipts are enrolled through the actual source scope before report
//! authentication. A report cannot insert receipts or socket observations.

use std::{cell::RefCell, os::unix::net::UnixDatagram};

use crucible::node_contract::OperationRequest;
use crucible_node_provider::reference_packet::{
    PacketProgramDefinition, control::PacketNativeRecord,
};
use serde::Serialize;

use super::*;
use crate::node_qualification::{CaseKind, CaseVerdict, OriginalCompletionObservation};

mod expected;
mod runtime_binding;

const MAXIMUM_NATIVE_BYTES: usize = 8 * 1024 * 1024;
const MAXIMUM_NATIVE_RECORDS: usize = 128;

/// Binds one independently authored runtime case to its original grant and ACK.
///
/// The host must authenticate these fields through its installed complete plan.
/// They supply expected semantics, never an opaque permission or native seal.
#[derive(Serialize)]
pub struct PacketNativeCase {
    /// Names the predeclared realized-provider case in the complete population.
    pub case: String,
    /// Identifies its independent original oracle and fixture bytes.
    pub oracle: ContentRef,
    /// Names the original operation, without changing it for report collection.
    pub operation: Id,
    /// Retains the independently expected complete original permission.
    pub request: crucible::node_contract::OperationRequest,
    /// Requires the actual retained output acknowledgement disposition.
    pub acknowledged: bool,
}

struct NativeSeal {
    reference: ContentRef,
    bytes: Vec<u8>,
    record: PacketNativeRecord,
}

struct Observations {
    seals: Vec<NativeSeal>,
    bytes: usize,
    traces: [[u8; 33]; 2],
    trace_lengths: [usize; 2],
    trace_count: usize,
    failed: bool,
}

/// Retains original source-validated receipts and actual socket observations.
///
/// Installation requires the complete source programme and exclusively owned
/// observation socket before Child launch. This store grants no collection,
/// admission, readiness or class authority.
pub struct PacketNativeObservationStore {
    source: Rc<PacketSemanticSource>,
    program: PacketProgramDefinition,
    expected_owner: crucible::node_contract::OwnerIdentity,
    payload_reference: ContentRef,
    socket: UnixDatagram,
    observed: RefCell<Observations>,
}

impl PacketNativeObservationStore {
    /// Reserves receipt slots and verifies the exact programme before launch.
    ///
    /// # Errors
    /// Refuses changed source configuration, nonfinite programme, failed socket
    /// configuration or unavailable fixed original receipt credit.
    pub fn install(
        source: Rc<PacketSemanticSource>,
        program: PacketProgramDefinition,
        socket: UnixDatagram,
    ) -> Result<Rc<Self>, QualificationError> {
        let bytes = scope::encoded_program(&program)?;
        source.installation().descriptor.model_ref.verify(&bytes)?;
        if program.events.len() != 2
            || program.events[0].payload.is_some()
            || program.events[1]
                .payload
                .as_ref()
                .is_none_or(|payload| payload.as_slice().len() > 32)
        {
            return Err(QualificationError::Refused(
                "independent packet effect population",
            ));
        }
        let selected = source.installation();
        let expected_owner = crucible::node_contract::OwnerIdentity {
            owner: selected.owner.owner.id.clone(),
            incarnation: selected.binding.authority.incarnation_id.clone(),
            generation: selected.binding.authority.owner_generation,
        };
        let payload = program.events[1]
            .payload
            .as_ref()
            .ok_or(QualificationError::Refused(
                "source-owned packet payload absent",
            ))?;
        let payload_reference = crucible_node_contract::canonical::content_ref(
            payload.as_slice(),
            "application/octet-stream",
        )?;
        socket
            .set_nonblocking(true)
            .map_err(|error| QualificationError::Evidence(error.to_string()))?;
        let mut seals = Vec::new();
        seals
            .try_reserve_exact(MAXIMUM_NATIVE_RECORDS)
            .map_err(|_| QualificationError::Refused("original packet receipt slot allocation"))?;
        Ok(Rc::new(Self {
            source,
            program,
            expected_owner,
            payload_reference,
            socket,
            observed: RefCell::new(Observations {
                seals,
                bytes: 0,
                traces: [[0; 33]; 2],
                trace_lengths: [0; 2],
                trace_count: 0,
                failed: false,
            }),
        }))
    }

    pub(super) fn observe(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
    ) -> Result<(), QualificationError> {
        if !std::ptr::eq(scope.installation, self.source.installation()) {
            return Err(QualificationError::Refused(
                "foreign original packet receipt source",
            ));
        }
        let original = self
            .source
            .latest_original_native_witness(&scope)
            .map_err(|error| QualificationError::Evidence(error.reason))?;
        let mut observed = self
            .observed
            .try_borrow_mut()
            .map_err(|_| QualificationError::Refused("original packet observations busy"))?;
        if observed.failed {
            return Err(QualificationError::Refused(
                "original packet observation fenced",
            ));
        }
        // Reserve complete encoded/expanded ownership before copying a receipt.
        // This selected programme permits only two callbacks and tiny payloads.
        let remaining = MAXIMUM_NATIVE_BYTES
            .checked_sub(observed.bytes)
            .and_then(|credit| credit.checked_sub(original.bytes().len()))
            .ok_or(QualificationError::Refused(
                "original packet native body credit",
            ))?;
        let expanded = scope::encoded_size(original.record(), remaining)?;
        let credit = original
            .bytes()
            .len()
            .checked_add(expanded)
            .and_then(|size| observed.bytes.checked_add(size))
            .filter(|size| *size <= MAXIMUM_NATIVE_BYTES);
        if credit.is_none()
            || (observed.seals.len() == MAXIMUM_NATIVE_RECORDS
                && !observed
                    .seals
                    .iter()
                    .any(|seal| &seal.reference == original.reference()))
        {
            return Err(QualificationError::Refused(
                "original packet native body credit",
            ));
        }
        if !observed
            .seals
            .iter()
            .any(|seal| &seal.reference == original.reference())
        {
            observed.bytes = credit.ok_or(QualificationError::Refused(
                "original packet native body credit",
            ))?;
            observed.seals.push(NativeSeal {
                reference: original.reference().clone(),
                bytes: original.bytes().to_vec(),
                record: original.record().clone(),
            });
        }
        loop {
            let mut bytes = [0; 34];
            match self.socket.recv(&mut bytes) {
                Ok(length) if length <= 33 && observed.trace_count < 2 => {
                    let index = observed.trace_count;
                    let expected = &self.program.events[index];
                    let valid = match &expected.payload {
                        None => length == 1 && bytes[0] == 0,
                        Some(payload) => {
                            length == payload.as_slice().len() + 1
                                && bytes[0] == 1
                                && &bytes[1..length] == payload.as_slice()
                        }
                    };
                    if !valid {
                        observed.failed = true;
                        return Err(QualificationError::Refused(
                            "independent packet effect differs from programme",
                        ));
                    }
                    observed.traces[index][..length].copy_from_slice(&bytes[..length]);
                    observed.trace_lengths[index] = length;
                    observed.trace_count += 1;
                }
                Ok(_) => {
                    observed.failed = true;
                    return Err(QualificationError::Refused(
                        "extra or overwide original packet effect",
                    ));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => {
                    observed.failed = true;
                    return Err(QualificationError::Evidence(error.to_string()));
                }
            }
        }
        let completed = original
            .record()
            .inventory
            .private_mutations
            .get()
            .checked_add(original.record().inventory.packet_effects.get())
            .ok_or(QualificationError::Refused(
                "original packet effect count overflow",
            ))?;
        // A native effect can arrive while its original Poll response is still
        // pending. Historical receipts may lag that independently retained prefix;
        // only the completed same-operation receipt can authenticate a report.
        if completed > observed.trace_count as u64 {
            observed.failed = true;
            return Err(QualificationError::Refused(
                "native receipt lacks independent complete effects",
            ));
        }
        Ok(())
    }
}

/// Checks original runner reports against pre-enrolled native and socket custody.
///
/// Construction retains the complete predeclared case list. The source-installed
/// authority separately authenticates its original oracle references and grants.
pub struct PacketNativeOracle {
    store: Rc<PacketNativeObservationStore>,
    plan: WitnessPlan,
    cases: Vec<PacketNativeCase>,
    original_bindings: runtime_binding::OriginalBindings,
}

impl PacketNativeOracle {
    /// Retains finite original case expectations before native allocation.
    ///
    /// # Errors
    /// Refuses unknown or repeated cases, wrong oracle/kind, unsupported requests
    /// or insufficient complete plan/case credit.
    pub fn install(
        store: Rc<PacketNativeObservationStore>,
        plan: &WitnessPlan,
        cases: Vec<PacketNativeCase>,
    ) -> Result<Rc<Self>, QualificationError> {
        if cases.is_empty() || cases.len() > 64 {
            return Err(QualificationError::Refused(
                "original packet native case credit",
            ));
        }
        scope::precharge_native_cases(plan, &cases)?;
        for (index, expected) in cases.iter().enumerate() {
            if cases[..index].iter().any(|case| case.case == expected.case)
                || !plan.cases.iter().any(|case| {
                    case.id == expected.case
                        && case.oracle == expected.oracle
                        && case.kind == CaseKind::RealizedProvider
                })
                || !matches!(
                    expected.request,
                    OperationRequest::ExactRun { .. } | OperationRequest::BoundarySettle { .. }
                )
            {
                return Err(QualificationError::Refused(
                    "unknown original packet native case",
                ));
            }
        }
        let original_bindings = runtime_binding::OriginalBindings::reserve(cases.len())?;
        Ok(Rc::new(Self {
            store,
            plan: plan.clone(),
            cases,
            original_bindings,
        }))
    }

    pub(super) fn authenticate_installation(
        &self,
        source: &Rc<PacketSemanticSource>,
        plan: &WitnessPlan,
        installed: &dyn InstalledPacketFixtureAuthority,
    ) -> Result<(), QualificationError> {
        if !Rc::ptr_eq(source, &self.store.source) || plan != &self.plan {
            return Err(QualificationError::Refused(
                "foreign original packet native oracle",
            ));
        }
        for case in &self.cases {
            installed.authenticate_packet_grant(
                plan,
                &source.installation().descriptor.id,
                &case.operation,
                &case.request,
            )?;
        }
        Ok(())
    }

    pub(super) fn preflight(&self) -> Result<(), QualificationError> {
        let observed = self
            .store
            .observed
            .try_borrow()
            .map_err(|_| QualificationError::Refused("original packet observations busy"))?;
        // Native Begin and its original Poll can each add one source-selected
        // 64 KiB body plus its typed copy. Refuse this credit before either effect.
        let bytes = self.store.source.installation().maximum_result_bytes;
        let reserved = bytes
            .checked_mul(4)
            .and_then(|credit| credit.checked_add(observed.bytes));
        if observed.failed
            || observed.seals.len() > MAXIMUM_NATIVE_RECORDS - 2
            || reserved.is_none_or(|credit| credit > MAXIMUM_NATIVE_BYTES)
        {
            return Err(QualificationError::Refused(
                "future original packet observation credit",
            ));
        }
        Ok(())
    }

    pub(super) fn observe(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
    ) -> Result<(), QualificationError> {
        self.store.observe(scope)
    }
}

impl InstalledRuntimeWitnessOracle for PacketNativeOracle {
    fn authenticate_original(
        &self,
        plan: &WitnessPlan,
        case: &PlannedWitnessCase,
        original: &OriginalCompletionWitness<'_, '_>,
    ) -> Result<CaseVerdict, QualificationError> {
        let expected = self
            .cases
            .iter()
            .find(|expected| expected.case == case.id && expected.oracle == case.oracle)
            .ok_or(QualificationError::Refused(
                "original packet native case unavailable",
            ))?;
        let completed = original.original();
        let admission = completed.admission();
        if plan != &self.plan
            || admission.activation().record().world_binding_hash
                != self.store.source.installation().world_binding_hash
            || admission.activation().record().owners
                != std::slice::from_ref(&self.store.expected_owner)
            || admission.token().route().node != self.store.source.installation().descriptor.id
            || admission.token().route().owners != std::slice::from_ref(&self.store.expected_owner)
            || admission.token().operation() != &expected.operation
            || admission.request() != &expected.request
            || completed.acknowledged() != expected.acknowledged
            || admission.inputs().is_some()
            || original.native_input().is_some()
            || !matches!(
                original.observation(),
                OriginalCompletionObservation::Exact(_)
            )
        {
            return Err(QualificationError::Refused(
                "original packet completion changed fixture scope",
            ));
        }
        let native = completed
            .outcome()
            .scheduling
            .as_ref()
            .ok_or(QualificationError::Refused(
                "original packet native inventory absent",
            ))?;
        let observed = self
            .store
            .observed
            .try_borrow()
            .map_err(|_| QualificationError::Refused("original packet observations busy"))?;
        let seal = observed
            .seals
            .iter()
            .find(|seal| seal.reference == native.proof_ref)
            .ok_or(QualificationError::Refused(
                "original packet receipt was not pre-enrolled",
            ))?;
        seal.reference.verify(&seal.bytes)?;
        let grant = seal
            .record
            .grant
            .as_ref()
            .ok_or(QualificationError::Refused(
                "original packet complete grant absent",
            ))?;
        let (start, limit) = match &expected.request {
            OperationRequest::ExactRun { start, limit, .. }
            | OperationRequest::BoundarySettle { start, limit } => (*start, *limit),
            _ => {
                return Err(QualificationError::Refused(
                    "unsupported packet native request",
                ));
            }
        };
        if observed.failed
            || !grant.complete
            || grant.operation != expected.operation
            || grant.start != start
            || grant.limit != limit
            || native.reached != grant.inventory.reached
            || native.node != self.store.source.installation().descriptor.id
            || !native.external_inputs.is_empty()
            || native.input_progress.is_some()
            || native.publications.len() != grant.newborn.len()
        {
            return Err(QualificationError::Refused(
                "original native packet grant association changed",
            ));
        }
        for (actual, source) in native.publications.iter().zip(&grant.newborn) {
            if actual.publication_id != source.event
                || actual.native_sequence != source.sequence
                || actual.evaluation != Some(source.evaluation)
                || actual.publication != source.publication
                || actual.payload_bytes != source.payload.as_slice()
                || !actual.causal_parents.is_empty()
            {
                return Err(QualificationError::Refused(
                    "original packet output differs from native/source oracle",
                ));
            }
            actual.payload.verify(&actual.payload_bytes)?;
        }
        self.store
            .source
            .authenticate_current_native()
            .map_err(|error| QualificationError::Evidence(error.reason))?;
        let index = self
            .cases
            .iter()
            .position(|selected| selected.case == case.id)
            .ok_or(QualificationError::Refused(
                "original packet case identity changed",
            ))?;
        self.original_bindings
            .retain(index, completed, original.reference())?;
        Ok(CaseVerdict::Passed)
    }
}

impl PacketNativeOracle {
    pub(super) fn authenticate_original_result(
        &self,
        case: &str,
        original: &crucible::node_contract::OriginalCompletedOperation<'_>,
        report: &ContentRef,
    ) -> Result<(), QualificationError> {
        let index = self
            .cases
            .iter()
            .position(|selected| selected.case == case)
            .ok_or(QualificationError::Refused(
                "original packet result case absent",
            ))?;
        self.original_bindings.authenticate(index, original, report)
    }
}
