//! Freezes finite typed-reader input and checksum oracles before native launch.
//!
//! The programme contains two closed producers and one consumer, with three
//! windows each. It selects no accepted class. Unknown normative obligations
//! remain required and unexecuted; source enrollment supplies unpredictable
//! native measurements independently of later common completion reports.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    time::Duration,
};

use crate::node_qualification::{
    CaseKind, PlannedWitnessCase, QualificationClass, QualificationUnit, WitnessCriterion,
    WitnessPlan, normative_specification, requirement_catalog,
};
use crucible::node_contract::OperationRequest;
use crucible_node_contract::{ContentRef, Id, Phase, Position, U64, canonical};
use crucible_node_provider::{ProviderError, reference_device::DeviceOutput};
use serde::Serialize;

const QUANTUM_PS: u64 = 1000;
const HOST_BUDGET_NS: u64 = 1_000_000_000;
pub(super) const PRODUCER_BYTES: &[u8] = b"{\"bytes_processed\":\"0\",\"checksum\":\"0\"}";

/// Identifies one independently authored original participant before Child.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TypedReaderProgrammePeer {
    /// Names the exact original node in the complete collection world.
    pub node: Id,
    /// Names its separately owned native execution group.
    pub owner: Id,
    /// Fences its original native incarnation from other planned participants.
    pub incarnation: Id,
}

/// Freezes one original window and its independent complete semantic output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TypedReaderProgrammeWindow {
    /// Names this original collection case, without retries under another label.
    pub case: String,
    /// Names the selected participant.
    pub node: Id,
    /// Names the original Stage operation, separately from execution.
    pub stage: Id,
    /// Names the original immutable input batch.
    pub batch: Id,
    /// Names the original execution operation.
    pub operation: Id,
    /// Names the original quantized window.
    pub window: Id,
    /// Orders the native checksum ancestry from zero through two.
    pub quantum: U64,
    /// Declares the actual independently expected start permission.
    pub request: OperationRequest,
    /// Gives checksum state immediately before this original window.
    pub checksum_before: U64,
    /// Gives the independently computed complete native semantic output.
    pub output: DeviceOutput,
    /// Declares the exact ordered producer names, empty for closed input.
    pub producers: Vec<Id>,
}

/// Retains a closed finite programme without source, execution or class authority.
///
/// Its private constructor-generated roster cannot accept arbitrary serialized
/// windows. The host must authenticate the measured package and complete world
/// separately, then reserve all seven original custody slots before Child.
pub struct TypedReaderProgramme {
    pub(super) package: ContentRef,
    pub(super) peers: [TypedReaderProgrammePeer; 3],
    windows: Vec<TypedReaderProgrammeWindow>,
    reference: ContentRef,
    bytes: Vec<u8>,
}

impl TypedReaderProgramme {
    /// Freezes complete unexecuted coverage before any original participant launches.
    ///
    /// Every normative obligation keeps a distinct required, unexecuted case.
    /// The nine planned native windows are additional quantized observations;
    /// the remaining quantized criterion stays unexecuted even if all nine pass.
    /// No report, namespace, class, launch or native authority is installed here.
    ///
    /// # Errors
    /// Refuses another specification or fixture identity, unsupported classes,
    /// an absent quantized obligation or exhausted whole encoded plan credit.
    pub fn witness_plan(
        &self,
        unit: QualificationUnit,
        limitations: ContentRef,
    ) -> Result<WitnessPlan, ProviderError> {
        use crucible_node_contract::Validate;
        limitations.validate()?;
        let specification = normative_specification().map_err(|_| invalid())?.0;
        if unit.specification != specification || unit.fixtures != self.reference {
            return Err(invalid());
        }
        let classes = BTreeSet::from([
            QualificationClass::BaseProvider,
            QualificationClass::QuantizedTiming,
            QualificationClass::RoleProfile,
        ]);
        let (_, obligations) = requirement_catalog().map_err(|_| invalid())?;
        if !obligations.contains(&"CN-QUANT-10") {
            return Err(invalid());
        }
        let mut cases = Vec::new();
        cases
            .try_reserve_exact(obligations.len() + self.windows.len())
            .map_err(|_| credit())?;
        let mut requirements = BTreeMap::new();
        for obligation in obligations {
            let id = format!("unexecuted/{obligation}");
            cases.push(PlannedWitnessCase {
                id: id.clone(),
                kind: CaseKind::RealizedProvider,
                classes: classes.clone(),
                oracle: self.reference.clone(),
            });
            let mut selected = vec![id];
            if obligation == "CN-QUANT-10" {
                for window in &self.windows {
                    cases.push(PlannedWitnessCase {
                        id: window.case.clone(),
                        kind: CaseKind::RealizedProvider,
                        classes: BTreeSet::from([QualificationClass::QuantizedTiming]),
                        oracle: self.reference.clone(),
                    });
                    selected.push(window.case.clone());
                }
                selected.sort();
            }
            requirements.insert(
                obligation.to_owned(),
                WitnessCriterion::Applicable {
                    cases: selected,
                    criterion: self.reference.clone(),
                },
            );
        }
        cases.sort_by(|a, b| a.id.cmp(&b.id));
        let plan = WitnessPlan {
            schema: "crucible.node-witness-plan.v1".into(),
            unit,
            classes,
            requirements,
            cases,
            limitations,
        };
        count(&plan, 1024 * 1024)?;
        Ok(plan)
    }

    /// Constructs all nine grants and four routed input oracles before launch.
    ///
    /// The first two peers are closed producers; the third is the consumer.
    /// Every native generation is one. Producer payload bytes are fixed by the
    /// independently inspected source specification, rather than read back from
    /// a running provider. Consumer checksum arithmetic uses wrapping modulo
    /// 2^64 and retains state across its second and third windows.
    ///
    /// # Errors
    /// Refuses malformed package identity, duplicate participant/owner/incarnation
    /// scope, invalid generated IDs or an unrepresentable bounded programme.
    pub fn new(
        package: ContentRef,
        peers: [TypedReaderProgrammePeer; 3],
    ) -> Result<Self, ProviderError> {
        use crucible_node_contract::Validate;
        package.validate()?;
        for names in [
            peers.iter().map(|peer| &peer.node).collect::<BTreeSet<_>>(),
            peers
                .iter()
                .map(|peer| &peer.owner)
                .collect::<BTreeSet<_>>(),
            peers
                .iter()
                .map(|peer| &peer.incarnation)
                .collect::<BTreeSet<_>>(),
        ] {
            if names.len() != 3 {
                return Err(invalid());
            }
        }
        if peers[0].node >= peers[1].node {
            // The two equal-time producer publications retain the scheduler's
            // actual ASCII producer tie-break, including when payloads match.
            return Err(invalid());
        }

        let mut windows = Vec::new();
        windows.try_reserve_exact(9).map_err(|_| credit())?;
        let mut consumer_checksum = 0;
        for quantum in 0..3 {
            let consumer_before = consumer_checksum;
            if quantum != 0 {
                for _ in 0..2 {
                    consumer_checksum = rolling_checksum(consumer_checksum, PRODUCER_BYTES);
                }
            }
            // At later boundaries consume the already published pair before
            // producers publish their next pair, preserving the original cut.
            let order = if quantum == 0 { [0, 1, 2] } else { [2, 0, 1] };
            for index in order {
                let peer = &peers[index];
                let prefix = format!("typed-onboarding/{}/q{quantum}", peer.node);
                let window = Id::new(format!("{prefix}/window"))?;
                let batch = Id::new(format!("{prefix}/batch"))?;
                let consumer = index == 2;
                let nonempty = consumer && quantum != 0;
                windows.push(TypedReaderProgrammeWindow {
                    case: format!("typed-window-{index}-{quantum}"),
                    node: peer.node.clone(),
                    stage: Id::new(format!("{prefix}/stage"))?,
                    batch: batch.clone(),
                    operation: Id::new(format!("{prefix}/run"))?,
                    window: window.clone(),
                    quantum: U64::new(quantum),
                    request: OperationRequest::QuantumBegin {
                        window,
                        start: Position::new(
                            U64::new(quantum * QUANTUM_PS),
                            U64::new(0),
                            Phase::BoundaryControl,
                        ),
                        end: Position::new(
                            U64::new((quantum + 1) * QUANTUM_PS),
                            U64::new(0),
                            Phase::Publication,
                        ),
                        input_batch: batch,
                        host_budget: Duration::from_nanos(HOST_BUDGET_NS),
                    },
                    checksum_before: U64::new(if consumer { consumer_before } else { 0 }),
                    output: DeviceOutput {
                        bytes_processed: U64::new(if nonempty {
                            (PRODUCER_BYTES.len() * 2) as u64
                        } else {
                            0
                        }),
                        checksum: U64::new(if consumer { consumer_checksum } else { 0 }),
                    },
                    producers: if nonempty {
                        vec![peers[0].node.clone(), peers[1].node.clone()]
                    } else {
                        Vec::new()
                    },
                });
            }
        }

        #[derive(Serialize)]
        struct Programme<'a> {
            schema: &'static str,
            package: &'a ContentRef,
            peers: &'a [TypedReaderProgrammePeer; 3],
            windows: &'a [TypedReaderProgrammeWindow],
            external_inputs: &'a [Id],
            generation: U64,
            producer_payload: &'a [u8],
            acceptance: &'static str,
        }
        let document = Programme {
            schema: "crucible.typed-reader-onboarding-programme.v1",
            package: &package,
            peers: &peers,
            windows: &windows,
            external_inputs: &[],
            generation: U64::new(1),
            producer_payload: PRODUCER_BYTES,
            acceptance: "refused-unexecuted-obligations-retained",
        };
        count(&document, 65536)?;
        let value =
            serde_json::to_value(document).map_err(crucible_node_contract::ContractError::from)?;
        let bytes = canonical::canonical_json(&value)?;
        let reference = canonical::content_ref(&bytes, "application/json")?;
        Ok(Self {
            package,
            peers,
            windows,
            reference,
            bytes,
        })
    }

    /// Returns the exact pre-Child programme identity, distinct from a certificate.
    pub fn reference(&self) -> &ContentRef {
        &self.reference
    }

    /// Borrows the complete canonical pre-Child programme bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the exact independently selected measured package identity.
    pub fn package(&self) -> &ContentRef {
        &self.package
    }

    /// Borrows all nine original windows in their declared driving order.
    pub fn windows(&self) -> &[TypedReaderProgrammeWindow] {
        &self.windows
    }

    pub(super) fn window(
        &self,
        node: &Id,
        quantum: U64,
    ) -> Result<&TypedReaderProgrammeWindow, ProviderError> {
        self.windows
            .iter()
            .find(|window| &window.node == node && window.quantum == quantum)
            .ok_or_else(invalid)
    }

    pub(super) fn peer(&self, node: &Id) -> Result<&TypedReaderProgrammePeer, ProviderError> {
        self.peers
            .iter()
            .find(|peer| &peer.node == node)
            .ok_or_else(invalid)
    }
}

pub(super) fn rolling_checksum(mut checksum: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        checksum = checksum.wrapping_mul(257).wrapping_add(u64::from(*byte));
    }
    checksum
}

pub(super) fn invalid() -> ProviderError {
    ProviderError::Correlation("typed original programme or semantic oracle differs")
}

fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("typed original programme credit")
}

pub(super) fn count(value: &impl Serialize, maximum: usize) -> Result<(), ProviderError> {
    struct Counter(usize);

    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_sub(bytes.len())
                .ok_or_else(|| std::io::Error::other("programme metadata ceiling"))?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    serde_json::to_writer(Counter(maximum), value).map_err(|_| credit())
}

#[cfg(test)]
mod tests;
