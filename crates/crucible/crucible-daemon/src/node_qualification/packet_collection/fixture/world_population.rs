//! Freezes one independently measured three-owner unit and all 436 witness cases.
//!
//! All 382 original RFC obligations remain required and NotExecuted. Fifty-four
//! source-native pre/post-ACK cases supplement them, without changing the RFC
//! catalog, applicability or claimed class scope. One common world, three measured
//! participants, nine windows and every fixed case/oracle ID bind the full unit.

use std::{collections::BTreeMap, rc::Rc};

use crucible_engine::{
    node_adapters::cnp::{CnpSemanticSource, PacketSemanticSource},
    node_admission::ScenarioRequirements,
    node_contract::{ExactBoundaryPolicy, OperationRequest},
};
use crucible_node_format::{ContentRef, Id, Phase, Position, U64, WorldBinding, canonical};
use crucible_node_transport::reference_packet::PacketProgramDefinition;

use super::{
    super::{
        PacketNativeCase, PacketNativeObservationStore, PacketNativeOracle, PacketWorldGrant,
        PacketWorldSchedule, scope,
    },
    FixtureBodies, InstalledPacketWorldGraphPolicy, QualificationError,
    issuer::records::decode,
    measurement,
    population::{classes, retain, retain_bytes},
};
use crate::node_qualification::{
    CaseKind, PlannedWitnessCase, QualificationUnit, WitnessCriterion, WitnessPlan,
    normative_specification, requirement_catalog,
};

/// Borrows complete source configuration for the fixed full-world population.
pub struct PacketWorldPopulationRequest<'a> {
    /// Retains the three exact world-scoped source objects in common world order.
    pub sources: [Rc<PacketSemanticSource>; 3],
    /// Retains the original compiled and measured full-world graph policy.
    pub graph_policy: Rc<InstalledPacketWorldGraphPolicy>,
    /// Borrows the one complete selected world.
    pub world: &'a WorldBinding,
    /// Borrows the exact authored limitation/requirements body.
    pub requirements: &'a ScenarioRequirements,
    /// Borrows complete original public program and graph policy objects.
    pub content: &'a FixtureBodies,
    /// Gives nine strictly increasing complete-programme exclusive horizons.
    pub horizons: [U64; 9],
    /// Gives 27 globally unique once-only operation IDs in window/member order.
    pub operations: [Id; 27],
}

/// Retains the complete measured Refused population and source-native templates.
///
/// This owns data only. It cannot authenticate a report, construct an accepted
/// certificate, grant Ready or replace the original policy/native owners.
pub struct PacketWorldWitnessPopulation {
    pub(in super::super) plan: WitnessPlan,
    pub(in super::super) reference: ContentRef,
    pub(in super::super) bytes: Vec<u8>,
    pub(in super::super) bodies: FixtureBodies,
    pub(in super::super) schedule: PacketWorldSchedule,
    pub(in super::super) native: [Vec<PacketNativeCase>; 3],
}

impl PacketWorldWitnessPopulation {
    /// Freezes the full measured unit and every original requirement before Child.
    ///
    /// # Errors
    /// Refuses revoked or foreign source policy, altered programme, incomplete
    /// normative catalog, changed measured scope, invalid schedule or byte ceilings.
    pub fn build(request: PacketWorldPopulationRequest<'_>) -> Result<Self, QualificationError> {
        let hash = canonical::json_hash("cnp.admission-requirements.v1", request.requirements)?;
        request
            .graph_policy
            .current(&request.sources, request.world, &hash)?;
        let measured = request.graph_policy.measurements();
        let selections: Vec<_> = request
            .sources
            .iter()
            .map(|source| source.installation())
            .collect();
        let programmes = [
            decode::<PacketProgramDefinition>(
                request.content,
                &selections[0].descriptor.model_ref,
            )?,
            decode::<PacketProgramDefinition>(
                request.content,
                &selections[1].descriptor.model_ref,
            )?,
            decode::<PacketProgramDefinition>(
                request.content,
                &selections[2].descriptor.model_ref,
            )?,
        ];
        scope::encoded_size(
            &(
                &request.operations,
                &request.horizons,
                &programmes,
                request.world,
                measured,
            ),
            1024 * 1024,
        )?;
        if programmes.iter().any(|program| {
            program.events.len() != 2
                || program.events.iter().any(|event| {
                    event.completion
                        >= Position::new(request.horizons[0], U64::new(0), Phase::BoundaryControl)
                })
        }) || selections.iter().any(|selected| {
            selected.maximum_operations < 9
                || selected.profile.profile_id.as_str() != "source-owned.packet-emitter-world/3"
        }) {
            return Err(refused());
        }
        let mut bodies = BTreeMap::new();
        let (specification, original_specification) = normative_specification()?;
        if retain_bytes(&mut bodies, original_specification, "application/json")? != specification {
            return Err(refused());
        }
        let (catalog, ids) = requirement_catalog()?;
        if ids.len() != 382 {
            return Err(refused());
        }
        if retain_bytes(
            &mut bodies,
            format!("{}\n", ids.join("\n")).into_bytes(),
            "text/plain",
        )? != catalog
        {
            return Err(refused());
        }
        let implementation = retain(
            &mut bodies,
            &(
                &selections
                    .iter()
                    .map(|selected| &selected.provider.implementation)
                    .collect::<Vec<_>>(),
                measured,
            ),
        )?;
        let realization = retain(
            &mut bodies,
            &(
                &selections
                    .iter()
                    .map(|selected| {
                        (
                            &selected.profile,
                            &selected.binding.compatibility,
                            &selected.capabilities,
                            &selected.guarantees,
                            &selected.owner,
                            &selected.realize.resource_limits,
                        )
                    })
                    .collect::<Vec<_>>(),
                request.world,
            ),
        )?;
        let descriptors = retain(
            &mut bodies,
            &selections
                .iter()
                .map(|selected| &selected.descriptor)
                .collect::<Vec<_>>(),
        )?;
        let contracts = retain(
            &mut bodies,
            &selections
                .iter()
                .map(|selected| {
                    (
                        &selected.binding.compatibility.operating_contract,
                        &selected.exact_facet,
                        &selected.receipt_schema,
                        selected.maximum_operations,
                        selected.maximum_result_bytes,
                        selected.maximum_authorization_bytes,
                        selected.maximum_semantic_bytes,
                    )
                })
                .collect::<Vec<_>>(),
        )?;
        let port_profiles = retain(
            &mut bodies,
            &selections
                .iter()
                .map(|selected| (&selected.descriptor.roles, &selected.descriptor.ports))
                .collect::<Vec<_>>(),
        )?;
        let kernel = measurement::kernel()?;
        let environment = retain(
            &mut bodies,
            &(
                std::env::consts::ARCH,
                std::env::consts::OS,
                &kernel,
                &selections
                    .iter()
                    .map(|selected| &selected.realize.resource_limits)
                    .collect::<Vec<_>>(),
            ),
        )?;
        let harness = retain(
            &mut bodies,
            &measured
                .iter()
                .map(|one| (&one.host, &one.sources))
                .collect::<Vec<_>>(),
        )?;
        let fixtures = retain(
            &mut bodies,
            &(
                &programmes,
                &request.operations,
                &request.horizons,
                request.world,
                &catalog,
                "one actual original activation; three UnixDatagram receivers; 27 original grants; 54 distinct pre/postACK source templates",
            ),
        )?;
        let unit = QualificationUnit {
            implementation,
            realization,
            descriptors,
            contracts,
            port_profiles,
            environment,
            harness,
            fixtures,
            specification,
        };
        let limitations = retain_bytes(&mut bodies, b"Collection only: all382 normative requirements remain required and NotExecuted absent their independent evidence. Fifty-four native cases over one three-owner world cannot issue an ordinary class, Clock, Compute, preservation, replay or input capability. Each original native owner, UnixDatagram receiver, full runtime and durable publisher remains mandatory.".to_vec(), "text/plain")?;
        let classes = classes();
        let mut native: [Vec<PacketNativeCase>; 3] = [Vec::new(), Vec::new(), Vec::new()];
        for cases in &mut native {
            cases.try_reserve_exact(18).map_err(|_| refused())?;
        }
        let mut planned = Vec::new();
        planned.try_reserve_exact(436).map_err(|_| refused())?;
        let mut grants = Vec::new();
        grants.try_reserve_exact(27).map_err(|_| refused())?;
        let mut start = U64::new(0);
        let mut additional = Vec::new();
        additional.try_reserve_exact(54).map_err(|_| refused())?;
        for window in 0..9 {
            let horizon = request.horizons[window];
            if horizon <= start {
                return Err(refused());
            }
            for member in 0..3 {
                let operation = &request.operations[window * 3 + member];
                let permission = OperationRequest::ExactRun {
                    start: Position::new(start, U64::new(0), Phase::BoundaryControl),
                    limit: Position::new(horizon, U64::new(0), Phase::BoundaryControl),
                    boundary_policy: ExactBoundaryPolicy::HorizonPark,
                };
                let before = format!("packet-world-window-{window}-owner-{member}-before-ack");
                let after = format!("packet-world-window-{window}-owner-{member}-after-ack");
                for (case, acknowledged) in [(&before, false), (&after, true)] {
                    let oracle = retain(
                        &mut bodies,
                        &(
                            "packet-world-original-template.v1",
                            case,
                            &selections[member].descriptor.id,
                            operation,
                            &permission,
                            &programmes[member],
                            acknowledged,
                            request.world,
                            "original source-native receipt plus independent UnixDatagram history BEFORE common completion/report",
                        ),
                    )?;
                    planned.push(PlannedWitnessCase {
                        id: case.clone(),
                        kind: CaseKind::RealizedProvider,
                        classes: classes.clone(),
                        oracle: oracle.clone(),
                    });
                    native[member].push(PacketNativeCase {
                        case: case.clone(),
                        oracle,
                        operation: operation.clone(),
                        request: permission.clone(),
                        acknowledged,
                    });
                    additional.push(case.clone());
                }
                grants.push(PacketWorldGrant {
                    operation: operation.clone(),
                    request: permission,
                    horizon,
                    before,
                    after,
                });
            }
            start = horizon;
        }
        additional.sort();
        let mut requirements = BTreeMap::new();
        for id in ids {
            let case = format!("unexecuted-original-{id}");
            let criterion = retain(
                &mut bodies,
                &(
                    "packet-world-full-obligation.v1",
                    id,
                    &catalog,
                    &unit.specification,
                    &unit.implementation,
                    "required original source-native or inspection evidence; no omission",
                ),
            )?;
            let oracle = retain(
                &mut bodies,
                &(
                    "packet-world-unexecuted-oracle.v1",
                    id,
                    &criterion,
                    "NotExecuted; cannot authenticate Passed",
                ),
            )?;
            planned.push(PlannedWitnessCase {
                id: case.clone(),
                kind: CaseKind::RealizedProvider,
                classes: classes.clone(),
                oracle,
            });
            let mut required = vec![case];
            if id == "CN-TEST-025" || id == "CN-TEST-038" {
                required.extend(additional.iter().cloned());
                required.sort();
            }
            requirements.insert(
                id.into(),
                WitnessCriterion::Applicable {
                    cases: required,
                    criterion,
                },
            );
        }
        planned.sort_by(|a, b| a.id.cmp(&b.id));
        let plan = WitnessPlan {
            schema: "crucible.node-witness-plan.v1".into(),
            unit,
            classes,
            requirements,
            cases: planned,
            limitations,
        };
        let schedule = PacketWorldSchedule {
            nodes: [
                selections[0].descriptor.id.clone(),
                selections[1].descriptor.id.clone(),
                selections[2].descriptor.id.clone(),
            ],
            bindings: [
                selections[0].binding.compatibility.identity()?,
                selections[1].binding.compatibility.identity()?,
                selections[2].binding.compatibility.identity()?,
            ],
            grants,
        };
        schedule.validate()?;
        scope::encoded_size(&plan, 1024 * 1024)?;
        let bytes = canonical::canonical_json(
            &serde_json::to_value(&plan).map_err(crucible_node_format::ContractError::from)?,
        )?;
        let reference = retain_bytes(&mut bodies, bytes.clone(), "application/json")?;
        request
            .graph_policy
            .current(&request.sources, request.world, &hash)?;
        Ok(Self {
            plan,
            reference,
            bytes,
            bodies,
            schedule,
            native,
        })
    }

    /// Borrows every normative and source-native case without class authority.
    pub fn plan(&self) -> &WitnessPlan {
        &self.plan
    }

    /// Borrows the exact complete canonical original population body.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Borrows its complete public content identity.
    pub fn reference(&self) -> &ContentRef {
        &self.reference
    }

    /// Borrows all complete independently bound public measurement/oracle objects.
    pub fn bodies(&self) -> &FixtureBodies {
        &self.bodies
    }

    /// Moves the original schedule and installs three native observation oracles.
    ///
    /// The stores must already retain their own receivers and exact full-world
    /// source before Child. This issues neither Accepted nor common Ready.
    ///
    /// # Errors
    /// Refuses unrelated source/template, incomplete stores or native-case credit.
    pub fn into_schedule_and_oracles(
        self,
        stores: [Rc<PacketNativeObservationStore>; 3],
    ) -> Result<(PacketWorldSchedule, [Rc<PacketNativeOracle>; 3]), QualificationError> {
        let [first, second, third] = self.native;
        let [one, two, three] = stores;
        let oracles = [
            PacketNativeOracle::install(one, &self.plan, first)?,
            PacketNativeOracle::install(two, &self.plan, second)?,
            PacketNativeOracle::install(three, &self.plan, third)?,
        ];
        Ok((self.schedule, oracles))
    }
}

fn refused() -> QualificationError {
    QualificationError::Refused("complete measured packet world population unavailable")
}
