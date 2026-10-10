//! Assembles original typed sessions, collection graph and runtime custody.
//!
//! Every session, incident holder and complete seven-slot cohort is prepared
//! before Child. Each source is launched and realized once. Refusal retains the
//! same capsule; private Hello and incident material never enters public reports.

use std::{
    path::PathBuf,
    rc::Rc,
    task::{Context, Poll},
    time::Duration,
};

use crucible::{
    node_adapters::cnp::LineageControlledReference,
    node_admission::{
        AdmissionLimits, AdmissionRequest, ConformanceAdmissionAuthority, ConformanceGraph,
        ConformancePlanEvidence, InstalledConformancePlan, admit_conformance_graph,
    },
    node_contract::{
        ActivationPublisher, ActivationRecord, ConformanceResultPublisher, ConformanceRuntime,
        ConformanceRuntimeFailure, OperationFailure, OwnerIdentity, PreparedRealization,
        RuntimeLimits, SimulationNode,
    },
};
use crucible_node_contract::{
    ContentRef, Id, NodeBinding, OwnerBinding, Phase, Position, ResourceLimits, U64,
};
use crucible_node_provider::{
    ProviderError,
    connection::{BodySchemaVerifier, ConnectionSupervisor},
};

use super::super::{NodeObservedError, refused};
use super::{
    InstalledTypedReaderConfiguration, InstalledTypedReaderFixtureAuthority,
    InstalledTypedReaderOwningPolicy, InstalledTypedReaderSourceFixture, PreparedTypedReaderCohort,
    PreparedTypedReaderHostCollection, PreparedTypedReaderSession,
    ReclaimedTypedReaderHostCollection, TypedReaderCustodySupervisor, TypedReaderFixtureAudit,
    TypedReaderFixtureLaunches, TypedReaderHostExecution, TypedReaderHostPreparationRequest,
    TypedReaderHostServices, TypedReaderProgramme, TypedReaderSessionFailure,
    TypedReaderSessionLaunchFailure, TypedReaderSessionRequest, TypedReaderSourceHandshake,
    TypedReaderWitnessAuthority,
};
use crate::node_qualification::{QualificationLimits, WitnessPlan};

/// Fixes one source's original transport identities before any participant exists.
pub struct TypedReaderHostSessionScope {
    /// Names a fresh private original socket directory.
    pub directory: PathBuf,
    /// Names the original Hello.
    pub hello: Id,
    /// Names the original Connection registration.
    pub connection: Id,
    /// Names the original Discover request.
    pub discovery: Id,
    /// Names the original Realize request.
    pub realization: Id,
    /// Bounds that same source's bootstrap, connection and Hello together.
    pub budget: Duration,
}

/// Borrows independently installed originals for complete pre-Child assembly.
pub struct TypedReaderHostSourcesRequest<'a> {
    /// Borrows the same shared authority used by graph, sources and host reports.
    pub authority: &'a Rc<TypedReaderWitnessAuthority>,
    /// Retains the independently installed actual source fixture.
    pub source: Rc<InstalledTypedReaderSourceFixture>,
    /// Retains the identical predeclared finite programme.
    pub programme: Rc<TypedReaderProgramme>,
    /// Borrows the original full Refused audit.
    pub audit: &'a TypedReaderFixtureAudit,
    /// Borrows the canonical complete plan data.
    pub plan: &'a WitnessPlan,
    /// Borrows the exact full plan bytes.
    pub plan_bytes: &'a [u8],
    /// Pins those original plan bytes.
    pub plan_reference: &'a ContentRef,
    /// Borrows the original private issued launch bodies; no secret is exported.
    pub launches: &'a TypedReaderFixtureLaunches,
    /// Borrows the complete independently selected source prerequisite roster.
    pub sources: &'a [ContentRef],
    /// Names the measured source descriptor already authenticated by installation.
    pub descriptor: PathBuf,
    /// Supplies three distinct original socket and request scopes.
    pub sessions: [TypedReaderHostSessionScope; 3],
    /// Supplies original native resource credit.
    pub resources: ResourceLimits,
    /// Bounds the complete common runtime reservation.
    pub runtime_limits: RuntimeLimits,
    /// Bounds admission of the actual realized complete graph.
    pub admission_limits: AdmissionLimits,
    /// Bounds all planned report rows before Child.
    pub qualification_limits: QualificationLimits,
    /// Bounds each complete original completion snapshot.
    pub maximum_snapshot_bytes: u64,
}

/// Retains the same private SDK owner after one original assembly failure.
///
/// These capsules can contain private Hello credentials and raw journals. They
/// are local custody only and must never be serialized, hashed or published.
pub enum TypedReaderHostSourceFailure {
    /// Retains original launch custody and its prepared session.
    Launch(Box<TypedReaderSessionLaunchFailure<TypedReaderSourceHandshake>>),
    /// Retains the same Hello, controller or attached source adoption failure.
    Realize(Box<TypedReaderSessionFailure<TypedReaderSourceHandshake>>),
    /// Retains failed collection runtime construction and its original world slot.
    Runtime(ConformanceRuntimeFailure),
    /// Retains the original effect knowledge after native node installation refuses.
    Node(OperationFailure),
}

/// Owns all preallocated host services and original source preparation.
///
/// The caller retains this owner and its authentic supervisor after refusal.
/// Its private failure field retains actual SDK owners; a sticky refusal never
/// starts a replacement Child or substitutes a missing realization.
pub struct PreparedTypedReaderHostSources<'a> {
    authority: &'a Rc<TypedReaderWitnessAuthority>,
    launches: &'a TypedReaderFixtureLaunches,
    _source: Rc<InstalledTypedReaderSourceFixture>,
    cohort: PreparedTypedReaderCohort,
    supervisor: TypedReaderCustodySupervisor,
    adoption: Option<super::custody::TypedReaderAdoptionSlot>,
    host: Option<PreparedTypedReaderHostCollection<'a>>,
    _services: Vec<TypedReaderHostServices>,
    prepared: Vec<Option<PreparedTypedReaderSession<TypedReaderSourceHandshake>>>,
    originals: Vec<Option<LineageControlledReference>>,
    nodes: Vec<Box<dyn SimulationNode>>,
    bindings: Vec<NodeBinding>,
    owners: Vec<OwnerBinding>,
    plan: InstalledConformancePlan,
    graph: Option<ConformanceGraph>,
    target: ActivationRecord,
    runtime_limits: RuntimeLimits,
    admission_limits: AdmissionLimits,
    runtime: Option<ConformanceRuntime>,
    failure: Option<TypedReaderHostSourceFailure>,
    refusal: Option<NodeObservedError>,
    attempted: bool,
}

impl<'a> PreparedTypedReaderHostSources<'a> {
    /// Prepares every source session, report slot and custody slot before Child.
    ///
    /// # Errors
    /// Refuses substituted installation/programme/world/plan, missing current
    /// source or registry authority, invalid private scopes or exhausted credit.
    /// No Child exists; the caller still owns its borrowed private originals.
    pub fn prepare(
        request: TypedReaderHostSourcesRequest<'a>,
    ) -> Result<Box<Self>, NodeObservedError> {
        if !std::ptr::eq(request.authority.source(), request.source.as_ref())
            || !std::ptr::eq(request.authority.programme(), request.programme.as_ref())
            || request.launches.world().world() != request.source.collection_world().world()
        {
            return Err(refused("typed host original installation or world differs"));
        }
        for (index, session) in request.sessions.iter().enumerate() {
            if request.sessions[..index].iter().any(|prior| {
                prior.directory == session.directory || prior.connection == session.connection
            }) {
                return Err(refused(
                    "typed host original source transport scopes overlap",
                ));
            }
        }

        request
            .authority
            .current_plan(request.plan_reference)
            .map_err(native)?;
        super::programme::count(&(request.plan, request.sources), 8 * 1024 * 1024)
            .map_err(native)?;

        let world = request.launches.world();
        let world_hash = world.world().identity()?;
        let mut identities: Vec<_> = request
            .programme
            .peers
            .iter()
            .map(|peer| OwnerIdentity {
                owner: peer.owner.clone(),
                incarnation: peer.incarnation.clone(),
                generation: U64::new(1),
            })
            .collect();
        identities.sort();

        let target = ActivationRecord {
            generation: U64::new(1),
            activation_id: request.launches.private_launches()[0]
                .bootstrap
                .activation_id
                .clone(),
            world_binding_hash: world_hash.clone(),
            owners: identities,
            boundary: Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl),
        };

        let plan = InstalledConformancePlan::install(
            ConformancePlanEvidence {
                plan_ref: request.plan_reference,
                plan_bytes: request.plan_bytes,
                refused_ref: request.audit.claim(),
                refused_bytes: request.audit.original_bytes(),
                world: &world_hash,
                sources: request.sources,
            },
            Rc::clone(request.authority) as Rc<dyn ConformanceAdmissionAuthority>,
        )
        .map_err(|error| NodeObservedError::Native(error.message))?;

        let host = PreparedTypedReaderHostCollection::prepare(TypedReaderHostPreparationRequest {
            authority: request.authority,
            programme: Rc::clone(&request.programme),
            node: request.programme.peers[0].node.clone(),
            plan_bytes: request.plan_bytes,
            plan: request.plan_reference,
            limits: request.qualification_limits,
            maximum_snapshot_bytes: request.maximum_snapshot_bytes,
        })
        .map_err(|error| NodeObservedError::Native(error.to_string()))?;

        let policy = Rc::new(InstalledTypedReaderOwningPolicy::for_conformance(
            request.source.package().identity().clone(),
            request
                .authority
                .collection_registry()
                .map_err(|error| NodeObservedError::Native(error.message))?,
            Some(Rc::clone(request.authority) as Rc<dyn InstalledTypedReaderFixtureAuthority>),
            request.resources,
        )?);
        let configurations = std::array::from_fn(|index| {
            let peer = &request.programme.peers[index];
            InstalledTypedReaderConfiguration {
                node: peer.node.clone(),
                owner: peer.owner.clone(),
                quantum_ps: U64::new(1000),
                host_budget_ns: U64::new(1_000_000_000),
                closed_ingress: index < 2,
                maximum_operations: 64,
            }
        });

        let cohort = PreparedTypedReaderCohort::prepare(
            policy,
            request.descriptor,
            configurations,
            target.clone(),
            request.runtime_limits,
        )?;
        let supervisor = cohort.supervisor().clone();
        let adoption = supervisor.reserve_adoption()?;

        let mut services = reserved()?;
        let mut prepared = reserved()?;
        let mut originals = reserved()?;
        let nodes = reserved()?;
        let mut bindings = reserved()?;
        let mut owners = reserved()?;

        for (index, scope) in request.sessions.into_iter().enumerate() {
            let original = &request.launches.private_launches()[index];
            super::owning::count_launch(original, 16 * 1024 * 1024).map_err(native)?;
            let service = TypedReaderHostServices::prepare(
                &request.source,
                request.plan_reference,
                original,
                scope.connection.clone(),
            )
            .map_err(native)?;
            let source = request
                .source
                .source(&original.bootstrap.node_id)
                .map_err(native)?;
            let (binding, owner) = source
                .profile
                .bind_qualified(
                    original.bootstrap.authority.clone(),
                    &original.qualification_refs,
                )
                .map_err(native)?;
            bindings.push(binding);
            owners.push(owner);

            let session = cohort
                .prepare_session(TypedReaderSessionRequest {
                    launch: original.clone(),
                    directory: scope.directory,
                    hello: scope.hello,
                    connection: scope.connection,
                    discovery: scope.discovery,
                    realization: scope.realization,
                    verifier: Box::new(
                        request
                            .source
                            .handshake(&original.bootstrap.node_id)
                            .map_err(native)?,
                    ),
                    supervisor: Rc::clone(&service.incidents) as Rc<dyn ConnectionSupervisor>,
                    schemas: Rc::clone(&service.schemas) as Rc<dyn BodySchemaVerifier>,
                    budget: scope.budget,
                })
                .map_err(|failure| failure.error)?;
            services.push(service);
            prepared.push(Some(session));
            originals.push(None);
        }

        bindings
            .sort_by(|left, right| left.compatibility.node_id.cmp(&right.compatibility.node_id));
        owners.sort_by(|left, right| left.owner.id.cmp(&right.owner.id));
        request
            .authority
            .current_plan(request.plan_reference)
            .map_err(native)?;

        Ok(Box::new(Self {
            authority: request.authority,
            launches: request.launches,
            _source: request.source,
            cohort,
            supervisor,
            adoption: Some(adoption),
            host: Some(host),
            _services: services,
            prepared,
            originals,
            nodes,
            bindings,
            owners,
            plan,
            graph: None,
            target,
            runtime_limits: request.runtime_limits,
            admission_limits: request.admission_limits,
            runtime: None,
            failure: None,
            refusal: None,
            attempted: false,
        }))
    }

    /// Borrows the actual prior custody actor for cancellation or uncertain failure.
    pub fn supervisor(&self) -> &TypedReaderCustodySupervisor {
        &self.supervisor
    }

    /// Borrows the first refusal without removing its original private owner.
    pub fn refusal(&self) -> Option<&NodeObservedError> {
        self.refusal.as_ref()
    }

    /// Borrows the original private failed capsule without fabricating reclamation.
    pub fn failure(&self) -> Option<&TypedReaderHostSourceFailure> {
        self.failure.as_ref()
    }

    /// Services the actual pre-realization failure without removing its journals.
    ///
    /// A true result applies only to this original failed Hello/controller or
    /// launch guard. Other realized sources and the world still have their own
    /// retained cleanup obligations. It is not whole-cohort reclamation.
    ///
    /// # Errors
    /// Refuses unavailable or attached runtime retirement and retains the same
    /// failed owner on unresolved native cleanup or an operational error.
    pub fn poll_failed_preparation(&mut self) -> Result<bool, ProviderError> {
        match self.failure.as_mut() {
            Some(TypedReaderHostSourceFailure::Realize(original)) => {
                original.poll_preparation_reclamation()
            }
            Some(TypedReaderHostSourceFailure::Launch(original)) => match &mut original.launch {
                super::TypedReaderLaunchError::Original(original) => match &mut original.guard {
                    Some(guard) => guard.poll_reclamation(),
                    None => Err(ProviderError::Correlation(
                        "failed launch has no original native guard",
                    )),
                },
                super::TypedReaderLaunchError::NoRemainingReservation(_) => Err(
                    ProviderError::Correlation("original launch reservation refused"),
                ),
            },
            Some(TypedReaderHostSourceFailure::Runtime(_))
            | Some(TypedReaderHostSourceFailure::Node(_))
            | None => Err(ProviderError::Correlation(
                "original attached custody requires runtime retirement",
            )),
        }
    }

    /// Transfers the original ready-to-collect owner to the finite host actor.
    ///
    /// Success retains this same source/service capsule beside the actor until
    /// authentic runtime reclamation. No private incident material is exported.
    ///
    /// # Errors
    /// Returns every supplied original on incomplete or refused assembly. No
    /// publisher callback, native effect or replacement runtime occurs here.
    pub fn into_execution<A: ActivationPublisher, R: ConformanceResultPublisher>(
        mut self: Box<Self>,
        activation_publisher: A,
        result_publisher: R,
        maximum_initial_record_bytes: usize,
    ) -> Result<TypedReaderHostSourcesExecution<'a, A, R>, TypedReaderHostStartFailure<'a, A, R>>
    {
        if self.refusal.is_some() || self.failure.is_some() {
            return Err(TypedReaderHostStartFailure {
                original: self,
                activation_publisher,
                result_publisher,
            });
        }
        let (host, runtime) = match (self.host.take(), self.runtime.take()) {
            (Some(host), Some(runtime)) => (host, runtime),
            (host, runtime) => {
                self.host = host;
                self.runtime = runtime;
                return Err(TypedReaderHostStartFailure {
                    original: self,
                    activation_publisher,
                    result_publisher,
                });
            }
        };
        // Complete assembly has no failed attachment. Release its unused
        // journal slot before lifecycle cleanup begins, avoiding a false hold.
        drop(self.adoption.take());
        let execution = host.start(
            runtime,
            self.supervisor.clone(),
            activation_publisher,
            result_publisher,
            maximum_initial_record_bytes,
        );
        Ok(TypedReaderHostSourcesExecution {
            execution,
            original: Some(self),
        })
    }

    /// Launches and realizes each source once, then admits their actual runtime.
    ///
    /// The caller must keep this owner on error. Completed source adoption is
    /// retained in place while subsequent failures retain their own original
    /// SDK capsules. No preparation or native request is retried.
    ///
    /// # Errors
    /// Refuses repetition or changed current scope and retains actual launch,
    /// Hello, registrar, realization, graph or runtime preparation uncertainty.
    pub fn instantiate_original(&mut self) -> Result<(), &NodeObservedError> {
        if !self.attempted {
            self.attempted = true;
            if let Err(original) = self.instantiate() {
                self.refusal = Some(original);
            }
        } else if self.refusal.is_none() {
            self.refusal = Some(refused("typed host original cohort already attempted"));
        }
        match &self.refusal {
            Some(original) => Err(original),
            None => Ok(()),
        }
    }

    fn instantiate(&mut self) -> Result<(), NodeObservedError> {
        self.authority
            .current_plan(self.plan.evidence().plan_ref)
            .map_err(native)?;
        self.plan
            .reauthenticate()
            .map_err(|error| NodeObservedError::Native(error.message))?;
        for index in 0..3 {
            let prepared = self.prepared[index]
                .take()
                .ok_or_else(|| refused("typed host original session unavailable"))?;
            let launched = match self.cohort.launch_session(prepared) {
                Ok(original) => original,
                Err(original) => {
                    self.failure = Some(TypedReaderHostSourceFailure::Launch(original));
                    return Err(refused("typed host original launch refused"));
                }
            };
            match launched.realize_original() {
                Ok(original) => self.originals[index] = Some(original),
                Err(original) => {
                    self.failure = Some(TypedReaderHostSourceFailure::Realize(original));
                    return Err(refused("typed host original realization refused"));
                }
            }
        }
        let world = self.launches.world();
        self.graph = Some(
            admit_conformance_graph(
                AdmissionRequest {
                    world: world.world(),
                    descriptors: &world.descriptors,
                    bindings: &self.bindings,
                    owners: &self.owners,
                    requirements: &world.requirements,
                },
                &self.plan,
                self.admission_limits,
            )
            .map_err(|error| NodeObservedError::Native(error.to_string()))?,
        );
        let graph = self
            .graph
            .as_ref()
            .ok_or_else(|| refused("typed host graph unavailable"))?;
        for index in 0..3 {
            let original = self.originals[index]
                .take()
                .ok_or_else(|| refused("typed host original realized owner unavailable"))?;
            let node = &self.launches.private_launches()[index].bootstrap.node_id;
            match original.into_conformance_node(graph, node, 64) {
                Ok(original) => self.nodes.push(Box::new(original)),
                Err(original) => {
                    self.failure = Some(TypedReaderHostSourceFailure::Node(original));
                    return Err(refused("typed host original node installation refused"));
                }
            }
        }
        let slot = self.cohort.take_world_slot()?;
        let prepared = PreparedRealization::new(
            std::mem::take(&mut self.nodes),
            self.target.clone(),
            self.runtime_limits,
            slot,
        );
        let graph = self
            .graph
            .take()
            .ok_or_else(|| refused("typed host graph already transferred"))?;
        match ConformanceRuntime::from_prepared_quantized(graph, prepared) {
            Ok(original) => self.runtime = Some(original),
            Err(original) => {
                self.failure = Some(TypedReaderHostSourceFailure::Runtime(original));
                return Err(refused(
                    "typed host original runtime retained after refusal",
                ));
            }
        }
        Ok(())
    }
}

impl Drop for PreparedTypedReaderHostSources<'_> {
    fn drop(&mut self) {
        let Some(TypedReaderHostSourceFailure::Realize(original)) = self.failure.take() else {
            return;
        };
        if let super::TypedReaderSessionFailure::Adoption(original) = *original {
            if let Some(slot) = self.adoption.take() {
                slot.retain(original);
            }
        } else {
            // Hello/controller failures retain their private SDK originals until
            // their existing guard Drop transfers the actual source capsule.
            self.failure = Some(TypedReaderHostSourceFailure::Realize(original));
        }
    }
}

/// Returns supplied publishers beside the same incomplete original capsule.
pub struct TypedReaderHostStartFailure<'a, A, R> {
    /// Retains all source/session/report/preparation failure custody.
    pub original: Box<PreparedTypedReaderHostSources<'a>>,
    /// Retains the unchanged original activation publisher.
    pub activation_publisher: A,
    /// Retains the unchanged original result publisher.
    pub result_publisher: R,
}

/// Holds the real finite actor beside all private original host services.
pub struct TypedReaderHostSourcesExecution<'a, A, R> {
    execution: TypedReaderHostExecution<'a, A, R>,
    original: Option<Box<PreparedTypedReaderHostSources<'a>>>,
}

/// Returns authentic reclaimed collection and its private source custody together.
///
/// This record is deliberately not serializable. The report member contains
/// only the selected public witness data; incident/Hello originals stay private.
pub struct ReclaimedTypedReaderHostSources<'a, A, R> {
    /// Retains the complete original report and both durable publisher journals.
    pub collection: ReclaimedTypedReaderHostCollection<A, R>,
    /// Retains the same host incidents and source preparation metadata privately.
    pub original: Box<PreparedTypedReaderHostSources<'a>>,
}

impl<'a, A: ActivationPublisher, R: ConformanceResultPublisher>
    TypedReaderHostSourcesExecution<'a, A, R>
{
    /// Borrows the same custody actor for cancellation and outstanding cleanup.
    pub fn supervisor(&self) -> &TypedReaderCustodySupervisor {
        self.execution.supervisor()
    }

    /// Advances the actual actor and retains private services through reclamation.
    ///
    /// This forwards original Pending unchanged. After yielding once, subsequent
    /// polls have no effects. No missing mailbox or numeric PID proves cleanup.
    pub fn poll(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<ReclaimedTypedReaderHostSources<'a, A, R>> {
        if self.original.is_none() {
            return Poll::Pending;
        }
        let collection = match self.execution.poll(context) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(original) => original,
        };
        let Some(original) = self.original.take() else {
            return Poll::Pending;
        };
        Poll::Ready(ReclaimedTypedReaderHostSources {
            collection,
            original,
        })
    }
}

fn reserved<T>() -> Result<Vec<T>, NodeObservedError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(3)
        .map_err(|_| refused("typed host complete source holder credit"))?;
    Ok(values)
}

fn native(error: ProviderError) -> NodeObservedError {
    NodeObservedError::Native(error.to_string())
}
