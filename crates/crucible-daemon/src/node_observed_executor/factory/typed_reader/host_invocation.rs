//! Installs and invokes one genuine finite typed conformance cohort.
//!
//! Explicit public source pins precede private authorization issuance. The same
//! programme, complete Refused audit and installed source authority then feed
//! the owning session assembly and both actual durable publishers before Child.
//! The caller retains returned failures and the original custody supervisor.

use std::{cell::Cell, path::PathBuf, rc::Rc, sync::Arc, time::Duration};

use crucible::node_admission::AdmissionLimits;
use crucible::node_contract::RuntimeLimits;
use crucible_cas::content_store::{DirectoryBlobBackend, DirectoryRefBackend, RefName};
use crucible_node_contract::{ContentRef, Id, ResourceLimits, canonical};
use crucible_node_provider::handshake::Limits;

use super::super::{NodeObservedError, refused};
use super::{
    InstalledTypedReaderPackage, InstalledTypedReaderSourceFixture, PreparedTypedReaderHostSources,
    StoredTypedReaderResultPublisher, TypedReaderCustodySupervisor, TypedReaderFixtureAudit,
    TypedReaderFixtureLaunchRequest, TypedReaderFixtureLaunches, TypedReaderHostSessionScope,
    TypedReaderHostSourcesExecution, TypedReaderHostSourcesRequest, TypedReaderHostStartFailure,
    TypedReaderProgramme, TypedReaderProgrammePeer, TypedReaderWitnessAuthority,
};
use crate::node_observed_executor::StoredWorldActivationPublisher;
use crate::node_qualification::{QualificationLimits, WitnessPlan};

#[path = "host_invocation/configuration.rs"]
mod configuration;
#[path = "host_invocation/private.rs"]
mod private;

pub use configuration::{SelectedTypedReaderHostSource, SelectedTypedReaderPublicRole};

const LIMITATIONS: &[u8] = b"Finite typed collection; all 382 normative obligations remain required and independently NotExecuted before collection. Nine planned source-authenticated quantized observations are distinct cases and cannot issue an accepted class, Ready, capture or ordinary runtime authority.";

/// Borrows explicit source selection and finite pre-Child collection credits.
pub struct TypedReaderHostInvocationRequest<'a> {
    /// Borrows independently selected public package and complete role pins.
    pub selected: &'a SelectedTypedReaderHostSource,
    /// Declares original per-source native resource ceilings.
    pub resources: ResourceLimits,
    /// Declares original protocol receiving credit.
    pub protocol_limits: Limits,
    /// Declares complete report population and evidence closure ceilings.
    pub qualification_limits: QualificationLimits,
    /// Bounds each original full runtime snapshot and durable result body.
    pub maximum_snapshot_bytes: usize,
}

/// Retains one source-installed fixture and its private original launch custody.
///
/// Installation measures the explicitly selected public assets and actual host
/// before issuing fresh capabilities. Its complete 391-case plan keeps all 382
/// normative obligations required and unexecuted. This object never implements
/// ordinary accepted-class installation and exposes no private launch body.
pub struct InstalledTypedReaderHostInvocation {
    descriptor: PathBuf,
    programme: Rc<TypedReaderProgramme>,
    audit: Rc<TypedReaderFixtureAudit>,
    plan: WitnessPlan,
    plan_bytes: Vec<u8>,
    plan_reference: ContentRef,
    sources: Vec<ContentRef>,
    launches: TypedReaderFixtureLaunches,
    source: Rc<InstalledTypedReaderSourceFixture>,
    authority: Rc<TypedReaderWitnessAuthority>,
    resources: ResourceLimits,
    qualification_limits: QualificationLimits,
    maximum_snapshot_bytes: usize,
    run: Id,
    prepared: Cell<bool>,
}

impl InstalledTypedReaderHostInvocation {
    /// Installs exact selected source, plan and fresh private authorization.
    ///
    /// No participant, socket or writable content store is created here. Public
    /// source files are streamed by the existing installed-artifact measurer.
    /// Private capabilities remain in the original launch/source capsules. Their
    /// bytes and hashes never enter public reports or content retention.
    ///
    /// # Errors
    /// Refuses source pin drift, unsupported credit, unavailable entropy or
    /// current host measurements, incomplete plan/audit or namespace mismatch.
    pub fn install(
        request: TypedReaderHostInvocationRequest<'_>,
    ) -> Result<Self, NodeObservedError> {
        let maximum = request.maximum_snapshot_bytes;
        if maximum == 0 || maximum > 64 * 1024 * 1024 {
            return Err(refused("typed invocation original body credit differs"));
        }
        request.selected.measure()?;
        let package = InstalledTypedReaderPackage::load(
            &request.selected.descriptor,
            &request.selected.package,
        )?;
        request.selected.authenticate_package(&package)?;

        let peers = peers()?;
        let programme = Rc::new(
            TypedReaderProgramme::new(request.selected.package.clone(), peers).map_err(native)?,
        );
        let unit = InstalledTypedReaderSourceFixture::qualification_unit(
            &package,
            &programme,
            &request.resources,
        )
        .map_err(native)?;
        let limitations = canonical::content_ref(LIMITATIONS, "text/plain")?;
        let plan = programme.witness_plan(unit, limitations).map_err(native)?;
        let plan_bytes = super::source_fixture::launch::encode(
            &plan,
            request.qualification_limits.maximum_claim_bytes,
        )
        .map_err(native)?;
        let plan_reference = canonical::content_ref(&plan_bytes, "application/json")?;
        let audit = Rc::new(
            TypedReaderFixtureAudit::prepare(
                &plan,
                &plan_reference,
                request.qualification_limits,
                request.qualification_limits.maximum_claim_bytes,
            )
            .map_err(qualification)?,
        );

        let run = private::fresh_run()?;
        let authorizations = private::authorizations(&programme, &audit, &run)?;
        let launches = TypedReaderFixtureLaunches::prepare(TypedReaderFixtureLaunchRequest {
            package: &package,
            programme: &programme,
            plan: &plan,
            plan_reference: &plan_reference,
            limitations_bytes: LIMITATIONS,
            audit: &audit,
            resources: &request.resources,
            limits: request.protocol_limits,
            authorizations: &authorizations,
        })
        .map_err(native)?;
        let source = Rc::new(
            InstalledTypedReaderSourceFixture::install(
                &request.selected.package,
                &package,
                &programme,
                &plan,
                &plan_reference,
                request.resources.clone(),
                launches.private_launches(),
            )
            .map_err(native)?,
        );
        let mut authority = TypedReaderWitnessAuthority::new(
            &source,
            &audit,
            &programme,
            &plan,
            &plan_reference,
            request.qualification_limits,
            maximum,
        )
        .map_err(qualification)?;
        authority
            .configure_collection_extensions(
                &request.selected.package,
                &request.selected.role("namespace_publication")?.content,
                &request.selected.role("handler")?.content,
            )
            .map_err(|error| NodeObservedError::Native(error.message))?;
        request.selected.authenticate_package(&package)?;
        source
            .authenticate_plan(&plan_reference, &plan_bytes, &plan)
            .map_err(qualification)?;
        let sources = source.collection_source_references().map_err(native)?;

        Ok(Self {
            descriptor: request.selected.descriptor.clone(),
            programme,
            audit,
            plan,
            plan_bytes,
            plan_reference,
            sources,
            launches,
            source,
            authority: Rc::new(authority),
            resources: request.resources,
            qualification_limits: request.qualification_limits,
            maximum_snapshot_bytes: maximum,
            run,
            prepared: Cell::new(false),
        })
    }

    /// Prepares all three original sessions and actual durable publishers once.
    ///
    /// The chosen directories are writable private host custody. Each session
    /// preparer enforces its existing fresh-directory/connection rules. Actual
    /// immutable blobs and mutable references use the same independently chosen
    /// storage root. No native Child exists until the returned owner is started.
    /// A refused attempt remains sticky on this original installation.
    ///
    /// # Errors
    /// Refuses repetition, changed current scope, unsupported runtime credit,
    /// unavailable fresh sessions or nondurable backend preparation.
    pub fn prepare(
        &self,
        private_sessions: PathBuf,
        public_storage: PathBuf,
        session_budget: Duration,
        runtime_limits: RuntimeLimits,
        admission_limits: AdmissionLimits,
    ) -> Result<PreparedTypedReaderHostInvocation<'_>, NodeObservedError> {
        if self.prepared.replace(true) {
            return Err(refused(
                "typed invocation original preparation already attempted",
            ));
        }
        self.authority
            .current_plan(&self.plan_reference)
            .map_err(native)?;
        let blobs = Arc::new(DirectoryBlobBackend::new(
            "typed-conformance-originals",
            public_storage.join("blobs"),
        ));
        let refs = Arc::new(DirectoryRefBackend::new(public_storage.join("refs")));
        let activation = StoredWorldActivationPublisher::new(
            blobs.clone(),
            refs.clone(),
            RefName::new(format!("node-world-activations/conformance-{}", self.run))
                .map_err(storage)?,
        )
        .map_err(storage)?;
        let results = StoredTypedReaderResultPublisher::new(
            Rc::clone(&self.authority),
            self.plan_reference.clone(),
            blobs,
            refs,
            RefName::new(format!("node-world-coordinators/conformance/{}", self.run))
                .map_err(storage)?,
            self.maximum_snapshot_bytes,
        )
        .map_err(storage)?;

        let mut sessions = Vec::new();
        sessions
            .try_reserve_exact(3)
            .map_err(|_| refused("typed invocation session credit"))?;
        for peer in &self.programme.peers {
            let name = format!("{}/{}", self.run, peer.node);
            sessions.push(TypedReaderHostSessionScope {
                directory: private_sessions.join(peer.node.as_str()),
                hello: Id::new(format!("{name}/hello"))?,
                connection: Id::new(format!("{name}/connection"))?,
                discovery: Id::new(format!("{name}/discover"))?,
                realization: Id::new(format!("{name}/realize"))?,
                budget: session_budget,
            });
        }
        let sessions = sessions
            .try_into()
            .map_err(|_| refused("typed invocation session roster"))?;
        let original = PreparedTypedReaderHostSources::prepare(TypedReaderHostSourcesRequest {
            authority: &self.authority,
            source: Rc::clone(&self.source),
            programme: Rc::clone(&self.programme),
            audit: &self.audit,
            plan: &self.plan,
            plan_bytes: &self.plan_bytes,
            plan_reference: &self.plan_reference,
            launches: &self.launches,
            sources: &self.sources,
            descriptor: self.descriptor.clone(),
            sessions,
            resources: self.resources.clone(),
            runtime_limits,
            admission_limits,
            qualification_limits: self.qualification_limits,
            maximum_snapshot_bytes: self.maximum_snapshot_bytes as u64,
        })?;
        Ok(PreparedTypedReaderHostInvocation {
            original,
            activation,
            results,
            maximum: self.maximum_snapshot_bytes,
            failure: Box::new(None),
            start_ready: None,
        })
    }

    /// Borrows the unchanged complete prelaunch plan, including all unknown cases.
    pub fn plan(&self) -> &WitnessPlan {
        &self.plan
    }

    /// Borrows the original public all-NotExecuted Refused audit bytes.
    pub fn audit(&self) -> &TypedReaderFixtureAudit {
        &self.audit
    }
}

/// Retains every original prepared session and both actual durable publishers.
pub struct PreparedTypedReaderHostInvocation<'a> {
    original: Box<PreparedTypedReaderHostSources<'a>>,
    activation: StoredWorldActivationPublisher,
    results: StoredTypedReaderResultPublisher,
    maximum: usize,
    failure: Box<Option<OriginalStartFailure<'a>>>,
    start_ready: Option<bool>,
}

type OriginalStartFailure<'a> = TypedReaderHostStartFailure<
    'a,
    StoredWorldActivationPublisher,
    StoredTypedReaderResultPublisher,
>;

/// Retains the exact original failed start in storage reserved before Child.
///
/// This opaque owner exposes no private launch or incident serialization. Its
/// original failure must remain under containment and authentic supervision.
pub struct TypedReaderHostInvocationFailure<'a> {
    original: Box<Option<OriginalStartFailure<'a>>>,
}

impl<'a> TypedReaderHostInvocationFailure<'a> {
    /// Borrows the original failure without transferring its custody.
    ///
    /// Returned start failures always contain the original owner.
    pub fn original(&self) -> Option<&OriginalStartFailure<'a>> {
        self.original.as_ref().as_ref()
    }

    /// Borrows the same complete original failure for retirement and servicing.
    pub fn original_mut(&mut self) -> Option<&mut OriginalStartFailure<'a>> {
        self.original.as_mut().as_mut()
    }

    /// Transfers the exact original failure for existing containment handling.
    ///
    /// Returned start failures always contain the original owner.
    pub fn into_original(self) -> Option<OriginalStartFailure<'a>> {
        *self.original
    }
}

impl<'a> PreparedTypedReaderHostInvocation<'a> {
    /// Attempts original launch while borrowing this complete owning invocation.
    ///
    /// The enclosing caller keeps profile/session/graph requests and publishers
    /// outside every native callback. The attempt is sticky; a second call
    /// returns the same disposition without redispatching the original launch.
    ///
    /// # Errors
    /// Retains the whole original on launch refusal or callback unwind.
    pub fn instantiate_original(&mut self) -> Result<(), NodeObservedError> {
        if self.start_ready.is_none() {
            let attempted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if self.original.instantiate_original().is_err() {
                    return false;
                }
                self.original.release_unused_adoption();
                true
            }));
            if attempted.is_err() {
                self.original.record_start_unwind();
            }
            self.start_ready = Some(matches!(attempted, Ok(true)));
        }
        if self.start_ready == Some(true) {
            Ok(())
        } else {
            Err(refused("original typed instantiation remains refused"))
        }
    }

    /// Transfers native obligations while retaining all original invocation fields.
    ///
    /// # Errors
    /// Leaves the complete original unresolved when a borrowed handoff refuses.
    pub fn retire_original(&mut self) -> Result<(), crucible_node_provider::ProviderError> {
        self.original.retire_original()
    }

    /// Borrows the authentic prior supervisor before any participant is spawned.
    ///
    /// The caller must retain a clone through cancellation or uncertain failure
    /// and keep polling actual reclamation. An empty queue is not a release proof.
    pub fn supervisor(&self) -> &TypedReaderCustodySupervisor {
        self.original.supervisor()
    }

    /// Launches original peers once and returns their full finite lifecycle actor.
    ///
    /// Success is driven through the actor's poll method, which performs genuine
    /// activation, Stage/Begin/Close, original durable ACK, report collection and
    /// complete supervision. Returned failure retains the same private original
    /// owner and both publishers; it must remain under containment and cleanup.
    ///
    /// # Errors
    /// Returns original launch/Hello/realization/admission/runtime uncertainty
    /// without dropping the owned failure or manufacturing a replacement peer.
    pub fn start(
        mut self,
    ) -> Result<
        TypedReaderHostSourcesExecution<
            'a,
            StoredWorldActivationPublisher,
            StoredTypedReaderResultPublisher,
        >,
        TypedReaderHostInvocationFailure<'a>,
    > {
        // Cached successful preparation has no remaining installed/native
        // callbacks: adoption and native construction were borrowed above.
        let result = if self.instantiate_original().is_err() {
            Err(TypedReaderHostStartFailure {
                original: self.original,
                activation_publisher: self.activation,
                result_publisher: self.results,
            })
        } else {
            self.original
                .into_execution(self.activation, self.results, self.maximum)
        };

        match result {
            Ok(execution) => Ok(execution),
            Err(original) => {
                // Fill the pre-Child holder without allocating on uncertainty.
                *self.failure = Some(original);
                Err(TypedReaderHostInvocationFailure {
                    original: self.failure,
                })
            }
        }
    }
}

fn peers() -> Result<[TypedReaderProgrammePeer; 3], NodeObservedError> {
    let mut peers = Vec::new();
    for name in ["producer-a", "producer-b", "consumer"] {
        peers.push(TypedReaderProgrammePeer {
            node: Id::new(name)?,
            owner: Id::new(format!("typed-fixture/{name}/owner"))?,
            incarnation: Id::new(format!("typed-fixture/{name}/incarnation"))?,
        });
    }
    peers
        .try_into()
        .map_err(|_| refused("typed invocation participant roster"))
}

fn native(error: crucible_node_provider::ProviderError) -> NodeObservedError {
    NodeObservedError::Native(error.to_string())
}

fn qualification(error: crate::node_qualification::QualificationError) -> NodeObservedError {
    NodeObservedError::Native(error.to_string())
}

fn storage(error: crucible_cas::content_store::StoreError) -> NodeObservedError {
    NodeObservedError::Native(error.to_string())
}
