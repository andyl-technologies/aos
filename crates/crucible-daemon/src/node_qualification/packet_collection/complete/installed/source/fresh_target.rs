//! Installs an explicit fresh target from real retained archive tickets.
//!
//! This operator path reuses the existing measured constructors and namespace
//! rules. It restores the Host from its actual ticket and registers the genuine
//! prebirth capsule before any native startup action. It never creates an
//! OriginalScene, changes a backend key, or interprets manifest DATA as a grant.

#[path = "fresh_target/host_setup17.rs"]
mod host_setup17;
pub(in crate::node_qualification::packet_collection::complete) use host_setup17::HostSource17SetupBorrow;

use super::*;
use crate::node_qualification::packet_collection::complete::PacketCompleteRestorationPrebirth;
use crucible::node_admission::InstalledConformancePlan;
use crucible::node_contract::RuntimePollFailure;
use crucible::node_scheduling::ValidatedSchedulingObservation;
use crucible_cas::content_store::{DirectoryBlobBackend, DirectoryRefBackend};
use std::{cell::RefCell, sync::Arc};

/// Retains the actual fresh registered holder and its original ticket capsule.
///
/// Baseline transport, graph binding and inactive runtime preparation use the
/// existing owning APIs through these same concrete originals. This type has
/// no decoder and creates no Ready, activation, operation or native permission.
#[must_use = "retain actual fresh tickets and partial native owners through cleanup"]
pub struct InstalledCompleteRestoration {
    original: Rc<RefCell<PacketCompleteReportStartupHolder>>,
    prebirth: Rc<RefCell<PacketCompleteRestorationPrebirth>>,
    authority: Rc<InstalledPacketCompleteCollectionAuthority>,
    plan: Rc<InstalledConformancePlan>,
    runtime_limits: RuntimeLimits,
    write_watchdog: Duration,
    _code_owners: Option<prepared::CodeOwners>,
}

impl InstalledCompleteRestoration {
    /// Installs a suffix-selected target around the caller's real source tickets.
    ///
    /// The output retains the registered holder before fallible preparation
    /// reservation. The caller keeps the incoming prebirth Rc outside unwind
    /// guards; ticketed Host construction remains sticky even on early refusal.
    /// An original-scene package cannot implicitly choose this fresh family.
    ///
    /// # Errors
    /// Refuses occupied output, another manifest edition, changed measured files,
    /// incompatible saved selection, foreign/spent tickets, namespace conflicts,
    /// graph mismatch or any original resource/preparation gate.
    pub fn install_into(
        manifest: InstalledCompleteSceneManifest,
        directory: PathBuf,
        prebirth: Rc<RefCell<PacketCompleteRestorationPrebirth>>,
        output: &mut Option<Self>,
    ) -> Result<(), QualificationError> {
        if output.is_some() {
            return Err(refused());
        }

        if prebirth
            .try_borrow()
            .map_err(|_| refused())?
            .host_requires_restored_settled_construction_data()
            .map_err(|_| refused())?
        {
            return Self::install_restored_settled_into(manifest, directory, prebirth, output);
        }

        let selected = super::super::manifest::load(&manifest)?;
        if !matches!(
            selected.schema.as_str(),
            "crucible.complete-scene.installation/6" | "crucible.complete-scene.installation/7"
        ) {
            return Err(refused());
        }

        let measurements = selected.measurements.map(|one| PacketFixtureMeasurements {
            peer: artifact(one.peer),
            host: one.host,
            sources: one.sources.into_iter().map(artifact).collect(),
        });
        for measurement in &measurements {
            measurement.authenticate()?;
        }

        let content = super::super::manifest::content(selected.content)?;

        prebirth
            .try_borrow_mut()
            .map_err(|_| refused())?
            .prepare_original_host(selected.host)
            .map_err(|_| refused())?;
        let host = prebirth
            .try_borrow()
            .map_err(|_| refused())?
            .original_host_source()
            .map_err(|_| refused())?;
        if host.world() != &selected.world.identity()? {
            return Err(refused());
        }

        let initial_bytes = encoded(&selected.coordinator)?;
        let initial = InstalledContent {
            reference: canonical::content_ref(&initial_bytes, "application/json")?,
            bytes: Bytes::new(initial_bytes),
        };

        let (sources, declarations) = if selected.schema == "crucible.complete-scene.installation/7"
        {
            prepare_restored_settled_sources(
                selected.participants,
                &selected.coordinator,
                selected.maximum_native_rows,
                selected.maximum_initial_bytes,
                selected.mechanism,
                selected.maximum_coordinator_records.ok_or_else(refused)?,
                &content,
            )?
        } else {
            prepare_sources(
                selected.participants,
                &selected.coordinator,
                selected.maximum_native_rows,
                selected.maximum_initial_bytes,
                selected.mechanism,
                true,
                true,
                true,
                true,
                &content,
            )?
        };

        let mut namespace = Namespace::create(directory)?;
        let directories = namespace.peer_directories()?;
        let paths: [PathBuf; 3] =
            std::array::from_fn(|member| namespace.path.join(format!("effect-{member}.sock")));
        let receivers = paths
            .each_ref()
            .map(|path| UnixDatagram::bind(path).map_err(|_| refused()));
        let [a, b, c] = receivers;
        let (group, reader) =
            PacketCompleteEffectReceiverGroup::from_original_receivers([a?, b?, c?]);

        let launches = launch_declarations(
            declarations,
            &selected.coordinator,
            &initial,
            &measurements,
            &paths,
        )?;
        let sources = ready_sources(
            sources,
            &launches,
            &group,
            &paths,
            selected.maximum_initial_bytes,
        )?;

        let roster = PacketCompleteRoster::new(sources, &selected.coordinator)?;
        let graph_owner = PacketCompleteGraphOwner::install(PacketCompleteGraphRequest {
            roster: roster.clone(),
            host: Rc::clone(&host),
            measurements: measurements.each_ref(),
            world: &selected.world,
            requirements: &selected.requirements,
            content: &content,
            coordinator: &selected.coordinator,
        })?;

        let authority =
            InstalledPacketCompleteCollectionAuthority::install(PacketCompleteCollectionRequest {
                roster,
                host,
                graph_policy: graph_owner.graph_policy()?,
                world: &selected.world,
                requirements: &selected.requirements,
                content: &content,
                coordinator: &selected.coordinator,
                launches,
                directories,
                limits: QualificationLimits::default(),
                maximum_audit_bytes: 8 * 1024 * 1024,
            })?;

        let plan = Rc::new(authority.collection_plan().map_err(|_| refused())?);
        let original = PacketCompleteReportStartupHolder::install_fresh_restoration(
            graph_owner,
            Rc::clone(&authority),
            Rc::clone(&plan),
            selected.resources,
            Rc::clone(&prebirth),
            group,
            reader,
        )?;

        // Once registered, neither later refusal nor namespace Drop may discard
        // this target. Every surviving owner is reachable through output.
        namespace.retained = true;
        *output = Some(Self {
            original,
            prebirth,
            authority,
            plan,
            runtime_limits: RuntimeLimits {
                maximum_nodes: 4,
                maximum_owners: 4,
                maximum_operations: selected.maximum_operations,
                maximum_retained_outputs: selected.maximum_retained_outputs,
            },
            write_watchdog: Duration::from_millis(selected.write_watchdog_ms),
            _code_owners: None,
        });

        let owner = output.as_ref().ok_or_else(refused)?;
        let content = Rc::new(content);
        let mut banks = Some([Rc::clone(&content), Rc::clone(&content), content]);
        PacketCompleteReportStartupHolder::retain_fresh_installation_content_into(
            &owner.original,
            &mut banks,
        )
        .map_err(|_| refused())?;

        PacketCompleteReportStartupHolder::reserve_original_preparation_supervisors(&owner.original)
    }

    /// Borrows the actual registered holder without reconstructing authority.
    pub fn holder(&self) -> &Rc<RefCell<PacketCompleteReportStartupHolder>> {
        &self.original
    }

    /// Borrows the same caller-retained source ticket capsule.
    pub fn prebirth(&self) -> &Rc<RefCell<PacketCompleteRestorationPrebirth>> {
        &self.prebirth
    }

    /// Borrows the newly installed measured target authority.
    pub fn authority(&self) -> &Rc<InstalledPacketCompleteCollectionAuthority> {
        &self.authority
    }

    /// Borrows the plan issued by this exact target authority.
    pub fn plan(&self) -> &Rc<InstalledConformancePlan> {
        &self.plan
    }

    /// Borrows the exact operator-selected runtime limits for target preparation.
    pub fn runtime_limits(&self) -> &RuntimeLimits {
        &self.runtime_limits
    }

    /// Returns the original bounded native bootstrap writer deadline.
    pub fn write_watchdog(&self) -> Duration {
        self.write_watchdog
    }

    /// Runs the real complete restoration and returns a fresh scheduling Observe.
    ///
    /// The caller first finishes the existing native/baseline/HOST transactions,
    /// binds the real target graph and constructs its inactive original runtime.
    /// This forwarding call neither constructs those premises nor retries them.
    ///
    /// # Errors
    /// Refuses incomplete original preparation, foreign/stale owners, exhausted
    /// policy, failed durable publication or real native proof/ACK failures.
    pub fn restore_and_observe(
        &self,
        activation: &ActivationRecord,
        prepare_ids: &mut Option<[Id; 3]>,
        commit_ids: &mut Option<[Id; 3]>,
        publisher: &mut Option<crate::node_observed_executor::StoredWorldActivationPublisher>,
        blobs: Arc<DirectoryBlobBackend>,
        refs: Arc<DirectoryRefBackend>,
        node: &Id,
    ) -> Result<ValidatedSchedulingObservation, RuntimePollFailure> {
        PacketCompleteReportStartupHolder::execute_original_complete_restoration_and_observe(
            &self.original,
            activation,
            prepare_ids,
            commit_ids,
            publisher,
            blobs,
            refs,
            node,
        )
    }

    /// Names the fixed operator owner and its actual constructor/borrow views.
    pub fn counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<Self>()
            + size_of::<Option<Self>>()
            + size_of::<&Self>()
            + size_of::<&mut Option<Self>>()
            + size_of::<Rc<RefCell<PacketCompleteReportStartupHolder>>>()
            + size_of::<Rc<RefCell<PacketCompleteRestorationPrebirth>>>()
            + size_of::<std::cell::Ref<'static, PacketCompleteRestorationPrebirth>>()
            + size_of::<std::cell::RefMut<'static, PacketCompleteRestorationPrebirth>>()
            + size_of::<
                Result<
                    std::cell::Ref<'static, PacketCompleteRestorationPrebirth>,
                    std::cell::BorrowError,
                >,
            >()
            + size_of::<
                Result<
                    std::cell::RefMut<'static, PacketCompleteRestorationPrebirth>,
                    std::cell::BorrowMutError,
                >,
            >()
            + size_of::<
                Result<
                    std::cell::Ref<'static, PacketCompleteRestorationPrebirth>,
                    QualificationError,
                >,
            >()
            + size_of::<
                Result<
                    std::cell::RefMut<'static, PacketCompleteRestorationPrebirth>,
                    QualificationError,
                >,
            >()
            + size_of::<
                Result<
                    Rc<crucible::node_contract::HostSchedulingSource>,
                    crucible::node_state::StateError,
                >,
            >()
            + size_of::<Result<Rc<crucible::node_contract::HostSchedulingSource>, QualificationError>>(
            )
            + size_of::<Result<(), crucible::node_state::StateError>>()
            + size_of::<Result<&'static Self, QualificationError>>()
            + size_of::<Option<&'static Self>>()
            + size_of::<Result<(), QualificationError>>()
            + size_of::<Result<ValidatedSchedulingObservation, RuntimePollFailure>>()
    }
}

#[path = "fresh_target/prepared.rs"]
mod prepared;
pub use prepared::PreparedCompleteRestoration;

#[path = "fresh_target/restored_host17.rs"]
mod restored_host17;
