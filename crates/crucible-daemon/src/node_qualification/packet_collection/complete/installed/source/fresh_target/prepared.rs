//! Shares immutable target launch DATA between code validation and fresh birth.
//!
//! The operator prepares one namespace, launch-token/path tuple and complete
//! selection before any archive ticket is issued. Historical code validation
//! uses distinct neverborn Sources and a real code Host owner. Fresh installation
//! later uses new Sources and the actual ticketed Host with those same DATA.
//! Plan equality never replaces the distinct authorities or original tickets.

use super::*;
use crate::node_qualification::packet_collection::complete::PacketCompleteArchiveCodeFactory;
use crucible::node_adapters::cnp::PacketCompleteEffectReceiverReader;
use crucible::node_admission::{AdmissionLimits, AdmissionRequest, CompleteArchiveCodeGraph};
use crucible::node_contract::{HostSchedulingContinuationLimits, HostSchedulingSource};
use crucible::node_state::{NativeArchiveLimits, NativeArchiveRecord};
use std::collections::BTreeMap;

/// Keeps the neverborn code policy and actual unattached Host alive.
///
/// Their underlying metadata remains reachable through the capsule's code
/// factory. These original owning wrappers prevent revision revocation; they
/// are moved to the target before its first fallible preparation reservation.
pub(super) struct CodeOwners {
    _graph: PacketCompleteGraphOwner,
    _host: HostSchedulingOwner,
}

/// Retains one exact target selection through code validation and fresh install.
///
/// This owns no native process, prepared controller, runtime or restoration
/// permission. The caller keeps the output outside unwind guards. Every ticket
/// attempt remains spent, and any partial capsule remains strongly retained.
#[must_use = "retain prepared code owners and partial tickets through target installation"]
pub struct PreparedCompleteRestoration {
    selected: Manifest,
    measurements: [PacketFixtureMeasurements; 3],
    content: Rc<BTreeMap<ContentRef, Vec<u8>>>,
    launches: [PacketNative5SourceLaunch; 3],
    directories: [PathBuf; 3],
    paths: [PathBuf; 3],
    receiver_group: Rc<PacketCompleteEffectReceiverGroup>,
    receiver_reader: Option<PacketCompleteEffectReceiverReader>,
    code_owners: Option<CodeOwners>,
    code_authority: Rc<InstalledPacketCompleteCollectionAuthority>,
    code_factory: Rc<PacketCompleteArchiveCodeFactory>,
    code_plan: Rc<InstalledConformancePlan>,
    code_graph: Option<Rc<CompleteArchiveCodeGraph>>,
    prebirth: Option<Rc<RefCell<PacketCompleteRestorationPrebirth>>>,
    prebirth_attempted: bool,
    prebirth_completed: bool,
    installation_attempted: bool,
}

impl PreparedCompleteRestoration {
    /// Prepares genuine code selection and one immutable target launch tuple.
    ///
    /// The manifest must already select distinct fresh live owners while keeping
    /// the desired durable compatibility. This function never rewrites owner
    /// generations, keys, coordinator rows or binding hashes after validation.
    /// The code Sources deliberately never reserve private birth or transport.
    ///
    /// # Errors
    /// Refuses occupied output, another edition, changed measured files,
    /// unsupported declaration, namespace conflict, invalid code graph or the
    /// existing finite archive/admission limits. Partial output stays retained.
    pub fn prepare_into(
        manifest: InstalledCompleteSceneManifest,
        directory: PathBuf,
        limits: NativeArchiveLimits,
        output: &mut Option<Self>,
    ) -> Result<(), QualificationError> {
        if output.is_some() {
            return Err(refused());
        }

        let mut selected = super::super::super::manifest::load(&manifest)?;
        if !matches!(
            selected.schema.as_str(),
            "crucible.complete-scene.installation/6" | "crucible.complete-scene.installation/7"
        ) {
            return Err(refused());
        }

        let measurements = selected
            .measurements
            .each_ref()
            .map(|one| PacketFixtureMeasurements {
                peer: artifact(one.peer.clone()),
                host: one.host.clone(),
                sources: one.sources.iter().cloned().map(artifact).collect(),
            });
        for measurement in &measurements {
            measurement.authenticate()?;
        }

        let content = Rc::new(super::super::super::manifest::content(std::mem::take(
            &mut selected.content,
        ))?);
        let code_host = HostSchedulingOwner::new_complete_original_continuation(
            selected.host.clone(),
            selected.world.identity()?,
        )
        .map_err(|_| refused())?;

        let initial_bytes = encoded(&selected.coordinator)?;
        let initial = InstalledContent {
            reference: canonical::content_ref(&initial_bytes, "application/json")?,
            bytes: Bytes::new(initial_bytes),
        };
        let (sources, declarations) = if selected.schema == "crucible.complete-scene.installation/7"
        {
            prepare_restored_settled_sources(
                duplicate_participant_data(&selected.participants)?,
                &selected.coordinator,
                selected.maximum_native_rows,
                selected.maximum_initial_bytes,
                selected.mechanism,
                selected.maximum_coordinator_records.ok_or_else(refused)?,
                &content,
            )?
        } else {
            prepare_sources(
                duplicate_participant_data(&selected.participants)?,
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
        let (receiver_group, receiver_reader) =
            PacketCompleteEffectReceiverGroup::from_original_receivers([a?, b?, c?]);
        let launches = launch_declarations(
            declarations,
            &selected.coordinator,
            &initial,
            &measurements,
            &paths,
        )?;

        // These separate code allocations remain neverborn for their entire
        // lifetime. Only the later ticketed target calls ready_sources.
        let (graph, code_authority, code_plan) = install_authority(
            &selected,
            &measurements,
            sources.map(Rc::new),
            code_host.source(),
            &content,
            duplicate_launch_data(&launches)?,
            directories.clone(),
        )?;
        let code_factory = PacketCompleteArchiveCodeFactory::install(
            Rc::clone(&code_authority),
            Rc::clone(&code_plan),
            limits,
        )
        .map_err(|_| refused())?;

        namespace.retained = true;
        *output = Some(Self {
            selected,
            measurements,
            content,
            launches,
            directories,
            paths,
            receiver_group,
            receiver_reader: Some(receiver_reader),
            code_owners: Some(CodeOwners {
                _graph: graph,
                _host: code_host,
            }),
            code_authority,
            code_factory,
            code_plan,
            code_graph: None,
            prebirth: None,
            prebirth_attempted: false,
            prebirth_completed: false,
            installation_attempted: false,
        });

        let prepared = output.as_mut().ok_or_else(refused)?;
        prepared.admit_code_graph(limits)
    }

    fn admit_code_graph(&mut self, limits: NativeArchiveLimits) -> Result<(), QualificationError> {
        let mut descriptors = Vec::with_capacity(4);
        let mut bindings = Vec::with_capacity(4);
        let mut owners = Vec::with_capacity(4);
        for source in &self.code_authority.roster().sources {
            let selection = source.installation();
            descriptors.push(selection.descriptor.clone());
            bindings.push(selection.binding.clone());
            owners.push(selection.owner.clone());
        }
        let host = self.code_authority.host_source().selection();
        descriptors.push(host.descriptor.clone());
        bindings.push(host.binding.clone());
        owners.push(host.owner.clone());

        self.code_graph = Some(
            self.code_factory
                .admit_original_code_graph(
                    AdmissionRequest {
                        world: &self.selected.world,
                        descriptors: &descriptors,
                        bindings: &bindings,
                        owners: &owners,
                        requirements: &self.selected.requirements,
                    },
                    AdmissionLimits {
                        maximum_nodes: 4,
                        maximum_owners: 4,
                        maximum_state_objects: 8,
                        maximum_connections: 2,
                        maximum_ports_or_lanes: 4,
                        maximum_content_bytes: limits.state.maximum_content_bytes,
                        maximum_total_content_bytes: limits.state.maximum_total_content_bytes,
                        ..AdmissionLimits::default()
                    },
                )
                .map_err(|_| refused())?,
        );
        Ok(())
    }

    /// Issues actual selected-load tickets beneath this same code plan once.
    ///
    /// The output receives any partial capsule before this method returns an
    /// error from ticket transfer. This owner retains the exact same Rc; a
    /// later install cannot substitute a foreign or reconstructed capsule.
    ///
    /// # Errors
    /// Refuses occupied output, absent code graph, repeated/late entry, a
    /// foreign signed archive or any original complete-code/ticket refusal.
    pub fn prepare_original_prebirth_into(
        &mut self,
        archive: NativeArchiveRecord,
        limits: HostSchedulingContinuationLimits,
        output: &mut Option<Rc<RefCell<PacketCompleteRestorationPrebirth>>>,
    ) -> Result<(), QualificationError> {
        if output.is_some() || self.prebirth_attempted || self.installation_attempted {
            return Err(refused());
        }

        self.prebirth_attempted = true;
        let graph = self.code_graph.as_ref().ok_or_else(refused)?;
        let mut capsule = None;
        let result = self
            .code_factory
            .prepare_original_restoration_prebirth_into(
                Rc::clone(graph),
                archive,
                limits,
                &mut capsule,
            );

        if let Some(capsule) = capsule {
            let original = Rc::new(RefCell::new(capsule));
            self.prebirth = Some(Rc::clone(&original));
            *output = Some(original);
        }

        result.map_err(|_| refused())?;
        if self.prebirth.is_none() {
            return Err(refused());
        }
        self.prebirth_completed = true;
        Ok(())
    }

    /// Installs distinct fresh Sources around the exact retained code selection.
    ///
    /// The prepared slot survives early failure. After registration, code owning
    /// wrappers move into target output and all duplicate pure setup DTOs drop
    /// before preparation supervisors or any report/native action is admitted.
    ///
    /// # Errors
    /// Refuses absent/spent prepared ownership, another capsule, incompatible
    /// Host ticket, target-plan mismatch or the original preparation budget.
    pub fn install_into(
        prepared: &mut Option<Self>,
        prebirth: Rc<RefCell<PacketCompleteRestorationPrebirth>>,
        output: &mut Option<InstalledCompleteRestoration>,
    ) -> Result<(), QualificationError> {
        if output.is_some() {
            return Err(refused());
        }
        let owner = prepared.as_mut().ok_or_else(refused)?;
        if owner.installation_attempted
            || !owner.prebirth_completed
            || !owner
                .prebirth
                .as_ref()
                .is_some_and(|original| Rc::ptr_eq(original, &prebirth))
        {
            return Err(refused());
        }

        owner.installation_attempted = true;
        prebirth
            .try_borrow_mut()
            .map_err(|_| refused())?
            .prepare_original_host(owner.selected.host.clone())
            .map_err(|_| refused())?;
        let host = prebirth
            .try_borrow()
            .map_err(|_| refused())?
            .original_host_source()
            .map_err(|_| refused())?;
        if host.world() != &owner.selected.world.identity()? {
            return Err(refused());
        }
        let (graph_owner, authority, plan) = owner.target_authority(host)?;
        // This consuming role is spent even if holder validation refuses. The
        // separately retained group still owns all three descriptors; no Child
        // exists and this same attempted owner cannot mint a replacement reader.
        let reader = owner.receiver_reader.take().ok_or_else(refused)?;
        let original = PacketCompleteReportStartupHolder::install_fresh_restoration(
            graph_owner,
            Rc::clone(&authority),
            Rc::clone(&plan),
            owner.selected.resources.clone(),
            Rc::clone(&prebirth),
            Rc::clone(&owner.receiver_group),
            reader,
        )?;

        let content = Rc::clone(&owner.content);
        *output = Some(InstalledCompleteRestoration {
            original,
            prebirth,
            authority,
            plan,
            runtime_limits: RuntimeLimits {
                maximum_nodes: 4,
                maximum_owners: 4,
                maximum_operations: owner.selected.maximum_operations,
                maximum_retained_outputs: owner.selected.maximum_retained_outputs,
            },
            write_watchdog: Duration::from_millis(owner.selected.write_watchdog_ms),
            _code_owners: owner.code_owners.take(),
        });
        // No pure manifest/launch/source setup copies survive into the effect
        // census. Actual code owners remain reachable through the target and
        // its same capsule/factory; namespace names deliberately remain reserved.
        drop(prepared.take());
        let owner = output.as_ref().ok_or_else(refused)?;
        let mut banks = Some([Rc::clone(&content), Rc::clone(&content), content]);
        PacketCompleteReportStartupHolder::retain_fresh_installation_content_into(
            &owner.original,
            &mut banks,
        )
        .map_err(|_| refused())?;
        PacketCompleteReportStartupHolder::reserve_original_preparation_supervisors(&owner.original)
    }

    fn target_authority(
        &self,
        host: Rc<HostSchedulingSource>,
    ) -> Result<AuthorityOwners, QualificationError> {
        let (sources, _) = if self.selected.schema == "crucible.complete-scene.installation/7" {
            prepare_restored_settled_sources(
                duplicate_participant_data(&self.selected.participants)?,
                &self.selected.coordinator,
                self.selected.maximum_native_rows,
                self.selected.maximum_initial_bytes,
                self.selected.mechanism,
                self.selected
                    .maximum_coordinator_records
                    .ok_or_else(refused)?,
                &self.content,
            )?
        } else {
            prepare_sources(
                duplicate_participant_data(&self.selected.participants)?,
                &self.selected.coordinator,
                self.selected.maximum_native_rows,
                self.selected.maximum_initial_bytes,
                self.selected.mechanism,
                true,
                true,
                true,
                true,
                &self.content,
            )?
        };
        let sources = ready_sources(
            sources,
            &self.launches,
            &self.receiver_group,
            &self.paths,
            self.selected.maximum_initial_bytes,
        )?;
        let owners = install_authority(
            &self.selected,
            &self.measurements,
            sources,
            host,
            &self.content,
            duplicate_launch_data(&self.launches)?,
            self.directories.clone(),
        )?;
        authenticate_plan_correspondence(
            &self.code_authority,
            &self.code_plan,
            &owners.1,
            &owners.2,
        )?;
        Ok(owners)
    }
}

// Programs remain non-cloneable; only immutable declaration DATA is copied
// before the code and target constructors independently validate it.
fn duplicate_participant_data(
    participants: &[Participant; 3],
) -> Result<[Participant; 3], QualificationError> {
    let [first, second, third] =
        participants
            .each_ref()
            .map(|participant| -> Result<Participant, QualificationError> {
                let bytes = encoded(&participant.program)?;
                let program = serde_json::from_slice(&bytes).map_err(|_| refused())?;
                Ok(Participant {
                    installation: participant.installation.clone(),
                    program,
                    storage: participant.storage.clone(),
                    capture_profile: participant.capture_profile.clone(),
                    protocol_metadata: participant.protocol_metadata,
                })
            });
    Ok([first?, second?, third?])
}

// Defining decode rechecks the complete launch DATA before target reservation;
// it neither copies a private boot owner nor issues another native capability.
fn duplicate_launch_data(
    launches: &[PacketNative5SourceLaunch; 3],
) -> Result<[PacketNative5SourceLaunch; 3], QualificationError> {
    let [first, second, third] = launches.each_ref().map(|launch| {
        let bytes = encoded(launch)?;
        PacketNative5SourceLaunch::decode(&bytes, bytes.len()).map_err(|_| refused())
    });
    Ok([first?, second?, third?])
}

type AuthorityOwners = (
    PacketCompleteGraphOwner,
    Rc<InstalledPacketCompleteCollectionAuthority>,
    Rc<InstalledConformancePlan>,
);

fn install_authority(
    selected: &Manifest,
    measurements: &[PacketFixtureMeasurements; 3],
    sources: [Rc<PacketCompleteSemanticSource>; 3],
    host: Rc<HostSchedulingSource>,
    content: &BTreeMap<ContentRef, Vec<u8>>,
    launches: [PacketNative5SourceLaunch; 3],
    directories: [PathBuf; 3],
) -> Result<AuthorityOwners, QualificationError> {
    let roster = PacketCompleteRoster::new(sources, &selected.coordinator)?;
    let graph_owner = PacketCompleteGraphOwner::install(PacketCompleteGraphRequest {
        roster: roster.clone(),
        host: Rc::clone(&host),
        measurements: measurements.each_ref(),
        world: &selected.world,
        requirements: &selected.requirements,
        content,
        coordinator: &selected.coordinator,
    })?;
    let authority =
        InstalledPacketCompleteCollectionAuthority::install(PacketCompleteCollectionRequest {
            roster,
            host,
            graph_policy: graph_owner.graph_policy()?,
            world: &selected.world,
            requirements: &selected.requirements,
            content,
            coordinator: &selected.coordinator,
            launches,
            directories,
            limits: QualificationLimits::default(),
            maximum_audit_bytes: 8 * 1024 * 1024,
        })?;
    let plan = Rc::new(authority.collection_plan().map_err(|_| refused())?);
    Ok((graph_owner, authority, plan))
}

// Full plan equality is immutable compatibility, never ticket authority. Both
// concrete plans must still belong to their distinct current owning issuers.
fn authenticate_plan_correspondence(
    code_authority: &Rc<InstalledPacketCompleteCollectionAuthority>,
    code_plan: &InstalledConformancePlan,
    target_authority: &Rc<InstalledPacketCompleteCollectionAuthority>,
    target_plan: &InstalledConformancePlan,
) -> Result<(), QualificationError> {
    if Rc::ptr_eq(code_authority, target_authority) {
        return Err(refused());
    }
    code_plan
        .authenticate_authority(code_authority.as_ref())
        .map_err(|_| refused())?;
    target_plan
        .authenticate_authority(target_authority.as_ref())
        .map_err(|_| refused())?;
    let historical = code_plan.evidence();
    let fresh = target_plan.evidence();
    if historical.plan_ref != fresh.plan_ref
        || historical.plan_bytes != fresh.plan_bytes
        || historical.refused_ref != fresh.refused_ref
        || historical.refused_bytes != fresh.refused_bytes
        || historical.world != fresh.world
        || historical.sources != fresh.sources
    {
        return Err(refused());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_qualification::packet_collection::complete::tests::native_roundtrip;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn shared_launch_tuple_matches_distinct_code_and_target_plans_without_child() {
        // The measured test ELF is constructor DATA. No native process,
        // archive ticket, Window, runtime or target permission is created here.
        let executable = std::env::current_exe().unwrap();
        let (_measured_owner, mut declaration, limits) =
            native_roundtrip::capture_declaration(&executable);
        declaration["schema"] = serde_json::json!("crucible.complete-scene.installation/6");
        let parent = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let bytes = canonical::canonical_json(&declaration).unwrap();
        let reference = canonical::content_ref(&bytes, "application/json").unwrap();
        let path = parent.path().join("installation.json");
        std::fs::write(&path, bytes).unwrap();
        let manifest = InstalledCompleteSceneManifest::new(path, reference).unwrap();
        let mut prepared = None;

        PreparedCompleteRestoration::prepare_into(
            manifest.clone(),
            parent.path().join("prepared"),
            limits,
            &mut prepared,
        )
        .unwrap();
        let owner = prepared.as_mut().unwrap();
        assert!(owner.code_graph.is_some());
        assert!(!owner.prebirth_attempted);
        assert!(!owner.prebirth_completed);
        assert!(!owner.installation_attempted);
        assert!(owner.prebirth.is_none());
        let [mut first, second, third] = duplicate_launch_data(&owner.launches).unwrap();
        assert_eq!(
            encoded(&[&first, &second, &third]).unwrap(),
            encoded(&owner.launches).unwrap(),
        );
        first.schema_version = 6;
        assert!(duplicate_launch_data(&[first, second, third]).is_err());
        owner
            .code_factory
            .retained_host_precredit_data(usize::MAX)
            .unwrap();

        // This calls the real target constructors with an unattached genuine
        // Host solely to inspect DATA correspondence, not to register a target.
        let (target_graph, target_authority, target_plan) = owner
            .target_authority(Rc::clone(owner.code_authority.host_source()))
            .unwrap();
        assert!(!Rc::ptr_eq(&owner.code_authority, &target_authority));
        for (code, target) in owner
            .code_authority
            .roster()
            .sources
            .iter()
            .zip(&target_authority.roster().sources)
        {
            assert!(!Rc::ptr_eq(code, target));
        }
        authenticate_plan_correspondence(
            &owner.code_authority,
            &owner.code_plan,
            &target_authority,
            &target_plan,
        )
        .unwrap();
        // Ready allocations on separate target Sources must not privatize or
        // revoke the retained code Sources used by the actual archive factory.
        owner
            .code_factory
            .retained_host_precredit_data(usize::MAX)
            .unwrap();

        assert!(
            authenticate_plan_correspondence(
                &owner.code_authority,
                &owner.code_plan,
                &owner.code_authority,
                &owner.code_plan,
            )
            .is_err()
        );
        let original_token = owner.launches[0].admission_token.clone();
        let mut changed_token = original_token.as_slice().to_vec();
        changed_token[0] ^= 1;
        owner.launches[0].admission_token = Bytes::new(changed_token);
        assert!(
            owner
                .target_authority(Rc::clone(owner.code_authority.host_source()),)
                .is_err()
        );
        owner.launches[0].admission_token = original_token;

        let occupied = parent.path().join("occupied");
        assert!(
            PreparedCompleteRestoration::prepare_into(
                manifest,
                occupied.clone(),
                limits,
                &mut prepared,
            )
            .is_err()
        );
        assert!(!occupied.exists());
        drop((target_plan, target_authority, target_graph, prepared));
    }
}
