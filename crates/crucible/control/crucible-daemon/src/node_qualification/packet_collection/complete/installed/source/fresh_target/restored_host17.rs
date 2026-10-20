//! Installs the distinct current17 Host under its complete actual setup census.
//!
//! Only the genuine ticket family selects this path. Metadata cloning and
//! namespace/native installation follow independently admitted Host construction;
//! neither a manifest tag nor this forwarding entry creates native authority.

use super::*;

impl InstalledCompleteRestoration {
    pub(super) fn install_restored_settled_into(
        manifest: InstalledCompleteSceneManifest,
        directory: PathBuf,
        prebirth: Rc<RefCell<PacketCompleteRestorationPrebirth>>,
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

        let content =
            super::super::super::manifest::content(std::mem::take(&mut selected.content))?;

        PacketCompleteRestorationPrebirth::prepare_original_host_for_target(
            &prebirth,
            &selected.host,
            &selected.resources,
            &HostSource17SetupBorrow::direct_data(
                &manifest,
                &directory,
                &selected,
                &measurements,
                &content,
            ),
        )
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
}
