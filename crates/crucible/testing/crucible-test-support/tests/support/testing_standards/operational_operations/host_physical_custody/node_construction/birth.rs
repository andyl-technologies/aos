//! Binds prepaid node stages and the unchanged allocation-only roster publisher.

use super::super::super::Companion;

pub(in super::super::super) const NODE_BIRTH: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/linux_attempt_host/normal_pool.rs",
    required: &[
        (
            r#"pub(super) fn prepare_next(
        &mut self,
        world: usize,
        original: &Arc<HostOperationGuard>,
    ) -> Result<Option<NormalNodeBirth>, OriginalActorAccountError> {
        if self
            .nodes
            .iter()
            .flatten()
            .any(|node| node.world == world && node.is_constructing())
        {
            return Err(OriginalActorAccountError::Unavailable);
        }
        let claim = self
            .worlds
            .get(world)
            .and_then(Option::as_ref)
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let Some(request) = claim.next_node()? else {
            return Ok(None);
        };
        let controls = OriginalNativeAccountRoster::shared_allocation_extent()?;
        let index = self
            .nodes
            .iter()
            .position(Option::is_none)
            .ok_or(OriginalActorAccountError::Unavailable)?;

        // The permanently prepaid array owns every raw/conversion holder
        // before issuance, postchecks, roster publication or physical setup.
        self.nodes[index] = Some(NormalNode::constructing(world));
        let node = self.nodes[index]
            .as_mut()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        node.prepare(claim, request.node, original, controls)?;
        Ok(Some(NormalNodeBirth {
            index,
            key: request.node,
            resources: request.resources,
        }))
    }"#,
            1,
        ),
        (
            r#"pub(super) fn sweep_retired(&mut self) -> Result<(), OriginalActorAccountError> {
        for entry in &mut self.nodes {
            let Some(node) = entry.as_mut() else {
                continue;
            };
            if node.verify_quiescent().is_err() {
                continue;
            }
            // Constructing closes its actual retained funding. A Published
            // row removes its real Weak alias before exclusive roster close;
            // any other alias still prevents Arc free.
            let closed = node.try_close();
            let returned = node.can_remove();
            if returned {
                *entry = None;
            }
            match closed {
                Ok(()) => {}
                // Existing competing aliases remain pending without starving
                // independent rows. A typed phase/post refusal remains visible.
                Err(OriginalActorAccountError::Unavailable) if !returned => {}
                Err(error) => return Err(error),
            }
        }
        for (index, world) in self.worlds.iter_mut().enumerate() {
            if self.nodes.iter().flatten().any(|node| node.world == index) {
                continue;
            }
            if let Some(claim) = world.as_mut() {
                let result = claim.try_finish_after_members_returned();
                let returned = claim.is_physically_returned();
                if returned {
                    *world = None;
                }
                if result? == NativeWorldReturn::PendingBody {
                    continue;
                }
            }
            *world = None;
        }
        Ok(())
    }"#,
            1,
        ),
        (
            r#"pub(super) fn is_physically_retired(&self) -> bool {
        // Returned credit alone does not destroy its containing facade or
        // retained aliases. Every owning entry must be removed before closure.
        self.nodes.iter().all(Option::is_none) && self.worlds.iter().all(Option::is_none)
    }"#,
            1,
        ),
    ],
};

pub(in super::super::super) const NODE_CREDIT_BIRTH: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/linux_attempt_host/native_account.rs",
    required: &[(
        r#"pub(super) fn move_from_normal_subdivision(
        source: &mut Option<AuthenticatedNativeSubdivision>,
        destination: &mut Option<Self>,
        preparation: &Arc<HostOperationGuard>,
        controls: u64,
    ) -> Result<(), OriginalActorAccountError> {
        if destination.is_some() {
            return Err(OriginalActorAccountError::Unavailable);
        }
        let purpose = source
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        purpose.verify_native_preparation(preparation)?;
        let bounds = purpose.bounds();
        if bounds.cpu_slots == 0 || controls > bounds.metadata_bytes {
            return Err(OriginalActorAccountError::Unavailable);
        }
        let purpose = source
            .take()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        *destination = Some(Self {
            original: Some(RetainedNativeCredit {
                _pair: None,
                normal: Some(purpose),
                preparation: Arc::clone(preparation),
            }),
            full_resident_bytes: bounds.resident_peak_bytes,
            full_backing_bytes: bounds.backing_peak_bytes,
            total_metadata_bytes: bounds.metadata_bytes,
            cpu_ceiling: bounds.cpu_slots,
            task_ceiling: bounds.task_slots,
            descriptor_ceiling: bounds.file_descriptors,
            normal_controls_bytes: controls,
            #[cfg(feature = "private-measurement-domain")]
            actor_family: None,
        });
        Ok(())
    }"#,
        1,
    )],
};

pub(in super::super::super) const NODE_PUBLISHER: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/linux_attempt_host/original_roster.rs",
    required: &[
        (
            r#"pub(super) fn publish_normal_credit(
        credit: &mut Option<OriginalNativeAccountCredit>,
    ) -> Result<(Self, OriginalNativeAccountFactoryBinding), OriginalActorAccountError> {
        let controls = Self::shared_allocation_extent()?;
        let retained = credit
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        if retained.normal_controls_bytes != controls
            || retained
                .original
                .as_ref()
                .and_then(|original| original.normal.as_ref())
                .is_none()
        {
            return Err(OriginalActorAccountError::Unavailable);
        }
        let credit = credit
            .take()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        Ok(Self::publish_allocated([Some(credit), None, None, None], 1))
    }"#,
            1,
        ),
        (
            r#"pub(super) fn publish(
        credits: [Option<OriginalNativeAccountCredit>; MAX_NATIVE_WORKERS],
        width: usize,
    ) -> Result<(Self, OriginalNativeAccountFactoryBinding), OriginalActorAccountError> {
        if !matches!(width, 1 | 2 | 4)
            || credits.iter().take(width).any(Option::is_none)
            || credits.iter().skip(width).any(Option::is_some)
        {
            return Err(OriginalActorAccountError::Unavailable);
        }
        Ok(Self::publish_allocated(credits, width))
    }"#,
            1,
        ),
        (
            r#"fn publish_allocated(
        credits: [Option<OriginalNativeAccountCredit>; MAX_NATIVE_WORKERS],
        width: usize,
    ) -> (Self, OriginalNativeAccountFactoryBinding) {
        let roster = Arc::new(Mutex::new(NativeRoster {
            slots: credits.map(|credit| NativeSlot {
                issuer_controls_bytes: credit.as_ref().map_or(0, |held| held.normal_controls_bytes),
                credit,
                family_constructor_bytes: 0,
                active: None,
                node_bindings_live: 0,
                digest_purposes: [device_digest::DigestPurposeState::default();
                    MAX_ORIGINAL_NATIVE_NODE_GENERATIONS as usize],
                launch_controls_bytes: 0,
                cleanup_controls_bytes: 0,
                process_binding_bytes: 0,
                installed_process: None,
                source_control_payer: None,
                launch_in_flight: false,
                launch_abandoned: false,
                launch_refusal: None,
                source_controller: None,
                source_cleanup_assigned: false,
                control: None,
                cleanup: None,
                unsettled: None,
                fork_target: fork_target::ForkTargetSlot::default(),
            }),
            width,
            next_generation: 1,
            next_workspace_generation: 1,
        }));
        let binding = OriginalNativeAccountFactoryBinding {
            roster: Arc::downgrade(&roster),
        };
        (
            Self {
                held: Some(roster),
                retiring_credits: std::array::from_fn(|_| None),
            },
            binding,
        )
    }"#,
            1,
        ),
        (
            r#"pub(super) fn shared_allocation_extent() -> Result<u64, OriginalActorAccountError> {
        Self::allocation_extent()?
            .checked_sub(std::mem::size_of::<Self>() as u64)
            .ok_or(OriginalActorAccountError::Unavailable)
    }"#,
            1,
        ),
        (
            r#"pub(super) fn allocation_extent() -> Result<u64, OriginalActorAccountError> {
        let (layout, _) = std::alloc::Layout::new::<(
            std::sync::atomic::AtomicUsize,
            std::sync::atomic::AtomicUsize,
        )>()
        .extend(std::alloc::Layout::new::<Mutex<NativeRoster>>())
        .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let bytes = layout
            .pad_to_align()
            .size()
            .checked_add(std::mem::size_of::<Self>())
            .ok_or(OriginalActorAccountError::Unavailable)?;
        u64::try_from(bytes).map_err(|_| OriginalActorAccountError::Unavailable)
    }"#,
            1,
        ),
    ],
};
