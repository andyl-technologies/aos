//! Binds actual World token publication, initial holders and native accounting.

use super::super::Companion;

pub(in super::super) const NATIVE_WORLD: Companion = Companion {
    path: "crates/crucible/crucible-qemu-host/src/linux_attempt_host/normal_pool.rs",
    required: &[
        (r#"self.worlds[index] = Some(world);"#, 2),
        (
            r#"let Some(world) = first.take_retained_world() else {
    return Err(first.into());
};
self.worlds[index] = Some(world);
Ok(RetainedWorldAdmission { index, refusal: Some(first), })"#,
            1,
        ),
        (
            r#"let retained = before_effects.retain_world(loan, controls);
complete_world_admission(
    admission_failure.take(), retained,"#,
            1,
        ),
        (
            r#"if let Some(first) = first { return Err(report(first, retained.err())); }
retained.map_err(|operation| QemuVmRealizationError::CleanupRetained { operation })?;
prepare()"#,
            1,
        ),
        (
            r#"original.wait_slice().map_err(|first| original_roster::original_error(first.into()))?;
before_effects.prepare_world()"#,
            1,
        ),
        (
            r#"let original = preparation.begin_attempt(purpose, identity)?;"#,
            1,
        ),
        (
            r#"let RetainedWorldAdmission {
                index: world,
                refusal: mut admission_failure,
            } = match pool.claim_world(
                identity,
                consumer_control_bytes,
                &original,
                || preparation.commit_world(|| before_effects.entered_world()),
                populate,
            ) {
                Ok(retained) => retained,
                Err(source) => {
                    proven_unassigned = matches!(
                        &source,
                        OriginalActorAccountError::NativePool(refusal)
                            if refusal.world_assignment_was_refused()
                    );
                    return Err(original_roster::original_error(source));
                }
            };"#,
            1,
        ),
        (
            r#"let claim = pool.worlds[world]
                .as_mut()
                .ok_or_else(|| missing_authority("retain logical World before effects"))?;
            let custody = claim.take_initial_custody();
            let (loan, controls) = match custody {
                Ok(custody) => custody,
                Err(delivery) => {
                    return Err(match admission_failure {
                        Some(mut first) => {
                            first.retain_world_delivery_error(delivery);
                            original_roster::original_error(first.into())
                        }
                        None => original_roster::original_error(delivery.into()),
                    });
                }
            };"#,
            1,
        ),
        (
            r#"match purpose.claim_world_from(identity, consumer_control_bytes, original, entered, populate,)"#,
            1,
        ),
        (
            r#"let retained = before_effects.retain_world(loan, controls);
            complete_world_admission(
                admission_failure.take(),
                retained,
                |mut first, receiver| {
                    if let Some(receiver) = receiver {
                        first.retain_world_receiver_refusal(receiver);
                    }
                    original_roster::original_error(first.into())
                },
                || {
                    original
                        .wait_slice()
                        .map_err(|first| original_roster::original_error(first.into()))?;
                    before_effects.prepare_world()
                },
            )?;"#,
            1,
        ),
        (
            r#"fn preparation_origin(
        &self,
    ) -> Result<LinuxQemuNativeWorldPreparationOrigin, OriginalActorAccountError> {
        let purpose = self
            .purpose
            .as_ref()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        Ok(LinuxQemuNativeWorldPreparationOrigin::from_purpose(purpose))
    }"#,
            1,
        ),
        (
            r#"pub fn native_world_preparation_origin(
        &self,
    ) -> Result<LinuxQemuNativeWorldPreparationOrigin, QemuVmRealizationError> {
        if self.poisoned || self.process.is_poisoned() {
            return Err(missing_authority("borrow normal World Preparation origin"));
        }
        self.normal_pool
            .as_ref()
            .ok_or_else(|| missing_authority("retain normal World Preparation pool"))?
            .preparation_origin()
            .map_err(original_roster::original_error)
    }"#,
            1,
        ),
        (
            r#"while let Some(node) = pool.prepare_next(world, &original).map_err(original_roster::original_error)?"#,
            1,
        ),
        (
            r#"original
                    .complete()
                    .map_err(|source| original_roster::original_error(source.into()))?;
                Ok(())
            })();
            if let Err(first) = setup {
                for node in &mut owners {
                    node.owner.quarantine();
                }
                return Err(first);
            }
            Ok(owners)
        })();
        self.normal_pool = Some(pool);
        if (result.is_ok() || proven_unassigned) && !self.process.is_poisoned() {
            self.poisoned = false;
        }
        result
    }"#,
            1,
        ),
    ],
};

pub(in super::super) const TOKEN: Companion = Companion {
    path: "crates/crucible/crucible-qemu-host/src/linux_attempt_host/normal_pool/world_preparation.rs",
    required: &[
        (
            r#"struct PreparationBinding { identity: NativeWorldIdentity, entry: PreparationEntry, }"#,
            1,
        ),
        (
            r#"fn begin_attempt(&mut self, same_pool: bool, identity: NativeWorldIdentity) -> bool {
        if !same_pool || self.identity != identity || self.entry != PreparationEntry::Ready {
            return false;
        }
        self.entry = PreparationEntry::Attempted;
        true
    }"#,
            1,
        ),
        (
            r#"fn commit_world(&mut self, entered: impl FnOnce()) {
        // Only the checked assignment's move-only callback reaches this cut.
        // Refusal never resets Attempted to Ready or reconstructs a proof.
        self.entry = PreparationEntry::Committed;
        entered();
    }"#,
            1,
        ),
        (
            r#"pub fn prepare(
        self,
        identity: NativeWorldIdentity,
    ) -> Result<LinuxQemuNativeWorldPreparation, QemuVmRealizationError> {
        let original = self
            .purpose
            .begin_native_preparation()
            .map_err(|source| original_roster::original_error(source.into()))?;
        Ok(LinuxQemuNativeWorldPreparation {
            purpose: self.purpose,
            original: Arc::new(original),
            binding: PreparationBinding {
                identity,
                entry: PreparationEntry::Ready,
            },
        })
    }"#,
            1,
        ),
        (
            r#"pub(super) fn begin_attempt(
        &mut self,
        purpose: &AuthenticatedNativePoolPurpose,
        identity: NativeWorldIdentity,
    ) -> Result<Arc<HostOperationGuard>, QemuVmRealizationError> {
        if !self
            .binding
            .begin_attempt(purpose.same_pool(&self.purpose), identity)
        {
            return Err(QemuVmRealizationError::CleanupRetained {
                operation: "enter the same World Preparation exactly once",
            });
        }
        Ok(Arc::clone(&self.original))
    }"#,
            1,
        ),
        (
            r#"pub(super) fn commit_world(&mut self, entered: impl FnOnce()) { self.binding.commit_world(entered); }"#,
            1,
        ),
        (
            r#"pub fn shared_control_extent() -> Option<u64> {
        let (allocation, _) = std::alloc::Layout::new::<(
            std::sync::atomic::AtomicUsize,
            std::sync::atomic::AtomicUsize,
        )>()
        .extend(std::alloc::Layout::new::<HostOperationGuard>())
        .ok()?;
        u64::try_from(allocation.pad_to_align().size()).ok()
    }"#,
            1,
        ),
        (
            r#"pub fn operation(&self) -> &HostOperationGuard {
        &self.original
    }"#,
            1,
        ),
        (r#"self.entry = PreparationEntry::Ready;"#, 0),
    ],
};

pub(in super::super) const POOL_CLAIM: Companion = Companion {
    path: "crates/crucible/crucible-host-resources/src/host_services/process_birth/executor_purpose/native_pool.rs",
    required: &[
        (
            r#"pub fn same_pool(&self, other: &Self) -> bool { Arc::ptr_eq(&self.held, &other.held) }"#,
            1,
        ),
        (
            r#"pub fn begin_native_preparation(&self) -> Result<HostOperationGuard, ServiceBirthError> { self.held.root.begin_world_preparation() }"#,
            1,
        ),
        (
            r#"pub fn claim_world_from(
        &self,
        identity: NativeWorldIdentity,
        consumer_control_bytes: u64,
        original: &Arc<HostOperationGuard>,
        entered: impl FnOnce(),
        populate: impl FnOnce(
            &mut dyn FnMut(NativeNodeReservation) -> Result<(), ServiceBirthError>,
        ) -> Result<(), ServiceBirthError>,
    ) -> Result<AuthenticatedNativeWorldClaim, NativePoolRefusal> {
        let snapshot = (|| {
            self.held.root.verify_world_preparation(original)?;
            let mut rows = self.held.selection.try_lock().map_err(|_| {
                ServiceBirthError::policy("native selection snapshot is occupied or uncertain")
            })?;
            rows.clear();
            populate(&mut |row| {
                if rows.len() >= self.held.capacity {
                    return Err(ServiceBirthError::policy(
                        "native selection exceeds its prepaid capacity",
                    ));
                }
                rows.push(row);
                Ok(())
            })?;
            rows.sort_unstable_by_key(|row| row.node);
            Ok(rows)
        })();
        match snapshot {
            Ok(rows) => {
                self.claim_world(identity, &rows, consumer_control_bytes, original, entered)
            }
            Err(cause) => Err(NativePoolRefusal {
                cause,
                after: self.held.root.verify_world_preparation(original).err().into(),
                _retained: RetainedClaim::empty(),
            }),
        }
    }"#,
            1,
        ),
        (
            r#"let mut born = None;
        let mut assignment_refused = false;
        let (result, after) = observe_world_attempt(
            || self.held.root.verify_world_preparation(original),
            || {
                let prepared = PreparedRefusal::reserve(&self.held.root.owner)?;
                let mut ledger = borrow_world_control(
                    &self.held.ledger,
                    "native World assignment ledger is busy or uncertain",
                )?;
                let (epoch, peak, tables) = match ledger.assign_source(
                    identity,
                    nodes,
                    consumer_control_bytes,
                    original,
                    entered,
                ) {
                    Ok(assigned) => assigned,
                    Err(cause) => {
                        // assign checks all fallible arithmetic before its
                        // publication cut. A failed snapshot callback never
                        // reaches this cut; no descriptor window has run.
                        assignment_refused = true;
                        return Err(cause);
                    }
                };
                // Assignment already marked the body issued under this same
                // ledger borrow. Save both actual holders before descriptor
                // effects or any independent post can refuse.
                let claim = AuthenticatedNativeWorldClaim {
                    held: Some(Arc::clone(&self.held)),
                    epoch,
                    original: Arc::clone(original),
                    initial_custody: Some(NativeWorldBirthCustody {
                        cleanup: AuthenticatedNativeWorldCleanupLoan {
                            held: Arc::clone(&self.held),
                            epoch,
                        },
                        controls: AuthenticatedNativeWorldControlLease {
                            held: Arc::clone(&self.held),
                            epoch,
                            closed: false,
                        },
                    }),
                    returned: false,
                };
                born = Some((claim, prepared));

                let window = borrow_world_control(
                    &self.held.root.owner.host_descriptors,
                    "World descriptor owner is busy or uncertain",
                )?
                .as_mut()
                .ok_or_else(|| ServiceBirthError::policy("Main descriptor owner is absent"))?
                .reserve_pool_windows(peak, tables, original)?;
                ledger.bind_window(epoch, window)?;
                Ok(())
            },
        );
        let assignment_refused = assignment_refused && after.is_none();
        match (result, after) {
            (Ok(()), None) => born
                .map(|(claim, _prepared)| claim)
                .ok_or_else(|| NativePoolRefusal {
                    cause: ServiceBirthError::policy("native World publication is absent"),
                    after: None.into(),
                    _retained: RetainedClaim::empty(),
                }),
            (result, after) => Err(NativePoolRefusal {
                cause: result
                    .err()
                    .unwrap_or_else(|| ServiceBirthError::policy("native World postcut refused")),
                after: RefusalPostcut::world_attempt(after, assignment_refused),
                _retained: born.map_or_else(RetainedClaim::empty, |(claim, prepared)| {
                    RetainedClaim::world(claim, prepared)
                }),
            }),
        }
    }"#,
            1,
        ),
        (
            r#"pub fn take_initial_custody(
        &mut self,
    ) -> Result<
        (
            AuthenticatedNativeWorldCleanupLoan,
            AuthenticatedNativeWorldControlLease,
        ),
        ServiceBirthError,
    > {
        let custody = self.initial_custody.take().ok_or_else(|| {
            ServiceBirthError::policy("native World birth custody is already delivered")
        })?;
        Ok((custody.cleanup, custody.controls))
    }"#,
            1,
        ),
        (r#"pub fn cleanup_loan("#, 0),
        (r#"pub fn take_consumer_controls("#, 0),
    ],
};

pub(in super::super) const LEDGER: Companion = Companion {
    path: "crates/crucible/crucible-host-resources/src/host_services/process_birth/executor_purpose/native_pool/ledger.rs",
    required: &[
        (
            r#"pub(super) fn assign_source(
        &mut self,
        identity: NativeWorldIdentity,
        requests: &[NativeNodeReservation],
        consumer_control_bytes: u64,
        original: &Arc<HostOperationGuard>,
        entered: impl FnOnce(),
    ) -> Result<(u64, u64, u64), ServiceBirthError> {
        if consumer_control_bytes == 0 {
            return Err(ServiceBirthError::policy(
                "Source World body controls are absent",
            ));
        }
        self.publish_assignment(
            identity,
            requests,
            consumer_control_bytes,
            original,
            true,
            entered,
        )
    }"#,
            1,
        ),
        (r#"#[cfg(test)] pub(super) fn assign("#, 1),
        (
            r#"pub(super) fn assign(
        &mut self,
        identity: NativeWorldIdentity,
        requests: &[NativeNodeReservation],
        consumer_control_bytes: u64,
        original: &Arc<HostOperationGuard>,
    ) -> Result<(u64, u64, u64), ServiceBirthError> {
        self.publish_assignment(
            identity,
            requests,
            consumer_control_bytes,
            original,
            false,
            || {},
        )
    }"#,
            1,
        ),
        (
            r#"if identity.owner == [0; 32]
            || identity.selection == [0; 32]
            || requests.is_empty()
            || self
                .worlds
                .iter()
                .flatten()
                .any(|world| world.identity == identity)
        {
            return Err(ServiceBirthError::policy(
                "native World selection is invalid or occupied",
            ));
        }
        let world_index = self
            .worlds
            .iter()
            .position(Option::is_none)
            .ok_or_else(|| ServiceBirthError::policy("native World capacity is occupied"))?;
        if self.nodes.iter().filter(|node| node.is_none()).count() < requests.len() {
            return Err(ServiceBirthError::policy(
                "native node capacity is occupied",
            ));
        }
        let (used, peak) = checked_selection(self.ceiling, self.used, requests)?;
        let used = charge_world_controls(self.ceiling, used, consumer_control_bytes)?;
        let epoch = self
            .next_world
            .checked_add(1)
            .ok_or_else(|| ServiceBirthError::policy("native World epoch exhausted"))?;
        let assignment_end = self
            .next_assignment
            .checked_add(
                u64::try_from(requests.len())
                    .map_err(|_| ServiceBirthError::policy("native node count overflows"))?,
            )
            .ok_or_else(|| ServiceBirthError::policy("native node epoch exhausted"))?;

        let tables = requests
            .iter()
            .try_fold(0_u64, |sum, node| {
                sum.checked_add(node.resources.file_descriptors)
            })
            .ok_or_else(|| ServiceBirthError::policy("native table aggregate overflows"))?;

        // The caller's nominal no-assignment proof is consumed only after all
        // checks, immediately before the first irreversible debit/row mutation.
        entered();
        self.used = used;
        self.next_world = epoch;
        let mut assignment = self.next_assignment;
        self.next_assignment = assignment_end;
        self.worlds[world_index] = Some(WorldSlot {
            identity,
            epoch,
            consumer_control_bytes,
            consumer_issued,
            node_constructor_entered: false,
            consumer_closed: consumer_control_bytes == 0,
            _original: Arc::clone(original),
            cleanup: std::sync::OnceLock::new(),
            window: None,
        });"#,
            1,
        ),
        (
            r#"for (slot, request) in self
            .nodes
            .iter_mut()
            .filter(|slot| slot.is_none())
            .zip(requests)
        {
            assignment += 1;
            *slot = Some(NodeSlot {
                world_epoch: epoch,
                assignment_epoch: assignment,
                request: *request,
                issued: false,
                windows_issued: [false; 2],
                windows_closed: [false; 2],
            });
        }
        Ok((epoch, peak, tables))
    }"#,
            1,
        ),
        (r#"#[cfg(test)] pub(super) fn take_consumer("#, 1),
    ],
};

pub(in super::super) const MAIN_CHECK: Companion = Companion {
    path: "crates/crucible/crucible-host-resources/src/host_services/process_birth/executor_purpose/world_admission.rs",
    required: &[
        (
            r#"fn check_world_origin(&self) -> Result<(), ServiceBirthError> {
        self.original
            .verify_retained_phase()
            .map_err(ServiceBirthError::from)?;
        if !self.owner.is_live() {
            return Err(ServiceBirthError::policy("normal executor main expired"));
        }
        self.family.check()
    }
fn check_world_admission(&self) -> Result<(), ServiceBirthError> {
        self.check_world_origin()?;
        if let Some(partition) = borrow_world_control(
            &self.host_descriptors,
            "World descriptor custody is busy or uncertain",
        )?
        .as_ref()
        {
            partition.check()?;
        }
        self.original
            .verify_retained_phase()
            .map_err(ServiceBirthError::from)
    }"#,
            1,
        ),
        (
            r#"impl AuthenticatedNativeSubdivision {
    fn require_world_root(&self) -> Result<(), ServiceBirthError> {
        if self.node.is_some() {
            return Err(ServiceBirthError::policy(
                "World admission requires the containing Main pool root",
            ));
        }
        Ok(())
    }

    fn check_world_admission(&self) -> Result<(), ServiceBirthError> {
        self.require_world_root()?;
        self.owner.check_world_admission()
    }

    pub(super) fn begin_world_preparation(&self) -> Result<HostOperationGuard, ServiceBirthError> {
        self.require_world_root()?;
        self.owner.check_world_origin()?;
        self.owner
            .supervisor
            .begin(HostOperationClass::Preparation)
            .map_err(ServiceBirthError::from)
    }

    pub(super) fn verify_world_preparation(
        &self,
        original: &Arc<HostOperationGuard>,
    ) -> Result<(), ServiceBirthError> {
        self.check_world_admission()?;
        verify_preparation(&self.owner.supervisor, original)?;
        self.check_world_admission()
    }
}

"#,
            1,
        ),
        (
            r#"pub(super) fn borrow_world_control<'a, T>(
    control: &'a Mutex<T>,
    refusal: &'static str,
) -> Result<MutexGuard<'a, T>, ServiceBirthError> {
    control
        .try_lock()
        .map_err(|_| ServiceBirthError::policy(refusal))
}"#,
            1,
        ),
        (
            r#"pub(super) fn observe_world_attempt(
    mut check: impl FnMut() -> Result<(), ServiceBirthError>,
    attempt: impl FnOnce() -> Result<(), ServiceBirthError>,
) -> (Result<(), ServiceBirthError>, Option<ServiceBirthError>) {
    let result = check().and_then(|()| attempt());
    let after = check().err();
    (result, after)
}"#,
            1,
        ),
    ],
};

pub(in super::super) const NATIVE_LAYOUT: Companion = Companion {
    path: "crates/crucible/crucible-qemu-host/src/linux_attempt_host/normal_pool.rs",
    required: &[(
        r#"pub(super) fn control_extent(capacity: usize) -> Option<u64> {
        let worlds =
            std::alloc::Layout::array::<Option<AuthenticatedNativeWorldClaim>>(capacity).ok()?;
        let nodes = std::alloc::Layout::array::<Option<NormalNode>>(capacity).ok()?;
        // The returned host vector may coexist with the caller's final guard
        // payload while it is consumed. The daemon prices its own vector too.
        let returned = std::alloc::Layout::array::<LinuxQemuNativeNodeHost>(capacity).ok()?;
        let (operation, _) = std::alloc::Layout::new::<(
            std::sync::atomic::AtomicUsize,
            std::sync::atomic::AtomicUsize,
        )>()
        .extend(std::alloc::Layout::new::<HostOperationGuard>())
        .ok()?;
        let preparation_peak = operation
            .pad_to_align()
            .size()
            .checked_mul(capacity.checked_mul(2)?.checked_add(1)?)?;
        std::mem::size_of::<Self>()
            .checked_add(worlds.size())?
            .checked_add(nodes.size())?
            .checked_add(returned.size())?
            .checked_add(preparation_peak)?
            .try_into()
            .ok()
    }"#,
        1,
    )],
};

pub(in super::super) const PREPARATION_CLASS: Companion = Companion {
    path: "crates/crucible/crucible-host-resources/src/host_services/process_birth/executor_purpose.rs",
    required: &[(
        r#"fn verify_preparation(
    supervisor: &HostOperationSupervisor,
    preparation: &HostOperationGuard,
) -> Result<(), ServiceBirthError> {
    preparation
        .verify_operation_class(HostOperationClass::Preparation)
        .map_err(ServiceBirthError::from)?;
    if !preparation.shares_outer_cap(supervisor) {
        return Err(ServiceBirthError::policy(
            "normal native preparation has a different original main",
        ));
    }
    Ok(())
}"#,
        1,
    )],
};

pub(in super::super) const LIVE_CLASS: Companion = Companion {
    path: "crates/crucible/crucible-host-resources/src/host_supervision.rs",
    required: &[(
        r#"pub fn verify_operation_class(
        &self,
        expected: HostOperationClass,
    ) -> Result<(), HostSupervisionError> {
        #[cfg(feature = "private-measurement-domain")]
        self.check_original_preparation()?;
        let mut state = self.supervisor.lock()?;
        let decision = self.supervisor.evaluate_decision(&mut state, self.id)?;
        decision.require_running(self.id)?;
        if decision.class != expected {
            return Err(HostSupervisionError::InvalidBudget);
        }
        Ok(())
    }"#,
        1,
    )],
};
