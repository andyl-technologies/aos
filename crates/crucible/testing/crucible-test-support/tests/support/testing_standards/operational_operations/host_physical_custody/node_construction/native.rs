//! Binds real native node delivery, conversion and physical return to saved custody.

use super::super::super::Companion;

pub(in super::super::super) const NODE_ISSUE: Companion = Companion {
    path: "crates/crucible/host/crucible-host-resources/src/host_services/process_birth/executor_purpose/native_pool.rs",
    required: &[(
        r#"pub fn take_node_into(
        &self,
        node: [u8; 32],
        destination: &mut Option<AuthenticatedNativeNodeClaim>,
    ) -> Result<(), NativePoolRefusal> {
        let result = (|| {
            if destination.is_some() {
                return Err(ServiceBirthError::policy(
                    "native node destination is occupied",
                ));
            }
            let held = self
                .held
                .as_ref()
                .ok_or_else(|| ServiceBirthError::policy("native World custody is absent"))?;
            held.root.verify_native_preparation(&self.original)?;
            let mut ledger = held
                .ledger
                .lock()
                .map_err(|_| ServiceBirthError::policy("native pool ledger is uncertain"))?;
            let (node_index, assignment_epoch) = ledger.take_node(self.epoch, node)?;
            *destination = Some(AuthenticatedNativeNodeClaim {
                held: Some(Arc::clone(held)),
                world_epoch: self.epoch,
                assignment_epoch,
                node_index,
                _original: Arc::clone(&self.original),
                target_window: Mutex::new(None),
            });
            Ok(())
        })();
        let after = postcut(self.held.as_ref(), &self.original);
        match (result, after) {
            (Ok(()), None) => Ok(()),
            (result, after) => Err(NativePoolRefusal {
                cause: result
                    .err()
                    .unwrap_or_else(|| ServiceBirthError::policy("native node postcut refused")),
                after: after.into(),
                _retained: RetainedClaim::empty(),
            }),
        }
    }"#,
        1,
    )],
};

pub(in super::super::super) const NODE_CONVERSION: Companion = Companion {
    path: "crates/crucible/host/crucible-host-resources/src/host_services/process_birth/executor_purpose/native_pool/node.rs",
    required: &[
        (
            r#"pub fn move_to_subdivision(
        source: &mut Option<Self>,
        destination: &mut Option<AuthenticatedNativeSubdivision>,
        original: &Arc<HostOperationGuard>,
    ) -> Result<(), NativePoolRefusal> {
        let held = source.as_ref().and_then(|node| node.held.as_ref().cloned());
        let result = (|| {
            if destination.is_some() {
                return Err(ServiceBirthError::policy(
                    "native subdivision destination is occupied",
                ));
            }
            let held = held
                .as_ref()
                .ok_or_else(|| ServiceBirthError::policy("native node custody is absent"))?;
            let node = source
                .as_ref()
                .ok_or_else(|| ServiceBirthError::policy("native node source is absent"))?;
            held.root.verify_native_preparation(original)?;
            let bounds = node.bounds()?;
            let node = source
                .take()
                .ok_or_else(|| ServiceBirthError::policy("native node source is absent"))?;
            *destination = Some(AuthenticatedNativeSubdivision {
                owner: Arc::clone(&held.root.owner),
                bounds,
                local_file_descriptors: bounds.file_descriptors / 2,
                node: Some(node),
            });
            Ok(())
        })();
        let after = postcut(held.as_ref(), original);
        match (result, after) {
            (Ok(()), None) => Ok(()),
            (result, after) => Err(NativePoolRefusal {
                cause: result.err().unwrap_or_else(|| {
                    ServiceBirthError::policy("native node issuer postcut refused")
                }),
                after: after.into(),
                _retained: RetainedClaim::empty(),
            }),
        }
    }"#,
            1,
        ),
        (
            r#"pub fn is_physically_returned(&self) -> bool {
        self.held.is_none()
    }"#,
            1,
        ),
        (
            r#"pub fn retire_before_subdivision(&mut self) -> Result<(), NativePoolReturnError> {
        if self.is_physically_returned() {
            return Ok(());
        }
        let cleanup = self.retained_world_cleanup()?;
        self.retire_after_control_free(&cleanup)
    }"#,
            1,
        ),
        (
            r#"pub(in super::super) fn retained_world_cleanup(
        &self,
    ) -> Result<Arc<HostOperationGuard>, ServiceBirthError> {
        let held = self
            .held
            .as_ref()
            .ok_or_else(|| ServiceBirthError::policy("native node already returned"))?;
        let ledger = held
            .ledger
            .try_lock()
            .map_err(|_| ServiceBirthError::policy("native node retirement is uncertain"))?;
        ledger.node_bounds(self.world_epoch, self.assignment_epoch, self.node_index)?;
        ledger.retained_cleanup(self.world_epoch)
    }"#,
            1,
        ),
        (
            r#"pub(in super::super) fn verify_world_cleanup(
        &self,
        cleanup: &Arc<HostOperationGuard>,
    ) -> Result<(), ServiceBirthError> {
        let held = self
            .held
            .as_ref()
            .ok_or_else(|| ServiceBirthError::policy("native node already returned"))?;
        {
            let ledger = held
                .ledger
                .try_lock()
                .map_err(|_| ServiceBirthError::policy("native node retirement is uncertain"))?;
            ledger.node_bounds(self.world_epoch, self.assignment_epoch, self.node_index)?;
            ledger.verify_cleanup(self.world_epoch, cleanup)?;
        }
        held.verify_return_custody(cleanup)?;
        held.ledger
            .try_lock()
            .map_err(|_| ServiceBirthError::policy("native node retirement is uncertain"))?
            .verify_cleanup(self.world_epoch, cleanup)
    }"#,
            1,
        ),
        (
            r#"pub(in super::super) fn retire_after_control_free(
        &mut self,
        cleanup: &Arc<HostOperationGuard>,
    ) -> Result<(), NativePoolReturnError> {
        let Some(held) = self.held.as_ref().cloned() else {
            return Ok(());
        };
        // Resolve only an already-latched result. Never run a postcheck against
        // a substituted operation or initialize missing Cleanup by verification.
        let saved = held
            .ledger
            .try_lock()
            .map_err(|_| ServiceBirthError::policy("native node retirement is uncertain"))?
            .saved_cleanup(self.world_epoch)?;
        if !Arc::ptr_eq(&saved, cleanup) {
            return Err(ServiceBirthError::policy("native node return Cleanup is foreign").into());
        }
        let result = (|| {
            self.verify_world_cleanup(&saved)?;
            if let Some(window) = self.target_window.get_mut().map_err(|_| {
                ServiceBirthError::policy("native Target landing custody is uncertain")
            })? {
                window.close_after_controls()?;
            }
            let mut ledger = held
                .ledger
                .try_lock()
                .map_err(|_| ServiceBirthError::policy("native node retirement is uncertain"))?;
            ledger.verify_cleanup(self.world_epoch, &saved)?;
            let prepared = ledger.prepare_node_return(
                self.world_epoch,
                self.assignment_epoch,
                self.node_index,
            )?;
            let (work, consumed) = held
                .root
                .owner
                .host_descriptors
                .try_lock()
                .map_err(|_| ServiceBirthError::policy("Main descriptor owner is uncertain"))?
                .as_mut()
                .ok_or_else(|| ServiceBirthError::policy("Main descriptor owner is absent"))?
                .close_pool_assignment(prepared.windows, prepared.tables);
            if consumed {
                ledger.commit_node_return(prepared);
            }
            drop(ledger);
            if consumed {
                drop(self.held.take());
            }
            work
        })();
        NativePoolReturnError::finish(
            result,
            saved.verify_operation_class(crate::host_supervision::HostOperationClass::Cleanup),
        )
    }"#,
            1,
        ),
    ],
};

pub(in super::super::super) const NODE_SUBDIVISION: Companion = Companion {
    path: "crates/crucible/host/crucible-host-resources/src/host_services/process_birth/executor_purpose.rs",
    required: &[
        (
            r#"pub fn retire_after_control_free(
        &mut self,
        cleanup: &Arc<HostOperationGuard>,
    ) -> Result<(), NativePoolReturnError> {
        let node = self
            .node
            .as_mut()
            .ok_or_else(|| ServiceBirthError::policy("native return node is absent"))?;
        node.retire_after_control_free(cleanup)
    }"#,
            1,
        ),
        (
            r#"pub fn retained_world_cleanup(&self) -> Result<Arc<HostOperationGuard>, ServiceBirthError> {
        self.node
            .as_ref()
            .ok_or_else(|| ServiceBirthError::policy("native return node is absent"))?
            .retained_world_cleanup()
    }"#,
            1,
        ),
        (
            r#"pub fn is_physically_returned(&self) -> bool {
        self.node
            .as_ref()
            .is_some_and(|node| node.is_physically_returned())
    }"#,
            1,
        ),
    ],
};

pub(in super::super::super) const NODE_LEDGER: Companion = Companion {
    path: "crates/crucible/host/crucible-host-resources/src/host_services/process_birth/executor_purpose/native_pool/ledger.rs",
    required: &[
        (
            r#"pub(super) fn take_node(
        &mut self,
        epoch: u64,
        node: [u8; 32],
    ) -> Result<(usize, u64), ServiceBirthError> {
        let world = self
            .worlds
            .iter_mut()
            .flatten()
            .find(|world| world.epoch == epoch && world.window.is_some())
            .ok_or_else(|| {
                ServiceBirthError::policy("native World descriptor custody is absent")
            })?;
        let (index, slot) = self
            .nodes
            .iter_mut()
            .enumerate()
            .find_map(|(index, slot)| {
                slot.as_mut()
                    .filter(|slot| {
                        slot.world_epoch == epoch && slot.request.node == node && !slot.issued
                    })
                    .map(|slot| (index, slot))
            })
            .ok_or_else(|| ServiceBirthError::policy("native node is absent or already issued"))?;

        // Every fallible lookup precedes either monotonic publication.
        slot.issued = true;
        let assignment_epoch = slot.assignment_epoch;
        world.node_constructor_entered = true;
        Ok((index, assignment_epoch))
    }"#,
            1,
        ),
        (
            r#"pub(super) fn prepare_node_return(
        &self,
        epoch: u64,
        assignment: u64,
        index: usize,
    ) -> Result<PreparedNodeReturn, ServiceBirthError> {
        let unused_landings = self.returnable_window_peak(epoch, assignment, index)?;
        let node = self.nodes[index]
            .as_ref()
            .ok_or_else(|| ServiceBirthError::policy("native node already returned"))?;
        let mut returned = node.request.resources;
        returned.file_descriptors = returned
            .file_descriptors
            .checked_add(unused_landings)
            .ok_or_else(|| ServiceBirthError::policy("native return descriptor sum overflows"))?;
        let used = subtract(self.used, returned)?;
        Ok(PreparedNodeReturn {
            windows: unused_landings,
            tables: node.request.resources.file_descriptors,
            index,
            used,
        })
    }"#,
            1,
        ),
        (
            r#"pub(super) fn commit_node_return(&mut self, prepared: PreparedNodeReturn) {
        self.nodes[prepared.index] = None;
        self.used = prepared.used;
    }"#,
            1,
        ),
    ],
};

pub(in super::super::super) const NODE_RETURN_HISTORY: Companion = Companion {
    path: "crates/crucible/host/crucible-host-resources/src/host_services/process_birth/executor_purpose/native_pool/world_return.rs",
    required: &[(
        r#"pub(super) fn finish<T>(
        result: Result<T, ServiceBirthError>,
        post: Result<(), crate::host_supervision::HostSupervisionError>,
    ) -> Result<T, Self> {
        match (result, post) {
            (Ok(value), Ok(())) => Ok(value),
            (result, post) => Err(Self {
                first: result.err(),
                post: post.err(),
            }),
        }
    }"#,
        1,
    )],
};
