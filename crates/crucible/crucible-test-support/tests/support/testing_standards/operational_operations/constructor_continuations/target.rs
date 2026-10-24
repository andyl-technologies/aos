//! Binds the retained target continuation to its actual physical owner.

use super::{Contract, facts};

pub(super) const CONTRACT: Contract = Contract {
    package: "crucible-daemon",
    target: "src/qemu_hot_fork_world_factory/target_construction",
    required: &[
        (
            r#"fn retry_cleanup(&mut self) -> Result<(), Self::Failure> {
        if self.pre_body_closed {
            return Ok(());
        }
        if !self.restore_source_backends() {
            return Err(Self::Failure::Retained(
                "exact Source backend handback remains pending",
            ));
        }
        // An untransferred carrier may still own a partial API frame. Native
        // member/aggregate/checkout obligations deliberately remain outside the
        // external Loop body and are driven only after its factual destruction.
        if let Some(construction) = self.construction.as_mut() {
            if self.launch_input.is_some() {
                construction.install_hot_fork_inputs(
                    &mut self.launch_input,
                    &mut self.continuation,
                    &mut self.adoptions,
                )?;
            }
            construction.install_adoption_cleanup(&mut self.adoptions)?;
            construction.retry_cleanup()?;
        } else if !self.adoptions.is_empty() {
            return Err(Self::Failure::Retained(
                "partial Target adoptions retain their original carrier",
            ));
        }
        self.pre_body_closed = true;
        Ok(())
    }"#,
            1,
        ),
        (
            r#"fn retry_node_rows(&mut self) -> bool {
        let Some(nodes) = self.nodes.as_mut() else {
            return self.members.is_none();
        };
        let Some(members) = self.members.as_mut() else {
            return nodes.iter().all(TargetNodeConstruction::is_vacant);
        };
        let mut all_returned = true;
        for row in nodes {
            if !row.retry_owned_cleanup(members) {
                all_returned = false;
            }
        }
        all_returned
    }"#,
            1,
        ),
        (
            r#"fn retry_rollback_children(&mut self) -> bool {
        if let Some(child) = self.adopting_child.as_mut() {
            let (Some(identity), Some(members)) =
                (self.adopting_identity.as_ref(), self.members.as_mut())
            else {
                return false;
            };
            if !members.rollback_child(identity.node(), child) {
                return false;
            }
            drop(self.adopting_child.take());
            drop(self.adopting_identity.take());
        }
        if !self.prepare_rollback_children() {
            return false;
        }
        let Some(children) = self.rollback_children.as_mut() else {
            return true;
        };
        let Some(members) = self.members.as_mut() else {
            return false;
        };
        let disposition = self
            .disposition
            .unwrap_or(AttemptExecutionDisposition::Canceled);
        for retired in children.extract_if(.., |node, child| {
            members.settle_child(node, child, disposition)
        }) {
            // The saved Cleanup and all Source/registry locks were released by
            // rollback_child before actual completed child metadata is dropped.
            drop(retired);
        }
        if !children.is_empty() {
            return false;
        }
        drop(self.rollback_children.take());
        // A partial adoption legitimately leaves two maps: unadopted children
        // in the assembly and returned leases in the registry. Drain them in
        // separate bounded passes before touching the aggregate.
        self.assembly.is_none() && self.complete.is_none() && self.reconciliations.is_none()
    }"#,
            1,
        ),
        (
            r#"fn retry_aggregate(&mut self) -> bool {
        if self.aggregate_attempted {
            return true;
        }
        if let Some(resources) = self.resources.as_mut() {
            use crate::qemu_hot_fork_world_resource::QemuHotForkWorldReleaseReadiness;
            match resources.release_readiness() {
                Ok(QemuHotForkWorldReleaseReadiness::Ready) => {}
                Ok(_) => return false,
                Err(first) => {
                    self.first_readiness.get_or_insert(first);
                    return false;
                }
            }
            self.aggregate_attempted = true;
            if let Err(first) = resources.finish() {
                self.first_aggregate.get_or_insert(first);
            }
        } else if let Some(guard) = self.guard.as_mut() {
            self.aggregate_attempted = true;
            if let Err(first) = guard.finish() {
                self.first_aggregate.get_or_insert(first);
            }
        } else if let Some(members) = self.members.as_mut() {
            // A pre-G composition/birth refusal still owns its actual partial
            // hosts in the original vector. The saved native Cleanups, not a
            // newly admitted guard, drive those same owners here.
            if let Err(first) = members.retry_native_bodies() {
                self.first_aggregate.get_or_insert_with(|| first.into());
            }
        }
        true
    }"#,
            1,
        ),
        (
            r#"fn retry_after_body(&mut self) -> bool {
        if self.physically_returned {
            return true;
        }
        // The canonical selector invokes this callback only after its exact
        // body_destroyed_epoch. It is not a caller-supplied physical assertion.
        self.body_destroyed = true;
        if !self.restore_source_backends() {
            return false;
        }
        if !self.retry_node_rows() || !self.retry_rollback_children() || !self.retry_aggregate() {
            return false;
        }
        let Some(members) = self.members.as_mut() else {
            // No selected native storage ever left Source, so this private
            // Pending could neither reserve a member nor begin physical Target.
            // Its checkout/row handback still remains terminal work below.
            if self.guard.is_none()
                && self.resources.is_none()
                && self.assembly.is_none()
                && self.complete.is_none()
                && self.adopting_child.is_none()
                && self.adopting_identity.is_none()
                && self.reconciliations.is_none()
                && self.rollback_children.is_none()
                && self.source_backends.is_none()
            {
                self.physically_returned = true;
            }
            return self.physically_returned;
        };
        if !members.retry_native_loans() {
            return false;
        }
        let recovered = if let Some(resources) = self.resources.as_mut() {
            resources.recover_target_construction_storage(members)
        } else if let Some(guard) = self.guard.as_mut() {
            guard.recover_target_construction_storage(members)
        } else {
            members.recover_retained_native_storage()
        };
        if !recovered {
            return false;
        }
        // Genuine loan returns precede storage recovery and every remaining
        // empty guard/control alias drop. Source rows and checkout remain in
        // this same paid Main body through protected terminal observation.
        drop(self.auxiliary.take());
        drop(self.auxiliary_binding.take());
        drop(self.resources.take());
        drop(self.guard.take());
        self.physically_returned = true;
        true
    }"#,
            1,
        ),
        (
            r#"drop(self.construction.take()); drop(self.continuation.take()); drop(self.launch_continuation.take()); self.post_body_taken = true;"#,
            1,
        ),
        (r#"Instant::now("#, 0),
        (r#"thread::sleep("#, 0),
        (r#"HostOperationSupervisor::new("#, 0),
    ],
    expressions: &[
        (r#"construction.retry_cleanup()"#, 1),
        (r#"row.retry_owned_cleanup(members)"#, 1),
        (r#"members.retry_native_bodies()"#, 1),
        (r#"self.retry_node_rows()"#, 1),
        (r#"self.retry_rollback_children()"#, 1),
        (r#"self.retry_aggregate()"#, 1),
        (r#"members.retry_native_loans()"#, 1),
    ],
    identifiers: &[
        (r#"retry_after_body"#, 1),
        (r#"retry_aggregate"#, 2),
        (r#"retry_cleanup"#, 2),
        (r#"retry_native_bodies"#, 1),
        (r#"retry_native_loans"#, 1),
        (r#"retry_node_rows"#, 2),
        (r#"retry_owned_cleanup"#, 1),
        (r#"retry_rollback_children"#, 2),
    ],
    companions: &[
        facts::MEMBERS,
        facts::TARGET_OWNER,
        facts::TARGET_BODIES,
        facts::TARGET_LOAN,
        facts::MAIN_AFTER_BODY,
        facts::BACKEND_FACT,
        facts::AGGREGATE,
        facts::COMPOSED,
    ],
};
