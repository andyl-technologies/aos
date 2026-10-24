//! Binds the retained node continuation to its actual physical owner.

use super::{Contract, facts};

pub(super) const CONTRACT: Contract = Contract {
    package: "crucible-daemon",
    target: "src/qemu_hot_fork_reconciliation/launch/node",
    required: &[
        (
            r#"pub(crate) fn retry_owned_cleanup(
        &mut self,
        members: &mut crate::qemu_lifecycle_launcher::TargetConstructionStorage,
    ) -> bool {
        if self.worker_panic.is_some() || self.launch.is_some() || self.detached.is_some() {
            return false;
        }
        if let Some(child) = self.child.as_mut() {
            if !members.rollback_child(&self.node, child) {
                return false;
            }
            drop(self.child.take());
        }
        if self.target.is_some() {
            if self.attempted && !self.proven_no_child {
                return false;
            }
            let returned = members.with_member_cleanup(&self.node, || {
                let Some(target) = self.target.as_mut() else {
                    return false;
                };
                match target.abort_without_child_retained() {
                    Ok(()) => {
                        // Exact no-child/local return preceded this disposal.
                        // Neither a Source nor an aggregate mutex is held.
                        drop(self.target.take());
                        drop(self.run_directory.take());
                        drop(self.launch_source.take());
                        drop(self.supervisor.take());
                        drop(self.assembly.take());
                        true
                    }
                    Err(first) => {
                        self.first_rollback.get_or_insert(first);
                        false
                    }
                }
            });
            if !returned {
                return false;
            }
        }
        self.target.is_none()
            && self.run_directory.is_none()
            && self.launch_source.is_none()
            && self.supervisor.is_none()
            && self.assembly.is_none()
    }"#,
            1,
        ),
        (
            r#"if self.attempted || self.first.is_some() || self.child.is_some() { return; }"#,
            1,
        ),
        (r#"self.attempted = true;"#, 1),
        (
            r#"self.proven_no_child = matches!(first, QemuHotForkLaunchError::Rejected { .. });"#,
            1,
        ),
        (r#"Instant::now("#, 1),
        (r#"thread::sleep("#, 0),
        (r#"HostOperationSupervisor::new("#, 0),
        (
            r#"#[cfg(test)]
#[allow(clippy::disallowed_methods)]
pub(crate) fn launch_measured(
    &mut self,
    source: QemuNodeSetPreparedHotForkSource<'_>,
    publish_source: impl FnOnce(
        &mut QemuNodeSetPreparedHotForkSource<'_>,
    ) -> Result<(), QemuNodeChannelError>,
) {
    if self.attempted { return; }
    let started = std::time::Instant::now();
    self.launch(source, publish_source);
    if self.attempted {
        self.launch_nanoseconds = Some(u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX));
    }
}"#,
            1,
        ),
    ],
    expressions: &[],
    identifiers: &[(r#"retry_owned_cleanup"#, 1)],
    companions: &[
        facts::MEMBERS,
        facts::TARGET_OWNER,
        facts::TARGET_BODIES,
        facts::TARGET_LOAN,
    ],
};
