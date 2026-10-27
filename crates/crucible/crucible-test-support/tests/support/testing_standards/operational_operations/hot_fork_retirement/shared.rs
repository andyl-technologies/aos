//! Binds existing Source owners, saved Cleanup and physical last-use order.

use super::{Companion, Contract};

pub(super) const CONTRACT: Contract = Contract {
    package: "crucible-daemon",
    target: "src/vm_lifecycle/hot_fork/shared_source",
    required: &[
        (
            r#"pub(in crate::vm_lifecycle) fn retry_body(&mut self) -> Result<(), CleanupError> {
    if self.source.is_none() {
        let shared = self.shared.as_mut().ok_or(CleanupError::Retained(
            "shared Source allocation and body are both unavailable",
        ))?;
        if !self.parent_park.retry(shared) {
            return Err(CleanupError::Retained(
                "same actual managed Park remains retained",
            ));
        }
        let body = unique_shared_body(shared)?;
        if !body.matches_shared_selection(&self.selector) {
            return Err(CleanupError::Retained(
                "shared Source does not retain its original detached selection",
            ));
        }
        if !self.parent_park.transfer_to(body) {
            return Err(CleanupError::Retained(
                "same Source retains independent managed Park history",
            ));
        }
        self.source = Some(body.take_shared_body());
        // The actual Source is already retained in this same Main carrier.
        // Only the inert allocation dies here, before native cleanup begins.
        drop(self.shared.take());
    }
    self.source
        .as_mut()
        .ok_or(CleanupError::Retained("shared Source body is unavailable"))?
        .retry_source_retirement_body()
}"#,
            1,
        ),
        (
            r#"pub(in crate::vm_lifecycle) fn take_post_body(
    &mut self,
) -> Result<Option<crate::ProductionVmConstructionPostBody>, CleanupError> {
    if self.shared.is_some() {
        return Err(CleanupError::Retained(
            "shared Source allocation is still live",
        ));
    }
    self.source
        .as_mut()
        .ok_or(CleanupError::Retained("shared Source body is unavailable"))?
        .take_source_retirement_post_body()
}"#,
            1,
        ),
        (
            r#"fn unique_shared_body<T>(shared: &mut Arc<Mutex<T>>) -> Result<&mut T, CleanupError> {
    Arc::get_mut(shared)
        .ok_or(CleanupError::SharedAliasesPending)?
        .get_mut()
        .map_err(|_| CleanupError::Poisoned)
}"#,
            1,
        ),
        (
            r#"fn take_shared_body(&mut self) -> Self {
    Self {
        lifecycle: self.lifecycle.take(),
        continuation: self.continuation.take(),
        prepared: std::mem::take(&mut self.prepared),
        disk_custody: std::mem::take(&mut self.disk_custody),
        cleanup_observer: self.cleanup_observer.take(),
        retirement: self.retirement.take(),
        target_backends_lent: std::mem::take(&mut self.target_backends_lent),
        #[cfg(feature = "private-measurement-domain")]
        managed_parent_park_history: self.managed_parent_park_history.take(),
    }
}"#,
            1,
        ),
        (
            r#"fn matches_shared_selection(&self, selector: &PreparedSourceSelector) -> bool {
    self.retirement.is_none()
        && self.lifecycle.as_ref().is_some_and(|lifecycle| {
            matches!(
                lifecycle.construction_custody,
                LifecycleConstructionCustody::Unissued(None)
            ) && lifecycle
                .prepared_source_selector()
                .as_ref()
                .is_some_and(|actual| actual.same_role(selector))
        })
}"#,
            1,
        ),
        (
            r#"fn retry(&self, source: &Arc<Mutex<ProductionVmHotForkSourceWorld>>) -> bool {
    #[cfg(feature = "private-measurement-domain")]
    if let Some(gate) = &self.gate {
        return gate.retry_retirement(source);
    }
    let _ = source;
    true
}"#,
            1,
        ),
        (
            r#"fn transfer_to(&mut self, source: &mut ProductionVmHotForkSourceWorld) -> bool {
    #[cfg(feature = "private-measurement-domain")]
    if let Some(gate) = &self.gate {
        if !gate.is_physically_returned() || source.managed_parent_park_history.is_some() {
            return false;
        }
        source.managed_parent_park_history = self.gate.take();
    }
    let _ = source;
    true
}"#,
            1,
        ),
        (
            r#"if !destination.matches_selector(&selector) { lifecycle.restore_retirement_custody(carrier, Some(destination)); return Err(self); }"#,
            1,
        ),
        (
            r#"drop(destination.deliver(carrier.install_owned_shared_source(source, selector, parent_park,)));"#,
            1,
        ),
        (
            r#"Arc::new("#,
            1,
        ),
        (
            r#"Arc::get_mut("#,
            1,
        ),
        (
            r#"Arc::make_mut("#,
            0,
        ),
        (
            r#"Arc::try_unwrap("#,
            0,
        ),
        (
            r#"HostOperationSupervisor::new("#,
            0,
        ),
        (
            r#"begin_original_cleanup_control("#,
            0,
        ),
    ],
    expressions: &[
        (
            r#"self.parent_park.retry(shared)"#,
            1,
        ),
        (
            r#"retry_source_retirement_body()"#,
            1,
        ),
        (
            r#"fn retry(&self, source: &Arc<Mutex<ProductionVmHotForkSourceWorld>>) -> bool"#,
            1,
        ),
        (
            r#"gate.retry_retirement(source)"#,
            1,
        ),
    ],
    identifiers: &[
        (
            r#"retry_body"#,
            1,
        ),
        (
            r#"retry"#,
            2,
        ),
        (
            r#"retry_source_retirement_body"#,
            1,
        ),
        (
            r#"retry_retirement"#,
            1,
        ),
    ],
    companions: &[
        Companion {
            path: "crates/crucible/crucible-daemon/src/vm_lifecycle/hot_fork/source_retirement.rs",
            required: super::source::REQUIRED,
        },
        Companion {
            path: "crates/crucible/crucible-daemon/src/managed_qemu_hot_fork_source_world_pool/parent_park/retirement.rs",
            required: super::park::REQUIRED,
        },
        Companion {
            path: "crates/crucible/crucible-daemon/src/vm_lifecycle/construction/custody.rs",
            required: &[
                (
                    r#"Phase::SharedSource(source) => source.retry_body()?,"#,
                    1,
                ),
                (
                    r#"Phase::SourceRearmFailure(source) => source.retry_body()?,"#,
                    1,
                ),
                (
                    r#"Phase::SourcePreparation(preparation) => preparation.retry_body()?,"#,
                    1,
                ),
                (
                    r#"self.physically_closed.store(true, Ordering::Release);"#,
                    1,
                ),
            ],
        },
    ],
};
