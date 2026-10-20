//! Binds the retained pending continuation to its actual physical owner.

use super::{Companion, Contract, facts};

pub(super) const CONTRACT: Contract = Contract {
    package: "crucible-daemon",
    target: "src/qemu_lifecycle_launcher/pending_construction",
    required: &[
        (
            r#"factory: Option<F>, world: Option<AuthenticatedNativeWorldCleanupLoan>, reservation: Option<crate::WorldLifecycleCleanupReservation>,"#,
            1,
        ),
        (
            r#"fn retry_cleanup(&mut self) -> Result<(), crate::ProductionVmConstructionCleanupError> { ProductionVmNodeLauncher::finish(self) }"#,
            1,
        ),
        (
            r#"self.require_external_body_acceptance()?; self.close_target_nodes()?; if self.body_cleanup_complete { return Ok(()); }"#,
            1,
        ),
        (
            r#"custody.retry_cleanup()?; self.body_cleanup_complete = true; return Ok(());"#,
            1,
        ),
        (
            r#"if let Some(launcher) = self.launch_input.as_mut() { launcher.finish()?; self.body_cleanup_complete = true; return Ok(()); }"#,
            1,
        ),
        (
            r#"if self.transferred || self.not_started.is_some() { self.body_cleanup_complete = true; return Ok(()); }"#,
            1,
        ),
        (
            r#"if let Err(controls) = reservation.attach_controls(controls) { self.controls = Some(controls);"#,
            1,
        ),
        (r#"self.finish_under_world_cleanup()"#, 1),
        (r#"Instant::now("#, 0),
        (r#"thread::sleep("#, 0),
        (r#"HostOperationSupervisor::new("#, 0),
    ],
    expressions: &[(r#"custody.retry_cleanup()"#, 1)],
    identifiers: &[(r#"retry_cleanup"#, 2)],
    companions: &[
        facts::SOURCE_CLEANUP,
        facts::BACKEND_FACT,
        facts::WORLD_0,
        facts::WORLD_1,
        facts::WORLD_2,
        facts::WORLD_3,
        facts::WORLD_4,
        super::super::source_world_admission::PREPARED_WORLD,
        super::super::source_world_admission::NATIVE_WORLD,
        super::super::source_world_admission::ADMISSION,
        super::super::source_world_admission::FACADE,
        super::super::source_world_admission::RECEIVER_API,
        super::super::source_world_admission::TOKEN,
        super::super::source_world_admission::POOL_CLAIM,
        super::super::source_world_admission::LEDGER,
        super::super::source_world_admission::MAIN_CHECK,
        super::super::source_world_admission::PENDING_LAYOUT,
        super::super::source_world_admission::PENDING_POST_BODY,
        super::super::source_world_admission::NATIVE_LAYOUT,
        super::super::source_world_admission::PREPARATION_CLASS,
        super::super::source_world_admission::LIVE_CLASS,
        Companion {
            path: "crates/crucible/control/crucible-daemon/src/qemu_lifecycle_launcher/pending_construction/post_body.rs",
            required: &[
                (
                    r#"if self.post_body.is_none() { self.post_body = Some(self.extract_post_body()?); }"#,
                    1,
                ),
                (
                    r#"if let Some(world) = self.world.take() { return Ok(PostBody::world(world, None)); } if let Some(not_started) = self.not_started.take() { return Ok(PostBody::never_entered(not_started)); }"#,
                    1,
                ),
            ],
        },
        super::super::host_physical_custody::NODE_OWNER,
        super::super::host_physical_custody::NODE_BIRTH,
        super::super::host_physical_custody::NODE_ISSUE,
        super::super::host_physical_custody::NODE_CONVERSION,
        super::super::host_physical_custody::NODE_SUBDIVISION,
        super::super::host_physical_custody::NODE_LEDGER,
        super::super::host_physical_custody::NODE_RETURN_HISTORY,
        super::super::host_physical_custody::NODE_CREDIT_BIRTH,
        super::super::host_physical_custody::NODE_PUBLISHER,
        super::super::host_physical_custody::NODE_LAYOUT,
        super::super::host_physical_custody::NODE_ROSTER_RETURN,
        super::super::host_physical_custody::NODE_CREDIT_RETURN,
        super::super::source_world_admission::ORIGIN_BODY,
        super::super::source_world_admission::ORIGIN_PUBLICATION,
        super::super::source_world_admission::ORIGIN_RUNNERS,
        super::super::source_world_admission::ORIGIN_FINDING,
        super::super::source_world_admission::ORIGIN_OWNER,
    ],
};
