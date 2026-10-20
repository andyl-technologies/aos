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
        Companion {
            path: "crates/crucible/control/crucible-daemon/src/qemu_lifecycle_launcher/pending_construction/prepared.rs",
            required: &[
                (
                    r#"if self.construction_started || self.transferred || self.history.first.is_some() { return Err(()); } self.construction_started = true;"#,
                    1,
                ),
                (
                    r#"drop(self.not_started.take()); let result = factory.begin_world("#,
                    1,
                ),
            ],
        },
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
    ],
};
