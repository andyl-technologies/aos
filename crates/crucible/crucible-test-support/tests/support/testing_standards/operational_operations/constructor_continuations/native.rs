//! Binds the retained native continuation to its actual physical owner.

use super::{Companion, Contract, facts};

pub(super) const CONTRACT: Contract = Contract {
    package: "crucible-daemon",
    target: "src/qemu_campaign_lifecycle/source_construction/native_observation",
    required: &[
        (
            r#"match prepared.service_main_handle().retry_prepared_body() { Ok(true) => Ok(()),"#,
            1,
        ),
        (
            r#"let mut retirement = prepared.clone().into_retirement(); match retirement.retry() { Ok(true) => {} result => { return Err(NativeObservationRetirementError::Pending { retirement, refusal: result.err(), }); } }"#,
            1,
        ),
        (
            r#"Ok(body) if body.first_failure().is_none() => { drop(body); Ok(()) }"#,
            1,
        ),
        (
            r#"Ok(body) => Err(NativeObservationRetirementError::Terminal(std::sync::Mutex::new(body),)),"#,
            1,
        ),
        (
            r#"Err(retirement) => Err(NativeObservationRetirementError::Pending { retirement, refusal: None, }),"#,
            1,
        ),
        (r#"Instant::now("#, 0),
        (r#"thread::sleep("#, 0),
        (r#"HostOperationSupervisor::new("#, 0),
    ],
    expressions: &[
        (r#"prepared.service_main_handle().retry_prepared_body()"#, 1),
        (r#"retirement.retry()"#, 1),
    ],
    identifiers: &[
        (r#"retry"#, 1),
        (r#"retry_native_observation_body"#, 1),
        (r#"retry_prepared_body"#, 1),
    ],
    companions: &[
        facts::MAIN_RETIREMENT,
        facts::BODY_DRIVER,
        Companion {
            path: "crates/crucible/crucible-daemon/src/lifecycle_cleanup/prepared_service.rs",
            required: &[(
                r#"if slot.epoch.load(Ordering::Acquire) != self.key.epoch || prepared.epoch != self.key.epoch || !(slot.is(CleanupPhase::Reserved) || slot.is(CleanupPhase::RetryingPrepared)) || prepared.owner.is_none() || prepared.post_body_taken { return Err(unavailable("same prepared body is stale, transferred or terminal",)); } slot.request_retirement(); super::prepared_driver::retry_body_in_place(slot, &mut prepared).map_err(ServiceMainPreclaimError::Role)?; Ok(prepared.body_closed)"#,
                1,
            )],
        },
    ],
};
