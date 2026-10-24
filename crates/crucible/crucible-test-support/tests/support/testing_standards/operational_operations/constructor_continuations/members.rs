//! Binds the retained members continuation to its actual physical owner.

use super::{Contract, facts};

pub(super) const CONTRACT: Contract = Contract {
    package: "crucible-daemon",
    target: "src/qemu_lifecycle_launcher/target_construction",
    required: &[
        facts::MEMBERS.required[0],
        facts::MEMBERS.required[1],
        facts::MEMBERS.required[2],
        facts::MEMBERS.required[3],
        facts::MEMBERS.required[4],
        (
            r#"if row.entered { return Err(launcher_message("Target selected row was already entered").into()); }"#,
            1,
        ),
        (r#"let prepared = prepare()?; row.entered = true;"#, 1),
        (
            r#"row.permit = Some(permit); row.cleanup = Some(cleanup);"#,
            1,
        ),
        (
            r#"row.cleanup = Some(cleanup); row.first_admission = Some(first);"#,
            1,
        ),
        (r#"Instant::now("#, 0),
        (r#"thread::sleep("#, 0),
        (r#"HostOperationSupervisor::new("#, 0),
    ],
    expressions: &[],
    identifiers: &[(r#"retry_native_bodies"#, 1), (r#"retry_native_loans"#, 1)],
    companions: facts::TARGET_NATIVE,
};
