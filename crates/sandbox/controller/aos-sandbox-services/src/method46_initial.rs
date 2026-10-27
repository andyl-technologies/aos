//! Assembles the two fixed manual initial-floor service entrypoints.
//!
//! The genuine Source captures the initial descriptor table before configuration
//! work. The immutable profile, executing images, live policy, unit, stopped
//! owners and credentials are independently checked before the same Source lends
//! its main and provisioning originals to Security. Durable state selects fresh
//! approval or cold recovery; no argument, environment path or supplied observation
//! selects authority. Original custody survives through explicit process exit.

use std::panic::{AssertUnwindSafe, catch_unwind};

use aos_sandbox_broker::receiving::Method46InitialServiceRoleV1;
use aos_sandbox_broker_session_security::method46_initial_provisioning::{
    Method46InitialDataErrorV1, Method46InitialMainCutOriginalV1,
    Method46InitialProvisionDecodeOriginalV1,
};
use aos_sandbox_controller_domain::method46_initial_startup::{
    Method46InitialStartupClosedV1, Method46InitialStartupOriginalV1,
};

/// Runs the fixed Controller Storage-client manual service until process exit.
///
/// The authenticated original must name this Controller purpose. The selected
/// unit admits only its executable as argv, without a recovery mode or paths.
/// Standalone or unprovisioned invocation exits unsuccessfully before protected
/// initialization. Successful completion requires every original terminal post.
pub fn controller_main() -> ! {
    run(Method46InitialServiceRoleV1::ControllerStorageClient)
}

/// Runs the fixed Storage-broker manual service until process exit.
///
/// The authenticated original must name this Storage purpose. Normal Storage
/// startup cannot call this path to initialize its own missing floor. Failed
/// and successful native originals remain resident through explicit exit.
pub fn storage_main() -> ! {
    run(Method46InitialServiceRoleV1::StorageBroker)
}

fn run(role: Method46InitialServiceRoleV1) -> ! {
    let mut startup = Method46InitialStartupOriginalV1::new(role);
    let admission = catch_unwind(AssertUnwindSafe(|| admit_startup(&mut startup)));
    if !matches!(admission, Ok(Ok(()))) {
        // Keep a caught payload and every reached Source original resident.
        finish_and_exit(&startup, false);
    }

    let provision = catch_unwind(AssertUnwindSafe(|| {
        startup
            .lend_provisioning_readback_once_v1()
            .map(Method46InitialProvisionDecodeOriginalV1::decode_captured_v1)
    }));
    let provision = match provision {
        Ok(Ok(provision)) => provision,
        _ => finish_and_exit(&startup, false),
    };

    let main = catch_unwind(AssertUnwindSafe(|| {
        startup.capture_initial_main_writer_once_v1()?;
        startup.prepare_initial_floor_writer_once_v1()?;
        startup
            .lend_initial_main_readback_once_v1()
            .map(|readback| {
                Method46InitialMainCutOriginalV1::hash_and_validate_captured_v1(
                    readback, &provision,
                )
            })
    }));
    let main = match main {
        Ok(Ok(main)) => main,
        _ => finish_and_exit(&startup, false),
    };

    // These continuously borrowed owners outlive the body and Source posts.
    // Only the native actual process exits; no failed owner returns via Drop.
    let body = catch_unwind(AssertUnwindSafe(|| initialize(&provision, &main)));
    finish_and_exit(&startup, matches!(body, Ok(Ok(()))));
}

fn admit_startup(
    startup: &mut Method46InitialStartupOriginalV1,
) -> Result<(), Method46InitialStartupClosedV1> {
    startup.capture_before_arguments_once_v1()?;
    startup.measure_profile_once_v1()?;
    startup.decode_profile_once_v1()?;

    startup.measure_images_once_v1()?;
    startup.measure_runtime_inventory_once_v1()?;
    startup.measure_actual_runtime_mappings_once_v1()?;
    startup.observe_live_policy_once_v1()?;

    startup.observe_unit_once_v1()?;
    startup.observe_stopped_owner_units_once_v1()?;
    startup.measure_normal_runtime_inventory_once_v1()?;
    startup.observe_stopped_owner_cgroups_once_v1()?;
    startup.capture_credential_files_once_v1()?;
    startup.admit_approval_listener_once_v1()
}

fn initialize<'owner>(
    provision: &Method46InitialProvisionDecodeOriginalV1<'owner>,
    main: &Method46InitialMainCutOriginalV1<'owner>,
) -> Result<(), Method46InitialDataErrorV1> {
    provision.capture_initial_intent_files_once_v1(main)?;
    provision.approve_captured_initial_intent_once_v1(main)?;
    provision.publish_approved_initial_intent_once_v1(main)?;

    provision.prepare_approved_initial_tpm_locks_once_v1(main)?;
    provision.prepare_approved_initial_tpm_helper_once_v1(main)?;
    provision.reconcile_approved_initial_nv_once_v1(main)
}

fn finish_and_exit(startup: &Method46InitialStartupOriginalV1, body_succeeded: bool) -> ! {
    let body = if body_succeeded {
        Ok(())
    } else {
        Err(Method46InitialStartupClosedV1)
    };
    let after = catch_unwind(AssertUnwindSafe(|| {
        startup.finish_source_after_owed_once_v1(body)
    }));
    let success = body_succeeded && matches!(after, Ok(Ok(())));
    std::process::exit(if success { 0 } else { 1 });
}
