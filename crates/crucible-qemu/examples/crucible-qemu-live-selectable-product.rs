//! Certifies a real product guest's typed choices across exact QEMU restore.
//!
//! Positional arguments are
//! `QEMU PLUGIN KERNEL FIRMWARE INITRD RUN_DIRECTORY`. Optional tuning:
//!
//! ```text
//! CRUCIBLE_SELECTABLE_PRODUCT_CEILING
//! CRUCIBLE_SELECTABLE_PRODUCT_TIMEOUT_SECS
//! ```

#[cfg(target_os = "linux")]
use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::env;
#[cfg(target_os = "linux")]
use std::error::Error;
#[cfg(target_os = "linux")]
use std::process::ExitCode;
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
use crucible_campaign::{
    AlternativeId, CampaignHash, ChoiceDomain, ChoiceValue, DiscreteAlternative, DiscreteDomain,
    ExactRational, IntegerDomain, IntegerRepresentation, IntegerValue,
};
#[cfg(target_os = "linux")]
use crucible_protocol::SelectionReply;
#[cfg(target_os = "linux")]
use crucible_protocol::selectable_catalog_plan::{
    SelectableCatalogPlan, SelectablePlanContinuation, SelectablePlanDeclaration,
    SelectablePlanLimits, SelectablePlanPresence,
};
#[cfg(target_os = "linux")]
use crucible_qemu::{
    QemuLaunchPluginSwitch, QemuLiveNodeStepGateConfig,
    run_qemu_live_selectable_product_snapshot_gate,
};

#[cfg(target_os = "linux")]
const RECOVERY_SELECTABLE: &str = "network.recovery-policy";
#[cfg(target_os = "linux")]
const RETRY_SELECTABLE: &str = "network.retry-quanta";
#[cfg(target_os = "linux")]
const SELECTED_PRODUCT_PAYLOAD: &[u8] = b"crucible-selected-fast-q7";

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("crucible-qemu-live-selectable-product: {error}");
            let mut source = error.source();
            while let Some(cause) = source {
                eprintln!("caused by: {cause}");
                source = cause.source();
            }
            ExitCode::FAILURE
        }
    }
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os();
    let program = args
        .next()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| String::from("crucible-qemu-live-selectable-product"));
    let qemu = required_arg(&mut args, &program)?;
    let plugin = required_arg(&mut args, &program)?;
    let kernel = required_arg(&mut args, &program)?;
    let firmware = required_arg(&mut args, &program)?;
    let initrd = required_arg(&mut args, &program)?;
    let run_directory = required_arg(&mut args, &program)?;
    if args.next().is_some() {
        return Err(usage(&program).into());
    }

    let (plan, first_reply, second_reply) = product_catalog_and_replies()?;
    let config = QemuLiveNodeStepGateConfig::new(qemu, plugin, kernel, firmware, run_directory)
        .with_initrd(initrd)
        .with_kernel_cmdline("console=ttyS0 reboot=k panic=1")
        .with_vm_shape(128, 1, 0)
        .with_whitebox(QemuLaunchPluginSwitch::On)
        .with_console_capture()
        .with_shmem_network_mac("02:00:00:00:00:02")
        .with_selectable_catalog_plan(plan)
        .with_completion_timeout(Duration::from_secs(env_u64(
            "CRUCIBLE_SELECTABLE_PRODUCT_TIMEOUT_SECS",
            900,
        )?));
    let report = run_qemu_live_selectable_product_snapshot_gate(
        &config,
        RECOVERY_SELECTABLE,
        &first_reply,
        RETRY_SELECTABLE,
        &second_reply,
        SELECTED_PRODUCT_PAYLOAD,
        env_u64("CRUCIBLE_SELECTABLE_PRODUCT_CEILING", 8_000_000_000)?,
    )?;

    println!("PASS");
    println!("gate=gate:typed-choice-product-checkpoint");
    println!("guest=real-network-product-initramfs");
    println!("first_selectable={}", report.first_selectable);
    println!("second_selectable={}", report.second_selectable);
    println!("capture_icount={}", report.capture_icount);
    println!("restored_pending_exact={}", report.restored_pending_exact);
    println!(
        "durable_envelope_round_trip={}",
        report.durable_envelope_round_trip
    );
    println!("completed_requests={}", report.completed_requests);
    println!("selected_value=discrete-fast,integer-7");
    println!("selected_frame=crucible-selected-fast-q7");
    println!("selected_frame_icount={}", report.selected_frame_icount);
    println!(
        "source_process_force_crashed={}",
        report.source_process_force_crashed
    );
    println!("orderly_child_exit={}", report.orderly_child_exit);
    Ok(())
}

#[cfg(target_os = "linux")]
fn product_catalog_and_replies()
-> Result<(SelectableCatalogPlan, SelectionReply, SelectionReply), Box<dyn Error>> {
    let fast = AlternativeId::from_hash(CampaignHash::from_bytes([1; 32]));
    let safe = AlternativeId::from_hash(CampaignHash::from_bytes([2; 32]));
    let recovery_domain = ChoiceDomain::Discrete(DiscreteDomain::new(
        1,
        BTreeMap::from([
            (fast, DiscreteAlternative::new(fast, "fast", None)?),
            (safe, DiscreteAlternative::new(safe, "safe", None)?),
        ]),
    )?);
    let retry_domain = ChoiceDomain::Integer(IntegerDomain::new(
        1,
        IntegerRepresentation::Unsigned64,
        IntegerValue::Unsigned(1),
        IntegerValue::Unsigned(9),
        2,
        Some(String::from("quanta")),
        ExactRational::new(1, 1)?,
        Vec::new(),
    )?);
    let declarations = vec![
        SelectablePlanDeclaration::new(
            RECOVERY_SELECTABLE,
            recovery_domain.canonical_bytes(),
            ChoiceValue::Discrete(safe).canonical_bytes(),
            Vec::new(),
            SelectablePlanPresence::Required,
        )?,
        SelectablePlanDeclaration::new(
            RETRY_SELECTABLE,
            retry_domain.canonical_bytes(),
            ChoiceValue::Integer(IntegerValue::Unsigned(3)).canonical_bytes(),
            Vec::new(),
            SelectablePlanPresence::Required,
        )?,
    ];
    let plan = SelectableCatalogPlan::new(
        SelectablePlanLimits::new(2, 1, 2)?,
        declarations,
        SelectablePlanContinuation::cold(),
    )?;

    let recovery_domain_id = recovery_domain.id()?.content_id().digest();
    let retry_domain_id = retry_domain.id()?.content_id().digest();
    let first_reply = SelectionReply::selected(
        1,
        CampaignHash::derive("crucible.live-product-opportunity.v1", b"recovery").as_bytes(),
        recovery_domain_id,
        ChoiceValue::Discrete(fast).canonical_bytes(),
    )?;
    let second_reply = SelectionReply::selected(
        2,
        CampaignHash::derive("crucible.live-product-opportunity.v1", b"retry").as_bytes(),
        retry_domain_id,
        ChoiceValue::Integer(IntegerValue::Unsigned(7)).canonical_bytes(),
    )?;
    Ok((plan, first_reply, second_reply))
}

#[cfg(target_os = "linux")]
fn required_arg(
    args: &mut impl Iterator<Item = std::ffi::OsString>,
    program: &str,
) -> Result<std::ffi::OsString, String> {
    args.next().ok_or_else(|| usage(program))
}

#[cfg(target_os = "linux")]
fn env_u64(name: &str, default: u64) -> Result<u64, String> {
    match env::var(name) {
        Ok(value) => value
            .parse::<u64>()
            .map_err(|_error| format!("{name} must be an unsigned 64-bit integer")),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(format!("cannot read {name}: {error}")),
    }
}

#[cfg(target_os = "linux")]
fn usage(program: &str) -> String {
    format!("usage: {program} QEMU PLUGIN KERNEL FIRMWARE INITRD RUN_DIRECTORY")
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("crucible-qemu-live-selectable-product requires Linux");
}
