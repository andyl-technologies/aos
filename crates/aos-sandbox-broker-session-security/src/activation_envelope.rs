//! Shared native activation-envelope and absolute-deadline observations.
//!
//! These functions adopt no descriptor, startup, peer, payer or service role.
//! Actual closed owners retain all authentication and before/after obligations.

use crate::ProductionBrokerSessionActivationErrorV1;

/// Checks the actual activation PID and expected descriptor count as DATA.
///
/// # Errors
/// Rejects absent or malformed inputs, invalid native values or an expired deadline.
pub fn validate_activation_process(
    expected_descriptors: usize,
) -> Result<(), ProductionBrokerSessionActivationErrorV1> {
    let listen_pid = environment_u32("LISTEN_PID")?;
    let current_pid = u32::try_from(rustix::process::getpid().as_raw_nonzero().get())
        .map_err(|_| ProductionBrokerSessionActivationErrorV1::Kernel)?;
    if listen_pid != current_pid {
        return Err(ProductionBrokerSessionActivationErrorV1::Activation(
            "LISTEN_PID does not name this process",
        ));
    }
    if usize::try_from(environment_u32("LISTEN_FDS")?)
        .map_err(|_| ProductionBrokerSessionActivationErrorV1::Kernel)?
        != expected_descriptors
    {
        return Err(ProductionBrokerSessionActivationErrorV1::Activation(
            "LISTEN_FDS has the wrong fixed count",
        ));
    }
    Ok(())
}

/// Reads bounded activation names without adopting any descriptor.
///
/// # Errors
/// Rejects absent or malformed inputs, invalid native values or an expired deadline.
pub fn activation_names(
    expected_descriptors: usize,
) -> Result<Vec<String>, ProductionBrokerSessionActivationErrorV1> {
    let names = std::env::var("LISTEN_FDNAMES").map_err(|_| {
        ProductionBrokerSessionActivationErrorV1::Activation("LISTEN_FDNAMES is absent")
    })?;
    let maximum_bytes = expected_descriptors.checked_mul(256).ok_or(
        ProductionBrokerSessionActivationErrorV1::Activation("activation name bound overflows"),
    )?;
    if names.len() > maximum_bytes
        || !names.is_ascii()
        || names.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ProductionBrokerSessionActivationErrorV1::Activation(
            "activation names exceed fixed bounds",
        ));
    }
    let names = names.split(':').map(str::to_owned).collect::<Vec<_>>();
    if names.len() != expected_descriptors || names.iter().any(String::is_empty) {
        return Err(ProductionBrokerSessionActivationErrorV1::Activation(
            "LISTEN_FDNAMES has the wrong fixed shape",
        ));
    }
    Ok(names)
}

fn environment_u32(name: &'static str) -> Result<u32, ProductionBrokerSessionActivationErrorV1> {
    std::env::var(name)
        .map_err(|_| {
            ProductionBrokerSessionActivationErrorV1::Activation("activation variable is absent")
        })?
        .parse()
        .map_err(|_| {
            ProductionBrokerSessionActivationErrorV1::Activation(
                "activation variable is not a decimal u32",
            )
        })
}

/// Samples the remaining absolute BOOTTIME interval as DATA.
///
/// # Errors
/// Rejects absent or malformed inputs, invalid native values or an expired deadline.
pub fn remaining_duration(
    deadline_boottime_nanoseconds: u64,
) -> Result<u64, ProductionBrokerSessionActivationErrorV1> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds =
        u64::try_from(now.tv_sec).map_err(|_| ProductionBrokerSessionActivationErrorV1::Kernel)?;
    let nanoseconds =
        u64::try_from(now.tv_nsec).map_err(|_| ProductionBrokerSessionActivationErrorV1::Kernel)?;
    let now = seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(ProductionBrokerSessionActivationErrorV1::Kernel)?;
    deadline_boottime_nanoseconds
        .checked_sub(now)
        .filter(|remaining| *remaining > 0)
        .ok_or(ProductionBrokerSessionActivationErrorV1::Deadline)
}

