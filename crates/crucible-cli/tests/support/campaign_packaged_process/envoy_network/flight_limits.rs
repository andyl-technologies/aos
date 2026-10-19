//! Policy inputs shared by the five-node Envoy flights and their VM checks.
//!
//! The packaged VM check wraps each Envoy flight in an outer host-time
//! timeout. That timeout is not a horizon of its own: the check derives it
//! from `flight_limits.toml`, and this module keeps that file equal to the
//! constants the flight runs with, so the two cannot drift apart.
//!
//! ```toml
//! policy_virtual_time_ps = 30000000000000
//! stall_window_seconds = 600
//! minimum_virtual_ps_per_host_second = 1000000000
//! setup_floor_seconds = 3600
//!
//! [flights.network]
//! attempt_waits = 7
//! ```

use super::*;

const FLIGHT_LIMITS: &str = include_str!("flight_limits.toml");

/// Reads one non-negative integer at `path` in the parsed limits.
fn flight_limit(limits: &toml::Table, path: &[&str]) -> Result<u64, Box<dyn Error>> {
    let (key, tables) = path.split_last().ok_or("empty flight limit path")?;
    let mut table = limits;
    for name in tables {
        table = table
            .get(*name)
            .and_then(toml::Value::as_table)
            .ok_or_else(|| format!("flight limits omit table {name}"))?;
    }
    let value = table
        .get(*key)
        .and_then(toml::Value::as_integer)
        .ok_or_else(|| format!("flight limits omit integer {}", path.join(".")))?;

    Ok(u64::try_from(value)?)
}

#[test]
fn vm_timeout_inputs_match_the_envoy_flight_policy() -> Result<(), Box<dyn Error>> {
    let limits: toml::Table = toml::from_str(FLIGHT_LIMITS)?;

    assert_eq!(
        flight_limit(&limits, &["policy_virtual_time_ps"])?,
        ENVOY_POLICY_VIRTUAL_TIME_PS
    );
    assert!(flight_limit(&limits, &["stall_window_seconds"])? > 0);
    assert!(flight_limit(&limits, &["minimum_virtual_ps_per_host_second"])? > 0);
    assert!(flight_limit(&limits, &["setup_floor_seconds"])? > 0);
    for flight in ["network", "known-finding"] {
        assert!(flight_limit(&limits, &["flights", flight, "attempt_waits"])? > 0);
    }
    Ok(())
}
