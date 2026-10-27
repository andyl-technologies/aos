//! Checks pure scheduling and conservative rounding before any native startup.

#![allow(
    clippy::unwrap_used,
    reason = "Pure configuration assertions intentionally panic on unexpected refusal."
)]

use super::*;

fn settings() -> LocalCollector {
    LocalCollector {
        lease_seconds: 300,
        poll_ms: 1_000,
        cycle_interval_ms: 60_000,
        mark_batch: 32,
        maintenance_batch: 8,
        deletion_seconds: 61,
    }
}

fn timing() -> LocalCommitTiming {
    LocalCommitTiming {
        maximum_ms: 30_001,
        grace_ms: 60_001,
        margin_ms: 10_000,
    }
}

#[test]
fn rounds_enforced_commit_and_grace_upward() {
    let settings = settings();
    settings.validate(&timing()).unwrap();
    let windows = settings.windows(&timing()).unwrap();

    assert_eq!(windows.commit(), 31);
    assert_eq!(windows.grace(), 61);
    assert_eq!(windows.deletion(), 61);
    assert_eq!(windows.retention(), 7_776_000);
}

#[test]
fn refuses_deletion_shorter_than_rounded_grace() {
    let mut settings = settings();
    settings.deletion_seconds = 60;

    assert!(settings.validate(&timing()).is_err());
}

#[test]
fn refuses_loss_of_strict_grace_after_rounding() {
    let timing = LocalCommitTiming {
        maximum_ms: 30_001,
        grace_ms: 30_999,
        margin_ms: 1,
    };
    timing.validated().unwrap();

    assert!(settings().windows(&timing).is_err());
}

#[test]
fn refuses_poll_at_half_lease_and_checked_overflows() {
    let mut settings = settings();
    settings.poll_ms = 150_000;
    settings.cycle_interval_ms = 150_000;
    assert!(settings.validate(&timing()).is_err());

    settings.poll_ms = 149_999;
    settings.validate(&timing()).unwrap();
    settings.lease_seconds = u64::MAX;
    assert!(settings.validate(&timing()).is_err());

    settings.lease_seconds = 300;
    settings.poll_ms = u64::MAX;
    assert!(settings.validate(&timing()).is_err());
}

#[test]
fn raises_registered_retention_for_long_enforced_windows() {
    let mut settings = settings();
    settings.deletion_seconds = 8_000_000;
    let timing = LocalCommitTiming {
        maximum_ms: 4_000_000_000,
        grace_ms: 8_000_000_000,
        margin_ms: 1_000,
    };

    let windows = settings.windows(&timing).unwrap();
    assert_eq!(windows.retention(), 12_000_000);
}

#[test]
fn rejects_collector_settings_without_repository_timing() {
    let input = r#"
role = "gc"
store = "bucket(file:///var/lib/terrane)"
[gc]
lease_seconds = 300
poll_ms = 1000
cycle_interval_ms = 60000
mark_batch = 32
maintenance_batch = 8
deletion_seconds = 86400
"#;

    assert!(matches!(
        crate::config::Config::parse(input),
        Err(ConfigError::Invalid(
            "local collector settings require trusted local repository timing"
        ))
    ));

    let trusted = r#"
[local_repository]
authority_directory = "/var/lib/terrane-authority"
issuer = "operator"
key_id = "current"
owner_uid = 840
store_name = "local"
domain = "private:owner"
default_private_domain = "private:owner"
current_reference = "refs/heads/_/main"
acl = []
[local_repository.timing]
maximum_ms = 30001
grace_ms = 60001
margin_ms = 10000
"#;
    let complete = format!("{input}\n{trusted}");
    let config = crate::config::Config::parse(&complete).unwrap();
    let settings = config.gc().unwrap();
    assert_eq!(settings.lease_seconds, 300);
    let windows = settings
        .windows(&config.local_repository().unwrap().timing)
        .unwrap();
    assert_eq!(windows.commit(), 31);
    assert_eq!(windows.grace(), 61);
    assert_eq!(windows.deletion(), 86_400);

    let unknown = complete.replace("mark_batch = 32", "mark_batch = 32\nunsafe_skip_age = true");
    assert!(matches!(
        crate::config::Config::parse(&unknown),
        Err(ConfigError::Toml(_))
    ));
}
