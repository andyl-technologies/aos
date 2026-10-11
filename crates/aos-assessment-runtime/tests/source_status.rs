//! Source availability is clock explicit and never modifies provider allowance.

use anyhow::Result;
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::source_status::{
    SourceAvailability, SourceBudgetWindow, SourceDelayCause, SourceStatus,
};

fn time(seconds: u64) -> Result<Timestamp> {
    Timestamp::from_unix_seconds(seconds)
}

fn budget() -> SourceBudgetWindow {
    SourceBudgetWindow {
        window_start: 172_800,
        window_seconds: 86_400,
        allowance: 2,
        consumed: 2,
        next_eligible_at: 0,
        circuit_until: 0,
    }
}

#[test]
fn exhausted_current_window_waits_for_its_exact_reset_without_refunding() -> Result<()> {
    let budget = budget();
    let before = budget.clone();
    assert_eq!(
        budget.availability(&time(172_900)?, &time(300_000)?)?,
        SourceAvailability::Waiting {
            retry_at: time(259_200)?,
            cause: SourceDelayCause::QuotaWindow
        }
    );
    assert_eq!(budget, before);
    Ok(())
}

#[test]
fn old_quota_windows_preserve_circuits_and_cooldowns() -> Result<()> {
    let mut budget = budget();
    budget.window_start = 86_400;
    budget.next_eligible_at = 173_100;
    budget.circuit_until = 173_300;
    assert_eq!(
        budget.availability(&time(172_900)?, &time(300_000)?)?,
        SourceAvailability::Waiting {
            retry_at: time(173_300)?,
            cause: SourceDelayCause::Circuit
        }
    );
    budget.circuit_until = 172_900;
    assert_eq!(
        budget.availability(&time(172_900)?, &time(300_000)?)?,
        SourceAvailability::Waiting {
            retry_at: time(173_100)?,
            cause: SourceDelayCause::SpacingOrCooldown
        }
    );
    assert_eq!(
        budget.availability(&time(173_100)?, &time(300_000)?)?,
        SourceAvailability::Eligible {}
    );
    assert_eq!(budget.consumed, 2);
    Ok(())
}

#[test]
fn authority_is_exclusive_and_must_last_through_the_next_reservation() -> Result<()> {
    let mut budget = budget();
    budget.consumed = 0;
    let now = time(172_900)?;
    assert_eq!(
        budget.availability(&now, &now)?,
        SourceAvailability::AuthorityUnavailable {}
    );
    budget.next_eligible_at = 173_000;
    assert_eq!(
        budget.availability(&now, &time(173_000)?)?,
        SourceAvailability::AuthorityUnavailable {}
    );
    assert!(matches!(
        budget.availability(&now, &time(173_001)?)?,
        SourceAvailability::Waiting { .. }
    ));
    Ok(())
}

#[test]
fn invalid_quota_facts_and_future_windows_never_become_eligible() -> Result<()> {
    for change in 0..4 {
        let mut budget = budget();
        match change {
            0 => budget.window_seconds = 0,
            1 => budget.allowance = 0,
            2 => budget.consumed = budget.allowance + 1,
            _ => budget.window_start = 172_901,
        }
        assert!(
            budget
                .availability(&time(172_900)?, &time(300_000)?)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn public_status_has_no_account_or_usage_and_refuses_invalid_retry_deadlines() -> Result<()> {
    let now = time(172_900)?;
    let mut status = SourceStatus {
        provider: "osv".into(),
        availability: SourceAvailability::Waiting {
            retry_at: time(173_000)?,
            cause: SourceDelayCause::SpacingOrCooldown,
        },
    };
    status.validate(&now)?;
    let value = serde_json::to_value(&status)?;
    assert_eq!(
        value.as_object().unwrap().keys().collect::<Vec<_>>(),
        ["availability", "provider"]
    );
    assert!(
        serde_json::from_value::<SourceStatus>(serde_json::json!({
            "provider":"osv", "availability":{"state":"eligible", "account":"private-account"}
        }))
        .is_err()
    );
    status.provider = "unknown-provider".into();
    assert!(status.validate(&now).is_err());
    status.provider = "osv".into();
    for deadline in [172_900, 259_361] {
        status.availability = SourceAvailability::Waiting {
            retry_at: time(deadline)?,
            cause: SourceDelayCause::Circuit,
        };
        assert!(status.validate(&now).is_err());
    }
    Ok(())
}
