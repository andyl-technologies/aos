//! Bounded notification coordination over exact SQL reviews and installed destinations.
//!
//! Queue messages and timer ticks merely wake this pass. It obtains a fresh
//! quota-backed claim, rechecks current reviewer authority, then delegates one
//! physical attempt. A failed or uncertain effect retains its lease and quota.

use anyhow::{ensure, Result};
use aos_assessment_runtime::notifications::{
    NotificationInstallationV1, NotificationWorkReceiptV1,
};
use aos_assessment_runtime::ports::RuntimeBounds;

use crate::db::{AssessmentNotificationPlacement, AssessmentNotificationWork, Database};

/// Executes one pinned notification attempt at the independently installed placement.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait AssessmentNotificationExecutor: RuntimeBounds {
    /// Returns compact physical facts without retaining the destination response body.
    ///
    /// Implementations pin the exact attempt before its first effect and recheck
    /// destination/key authority through their full physical timeout. Hybrid
    /// implementations use only their paired Worker and never fall back locally.
    ///
    /// # Errors
    /// Returns an error for revoked authority, uncertain/replayed attempts or unavailable transport.
    async fn execute(&self, work: &AssessmentNotificationWork)
        -> Result<NotificationWorkReceiptV1>;
}

/// Reports a finite notification pass without disclosing destination or exception text.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AssessmentNotificationPass {
    /// Number of due intents examined, including members already claimed by a digest.
    pub examined: u32,
    /// Number of physical attempt receipts committed under current authority.
    pub settled: u32,
    /// Number of intents deferred by unavailable placement, authority or transport.
    pub deferred: u32,
}

/// Claims and executes a bounded registry notification page under current SQL authority.
///
/// Concurrent passes cannot claim the same attempt. First digest claims pin
/// membership; subsequent member IDs in this page may be deferred harmlessly.
/// Installation confers neither user permissions nor subscription review authority.
///
/// # Errors
/// Returns an error for invalid installation/page bounds or unavailable journal enumeration.
pub async fn run_assessment_notification_pass<E: AssessmentNotificationExecutor>(
    db: &Database,
    registry_id: i64,
    installation: &NotificationInstallationV1,
    limit: u32,
    executor: &E,
) -> Result<AssessmentNotificationPass> {
    installation.validate()?;
    ensure!(
        (1..=10).contains(&limit),
        "notification controller page exceeds its bound"
    );
    db.reconcile_assessment_notifications(registry_id, limit)
        .await?;
    let due = db
        .assessment_notification_due_page(registry_id, limit)
        .await?;
    let mut pass = AssessmentNotificationPass {
        examined: due.len() as u32,
        ..Default::default()
    };
    for delivery in due {
        let result = execute_one(db, registry_id, &delivery, installation, executor).await;
        match result {
            Ok(()) => pass.settled += 1,
            Err(_) => pass.deferred += 1,
        }
    }
    Ok(pass)
}

async fn execute_one<E: AssessmentNotificationExecutor>(
    db: &Database,
    registry_id: i64,
    delivery_id: &str,
    installation: &NotificationInstallationV1,
    executor: &E,
) -> Result<()> {
    let (reference, digest) = db
        .assessment_notification_intent_destination(registry_id, delivery_id)
        .await?;
    let registry = db
        .registry_by_id(registry_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("notification registry is absent"))?;
    let route = installation
        .destinations
        .iter()
        .find(|route| {
            route.destination.resource_scope == registry.scope_key
                && route.destination.destination_reference == reference
                && route
                    .destination
                    .digest()
                    .is_ok_and(|installed| installed == digest)
        })
        .ok_or_else(|| {
            anyhow::anyhow!("notification destination is not independently installed")
        })?;
    let placement = AssessmentNotificationPlacement {
        deployment_id: installation.deployment_id.clone(),
        issuer: installation.coordinator_id.clone(),
        audience: installation.executor_id.clone(),
        budget_key: route.budget_key.clone(),
    };
    let work = db
        .claim_assessment_notification_work(
            registry_id,
            delivery_id,
            &placement,
            &route.destination,
        )
        .await?;
    db.check_assessment_notification_work(&work).await?;
    let receipt = executor.execute(&work).await?;
    db.admit_assessment_notification_receipt(&work, &receipt)
        .await
}
