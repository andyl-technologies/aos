//! Dispatches closed registry controls through the installed external writer.
//!
//! Companion parsing completes under the protected reader before this effect.
//! The existing per-key coordinator retains unknown PUTs and positive receipts;
//! neither the attached body nor provider credentials enter its journal.

use anyhow::{Context as _, Result, ensure};
use aos_hub_core::{
    storage_authority::external_object::{
        EXTERNAL_OBJECT_APPLICATION_DOMAIN, ExternalObjectOutcome, ExternalObjectRequest,
    },
    storage_work::{StorageBindingPublication, StorageWorkOperation, StorageWorkPlan},
};
use worker::Env;

use super::{config::configured, copy, executor, stage};

/// Writes one exact control after its storage-local semantic validation.
///
/// # Errors
/// Refuses another operation, missing installed writer, stale credential or
/// binding, expired lease, ambiguous provider effect or changed acknowledgement.
pub(crate) async fn put(
    env: &Env,
    plan: &StorageWorkPlan,
    publication: &StorageBindingPublication,
    control: &[u8],
    signal: &worker::web_sys::AbortSignal,
) -> Result<()> {
    ensure!(
        matches!(
            plan.operation,
            StorageWorkOperation::PutPreparedControl { .. }
        ),
        "prepared writer requires an exact control PUT"
    );
    aos_hub_core::storage_work::prepared_control::validate_body(&plan.operation, control)?;
    let object = configured(env)?.context("prepared writer object domain absent")?;
    ensure!(
        object.manages(&publication.snapshot)?,
        "prepared writer binding is unmanaged"
    );
    let copy = copy::config::configured(env, &object)?
        .context("prepared writer installed storage domain absent")?;
    let mut domains = copy.domains.iter().filter(|domain| {
        domain.write_cohort.association.binding_id.get() == plan.binding_id
            && domain.write_cohort.association.binding_stable_id
                == publication.snapshot.binding_stable_id
    });
    let domain = domains.next().context("prepared writer cohort absent")?;
    ensure!(domains.next().is_none(), "prepared writer cohort ambiguous");
    let cohort = &domain.write_cohort;
    ensure!(
        executor::select_cohort(
            &object,
            publication,
            "write",
            cohort.association.binding_write_revision.get()
        )? == cohort,
        "prepared writer current credential or association differs"
    );
    ensure!(
        plan.credential_references.contains(
            &aos_hub_core::storage_work::StorageCredentialSelector {
                purpose: "write".into(),
                generation: cohort.credential.generation.get(),
            }
        ),
        "prepared writer credential is outside its signed plan"
    );
    let lease = stage::acquire_configured_lease(
        env,
        &object,
        &domain.issuer_installation,
        cohort,
        &cohort.admitted_prefix,
    )
    .await?;
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let work = ExternalObjectRequest {
        version: 1,
        domain: EXTERNAL_OBJECT_APPLICATION_DOMAIN.into(),
        operation_id: plan.plan_id.clone(),
        binding_write_revision: cohort.association.binding_write_revision,
        plan: plan.clone(),
        lease,
    };
    work.validate(&deployment, object.clock().observed_at)?;
    publication
        .snapshot
        .authorizes(plan, &deployment, object.clock().observed_at)?;
    let result = executor::execute_authorized(
        env,
        object,
        work,
        publication,
        deployment,
        Some(signal.clone()),
        Some(control),
    )
    .await?;
    ensure!(
        matches!(result.outcome, ExternalObjectOutcome::PutAcknowledged),
        "prepared writer returned another effect"
    );
    Ok(())
}
