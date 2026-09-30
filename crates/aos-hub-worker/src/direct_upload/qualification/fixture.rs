//! Scoped candidate material for private qualification stages only.
//!
//! The fixture projects actual protected provider material into a distinct
//! reserved namespace. It creates no Native admission, quota reservation,
//! promotion permission or accepted runtime descriptor.

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::*;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use worker::Env;

use super::protocol::{Control, ObjectPlan, Original, Provider};
use crate::direct_upload::{
    authority::{MaterialProfile, StageAuthority},
    config::{self, ManagedCredentials},
    journal, provider_capacity,
};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Material {
    Managed {
        profile: DirectManagedR2Profile,
        policy: DirectPrivateStagePolicyRef,
    },
    External {
        profile: Box<DirectExternalStorageCapabilities>,
    },
}

pub(crate) struct Fixture<'a> {
    pub(crate) original: &'a Original,
    pub(crate) uncertainty: u64,
}

#[async_trait(?Send)]
impl StageAuthority for Fixture<'_> {
    fn latest_now(&self) -> Result<u64> {
        now()?
            .checked_add(self.uncertainty)
            .ok_or_else(|| anyhow::anyhow!("qualification clock overflow"))
    }

    fn maximum_object_bytes(&self) -> u64 {
        self.original.limits.maximum_object_bytes.get()
    }

    fn managed(&self, env: &Env) -> Result<(DirectManagedR2Profile, ManagedCredentials)> {
        let clock = env
            .var("HUB_DIRECT_UPLOAD_CLOCK_QUALIFICATION")?
            .to_string();
        let actual = config::managed_descriptor(env, &clock, self.uncertainty)?;
        ensure!(
            matches!(&self.original.material, Material::Managed {profile,..} if profile == &actual.0),
            "qualification managed material changed"
        );
        Ok(actual)
    }

    async fn protected_material(
        &self,
        env: &Env,
        placement: &DirectPlacement,
    ) -> Result<MaterialProfile> {
        ensure!(
            placement.protected_profile_digest == journal::digest(&self.original.material)?,
            "qualification material commitment changed"
        );
        match &self.original.material {
            Material::Managed { .. } => Ok(MaterialProfile::Managed {
                profile: self.managed(env)?.0,
            }),
            Material::External { profile } => {
                let actual = crate::external_object::resolve_external_profiles(
                    env,
                    &[profile.selector.clone()],
                )
                .await?;
                ensure!(
                    actual.len() == 1 && &actual[0] == profile.as_ref(),
                    "qualification external material changed"
                );
                Ok(MaterialProfile::External {
                    profile: profile.as_ref().clone(),
                })
            }
        }
    }
}

pub(crate) fn now() -> Result<u64> {
    Ok(u64::try_from(aos_hub_core::clock::now_unix_secs())?)
}

pub(crate) fn source() -> Result<String> {
    option_env!("AOS_HUB_WORKER_SOURCE_DIGEST")
        .filter(|source| valid_direct_digest(source))
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("qualification compiled source absent"))
}

pub(crate) fn uncertainty(env: &Env) -> Result<u64> {
    let uncertainty = config::integer(env, "HUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS")?.get();
    let policy = DirectClockPolicy {
        version: 1,
        mode: DirectClockPolicyMode::BoundedUtc,
        uncertainty_seconds: WireInteger::new(uncertainty),
    };
    ensure!(
        (1..30).contains(&uncertainty)
            && env.var("HUB_DIRECT_UPLOAD_CLOCK_MODE")?.to_string() == "bounded_utc"
            && env
                .var("HUB_DIRECT_UPLOAD_CLOCK_QUALIFICATION")?
                .to_string()
                == policy.commitment()?,
        "qualification installed clock policy differs"
    );
    Ok(uncertainty)
}

/// Checks the installed candidate controls against the immutable run original.
pub(crate) fn installed(env: &Env, original: &Original) -> Result<()> {
    let maximum = original.maximum_parallel_objects.get();
    ensure!(
        (2..=32).contains(&maximum)
            && config::qualification_limits(env)?.as_ref() == Some(&original.limits)
            && config::integer(env, "HUB_DIRECT_VERIFY_MAX_PARALLEL_OBJECTS")?
                == original.maximum_parallel_objects
            && env.var("HUB_DEPLOYMENT_ID")?.to_string() == original.deployment_id
            && env.var("HUB_DIRECT_UPLOAD_PUBLIC_ORIGIN")?.to_string() == original.public_origin
            && env.var("HUB_DIRECT_VERIFY_BULK_NAME")?.to_string() == original.bulk_queue_name
            && env.var("HUB_DIRECT_VERIFY_METADATA_NAME")?.to_string()
                == original.metadata_queue_name
            && config::queue_policy(env, "HUB_DIRECT_VERIFY_BULK", maximum - 1)?
                == original.bulk_queue_policy
            && config::queue_policy(env, "HUB_DIRECT_VERIFY_METADATA", maximum)?
                == original.metadata_queue_policy,
        "qualification installed candidate controls changed"
    );
    uncertainty(env)?;
    Ok(())
}

pub(crate) async fn original(
    env: &Env,
    control: &Control,
    provider: &Provider,
    objects: &[ObjectPlan],
) -> Result<Original> {
    let limits = config::qualification_limits(env)?
        .ok_or_else(|| anyhow::anyhow!("isolated qualification disabled"))?;
    let maximum_parallel_objects = config::integer(env, "HUB_DIRECT_VERIFY_MAX_PARALLEL_OBJECTS")?;
    ensure!(
        (2..=32).contains(&maximum_parallel_objects.get()),
        "qualification object capacity invalid"
    );
    provider_capacity::configure(u32::try_from(limits.maximum_provider_requests.get())?)?;
    let uncertainty = uncertainty(env)?;
    let material = match provider {
        Provider::Managed => {
            ensure!(
                !cfg!(feature = "do-e2e"),
                "emulator cannot qualify managed R2"
            );
            let clock = env
                .var("HUB_DIRECT_UPLOAD_CLOCK_QUALIFICATION")?
                .to_string();
            Material::Managed {
                profile: config::managed_descriptor(env, &clock, uncertainty)?.0,
                policy: config::managed_policy(env)?,
            }
        }
        Provider::External { selector } => {
            let mut profiles =
                crate::external_object::resolve_external_profiles(env, &[selector.clone()]).await?;
            ensure!(profiles.len() == 1, "qualification actual profile absent");
            let profile = profiles.remove(0);
            ensure!(
                profile
                    .staging_prefix
                    .split('/')
                    .any(|p| p == ".aos-direct-qualification"),
                "qualification external domain not isolated"
            );
            validate_direct_worker_external_execution(
                if cfg!(feature = "do-e2e") {
                    DirectWorkerExecutionKind::EmulatedExternal
                } else {
                    DirectWorkerExecutionKind::Hosted
                },
                &profile,
            )?;
            Material::External {
                profile: Box::new(profile),
            }
        }
    };
    let original = Original {
        version: 1,
        run_id: control.run_id.clone(),
        source_digest: source()?,
        script_version: config::runtime_script_version(env)?,
        provider: provider.clone(),
        objects: objects.to_vec(),
        deployment_id: env.var("HUB_DEPLOYMENT_ID")?.to_string(),
        public_origin: env.var("HUB_DIRECT_UPLOAD_PUBLIC_ORIGIN")?.to_string(),
        execution_kind: if cfg!(feature = "do-e2e") {
            DirectWorkerExecutionKind::EmulatedExternal
        } else {
            DirectWorkerExecutionKind::Hosted
        },
        bulk_queue_name: env.var("HUB_DIRECT_VERIFY_BULK_NAME")?.to_string(),
        metadata_queue_name: env.var("HUB_DIRECT_VERIFY_METADATA_NAME")?.to_string(),
        bulk_queue_policy: config::queue_policy(
            env,
            super::super::verification::BULK_QUEUE,
            maximum_parallel_objects.get() - 1,
        )?,
        metadata_queue_policy: config::queue_policy(
            env,
            super::super::verification::METADATA_QUEUE,
            maximum_parallel_objects.get(),
        )?,
        limits,
        maximum_parallel_objects,
        material,
        admission_expires_at: WireInteger::new(now()?.saturating_add(3600)),
        created_at_millis: WireInteger::new(worker::Date::now().as_millis()),
    };
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    for object in objects {
        ensure!(
            object.byte_size.get() <= original.limits.maximum_object_bytes.get(),
            "qualification source exceeds installed candidate ceiling"
        );
        admission(&original, object, &deployment)?;
    }
    Ok(original)
}

pub(crate) fn admission(
    original: &Original,
    object: &ObjectPlan,
    deployment: &str,
) -> Result<DirectUploadAdmission> {
    let fixture_prefix = format!(".aos-direct-qualification/{}", original.run_id);
    let digest = journal::digest(&original.material)?;
    let placement = match &original.material {
        Material::Managed { profile, policy } => {
            let credential = |purpose: &str| DirectCredentialRevision {
                purpose: purpose.into(),
                credential_id: profile.credential_id.clone(),
                generation: profile.credential_generation,
                secret_version_ref: profile.secret_version_ref.clone(),
                credential_fingerprint: profile.credential_fingerprint.clone(),
            };
            DirectPlacement {
                placement_id: WireInteger::new(1),
                placement_resource_version: WireInteger::new(1),
                write_spec_version: WireInteger::new(1),
                binding_id: WireInteger::new(1),
                binding_resource_version: WireInteger::new(1),
                binding_write_revision: WireInteger::new(1),
                final_key: format!("{fixture_prefix}/probe/{}", object.object_id),
                staging_prefix: format!("{fixture_prefix}/.aos-direct-upload"),
                private_stage_policy: policy.clone(),
                protected_profile_digest: digest,
                checksum_algorithm: profile.checksum_algorithm,
                physical: DirectPhysicalContext::DeploymentR2 {
                    deployment_id: deployment.into(),
                    bucket_namespace: profile.bucket_namespace.clone(),
                },
                write_credential: credential("write"),
                read_credential: credential("read"),
                presign_credential: credential("presign"),
            }
        }
        Material::External { profile } => {
            let association = &profile.selector.association;
            DirectPlacement {
                placement_id: WireInteger::new(1),
                placement_resource_version: WireInteger::new(1),
                write_spec_version: WireInteger::new(1),
                binding_id: WireInteger::new(u64::try_from(association.binding_id.get())?),
                binding_resource_version: WireInteger::new(u64::try_from(
                    association.binding_resource_version.get(),
                )?),
                binding_write_revision: WireInteger::new(u64::try_from(
                    association.binding_write_revision.get(),
                )?),
                final_key: format!(
                    "{}/probe/{}/{}",
                    profile.write_cohort.admitted_prefix, original.run_id, object.object_id
                ),
                staging_prefix: profile.staging_prefix.clone(),
                private_stage_policy: profile.private_stage_policy.clone(),
                protected_profile_digest: digest,
                checksum_algorithm: profile.checksum_algorithm,
                physical: DirectPhysicalContext::External {
                    write_cohort: Box::new(profile.write_cohort.clone()),
                    read_cohort: Box::new(profile.read_cohort.clone()),
                },
                write_credential: profile.selector.write_credential.clone(),
                read_credential: profile.selector.read_credential.clone(),
                presign_credential: profile.selector.presign_credential.clone(),
            }
        }
    };
    let actor_slot = DirectActorSlot {
        kind: DirectActorKind::ServiceAccount,
        numeric_id: WireInteger::new(1),
        incarnation: uuid::Uuid::from_slice(
            &hex::decode(journal::digest(&(
                &original.run_id,
                &object.object_id,
                "fixture-actor",
            ))?)?[..16],
        )?
        .to_string(),
    };
    let mut admission = DirectUploadAdmission {
        session_id: journal::digest(&(&original.run_id, &object.object_id, "private-source"))?,
        principal_id: actor_slot.principal_id(deployment)?,
        actor_slot,
        intent: DirectUploadIntent {
            version: 1,
            client_operation_id: journal::digest(&(&original.run_id, &object.object_id))?,
            target: DirectUploadTarget::CacheObject {
                cache_id: "isolated-qualification".into(),
                path: format!(
                    "{}.{}",
                    object.object_id,
                    if object.metadata { "narinfo" } else { "nar" }
                ),
            },
            expected_sha256: object.expected_sha256.clone(),
            byte_size: object.byte_size,
            part_size: object.part_size,
            dependency_phase: if object.metadata {
                DirectDependencyPhase::LeafMetadata
            } else {
                DirectDependencyPhase::Content
            },
            transfer_mode: DirectTransferMode::DirectRequired,
        },
        logical_fingerprint: String::new(),
        expires_at: original.admission_expires_at,
        placements: vec![placement],
    };
    admission.logical_fingerprint = admission.fingerprint(deployment)?;
    admission.validate(deployment)?;
    Ok(admission)
}

pub(crate) fn context(
    env: &Env,
    control: &Control,
    admission: &DirectUploadAdmission,
) -> Result<DirectRequestContext> {
    let issued = now()?;
    let origin = env.var("HUB_DIRECT_UPLOAD_PUBLIC_ORIGIN")?.to_string();
    let authority = url::Url::parse(&origin)?.authority().to_owned();
    Ok(DirectRequestContext {
        deployment_id: env.var("HUB_DEPLOYMENT_ID")?.to_string(),
        executor_public_origin: origin,
        public_authority: authority,
        foreground: DirectForegroundBudget {
            invocation_id: control.nonce.clone(),
            issued_at: WireInteger::new(issued),
            expires_at: control.expires_at,
        },
        request_nonce: control.nonce.clone(),
        request_body_sha256: journal::digest(&(control, &admission.session_id))?,
        public_method: "POST".into(),
        public_path: "/aos.hub.v1.DirectUploadService/BeginBatch".into(),
        issued_at: WireInteger::new(issued),
        expires_at: control.expires_at,
    })
}
