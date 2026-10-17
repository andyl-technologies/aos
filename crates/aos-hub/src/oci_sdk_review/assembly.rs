//! Fresh assembly from exact independently retained observation and installed bytes.

use std::path::Path;

use anyhow::{ensure, Result};
use aos_hub_core::{
    direct_upload::{
        direct_private_stage_policy_commitment, direct_qualification_digest,
        DirectPrivateStagePolicyRef,
    },
    oci_sdk_emulation::{
        OciSdkAcceptanceExecution, OciSdkAcceptancePurpose, OciSdkEmulationArtifact,
        OciSdkEmulationEvidence, OciSdkEmulationProfile, OciSdkInstallation,
        OciSdkObservationScope,
    },
};
use serde_json::Value;

use super::{
    anchor, clock, files,
    observations::{Namespace, Native},
    selection::{OciSdkObservedOperationScope, OciSdkReviewCandidate, OciSdkReviewSelection},
};

fn binding<'a>(configuration: &'a Value, name: &str) -> Result<&'a str> {
    configuration
        .get("bindings")
        .and_then(|bindings| bindings.get(name))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("OCI installed binding absent or malformed"))
}

pub(super) fn assemble(selection_file: &Path, now: u64) -> Result<OciSdkReviewCandidate> {
    let bytes = files::private_bytes(selection_file, files::DOCUMENT_LIMIT)?;
    let selected: OciSdkReviewSelection = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("OCI selection is not a closed supported format"))?;
    let base = selection_file.parent().unwrap_or(Path::new("."));
    ensure!(
        selected.version == 1 && selected.issued_at <= now && now < selected.expires_at,
        "OCI selection original version or cutoff differs"
    );
    selected.clock_policy.commitment()?;
    let namespace: Namespace = files::document(base, &selected.namespace_observation)?;
    let native: Native = files::document(base, &selected.native_observation)?;
    let public = files::public_key(&files::selected_bytes(base, &selected.reviewer_public_key)?)?;
    let native_configuration = files::selected_bytes(base, &selected.native_configuration)?;
    let native_configuration_shape: super::native::Configuration =
        serde_json::from_slice(&native_configuration)?;
    ensure!(
        native_configuration_shape.version == 1
            && native_configuration_shape.process_id == native.process_id
            && native_configuration_shape.start_ticks == native.start_ticks,
        "OCI retained Native private configuration differs"
    );
    let configuration_bytes = files::selected_bytes(base, &selected.installed.configuration)?;
    let configuration = serde_json::from_slice::<super::json::UniqueJson>(&configuration_bytes)?.0;
    let control_key = files::private_bytes(&base.join(&selected.conformance_key_file), 4096)?;
    let control_key = std::str::from_utf8(&control_key)
        .map_err(|_| anyhow::anyhow!("OCI control key malformed"))?
        .trim();
    ensure!(
        control_key.len() >= 32
            && binding(&configuration, "HUB_DIRECT_UPLOAD_CONFORMANCE_KEY")? == control_key
            && binding(&configuration, "HUB_DIRECT_UPLOAD_JOURNAL_KEY")? != control_key,
        "OCI actual conformance key installation differs"
    );
    let wasm_size = files::selected_installed(base, &selected.installed.wasm)?;

    ensure!(
        namespace.version == 1
            && namespace.observation_scope == "oci_sdk_emulator_namespace_readback"
            && namespace.miniflare_version == "5.20260801.0-alpha"
            && namespace.runner_pid > 0
            && namespace.workerd_pid > 0
            && namespace.runner_start_ticks.get() > 0
            && namespace.workerd_start_ticks.get() > 0
            && namespace.source_store_path == selected.source_store_path.to_str().unwrap_or("")
            && namespace.build_derived_source_digest
                == files::digest(namespace.source_store_path.as_bytes())
            && namespace.build_derived_source_digest == selected.expected_source_digest
            && namespace.build_derived_script_version == selected.expected_script_version
            && namespace.wasm_byte_size.get() == wasm_size
            && namespace.wasm_sha256 == selected.installed.wasm.sha256
            && namespace.configuration_sha256 == selected.installed.configuration.sha256
            && namespace.runner_sha256 == selected.installed.runner.sha256
            && namespace.shim_sha256 == selected.installed.shim.sha256
            && namespace.miniflare_module_sha256 == selected.installed.miniflare_module.sha256
            && namespace.miniflare_entry_worker_sha256
                == selected.installed.miniflare_entry_worker.sha256
            && namespace.miniflare_bucket_worker_sha256
                == selected.installed.miniflare_bucket_worker.sha256
            && namespace.workerd_executable_sha256 == selected.installed.workerd_executable.sha256,
        "OCI actual namespace, source or installed bytes differ"
    );
    for file in [
        &selected.installed.native_executable,
        &selected.installed.shim,
        &selected.installed.runner,
        &selected.installed.miniflare_module,
        &selected.installed.miniflare_entry_worker,
        &selected.installed.miniflare_bucket_worker,
        &selected.installed.workerd_executable,
        &selected.installed.nix_executable,
    ] {
        files::selected_installed(base, file)?;
    }
    ensure!(
        native.version == 1
            && native.observation_scope == "oci_sdk_native_process_readback"
            && native.process_id > 0
            && native.start_ticks.get() > 0
            && native.observed_at > 0
            && native.observed_at <= selected.issued_at
            && selected.issued_at - native.observed_at <= 3600
            && native.executable_sha256 == selected.installed.native_executable.sha256
            && native.configuration_sha256 == files::digest(&native_configuration),
        "OCI actual Native process/executable observation differs"
    );
    let namespace_time = anchor::utc_millis(&namespace.observed_at)? / 1000;
    ensure!(
        namespace_time > 0
            && namespace_time <= selected.issued_at
            && selected.issued_at - namespace_time <= 3600,
        "OCI namespace observation time differs"
    );

    // These private configuration checks are installation facts, not provider
    // readiness or a substitute for the live signed Clock/source response.
    ensure!(
        configuration
            .get("ociSdkAcceptanceRegistryKey")
            .and_then(Value::as_str)
            == Some(
                aos_hub_core::oci_sdk_emulation::oci_sdk_emulation_acceptance_key(
                    &selected.deployment_id,
                    &selected.expected_source_digest,
                    &selected.expected_script_version,
                )?
                .as_str()
            ),
        "OCI independently installed registry slot differs"
    );
    let bucket = configuration
        .get("r2Buckets")
        .and_then(|buckets| buckets.get("REGISTRY_BUCKET"))
        .ok_or_else(|| anyhow::anyhow!("OCI SDK attachment absent"))?;
    let bucket_id = bucket
        .as_str()
        .or_else(|| bucket.get("id").and_then(Value::as_str));
    ensure!(
        bucket_id == Some(namespace.namespace_id.as_str())
            && configuration.get("name").and_then(Value::as_str)
                == Some(namespace.worker_name.as_str())
            && configuration.get("scriptPath").and_then(Value::as_str)
                == base.join(&selected.installed.shim.path).to_str()
            && configuration
                .get("resourcePersistencePath")
                .and_then(Value::as_str)
                .is_some_and(|path| Path::new(path).join("r2").to_str()
                    == Some(namespace.persistence_root.as_str()))
            && binding(&configuration, "HUB_DEPLOYMENT_ID")? == selected.deployment_id
            && binding(&configuration, "HUB_HYBRID_ORIGIN_URL")? == selected.native_origin
            && binding(&configuration, "HUB_OCI_SDK_EMULATOR_ENABLED")? == "true"
            && binding(&configuration, "HUB_OCI_SDK_EMULATOR_PUBLIC_ORIGIN")?
                == selected.public_origin
            && binding(&configuration, "HUB_OCI_SDK_EMULATOR_REVIEWER_KEY_ID")?
                == selected.reviewer_key_id
            && binding(&configuration, "HUB_OCI_SDK_EMULATOR_REVIEWER_PUBLIC_KEY")? == public
            && binding(&configuration, "HUB_OCI_SDK_EMULATOR_MAX_PROVIDER_REQUESTS")?
                == selected.maximum_provider_requests.to_string()
            && binding(&configuration, "HUB_DIRECT_UPLOAD_CLOCK_MODE")? == "bounded_utc"
            && binding(
                &configuration,
                "HUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS"
            )? == selected.clock_policy.uncertainty_seconds.get().to_string()
            && binding(&configuration, "HUB_DIRECT_UPLOAD_CLOCK_QUALIFICATION")?
                == selected.clock_policy.commitment()?,
        "OCI independently installed configuration differs"
    );
    ensure!(
        base.join(&selected.installed.wasm.path).parent()
            == Some(selected.distribution_store_path.as_path())
            && base.join(&selected.installed.shim.path).parent()
                == Some(selected.distribution_store_path.as_path()),
        "OCI actual distribution attachment differs"
    );
    files::nar_hash(
        &base.join(&selected.installed.nix_executable.path),
        &selected.source_store_path,
        &selected.source_nar_sha256,
    )?;
    files::nar_hash(
        &base.join(&selected.installed.nix_executable.path),
        &selected.distribution_store_path,
        &selected.distribution_nar_sha256,
    )?;

    let clock = clock::assemble(base, &selected)?;
    let (anchor, sdk_observation_sha256) = anchor::assemble(base, &selected)?;
    let profile = OciSdkEmulationProfile {
        deployment_id: selected.deployment_id.clone(),
        public_origin: selected.public_origin.clone(),
        native_origin: selected.native_origin.clone(),
        worker_source_digest: selected.expected_source_digest.clone(),
        worker_script_version: selected.expected_script_version.clone(),
        worker_name: namespace.worker_name.clone(),
        binding_name: namespace.binding_name.clone(),
        namespace_id: namespace.namespace_id.clone(),
        namespace_object_id: namespace.namespace_object_id.clone(),
        namespace_unique_key: namespace.namespace_unique_key.clone(),
        clock_policy: selected.clock_policy.clone(),
        maximum_provider_requests: selected.maximum_provider_requests,
        private_stage_policy: DirectPrivateStagePolicyRef {
            policy_id: selected.private_stage_policy_id.clone(),
            namespace: namespace.namespace_id.clone(),
            policy_digest: direct_private_stage_policy_commitment(
                &selected.private_stage_policy_id,
                &namespace.namespace_id,
            )?,
        },
        anchor: anchor.clone(),
    };
    let evidence = OciSdkEmulationEvidence {
        sdk_observation_scope: OciSdkObservationScope::AnchorCreateAndConditionalRead,
        installation: OciSdkInstallation {
            namespace_observation_sha256: selected.namespace_observation.sha256,
            native_observation_sha256: selected.native_observation.sha256,
            observed_at: namespace_time.min(native.observed_at),
            native_executable_sha256: native.executable_sha256,
            native_configuration_sha256: native.configuration_sha256,
            source_nar_sha256: selected.source_nar_sha256,
            distribution_nar_sha256: selected.distribution_nar_sha256,
            wasm_sha256: namespace.wasm_sha256,
            wasm_byte_size: wasm_size,
            shim_sha256: namespace.shim_sha256,
            runner_sha256: namespace.runner_sha256,
            configuration_sha256: namespace.configuration_sha256,
            miniflare_module_sha256: namespace.miniflare_module_sha256,
            miniflare_entry_worker_sha256: namespace.miniflare_entry_worker_sha256,
            miniflare_bucket_worker_sha256: namespace.miniflare_bucket_worker_sha256,
            workerd_executable_sha256: namespace.workerd_executable_sha256,
            worker_source_digest: namespace.build_derived_source_digest,
            worker_script_version: namespace.build_derived_script_version,
            worker_name: namespace.worker_name,
            binding_name: namespace.binding_name,
            namespace_id: namespace.namespace_id,
            namespace_object_id: namespace.namespace_object_id,
            namespace_unique_key: namespace.namespace_unique_key,
        },
        clock,
        sdk_observation_sha256,
        anchor,
        // Only the two observed anchor operations are counted, both positively
        // completed before the retained anchor cutoff. Business expiry is not measured.
        expired_effects: 0,
    };
    let artifact = OciSdkEmulationArtifact {
        version: 1,
        purpose: OciSdkAcceptancePurpose::OciDocuments,
        execution_kind: OciSdkAcceptanceExecution::EmulatedManagedSdk,
        reviewer_key_id: selected.reviewer_key_id,
        profile,
        evidence_sha256: direct_qualification_digest(&evidence)?,
        evidence,
        issued_at: selected.issued_at,
        expires_at: selected.expires_at,
        signature: String::new(),
    };
    artifact.validate_unsigned(
        &artifact.profile.deployment_id,
        &artifact.profile.public_origin,
        now,
    )?;
    ensure!(
        files::private_bytes(selection_file, files::DOCUMENT_LIMIT)?.as_slice() == bytes.as_slice(),
        "OCI private selection changed during assembly"
    );
    Ok(OciSdkReviewCandidate {
        version: 1,
        selection_sha256: files::digest(&bytes),
        trusted_public_key: public,
        observed_operation_scope: OciSdkObservedOperationScope::AnchorCreateAndConditionalRead,
        artifact,
    })
}
