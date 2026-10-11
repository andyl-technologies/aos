//! Package-owned platform detection and metadata acquisition ability handler.
//!
//! The provider receives exact native executables through checked method
//! parameters. Mounted media and fetched bytes remain private to one invocation;
//! only typed operation results cross into the generic authorization provider.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::AbilityValue;
use aos_net::{BootstrapLinkSelector, BootstrapNetwork};
use serde::Deserialize;
use tempfile::Builder;

use crate::detect::{AcquisitionContext, PlatformId, detect};
use crate::executable::resolve_executable;
use crate::mount::BlkidProbe;
use crate::native_handler::{read_invocation, write_response};
use crate::{AcquiredMetadata, DetectedPlatform, fetch_metadata};

const ACQUIRED_METADATA_SCHEMA: &str = "aos.metadata.acquired-provisioning-input/v1";
const DETECTED_PLATFORM_SCHEMA: &str = "aos.metadata.provisioning-platform/v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DetectionParameters {
    blkid: String,
    mount: String,
    umount: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcquisitionParameters {
    platform: DetectedPlatform,
    blkid: String,
    mount: String,
    umount: String,
}

#[derive(Debug)]
struct NativeTools {
    blkid: PathBuf,
    mount: PathBuf,
    umount: PathBuf,
}

impl NativeTools {
    fn resolve(blkid: &str, mount: &str, umount: &str) -> Result<Self> {
        Ok(Self {
            blkid: resolve_executable(blkid)?,
            mount: resolve_executable(mount)?,
            umount: resolve_executable(umount)?,
        })
    }
}

/// Executes one native detection or acquisition operation from stdin.
///
/// # Errors
/// Returns an error for invalid invocation data, mutable executable paths,
/// unavailable platforms, or failed metadata acquisition and media cleanup.
pub async fn run_provider_from_process() -> Result<()> {
    let (purpose, invocation) = read_invocation()?;
    let operation = invocation
        .effect
        .identity
        .iter()
        .rev()
        .nth(1)
        .context("metadata operation identity is missing")?;
    ensure!(
        matches!(operation.as_str(), "detect" | "acquire"),
        "unknown metadata operation"
    );
    let output = match purpose.as_str() {
        "remove" => serde_json::json!({}),
        "observe" if invocation.action == aos_ability_runtime::activation::Action::Remove => {
            serde_json::json!({"status":"absent"})
        }
        "observe" => serde_json::json!({"status":"retry-safe"}),
        _ if operation == "detect" => {
            let parameters: DetectionParameters = serde_json::from_value(invocation.input)?;
            let tools =
                NativeTools::resolve(&parameters.blkid, &parameters.mount, &parameters.umount)?;
            let platform = detect_platform(&tools)?;
            serde_json::json!({"need_network":platform.need_network,"platform":platform})
        }
        _ => {
            let parameters: AcquisitionParameters = serde_json::from_value(invocation.input)?;
            let tools =
                NativeTools::resolve(&parameters.blkid, &parameters.mount, &parameters.umount)?;
            let (acquired, network_bootstrap) = acquire(&parameters.platform, &tools).await?;
            serde_json::json!({"acquired_metadata":acquired,"network_bootstrap":network_bootstrap})
        }
    };
    write_response(&output)
}

fn detect_platform(tools: &NativeTools) -> Result<DetectedPlatform> {
    let scratch = Builder::new().prefix("aos-metadata-detection-").tempdir()?;
    let context = detect_environment(scratch.path().join("media"), tools)?;
    let platform = detected_platform(&context);
    finish_config_drive(&context, tools, platform)
}

async fn acquire(
    expected_platform: &DetectedPlatform,
    tools: &NativeTools,
) -> Result<(AcquiredMetadata, Option<AbilityValue>)> {
    validate_detected_platform(expected_platform)?;
    let scratch = Builder::new()
        .prefix("aos-metadata-acquisition-")
        .tempdir()?;
    let context = detect_environment(scratch.path().join("media"), tools)?;
    let actual_platform = detected_platform(&context);
    let actual_platform = match actual_platform {
        Ok(platform) => platform,
        Err(error) => return finish_config_drive(&context, tools, Err(error)),
    };

    let outcome: Result<(AcquiredMetadata, Option<AbilityValue>)> = async {
        ensure!(
            actual_platform == *expected_platform,
            "metadata platform changed after the checked detection operation"
        );
        let fetched = fetch_metadata(&context).await?;
        let facts = fetched.facts;
        let network_bootstrap = facts
            .network
            .as_ref()
            .filter(|network| network.is_seedable())
            .map(network_bootstrap)
            .transpose()?;
        Ok((
            AcquiredMetadata {
                schema: ACQUIRED_METADATA_SCHEMA.into(),
                platform_id: actual_platform.platform_id,
                host_module: fetched.host_module,
                host_module_signature: fetched.host_module_signature,
                facts,
            },
            network_bootstrap,
        ))
    }
    .await;
    finish_config_drive(&context, tools, outcome)
}

fn detect_environment(mountpoint: PathBuf, tools: &NativeTools) -> Result<AcquisitionContext> {
    detect(
        Path::new("/"),
        &BlkidProbe::with_tools(&tools.blkid, &tools.mount),
        &mountpoint,
    )
}

fn detected_platform(context: &AcquisitionContext) -> Result<DetectedPlatform> {
    let platform = DetectedPlatform {
        schema: DETECTED_PLATFORM_SCHEMA.into(),
        platform_id: context.platform.as_str().into(),
        need_network: context.needs_network(),
    };
    validate_detected_platform(&platform)?;
    Ok(platform)
}

/// Validates a platform result against the package-owned platform model.
///
/// # Errors
///
/// Returns an error when the schema or identifier is unknown or the network
/// requirement differs from the selected platform capability.
pub fn validate_detected_platform(platform: &DetectedPlatform) -> Result<()> {
    ensure!(
        platform.schema == DETECTED_PLATFORM_SCHEMA,
        "unsupported metadata platform result"
    );
    let selected = PlatformId::parse(&platform.platform_id)?;
    ensure!(
        platform.need_network
            == matches!(
                selected.capability(),
                crate::detect::PlatformCapability::NetworkMetadata
            ),
        "metadata platform network requirement is inconsistent"
    );
    Ok(())
}

fn finish_config_drive<T>(
    context: &AcquisitionContext,
    tools: &NativeTools,
    outcome: Result<T>,
) -> Result<T> {
    let cleanup = if let Some(directory) = &context.metadata_dir {
        let status = Command::new(&tools.umount)
            .arg(directory)
            .env_clear()
            .status()
            .context("unmounting metadata config drive")?;
        ensure!(status.success(), "metadata config-drive unmount failed");
        Ok(())
    } else {
        Ok(())
    };
    match (outcome, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup_error)) => Err(error.context(format!(
            "config-drive cleanup also failed: {cleanup_error:#}"
        ))),
    }
}

fn network_bootstrap(network: &crate::fetcher::StaticNetwork) -> Result<AbilityValue> {
    let selector = if let Some(mac) = network
        .mac
        .as_ref()
        .filter(|mac| crate::fetcher::is_canonical_mac(mac))
    {
        BootstrapLinkSelector::Mac(mac.clone())
    } else if let Some(name) = network
        .interface_name
        .as_ref()
        .filter(|name| crate::fetcher::is_exact_interface_name(name))
    {
        BootstrapLinkSelector::Name(name.clone())
    } else {
        bail!("seedable metadata network has no exact link selector")
    };

    BootstrapNetwork {
        selector,
        addresses: network.addresses.clone(),
        gateway: network.gateway.clone(),
        dns: network.dns.clone(),
    }
    .into_ability_value()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detected_platform_binds_network_requirement() {
        let cloud = DetectedPlatform {
            schema: DETECTED_PLATFORM_SCHEMA.into(),
            platform_id: "aws".into(),
            need_network: true,
        };
        validate_detected_platform(&cloud).expect("cloud platform");
        let inconsistent = DetectedPlatform {
            need_network: false,
            ..cloud
        };
        assert!(validate_detected_platform(&inconsistent).is_err());
    }
}
