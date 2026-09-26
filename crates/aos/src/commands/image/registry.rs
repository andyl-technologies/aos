//! Adapts authenticated APM image catalogs to the common CLI rendering contract.

use anyhow::{Result, bail};
use aos_core::output::Printer;
use aos_package::config::ApmConfig;
use aos_package::images::{ImageSelection, VerifiedRegistryImage};
use aos_package::types::{ImageCompression, ImageTarget, ProfileScope};
use aos_remote::hub_types::{ImageInfo, SystemImage};

use crate::cli::ImageSelectionArgs;

pub(super) async fn images(
    selection: &ImageSelectionArgs,
    resolve: bool,
    printer: &Printer,
) -> Result<Vec<SystemImage>> {
    let config = ApmConfig::load(ProfileScope::User)?;
    let request = ImageSelection {
        registry: selection.registry.clone(),
        release: selection.release.clone(),
        channel: selection.channel.clone(),
        package: selection.package.clone(),
        architecture: selection.architecture.clone(),
        format: selection.format.clone(),
        target: selection.target.clone(),
    };
    let images = aos_package::images::list(&config, &request, printer).await?;
    if resolve && images.len() != 1 {
        if images.is_empty() {
            bail!("no image matches the selected registry and filters");
        }
        bail!(
            "image selection is ambiguous; specify package, release, architecture, format, or target"
        );
    }
    Ok(images
        .into_iter()
        .map(|image| message(image, selection.channel.as_deref()))
        .collect())
}

fn message(verified: VerifiedRegistryImage, channel: Option<&str>) -> SystemImage {
    let image = verified.image;
    let delivery = image.delivery;
    let contract_schema = delivery.artifact_contract.schema.clone();
    SystemImage {
        package: verified.package,
        release: delivery.release,
        channel: channel.unwrap_or_default().to_string(),
        platform: delivery.platform,
        architecture: delivery.architecture,
        format: image.format,
        logical_image_id: delivery.logical_image_id,
        filename: delivery.filename,
        download_url: String::new(),
        media_type: delivery.media_type,
        compression: match delivery.compression {
            ImageCompression::None => "none",
            ImageCompression::Zstd => "zstd",
        }
        .to_string(),
        byte_size: delivery.byte_size,
        sha256: delivery.sha256,
        compatible_targets: delivery
            .compatible_targets
            .into_iter()
            .map(|target| {
                match target {
                    ImageTarget::BareMetal => "bare-metal",
                    ImageTarget::QemuKvm => "qemu-kvm",
                    ImageTarget::Openstack => "openstack",
                    ImageTarget::Vmware => "vmware",
                    ImageTarget::HyperV => "hyper-v",
                }
                .to_string()
            })
            .collect(),
        boot_verification: format!("provider-contract:{contract_schema}"),
        object_key: delivery.object_key,
        image_info: Some(ImageInfo {
            filename: delivery.artifact_contract.document.filename,
            download_url: String::new(),
            object_key: delivery.artifact_contract.document.object_key,
            media_type: delivery.artifact_contract.document.media_type,
            byte_size: delivery.artifact_contract.document.byte_size,
            sha256: delivery.artifact_contract.document.sha256,
            store_path: delivery.artifact_contract.document.store_path,
            nar_hash: delivery.artifact_contract.document.nar_hash,
            nar_size: delivery.artifact_contract.document.nar_size,
        }),
        logical_disk_sha256: delivery.logical_disk_sha256,
        rootfs_sha256: String::new(),
        uki: None,
        release_verification: "verified".to_string(),
        store_path: image.store_path,
        nar_hash: image.nar_hash,
        nar_size: image.nar_size,
        cache_urls: verified.cache_urls,
    }
}
