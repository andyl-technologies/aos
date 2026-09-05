//! Adapts authenticated APM image catalogs to the common CLI rendering contract.

use anyhow::{Result, bail};
use aos_core::output::Printer;
use aos_package::config::ApmConfig;
use aos_package::images::{ImageSelection, VerifiedRegistryImage};
use aos_package::types::{ImageCompression, ImageTarget, ImageVerificationState, ProfileScope};
use aos_remote::hub_types::{ImageInfo, ImageUki, SbatGeneration, SystemImage};

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
    let verification = match delivery.uki.verification {
        ImageVerificationState::Unsigned => "unsigned",
        ImageVerificationState::SignedUnverified => "signed-unverified",
        ImageVerificationState::PolicyVerified => "policy-verified",
    };
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
        boot_verification: verification.to_string(),
        object_key: delivery.object_key,
        image_info: Some(ImageInfo {
            filename: delivery.image_info.filename,
            download_url: String::new(),
            object_key: delivery.image_info.object_key,
            media_type: delivery.image_info.media_type,
            byte_size: delivery.image_info.byte_size,
            sha256: delivery.image_info.sha256,
            store_path: delivery.image_info.store_path,
            nar_hash: delivery.image_info.nar_hash,
            nar_size: delivery.image_info.nar_size,
        }),
        logical_disk_sha256: delivery.logical_disk_sha256,
        rootfs_sha256: delivery.rootfs_sha256,
        uki: Some(ImageUki {
            filename: delivery.uki.filename,
            esp_path: delivery.uki.esp_path,
            byte_size: delivery.uki.byte_size,
            sha256: delivery.uki.sha256,
            verification: verification.to_string(),
            signer_cert_sha256: delivery.uki.signer_cert_sha256.unwrap_or_default(),
            sbat: delivery
                .uki
                .sbat
                .into_iter()
                .map(|entry| SbatGeneration {
                    component: entry.component,
                    generation: entry.generation,
                })
                .collect(),
            measured: delivery.uki.measured,
            expected_pcr11: delivery.uki.expected_pcr11.unwrap_or_default(),
        }),
        release_verification: "verified".to_string(),
        store_path: image.store_path,
        nar_hash: image.nar_hash,
        nar_size: image.nar_size,
        cache_urls: verified.cache_urls,
    }
}
