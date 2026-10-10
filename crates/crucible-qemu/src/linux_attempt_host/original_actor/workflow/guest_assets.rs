//! Validates the authored direct-kernel asset tuple before service admission.
//!
//! These identities are declarations authenticated by the same workflow bytes.
//! The daemon still pins and hashes the actual files under original custody;
//! validation here creates no filesystem, native or process permission.

use crucible::owned_decode::json_profiles::workflow::{GuestArtifact, GuestAssets};

use super::*;
#[cfg(test)]
use crucible::owned_decode::json_profiles::workflow::RootImageFormat;

pub(super) trait GuestAssetsValidation {
    fn validate(&self) -> Result<(), MeasurementOriginError>;
    #[cfg(test)]
    fn fixture() -> Self;
}

impl GuestAssetsValidation for GuestAssets {
    fn validate(&self) -> Result<(), MeasurementOriginError> {
        if self.architecture != "x86_64"
            || self.boot_mode != "directKernel"
            || self.kernel_cmdline.as_bytes().contains(&0)
        {
            return Err(MeasurementOriginError::Authentication(
                "original guest tuple",
            ));
        }
        self.kernel.validate()?;
        self.root_image.validate()?;
        if let Some(initrd) = &self.initrd {
            initrd.validate()?;
        }
        Ok(())
    }

    #[cfg(test)]
    fn fixture() -> Self {
        Self {
            architecture: "x86_64".into(),
            boot_mode: "directKernel".into(),
            kernel: GuestArtifact::fixture("kernel"),
            root_image: GuestArtifact::fixture("root.ext4"),
            initrd: None,
            _root_image_format: RootImageFormat::Raw,
            kernel_cmdline: "console=ttyS0".into(),
        }
    }
}

trait GuestArtifactValidation {
    fn validate(&self) -> Result<(), MeasurementOriginError>;
    #[cfg(test)]
    fn fixture(name: &str) -> Self;
}

impl GuestArtifactValidation for GuestArtifact {
    fn validate(&self) -> Result<(), MeasurementOriginError> {
        let path = std::path::Path::new(&self.path);
        if !path.is_absolute()
            || !path.starts_with("/nix/store")
            || path
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
            || self.path.as_bytes().contains(&0)
            || self.bytes == 0
            || blake3::Hash::from_hex(&self.blake3).is_err()
        {
            return Err(MeasurementOriginError::Authentication(
                "original guest artifact",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    fn fixture(name: &str) -> Self {
        Self {
            path: format!("/nix/store/00000000000000000000000000000000-fixture/{name}"),
            bytes: 1,
            blake3: blake3::hash(b"fixture").to_hex().to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_asset_tuple_refuses_wrong_architecture_and_traversal() {
        let mut assets = GuestAssets::fixture();
        assert!(assets.validate().is_ok());
        assets.architecture = "aarch64".into();
        assert!(assets.validate().is_err());
        assets.architecture = "x86_64".into();
        assets.kernel.path = "/nix/store/fixture/../kernel".into();
        assert!(assets.validate().is_err());
    }

    #[test]
    fn typed_asset_tuple_refuses_missing_bytes_digest_and_unknown_format() {
        let mut assets = GuestAssets::fixture();
        assets.root_image.bytes = 0;
        assert!(assets.validate().is_err());
        assets.root_image.bytes = 1;
        assets.root_image.blake3 = "not-a-content-digest".into();
        assert!(assets.validate().is_err());
        assert!(serde_json::from_slice::<RootImageFormat>(br#""automatic""#).is_err());
    }
}
