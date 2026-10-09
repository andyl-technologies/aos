//! Installed fixed guest/source policy for actual native closure witnesses.
//!
//! The policy recognizes audited immutable AOS artifacts and two known syscall
//! workloads. It never promotes an arbitrary executable merely by measuring it.

use super::*;
use sha2::{Digest, Sha256};

pub(super) struct InstalledProfile;

impl Gem5OpaqueProfileVerifier for InstalledProfile {
    fn verify_opaque_profile(
        &self,
        launch: &Gem5Launch,
        auditor: &Gem5LaunchArtifact,
    ) -> Result<(), crate::ProviderError> {
        let tools = launch
            .process_images
            .as_ref()
            .ok_or(crate::ProviderError::Correlation(
                "installed image tools omitted",
            ))?;
        let native =
            Path::new("/nix/store/afglidl1n0zl2icjzi17yj66d5b5gyg8-gem5-25.1.0.1/bin/gem5");
        let dmtcp = Path::new("/nix/store/rpjbjf6ydsiz6v4675v6y5wa2mrrc98w-dmtcp-4.2.0");
        let installed_auditor = Path::new(
            "/nix/store/qf0hb20a34g1bacg4fxcl62z1i9xdwh7-gem5-process-image-inventory-1/bin/gem5-process-image-inventory",
        );
        let helper = Path::new(
            "/nix/store/ryw7b05an68x67d25dpanb7v1napfh0w-gem5-process-custody-1/lib/libcrucible-resource-custody.so",
        );
        if launch.executable.path != native
            || auditor.path != installed_auditor
            || tools.launcher.path != dmtcp.join("bin/dmtcp_launch")
            || tools.restarter.path != dmtcp.join("bin/dmtcp_restart")
            || tools.resource_helper.path != helper
        {
            return Err(crate::ProviderError::Correlation(
                "native artifact is outside the installed closed-profile allowlist",
            ));
        }
        launch.owner_script.content.verify(include_bytes!(
            "../../../../../pkgs/emulation/_gem5/native-owner.py"
        ))?;
        launch.model_script.content.verify(include_bytes!(
            "../../../../../pkgs/emulation/_gem5/native-owner-model.py"
        ))?;
        let guest = fs::read(&launch.guest.path)?;
        launch.guest.content.verify(&guest)?;
        let digest = format!("{:x}", Sha256::digest(&guest));
        let expected = match launch.guest_isa.as_str() {
            "x86_64" => "13152b6cd760c2d628b2ebf6491172d7904a5444a3c6a516fe33a3730ebd5579",
            "aarch64" => "8c4aec95a1b9146446fd39a5a3de4d2ddce949b551a59336545c79fc43daacc8",
            _ => {
                return Err(crate::ProviderError::Correlation(
                    "unknown closed guest ISA",
                ));
            }
        };
        if digest != expected {
            return Err(crate::ProviderError::Correlation(
                "guest is not an installed pure checksum/stdout/exit workload",
            ));
        }
        // These exact freestanding guests only touch modeled memory, write
        // stdout and exit. They have no host file/time/random/network ingress.
        for artifact in [
            &launch.executable,
            auditor,
            &tools.launcher,
            &tools.restarter,
            &tools.resource_helper,
        ] {
            artifact.content.verify(&fs::read(&artifact.path)?)?;
        }
        Ok(())
    }
}

impl Gem5ExactProfileVerifier for InstalledProfile {
    fn verify_superdense_mapping(
        &self,
        _launch: &Gem5Launch,
        maximum_microsteps: U64,
    ) -> Result<(), crate::ProviderError> {
        if maximum_microsteps != U64::new(1_000_000) {
            return Err(crate::ProviderError::Correlation(
                "unqualified same-time closure budget",
            ));
        }
        Ok(())
    }
}
