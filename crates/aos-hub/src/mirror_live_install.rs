//! Parses and runs explicit installation of independently reviewed live evidence.
//!
//! All public review documents are selected by path. The existing protected
//! guard key remains an owner-private file; no trust or credential is inferred
//! from a document and no measurement or signature is created here.

use std::path::PathBuf;

use anyhow::Result;

#[derive(clap::Args)]
pub(super) struct Args {
    #[command(flatten)]
    config: super::HybridConfigArgs,
    /// Authenticate the current deployment with the existing Native-matched guard role.
    #[arg(long)]
    direct_upload_guard_key_file: PathBuf,
    /// Read the independently reviewed and signed ordinary mirror prerequisite.
    #[arg(long)]
    mirror_acceptance_file: PathBuf,
    /// Read the separately signed pack prerequisite linked to that exact mirror.
    #[arg(long)]
    mirror_pack_acceptance_file: PathBuf,
    /// Read the separately signed thirteen-case live-purpose review.
    #[arg(long)]
    mirror_live_acceptance_file: PathBuf,
}

impl Args {
    /// Publishes selected live evidence through the existing protected installer.
    ///
    /// # Errors
    /// Returns an error for configuration, custody, review-chain or KV failure.
    pub(super) async fn run(&self) -> Result<()> {
        use aos_hub::cloudflare;

        let config = self.config.to_config()?;
        let acceptance = cloudflare::HybridMirrorLiveAcceptanceConfig::from_files(
            &self.mirror_acceptance_file,
            &self.mirror_pack_acceptance_file,
            &self.mirror_live_acceptance_file,
        )?;
        let assets = cloudflare::Assets::from_env()?;
        cloudflare::activate_hybrid_mirror_live(
            &assets,
            &config,
            &self.direct_upload_guard_key_file,
            &acceptance,
        )
        .await?;

        println!(
            "reviewed live purpose published; runtime qualification remains independently required"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests;
