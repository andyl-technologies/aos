//! Command-line arguments for discovering and downloading AOS system images.

use std::path::PathBuf;

use clap::{Args, Subcommand};

#[derive(Subcommand)]
pub enum ImageCommand {
    /// List signed system images.
    List(ImageListArgs),
    /// Resolve and inspect one signed system image.
    Show(ImageShowArgs),
    /// Download disk-image bytes and verify their SHA-256.
    Download(ImageDownloadArgs),
}

#[derive(Debug, Clone, Args)]
pub struct ImageSelectionArgs {
    /// Hub API base URL.
    #[arg(long, env = "AOS_HUB", default_value = "https://aos.andyl.org")]
    pub hub: String,
    /// Bearer token for private registries.
    #[arg(long, env = "AOS_TOKEN")]
    pub token: Option<String>,
    /// Registry slug or name.
    #[arg(long)]
    pub registry: String,
    /// Select a sysroot package when a registry publishes more than one.
    #[arg(long)]
    pub package: Option<String>,
    /// Select an immutable release.
    #[arg(long, conflicts_with = "channel")]
    pub release: Option<String>,
    /// Resolve a signed release channel.
    #[arg(long, conflicts_with = "release")]
    pub channel: Option<String>,
    /// Select an architecture.
    #[arg(long)]
    pub architecture: Option<String>,
    /// Select a disk format.
    #[arg(long)]
    pub format: Option<String>,
    /// Select an end-user target such as `qemu-kvm` or `bare-metal`.
    #[arg(long)]
    pub target: Option<String>,
}

#[derive(Args)]
pub struct ImageListArgs {
    /// Image filters.
    #[command(flatten)]
    pub selection: ImageSelectionArgs,
}

#[derive(Args)]
pub struct ImageShowArgs {
    /// Exact image selection.
    #[command(flatten)]
    pub selection: ImageSelectionArgs,
}

#[derive(Args)]
pub struct ImageDownloadArgs {
    /// Exact image selection.
    #[command(flatten)]
    pub selection: ImageSelectionArgs,
    /// Destination file; defaults to the signed useful filename.
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Restart rather than resume an existing partial file.
    #[arg(long)]
    pub no_resume: bool,
}
