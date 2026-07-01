//! Arguments for `aos cache` — the binary cache client.
//!
//! `CacheCmd` defines the four cache subcommands (`push`, `pull`,
//! `prefetch`, `list`), each targeting a cache URL (`file://`, `http://`,
//! `s3://`, or `sftp://`) and selecting store paths either directly or by
//! evaluating installables from a Nix file/attribute/expression.
//! `CacheAuthArgs` is flattened into every subcommand and groups the
//! HTTP, S3, and SFTP authentication flags.
//!
//! Doc comments here are clap `--help` text; the implementation lives in
//! `commands::cache`, which delegates to the `aos-cache` crate.

use clap::{Args, Subcommand};

#[derive(Subcommand)]
pub enum CacheCmd {
    /// Push store paths to a binary cache
    Push {
        /// Installable names or store paths
        installables: Vec<String>,
        /// Cache URL (file://, http://, s3://, sftp://)
        #[arg(long)]
        to: String,
        /// Nix file to evaluate (default: ./default.nix)
        #[arg(short, long)]
        file: Option<String>,
        /// Attribute path to evaluate
        #[arg(short = 'A', long)]
        attr: Option<String>,
        /// Raw Nix expression to evaluate
        #[arg(long)]
        expr: Option<String>,
        /// Parallel connections
        #[arg(short, long, default_value_t = 8)]
        jobs: usize,
        /// Total bandwidth cap (e.g. "100MB/s")
        #[arg(long)]
        max_bandwidth: Option<String>,
        /// NARs below this size batched into AOSP packs (e.g. "1MB", HTTP only)
        #[arg(long, default_value = "1MB")]
        batch_threshold: String,
        /// Resumable upload chunk size (e.g. "5MB")
        #[arg(long, default_value = "5MB")]
        chunk_size: String,
        /// Per-stream I/O buffer size (e.g. "256KB")
        #[arg(long, default_value = "256KB")]
        buffer_size: String,
        /// Per-connection timeout in seconds
        #[arg(long, default_value_t = 10)]
        connect_timeout: u64,
        /// Abort if speed drops below this (e.g. "10KB/s")
        #[arg(long, default_value = "10KB/s")]
        min_speed: String,
        /// Compression algorithm: none, zstd, xz
        #[arg(long)]
        compression: Option<String>,
        /// Compression level
        #[arg(long, default_value_t = 3)]
        compression_level: i32,
        /// Show what would be transferred without uploading
        #[arg(long)]
        dry_run: bool,
        #[command(flatten)]
        auth: CacheAuthArgs,
    },
    /// Pull store paths from a binary cache
    Pull {
        /// Installable names or store paths
        installables: Vec<String>,
        /// Cache URL to pull from
        #[arg(long)]
        from: String,
        /// Nix file to evaluate (default: ./default.nix)
        #[arg(short, long)]
        file: Option<String>,
        /// Attribute path to evaluate
        #[arg(short = 'A', long)]
        attr: Option<String>,
        /// Raw Nix expression to evaluate
        #[arg(long)]
        expr: Option<String>,
        /// Parallel connections
        #[arg(short, long, default_value_t = 8)]
        jobs: usize,
        /// Total bandwidth cap (e.g. "100MB/s")
        #[arg(long)]
        max_bandwidth: Option<String>,
        /// Per-stream I/O buffer size (e.g. "256KB")
        #[arg(long, default_value = "256KB")]
        buffer_size: String,
        /// Per-connection timeout in seconds
        #[arg(long, default_value_t = 10)]
        connect_timeout: u64,
        /// Abort if speed drops below this (e.g. "10KB/s")
        #[arg(long, default_value = "10KB/s")]
        min_speed: String,
        /// Show what would be transferred without downloading
        #[arg(long)]
        dry_run: bool,
        #[command(flatten)]
        auth: CacheAuthArgs,
    },
    /// Prefetch source tarballs (FODs) into a cache
    Prefetch {
        /// Installable names
        installables: Vec<String>,
        /// Cache URL to push sources to
        #[arg(long)]
        to: String,
        /// Nix file to evaluate (default: ./default.nix)
        #[arg(short, long)]
        file: Option<String>,
        /// Attribute path to evaluate
        #[arg(short = 'A', long)]
        attr: Option<String>,
        /// Raw Nix expression to evaluate
        #[arg(long)]
        expr: Option<String>,
        /// Parallel connections
        #[arg(short, long, default_value_t = 8)]
        jobs: usize,
        /// Show what would be fetched without acting
        #[arg(long)]
        dry_run: bool,
        #[command(flatten)]
        auth: CacheAuthArgs,
    },
    /// List cached paths, optionally filtered by installable closure
    List {
        /// Installable names or store paths
        installables: Vec<String>,
        /// Cache URL to list from
        #[arg(long)]
        from: String,
        /// Nix file to evaluate (default: ./default.nix)
        #[arg(short, long)]
        file: Option<String>,
        /// Attribute path to evaluate
        #[arg(short = 'A', long)]
        attr: Option<String>,
        /// Raw Nix expression to evaluate
        #[arg(long)]
        expr: Option<String>,
        #[command(flatten)]
        auth: CacheAuthArgs,
    },
}

/// Shared authentication flags across all cache subcommands.
#[derive(Args)]
pub struct CacheAuthArgs {
    // --- HTTP ---
    /// AOS provisioning token (AOS_TOKEN env)
    #[arg(long, env = "AOS_TOKEN")]
    pub token: Option<String>,
    /// AOS cache view (default: "default", AOS_VIEW env)
    #[arg(long, env = "AOS_VIEW", default_value = "default")]
    pub view: String,
    /// Basic auth username (for generic caches)
    #[arg(long)]
    pub http_user: Option<String>,
    /// Basic auth password (AOS_HTTP_PASSWORD env)
    #[arg(long, env = "AOS_HTTP_PASSWORD")]
    pub http_password: Option<String>,
    /// Arbitrary HTTP header (repeatable, e.g. "Authorization: Bearer ...")
    #[arg(long)]
    pub header: Vec<String>,

    // --- S3 ---
    /// AWS region
    #[arg(long, env = "AWS_REGION")]
    pub s3_region: Option<String>,
    /// AWS credentials profile name
    #[arg(long)]
    pub s3_profile: Option<String>,
    /// Custom S3-compatible endpoint (MinIO, B2, R2, etc.)
    #[arg(long, env = "S3_ENDPOINT")]
    pub s3_endpoint: Option<String>,

    // --- SFTP ---
    /// Path to SSH private key
    #[arg(long)]
    pub ssh_key: Option<String>,
    /// SSH password (AOS_SSH_PASSWORD env)
    #[arg(long, env = "AOS_SSH_PASSWORD")]
    pub ssh_password: Option<String>,
    /// Prompt for SSH password interactively
    #[arg(long)]
    pub ssh_ask_pass: bool,
}
