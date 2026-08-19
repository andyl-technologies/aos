//! Command-line arguments for running downloaded AOS images locally.

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

#[derive(Subcommand)]
pub enum VmCommand {
    /// Prepare and run an AOS image with QEMU.
    Run(VmRunArgs),
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum VmAcceleration {
    /// Use KVM when available, otherwise fall back to software emulation.
    #[default]
    Auto,
    /// Require hardware acceleration through KVM.
    Kvm,
    /// Use portable software emulation.
    Tcg,
}

#[derive(Args)]
pub struct VmRunArgs {
    /// Downloaded raw or QCOW2 AOS disk image.
    pub image: PathBuf,
    /// Stable VM name used for persistent disk and firmware state.
    #[arg(long)]
    pub name: Option<String>,
    /// Literal host.nix supplied through QEMU fw_cfg.
    #[arg(long)]
    pub host_config: Option<PathBuf>,
    /// Detached signature supplied beside host.nix through QEMU fw_cfg.
    #[arg(long, requires = "host_config")]
    pub host_config_signature: Option<PathBuf>,
    /// Virtual disk capacity in GiB.
    #[arg(long, default_value_t = 16)]
    pub disk_size_gib: u64,
    /// Guest memory in MiB.
    #[arg(long, default_value_t = 4096)]
    pub memory_mib: u64,
    /// Number of virtual CPUs.
    #[arg(long, default_value_t = 2)]
    pub cpus: u32,
    /// Forward this host TCP port to guest SSH port 22.
    #[arg(long, default_value_t = 2222)]
    pub ssh_port: u16,
    /// Select hardware acceleration or software emulation.
    #[arg(long, value_enum, default_value_t)]
    pub accel: VmAcceleration,
    /// Directory that retains the writable disk and UEFI variables.
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    /// Read-only OVMF firmware code image.
    #[arg(long, env = "AOS_OVMF_CODE")]
    pub firmware_code: Option<PathBuf>,
    /// OVMF variable-store template copied for this VM.
    #[arg(long, env = "AOS_OVMF_VARS")]
    pub firmware_vars: Option<PathBuf>,
    /// QEMU x86_64 system emulator executable.
    #[arg(long, env = "AOS_QEMU")]
    pub qemu: Option<PathBuf>,
    /// QEMU disk conversion executable.
    #[arg(long, env = "AOS_QEMU_IMG")]
    pub qemu_img: Option<PathBuf>,
    /// GPT repair executable.
    #[arg(long, env = "AOS_SGDISK")]
    pub sgdisk: Option<PathBuf>,
    /// Print the resolved launch configuration without changing VM state.
    #[arg(long)]
    pub dry_run: bool,
}
