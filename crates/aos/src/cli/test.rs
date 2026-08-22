//! Arguments for `aos test` — the test-layer runner.
//!
//! `TestCmd` selects one of the five test layers (`eval`, `rust`, `build`,
//! `vm`, `fleet`), each mapping to a `checks.*` attribute in the Nix tree; with
//! no subcommand, `aos test` runs all layers in sequence. The `fleet`
//! layer additionally supports `--interactive` for booting the fleet VMs
//! outside the Nix sandbox with SSH access.
//!
//! Doc comments here are clap `--help` text; the implementation lives in
//! `commands::test`.

use clap::Subcommand;

#[derive(Subcommand)]
pub enum TestCmd {
    /// Run evaluation tests
    Eval,
    /// Run parallel Rust tests
    Rust {
        /// Test suite name
        suite: Option<String>,
    },
    /// Run build tests
    Build,
    /// Run VM integration tests
    Vm {
        /// Test suite name
        suite: Option<String>,
    },
    /// Run fleet tests
    Fleet {
        /// Test suite name
        suite: Option<String>,
        /// Boot the fleet outside the Nix sandbox for interactive
        /// debugging. Each VM gets a second NIC with QEMU user-mode
        /// networking and a hostfwd to a local 127.0.0.1 port for SSH.
        /// Requires --ssh-authorized-key and a specific suite name.
        #[arg(long)]
        interactive: bool,
        /// SSH public key authorized for root login when --interactive
        /// is set. Typically `"$(ssh-add -L | head -1)"`. The key is
        /// baked into each per-machine metadata ISO as host configuration; the
        /// per-machine disk image is content-addressed independently
        /// of the key, so changing the key only rebuilds tiny ISOs.
        #[arg(long, requires = "interactive")]
        ssh_authorized_key: Option<String>,
    },
}
