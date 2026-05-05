use clap::Subcommand;

#[derive(Subcommand)]
pub enum TestCmd {
    /// Run evaluation tests
    Eval,
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
        /// networking and a hostfwd to 127.0.0.1:<port> for SSH.
        /// Requires --ssh-authorized-key and a specific suite name.
        #[arg(long)]
        interactive: bool,
        /// SSH public key authorized for root login when --interactive
        /// is set. Typically `"$(ssh-add -L | head -1)"`. The key is
        /// baked into each per-machine metadata ISO via ignition; the
        /// per-machine disk image is content-addressed independently
        /// of the key, so changing the key only rebuilds tiny ISOs.
        #[arg(long, requires = "interactive")]
        ssh_authorized_key: Option<String>,
    },
}
