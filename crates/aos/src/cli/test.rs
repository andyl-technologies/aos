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
    },
}
