//! CLI argument types for `aos nix-diff`.

use clap::ValueEnum;

use aos_nix_harness::diff::DiffMode;

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum NixDiffMode {
    /// Compare only the top-level `.drv` path.
    Path,
    /// Compare `.drv` paths and ATerm bytes through the input closure.
    Byte,
    /// Compare bytes and report the first parsed derivation field that differs.
    Structural,
}

impl From<NixDiffMode> for DiffMode {
    fn from(mode: NixDiffMode) -> Self {
        match mode {
            NixDiffMode::Path => Self::Path,
            NixDiffMode::Byte => Self::Byte,
            NixDiffMode::Structural => Self::Structural,
        }
    }
}
