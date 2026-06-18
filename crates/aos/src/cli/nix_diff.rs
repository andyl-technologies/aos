//! CLI argument types for `aos nix-diff`.

use clap::ValueEnum;

use aos_core::nix::diff::DiffMode;

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum NixDiffMode {
    /// Compare only the top-level `.drv` path.
    Path,
    /// Compare `.drv` paths and ATerm bytes through the input closure.
    Byte,
}

impl From<NixDiffMode> for DiffMode {
    fn from(mode: NixDiffMode) -> Self {
        match mode {
            NixDiffMode::Path => Self::Path,
            NixDiffMode::Byte => Self::Byte,
        }
    }
}
