//! Authenticated discovery and bootstrap for the native gem5 provider.
//!
//! Discovery measures the actual installed artifacts and advertises no execution
//! profile until native input, phase, publication and preservation closure have
//! been independently qualified. A stopped event loop or a process image is not
//! sufficient evidence of those contracts. Native realization remains available
//! through the original-permit APIs in the parent module.

mod bootstrap;
mod catalog;
mod endpoint;

pub use bootstrap::{Gem5InstallationVerifier, Gem5ServiceBootstrap};
pub use catalog::Gem5Catalog;
pub use endpoint::Gem5DiscoveryService;

#[cfg(test)]
mod tests;
