//! Groups the private operational namespaces of installed gem5 root launches.
//!
//! These paths select storage locations only. Each architecture's installed
//! constructor independently validates private custody, emptiness and separation
//! before loading its measured model. Directory DATA supplies no native scope.

use std::path::PathBuf;

/// Names the three distinct private namespaces of an installed root launch.
///
/// Both ARM and x86 constructors require existing canonical private directories
/// with no contents or ancestor overlap. The installed model and executable
/// remain selected by their source-owned profile, independently of these paths.
#[derive(Debug)]
pub struct Gem5RootLaunchDirectories {
    /// Holds the native process's private operational resources.
    pub resource_root: PathBuf,
    /// Holds the process images used by the installed capture machinery.
    pub image_root: PathBuf,
    /// Holds the private control endpoint and temporary capture resources.
    pub temporary_root: PathBuf,
}
