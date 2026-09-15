//! Command entry point for the package-owned OpenZFS memory policy.

fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if let Err(error) = aos_block_storage_provider::zfs_memory::run(
        &arguments,
        option_env!("AOS_ZFS_VERSION").unwrap_or(env!("CARGO_PKG_VERSION")),
    ) {
        eprintln!("aos-zfs-memory-policy: {error:#}");
        std::process::exit(1);
    }
}
