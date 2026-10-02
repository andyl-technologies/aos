//! Command entry point for package-owned OpenZFS maintenance operations.

fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if let Err(error) = aos_block_storage_provider::zfs_maintenance::run(&arguments) {
        eprintln!("aos-zfs-maintenance: {error:#}");
        std::process::exit(1);
    }
}
