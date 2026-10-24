//! Runs the retained AOS initrd store operation.

fn main() {
    if let Err(error) = aos_boot_runtime::commands::run_initrd_store() {
        eprintln!("aos-systemd-initrd-store: {error:#}");
        std::process::exit(1);
    }
}
