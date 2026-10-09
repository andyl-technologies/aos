//! Runs the retained AOS image evidence operation.

fn main() {
    if let Err(error) = aos_boot_runtime::commands::run_image_evidence() {
        eprintln!("aos-systemd-image-evidence: {error:#}");
        std::process::exit(1);
    }
}
