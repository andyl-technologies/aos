//! Runs the retained AOS image stage operation.

fn main() {
    if let Err(error) = aos_boot_runtime::commands::run_image_stage() {
        eprintln!("aos-systemd-image-stage: {error:#}");
        std::process::exit(1);
    }
}
