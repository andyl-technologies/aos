//! Command entry point for typed GPT provisioning-marker observation.

fn main() {
    if let Err(error) = aos_block_storage_provider::provisioning_marker::run_from_process() {
        eprintln!("aos-storage-provisioning-marker-observer: {error:#}");
        std::process::exit(1);
    }
}
