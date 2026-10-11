//! Prints signed boot measurements using exact retained verifier tools.

#[path = "../image_profile.rs"]
mod image_profile;
#[path = "../measurement_index.rs"]
mod measurement_index;

fn main() {
    if let Err(error) = measurement_index::run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        eprintln!("aos-systemd-image-evidence: {error:#}");
        std::process::exit(1);
    }
}
