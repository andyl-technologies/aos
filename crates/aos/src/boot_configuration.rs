//! OS-owned authenticated platform source adoption before host activation.

fn main() {
    if let Err(error) = aos_package::boot_configuration::run_from_process() {
        eprintln!("aos-boot-configuration: {error:#}");
        std::process::exit(1);
    }
}
