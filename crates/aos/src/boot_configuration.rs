//! OS-owned authenticated platform source adoption before host activation.

// Native activation is synchronous; other scheduler workers keep its signal
// cancellation listeners live while it evaluates and dispatches effects.
#[tokio::main]
async fn main() {
    if let Err(error) = aos_package::boot_configuration::run_from_process() {
        eprintln!("aos-boot-configuration: {error:#}");
        std::process::exit(1);
    }
}
