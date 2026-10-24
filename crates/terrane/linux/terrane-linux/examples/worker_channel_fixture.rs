//! Runs a privileged, isolated native worker-channel component qualification.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    terrane_linux::worker_channel::native_fixture::run()
}
