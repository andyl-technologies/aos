//! Entry point for the VM-only Linux FUSE adapter qualification worker.

#[cfg(target_os = "linux")]
mod linux;

fn main() {
    #[cfg(target_os = "linux")]
    linux::main();

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("the FUSE kernel qualification fixture requires Linux");
        std::process::exit(2);
    }
}
