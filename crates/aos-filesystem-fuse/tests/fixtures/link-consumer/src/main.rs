//! Exercises downstream linkage independently of the adapter's build script.

fn main() {
    #[cfg(target_os = "linux")]
    std::hint::black_box(aos_filesystem_fuse::run_metadata as *const ());
}
