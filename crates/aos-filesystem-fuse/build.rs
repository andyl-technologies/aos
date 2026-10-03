//! Links the AOS-built synchronous FUSE transport through its installed metadata.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS")?.as_str() != "linux" {
        return Ok(());
    }
    let library = pkg_config::Config::new()
        .atleast_version("0.1.0")
        .probe("aos-fuse-transport")?;
    for directory in library.link_paths {
        // Direct binaries must resolve the exact AOS transport without a
        // process-wide LD_LIBRARY_PATH that contaminates their subprocesses.
        println!("cargo:rustc-link-arg=-Wl,-rpath,{}", directory.display());
    }
    Ok(())
}
