//! Probes the fleet-visible Crucible content-addressed store.
//!
//! This small binary is packaged as the AOS `crucible-fleet-store` component.
//! It intentionally exposes only a deterministic local probe surface for the
//! packaging and fleet-check harnesses; the public store interface remains the
//! `crucible-cas` [`crucible_cas::DagStore`] trait.

use std::env;
use std::error::Error;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Barrier;
use std::thread;

use crucible_cas::{DagStore, SharedDagStore};

const PROBE_PAYLOAD: &[u8] = b"crucible-fleet-store-probe-v1";
const CONCURRENT_WRITERS: usize = 16;

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os();
    let program = match args.next() {
        Some(program) => program,
        None => OsString::from("crucible-fleet-store"),
    };
    let Some(command) = args.next() else {
        print_usage(&program);
        return Err(input_error("missing command"));
    };
    match command.to_string_lossy().as_ref() {
        "probe" => {
            let Some(root) = args.next() else {
                print_usage(&program);
                return Err(input_error("missing probe root"));
            };
            if args.next().is_some() {
                print_usage(&program);
                return Err(input_error("unexpected extra argument"));
            }
            run_probe(PathBuf::from(root))
        }
        _ => {
            print_usage(&program);
            Err(input_error(format!(
                "unknown command `{}`",
                command.to_string_lossy()
            )))
        }
    }
}

fn print_usage(program: &OsString) {
    eprintln!("usage: {} probe <store-root>", program.to_string_lossy());
}

fn input_error(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message.into()))
}

fn run_probe(root: PathBuf) -> Result<(), Box<dyn Error>> {
    let location_key =
        prove_location_independent_identity(&root.join("host-a"), &root.join("host-b"))?;
    let concurrent_key = prove_concurrent_put_idempotent(&root.join("shared"))?;
    let object_file_count =
        count_regular_files_named(&root.join("shared"), &concurrent_key.to_hex())?;
    if object_file_count != 1 {
        return Err(input_error(
            "shared store probe created duplicate concurrent objects",
        ));
    }

    println!("crucible-fleet-store probe");
    println!("root={}", root.display());
    println!("object={}", concurrent_key.to_hex());
    println!("interface=DagStore::put,DagStore::get,DagStore::has");
    println!("backend=SharedDagStore");
    println!("location_independent_identity=true");
    println!("location_independent_roots=2");
    println!("location_independent_object={}", location_key.to_hex());
    println!("concurrent_put=idempotent");
    println!("concurrent_writers={CONCURRENT_WRITERS}");
    println!("object_file_count={object_file_count}");
    Ok(())
}

fn prove_location_independent_identity(
    left_root: &Path,
    right_root: &Path,
) -> Result<crucible_cas::ContentHash, Box<dyn Error>> {
    let left = SharedDagStore::new(left_root);
    let right = SharedDagStore::new(right_root);
    let left_key = left.put(PROBE_PAYLOAD)?;
    let right_key = right.put(PROBE_PAYLOAD)?;
    if left_key != right_key {
        return Err(input_error(
            "shared store probe produced root-dependent keys",
        ));
    }
    if left.object_path(&left_key) == right.object_path(&right_key) {
        return Err(input_error(
            "shared store probe used the same path for distinct roots",
        ));
    }
    if left.get(&left_key)? != right.get(&right_key)? {
        return Err(input_error(
            "shared store probe read root-dependent object bytes",
        ));
    }
    Ok(left_key)
}

fn prove_concurrent_put_idempotent(
    root: &Path,
) -> Result<crucible_cas::ContentHash, Box<dyn Error>> {
    let store = Arc::new(SharedDagStore::new(root));
    let start = Arc::new(Barrier::new(CONCURRENT_WRITERS));
    let mut handles = Vec::with_capacity(CONCURRENT_WRITERS);
    for _ in 0..CONCURRENT_WRITERS {
        let store = Arc::clone(&store);
        let start = Arc::clone(&start);
        handles.push(thread::spawn(move || {
            start.wait();
            store.put(PROBE_PAYLOAD)
        }));
    }

    let mut key = None;
    for handle in handles {
        let writer_key = handle
            .join()
            .map_err(|_| input_error("shared store writer panicked"))??;
        match key {
            Some(existing) if existing != writer_key => {
                return Err(input_error(
                    "shared store probe produced non-idempotent concurrent keys",
                ));
            }
            Some(_) => {}
            None => key = Some(writer_key),
        }
    }

    let key =
        key.ok_or_else(|| input_error("shared store probe did not publish a concurrent key"))?;
    if !store.has(&key)? {
        return Err(input_error(
            "shared store probe lost the concurrently published object",
        ));
    }
    if store.get(&key)? != PROBE_PAYLOAD {
        return Err(input_error(
            "shared store probe read back different concurrent bytes",
        ));
    }
    Ok(key)
}

fn count_regular_files_named(root: &Path, file_name: &str) -> Result<usize, io::Error> {
    if !root.exists() {
        return Ok(0);
    }
    let mut count = 0;
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() && entry.file_name() == OsStr::new(file_name) {
                count += 1;
            }
        }
    }
    Ok(count)
}
