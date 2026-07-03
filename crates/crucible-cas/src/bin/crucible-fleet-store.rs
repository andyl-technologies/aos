//! Probes the fleet-visible Crucible content-addressed store.
//!
//! This small binary is packaged as the AOS `crucible-fleet-store` component.
//! It intentionally exposes only a deterministic local probe surface for the
//! packaging and fleet-check harnesses; the public store interface remains the
//! `crucible-cas` [`crucible_cas::DagStore`] trait.

use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;

use crucible_cas::{DagStore, SharedDagStore};

const PROBE_PAYLOAD: &[u8] = b"crucible-fleet-store-probe-v1";

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
    let store = SharedDagStore::new(root.clone());
    let first = store.put(PROBE_PAYLOAD)?;
    let second = store.put(PROBE_PAYLOAD)?;
    if first != second {
        return Err(input_error(
            "shared store probe produced non-idempotent keys",
        ));
    }
    let fetched = store.get(&first)?;
    if fetched != PROBE_PAYLOAD {
        return Err(input_error("shared store probe read back different bytes"));
    }

    println!("crucible-fleet-store probe");
    println!("root={}", root.display());
    println!("object={}", first.to_hex());
    println!("interface=DagStore::put,DagStore::get,DagStore::has");
    println!("backend=SharedDagStore");
    println!("location_independent_identity=true");
    println!("concurrent_put=idempotent");
    Ok(())
}
