//! Runs one private SourceBirth derivation request on inherited standard streams.
//! Spec index: RFC-0025 files 01, 02, 05, 06, 08, 09.
//!
//! This L4 leaf calls Engine's shared typed request/derivation/result codec. The
//! measured launcher supplies independent operational bounds and expected binary
//! and algorithm digests. It supplies no paths, token, Source, native mechanism,
//! environment-selected implementation, process supervisor or fallback route.
//! Actual cgroup/quota/confinement and complete process reap remain parent-owned.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

use crucible_engine::node_adapters::cnp::source_birth_derivation::request_wire::{
    ExpectedIdentity, OperationalLimits, run_worker,
};
use std::{
    ffi::{OsStr, OsString},
    io::{self, Write},
    process::ExitCode,
};

struct Configuration {
    identity: ExpectedIdentity,
    limits: OperationalLimits,
}

#[derive(Debug)]
enum ArgumentError {
    Missing,
    Name,
    Encoding,
    Number,
    Digest,
    Trailing,
}

fn operand(
    arguments: &mut impl Iterator<Item = OsString>,
    name: &str,
) -> Result<OsString, ArgumentError> {
    let flag = arguments.next().ok_or(ArgumentError::Missing)?;
    if flag != OsStr::new(name) {
        return Err(ArgumentError::Name);
    }
    arguments.next().ok_or(ArgumentError::Missing)
}

fn number(value: OsString) -> Result<usize, ArgumentError> {
    let text = value.to_str().ok_or(ArgumentError::Encoding)?;
    let number = text.parse::<usize>().map_err(|_| ArgumentError::Number)?;
    if number == 0 {
        return Err(ArgumentError::Number);
    }
    Ok(number)
}

fn digest(value: OsString) -> Result<[u8; 32], ArgumentError> {
    let bytes = value.to_str().ok_or(ArgumentError::Encoding)?.as_bytes();
    if bytes.len() != 64 {
        return Err(ArgumentError::Digest);
    }

    fn half(byte: u8) -> Result<u8, ArgumentError> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err(ArgumentError::Digest),
        }
    }

    let mut result = [0; 32];
    for (target, pair) in result.iter_mut().zip(bytes.chunks_exact(2)) {
        *target = (half(pair[0])? << 4) | half(pair[1])?;
    }
    Ok(result)
}

fn configuration(
    mut arguments: impl Iterator<Item = OsString>,
) -> Result<Configuration, ArgumentError> {
    let _executable_name = arguments.next().ok_or(ArgumentError::Missing)?;
    let worker_digest = digest(operand(&mut arguments, "--worker-digest")?)?;
    let algorithm_digest = digest(operand(&mut arguments, "--algorithm-digest")?)?;
    let maximum_input_bytes = number(operand(&mut arguments, "--maximum-input-bytes")?)?;
    let maximum_elements = number(operand(&mut arguments, "--maximum-elements")?)?;
    let maximum_output_bytes = number(operand(&mut arguments, "--maximum-output-bytes")?)?;
    let maximum_diagnostic_bytes = number(operand(&mut arguments, "--maximum-diagnostic-bytes")?)?;
    if arguments.next().is_some() {
        return Err(ArgumentError::Trailing);
    }
    Ok(Configuration {
        identity: ExpectedIdentity {
            worker_digest,
            algorithm_digest,
        },
        limits: OperationalLimits {
            maximum_input_bytes,
            maximum_elements,
            maximum_output_bytes,
            maximum_diagnostic_bytes,
        },
    })
}

fn main() -> ExitCode {
    let config = match configuration(std::env::args_os()) {
        Ok(config) => config,
        Err(_) => return ExitCode::from(64),
    };

    let input = io::stdin();
    let output = io::stdout();

    match run_worker(
        &mut input.lock(),
        &mut output.lock(),
        config.limits,
        config.identity,
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            // The fixed bounded stderr message is operational only. Detailed
            // semantic errors belong to a fully correlated result frame.
            if io::stderr()
                .lock()
                .write_all(b"source-birth worker operation refused\n")
                .is_err()
            {
                ExitCode::from(74)
            } else {
                ExitCode::from(2)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_arguments_refuse_missing_uppercase_and_trailing_operands() {
        assert!(configuration(["worker"].map(OsString::from).into_iter()).is_err());
        assert!(digest(OsString::from("A".repeat(64))).is_err());
        assert!(number(OsString::from("0")).is_err());

        let args = [
            "worker",
            "--worker-digest",
            &"01".repeat(32),
            "--algorithm-digest",
            &"02".repeat(32),
            "--maximum-input-bytes",
            "160",
            "--maximum-elements",
            "1",
            "--maximum-output-bytes",
            "1",
            "--maximum-diagnostic-bytes",
            "1",
        ];

        assert!(configuration(args.map(OsString::from).into_iter()).is_ok());

        let mut trailing = args.map(OsString::from).to_vec();
        trailing.push(OsString::from("extra"));

        assert!(configuration(trailing.into_iter()).is_err());
    }
}
