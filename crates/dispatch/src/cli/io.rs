//! Bounded JSON input and uncontaminated machine-readable output.
//!
//! Documents use the published assignment model, assignment, and result JSON
//! schemas. Every operation emits one complete JSON value:
//!
//! ```json
//! {"error":{"category":"invalid_input","message":"invalid JSON"}}
//! ```

use std::io::{Read, Write};
use std::path::Path;

use serde::Serialize;
use serde::de::DeserializeOwned;

use super::{CliError, ExitCategory};

/// Reads one JSON document without retaining more than the configured bound.
pub(super) fn read_json<T: DeserializeOwned>(path: &Path, max_bytes: u64) -> Result<T, CliError> {
    let reader: Box<dyn Read> = if path == Path::new("-") {
        Box::new(std::io::stdin())
    } else {
        Box::new(std::fs::File::open(path).map_err(|source| CliError::Io {
            path: path.to_owned(),
            source,
        })?)
    };

    let bound = max_bytes.checked_add(1).ok_or_else(|| CliError::Message {
        category: ExitCategory::InvalidInput,
        message: "input limit is too large".to_owned(),
    })?;
    let mut bytes = Vec::new();
    reader
        .take(bound)
        .read_to_end(&mut bytes)
        .map_err(|source| CliError::Io {
            path: path.to_owned(),
            source,
        })?;

    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(CliError::Message {
            category: ExitCategory::InvalidInput,
            message: format!("input {} exceeds {max_bytes} bytes", path.display()),
        });
    }

    let max_bytes = usize::try_from(max_bytes).map_err(|_| CliError::Message {
        category: ExitCategory::InvalidInput,
        message: "input limit exceeds this platform's address range".to_owned(),
    })?;
    let max_decoded_bytes = max_bytes.checked_mul(4).ok_or_else(|| CliError::Message {
        category: ExitCategory::InvalidInput,
        message: "decoded input limit is too large".to_owned(),
    })?;
    let limits = dispatch_protocol::json::JsonLimits {
        max_bytes,
        max_decoded_bytes,
        ..dispatch_protocol::json::JsonLimits::default()
    };
    dispatch_protocol::json::from_slice(&bytes, limits).map_err(|source| CliError::PortableJson {
        path: path.to_owned(),
        source,
    })
}

/// Writes one JSON value and a newline to a file or standard output.
pub(super) fn write_json<T: Serialize>(
    destination: Option<&Path>,
    value: &T,
) -> Result<(), CliError> {
    let destination = destination.unwrap_or_else(|| Path::new("-"));
    let writer: Box<dyn Write> = if destination == Path::new("-") {
        Box::new(std::io::stdout().lock())
    } else {
        Box::new(
            std::fs::File::create(destination).map_err(|source| CliError::Io {
                path: destination.to_owned(),
                source,
            })?,
        )
    };

    write_document(writer, destination, value)
}

fn write_document<T: Serialize>(
    mut writer: impl Write,
    path: &Path,
    value: &T,
) -> Result<(), CliError> {
    serde_json::to_writer_pretty(&mut writer, value).map_err(|source| CliError::Json {
        path: path.to_owned(),
        source,
    })?;

    writer.write_all(b"\n").map_err(|source| CliError::Io {
        path: path.to_owned(),
        source,
    })
}

/// Reports a failure separately from any successful result document.
pub(super) fn report_error(error: &CliError) -> Result<(), std::io::Error> {
    #[derive(Serialize)]
    struct ErrorDocument<'a> {
        error: ErrorBody<'a>,
    }

    #[derive(Serialize)]
    struct ErrorBody<'a> {
        category: &'a str,
        message: String,
    }

    let document = ErrorDocument {
        error: ErrorBody {
            category: error.category().label(),
            message: error.to_string(),
        },
    };
    let mut stderr = std::io::stderr().lock();
    serde_json::to_writer(&mut stderr, &document).map_err(std::io::Error::other)?;
    stderr.write_all(b"\n")
}
