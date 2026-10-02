//! Bounded JSON-RPC framing for native module documentation editor requests.
//!
//! The native server owns completion and inspection; this module owns stdio
//! framing and UTF-16 cursor conversion. Buffers are never evaluated.

use std::io::{BufRead, Write};

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

mod native;

const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// Serves editor requests over validated native references and transactions.
///
/// # Errors
/// Returns an error for malformed framing or stream failures.
pub(crate) fn run_native(documents: Vec<aos_doc_model::runtime::RuntimeDocument>) -> Result<()> {
    native::run(documents)
}

fn word_at_position(
    text: &str,
    line: usize,
    character: usize,
    prefix_only: bool,
) -> Option<String> {
    let line = text.lines().nth(line)?;
    let byte = byte_offset_for_utf16(line, character);
    let bytes = line.as_bytes();
    let mut start = byte.min(bytes.len());
    while start > 0 && is_option_byte(bytes[start - 1]) {
        start -= 1;
    }
    let mut end = byte.min(bytes.len());
    if !prefix_only {
        while end < bytes.len() && is_option_byte(bytes[end]) {
            end += 1;
        }
    }
    Some(line[start..end].to_string())
}

fn is_option_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
}

fn byte_offset_for_utf16(text: &str, target: usize) -> usize {
    let mut utf16 = 0usize;
    for (index, character) in text.char_indices() {
        if utf16 >= target {
            return index;
        }
        utf16 += character.len_utf16();
    }
    text.len()
}

fn utf16_len(text: &str) -> usize {
    text.encode_utf16().count()
}

fn opened_text(params: &Value) -> Option<(String, String)> {
    let document = params.get("textDocument")?;
    Some((
        document.get("uri")?.as_str()?.to_string(),
        document.get("text")?.as_str()?.to_string(),
    ))
}

fn changed_text(params: &Value) -> Option<(String, String)> {
    let uri = text_document_uri(params)?;
    let text = params
        .get("contentChanges")?
        .as_array()?
        .last()?
        .get("text")?
        .as_str()?
        .to_string();
    Some((uri, text))
}

fn text_document_uri(params: &Value) -> Option<String> {
    params
        .get("textDocument")?
        .get("uri")?
        .as_str()
        .map(str::to_string)
}

fn notify_diagnostics(output: &mut impl Write, uri: &str, diagnostics: Vec<Value>) -> Result<()> {
    write_message(
        output,
        &json!({
            "jsonrpc": "2.0",
            "method": "textDocument/publishDiagnostics",
            "params": { "uri": uri, "diagnostics": diagnostics }
        }),
    )
}

fn respond(output: &mut impl Write, id: Option<Value>, result: Value) -> Result<()> {
    if let Some(id) = id {
        write_message(
            output,
            &json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        )?;
    }
    Ok(())
}

fn respond_error(
    output: &mut impl Write,
    id: Option<Value>,
    code: i64,
    message: &str,
) -> Result<()> {
    if let Some(id) = id {
        write_message(
            output,
            &json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }),
        )?;
    }
    Ok(())
}

fn read_message(input: &mut impl BufRead) -> Result<Option<Value>> {
    let mut content_length = None;
    let mut saw_header = false;
    loop {
        let mut line = String::new();
        let read = input.read_line(&mut line)?;
        if read == 0 {
            if saw_header {
                bail!("truncated LSP headers");
            }
            return Ok(None);
        }
        saw_header = true;
        if line == "\r\n" || line == "\n" {
            break;
        }
        let Some((name, value)) = line.trim_end().split_once(':') else {
            bail!("invalid LSP header");
        };
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                bail!("duplicate LSP Content-Length");
            }
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .context("invalid LSP Content-Length")?,
            );
        }
    }
    let length = content_length.context("LSP message omitted Content-Length")?;
    if length == 0 || length > MAX_MESSAGE_BYTES {
        bail!("LSP message length is outside the accepted bounds");
    }
    let mut bytes = vec![0; length];
    input.read_exact(&mut bytes)?;
    serde_json::from_slice(&bytes)
        .context("decoding LSP JSON-RPC message")
        .map(Some)
}

fn write_message(output: &mut impl Write, value: &Value) -> Result<()> {
    let bytes = serde_json::to_vec(value).context("encoding LSP JSON-RPC response")?;
    write!(output, "Content-Length: {}\r\n\r\n", bytes.len())?;
    output.write_all(&bytes)?;
    output.flush()?;
    Ok(())
}
