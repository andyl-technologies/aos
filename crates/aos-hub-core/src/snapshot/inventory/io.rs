//! Bounded canonical private records over the existing authenticated framing.

use std::io::{Read, Write};

use anyhow::{ensure, Result};
use serde::Serialize;
use zeroize::Zeroizing;

use super::RECORD_BYTES;
use crate::snapshot::archive::{StreamDecoder, StreamEncoder};

struct Buffer(Zeroizing<Vec<u8>>);

impl Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > RECORD_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other(
                "object requirement record exceeds limits",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(super) fn encode(value: &impl Serialize) -> Result<Zeroizing<Vec<u8>>> {
    let mut output = Buffer(Zeroizing::new(Vec::new()));
    serde_json::to_writer(&mut output, value)
        .map_err(|_| anyhow::anyhow!("object requirement encoding failed"))?;
    Ok(output.0)
}

pub(super) fn write<W: Write>(stream: &mut StreamEncoder<W>, value: &impl Serialize) -> Result<()> {
    stream.write_plaintext(&encode(value)?)?;
    stream.write_plaintext(b"\n")
}

pub(super) struct Reader<R: Read> {
    pub decoder: StreamDecoder<R>,
    chunk: Zeroizing<Vec<u8>>,
    offset: usize,
}

impl<R: Read> Reader<R> {
    pub fn new(decoder: StreamDecoder<R>) -> Self {
        Self {
            decoder,
            chunk: Zeroizing::new(Vec::new()),
            offset: 0,
        }
    }

    fn line(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let mut line = Zeroizing::new(Vec::new());
        loop {
            if self.offset == self.chunk.len() {
                match self.decoder.next_chunk()? {
                    Some(chunk) => {
                        self.chunk =
                            chunk.with_private_bytes(|bytes| Zeroizing::new(bytes.to_vec()));
                        self.offset = 0;
                    }
                    None => {
                        ensure!(line.is_empty(), "object requirement record is incomplete");
                        return Ok(None);
                    }
                }
            }
            let remaining = &self.chunk[self.offset..];
            let delimiter = remaining.iter().position(|byte| *byte == b'\n');
            let take = delimiter.unwrap_or(remaining.len());
            ensure!(
                take <= RECORD_BYTES.saturating_sub(line.len()),
                "object requirement record exceeds limits"
            );
            line.extend_from_slice(&remaining[..take]);
            self.offset += take;
            if delimiter.is_some() {
                self.offset += 1;
                ensure!(!line.is_empty(), "object requirement record is empty");
                return Ok(Some(line));
            }
        }
    }

    pub fn compare(&mut self, expected: &impl Serialize) -> Result<()> {
        let actual = self
            .line()?
            .ok_or_else(|| anyhow::anyhow!("object requirement record is absent"))?;
        ensure!(
            actual.as_slice() == encode(expected)?.as_slice(),
            "object requirement projection differs"
        );
        Ok(())
    }

    pub fn finish(&mut self) -> Result<()> {
        ensure!(
            self.line()?.is_none() && self.decoder.summary().is_some(),
            "object requirements stream is incomplete or has trailing records"
        );
        Ok(())
    }
}
