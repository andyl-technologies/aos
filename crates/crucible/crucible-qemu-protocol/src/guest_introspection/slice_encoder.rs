//! Encodes validated records directly into caller-owned fixed storage.

use super::*;

impl GuestIntrospectionRecord {
    /// Encodes a complete record into the beginning of caller-owned storage.
    ///
    /// Returns the number of bytes written and preserves the remaining tail.
    /// All field, length and capacity validation precedes the first write.
    ///
    /// # Errors
    /// Returns invalid-field, oversized-record or insufficient-capacity errors
    /// without modifying any output byte.
    pub fn encode_into_slice(&self, output: &mut [u8]) -> Result<usize, GuestIntrospectionError> {
        let length = self.encoded_len()?;
        if output.len() < length {
            return Err(GuestIntrospectionError::OutputCapacity {
                required: length,
                available: output.len(),
            });
        }

        let mut writer = RecordWriter {
            bytes: &mut output[..length],
            position: 0,
        };
        self.encode_validated(&mut writer, length);
        Ok(length)
    }

    // Both callers validate the immutable record and the complete destination
    // before entering. Every bounded field contributes to that exact length.
    /// Appends canonical bytes after the parent validates record and capacity.
    pub(super) fn encode_reserved(&self, output: &mut Vec<u8>, length: usize) {
        self.encode_validated(output, length);
    }

    fn encode_validated(&self, output: &mut impl RecordOutput, length: usize) {
        let (kind, flags) = message_header(&self.message);
        output.append(&GUEST_INTROSPECTION_MAGIC);
        output.append(&GUEST_INTROSPECTION_PROTOCOL_VERSION.to_le_bytes());
        output.append(&[kind]);
        output.append(&[flags]);
        output.append(&self.channel_id.to_le_bytes());
        output.append(&((length - GUEST_INTROSPECTION_HEADER_LEN) as u32).to_le_bytes());
        match &self.message {
            GuestIntrospectionMessage::Features(features) => {
                output.append(&features.bits.to_le_bytes());
                output.append(&features.max_channels.to_le_bytes());
            }
            GuestIntrospectionMessage::Exec { argv, .. } => output.append_argv(argv),
            GuestIntrospectionMessage::Pty {
                argv,
                columns,
                rows,
                ..
            } => {
                output.append(&columns.to_le_bytes());
                output.append(&rows.to_le_bytes());
                output.append_argv(argv);
            }
            GuestIntrospectionMessage::Input(bytes)
            | GuestIntrospectionMessage::Output { bytes, .. } => output.append(bytes),
            GuestIntrospectionMessage::Resize { columns, rows } => {
                output.append(&columns.to_le_bytes());
                output.append(&rows.to_le_bytes());
            }
            GuestIntrospectionMessage::Exit { status, signal } => {
                output.append(&status.to_le_bytes());
                output.append(&signal.unwrap_or(0).to_le_bytes());
            }
            GuestIntrospectionMessage::Error { code, message } => {
                output.append(&code.wire_value().to_le_bytes());
                output.append(message.as_bytes());
            }
            GuestIntrospectionMessage::Ssh { .. } | GuestIntrospectionMessage::Close => {}
        }
    }
}

struct RecordWriter<'a> {
    bytes: &'a mut [u8],
    position: usize,
}

trait RecordOutput {
    fn append(&mut self, bytes: &[u8]);

    fn append_argv(&mut self, argv: &[String]) {
        // The record validator bounds both the count and each UTF-8 length.
        self.append(&(argv.len() as u16).to_le_bytes());
        for argument in argv {
            self.append(&(argument.len() as u16).to_le_bytes());
            self.append(argument.as_bytes());
        }
    }
}

impl RecordOutput for Vec<u8> {
    fn append(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

impl RecordOutput for RecordWriter<'_> {
    fn append(&mut self, bytes: &[u8]) {
        let end = self.position + bytes.len();
        self.bytes[self.position..end].copy_from_slice(bytes);
        self.position = end;
    }
}
