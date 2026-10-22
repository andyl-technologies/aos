//! Closed two-page CPU writer evidence under the caller's retained original.

use super::*;

const WINDOW_BYTES: usize = 8192;
const REPLY_BYTES: usize = 32 * 1024;
const PROFILE_COUNT: u32 = 28;

/// Owns the fixed writer arena and registers before its original evidence loan.
pub struct QemuCpuWriteObservation {
    /// Architectural registers at the actual paused boundary.
    pub registers: String,
    /// All bytes in the fixed physical interval `0x7000..0x9000`.
    pub arena: Vec<u8>,
    /// Closed profile index read from the actual selected ROM, not an issuer.
    pub profile_index: u32,
    _resident: crucible_ram::ResourceLoan,
}

impl<S: QmpTimeoutStream> QmpClient<S> {
    pub(super) fn cpu_write_observation(
        &mut self,
        guard: &HostOperationGuard,
        resident: crucible_ram::ResourceLoan,
    ) -> Result<QemuCpuWriteObservation, QmpError> {
        if self.host_supervisor.is_none() {
            return Err(invalid());
        }
        // The original caller prepays the bounded parser, replies and retained
        // samples. Allocate output before the first native query, never afterward.
        let mut arena = Vec::new();
        arena
            .try_reserve_exact(WINDOW_BYTES)
            .map_err(|_| invalid())?;
        let old_limit = self.io_timeout_policy.max_line_bytes;
        self.io_timeout_policy.max_line_bytes = old_limit.min(REPLY_BYTES);
        let result = (|| {
            self.performance_paused(guard)?;
            let registers = self.performance_text("info registers", guard)?;
            let identity = super::performance_observation::parse_window::<12>(
                &self.performance_text("xp /12bx 0xfffd0", guard)?,
                0xfffd0,
            )?;
            let profile_index = decode_profile_index(&identity)?;
            for (command, base) in [("xp /4096bx 0x7000", 0x7000), ("xp /4096bx 0x8000", 0x8000)] {
                append_page(&self.performance_text(command, guard)?, base, &mut arena)?;
            }
            self.performance_paused(guard)?;
            Ok((registers, profile_index))
        })();
        self.io_timeout_policy.max_line_bytes = old_limit;
        match result {
            Ok((registers, profile_index)) => Ok(QemuCpuWriteObservation {
                registers,
                arena,
                profile_index,
                _resident: resident,
            }),
            Err(error) => {
                // Both partial output and parser temporaries close before the
                // loan; the caller retains its original diagnostic custody.
                drop(arena);
                drop(resident);
                Err(error)
            }
        }
    }
}

fn invalid() -> QmpError {
    QmpError::InvalidBound {
        operation: "fixed CPU write observation",
    }
}

// The ROM tag selects a closed oracle profile; it never grants an address,
// deadline, CPU capability or resource allowance.
fn decode_profile_index(identity: &[u8]) -> Result<u32, QmpError> {
    if identity.len() != 12 || &identity[..8] != b"CRUCWRT1" {
        return Err(invalid());
    }
    let profile_index = u32::from_le_bytes(identity[8..12].try_into().map_err(|_| invalid())?);
    if profile_index >= PROFILE_COUNT {
        return Err(invalid());
    }
    Ok(profile_index)
}

fn append_page(text: &str, base: u64, arena: &mut Vec<u8>) -> Result<(), QmpError> {
    let start = arena.len();
    for line in text.lines() {
        let (address, values) = line.split_once(':').ok_or_else(invalid)?;
        let address = u64::from_str_radix(address.trim().trim_start_matches("0x"), 16)
            .map_err(|_| invalid())?;
        if address != base + (arena.len() - start) as u64 {
            return Err(invalid());
        }
        for value in values.split_whitespace() {
            if arena.len() - start == 4096 {
                return Err(invalid());
            }
            let byte = u8::from_str_radix(value.strip_prefix("0x").ok_or_else(invalid)?, 16)
                .map_err(|_| invalid())?;
            arena.push(byte);
        }
    }
    if arena.len() - start != 4096 {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_all_closed_rom_profiles_from_the_actual_identity_window() {
        for profile_index in 0..PROFILE_COUNT {
            let mut identity = *b"CRUCWRT1\0\0\0\0";
            identity[8..].copy_from_slice(&profile_index.to_le_bytes());
            let bytes = identity
                .iter()
                .map(|byte| format!("0x{byte:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            let text = format!("0xfffd0: {bytes}");
            let parsed =
                super::super::performance_observation::parse_window::<12>(&text, 0xfffd0).unwrap();

            assert_eq!(decode_profile_index(&parsed).unwrap(), profile_index);
        }
    }

    #[test]
    fn rejects_unlisted_profiles_and_malformed_identity_before_page_reads() {
        for profile_index in [PROFILE_COUNT, u32::MAX] {
            let mut identity = *b"CRUCWRT1\0\0\0\0";
            identity[8..].copy_from_slice(&profile_index.to_le_bytes());
            assert!(decode_profile_index(&identity).is_err());
        }

        for identity in [
            &b"CRUCWRT1\0\0\0"[..],
            &b"CRUCWRT1\0\0\0\0\0"[..],
            &b"CRUCWRT2\0\0\0\0"[..],
            &b""[..],
        ] {
            assert!(decode_profile_index(identity).is_err());
        }
    }

    #[test]
    fn rejects_short_duplicate_address_and_outside_page_evidence() {
        for text in ["0x7000: 0x35", "0x7001: 0x35", "0x7000: 0x35\n0x7000: 0x35"] {
            let mut arena = Vec::with_capacity(WINDOW_BYTES);
            assert!(append_page(text, 0x7000, &mut arena).is_err());
        }
    }
}
