//! Bridges the optional C observer to the existing bounded SDK marker vocabulary.

use std::error::Error;
use std::process::Command;

use super::ClockReturn;

const OBSERVER: &str = "/clock-vvar-observer";
const MAX_OUTPUT: usize = 512;
const ANCHOR_WORDS: usize = 16;

pub(super) struct ObservedRead {
    pub(super) returned: ClockReturn,
    pub(super) anchor: Vec<u64>,
}

/// Reads the observer installed by the optional initramfs constructor.
///
/// # Errors
///
/// Returns an error if the installed observer fails or emits an invalid record.
pub(super) fn read(clock: &str) -> Result<ObservedRead, Box<dyn Error>> {
    let output = Command::new(OBSERVER).arg(clock).output()?;
    if output.stderr.len() > MAX_OUTPUT {
        return Err("VVAR observer diagnostic exceeds 512 bytes".into());
    }
    if !output.status.success() {
        return Err(format!(
            "VVAR observer refused {clock}: {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    parse(clock, &output.stdout)
}

fn parse(clock: &str, output: &[u8]) -> Result<ObservedRead, Box<dyn Error>> {
    if output.len() > MAX_OUTPUT {
        return Err("VVAR observer output exceeds 512 bytes".into());
    }
    let fields: Vec<_> = std::str::from_utf8(output)?
        .split_ascii_whitespace()
        .collect();
    if fields.len() != 3 + ANCHOR_WORDS {
        return Err("VVAR observer output has an incomplete scalar record".into());
    }
    let unit = match clock {
        "realtime" | "monotonic" => "nanoseconds",
        "gettimeofday" => "microseconds",
        "tsc" => "cycles",
        _ => return Err("VVAR observer clock is outside the original vocabulary".into()),
    };
    let returned = ClockReturn {
        seconds: fields[0].parse()?,
        fraction: fields[1].parse()?,
        value: fields[2].parse()?,
        unit,
    };
    let anchor = fields[3..]
        .iter()
        .map(|field| field.parse())
        .collect::<Result<Vec<u64>, _>>()?;
    if anchor[0] != 1
        || anchor[1] & 1 != 0
        || anchor[2] != 1
        || anchor[14] >= 16
        || anchor[15] != anchor[1]
    {
        return Err("VVAR observer layout, generation or mode is unsupported".into());
    }
    Ok(ObservedRead { returned, anchor })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_observer_record_retains_distinct_kernel_bases() {
        let record =
            b"123 456 0 1 2 1 100 10000 18446744073709551615 4 2 123 100 7 200 101 102 0 2\n";
        let observed = parse("realtime", record).expect("bounded observer record");

        assert_eq!(observed.returned.seconds, 123);
        assert_eq!(observed.returned.fraction, 456);
        assert_eq!(observed.anchor[8..12], [123, 100, 7, 200]);
    }

    #[test]
    fn observer_record_refuses_partial_oversized_or_unsupported_generations() {
        let record = "123 456 0 1 2 1 100 10000 18446744073709551615 4 2 123 100 7 200 101 102 0 2";
        assert!(parse("realtime", b"123 456").is_err());
        assert!(parse("realtime", &[b' '; MAX_OUTPUT + 1]).is_err());
        assert!(parse("unknown", record.as_bytes()).is_err());
        for (index, value) in [(3, "2"), (4, "3"), (5, "0"), (17, "16"), (18, "4")] {
            let mut fields: Vec<_> = record.split_ascii_whitespace().collect();
            fields[index] = value;
            assert!(parse("realtime", fields.join(" ").as_bytes()).is_err());
        }
    }
}
