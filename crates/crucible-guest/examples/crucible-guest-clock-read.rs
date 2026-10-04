//! Emits two bounded batches of actual Linux clock returns through the guest SDK.
//!
//! Each read is enclosed by semantic markers. Their authenticated instruction
//! coordinates bracket the read; the later marker is never treated as its time.
//! PID 1 blocks on an ordinary Linux timer between batches. This fresh x86
//! fixture does not restore state, install clock faults, or invoke nested VMs.

use std::error::Error;
use std::process::ExitCode;

#[cfg(any(test, all(target_os = "linux", target_arch = "x86_64")))]
#[path = "crucible-guest-clock-read/vvar.rs"]
mod vvar;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use crucible_guest::{
    InstructionDoorbellTransport, emit_command, emit_selectable_registration, request_selection,
};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use crucible_protocol::{SelectableRegister, SelectionRequest};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const CLOCKS: [&str; 4] = ["realtime", "monotonic", "gettimeofday", "tsc"];

#[cfg(any(test, all(target_os = "linux", target_arch = "x86_64")))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ClockReturn {
    seconds: i64,
    fraction: i64,
    value: u64,
    unit: &'static str,
}

#[cfg(any(test, all(target_os = "linux", target_arch = "x86_64")))]
use crucible_guest::GuestCommand;
#[cfg(any(test, all(target_os = "linux", target_arch = "x86_64")))]
use crucible_protocol::{WhiteboxMeasurementValue, WhiteboxSemanticMarkerDetail};

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn run() -> Result<(), Box<dyn Error>> {
    Err("guest clock-read fixture requires Linux x86_64 sim/TCG".into())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("guest clock-read fixture: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn run() -> Result<(), Box<dyn Error>> {
    pin_to_boot_cpu()?;
    let mut transport = InstructionDoorbellTransport::native()?;
    let registration = SelectableRegister::new(
        1,
        "flight.ready",
        vec![1],
        vec![1],
        vec!["readiness".into()],
    )?;
    emit_selectable_registration(&registration, &mut transport)?;
    emit_command(&GuestCommand::setup_complete(), &mut transport)?;
    pause(2, "boot", &mut transport)?;

    for batch in 0..2 {
        for clock in CLOCKS {
            let instance = format!("{batch}-{clock}");
            let cpu = current_cpu()?;
            emit_command(&before(&instance, cpu), &mut transport)?;
            // Only the optional constructor sets this compile-time flag. The
            // default flight retains its ordinary API call without a file probe.
            let marker = if option_env!("CRUCIBLE_GUEST_CLOCK_VVAR_OBSERVER") == Some("1") {
                let observed = vvar::read(clock)?;
                after_with_anchor(&instance, cpu, observed.returned, Some(observed.anchor))
            } else {
                after(&instance, cpu, read_clock(clock)?)
            };
            emit_command(&marker, &mut transport)?;
        }
        pause(3 + batch, &format!("clock-{batch}"), &mut transport)?;
        if batch == 0 {
            sleep_one_second()?;
        }
    }

    emit_command(&GuestCommand::test_done(), &mut transport)?;
    loop {
        sleep_one_second()?;
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn pause(
    sequence: u64,
    instance: &str,
    transport: &mut InstructionDoorbellTransport,
) -> Result<(), Box<dyn Error>> {
    let request = SelectionRequest::new(sequence, "flight.ready", instance, None, 128)?;
    // A typed Unavailable reply releases the original barrier without inventing
    // a campaign choice or changing the guest clock workload.
    request_selection(&request, transport)?;
    Ok(())
}

#[cfg(any(test, all(target_os = "linux", target_arch = "x86_64")))]
fn before(instance: &str, cpu: u64) -> GuestCommand {
    GuestCommand::semantic_marker(
        "clock.read.before",
        instance,
        vec![detail("cpu", WhiteboxMeasurementValue::Unsigned(cpu))],
    )
}

#[cfg(any(test, all(target_os = "linux", target_arch = "x86_64")))]
fn after(instance: &str, cpu: u64, returned: ClockReturn) -> GuestCommand {
    after_with_anchor(instance, cpu, returned, None)
}

#[cfg(any(test, all(target_os = "linux", target_arch = "x86_64")))]
fn after_with_anchor(
    instance: &str,
    cpu: u64,
    returned: ClockReturn,
    anchor: Option<Vec<u64>>,
) -> GuestCommand {
    let mut details = vec![
        detail("cpu", WhiteboxMeasurementValue::Unsigned(cpu)),
        detail(
            "fraction",
            WhiteboxMeasurementValue::Signed(returned.fraction),
        ),
        detail(
            "seconds",
            WhiteboxMeasurementValue::Signed(returned.seconds),
        ),
        detail(
            "unit",
            WhiteboxMeasurementValue::Enumerated(returned.unit.into()),
        ),
        detail("value", WhiteboxMeasurementValue::Unsigned(returned.value)),
    ];
    if let Some(anchor) = anchor {
        details.push(detail(
            "vvar",
            WhiteboxMeasurementValue::UnsignedVector(anchor),
        ));
    }
    GuestCommand::semantic_marker("clock.read.after", instance, details)
}

#[cfg(any(test, all(target_os = "linux", target_arch = "x86_64")))]
fn detail(key: &str, value: WhiteboxMeasurementValue) -> WhiteboxSemanticMarkerDetail {
    WhiteboxSemanticMarkerDetail {
        key: key.into(),
        value,
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn pin_to_boot_cpu() -> Result<(), Box<dyn Error>> {
    // SAFETY: the initialized CPU set is valid for its exact allocation, and
    // sched_setaffinity receives only that set for the calling process.
    let status = unsafe {
        let mut affinity: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut affinity);
        libc::CPU_SET(0, &mut affinity);
        libc::sched_setaffinity(0, std::mem::size_of_val(&affinity), &affinity)
    };
    if status != 0 || current_cpu()? != 0 {
        return Err("clock-read fixture could not bind CPU 0".into());
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn current_cpu() -> Result<u64, Box<dyn Error>> {
    // SAFETY: sched_getcpu has no pointer arguments or memory preconditions.
    let cpu = unsafe { libc::sched_getcpu() };
    Ok(u64::try_from(cpu)?)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn read_clock(clock: &str) -> Result<ClockReturn, Box<dyn Error>> {
    match clock {
        "realtime" | "monotonic" => {
            let mut time = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let id = if clock == "realtime" {
                libc::CLOCK_REALTIME
            } else {
                libc::CLOCK_MONOTONIC
            };
            // SAFETY: time is a writable timespec for the complete call.
            if unsafe { libc::clock_gettime(id, &mut time) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            Ok(ClockReturn {
                seconds: time.tv_sec,
                fraction: time.tv_nsec,
                value: 0,
                unit: "nanoseconds",
            })
        }
        "gettimeofday" => {
            let mut time = libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            };
            // SAFETY: time is writable and the unused timezone pointer is null.
            if unsafe { libc::gettimeofday(&mut time, std::ptr::null_mut()) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            Ok(ClockReturn {
                seconds: time.tv_sec,
                fraction: time.tv_usec,
                value: 0,
                unit: "microseconds",
            })
        }
        "tsc" => {
            // SAFETY: this fixture runs on the original x86_64 sim/TCG profile
            // with SSE2 and TSC. Fences enclose the actual architectural read.
            let value = unsafe {
                core::arch::x86_64::_mm_lfence();
                let value = core::arch::x86_64::_rdtsc();
                core::arch::x86_64::_mm_lfence();
                value
            };
            Ok(ClockReturn {
                seconds: 0,
                fraction: 0,
                value,
                unit: "cycles",
            })
        }
        _ => Err("unknown clock in the closed read vocabulary".into()),
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn sleep_one_second() -> Result<(), Box<dyn Error>> {
    let interval = libc::timespec {
        tv_sec: 1,
        tv_nsec: 0,
    };
    // SAFETY: interval is readable for the full call; no remainder is requested.
    if unsafe { libc::nanosleep(&interval, std::ptr::null_mut()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_guest::{DoorbellTransport, GuestEmitterError, emit_command};
    use crucible_protocol::{
        WhiteboxDoorbellFrame, WhiteboxMarkerPayload, decode_whitebox_marker_payload,
    };

    #[derive(Default)]
    struct RecordingTransport(Vec<Vec<u8>>);

    impl DoorbellTransport for RecordingTransport {
        fn ring(&mut self, bytes: &mut [u8]) -> Result<(), GuestEmitterError> {
            self.0.push(bytes.to_vec());
            Ok(())
        }
    }

    #[test]
    fn actual_sdk_roundtrip_retains_clock_returns_and_read_brackets() {
        let mut transport = RecordingTransport::default();
        let returned = ClockReturn {
            seconds: 1_700_000_000,
            fraction: 999_999_999,
            value: 0,
            unit: "nanoseconds",
        };
        emit_command(&before("0-realtime", 0), &mut transport).expect("before encoding");
        emit_command(&after("0-realtime", 0, returned), &mut transport).expect("return encoding");

        for (index, marker) in ["clock.read.before", "clock.read.after"]
            .into_iter()
            .enumerate()
        {
            let frame = WhiteboxDoorbellFrame::decode(&transport.0[index]).expect("frame decode");
            let payload = decode_whitebox_marker_payload(&frame).expect("typed payload decode");
            let WhiteboxMarkerPayload::SemanticMarker(body) = payload else {
                panic!("semantic marker required")
            };
            assert_eq!(body.marker, marker);
            assert_eq!(body.instance, "0-realtime");
            let expected = if index == 0 {
                before("0-realtime", 0)
            } else {
                after("0-realtime", 0, returned)
            };
            assert_eq!(
                expected.encode_frame().expect("canonical frame"),
                transport.0[index]
            );
            if index == 1 {
                assert_eq!(
                    body.details[1].value,
                    WhiteboxMeasurementValue::Signed(999_999_999)
                );
                assert_eq!(
                    body.details[2].value,
                    WhiteboxMeasurementValue::Signed(1_700_000_000)
                );
            }
        }
    }

    #[test]
    fn actual_sdk_retains_full_width_tsc_without_converting_to_marker_time() {
        let returned = ClockReturn {
            seconds: 0,
            fraction: 0,
            value: u64::MAX,
            unit: "cycles",
        };
        let command = after("1-tsc", 0, returned);
        let bytes = command.encode_frame().expect("bounded maximum-width frame");
        let frame = WhiteboxDoorbellFrame::decode(&bytes).expect("frame decode");
        let WhiteboxMarkerPayload::SemanticMarker(body) =
            decode_whitebox_marker_payload(&frame).expect("payload decode")
        else {
            panic!("semantic marker required")
        };
        assert_eq!(
            body.details[4].value,
            WhiteboxMeasurementValue::Unsigned(u64::MAX)
        );
        assert!(bytes.len() < 512);
    }

    #[test]
    fn actual_sdk_roundtrip_retains_optional_kernel_bases_and_generation() {
        let anchor = vec![
            1,
            2,
            1,
            1000,
            10000,
            u64::MAX,
            4,
            4,
            123,
            100,
            7,
            200,
            1040,
            1080,
            0,
            2,
        ];
        let returned = ClockReturn {
            seconds: 123,
            fraction: 456,
            value: 0,
            unit: "nanoseconds",
        };
        let command = after_with_anchor("0-realtime", 0, returned, Some(anchor.clone()));
        let frame = WhiteboxDoorbellFrame::decode(&command.encode_frame().expect("anchored frame"))
            .expect("decoded anchored frame");
        let WhiteboxMarkerPayload::SemanticMarker(body) =
            decode_whitebox_marker_payload(&frame).expect("typed anchored marker")
        else {
            panic!("semantic marker required")
        };

        assert_eq!(body.details.len(), 6);
        assert_eq!(body.details[5].key, "vvar");
        assert_eq!(
            body.details[5].value,
            WhiteboxMeasurementValue::UnsignedVector(anchor)
        );
    }
}
