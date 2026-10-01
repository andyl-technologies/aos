//! Borrows selected systemd property shapes as DATA, without startup authority.
//!
//! Callers retain the original values and own every purpose, currentness and
//! error check. These helpers do not observe PID1, allocate retained state or
//! strengthen an array's signature beyond the original caller's conversion.
//!
//! ```text
//! SELinuxContext: (false, string)
//! ExecStart:      [(string, array, false, u64, u64, u64, u64, u32, i32, i32)]
//! InvocationID:   array -> sixteen converted u8 values, not all zero
//! ```

use aos_systemd::{OwnedValue, Value};

/// Borrows the exact explicit-context tuple without selecting a trusted SID.
pub(crate) fn explicit_context(value: &OwnedValue) -> Option<&str> {
    let Value::Structure(context) = &**value else {
        return None;
    };
    let [Value::Bool(false), Value::Str(context)] = context.fields() else {
        return None;
    };

    Some(context.as_str())
}

/// Borrows one command's DATA; no field establishes an image or process role.
pub(crate) struct ExecStartData<'value> {
    /// Borrows the reported executable path, not a retained image.
    pub(crate) path: &'value str,
    /// Borrows the original array without converting its element types.
    pub(crate) argv: &'value [Value<'static>],
    /// Reports the command PID as historical DATA, not a process pin.
    pub(crate) pid: u32,
}

/// Borrows the complete singleton command shape before caller-side allocation.
pub(crate) fn single_exec_start(value: &OwnedValue) -> Option<ExecStartData<'_>> {
    let Value::Array(commands) = &**value else {
        return None;
    };
    let [Value::Structure(command)] = commands.inner() else {
        return None;
    };
    let [
        Value::Str(path),
        Value::Array(argv),
        Value::Bool(false),
        Value::U64(_),
        Value::U64(_),
        Value::U64(_),
        Value::U64(_),
        Value::U32(pid),
        Value::I32(_),
        Value::I32(_),
    ] = command.fields()
    else {
        return None;
    };

    Some(ExecStartData {
        path: path.as_str(),
        argv: argv.inner(),
        pid: *pid,
    })
}

/// Converts only the original sixteen-element, nonzero invocation DATA.
pub(crate) fn nonzero_invocation_bytes(values: &[Value<'_>]) -> Option<[u8; 16]> {
    if values.len() != 16 {
        return None;
    }

    let mut invocation = [0; 16];
    for (slot, value) in invocation.iter_mut().zip(values) {
        *slot = u8::try_from(value).ok()?;
    }

    (invocation != [0; 16]).then_some(invocation)
}

#[cfg(test)]
mod tests {
    use super::*;

    type CommandData = (String, Vec<String>, bool, u64, u64, u64, u64, u32, i32, i32);

    fn value(value: impl Into<Value<'static>>) -> OwnedValue {
        OwnedValue::try_from(value.into()).unwrap()
    }

    fn command(ignore_failure: bool) -> CommandData {
        (
            "/selected/executable".into(),
            vec!["/selected/executable".into(), "selected-argument".into()],
            ignore_failure,
            1_u64,
            2_u64,
            3_u64,
            4_u64,
            7_u32,
            0_i32,
            0_i32,
        )
    }

    #[test]
    fn context_requires_only_the_original_false_string_pair() {
        let context = value((false, "untrusted-purpose-data"));

        assert_eq!(explicit_context(&context), Some("untrusted-purpose-data"));
        for malformed in [
            value((true, "untrusted-purpose-data")),
            value((false, 1_u32)),
            value((false, "context", "extra")),
            OwnedValue::from(false),
        ] {
            assert!(explicit_context(&malformed).is_none());
        }
    }

    #[test]
    fn command_borrows_the_same_original_path_and_argument_array() {
        let original = value(vec![command(false)]);
        let Value::Array(commands) = &*original else {
            panic!("fixture is not an array");
        };
        let [Value::Structure(fields)] = commands.inner() else {
            panic!("fixture is not a singleton command");
        };
        let [Value::Str(path), Value::Array(argv), ..] = fields.fields() else {
            panic!("fixture lacks path and argv");
        };

        let parsed = single_exec_start(&original).unwrap();

        assert_eq!(parsed.pid, 7);
        assert_eq!(parsed.path, "/selected/executable");
        assert_eq!(parsed.argv.len(), 2);
        assert!(std::ptr::eq(parsed.path.as_ptr(), path.as_str().as_ptr()));
        assert!(std::ptr::eq(parsed.argv.as_ptr(), argv.inner().as_ptr()));
    }

    #[test]
    fn command_requires_singleton_full_typed_fields_and_false_ignore_failure() {
        let path = "/selected/executable";
        let argv = vec![path, "selected-argument"];
        let wrong_time = value(vec![(
            path,
            argv.clone(),
            false,
            1_u32,
            2_u64,
            3_u64,
            4_u64,
            7_u32,
            0_i32,
            0_i32,
        )]);
        let extra_status = value(vec![(
            path,
            argv.clone(),
            false,
            1_u64,
            2_u64,
            3_u64,
            4_u64,
            7_u32,
            0_i32,
            0_i32,
            0_i32,
        )]);

        for malformed in [
            OwnedValue::from(1_u32),
            value(Vec::<CommandData>::new()),
            value(vec![command(false), command(false)]),
            value(vec![command(true)]),
            value(vec![(path, argv.clone(), false)]),
            wrong_time,
            extra_status,
        ] {
            assert!(single_exec_start(&malformed).is_none());
        }
    }

    #[test]
    fn invocation_keeps_original_width_zero_and_element_conversion_semantics() {
        for bytes in [
            vec![],
            vec![1_u8; 15],
            vec![0_u8; 16],
            vec![1_u8; 16],
            vec![1_u8; 17],
        ] {
            let original = value(bytes.clone());
            let Value::Array(values) = &*original else {
                panic!("fixture is not an array");
            };
            let expected = (bytes.len() == 16 && bytes.iter().any(|byte| *byte != 0))
                .then(|| <[u8; 16]>::try_from(bytes).unwrap());

            assert_eq!(nonzero_invocation_bytes(values.inner()), expected);
        }

        for original in [
            value(vec![1_u32; 16]),
            value(vec!["not-a-byte"; 16]),
            value((0..16).map(|_| Value::new(Value::from(1_u8))).collect::<Vec<_>>()),
        ] {
            let Value::Array(values) = &*original else {
                panic!("fixture is not an array");
            };
            // The old callers used this exact per-element conversion, not an
            // array-signature check. Preserve its treatment of variants too.
            let converted = values.inner().iter().map(u8::try_from)
                .collect::<Result<Vec<_>, _>>()
                .ok();
            let expected = converted.and_then(|bytes| {
                let bytes: [u8; 16] = bytes.try_into().ok()?;
                (bytes != [0; 16]).then_some(bytes)
            });

            assert_eq!(nonzero_invocation_bytes(values.inner()), expected);
        }
    }
}
