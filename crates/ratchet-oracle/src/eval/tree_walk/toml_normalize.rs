//! TOML numeric-overflow normalization for `builtins.fromTOML`.

pub(crate) fn normalize_toml_numeric_overflows(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut normalized = String::new();
    let mut changed = false;
    let mut last = 0usize;
    let mut index = 0usize;
    let mut array_depth = 0usize;

    while index < bytes.len() {
        match bytes[index] {
            b'#' => {
                index = skip_toml_comment(bytes, index);
            }
            b'"' => {
                index = skip_toml_basic_string(bytes, index);
            }
            b'\'' => {
                index = skip_toml_literal_string(bytes, index);
            }
            b'[' if array_depth == 0 && toml_line_prefix_is_whitespace(bytes, index) => {
                index = skip_toml_comment(bytes, index);
            }
            b'[' => {
                array_depth += 1;
                index += 1;
            }
            b']' => {
                array_depth = array_depth.saturating_sub(1);
                index += 1;
            }
            _ => {
                if let Some((end, replacement)) = normalize_toml_float_at(source, index)
                    .or_else(|| normalize_toml_integer_at(source, index))
                {
                    normalized.push_str(&source[last..index]);
                    normalized.push_str(&replacement);
                    last = end;
                    index = end;
                    changed = true;
                } else {
                    index += 1;
                }
            }
        }
    }

    if changed {
        normalized.push_str(&source[last..]);
        normalized
    } else {
        source.to_owned()
    }
}

fn toml_line_prefix_is_whitespace(bytes: &[u8], start: usize) -> bool {
    let mut line_start = start;
    while line_start > 0 && !matches!(bytes[line_start - 1], b'\n' | b'\r') {
        line_start -= 1;
    }
    bytes[line_start..start]
        .iter()
        .all(|byte| matches!(byte, b' ' | b'\t'))
}

fn skip_toml_comment(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() && !matches!(bytes[index], b'\n' | b'\r') {
        index += 1;
    }
    index
}

fn skip_toml_basic_string(bytes: &[u8], mut index: usize) -> usize {
    if bytes.get(index..index + 3) == Some(b"\"\"\"") {
        index += 3;
        while index < bytes.len() {
            if bytes.get(index..index + 3) == Some(b"\"\"\"") {
                return index + 3;
            }
            if bytes[index] == b'\\' && index + 1 < bytes.len() {
                index += 2;
            } else {
                index += 1;
            }
        }
        return index;
    }

    index += 1;
    while index < bytes.len() {
        if bytes[index] == b'\\' && index + 1 < bytes.len() {
            index += 2;
        } else if bytes[index] == b'"' {
            return index + 1;
        } else {
            index += 1;
        }
    }
    index
}

fn skip_toml_literal_string(bytes: &[u8], mut index: usize) -> usize {
    if bytes.get(index..index + 3) == Some(b"'''") {
        index += 3;
        while index < bytes.len() {
            if bytes.get(index..index + 3) == Some(b"'''") {
                return index + 3;
            }
            index += 1;
        }
        return index;
    }

    index += 1;
    while index < bytes.len() {
        if bytes[index] == b'\'' {
            return index + 1;
        }
        index += 1;
    }
    index
}

fn normalize_toml_float_at(source: &str, start: usize) -> Option<(usize, String)> {
    let bytes = source.as_bytes();
    if !toml_integer_has_start_boundary(bytes, start) {
        return None;
    }

    let mut integer_start = start;
    if matches!(bytes[start], b'+' | b'-') {
        integer_start += 1;
    }
    if !bytes.get(integer_start).is_some_and(u8::is_ascii_digit) {
        return None;
    }

    let mut end = integer_start;
    while bytes
        .get(end)
        .is_some_and(|byte| byte.is_ascii_digit() || *byte == b'_')
    {
        end += 1;
    }
    if !toml_integer_underscores_are_valid(&source[integer_start..end], 10)
        || !toml_decimal_leading_zeroes_are_valid(&source[integer_start..end])
    {
        return None;
    }

    let mut is_float = false;
    if bytes.get(end) == Some(&b'.') {
        let fraction_start = end + 1;
        let mut fraction_end = fraction_start;
        while bytes
            .get(fraction_end)
            .is_some_and(|byte| byte.is_ascii_digit() || *byte == b'_')
        {
            fraction_end += 1;
        }
        if !toml_integer_underscores_are_valid(&source[fraction_start..fraction_end], 10) {
            return None;
        }
        end = fraction_end;
        is_float = true;
    }

    if matches!(bytes.get(end), Some(b'e' | b'E')) {
        let mut exponent_start = end + 1;
        if matches!(bytes.get(exponent_start), Some(b'+' | b'-')) {
            exponent_start += 1;
        }
        let mut exponent_end = exponent_start;
        while bytes
            .get(exponent_end)
            .is_some_and(|byte| byte.is_ascii_digit() || *byte == b'_')
        {
            exponent_end += 1;
        }
        if !toml_integer_underscores_are_valid(&source[exponent_start..exponent_end], 10) {
            return None;
        }
        end = exponent_end;
        is_float = true;
    }

    if !is_float || !toml_integer_has_value_terminator(bytes, end) {
        return None;
    }

    let cleaned = source[start..end].replace('_', "");
    let value = cleaned.parse::<f64>().ok()?;
    if value.is_infinite() {
        Some((
            end,
            if value.is_sign_negative() {
                "-inf".to_owned()
            } else {
                "inf".to_owned()
            },
        ))
    } else {
        None
    }
}

fn normalize_toml_integer_at(source: &str, start: usize) -> Option<(usize, String)> {
    let bytes = source.as_bytes();
    if !toml_integer_has_start_boundary(bytes, start) {
        return None;
    }

    let mut digits_start = start;
    let mut sign = 1i8;
    if matches!(bytes[start], b'+' | b'-') {
        sign = if bytes[start] == b'-' { -1 } else { 1 };
        digits_start += 1;
    }
    if !bytes.get(digits_start).is_some_and(u8::is_ascii_digit) {
        return None;
    }

    let (base, end) = if digits_start == start
        && bytes.get(digits_start) == Some(&b'0')
        && matches!(bytes.get(digits_start + 1), Some(b'x' | b'o' | b'b'))
    {
        let base = match bytes.get(digits_start + 1).copied() {
            Some(b'x') => 16,
            Some(b'o') => 8,
            Some(b'b') => 2,
            _ => return None,
        };
        let mut end = digits_start + 2;
        while bytes
            .get(end)
            .is_some_and(|byte| toml_integer_digit_or_underscore(*byte, base))
        {
            end += 1;
        }
        if end == digits_start + 2
            || !toml_integer_underscores_are_valid(&source[digits_start + 2..end], base)
        {
            return None;
        }
        (base, end)
    } else {
        let mut end = digits_start;
        while bytes
            .get(end)
            .is_some_and(|byte| byte.is_ascii_digit() || *byte == b'_')
        {
            end += 1;
        }
        if !toml_integer_underscores_are_valid(&source[digits_start..end], 10) {
            return None;
        }
        if !toml_decimal_leading_zeroes_are_valid(&source[digits_start..end]) {
            return None;
        }
        (10, end)
    };

    if !toml_integer_has_value_terminator(bytes, end) {
        return None;
    }

    normalized_toml_integer_replacement(&source[start..end], base, sign).map(|value| (end, value))
}

fn toml_integer_has_start_boundary(bytes: &[u8], start: usize) -> bool {
    let Some(byte) = bytes.get(start).copied() else {
        return false;
    };
    let starts_integer = byte.is_ascii_digit()
        || (matches!(byte, b'+' | b'-') && bytes.get(start + 1).is_some_and(u8::is_ascii_digit));
    if !starts_integer {
        return false;
    }
    start == 0
        || !matches!(
            bytes[start - 1],
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'+' | b'-'
        )
}

fn toml_integer_has_value_terminator(bytes: &[u8], end: usize) -> bool {
    let mut index = end;
    while matches!(bytes.get(index), Some(b' ' | b'\t')) {
        index += 1;
    }
    matches!(
        bytes.get(index),
        None | Some(b'\n' | b'\r' | b'#' | b',' | b']' | b'}')
    )
}

fn toml_integer_digit_or_underscore(byte: u8, base: u32) -> bool {
    byte == b'_'
        || match base {
            2 => matches!(byte, b'0' | b'1'),
            8 => matches!(byte, b'0'..=b'7'),
            16 => byte.is_ascii_hexdigit(),
            _ => byte.is_ascii_digit(),
        }
}

fn toml_integer_underscores_are_valid(raw: &str, base: u32) -> bool {
    let bytes = raw.as_bytes();
    if bytes.is_empty() || matches!(bytes.first(), Some(b'_')) || matches!(bytes.last(), Some(b'_'))
    {
        return false;
    }
    for window in bytes.windows(2) {
        if window == b"__" {
            return false;
        }
    }
    bytes.iter().all(|byte| match *byte {
        b'_' => true,
        byte => toml_integer_digit_or_underscore(byte, base),
    })
}

fn toml_decimal_leading_zeroes_are_valid(raw: &str) -> bool {
    let mut digits = raw.bytes().filter(|byte| *byte != b'_');
    digits.next() != Some(b'0') || digits.next().is_none()
}

fn normalized_toml_integer_replacement(raw: &str, base: u32, sign: i8) -> Option<String> {
    match base {
        10 => normalized_toml_decimal_replacement(raw, sign),
        2 => normalized_toml_binary_replacement(raw),
        8 | 16 => normalized_toml_unsigned_saturating_replacement(raw, base),
        _ => None,
    }
}

fn normalized_toml_decimal_replacement(raw: &str, sign: i8) -> Option<String> {
    let cleaned = raw.replace('_', "");
    match cleaned.parse::<i128>() {
        Ok(value) if value < i64::MIN as i128 => Some(i64::MIN.to_string()),
        Ok(value) if value > i64::MAX as i128 => Some(i64::MAX.to_string()),
        Ok(_) => None,
        Err(_) if sign < 0 => Some(i64::MIN.to_string()),
        Err(_) => Some(i64::MAX.to_string()),
    }
}

fn normalized_toml_unsigned_saturating_replacement(raw: &str, base: u32) -> Option<String> {
    let digits = raw[2..].replace('_', "");
    match u128::from_str_radix(&digits, base) {
        Ok(value) if value <= i64::MAX as u128 => None,
        Ok(_) | Err(_) => Some(i64::MAX.to_string()),
    }
}

fn normalized_toml_binary_replacement(raw: &str) -> Option<String> {
    let digits = raw[2..].replace('_', "");
    let significant = digits.trim_start_matches('0');
    if significant.len() <= 63 {
        return None;
    }

    let mut value = 0u64;
    for byte in significant.bytes() {
        value = (value << 1) | u64::from(byte == b'1');
    }
    Some((value as i64).to_string())
}
