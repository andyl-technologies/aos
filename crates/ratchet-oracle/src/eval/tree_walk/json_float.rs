//! Byte-exact port of nlohmann/json's Grisu2 float printer for `toJSON`.
//!
//! C++ Nix 2.24 renders `builtins.toJSON` floats through nlohmann/json's
//! `detail::to_chars`, a Grisu2 implementation derived from Florian
//! Loitsch's reference code (MIT, (c) 2009 Florian Loitsch; nlohmann/json
//! 3.11.x `detail/conversions/to_chars.hpp`). Grisu2 is round-trip correct
//! but *not always shortest*: for example `5e22` prints as
//! `4.9999999999999996e+22`. A generic shortest-representation formatter
//! (Ryu, `serde_json`, Rust's `{}`) therefore diverges from C++ Nix on the
//! doubles where Grisu2 misses the shortest form, so this module ports the
//! nlohmann algorithm exactly — digit generation, the cached powers-of-ten
//! table, the `%.*g`-style buffer formatting, and the two-digit-minimum
//! exponent — rather than approximating it.
//!
//! Sample renderings (verified against `nix-instantiate --eval --json`):
//!
//! ```text
//! 1.5      -> 1.5          5e22    -> 4.9999999999999996e+22
//! 100.0    -> 100.0        1e-7    -> 1e-07
//! -0.0     -> -0.0         2.5e15  -> 2.5e+15
//! 0.0001   -> 0.0001       1e-5    -> 1e-05
//! ```
//!
//! This printer is specific to the JSON surface. `toString` and `.drv`
//! serialization use the C++ `std::to_string`-style `%f` path
//! (`to_string_float_bytes`), which must not be conflated with this one.

/// A DIY floating-point value `f * 2^e` with a 64-bit significand
/// (nlohmann `dtoa_impl::diyfp`).
#[derive(Clone, Copy)]
struct DiyFp {
    f: u64,
    e: i32,
}

impl DiyFp {
    /// Returns `x - y`, requiring `x.e == y.e` and `x.f >= y.f`.
    fn sub(x: DiyFp, y: DiyFp) -> DiyFp {
        debug_assert_eq!(x.e, y.e);
        debug_assert!(x.f >= y.f);
        DiyFp {
            f: x.f - y.f,
            e: x.e,
        }
    }

    /// Returns `x * y`, keeping the rounded upper 64 bits of the product
    /// (round to nearest, ties up — matching nlohmann's `diyfp::mul`).
    fn mul(x: DiyFp, y: DiyFp) -> DiyFp {
        let product = u128::from(x.f) * u128::from(y.f);
        let rounded_high = ((product + (1u128 << 63)) >> 64) as u64;
        DiyFp {
            f: rounded_high,
            e: x.e + y.e + 64,
        }
    }

    /// Normalizes `x` so that the significand's top bit is set.
    fn normalize(mut x: DiyFp) -> DiyFp {
        debug_assert!(x.f != 0);
        while (x.f >> 63) == 0 {
            x.f <<= 1;
            x.e -= 1;
        }
        x
    }

    /// Normalizes `x` to the exponent `target`, which must not exceed `x.e`.
    fn normalize_to(x: DiyFp, target: i32) -> DiyFp {
        let delta = x.e - target;
        debug_assert!(delta >= 0);
        DiyFp {
            f: x.f << delta,
            e: target,
        }
    }
}

/// The value `w` and its rounding-boundary neighbors `m-` / `m+`.
struct Boundaries {
    w: DiyFp,
    minus: DiyFp,
    plus: DiyFp,
}

/// Computes the normalized `DiyFp` for a finite positive double and the
/// boundaries of its rounding interval (nlohmann `compute_boundaries`).
fn compute_boundaries(value: f64) -> Boundaries {
    debug_assert!(value.is_finite() && value > 0.0);
    // IEEE-754 binary64: p = 53 significand bits (with hidden bit).
    const PRECISION: i32 = 53;
    const BIAS: i32 = 1023 + (PRECISION - 1);
    const MIN_EXP: i32 = 1 - BIAS;
    const HIDDEN_BIT: u64 = 1u64 << (PRECISION - 1);

    let bits = value.to_bits();
    let biased_exponent = bits >> (PRECISION - 1);
    let fraction = bits & (HIDDEN_BIT - 1);

    let v = if biased_exponent == 0 {
        DiyFp {
            f: fraction,
            e: MIN_EXP,
        }
    } else {
        DiyFp {
            f: fraction + HIDDEN_BIT,
            e: biased_exponent as i32 - BIAS,
        }
    };

    // The lower boundary is closer when the significand is a power of two
    // (except at the minimum exponent).
    let lower_boundary_is_closer = fraction == 0 && biased_exponent > 1;
    let m_plus = DiyFp {
        f: 2 * v.f + 1,
        e: v.e - 1,
    };
    let m_minus = if lower_boundary_is_closer {
        DiyFp {
            f: 4 * v.f - 1,
            e: v.e - 2,
        }
    } else {
        DiyFp {
            f: 2 * v.f - 1,
            e: v.e - 1,
        }
    };

    let w_plus = DiyFp::normalize(m_plus);
    let w_minus = DiyFp::normalize_to(m_minus, w_plus.e);
    Boundaries {
        w: DiyFp::normalize(v),
        minus: w_minus,
        plus: w_plus,
    }
}

/// Grisu2's digit-generation window `[alpha, gamma]` for the scaled
/// exponent (nlohmann `kAlpha` / `kGamma`).
const ALPHA: i32 = -60;

/// A cached power of ten `c ~= 10^k` stored as `f * 2^e`.
struct CachedPower {
    f: u64,
    e: i32,
    k: i32,
}

/// nlohmann's 79-entry cached powers-of-ten table (decimal exponents
/// `-300..=324` in steps of 8), copied verbatim from `to_chars.hpp`.
const CACHED_POWERS: [CachedPower; 79] = {
    /// Shorthand constructor keeping the table rows compact.
    const fn row(f: u64, e: i32, k: i32) -> CachedPower {
        CachedPower { f, e, k }
    }
    [
        row(0xAB70FE17C79AC6CA, -1060, -300),
        row(0xFF77B1FCBEBCDC4F, -1034, -292),
        row(0xBE5691EF416BD60C, -1007, -284),
        row(0x8DD01FAD907FFC3C, -980, -276),
        row(0xD3515C2831559A83, -954, -268),
        row(0x9D71AC8FADA6C9B5, -927, -260),
        row(0xEA9C227723EE8BCB, -901, -252),
        row(0xAECC49914078536D, -874, -244),
        row(0x823C12795DB6CE57, -847, -236),
        row(0xC21094364DFB5637, -821, -228),
        row(0x9096EA6F3848984F, -794, -220),
        row(0xD77485CB25823AC7, -768, -212),
        row(0xA086CFCD97BF97F4, -741, -204),
        row(0xEF340A98172AACE5, -715, -196),
        row(0xB23867FB2A35B28E, -688, -188),
        row(0x84C8D4DFD2C63F3B, -661, -180),
        row(0xC5DD44271AD3CDBA, -635, -172),
        row(0x936B9FCEBB25C996, -608, -164),
        row(0xDBAC6C247D62A584, -582, -156),
        row(0xA3AB66580D5FDAF6, -555, -148),
        row(0xF3E2F893DEC3F126, -529, -140),
        row(0xB5B5ADA8AAFF80B8, -502, -132),
        row(0x87625F056C7C4A8B, -475, -124),
        row(0xC9BCFF6034C13053, -449, -116),
        row(0x964E858C91BA2655, -422, -108),
        row(0xDFF9772470297EBD, -396, -100),
        row(0xA6DFBD9FB8E5B88F, -369, -92),
        row(0xF8A95FCF88747D94, -343, -84),
        row(0xB94470938FA89BCF, -316, -76),
        row(0x8A08F0F8BF0F156B, -289, -68),
        row(0xCDB02555653131B6, -263, -60),
        row(0x993FE2C6D07B7FAC, -236, -52),
        row(0xE45C10C42A2B3B06, -210, -44),
        row(0xAA242499697392D3, -183, -36),
        row(0xFD87B5F28300CA0E, -157, -28),
        row(0xBCE5086492111AEB, -130, -20),
        row(0x8CBCCC096F5088CC, -103, -12),
        row(0xD1B71758E219652C, -77, -4),
        row(0x9C40000000000000, -50, 4),
        row(0xE8D4A51000000000, -24, 12),
        row(0xAD78EBC5AC620000, 3, 20),
        row(0x813F3978F8940984, 30, 28),
        row(0xC097CE7BC90715B3, 56, 36),
        row(0x8F7E32CE7BEA5C70, 83, 44),
        row(0xD5D238A4ABE98068, 109, 52),
        row(0x9F4F2726179A2245, 136, 60),
        row(0xED63A231D4C4FB27, 162, 68),
        row(0xB0DE65388CC8ADA8, 189, 76),
        row(0x83C7088E1AAB65DB, 216, 84),
        row(0xC45D1DF942711D9A, 242, 92),
        row(0x924D692CA61BE758, 269, 100),
        row(0xDA01EE641A708DEA, 295, 108),
        row(0xA26DA3999AEF774A, 322, 116),
        row(0xF209787BB47D6B85, 348, 124),
        row(0xB454E4A179DD1877, 375, 132),
        row(0x865B86925B9BC5C2, 402, 140),
        row(0xC83553C5C8965D3D, 428, 148),
        row(0x952AB45CFA97A0B3, 455, 156),
        row(0xDE469FBD99A05FE3, 481, 164),
        row(0xA59BC234DB398C25, 508, 172),
        row(0xF6C69A72A3989F5C, 534, 180),
        row(0xB7DCBF5354E9BECE, 561, 188),
        row(0x88FCF317F22241E2, 588, 196),
        row(0xCC20CE9BD35C78A5, 614, 204),
        row(0x98165AF37B2153DF, 641, 212),
        row(0xE2A0B5DC971F303A, 667, 220),
        row(0xA8D9D1535CE3B396, 694, 228),
        row(0xFB9B7CD9A4A7443C, 720, 236),
        row(0xBB764C4CA7A44410, 747, 244),
        row(0x8BAB8EEFB6409C1A, 774, 252),
        row(0xD01FEF10A657842C, 800, 260),
        row(0x9B10A4E5E9913129, 827, 268),
        row(0xE7109BFBA19C0C9D, 853, 276),
        row(0xAC2820D9623BF429, 880, 284),
        row(0x80444B5E7AA7CF85, 907, 292),
        row(0xBF21E44003ACDD2D, 933, 300),
        row(0x8E679C2F5E44FF8F, 960, 308),
        row(0xD433179D9C8CB841, 986, 316),
        row(0x9E19DB92B4E31BA9, 1013, 324),
    ]
};

/// Returns the cached power of ten scaling a binary exponent `e` into the
/// Grisu window (nlohmann `get_cached_power_for_binary_exponent`).
fn cached_power_for_binary_exponent(e: i32) -> &'static CachedPower {
    const MIN_DEC_EXP: i32 = -300;
    const DEC_STEP: i32 = 8;
    debug_assert!((-1500..=1500).contains(&e));
    // Integer approximation of k = ceil((ALPHA - e - 1) * log10(2)); both
    // divisions truncate toward zero exactly as the C++ original.
    let f = ALPHA - e - 1;
    let k = (f * 78913) / (1 << 18) + i32::from(f > 0);
    let index = (-MIN_DEC_EXP + k + (DEC_STEP - 1)) / DEC_STEP;
    &CACHED_POWERS[index as usize]
}

/// For `n != 0`, returns `(k, 10^(k-1))` such that `10^(k-1) <= n < 10^k`.
fn find_largest_pow10(n: u32) -> (i32, u32) {
    match n {
        1_000_000_000.. => (10, 1_000_000_000),
        100_000_000.. => (9, 100_000_000),
        10_000_000.. => (8, 10_000_000),
        1_000_000.. => (7, 1_000_000),
        100_000.. => (6, 100_000),
        10_000.. => (5, 10_000),
        1_000.. => (4, 1_000),
        100.. => (3, 100),
        10.. => (2, 10),
        _ => (1, 1),
    }
}

/// Decrements the generated digits toward `w` while the result stays inside
/// `[M-, M+]` (nlohmann `grisu2_round`).
fn grisu2_round(buffer: &mut [u8], length: usize, dist: u64, delta: u64, mut rest: u64, ten_k: u64) {
    debug_assert!(length >= 1);
    debug_assert!(dist <= delta && rest <= delta && ten_k > 0);
    while rest < dist
        && delta - rest >= ten_k
        && (rest + ten_k < dist || dist - rest > rest + ten_k - dist)
    {
        debug_assert!(buffer[length - 1] != b'0');
        buffer[length - 1] -= 1;
        rest += ten_k;
    }
}

/// Generates the decimal digits of a value in `[M-, M+]`, returning the
/// digit count and updating the decimal exponent (nlohmann
/// `grisu2_digit_gen`).
fn grisu2_digit_gen(
    buffer: &mut [u8],
    decimal_exponent: &mut i32,
    m_minus: DiyFp,
    w: DiyFp,
    m_plus: DiyFp,
) -> usize {
    debug_assert!(m_plus.e >= ALPHA && m_plus.e <= -32);
    let mut delta = DiyFp::sub(m_plus, m_minus).f;
    let dist = DiyFp::sub(m_plus, w).f;

    // Split M+ = f * 2^e into an integral part p1 and fractional part p2.
    let one = DiyFp {
        f: 1u64 << -m_plus.e,
        e: m_plus.e,
    };
    let mut p1 = (m_plus.f >> -one.e) as u32;
    let mut p2 = m_plus.f & (one.f - 1);
    debug_assert!(p1 > 0);

    let mut length = 0usize;
    let (k, mut pow10) = find_largest_pow10(p1);

    // 1) Digits of the integral part.
    let mut n = k;
    while n > 0 {
        let d = p1 / pow10;
        let r = p1 % pow10;
        debug_assert!(d <= 9);
        buffer[length] = b'0' + d as u8;
        length += 1;
        p1 = r;
        n -= 1;

        let rest = (u64::from(p1) << -one.e) + p2;
        if rest <= delta {
            *decimal_exponent += n;
            let ten_n = u64::from(pow10) << -one.e;
            grisu2_round(buffer, length, dist, delta, rest, ten_n);
            return length;
        }
        pow10 /= 10;
    }

    // 2) Digits of the fractional part.
    debug_assert!(p2 > delta);
    let mut m = 0i32;
    let mut dist = dist;
    loop {
        p2 *= 10;
        let d = p2 >> -one.e;
        let r = p2 & (one.f - 1);
        debug_assert!(d <= 9);
        buffer[length] = b'0' + d as u8;
        length += 1;
        p2 = r;
        m += 1;

        delta *= 10;
        dist *= 10;
        if p2 <= delta {
            break;
        }
    }

    *decimal_exponent -= m;
    grisu2_round(buffer, length, dist, delta, p2, one.f);
    length
}

/// Runs Grisu2 for a finite positive double, filling `buffer` with the
/// digits and returning `(length, decimal_exponent)` such that
/// `value ~= buffer * 10^decimal_exponent`.
fn grisu2(buffer: &mut [u8], value: f64) -> (usize, i32) {
    let boundaries = compute_boundaries(value);
    let cached = cached_power_for_binary_exponent(boundaries.plus.e);
    let c_minus_k = DiyFp {
        f: cached.f,
        e: cached.e,
    };
    let w = DiyFp::mul(boundaries.w, c_minus_k);
    let w_minus = DiyFp::mul(boundaries.minus, c_minus_k);
    let w_plus = DiyFp::mul(boundaries.plus, c_minus_k);

    // Account for the rounding in the scaled products by shrinking the
    // boundary interval by one ulp on each side.
    let m_minus = DiyFp {
        f: w_minus.f + 1,
        e: w_minus.e,
    };
    let m_plus = DiyFp {
        f: w_plus.f - 1,
        e: w_plus.e,
    };

    let mut decimal_exponent = -cached.k;
    let length = grisu2_digit_gen(buffer, &mut decimal_exponent, m_minus, w, m_plus);
    (length, decimal_exponent)
}

/// Appends `e` as a sign plus at-least-two exponent digits (nlohmann
/// `append_exponent`, `printf %g` compatible).
fn append_exponent(out: &mut Vec<u8>, e: i32) {
    debug_assert!((-1000..1000).contains(&e));
    let k = if e < 0 {
        out.push(b'-');
        (-e) as u32
    } else {
        out.push(b'+');
        e as u32
    };
    if k < 10 {
        out.push(b'0');
        out.push(b'0' + k as u8);
    } else if k < 100 {
        out.push(b'0' + (k / 10) as u8);
        out.push(b'0' + (k % 10) as u8);
    } else {
        out.push(b'0' + (k / 100) as u8);
        out.push(b'0' + (k / 10 % 10) as u8);
        out.push(b'0' + (k % 10) as u8);
    }
}

/// Lays out the generated digits as fixed-point or scientific notation
/// (nlohmann `format_buffer` with `kMinExp = -4`, `kMaxExp = digits10`).
fn format_buffer(out: &mut Vec<u8>, digits: &[u8], decimal_exponent: i32) {
    const MIN_EXP: i32 = -4;
    const MAX_EXP: i32 = 15; // std::numeric_limits<double>::digits10
    let k = digits.len() as i32;
    let n = k + decimal_exponent;

    if k <= n && n <= MAX_EXP {
        // digits[000].0
        out.extend_from_slice(digits);
        out.resize(out.len() + (n - k) as usize, b'0');
        out.extend_from_slice(b".0");
    } else if 0 < n && n <= MAX_EXP {
        // dig.its
        out.extend_from_slice(&digits[..n as usize]);
        out.push(b'.');
        out.extend_from_slice(&digits[n as usize..]);
    } else if MIN_EXP < n && n <= 0 {
        // 0.[000]digits
        out.extend_from_slice(b"0.");
        out.resize(out.len() + (-n) as usize, b'0');
        out.extend_from_slice(digits);
    } else {
        // d[.igits]e+123
        out.push(digits[0]);
        if k > 1 {
            out.push(b'.');
            out.extend_from_slice(&digits[1..]);
        }
        out.push(b'e');
        append_exponent(out, n - 1);
    }
}

/// Renders a finite double exactly as nlohmann/json's `detail::to_chars`
/// (the C++ Nix 2.24 `builtins.toJSON` float printer).
///
/// Negative zero renders as `-0.0`, matching the C++ `signbit` handling.
///
/// # Panics
///
/// Panics in debug builds when `value` is non-finite; callers render NaN
/// and infinities as JSON `null` before reaching this function.
pub(crate) fn nlohmann_json_float_bytes(value: f64) -> Vec<u8> {
    debug_assert!(value.is_finite());
    let mut out = Vec::with_capacity(32);
    let magnitude = if value.is_sign_negative() {
        out.push(b'-');
        -value
    } else {
        value
    };
    if magnitude == 0.0 {
        out.extend_from_slice(b"0.0");
        return out;
    }
    // max_digits10 (17) digits plus slack, as in the C++ buffer sizing.
    let mut digits = [0u8; 32];
    let (length, decimal_exponent) = grisu2(&mut digits, magnitude);
    format_buffer(&mut out, &digits[..length], decimal_exponent);
    out
}

#[cfg(test)]
mod tests {
    use super::nlohmann_json_float_bytes;

    fn render(value: f64) -> String {
        String::from_utf8(nlohmann_json_float_bytes(value)).expect("printer emits ASCII")
    }

    /// Fixed vectors captured from `nix-instantiate --eval --json --expr
    /// 'builtins.toJSON [...]'` (Nix 2.24.5, nlohmann Grisu2).
    #[test]
    fn matches_cpp_nix_tojson_renderings() {
        for (value, expected) in [
            (1.5, "1.5"),
            (0.1, "0.1"),
            (1.0e-7, "1e-07"),
            (1.0e22, "1e+22"),
            // Grisu2's non-shortest case from eval-okay-fromTOML.
            (5.0e22, "4.9999999999999996e+22"),
            (1.7976931348623157e308, "1.7976931348623157e+308"),
            (2.2250738585072014e-308, "2.2250738585072014e-308"),
            (3.141592653589793, "3.141592653589793"),
            (0.0, "0.0"),
            (-0.0, "-0.0"),
            (100.0, "100.0"),
            (2.5e15, "2.5e+15"),
            (1.0, "1.0"),
            (1.0 / 3.0, "0.3333333333333333"),
            (0.30000000000000004, "0.30000000000000004"),
            (123456789012345680.0, "1.2345678901234568e+17"),
            (1.0e100, "1e+100"),
            (6.02e23, "6.02e+23"),
            (-1.5, "-1.5"),
            (0.001, "0.001"),
            (1.0e-5, "1e-05"),
            (9007199254740993.0, "9.007199254740992e+15"),
            (2.0e15, "2e+15"),
            (1.23456789e-300, "1.23456789e-300"),
            (4.35e-5, "4.35e-05"),
            (1.0e15, "1e+15"),
            (1.0e16, "1e+16"),
            (1.0e21, "1e+21"),
            (1.0e-4, "0.0001"),
            (12345678901234567890.0, "1.2345678901234567e+19"),
            (767.0, "767.0"),
            (65.6, "65.6"),
            (3.0517578125e-5, "3.0517578125e-05"),
            (5.0e-324, "5e-324"),
            (1.1125369292536007e-308, "1.1125369292536007e-308"),
            (f64::MIN_POSITIVE, "2.2250738585072014e-308"),
            (0.000001, "1e-06"),
        ] {
            assert_eq!(render(value), expected, "value {value:?}");
        }
    }

    /// Round-trip property: Grisu2 output always parses back to the input.
    #[test]
    fn renderings_round_trip() {
        let mut state = 0x9E3779B97F4A7C15u64;
        for _ in 0..200_000 {
            // SplitMix64 over raw bit patterns.
            state = state.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            let bits = z ^ (z >> 31);
            let value = f64::from_bits(bits);
            if !value.is_finite() {
                continue;
            }
            let rendered = render(value);
            let reparsed: f64 = rendered.parse().expect("rendering parses as f64");
            assert_eq!(
                reparsed.to_bits(),
                value.to_bits(),
                "round trip for {value:?} via {rendered}"
            );
        }
    }
}
