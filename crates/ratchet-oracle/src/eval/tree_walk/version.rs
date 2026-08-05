//! Derivation-name splitting and Nix version-string comparison helpers.

pub(crate) fn base_name_range(bytes: &[u8]) -> (usize, usize) {
    if bytes.is_empty() {
        return (0, 0);
    }
    let mut last = bytes.len() - 1;
    if bytes[last] == b'/' && last > 0 {
        last -= 1;
    }
    let start = bytes[..=last]
        .iter()
        .rposition(|byte| *byte == b'/')
        .map_or(0, |index| index + 1);
    (start, last + 1 - start)
}

pub(crate) fn parse_drv_name_split(bytes: &[u8]) -> (usize, usize) {
    if let Some(dash) = bytes
        .windows(2)
        .position(|pair| pair[0] == b'-' && !pair[1].is_ascii_alphabetic())
    {
        (dash, dash + 1)
    } else {
        (bytes.len(), bytes.len())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SplitVersionRanges<'a> {
    pub(crate) bytes: &'a [u8],
    pub(crate) next: usize,
}

impl<'a> SplitVersionRanges<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, next: 0 }
    }
}

impl Iterator for SplitVersionRanges<'_> {
    type Item = (usize, usize);

    fn next(&mut self) -> Option<Self::Item> {
        while self
            .bytes
            .get(self.next)
            .is_some_and(|byte| matches!(*byte, b'.' | b'-'))
        {
            self.next += 1;
        }
        let start = self.next;
        let first = *self.bytes.get(start)?;
        let digit = first.is_ascii_digit();
        self.next += 1;
        while self
            .bytes
            .get(self.next)
            .is_some_and(|byte| !matches!(*byte, b'.' | b'-') && byte.is_ascii_digit() == digit)
        {
            self.next += 1;
        }
        Some((start, self.next))
    }
}

pub(crate) fn compare_version_bytes(left: &[u8], right: &[u8]) -> i64 {
    let mut left_ranges = SplitVersionRanges::new(left);
    let mut right_ranges = SplitVersionRanges::new(right);
    loop {
        let left_range = left_ranges.next();
        let right_range = right_ranges.next();
        let (Some((left_start, left_end)), Some((right_start, right_end))) =
            (left_range, right_range)
        else {
            return match (left_range, right_range) {
                (None, None) => 0,
                (Some((left_start, left_end)), None) => {
                    compare_version_components(&left[left_start..left_end], b"")
                }
                (None, Some((right_start, right_end))) => {
                    compare_version_components(b"", &right[right_start..right_end])
                }
                (Some(_), Some(_)) => unreachable!("both ranges were matched above"),
            };
        };
        let ordering =
            compare_version_components(&left[left_start..left_end], &right[right_start..right_end]);
        if ordering != 0 {
            return ordering;
        }
    }
}

pub(crate) fn compare_version_components(left: &[u8], right: &[u8]) -> i64 {
    if left == right {
        return 0;
    }
    if left == b"pre" {
        return -1;
    }
    if right == b"pre" {
        return 1;
    }
    let left_digit = left.first().is_some_and(u8::is_ascii_digit);
    let right_digit = right.first().is_some_and(u8::is_ascii_digit);
    match (left_digit, right_digit) {
        (true, true) => compare_version_numbers(left, right),
        (true, false) => 1,
        (false, true) => -1,
        (false, false) => match left.cmp(right) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        },
    }
}

pub(crate) fn compare_version_numbers(left: &[u8], right: &[u8]) -> i64 {
    let left = trim_version_leading_zeroes(left);
    let right = trim_version_leading_zeroes(right);
    match left.len().cmp(&right.len()) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Greater => 1,
        std::cmp::Ordering::Equal => match left.cmp(right) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        },
    }
}

pub(crate) fn trim_version_leading_zeroes(bytes: &[u8]) -> &[u8] {
    let first_non_zero = bytes
        .iter()
        .position(|byte| *byte != b'0')
        .unwrap_or(bytes.len());
    &bytes[first_non_zero..]
}
