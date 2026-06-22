#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    aos_nix_fuzz::fuzz_parity_json(data);
});
