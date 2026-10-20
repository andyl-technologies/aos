//! Native entropy for fresh protected Root challenges.

use std::io;

/// Reads one complete fresh nonce without creating role authority.
///
/// # Errors
/// Returns the original entropy error, or rejects a zero-length native read.
pub fn fresh_root_nonce() -> io::Result<[u8; 16]> {
    let mut nonce = [0_u8; 16];
    let mut filled = 0;
    while filled < nonce.len() {
        let count =
            rustix::rand::getrandom(&mut nonce[filled..], rustix::rand::GetRandomFlags::empty())
                .map_err(io::Error::other)?;
        if count == 0 {
            return Err(io::Error::other("root entropy unavailable"));
        }
        filled += count;
    }
    Ok(nonce)
}
