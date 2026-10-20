//! Enables and measures Linux fs-verity on retained read-only descriptors.
//!
//! Kernel measurements are not Terrane content identities. Enabling verity
//! permanently prevents plaintext writes, including writes by the inode owner.

use std::io;
use std::os::fd::{AsFd, AsRawFd};

use terrane_sdk::host::publication::VerityBinding;

// These Linux UAPI commands encode a 128-byte enable argument and a four-byte
// measurement header. Their values are stable on the supported Linux targets.
const ENABLE_VERITY: libc::c_ulong = 0x4080_6685;
const MEASURE_VERITY: libc::c_ulong = 0xc004_6686;

#[repr(C)]
struct EnableArgument {
    version: u32,
    hash_algorithm: u32,
    block_size: u32,
    salt_size: u32,
    salt_pointer: u64,
    signature_size: u32,
    reserved: u32,
    signature_pointer: u64,
    reserved_words: [u64; 11],
}

#[repr(C)]
struct Measurement {
    algorithm: u16,
    size: u16,
    digest: [u8; 64],
}

/// Permanently enables fs-verity and independently measures the kernel seal.
///
/// The descriptor must retain an owned inode with every writer already closed.
/// No capability is needed when the caller owns the inode.
///
/// # Errors
/// Returns unsupported filesystem, outstanding writer, permission, kernel or
/// invalid measurement errors. Mode bits never substitute for fs-verity.
pub fn enable(file: impl AsFd) -> io::Result<VerityBinding> {
    let argument = EnableArgument {
        version: 1,
        hash_algorithm: 1,
        block_size: 4096,
        salt_size: 0,
        salt_pointer: 0,
        signature_size: 0,
        reserved: 0,
        signature_pointer: 0,
        reserved_words: [0; 11],
    };
    // SAFETY: file's borrowed descriptor remains live for the ioctl. The UAPI
    // argument has its exact repr(C) layout, is initialized, and contains no
    // userspace pointers because both optional buffers have zero length.
    let result = unsafe { libc::ioctl(file.as_fd().as_raw_fd(), ENABLE_VERITY, &argument) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    measure(file)
}

/// Obtains a kernel fs-verity measurement from the retained inode.
///
/// # Errors
/// Returns an error for an unsealed inode, unsupported filesystem, ioctl
/// failure or a measurement outside the supported SHA-256/SHA-512 profiles.
pub fn measure(file: impl AsFd) -> io::Result<VerityBinding> {
    let mut measurement = Measurement {
        algorithm: 0,
        size: 64,
        digest: [0; 64],
    };
    // SAFETY: the repr(C) buffer contains the UAPI header plus the full declared
    // writable digest capacity. The borrowed descriptor and buffer remain live
    // for the synchronous ioctl; no kernel-written pointer is dereferenced.
    let result = unsafe { libc::ioctl(file.as_fd().as_raw_fd(), MEASURE_VERITY, &mut measurement) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    let valid = matches!((measurement.algorithm, measurement.size), (1, 32) | (2, 64));
    if !valid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid kernel verity measurement",
        ));
    }
    Ok(VerityBinding {
        algorithm: measurement.algorithm,
        digest: measurement.digest[..usize::from(measurement.size)].to_vec(),
    })
}
