//! Encrypts credentials with an exact retained systemd-creds executable.

#[path = "../credential_encryption.rs"]
mod credential_encryption;
#[path = "../executable.rs"]
mod executable;

fn main() {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if let Err(error) = credential_encryption::run(&arguments) {
        eprintln!("aos-systemd-credential-encrypt: {error:#}");
        std::process::exit(1);
    }
}
