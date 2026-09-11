//! Canonical PostgreSQL final and quarantine configuration bytes.

use std::io;

use super::super::{PostgresqlInput, postgresql_probe_principal, storage::StorageBinding};
use super::{PostgresqlAuth, PostgresqlPaths};

pub(super) struct CandidateBytes {
    pub(super) final_config: Vec<u8>,
    pub(super) final_hba: Vec<u8>,
    pub(super) final_ident: Vec<u8>,
    pub(super) quarantine_config: Vec<u8>,
    pub(super) quarantine_hba: Vec<u8>,
    pub(super) quarantine_ident: Vec<u8>,
}

pub(super) fn candidates(
    paths: &PostgresqlPaths,
    input: &PostgresqlInput,
    binding: &StorageBinding,
    auth: PostgresqlAuth,
) -> Result<CandidateBytes, io::Error> {
    let _endpoint = input
        .endpoint
        .as_ref()
        .ok_or_else(|| super::invalid("PostgreSQL materialization has no endpoint"))?;
    let map = format!("aos_slot_{:02}", binding.slot);
    let final_method = match auth {
        PostgresqlAuth::Scram => "scram-sha-256",
    };

    Ok(CandidateBytes {
        final_config: config(paths, input, 20_000 + u16::from(binding.slot), ""),
        final_hba: format!(
            "local all \"aos-ability-postgresql\" peer map={map}\n\
             local \"{}\" \"{}\" {final_method}\n\
             local all all reject\n\
             host all all 127.0.0.1/32 reject\n\
             host all all ::1/128 reject\n",
            input.database, input.role
        )
        .into_bytes(),
        final_ident: format!("{map} {} aos-ability-postgresql\n", binding.principal).into_bytes(),
        quarantine_config: config(paths, input, 20_000 + u16::from(binding.slot), ""),
        quarantine_hba: format!(
            "local all \"aos-ability-postgresql\" peer map={map}\n\
             local all all reject\n\
             host all all 127.0.0.1/32 reject\n\
             host all all ::1/128 reject\n"
        )
        .into_bytes(),
        quarantine_ident: format!(
            "{map} {} aos-ability-postgresql\n",
            postgresql_probe_principal(binding.slot)?
        )
        .into_bytes(),
    })
}

fn config(
    paths: &PostgresqlPaths,
    input: &PostgresqlInput,
    port: u16,
    listen_addresses: &str,
) -> Vec<u8> {
    format!(
        "data_directory = '{}'\n\
         hba_file = '{}'\n\
         ident_file = '{}'\n\
         listen_addresses = '{listen_addresses}'\n\
         port = {port}\n\
         unix_socket_directories = '{}'\n\
         unix_socket_permissions = 0770\n\
         password_encryption = 'scram-sha-256'\n\
         aos.configuration_revision = '{}'\n",
        paths.data.display(),
        paths.active_hba.display(),
        paths.active_ident.display(),
        paths.run.display(),
        input.configuration_revision,
    )
    .into_bytes()
}
